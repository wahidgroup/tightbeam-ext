//! The claim of a caller: its own signature over one call, bound to its
//! principal and to the SHA-256 of its TLS certificate.
//!
//! # Sources
//!
//! - RFC 5652, CMS, September 2009, section 5: <https://www.rfc-editor.org/rfc/rfc5652#section-5>
//! - CWE-294, Authentication Bypass by Capture-replay: <https://cwe.mitre.org/data/definitions/294.html>

use core::sync::atomic::{AtomicU64, Ordering};

use http::HeaderMap;
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use tightbeam::builder::TypeBuilder;
use tightbeam::clock::UnixMillis;
use tightbeam::crypto::policy::VerifiedSignature;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::crypto::x509::{Certificate, ErasedSigning, KeyPurposes, PeerCertificate};
use tightbeam::der::asn1::OctetString;
use tightbeam::der::{Decode, Encode};
use tightbeam::{Frame, TightBeamError, Version};
use tonic::metadata::{MetadataMap, MetadataValue};

use super::fault::CallFault;
use super::message::{ClaimBody, ClaimEnvelope};
use super::principal::{Caller, Principal};

/// Signs the claims of one caller, under its tightbeam identity, bound to its
/// TLS certificate.
///
/// The replay window of the edge refuses two claims of one signer at one
/// order, so the signer issues strictly increasing orders: the current time,
/// or one past the last order when the clock has not moved on.
///
/// # Examples
///
/// ```no_run
/// use rustls_pki_types::CertificateDer;
/// use tightbeam::crypto::sign::SigningIdentity;
/// use tightbeam_grpc::couple::ClaimSigner;
///
/// # async fn claim(identity: SigningIdentity, tls_leaf: CertificateDer<'static>, body: Vec<u8>) -> Result<(), tightbeam::TightBeamError> {
/// let signer = ClaimSigner::new(identity, [], &tls_leaf);
/// let claim = signer.sign("/orders.v1.Orders/Place", &body).await?;
/// let mut request = tonic::Request::new(body);
/// claim.attach(request.metadata_mut())?;
/// # Ok(())
/// # }
/// ```
pub struct ClaimSigner {
	identity: SigningIdentity,
	issuers: Vec<Certificate>,
	leaf_digest: [u8; 32],
	last_order: AtomicU64,
}

impl ClaimSigner {
	/// A signer under `identity`, whose certificate the certificates of
	/// `issuers` issue, for the caller that presents the TLS certificate
	/// `tls_leaf`.
	pub fn new(
		identity: SigningIdentity,
		issuers: impl IntoIterator<Item = Certificate>,
		tls_leaf: &CertificateDer<'_>,
	) -> Self {
		let issuers = issuers.into_iter().collect();
		let leaf_digest = Caller::digest(tls_leaf.as_ref());
		Self { identity, issuers, leaf_digest, last_order: AtomicU64::new(0) }
	}

	/// The claim of the call of `method` with the encoded request `body`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a frame that does not build, sign, or encode.
	pub async fn sign(&self, method: impl AsRef<str>, body: &[u8]) -> Result<CallClaim, TightBeamError> {
		let order = self.next_order();
		let body_digest = OctetString::new(Sha256::digest(body).to_vec())?;
		let leaf_digest = OctetString::new(self.leaf_digest.to_vec())?;
		let claimed = ClaimBody { method: method.as_ref().to_owned(), body_digest, leaf_digest };

		let id = order.to_be_bytes();
		let draft = Version::V1.compose().with_id(id).with_order(order).with_message(claimed);
		let mut frame = draft.build()?;
		frame.sign_with_provider(&self.identity).await?;

		let frame = OctetString::new(frame.to_der()?)?;
		let signer = self.identity.certificate().clone();
		let envelope = ClaimEnvelope { frame, signer, issuers: self.issuers.clone() };
		let encoded = envelope.to_der()?;
		Ok(CallClaim { envelope, encoded })
	}

	/// The next order: the current time in milliseconds, or one past the last
	/// order.
	fn next_order(&self) -> u64 {
		let now = UnixMillis::now().get();
		let previous = self
			.last_order
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |last| Some(now.max(last + 1)));
		let last = previous.unwrap_or_else(|last| last);
		now.max(last + 1)
	}
}

/// The claim of one call, as a caller attaches it and as the edge reads it.
#[derive(Clone, Debug)]
pub struct CallClaim {
	envelope: ClaimEnvelope,
	/// The DER of the envelope as it arrived, which a coupled call forwards
	/// unchanged.
	encoded: Vec<u8>,
}

impl CallClaim {
	/// The binary metadata key that carries a claim.
	pub const METADATA_KEY: &'static str = "tightbeam-claim-bin";

	/// Attach the claim to the metadata of a request.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the claim does not encode.
	pub fn attach(&self, metadata: &mut MetadataMap) -> Result<(), TightBeamError> {
		metadata.insert_bin(Self::METADATA_KEY, MetadataValue::from_bytes(&self.encoded));
		Ok(())
	}

	/// The claim of a call head, `None` when the head carries none.
	///
	/// # Errors
	///
	/// - [`CallFault::ClaimRefused`] -- the head carries a claim that does not
	///   decode, or carries two.
	pub(crate) fn of_head(headers: &HeaderMap) -> Result<Option<Self>, CallFault> {
		let metadata = MetadataMap::from_headers(headers.clone());
		let mut values = metadata.get_all_bin(Self::METADATA_KEY).iter();
		let Some(value) = values.next() else {
			return Ok(None);
		};
		if values.next().is_some() {
			return Err(CallFault::ClaimRefused);
		}

		let encoded = value.to_bytes().map_err(|_| CallFault::ClaimRefused)?;
		Self::from_der(&encoded).map(Some)
	}

	/// Verify the claim for the call of `method` with `body` on the
	/// connection of `caller`, under the claim store `claims`:
	///
	/// 1. The signer path verifies under `claims`, and the signer certificate
	///    is admitted for signing.
	/// 2. The claim frame verifies under the signer.
	/// 3. The signer certificate names the principal of the caller.
	/// 4. The claim covers `method`, the SHA-256 of `body`, and the SHA-256 of
	///    the TLS certificate of the caller.
	///
	/// # Errors
	///
	/// - [`CallFault::ClaimRefused`] -- a step fails.
	pub(crate) fn verify(
		self,
		caller: &Caller,
		method: &str,
		body: &[u8],
		claims: &dyn CertificateTrust,
	) -> Result<VerifiedClaim, CallFault> {
		let opened = self.open(method, body, claims, caller.principal())?;
		let bound = opened.body.leaf_digest.as_bytes() == caller.leaf_digest();
		if !bound {
			return Err(CallFault::ClaimRefused);
		}

		Ok(opened.verified)
	}

	/// Verify the claim for `method` and `body` of `principal`, as a servlet
	/// can: steps 1 to 4 of [`CallClaim::verify`], with no TLS certificate to
	/// compare.
	///
	/// # Errors
	///
	/// - [`CallFault::ClaimRefused`] -- a step fails.
	pub(crate) fn verify_for(
		self,
		principal: &Principal,
		method: &str,
		body: &[u8],
		claims: &dyn CertificateTrust,
	) -> Result<VerifiedClaim, CallFault> {
		let opened = self.open(method, body, claims, principal)?;
		Ok(opened.verified)
	}

	/// The DER of a claim that a coupled call forwards.
	pub(crate) fn from_der(encoded: &[u8]) -> Result<Self, CallFault> {
		let envelope = ClaimEnvelope::from_der(encoded).map_err(|_| CallFault::ClaimRefused)?;
		Ok(Self { envelope, encoded: encoded.to_vec() })
	}

	/// Steps 1 to 4 of [`CallClaim::verify`] with the certificate digest left
	/// to the caller.
	fn open(
		self,
		method: &str,
		body: &[u8],
		claims: &dyn CertificateTrust,
		principal: &Principal,
	) -> Result<Opened, CallFault> {
		let ClaimEnvelope { frame, signer, issuers } = self.envelope;
		let forwarded = self.encoded;
		let refused = |_| CallFault::ClaimRefused;

		claims.verify_presented(&issuers, &signer).map_err(refused)?;
		let signer_key = signer.to_der().map_err(|_| CallFault::ClaimRefused)?;
		let named = Principal::of(&signer);
		let peer = PeerCertificate::<ErasedSigning>::parse(signer, KeyPurposes::HOUSE.signer).map_err(refused)?;

		let frame = Frame::from_der(frame.as_bytes()).map_err(|_| CallFault::ClaimRefused)?;
		let signature = frame
			.verify_under(&peer, claims.to_policy_ref())
			.map_err(|_| CallFault::ClaimRefused)?;
		if named.as_ref() != Some(principal) {
			return Err(CallFault::ClaimRefused);
		}

		let claimed: ClaimBody = frame.decode_message().map_err(|_| CallFault::ClaimRefused)?;
		let digest = Sha256::digest(body);
		let covers = claimed.method == method && claimed.body_digest.as_bytes() == digest.as_slice();
		if !covers {
			return Err(CallFault::ClaimRefused);
		}

		let order = UnixMillis::new(frame.metadata().order());
		let verified = VerifiedClaim { signer_key, signature, order, forwarded };
		Ok(Opened { body: claimed, verified })
	}
}

/// A claim whose signer and coverage verified, before its certificate digest
/// is compared.
struct Opened {
	body: ClaimBody,
	verified: VerifiedClaim,
}

/// A claim that verified for its call. Only [`CallClaim::verify`] builds
/// one, and the coupler spends it once.
#[derive(Debug)]
pub(crate) struct VerifiedClaim {
	signer_key: Vec<u8>,
	signature: VerifiedSignature,
	order: UnixMillis,
	forwarded: Vec<u8>,
}

impl VerifiedClaim {
	/// The partition of the replay window that the claim spends in: the DER
	/// of its signer certificate.
	pub(crate) fn signer_key(&self) -> &[u8] {
		&self.signer_key
	}

	/// The signature of the claim, the replay key of the window.
	pub(crate) fn signature(&self) -> &VerifiedSignature {
		&self.signature
	}

	/// The order of the claim frame, which the window holds to its freshness.
	pub(crate) fn order(&self) -> UnixMillis {
		self.order
	}

	/// The DER of the claim, which the coupled call forwards to the servlet.
	pub(crate) fn forwarded(&self) -> &[u8] {
		&self.forwarded
	}
}
