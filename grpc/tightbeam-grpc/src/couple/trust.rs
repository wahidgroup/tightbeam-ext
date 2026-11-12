//! The trust of a coupled edge in its callers, and the one decision of who
//! the caller of each call is.

use std::path::Path;
use std::sync::Arc;

use http::HeaderMap;
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ClientCertVerifierBuilder, WebPkiClientVerifier};
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer};
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::{Certificate, KeyCurves};
use tightbeam::der::Decode;

use super::bearer::BearerTrust;
use super::claim::{CallClaim, VerifiedClaim};
use super::fault::CallFault;
use super::forwarded::ForwardedChain;
use super::method::MethodPath;
use super::principal::{Principal, TlsIdentity};
use super::proof::Proof;
use crate::deadline::WallClock;
use crate::edge::{EdgeError, EdgeTlsPolicy};
use crate::incoming::{CoupledSlot, GrpcConnectInfo, LaneRefusal, ProvenLane};

/// The PEM files of the trust of a coupled edge in its callers, which
/// [`CallerTrust::from_pem`] reads.
#[derive(Clone, Debug)]
pub struct CallerTrustFiles<P> {
	/// The file of the roots that the TLS chain of each caller ends at.
	pub tls_roots: P,
	/// The file of the roots that the signer of each claim chains to.
	pub claim_roots: P,
}

/// The trust of a coupled edge in its callers.
///
/// - The TLS roots verify the client chain of each connection, with the
///   CRLs of [`CallerTrust::with_crls`]. A connection with no client chain
///   still connects, so a native tunnel client needs no TLS certificate.
/// - A coupled call on a connection with no client chain names its caller by
///   the bearer token of [`CallerTrust::with_bearer`], and refuses with
///   `UNAUTHENTICATED` when it carries none that verifies.
/// - The claim store verifies the signer of each claim, a tightbeam identity
///   issued to the same principal as the TLS certificate of its caller.
/// - [`CallerTrust::with_forwarding_proxy`] admits the client chain that a
///   pinned proxy forwards, and [`CallerTrust::with_bearer`] a JWT-SVID.
///
/// # Examples
///
/// ```
/// use tightbeam_grpc::couple::{CallerTrust, CallerTrustFiles};
/// # use tightbeam::der::{pem::LineEnding, EncodePem};
/// # use tightbeam_grpc::testing::CoupledStack;
/// # use tightbeam_ws::testing::Identity;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let dir = std::env::temp_dir().join(format!("tightbeam-grpc-doc-callers-{}", std::process::id()));
/// # let stack = CoupledStack::at(dir);
/// # let lifetime = core::time::Duration::from_secs(60);
/// # stack.write(lifetime, |staged| -> Result<(), Box<dyn std::error::Error>> {
/// # 	let claims = Identity::mint(CoupledStack::SIGNER, 1, lifetime)?;
/// # 	Ok(std::fs::write(staged.claims(), claims.certificate().to_pem(LineEnding::LF)?)?)
/// # })?;
/// # let (callers_ca, claims_ca) = (stack.root(), stack.claims());
///
/// let trust = CallerTrust::from_pem(CallerTrustFiles { tls_roots: callers_ca, claim_roots: claims_ca })?;
/// # std::fs::remove_dir_all(stack.dir())?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct CallerTrust {
	tls: Arc<RootCertStore>,
	crls: Vec<CertificateRevocationListDer<'static>>,
	claims: Arc<dyn CertificateTrust>,
	proxy: Option<Principal>,
	bearer: Option<BearerTrust>,
}

impl CallerTrust {
	/// The headers that name a caller to the edge alone: the bearer token and
	/// the forwarded client chain, which no call carries to its servlet.
	pub(crate) const CREDENTIAL_HEADERS: [&'static str; 2] = [BearerTrust::HEADER, ForwardedChain::HEADER];

	/// Trust in callers whose TLS chains end at `tls_roots`, and whose claims
	/// verify under `claims`.
	///
	/// # Errors
	///
	/// - [`EdgeError::NoCertificate`] -- `tls_roots` is empty.
	/// - [`EdgeError::Tls`] -- a root does not parse as a trust anchor.
	pub fn new(
		tls_roots: impl IntoIterator<Item = CertificateDer<'static>>,
		claims: Arc<dyn CertificateTrust>,
	) -> Result<Self, EdgeError> {
		let mut store = RootCertStore::empty();
		for root in tls_roots {
			store.add(root)?;
		}
		if store.is_empty() {
			return Err(EdgeError::NoCertificate);
		}

		Ok(Self { tls: Arc::new(store), crls: Vec::new(), claims, proxy: None, bearer: None })
	}

	/// Trust in callers whose TLS chains end at the PEM roots of
	/// `files.tls_roots`, and whose claims chain to the PEM roots of
	/// `files.claim_roots`, under the secp256k1 policy of tightbeam.
	///
	/// # Errors
	///
	/// - [`EdgeError::Io`] -- a file cannot be read.
	/// - [`EdgeError::Pem`] -- a file is malformed.
	/// - [`EdgeError::Trust`] -- tightbeam refuses a claim root.
	/// - The errors of [`CallerTrust::new`].
	pub fn from_pem<P: AsRef<Path>>(files: CallerTrustFiles<P>) -> Result<Self, EdgeError> {
		let blocks = CertificateDer::pem_file_iter(files.tls_roots)?;
		let tls_roots = blocks.collect::<Result<Vec<_>, _>>()?;

		let mut builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
		for root in certificates(files.claim_roots)? {
			builder = builder.with_certificate(root)?;
		}

		Self::new(tls_roots, Arc::new(builder.build()))
	}

	/// Check each client chain, direct or forwarded, against `crls`:
	///
	/// - A certificate that a CRL of its issuer revokes is refused.
	/// - Each certificate of a chain needs a CRL of its issuer, or its status is unknown and it is refused.
	/// - A CRL past its `nextUpdate` refuses every chain that it covers.
	#[must_use]
	pub fn with_crls(mut self, crls: impl IntoIterator<Item = CertificateRevocationListDer<'static>>) -> Self {
		self.crls.extend(crls);
		self
	}

	/// Take the caller of each call on a connection whose client chain names
	/// `proxy` from the client chain that the proxy forwards in
	/// `x-forwarded-client-cert`, or else from a bearer token.
	///
	/// - The edge verifies a forwarded chain under the TLS roots and CRLs, as
	///   it verifies its own connections.
	/// - The last element of the header counts, the one that `proxy` appended.
	/// - Any other connection names its own caller, whatever the header says.
	#[must_use]
	pub fn with_forwarding_proxy(mut self, proxy: Principal) -> Self {
		self.proxy = Some(proxy);
		self
	}

	/// Take the caller of each call that proves no client chain from the
	/// JWT-SVID in its `authorization` metadata, under `bearer`. Its calls
	/// prove [`Assurance::Bearer`](super::Assurance::Bearer), and carry no
	/// claim.
	#[must_use]
	pub fn with_bearer(mut self, bearer: BearerTrust) -> Self {
		self.bearer = Some(bearer);
		self
	}

	/// The callers of a live edge, whose bearer tokens it judges at the unix
	/// time of `wall`.
	///
	/// # Errors
	///
	/// - [`EdgeError::Verifier`] -- rustls refuses a CRL.
	pub(crate) fn live(&self, wall: WallClock) -> Result<LiveCallers, EdgeError> {
		let forwarded = self.checked().build()?;
		let claims = Arc::clone(&self.claims);
		Ok(LiveCallers { forwarded, proxy: self.proxy.clone(), bearer: self.bearer.clone(), claims, wall })
	}

	/// The client verifier of the edge, which admits a connection with no
	/// client chain.
	///
	/// # Errors
	///
	/// - [`EdgeError::Verifier`] -- rustls refuses a CRL.
	pub(crate) fn verifier(&self) -> Result<Arc<dyn ClientCertVerifier>, EdgeError> {
		let verifier = self.checked().allow_unauthenticated().build()?;
		Ok(verifier)
	}

	/// The verifier of a client chain under the TLS roots and the CRLs, under
	/// the TLS policy of the edge, which refuses a CRL past its `nextUpdate`.
	fn checked(&self) -> ClientCertVerifierBuilder {
		let provider = EdgeTlsPolicy::provider();
		let builder = WebPkiClientVerifier::builder_with_provider(Arc::clone(&self.tls), provider);
		builder.with_crls(self.crls.iter().cloned()).enforce_revocation_expiration()
	}

	/// The store that verifies the signer of each claim, which the servlets
	/// of the edge share through `AdmissionTrust`, so a claim that the edge
	/// verifies is a claim that each servlet verifies.
	#[must_use]
	pub fn claim_store(&self) -> Arc<dyn CertificateTrust> {
		Arc::clone(&self.claims)
	}
}

/// The callers of a live coupled edge: the verifier of each forwarded chain,
/// the proxy that may forward one, the trust in bearer tokens, and the store
/// that verifies the signer of each claim.
pub(crate) struct LiveCallers {
	forwarded: Arc<dyn ClientCertVerifier>,
	proxy: Option<Principal>,
	bearer: Option<BearerTrust>,
	claims: Arc<dyn CertificateTrust>,
	/// The unix time of the coupler, which each bearer token is judged at.
	wall: WallClock,
}

impl LiveCallers {
	/// The caller of a call with `headers` on `connection`:
	///
	/// - On a connection of the forwarding proxy, the client chain that it forwards, or else a bearer token.
	/// - On any other connection with a client chain, the caller of that chain.
	/// - On a connection whose client chain names no principal, no caller.
	/// - On a connection with none, a bearer token.
	///
	/// # Errors
	///
	/// - [`CallFault::Unauthenticated`] -- the call proves no caller, its
	///   client chain names no principal, or a forwarded chain or a token does
	///   not verify.
	pub(crate) fn caller_of(
		&self,
		connection: &GrpcConnectInfo,
		headers: &HeaderMap,
	) -> Result<ProvenCaller, CallFault> {
		let credential = connection.chain().credential(self, headers)?;
		let lane = connection.proven_lane(&credential);
		Ok(ProvenCaller { credential, lane })
	}

	/// The credential of a call with `headers` on a connection whose client
	/// chain names `identity`: on a connection of the forwarding proxy, the
	/// client chain that it forwards, or else a bearer token, and on any other
	/// connection, the caller of that chain.
	///
	/// # Errors
	///
	/// - [`CallFault::Unauthenticated`] -- the call on a connection of the
	///   proxy proves no caller, or a forwarded chain or a token does not verify.
	pub(crate) fn of_chain(&self, identity: &Arc<TlsIdentity>, headers: &HeaderMap) -> Result<Credential, CallFault> {
		if self.proxy.as_ref() != Some(identity.principal()) {
			return Ok(Credential(Proved::Tls(Arc::clone(identity))));
		}

		if headers.contains_key(ForwardedChain::HEADER) {
			return self.forwarded(headers);
		}

		self.bearer(headers)
	}

	/// The client chain that the XFCC field of `headers` forwards, once it
	/// verifies under the TLS roots and CRLs of the edge.
	fn forwarded(&self, headers: &HeaderMap) -> Result<Credential, CallFault> {
		let chain = ForwardedChain::of(headers).ok_or(CallFault::Unauthenticated)?;
		let identity = chain.verify(&*self.forwarded).ok_or(CallFault::Unauthenticated)?;
		Ok(Credential(Proved::Tls(Arc::new(identity))))
	}

	/// The principal of the bearer token in `headers`.
	///
	/// # Errors
	///
	/// - [`CallFault::Unauthenticated`] -- the edge trusts no bearer token, or
	///   `headers` carry none that verifies.
	pub(crate) fn bearer(&self, headers: &HeaderMap) -> Result<Credential, CallFault> {
		let bearer = self.bearer.as_ref().ok_or(CallFault::Unauthenticated)?;
		let principal = bearer
			.principal_of(headers, self.wall.now())
			.ok_or(CallFault::Unauthenticated)?;
		let principal = principal.map_err(|_| CallFault::Unauthenticated)?;
		Ok(Credential(Proved::Bearer(principal)))
	}
}

/// The caller of one coupled call, which only [`LiveCallers::caller_of`]
/// proves, and the lane of the connection that it proved the caller on.
pub(crate) struct ProvenCaller {
	credential: Credential,
	lane: ProvenLane,
}

/// What proved a caller to the edge. Only this module creates one, so only a
/// proven caller opens a coupled call on its lane.
pub(crate) struct Credential(Proved);

/// The kind of a [`Credential`].
enum Proved {
	/// A TLS client certificate, of the connection or one that a pinned proxy
	/// forwards, which a claim binds to.
	Tls(Arc<TlsIdentity>),
	/// A bearer token, which no claim can bind to.
	Bearer(Principal),
}

impl Proved {
	/// The principal that proved itself.
	fn principal(&self) -> &Principal {
		match self {
			Self::Tls(identity) => identity.principal(),
			Self::Bearer(principal) => principal,
		}
	}

	/// What a call proves with `claim` over `method` and `body`, whose signer
	/// verifies under `claims`.
	///
	/// # Errors
	///
	/// - [`CallFault::ClaimRefused`] -- the claim does not verify, or a bearer caller carries one.
	fn prove(
		&self,
		claim: Option<CallClaim>,
		method: &MethodPath,
		body: &[u8],
		claims: &dyn CertificateTrust,
	) -> Result<Proof<VerifiedClaim>, CallFault> {
		match (self, claim) {
			(Self::Tls(_), None) => Ok(Proof::Vouched),
			(Self::Tls(identity), Some(claim)) => {
				let verified = claim.verify(identity.principal(), identity.leaf(), method, body, claims)?;
				Ok(Proof::Signed(verified))
			}
			(Self::Bearer(_), None) => Ok(Proof::Bearer),
			(Self::Bearer(_), Some(_)) => Err(CallFault::ClaimRefused),
		}
	}
}

impl ProvenCaller {
	pub(crate) fn principal(&self) -> &Principal {
		self.credential.0.principal()
	}

	/// What a call of the caller proves with `claim`, over `method` and
	/// `body`. A call with no claim proves what its caller proved, and a claim
	/// verifies under the claim store of `callers` for the TLS certificate of
	/// the caller.
	///
	/// # Errors
	///
	/// - The errors of [`Proved::prove`].
	pub(crate) fn prove(
		&self,
		claim: Option<CallClaim>,
		method: &MethodPath,
		body: &[u8],
		callers: &LiveCallers,
	) -> Result<Proof<VerifiedClaim>, CallFault> {
		self.credential.0.prove(claim, method, body, &*callers.claims)
	}

	/// Open a coupled call on the lane of the connection that proved the
	/// caller, so the connection gives up its slot for a coupled permit only
	/// once the coupler proved who calls on it.
	///
	/// # Errors
	///
	/// - The [`LaneRefusal`] of a lane that refuses the call.
	pub(crate) fn open_coupled(&self) -> Result<CoupledSlot, LaneRefusal> {
		self.lane.open_coupled()
	}
}

/// Every certificate of the PEM file at `path`, decoded as tightbeam takes
/// it.
///
/// # Errors
///
/// - [`EdgeError::Io`] -- the file cannot be read.
/// - [`EdgeError::Pem`] -- the file is malformed.
/// - [`EdgeError::Trust`] -- a certificate does not decode.
fn certificates(path: impl AsRef<Path>) -> Result<Vec<Certificate>, EdgeError> {
	let mut decoded = Vec::new();
	for block in CertificateDer::pem_file_iter(path)? {
		let block = block?;
		let certificate = Certificate::from_der(block.as_ref()).map_err(CertificateValidationError::from)?;
		decoded.push(certificate);
	}

	Ok(decoded)
}
