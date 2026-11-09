//! The admission of a coupled call at the servlet that serves it.
//!
//! A servlet trusts three stores, which [`AdmissionTrust`] holds:
//!
//! - The vouchers: the couplers whose signature vouches for the principal
//!   that a call names.
//! - The direct callers: the tightbeam identities that sign their own calls,
//!   each the principal its certificate names.
//! - The claim store: the signers of the claims that a vouched call forwards.
//!
//! [`AdmittedCall::admit`] decodes the call from its frame and decides its
//! principal and its assurance from the signer of the frame, so a frame whose
//! origin names a principal that its signer may not vouch for never admits.

use std::sync::Arc;

use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::store::{CertificateTrust, TrustVerification};
use tightbeam::der::asn1::OctetString;
use tightbeam::policy::TransitStatus;
use tightbeam::{compose, Frame, TightBeamError};
use tonic::Code;

use super::claim::CallClaim;
use super::message::{CoupledCall, CoupledReply};
use super::principal::Principal;
use super::routes::Assurance;

/// The refusal of a call that does not admit.
const NOT_ADMITTED: TightBeamError = TightBeamError::WorkRefused(TransitStatus::Unauthenticated);

/// The trust of a servlet in the senders of its coupled calls.
#[derive(Clone, Debug)]
pub struct AdmissionTrust {
	vouchers: Arc<dyn CertificateTrust>,
	direct: Arc<dyn CertificateTrust>,
	claims: Arc<dyn CertificateTrust>,
}

impl AdmissionTrust {
	/// Trust in the couplers of `vouchers`, the direct callers of `direct`,
	/// and the claim signers of `claims`.
	pub fn new(
		vouchers: Arc<dyn CertificateTrust>,
		direct: Arc<dyn CertificateTrust>,
		claims: Arc<dyn CertificateTrust>,
	) -> Self {
		Self { vouchers, direct, claims }
	}
}

/// A coupled call that its servlet admitted: the principal that made it, the
/// assurance it proves, its method, and its body.
#[derive(Debug)]
pub struct AdmittedCall {
	principal: Principal,
	assurance: Assurance,
	method: String,
	body: Vec<u8>,
	request_id: Vec<u8>,
	/// The DER of the claim that a vouched call forwards, which a backend
	/// forwards on.
	claim: Option<Vec<u8>>,
}

impl AdmittedCall {
	/// Admit the coupled call of `frame` under `trust`:
	///
	/// - A call with an origin admits when a voucher of `trust` signed the
	///   frame. Its principal is the principal of the origin, and its
	///   assurance is [`Assurance::Signed`] when its forwarded claim verifies
	///   for that principal, method, and body under the claim store, and
	///   [`Assurance::Vouched`] when it forwards no claim.
	/// - A call with no origin admits when a direct caller of `trust` signed
	///   the frame. Its principal is the principal of the certificate of the
	///   signer, and its assurance is [`Assurance::Signed`].
	///
	/// # Errors
	///
	/// - [`TightBeamError::WorkRefused`] -- the frame holds no coupled call,
	///   its signer is not trusted for its origin, its origin names no valid
	///   principal, or its forwarded claim does not verify.
	pub fn admit(frame: &Frame, trust: &AdmissionTrust) -> Result<Self, TightBeamError> {
		let call: CoupledCall = frame.decode_message().map_err(|_| NOT_ADMITTED)?;
		let CoupledCall { method, vouched, body } = call;
		let body = body.into_bytes();

		let mut forwarded = None;
		let (principal, assurance) = match vouched {
			Some(origin) => {
				let TrustVerification::Verified(_, _) = trust.vouchers.verify_frame(frame) else {
					return Err(NOT_ADMITTED);
				};
				let principal = Principal::try_from(origin.principal).map_err(|_| NOT_ADMITTED)?;
				let assurance = match origin.claim {
					None => Assurance::Vouched,
					Some(claim) => {
						let claim = CallClaim::from_der(claim.as_bytes()).map_err(|_| NOT_ADMITTED)?;
						let verified = claim.verify_for(&principal, &method, &body, &*trust.claims);
						let verified = verified.map_err(|_| NOT_ADMITTED)?;
						forwarded = Some(verified.forwarded().to_vec());
						Assurance::Signed
					}
				};
				(principal, assurance)
			}
			None => {
				let TrustVerification::Verified(signer, _) = trust.direct.verify_frame(frame) else {
					return Err(NOT_ADMITTED);
				};
				let principal = Principal::of(signer.certificate()).ok_or(NOT_ADMITTED)?;
				(principal, Assurance::Signed)
			}
		};

		let request_id = frame.metadata().id().to_vec();
		Ok(Self { principal, assurance, method, body, request_id, claim: forwarded })
	}

	/// The principal that made the call.
	pub fn principal(&self) -> &Principal {
		&self.principal
	}

	/// How much the call proves about its principal.
	pub fn assurance(&self) -> Assurance {
		self.assurance
	}

	/// The gRPC method of the call, such as `/orders.v1.Orders/Place`.
	pub fn method(&self) -> &str {
		&self.method
	}

	/// The encoded request message of the call.
	pub fn body(&self) -> &[u8] {
		&self.body
	}

	/// The DER of the claim that the call forwards, when its caller signed
	/// one.
	pub(crate) fn claim(&self) -> Option<&[u8]> {
		self.claim.as_deref()
	}

	/// The reply to the call: the gRPC status `code` and the encoded response
	/// message `body`, in a frame that answers the id of the call and that
	/// `signer` signs.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a reply that does not build or sign.
	pub async fn reply(
		self,
		code: Code,
		body: impl Into<Vec<u8>>,
		signer: &SigningIdentity,
	) -> Result<Option<Frame>, TightBeamError> {
		self.answer(code, None, body, signer).await
	}

	/// The reply to the call with the status `code` and its `message`, as
	/// [`AdmittedCall::reply`] signs it.
	pub(crate) async fn answer(
		self,
		code: Code,
		message: Option<String>,
		body: impl Into<Vec<u8>>,
		signer: &SigningIdentity,
	) -> Result<Option<Frame>, TightBeamError> {
		let body = OctetString::new(body.into())?;
		let answer = CoupledReply { code: code as i32, message, body };
		let mut reply = compose! {
			V1: id: self.request_id.as_slice(),
				message: answer
		}?;

		reply.sign_with_provider(signer).await?;
		Ok(Some(reply))
	}
}
