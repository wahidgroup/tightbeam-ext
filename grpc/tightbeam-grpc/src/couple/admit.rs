//! The admission of a coupled call at the servlet that serves it: a unary
//! call, or the head of a stream.

use core::time::Duration;
use std::sync::Arc;

use tightbeam::clock::{Clock, SystemClock};
use tightbeam::constants::DEFAULT_MAX_ENCRYPTED_ENVELOPE;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::store::{CertificateTrust, TrustVerification};
use tightbeam::crypto::x509::Certificate;
use tightbeam::policy::TransitStatus;
use tightbeam::{compose, Frame, TightBeamError};
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::{Request, Status};

use super::claim::{CallClaim, ForwardedClaim};
use super::message::{CallParts, CoupledCall, CoupledReply, StreamTerms, VouchedOrigin};
use super::metadata::{CallMetadata, Metadata};
use super::method::MethodPath;
use super::principal::Principal;
use super::proof::Proof;
use super::routes::{Assurance, StreamShape};
use crate::deadline::Deadline;

/// The trust of a servlet in the senders of its coupled calls, and the
/// ceiling of each part of a stream it reads.
///
/// It trusts no sender until a setter names one, so a call from a sender of a
/// kind that no setter names refuses.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
///
/// use tightbeam::crypto::x509::store::CertificateTrust;
/// use tightbeam_grpc::couple::AdmissionTrust;
///
/// # fn trust(couplers: Arc<dyn CertificateTrust>, claims: Arc<dyn CertificateTrust>) -> AdmissionTrust {
/// AdmissionTrust::new().with_vouchers(couplers).with_claim_signers(claims)
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct AdmissionTrust {
	vouchers: Option<Arc<dyn CertificateTrust>>,
	direct: Option<Arc<dyn CertificateTrust>>,
	claims: Option<Arc<dyn CertificateTrust>>,
	part_ceiling: usize,
	/// The clock that the deadline of each admitted call runs on.
	clock: Arc<dyn Clock>,
}

impl AdmissionTrust {
	/// Trust in no sender, with parts of at most 256 KiB, and the deadline of
	/// each call on [`SystemClock`].
	#[must_use]
	pub fn new() -> Self {
		Self {
			vouchers: None,
			direct: None,
			claims: None,
			part_ceiling: DEFAULT_MAX_ENCRYPTED_ENVELOPE,
			clock: Arc::new(SystemClock),
		}
	}

	/// Admit the calls that a coupler of `vouchers` vouches for.
	#[must_use]
	pub fn with_vouchers(mut self, vouchers: Arc<dyn CertificateTrust>) -> Self {
		self.vouchers = Some(vouchers);
		self
	}

	/// Admit the calls that a caller of `direct` signs itself, with no
	/// coupler, as [`Assurance::Signed`].
	#[must_use]
	pub fn with_direct_callers(mut self, direct: Arc<dyn CertificateTrust>) -> Self {
		self.direct = Some(direct);
		self
	}

	/// Admit a vouched call that forwards a claim of a signer of `claims` as
	/// [`Assurance::Signed`]. A vouched call that forwards a claim refuses
	/// without one.
	#[must_use]
	pub fn with_claim_signers(mut self, claims: Arc<dyn CertificateTrust>) -> Self {
		self.claims = Some(claims);
		self
	}

	/// Read and send each part of a stream of at most `ceiling` bytes, in
	/// place of 256 KiB.
	#[must_use]
	pub fn with_part_ceiling(mut self, ceiling: usize) -> Self {
		self.part_ceiling = ceiling;
		self
	}

	/// The most bytes that a part of a stream carries.
	pub(crate) fn part_ceiling(&self) -> usize {
		self.part_ceiling
	}

	/// Run the deadline of each admitted call on `clock`.
	#[must_use]
	pub(crate) fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
		self.clock = clock;
		self
	}
}

impl Default for AdmissionTrust {
	fn default() -> Self {
		Self::new()
	}
}

/// Who made one admitted call or opened one admitted stream, and what it
/// carries for its servlet beside its messages: the head that every admitted
/// call and stream shares.
#[derive(Debug)]
pub struct Origin {
	principal: Principal,
	proof: Proof<Option<ForwardedClaim>>,
	method: MethodPath,
	request_id: Vec<u8>,
	deadline: Deadline,
	metadata: CallMetadata,
}

/// The head of a stream that a servlet admitted: its origin, the shape of its
/// method, the most bytes of each later part, and the signer that each later
/// part verifies under.
pub(crate) struct AdmittedHead {
	pub(crate) origin: Origin,
	pub(crate) shape: StreamShape,
	pub(crate) ceiling: usize,
	pub(crate) signer: AdmittedSigner,
}

/// What a frame admits as: its origin, its body, its stream terms when it
/// opens a stream, and the signer that each later part of a stream verifies
/// under.
struct Decoded {
	origin: Origin,
	body: Vec<u8>,
	stream: Option<StreamTerms>,
	signer: AdmittedSigner,
}

impl Origin {
	/// The binary metadata key that carries the principal of each call that a
	/// backend makes for a coupled call: the UTF-8 of its SPIFFE ID, or of its
	/// subject in the string form of RFC 4514.
	pub const PRINCIPAL_KEY: &'static str = "tightbeam-principal-bin";

	/// Decode the coupled call of `frame` under `trust`, whose sender admits
	/// as [`Sender::admit`] states.
	///
	/// # Errors
	///
	/// - [`AdmissionFault::Refused`] -- the frame does not admit.
	fn decode(frame: &Frame, trust: &AdmissionTrust) -> Result<Decoded, AdmissionFault> {
		let call: CoupledCall = frame.decode_message().map_err(|_| AdmissionFault::Refused)?;
		let parts = call.into_parts().map_err(|_| AdmissionFault::Refused)?;
		let CallParts { method, vouched, body, timeout, metadata, stream } = parts;
		let metadata = CallMetadata::admit(metadata).map_err(|_| AdmissionFault::Refused)?;
		let AdmittedSender { principal, proof, signer } = Sender::of(vouched).admit(frame, trust, &method, &body)?;

		let request_id = frame.metadata().id().to_vec();
		let deadline = match timeout {
			Some(millis) => Deadline::after(&trust.clock, Duration::from_millis(millis)),
			None => Deadline::unbounded(&trust.clock),
		};
		let origin = Origin { principal, proof, method, request_id, deadline, metadata };
		Ok(Decoded { origin, body, stream, signer })
	}

	/// The head of the stream that `frame` opens under `trust`: the shape and
	/// the part ceiling that its terms declare, and the signer that each later
	/// part verifies under.
	///
	/// # Errors
	///
	/// - [`AdmissionFault::Refused`] -- the frame does not admit.
	/// - [`AdmissionFault::Malformed`] -- the frame opens no stream, or one of a unary shape or with a body.
	/// - [`AdmissionFault::Oversize`] -- the head declares a part ceiling past that of `trust`.
	pub(crate) fn of_head(frame: &Frame, trust: &AdmissionTrust) -> Result<AdmittedHead, AdmissionFault> {
		let Decoded { origin, body, stream, signer } = Self::decode(frame, trust)?;
		let terms = stream.filter(|_| body.is_empty()).ok_or(AdmissionFault::Malformed)?;
		let shape = terms.shape().streamed().ok_or(AdmissionFault::Malformed)?;
		let ceiling = terms.ceiling();
		if ceiling > trust.part_ceiling {
			return Err(AdmissionFault::Oversize);
		}

		Ok(AdmittedHead { origin, shape, ceiling, signer })
	}

	/// The time left to the deadline of the call, which counts from its
	/// admission on the clock of its trust, or `None` when it carries none,
	/// or one past the range of the clock.
	pub fn remaining(&self) -> Option<Duration> {
		self.deadline.left()
	}

	/// Each metadata entry of the call.
	pub fn metadata(&self) -> impl Iterator<Item = Metadata<'_>> {
		self.metadata.iter()
	}

	/// The principal that made the call.
	pub fn principal(&self) -> &Principal {
		&self.principal
	}

	/// How much the call proves about its principal.
	pub fn assurance(&self) -> Assurance {
		self.proof.assurance()
	}

	/// The gRPC method of the call.
	pub fn method(&self) -> &MethodPath {
		&self.method
	}

	/// Write the identity of the call onto `metadata`, the metadata of a call
	/// that a backend makes for it: each metadata entry of the call, its
	/// principal under [`Origin::PRINCIPAL_KEY`], and the claim that it
	/// forwards under [`CallClaim::METADATA_KEY`].
	pub fn stamp(&self, metadata: &mut MetadataMap) {
		self.metadata.append_to(metadata);

		let principal = self.principal.to_string();
		metadata.insert_bin(Self::PRINCIPAL_KEY, MetadataValue::from_bytes(principal.as_bytes()));
		if let Some(claim) = self.proof.forwarded() {
			metadata.insert_bin(CallClaim::METADATA_KEY, MetadataValue::from_bytes(claim));
		}
	}

	/// The id of the call, which its answer and every later part carry.
	pub(crate) fn request_id(&self) -> &[u8] {
		&self.request_id
	}

	/// The deadline `timeout` from now, or the deadline of the call when that
	/// is sooner, on the clock of its trust.
	pub(crate) fn bounded(&self, timeout: Duration) -> Deadline {
		self.deadline.clone().sooner(timeout)
	}

	/// The request of `message` that a backend makes for the call: the
	/// identity of the call, and the time left to `deadline` as its
	/// `grpc-timeout`.
	pub(crate) fn request<T>(&self, message: T, deadline: &Deadline) -> Request<T> {
		let mut request = Request::new(message);
		if let Some(left) = deadline.left() {
			request.set_timeout(left);
		}
		self.stamp(request.metadata_mut());
		request
	}
}

/// The sender of a coupled call: a coupler that vouches for the origin of the
/// call, or a direct caller that signs the call itself.
enum Sender {
	Vouched(VouchedOrigin),
	Direct,
}

impl Sender {
	/// The sender of a call that carries `vouched`: the coupler of that
	/// origin, or a direct caller for a call with no origin.
	fn of(vouched: Option<VouchedOrigin>) -> Self {
		vouched.map_or(Self::Direct, Self::Vouched)
	}

	/// Admit the sender of `frame`, a call of `method` with `body`, under
	/// `trust`, as [`AdmittedCall::admit`] states.
	///
	/// # Errors
	///
	/// - [`AdmissionFault::Refused`] -- the sender does not admit.
	fn admit(
		self,
		frame: &Frame,
		trust: &AdmissionTrust,
		method: &MethodPath,
		body: &[u8],
	) -> Result<AdmittedSender, AdmissionFault> {
		match self {
			Self::Vouched(origin) => {
				let vouchers = trust.vouchers.as_ref().ok_or(AdmissionFault::Refused)?;
				let signer = AdmittedSigner::of(frame, vouchers).ok_or(AdmissionFault::Refused)?;
				let principal = Principal::try_from(origin.principal).map_err(|_| AdmissionFault::Refused)?;
				let proof = origin.proof.admit(&principal, method, body, trust.claims.as_deref());
				let proof = proof.map_err(|_| AdmissionFault::Refused)?;
				Ok(AdmittedSender { principal, proof, signer })
			}
			Self::Direct => {
				let direct = trust.direct.as_ref().ok_or(AdmissionFault::Refused)?;
				let signer = AdmittedSigner::of(frame, direct).ok_or(AdmissionFault::Refused)?;
				let principal = Principal::of(&signer.certificate).ok_or(AdmissionFault::Refused)?;
				Ok(AdmittedSender { principal, proof: Proof::Signed(None), signer })
			}
		}
	}
}

/// A sender that admitted: the principal of its call, what the call proves,
/// and the signer that each later part of its stream verifies under.
struct AdmittedSender {
	principal: Principal,
	proof: Proof<Option<ForwardedClaim>>,
	signer: AdmittedSigner,
}

/// A unary coupled call that its servlet admitted.
#[derive(Debug)]
pub struct AdmittedCall {
	origin: Origin,
	body: Vec<u8>,
}

/// The certificate that signed an admitted frame, and the store that trusts
/// it, which every later part of its stream must verify under.
pub(crate) struct AdmittedSigner {
	certificate: Arc<Certificate>,
	store: Arc<dyn CertificateTrust>,
}

impl AdmittedSigner {
	/// The signer of `frame` under `store`, or `None` when the store does not
	/// verify it.
	fn of(frame: &Frame, store: &Arc<dyn CertificateTrust>) -> Option<Self> {
		let TrustVerification::Verified(signer, _) = store.verify_frame(frame) else {
			return None;
		};

		Some(Self { certificate: Arc::clone(signer.certificate()), store: Arc::clone(store) })
	}

	/// Whether the store verifies `frame` under the certificate of this
	/// signer.
	pub(crate) fn verifies(&self, frame: &Frame) -> bool {
		let TrustVerification::Verified(signer, _) = self.store.verify_frame(frame) else {
			return false;
		};

		**signer.certificate() == *self.certificate
	}
}

/// Why a frame does not admit as a coupled call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionFault {
	/// The frame holds no coupled call, names no valid method, or carries
	/// metadata that does not admit, its signer is not trusted for its origin,
	/// its origin or the certificate of its direct signer names no valid
	/// principal, or its claim does not verify.
	Refused,
	/// A unary call opens a stream, or a stream opens with a unary shape or a
	/// body, or with no stream terms.
	Malformed,
	/// The head of a stream declares a part ceiling past that of its servlet.
	Oversize,
}

impl AdmissionFault {
	/// The status that ends a call that does not admit.
	pub(crate) fn status(self) -> TransitStatus {
		match self {
			Self::Refused => TransitStatus::Unauthenticated,
			Self::Malformed => TransitStatus::InvalidArgument,
			Self::Oversize => TransitStatus::ResourceExhausted,
		}
	}
}

impl AdmittedCall {
	/// Admit the unary coupled call of `frame` under `trust`:
	///
	/// - A call with an origin admits when a voucher of `trust` signed the
	///   frame. Its principal is the principal of the origin.
	/// - A call with no origin admits when a direct caller of `trust` signed
	///   the frame. Its principal is the principal of the certificate of the
	///   signer, and its assurance is [`Assurance::Signed`].
	///
	/// A call with an origin takes one of three assurances:
	///
	/// - [`Assurance::Signed`] when its forwarded claim verifies for that
	///   principal, method, and body under the claim store.
	/// - [`Assurance::Vouched`] for a TLS origin with no claim.
	/// - [`Assurance::Bearer`] for a bearer origin, which no claim may join.
	///
	/// # Errors
	///
	/// Each refusal is a [`TightBeamError::WorkRefused`] of its status:
	///
	/// - [`TransitStatus::Unauthenticated`] -- the frame holds no coupled call, names no valid method, or
	///   carries metadata that does not admit, its signer is not trusted for its origin, its origin or the
	///   certificate of its direct signer names no valid principal, or its forwarded claim does not verify.
	/// - [`TransitStatus::InvalidArgument`] -- the frame opens a stream.
	pub fn admit(frame: &Frame, trust: &AdmissionTrust) -> Result<Self, TightBeamError> {
		let refused = |fault: AdmissionFault| TightBeamError::WorkRefused(fault.status());
		let Decoded { origin, body, stream, .. } = Origin::decode(frame, trust).map_err(refused)?;
		if stream.is_some() {
			return Err(refused(AdmissionFault::Malformed));
		}

		Ok(Self { origin, body })
	}

	/// Who made the call, and what it carries beside its body.
	pub fn origin(&self) -> &Origin {
		&self.origin
	}

	/// The encoded request message of the call.
	pub fn body(&self) -> &[u8] {
		&self.body
	}

	/// The reply of status 0 to the call, with the encoded response message
	/// `body`, in a frame that answers the id of the call and that `signer`
	/// signs.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a reply that does not build or sign.
	pub async fn reply(
		self,
		body: impl Into<Vec<u8>>,
		signer: &SigningIdentity,
	) -> Result<Option<Frame>, TightBeamError> {
		let reply = CoupledReply::ok(body.into())?;
		self.answer(reply, signer).await
	}

	/// The reply that fails the call with `status`: its code, its message, and
	/// its details, which the caller reads in `grpc-status-details-bin`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a reply that does not build or sign.
	pub async fn fail(self, status: &Status, signer: &SigningIdentity) -> Result<Option<Frame>, TightBeamError> {
		let reply = CoupledReply::of_status(status, Vec::new())?;
		self.answer(reply, signer).await
	}

	/// The frame of `reply`, which answers the id of the call and which
	/// `signer` signs.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a frame that does not build or sign.
	pub(crate) async fn answer(
		self,
		reply: CoupledReply,
		signer: &SigningIdentity,
	) -> Result<Option<Frame>, TightBeamError> {
		let mut frame = compose! {
			V1: id: self.origin.request_id.as_slice(),
				message: reply
		}?;

		frame.sign_with_provider(signer).await?;
		Ok(Some(frame))
	}
}
