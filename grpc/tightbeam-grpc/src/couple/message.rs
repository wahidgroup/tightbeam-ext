//! The DER messages of a coupled call: the call, the reply, the parts of a
//! stream, and the claim.

use core::time::Duration;

use tightbeam::crypto::x509::name::Name;
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::crypto::x509::Certificate;
use tightbeam::der::asn1::Null;
use tightbeam::der::asn1::OctetString;
use tightbeam::der::{self, Choice, Sequence};
use tightbeam::Beamable;
use tonic::{Code, Status};

use super::claim::VerifiedClaim;
use super::claim::{CallClaim, ForwardedClaim};
use super::error::CoupleError;
use super::fault::CallFault;
use super::metadata::{CallMetadata, Metadata, MetadataKey};
use super::method::MethodPath;
use super::principal::{Named, Principal};
use super::proof::Proof;
use super::routes::{Shape, StreamShape};

/// The encoded form of a [`Principal`], which [`Principal::try_from`] admits
/// back.
#[derive(Choice, Clone, Debug, Eq, PartialEq)]
pub(crate) enum PrincipalWire {
	Spiffe(String),
	Subject(Name),
}

/// The encoded form of the one name of a principal, which
/// [`Principal::try_from`] admits back.
impl From<&Named> for PrincipalWire {
	fn from(named: &Named) -> Self {
		match named {
			Named::Spiffe(id) => Self::Spiffe(id.as_str().to_owned()),
			Named::Subject(name) => Self::Subject(name.clone()),
		}
	}
}

/// A TLS client chain that proved a principal, of the connection or
/// forwarded by a pinned proxy, and the claim of the principal when it signed
/// one.
#[derive(Sequence, Clone, Debug, Eq, PartialEq)]
pub(crate) struct TlsProof {
	#[asn1(optional = "true")]
	pub(crate) claim: Option<OctetString>,
}

/// What proved the principal of a vouched call to the edge. A bearer token
/// carries no claim, because a claim binds to a TLS certificate.
#[derive(Choice, Clone, Debug, Eq, PartialEq)]
pub(crate) enum OriginProof {
	Tls(TlsProof),
	Bearer(Null),
}

/// How a proof travels to the servlet, in the origin that the voucher signs:
/// a bearer token carries no claim, and a TLS chain carries the claim of a
/// signed call.
///
/// # Errors
///
/// - [`CallFault::Internal`] -- the claim passes the length of a DER octet string.
impl TryFrom<&Proof<VerifiedClaim>> for OriginProof {
	type Error = CallFault;

	fn try_from(proof: &Proof<VerifiedClaim>) -> Result<Self, CallFault> {
		match proof {
			Proof::Bearer => Ok(Self::Bearer(Null)),
			Proof::Vouched => Ok(Self::Tls(TlsProof { claim: None })),
			Proof::Signed(claim) => {
				let forwarded = OctetString::new(claim.forwarded().to_vec()).map_err(|_| CallFault::Internal)?;
				Ok(Self::Tls(TlsProof { claim: Some(forwarded) }))
			}
		}
	}
}

impl OriginProof {
	/// What the origin proves at a servlet, for the call of `principal` of
	/// `method` with `body`: a forwarded claim verifies under `claims`.
	///
	/// # Errors
	///
	/// - [`CallFault::ClaimRefused`] -- the call forwards a claim, and the
	///   servlet trusts no claim signer, or the claim does not verify.
	pub(crate) fn admit(
		self,
		principal: &Principal,
		method: &MethodPath,
		body: &[u8],
		claims: Option<&dyn CertificateTrust>,
	) -> Result<Proof<Option<ForwardedClaim>>, CallFault> {
		match self {
			Self::Bearer(_) => Ok(Proof::Bearer),
			Self::Tls(TlsProof { claim: None }) => Ok(Proof::Vouched),
			Self::Tls(TlsProof { claim: Some(claim) }) => {
				let claims = claims.ok_or(CallFault::ClaimRefused)?;
				let claim = CallClaim::from_der(claim.as_bytes())?;
				let forwarded = claim.verify_for(principal, method, body, claims)?;
				Ok(Proof::Signed(Some(forwarded)))
			}
		}
	}
}

/// The origin of a call that a coupler vouches for: the principal that the
/// edge authenticated, and what proved it.
#[derive(Sequence, Clone, Debug, Eq, PartialEq)]
pub(crate) struct VouchedOrigin {
	pub(crate) principal: PrincipalWire,
	pub(crate) proof: OriginProof,
}

/// What the head of a stream fixes for both ends: the shape of its method,
/// and the most bytes of a part, which each end reads and sends under.
#[derive(Sequence, Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StreamTerms {
	shape: Shape,
	part_ceiling: u64,
}

impl StreamTerms {
	/// The terms of a stream of `shape` whose parts take at most
	/// `part_ceiling` bytes.
	pub(crate) fn new(shape: StreamShape, part_ceiling: u64) -> Self {
		Self { shape: shape.into(), part_ceiling }
	}

	/// How many messages each side of the stream sends.
	pub(crate) fn shape(&self) -> Shape {
		self.shape
	}

	/// The most bytes of a part, on this host.
	pub(crate) fn ceiling(&self) -> usize {
		usize::try_from(self.part_ceiling).unwrap_or(usize::MAX)
	}
}

/// One metadata entry as a call carries it: a key that `MetadataKey` admits,
/// and its value, decoded for a key that ends in `-bin`.
#[derive(Sequence, Clone, Debug, Eq, PartialEq)]
pub(crate) struct MetadataEntry {
	pub(crate) key: String,
	pub(crate) value: OctetString,
}

/// The entry of `metadata` as a call carries it.
///
/// # Errors
///
/// - [`CoupleError::Encoding`] -- the value passes the length of a DER octet string.
impl TryFrom<Metadata<'_>> for MetadataEntry {
	type Error = CoupleError;

	fn try_from(metadata: Metadata<'_>) -> Result<Self, CoupleError> {
		let value = OctetString::new(metadata.value.to_vec()).map_err(CoupleError::Encoding)?;
		Ok(Self { key: metadata.key.to_owned(), value })
	}
}

/// One coupled call, in a frame that its sender signs. A servlet admits it
/// through [`AdmittedCall::admit`](super::AdmittedCall::admit), which reads
/// the principal and the assurance from a direct signer, or a vouched origin.
///
/// The head of a stream is a call with an empty body and its stream terms.
#[derive(Beamable, Sequence, Clone, Debug, Eq, PartialEq)]
#[beam(min_version = "V1")]
pub struct CoupledCall {
	method: String,
	#[asn1(context_specific = "0", optional = "true")]
	vouched: Option<VouchedOrigin>,
	body: OctetString,
	/// The milliseconds that remained of the deadline when the sender signed.
	#[asn1(context_specific = "1", optional = "true")]
	timeout: Option<u64>,
	#[asn1(context_specific = "2", optional = "true")]
	metadata: Option<Vec<MetadataEntry>>,
	#[asn1(context_specific = "3", optional = "true")]
	stream: Option<StreamTerms>,
}

/// What a decoded [`CoupledCall`] carries, which its servlet admits.
pub(crate) struct CallParts {
	pub(crate) method: MethodPath,
	pub(crate) vouched: Option<VouchedOrigin>,
	pub(crate) body: Vec<u8>,
	pub(crate) timeout: Option<u64>,
	pub(crate) metadata: Option<Vec<MetadataEntry>>,
	pub(crate) stream: Option<StreamTerms>,
}

impl CoupledCall {
	/// The call of `method` with the encoded request `body` that a native
	/// tightbeam client makes in its own name, as the principal of the
	/// identity that signs its frame.
	///
	/// # Errors
	///
	/// - [`CoupleError::Method`] -- `method` is no [`MethodPath`].
	/// - [`CoupleError::Encoding`] -- `body` passes the length of a DER octet string.
	pub fn direct<M>(method: M, body: impl Into<Vec<u8>>) -> Result<Self, CoupleError>
	where
		M: TryInto<MethodPath>,
		CoupleError: From<M::Error>,
	{
		let method: MethodPath = method.try_into()?;
		let body = OctetString::new(body.into()).map_err(CoupleError::Encoding)?;
		Ok(Self {
			method: method.as_str().to_owned(),
			vouched: None,
			body,
			timeout: None,
			metadata: None,
			stream: None,
		})
	}

	/// The call with a deadline of `timeout`, which the servlet reads.
	#[must_use]
	pub fn with_timeout(mut self, timeout: Duration) -> Self {
		let millis = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
		self.timeout = Some(millis);
		self
	}

	/// The call with the metadata entry `key` and `value`, which the servlet
	/// reads and a backend adapter forwards.
	///
	/// # Errors
	///
	/// - [`CoupleError::Metadata`] -- `key` or `value` is no metadata that a call carries.
	/// - [`CoupleError::Encoding`] -- `value` passes the length of a DER octet string.
	pub fn with_metadata(mut self, key: impl AsRef<str>, value: impl Into<Vec<u8>>) -> Result<Self, CoupleError> {
		let key = MetadataKey::new(key.as_ref())?;
		let pair = key.pair(value.into())?;
		let entry = MetadataEntry::try_from(pair.metadata())?;
		self.metadata.get_or_insert_with(Vec::new).push(entry);
		Ok(self)
	}

	/// The head of a stream of `method` under `terms`: a call with an empty
	/// body.
	///
	/// # Errors
	///
	/// - The errors of [`CoupledCall::direct`].
	pub(crate) fn head(method: &MethodPath, terms: StreamTerms) -> Result<Self, CoupleError> {
		let head = Self::direct(method.clone(), Vec::new())?;
		Ok(Self { stream: Some(terms), ..head })
	}

	/// What the call carries, once its method parses.
	///
	/// # Errors
	///
	/// - [`CoupleError::Method`] -- the method is no [`MethodPath`].
	pub(crate) fn into_parts(self) -> Result<CallParts, CoupleError> {
		let Self { method, vouched, body, timeout, metadata, stream } = self;
		let method = MethodPath::try_from(method.as_str())?;
		let body = body.into_bytes();
		Ok(CallParts { method, vouched, body, timeout, metadata, stream })
	}

	/// The call vouched for `origin`, with the metadata that the coupler
	/// forwards.
	pub(crate) fn vouched_for(mut self, origin: VouchedOrigin, metadata: &CallMetadata) -> Result<Self, CoupleError> {
		let entries = metadata.iter().map(MetadataEntry::try_from).collect::<Result<Vec<_>, _>>()?;
		self.vouched = Some(origin);
		self.metadata = (!entries.is_empty()).then_some(entries);
		Ok(self)
	}
}

/// The answer of a servlet to a coupled call: the gRPC status code, its
/// message, its details, and the body of the response.
///
/// The last part of the answer of a stream is a reply with an empty body.
#[derive(Beamable, Sequence, Clone, Debug, Eq, PartialEq)]
#[beam(min_version = "V1")]
pub struct CoupledReply {
	code: i32,
	#[asn1(context_specific = "0", optional = "true")]
	message: Option<String>,
	body: OctetString,
	/// The encoded `google.rpc.Status` that `grpc-status-details-bin` carries.
	#[asn1(context_specific = "1", optional = "true")]
	details: Option<OctetString>,
}

impl CoupledReply {
	/// The reply of `status`, its code, its message, and its details, with the
	/// response `body`. An empty message or empty details travel as none, so
	/// [`CoupledReply::into_result`] gives `status` back.
	///
	/// # Errors
	///
	/// - The [`der::Error`] of a body or details past the length of a DER octet string.
	pub(crate) fn of_status(status: &Status, body: Vec<u8>) -> Result<Self, der::Error> {
		let message = (!status.message().is_empty()).then(|| status.message().to_owned());
		let details = (!status.details().is_empty()).then(|| status.details().to_vec());
		let details = details.map(OctetString::new).transpose()?;
		let body = OctetString::new(body)?;
		Ok(Self { code: status.code() as i32, message, body, details })
	}

	/// The reply of status 0 with the response `body`.
	///
	/// # Errors
	///
	/// - The errors of [`CoupledReply::of_status`].
	pub(crate) fn ok(body: Vec<u8>) -> Result<Self, der::Error> {
		Self::of_status(&Status::new(Code::Ok, ""), body)
	}

	/// The gRPC status code of the answer.
	pub fn code(&self) -> Code {
		Code::from_i32(self.code)
	}

	/// The status message of the answer, when it carries one.
	pub fn message(&self) -> Option<&str> {
		self.message.as_deref()
	}

	/// The encoded response message of the answer.
	pub fn body(&self) -> &[u8] {
		self.body.as_bytes()
	}

	/// The encoded `google.rpc.Status` of the answer, when it carries one.
	pub fn details(&self) -> Option<&[u8]> {
		self.details.as_ref().map(OctetString::as_bytes)
	}

	/// The answer as a caller reads it: the response body for status 0, and
	/// the status, its message, and its details otherwise.
	///
	/// # Errors
	///
	/// - The [`Status`] of an answer with a code other than 0.
	pub fn into_result(self) -> Result<Vec<u8>, Status> {
		let code = self.code();
		if code == Code::Ok {
			return Ok(self.body.into_bytes());
		}

		let message = self.message.unwrap_or_default();
		match self.details {
			Some(details) => Err(Status::with_details(code, message, details.into_bytes().into())),
			None => Err(Status::new(code, message)),
		}
	}
}

/// What one part of a stream carries: a message, or the status that ends an
/// answer.
#[derive(Choice, Clone, Debug, Eq, PartialEq)]
pub(crate) enum PartWire {
	Message(OctetString),
	End(CoupledReply),
}

impl PartWire {
	/// What the part carries: its message, or as `Err` the reply that ends an
	/// answer.
	pub(crate) fn carried(self) -> Result<OctetString, CoupledReply> {
		match self {
			Self::Message(message) => Ok(message),
			Self::End(end) => Err(end),
		}
	}
}

/// One part of a coupled stream after its head, in a frame that its sender
/// signs under the id of the call and an order that counts from 1.
#[derive(Beamable, Sequence, Clone, Debug, Eq, PartialEq)]
#[beam(min_version = "V1")]
pub(crate) struct CoupledPart {
	pub(super) part: PartWire,
}

/// What a claim covers: the method, the SHA-256 of the body, and the SHA-256
/// of the TLS certificate of its caller.
#[derive(Beamable, Sequence, Clone, Debug, Eq, PartialEq)]
#[beam(min_version = "V1")]
pub(crate) struct ClaimBody {
	pub(crate) method: String,
	pub(crate) body_digest: OctetString,
	pub(crate) leaf_digest: OctetString,
}

/// A claim as it travels: the DER of the signed frame of a [`ClaimBody`],
/// the certificate of its signer, and the issuers above that certificate.
#[derive(Sequence, Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimEnvelope {
	pub(crate) frame: OctetString,
	pub(crate) signer: Certificate,
	pub(crate) issuers: Vec<Certificate>,
}
