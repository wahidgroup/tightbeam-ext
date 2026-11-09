//! The DER messages of a coupled call: the call a servlet receives, the reply
//! it answers with, and the claim a caller signs.

use tightbeam::crypto::x509::name::Name;
use tightbeam::crypto::x509::Certificate;
use tightbeam::der::asn1::OctetString;
use tightbeam::der::{self, Choice, Sequence};
use tightbeam::Beamable;

use super::principal::Principal;

/// The wire form of a [`Principal`], which [`Principal::try_from`] admits
/// back.
#[derive(Choice, Clone, Debug, Eq, PartialEq)]
pub(crate) enum PrincipalWire {
	Spiffe(String),
	Subject(Name),
}

impl From<&Principal> for PrincipalWire {
	fn from(principal: &Principal) -> Self {
		match principal {
			Principal::Spiffe(id) => Self::Spiffe(id.clone()),
			Principal::Subject(name) => Self::Subject(name.clone()),
		}
	}
}

/// A SPIFFE ID from the wire passes the rule of [`Principal::spiffe`].
impl TryFrom<PrincipalWire> for Principal {
	type Error = crate::edge::EdgeError;

	fn try_from(wire: PrincipalWire) -> Result<Self, Self::Error> {
		match wire {
			PrincipalWire::Spiffe(id) => Self::spiffe(id),
			PrincipalWire::Subject(name) => Ok(Self::Subject(name)),
		}
	}
}

/// The origin of a call that a coupler vouches for: the principal that the
/// edge authenticated, and the claim of that principal when it signed one.
#[derive(Sequence, Clone, Debug, Eq, PartialEq)]
pub(crate) struct VouchedOrigin {
	pub(crate) principal: PrincipalWire,
	#[asn1(optional = "true")]
	pub(crate) claim: Option<OctetString>,
}

/// One coupled call, as a servlet receives it in a frame that its sender
/// signed. The sender signs under a signing identity after the frame builds,
/// so the type sets no signing requirement of the builder, and the admission
/// of the servlet refuses a frame that carries no signature.
///
/// A frame from a coupler carries the origin of the call, and the coupler
/// signed it. A frame with no origin comes direct from its principal, who
/// signed it. A servlet reads neither field itself: it admits the frame
/// through `AdmittedCall::admit`, which decides the principal and the
/// assurance from the signer.
#[derive(Beamable, Sequence, Clone, Debug, Eq, PartialEq)]
#[beam(min_version = "V1")]
pub struct CoupledCall {
	pub(crate) method: String,
	#[asn1(context_specific = "0", optional = "true")]
	pub(crate) vouched: Option<VouchedOrigin>,
	pub(crate) body: OctetString,
}

impl CoupledCall {
	/// The call of `method` with the encoded request `body` that a native
	/// tightbeam client makes in its own name, as the principal of the
	/// identity that signs its frame.
	///
	/// # Errors
	///
	/// - [`der::Error`] -- `body` passes the length of a DER octet string.
	pub fn direct(method: impl Into<String>, body: impl Into<Vec<u8>>) -> Result<Self, der::Error> {
		let body = OctetString::new(body.into())?;
		Ok(Self { method: method.into(), vouched: None, body })
	}
}

/// The answer of a servlet to a coupled call: the gRPC status code, its
/// message, and the body of the response.
#[derive(Beamable, Sequence, Clone, Debug, Eq, PartialEq)]
#[beam(min_version = "V1")]
pub struct CoupledReply {
	pub(crate) code: i32,
	#[asn1(context_specific = "0", optional = "true")]
	pub(crate) message: Option<String>,
	pub(crate) body: OctetString,
}

impl CoupledReply {
	/// The gRPC status code of the answer.
	pub fn code(&self) -> tonic::Code {
		tonic::Code::from_i32(self.code)
	}

	/// The status message of the answer, when it carries one.
	pub fn message(&self) -> Option<&str> {
		self.message.as_deref()
	}

	/// The encoded response message of the answer.
	pub fn body(&self) -> &[u8] {
		self.body.as_bytes()
	}
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
