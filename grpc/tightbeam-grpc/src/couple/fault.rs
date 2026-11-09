//! Why a coupled call is refused, and the gRPC status the caller reads.
//!
//! # Sources
//!
//! - gRPC status codes, `grpc/grpc` `doc/statuscodes.md`: <https://github.com/grpc/grpc/blob/master/doc/statuscodes.md>

use tightbeam::policy::TransitStatus;
use tonic::{Code, Status};

/// Why the coupler refuses a call, which decides the status of its answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallFault {
	/// The connection carries no verified TLS client chain that names a
	/// principal.
	Unauthenticated,
	/// The edge routes no such method.
	Unrouted,
	/// The `grpc-timeout` of the call does not parse.
	Timeout,
	/// No coupled lane is free, the connection carries a tunnel, or the
	/// loopback session is not open.
	Unavailable,
	/// The claim of the call does not verify, names another principal, or
	/// covers another method, body, or TLS certificate.
	ClaimRefused,
	/// The claim was spent already, or it falls outside the replay window.
	Replayed,
	/// No grant names the principal for the method, or the call proves less
	/// assurance than the route requires.
	Denied,
	/// The work frame of the call passes the envelope ceiling of the edge.
	Oversize,
	/// The deadline of the call passed before the answer.
	Deadline,
	/// The gateway refused the work with this status.
	Transit(TransitStatus),
	/// The answer does not verify under the signer of the route, or answers
	/// another request.
	AnswerRefused,
	/// The coupler failed to build or to send the work.
	Internal,
}

impl CallFault {
	/// The name that the audit trail records the refusal under.
	#[cfg(feature = "instrument")]
	pub(crate) const fn as_str(&self) -> &'static str {
		match self {
			Self::Unauthenticated => "unauthenticated",
			Self::Unrouted => "unrouted",
			Self::Timeout => "timeout",
			Self::Unavailable => "unavailable",
			Self::ClaimRefused => "claim-refused",
			Self::Replayed => "replayed",
			Self::Denied => "denied",
			Self::Oversize => "oversize",
			Self::Deadline => "deadline",
			Self::Transit(_) => "transit",
			Self::AnswerRefused => "answer-refused",
			Self::Internal => "internal",
		}
	}

	/// The status that answers the refusal.
	pub(crate) fn status(&self) -> Status {
		match self {
			Self::Unauthenticated => Status::unauthenticated("the call carries no verified client certificate"),
			Self::Unrouted => Status::unimplemented("the edge routes no such method"),
			Self::Timeout => Status::invalid_argument("the grpc-timeout of the call does not parse"),
			Self::Unavailable => Status::unavailable("the edge cannot carry the call now"),
			Self::ClaimRefused => Status::unauthenticated("the claim of the call does not verify"),
			Self::Replayed => Status::unauthenticated("the claim of the call was spent or is stale"),
			Self::Denied => Status::permission_denied("the caller may not call the method"),
			Self::Oversize => Status::resource_exhausted("the call passes the envelope ceiling of the edge"),
			Self::Deadline => Status::deadline_exceeded("the call passed its deadline"),
			Self::Transit(status) => Self::transit(*status),
			Self::AnswerRefused => Status::internal("the answer of the servlet does not verify"),
			Self::Internal => Status::internal("the coupler failed to carry the call"),
		}
	}

	/// The status of a refusal of the gateway: tightbeam's transit statuses
	/// number the gRPC codes.
	fn transit(status: TransitStatus) -> Status {
		let code = Code::from_i32(status as i32);
		Status::new(code, "the gateway refused the work")
	}
}
