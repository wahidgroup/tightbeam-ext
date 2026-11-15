//! Why a coupled call is refused, and the gRPC status the caller reads.
//!
//! # Sources
//!
//! - gRPC status codes, `grpc/grpc` `doc/statuscodes.md`:
//!   <https://github.com/grpc/grpc/blob/master/doc/statuscodes.md>

use tightbeam::clock::Lapse;
use tightbeam::policy::TransitStatus;
use tonic::{Code, Status};

use super::routes::AccessRefusal;
use crate::incoming::LaneRefusal;

/// Why the coupler refuses a call, which decides the status of its answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallFault {
	/// The call proves no caller: its verified client chain names no
	/// principal, or it has no verified client chain of its own or of a
	/// pinned proxy, and no bearer token.
	Unauthenticated,
	/// The policy of the coupler refuses the call: no route serves its
	/// method, no grant names its principal for it, or it proves less
	/// assurance than the route requires.
	Access(AccessRefusal),
	/// The `grpc-timeout` of the call does not parse.
	Timeout,
	/// The lane of the connection carries no coupled call now, for this
	/// reason.
	Lane(LaneRefusal),
	/// The loopback session is not open, fails, or runs one call at a time
	/// when a stream needs it multiplexed, the stream to the servlet fails
	/// with no status, ends in the middle of a part, or refuses a part, or the
	/// claim ledger fails a spend.
	Unavailable,
	/// The claim of the call does not verify, names another principal, or
	/// covers another method, body, or TLS certificate.
	ClaimRefused,
	/// The claim was spent already, or it falls outside the replay window.
	Replayed,
	/// The work frame of the call, or a part of its stream, passes its ceiling.
	Oversize,
	/// The deadline of the call passed before the answer, or the clock gave a
	/// wait of its send no timer.
	Deadline,
	/// A wait of the send, or of a part of the stream, of the call passed the
	/// read deadline of an end of the loopback session, after its frame may
	/// have left, or the gateway answered the call with `DEADLINE_EXCEEDED`.
	/// tightbeam reports both alike, so the coupler cannot tell them apart.
	Stalled,
	/// The gateway refused the work with this status.
	Transit(TransitStatus),
	/// An answer or a part does not verify under the signer of the route,
	/// answers another request or order, or ends with no status.
	AnswerRefused,
	/// The coupler failed to build, sign, encode, or decode a frame of the
	/// call, the expiry of its claim passes the range of the clock, or the
	/// clock gave no timer to a wait of the call other than its send.
	Internal,
	/// A metadata value that the coupler forwards does not decode, or holds a
	/// byte that its key does not admit.
	Metadata,
	/// The caller sends more request messages than its method takes, or none
	/// to a method that takes one.
	Shape,
	/// The servlet answers more messages than the method takes, or ends with
	/// status 0 and none.
	AnswerShape,
	/// The edge carries its most streams at once.
	Streams,
	/// The caller ended the call before its answer did.
	Cancelled,
	/// tonic refused the request of the call with this code, such as a
	/// message past the envelope ceiling of the edge.
	Refused(Code),
}

impl CallFault {
	/// The name that the audit trail records the refusal under.
	#[cfg(feature = "instrument")]
	pub(crate) fn as_str(&self) -> &'static str {
		match self {
			Self::Unauthenticated => "unauthenticated",
			Self::Access(refusal) => refusal.as_str(),
			Self::Lane(refusal) => refusal.as_str(),
			Self::Timeout => "timeout",
			Self::Unavailable => "unavailable",
			Self::ClaimRefused => "claim-refused",
			Self::Replayed => "replayed",
			Self::Oversize => "oversize",
			Self::Deadline => "deadline",
			Self::Stalled => "stalled",
			Self::Transit(_) => "transit",
			Self::AnswerRefused => "answer-refused",
			Self::Internal => "internal",
			Self::Metadata => "metadata",
			Self::Shape => "shape",
			Self::AnswerShape => "answer-shape",
			Self::Streams => "streams",
			Self::Cancelled => "cancelled",
			Self::Refused(_) => "refused",
		}
	}

	/// The status that answers the refusal.
	pub(crate) fn status(&self) -> Status {
		match self {
			Self::Unauthenticated => Status::unauthenticated("the call proves no caller that the edge trusts"),
			Self::Access(refusal) => refusal.status(),
			Self::Timeout => Status::invalid_argument("the grpc-timeout of the call does not parse"),
			Self::Lane(_) | Self::Unavailable => Status::unavailable("the edge cannot carry the call now"),
			Self::ClaimRefused => Status::unauthenticated("the claim of the call does not verify"),
			Self::Replayed => Status::unauthenticated("the claim of the call was spent or is stale"),
			Self::Oversize => Status::resource_exhausted("the call passes the envelope ceiling of the edge"),
			Self::Deadline => Status::deadline_exceeded("the call passed its deadline"),
			Self::Stalled => Status::deadline_exceeded("the call passed a deadline on the loopback session"),
			Self::Transit(status) => Self::transit(*status),
			Self::AnswerRefused => Status::internal("the answer of the servlet does not verify"),
			Self::Internal => Status::internal("the coupler failed to carry the call"),
			Self::Metadata => Status::invalid_argument("a forwarded metadata value of the call does not decode"),
			Self::Shape => Status::unimplemented("the call sends a count of messages that its method does not take"),
			Self::AnswerShape => {
				Status::unimplemented("the servlet answers a count of messages that the method does not take")
			}
			Self::Streams => Status::resource_exhausted("the edge carries its most streams at once"),
			Self::Cancelled => Status::cancelled("the caller ended the call"),
			Self::Refused(code) => Status::new(*code, "tonic refused the request of the call"),
		}
	}

	/// The status of a refusal of the gateway: tightbeam's transit statuses
	/// number the gRPC codes.
	fn transit(status: TransitStatus) -> Status {
		let code = Code::from_i32(status as i32);
		Status::new(code, "the gateway refused the work")
	}
}

/// The status that tonic refuses the request of a call with is the fault of
/// the call: `Cancelled` when its caller ended it, and a refusal of that code
/// otherwise.
impl From<Status> for CallFault {
	fn from(status: Status) -> Self {
		match status.code() {
			Code::Cancelled => Self::Cancelled,
			code => Self::Refused(code),
		}
	}
}

/// A bound on the clock of the coupler that lapsed is the fault of its call:
/// the deadline when the span passed, and an internal fault when the clock
/// gave the wait no timer.
impl From<Lapse> for CallFault {
	fn from(lapse: Lapse) -> Self {
		match lapse {
			Lapse::Passed => Self::Deadline,
			Lapse::NoTimer => Self::Internal,
		}
	}
}

/// A refusal of the policy is the fault of its call.
impl From<AccessRefusal> for CallFault {
	fn from(refusal: AccessRefusal) -> Self {
		Self::Access(refusal)
	}
}
