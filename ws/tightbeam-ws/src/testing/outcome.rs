//! How the read of a dialing transport ended, as the spec of a scenario
//! grades it.
//!
//! The emit path of tightbeam files no refusal event for an answer that its
//! read refuses before the decode, so a scenario that dials a hostile peer
//! records the outcome of the read itself, and its spec grades the name.

use tightbeam::trace::TraceCollector;
use tightbeam::transport::error::{TransportError, TransportFailure};
use tightbeam::urn::Urn;
use tightbeam::{urn, TightBeamError};

/// How the read of a dialing transport ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadOutcome {
	/// The read delivered a message.
	Delivered,
	/// The connection under the read failed.
	Io,
	/// The connection under the read closed.
	Closed,
	/// The read refused a message past the ceiling of its endpoint.
	SizeExceeded,
	/// The read failed for another reason.
	Other,
}

impl ReadOutcome {
	/// The event that records an outcome on the trace of a scenario, with its
	/// name as the value.
	pub const EVENT: Urn<'static> = urn!("test", "event:transport/read-outcome");

	/// The outcome of `read`.
	pub fn of<T>(read: &Result<T, TransportError>) -> Self {
		match read {
			Ok(_) => Self::Delivered,
			Err(TransportError::IoError(_)) => Self::Io,
			Err(TransportError::ConnectionClosed) => Self::Closed,
			Err(TransportError::OperationFailed(TransportFailure::SizeExceeded)) => Self::SizeExceeded,
			Err(_) => Self::Other,
		}
	}

	/// The name that a spec grades: `delivered`, `io`, `closed`,
	/// `size-exceeded`, or `other`.
	pub const fn as_str(self) -> &'static str {
		match self {
			Self::Delivered => "delivered",
			Self::Io => "io",
			Self::Closed => "closed",
			Self::SizeExceeded => "size-exceeded",
			Self::Other => "other",
		}
	}

	/// Record the outcome of `read` on `trace` as [`ReadOutcome::EVENT`].
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace refused the event.
	pub fn record<T>(read: &Result<T, TransportError>, trace: &TraceCollector) -> Result<(), TightBeamError> {
		let outcome = Self::of(read);
		trace.event_with(Self::EVENT, &[], outcome.as_str())?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use std::io;

	use super::*;

	#[test]
	fn each_read_names_its_outcome() {
		let delivered: Result<(), TransportError> = Ok(());
		let io = Err(TransportError::IoError(io::Error::other("reset")));
		let closed = Err(TransportError::ConnectionClosed);
		let size = Err(TransportError::OperationFailed(TransportFailure::SizeExceeded));
		let other = Err(TransportError::InvalidState);
		assert_eq!(ReadOutcome::of(&delivered), ReadOutcome::Delivered);
		assert_eq!(ReadOutcome::of::<()>(&io), ReadOutcome::Io);
		assert_eq!(ReadOutcome::of::<()>(&closed), ReadOutcome::Closed);
		assert_eq!(ReadOutcome::of::<()>(&size), ReadOutcome::SizeExceeded);
		assert_eq!(ReadOutcome::of::<()>(&other), ReadOutcome::Other);
	}
}
