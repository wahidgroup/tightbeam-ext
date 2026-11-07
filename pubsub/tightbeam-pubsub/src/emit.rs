//! What one emit of a frame settles as.
//!
//! [`Emitter`] owns the handle of one link and sorts each failure of
//! [`MuxHandle::emit_on_stream`] once. The registry and an application that
//! emits beside it read that one decision: [`Settled`] for a frame the link
//! answered or refused, and [`LinkLost`] for the end of the link.

use core::error::Error;
use core::fmt;

use tightbeam::clock::Lapse;
use tightbeam::transport::error::{TransportError, TransportFailure};
use tightbeam::transport::multiplex::MuxHandle;
use tightbeam::transport::TransportResult;
use tightbeam::Frame;

/// The emitter of one link: the handle each frame leaves on, and the sort of
/// each failed emit.
///
/// # Examples
///
/// ```
/// use tightbeam::transport::handshake::negotiation::MuxSettings;
/// use tightbeam_pubsub::testing::{MemoryLink, OpaqueFrame};
/// use tightbeam_pubsub::{Emitter, Settled};
///
/// # async fn emit() -> Result<(), Box<dyn std::error::Error>> {
/// let (_client, server) = MemoryLink::default().mux_pair(MuxSettings::symmetric(4));
/// let (handle, _reader, _writer, _responder) = server.into_parts();
/// let emitter = Emitter::from(handle);
/// let notice = OpaqueFrame { id: "notice", order: 1, payload: b"ping" }.build()?;
///
/// let settled = emitter.until_settled(&notice).await?;
/// if let Settled::Refused(cause) = settled {
///     eprintln!("the peer refused the notice: {cause}");
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Emitter {
	handle: MuxHandle,
}

impl From<MuxHandle> for Emitter {
	fn from(handle: MuxHandle) -> Self {
		Self { handle }
	}
}

impl Emitter {
	/// Emit `frame` until the emit settles.
	///
	/// An emit that finds every local stream slot in flight waits for a free
	/// slot, then emits again.
	///
	/// # Errors
	///
	/// - [`LinkLost`]: the emit or the wait for a stream slot counts as the end of the link.
	pub async fn until_settled(&self, frame: &Frame) -> Result<Settled, LinkLost> {
		loop {
			let emitted = self.handle.emit_on_stream(frame).await;
			let attempt = Attempt::from(emitted);
			match attempt {
				Attempt::Settled(settled) => return Ok(settled),
				Attempt::Lost(lost) => return Err(lost),
				Attempt::Busy => {}
			}

			let freed = self.handle.wait_for_stream_slot().await;
			freed.map_err(LinkLost)?;
		}
	}
}

/// What a settled emit of one frame came to, while the link stays up.
#[derive(Debug)]
pub enum Settled {
	/// The peer accepted the frame, with the frame it answered, if any.
	Answered(Option<Box<Frame>>),
	/// Only this frame is lost.
	///
	/// The peer answered with a refusal, or the session budget cannot carry
	/// the frame until a renewal restores it.
	Refused(TransportError),
}

/// An emit that counts as the end of the link it ran on.
///
/// The link failed or drains, the frame or its reply broke a local rule, or
/// the emit outlived its deadline on the clock of the link.
#[derive(Debug)]
pub struct LinkLost(TransportError);

impl LinkLost {
	/// The loss of an emit that ran past its deadline, as `lapse` reports it.
	pub(crate) fn lapsed(lapse: Lapse) -> Self {
		let cause = TransportError::from(lapse);
		Self(cause)
	}
}

impl fmt::Display for LinkLost {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "the emit counts as the end of the link: {}", self.0)
	}
}

impl Error for LinkLost {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		Some(&self.0)
	}
}

/// One attempt of an emit, sorted by what it asks of the [`Emitter`].
enum Attempt {
	/// The attempt settled the emit.
	Settled(Settled),
	/// Every local stream slot is in flight. The frame goes again once
	/// [`MuxHandle::wait_for_stream_slot`] resolves.
	Busy,
	/// The attempt counts as the end of the link.
	Lost(LinkLost),
}

impl From<TransportResult<Option<Frame>>> for Attempt {
	/// Sort one attempt by what it costs the link.
	///
	/// An answer settles the emit. A refusal of the peer
	/// ([`TransportError::transit_status`]) refuses one frame. Of the local
	/// failures, an exhausted session budget refuses one frame, an exhausted
	/// stream cap waits, and every other failure counts as the end of the link.
	fn from(emitted: TransportResult<Option<Frame>>) -> Self {
		let error = match emitted {
			Ok(answer) => return Self::Settled(Settled::Answered(answer.map(Box::new))),
			Err(error) => error,
		};
		if error.transit_status().is_some() {
			return Self::refused(error);
		}

		match error {
			TransportError::OperationFailed(TransportFailure::StreamsExhausted) => Self::Busy,
			TransportError::OperationFailed(TransportFailure::BudgetExhausted) => Self::refused(error),
			lost => Self::Lost(LinkLost(lost)),
		}
	}
}

impl Attempt {
	/// The attempt whose frame alone is lost, for `cause`.
	fn refused(cause: TransportError) -> Self {
		Self::Settled(Settled::Refused(cause))
	}
}

#[cfg(test)]
mod tests {
	use core::time::Duration;

	use tightbeam::policy::TransitStatus;
	use tightbeam::transport::handshake::negotiation::MuxSettings;
	use tightbeam::transport::multiplex::SpawnedMux;
	use tightbeam::transport::ResponsePackage;
	use tokio::task::yield_now;
	use tokio::time::timeout;

	use super::*;
	use crate::testing::{MemoryLink, OpaqueFrame};

	/// Bound every wait on a live link, so a regression fails instead of
	/// hanging.
	const DEADLINE: Duration = Duration::from_secs(2);

	/// The frame every test emits.
	fn notice() -> Frame {
		let notice = OpaqueFrame { id: "notice", order: 1, payload: b"ping" };
		notice.build().expect("the notice builds")
	}

	/// The handle of one end of a link under `settings`, whose peer answers
	/// every stream with `Ok`. The returned guard keeps both ends alive.
	fn answered(settings: MuxSettings) -> (MuxHandle, impl Sized) {
		let (peer, local) = MemoryLink::default().mux_pair(settings);
		let SpawnedMux { handle: peer_handle, responder, drivers: peer_drivers } = peer.spawn();
		let answer = |_| async { ResponsePackage::new(TransitStatus::Ok, None) };
		let answering = tokio::spawn(responder.serve(answer));

		let SpawnedMux { handle, responder: unserved, drivers } = local.spawn();
		let guard = (peer_handle, peer_drivers, answering.abort_handle(), unserved, drivers);
		(handle, guard)
	}

	/// The handle of one end of a link whose peer end is gone. The returned
	/// guard keeps this end alive.
	fn closed() -> (MuxHandle, impl Sized) {
		let (peer, local) = MemoryLink::default().mux_pair(MuxSettings::symmetric(4));
		drop(peer);

		let SpawnedMux { handle, responder, drivers } = local.spawn();
		(handle, (responder, drivers))
	}

	#[tokio::test]
	async fn a_budget_exhausted_emit_settles_as_refused() {
		let unfunded = MuxSettings::symmetric(4).with_send_budget(Some(0));
		let (handle, _peer) = answered(unfunded);
		let emitter = Emitter::from(handle);
		let notice = notice();

		let settling = emitter.until_settled(&notice);
		let settled = timeout(DEADLINE, settling).await;
		assert!(matches!(settled, Ok(Ok(Settled::Refused(_)))));
	}

	#[tokio::test]
	async fn a_closed_link_emit_returns_link_lost() {
		let (handle, _end) = closed();
		let emitter = Emitter::from(handle);
		let notice = notice();

		let settling = emitter.until_settled(&notice);
		let settled = timeout(DEADLINE, settling).await;
		assert!(matches!(settled, Ok(Err(LinkLost(_)))));
	}

	#[tokio::test]
	async fn a_full_stream_cap_waits_then_emits() -> Result<(), TransportError> {
		let (handle, _peer) = answered(MuxSettings::symmetric(1));
		let held = handle.open_stream()?;
		let emitter = Emitter::from(handle);
		let notice = notice();

		let settling = tokio::spawn(async move { emitter.until_settled(&notice).await });
		yield_now().await;

		let parked = !settling.is_finished();
		drop(held);
		let settled = timeout(DEADLINE, settling).await;
		assert!(parked);
		assert!(matches!(settled, Ok(Ok(Ok(Settled::Answered(None))))));
		Ok(())
	}
}
