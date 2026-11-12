//! The emitter of a link, which bounds each emit by its deadline. The page
//! `docs/pubsub.md` (Emitter) states what an emit settles as.

use core::error::Error;
use core::fmt;
use core::pin::pin;
use core::time::Duration;

use tightbeam::clock::{Lapse, Timer};
use tightbeam::constants::DEFAULT_OPERATION_TIMEOUT;
use tightbeam::transport::error::{TransportError, TransportFailure};
use tightbeam::transport::multiplex::MuxHandle;
use tightbeam::transport::TransportResult;
use tightbeam::Frame;
use tightbeam_ws::serve::{RacingClock, ServedMux};

/// How long one emit may take to settle.
///
/// The span is above zero, because no emit finishes in zero time. The
/// default is [`DEFAULT_OPERATION_TIMEOUT`], the deadline of one write on an
/// established tightbeam session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmitDeadline(Duration);

impl EmitDeadline {
	/// A deadline of `span`, or `None` for a zero span.
	#[must_use]
	pub const fn new(span: Duration) -> Option<Self> {
		if span.is_zero() {
			return None;
		}

		Some(Self(span))
	}
}

impl Default for EmitDeadline {
	fn default() -> Self {
		Self(DEFAULT_OPERATION_TIMEOUT)
	}
}

/// The emitter of one link: the handle each frame leaves on, the clock and
/// the deadline that bound each emit, and the sort of each failed emit.
///
/// A served connection lends it to the application through
/// [`ConnectionContext::emitter`], under the [`emit_deadline`] of its registry.
///
/// [`ConnectionContext::emitter`]: crate::ConnectionContext::emitter
/// [`emit_deadline`]: crate::RegistryOptions::emit_deadline
///
/// # Examples
///
/// ```
/// use tightbeam_pubsub::{EmitDeadline, Emitter, OpaqueFrame, Settled};
/// use tightbeam_ws::serve::ServedMux;
///
/// /// Emit one notice on `served`, a connection that a server accepted.
/// async fn notify(served: &ServedMux) -> Result<(), Box<dyn std::error::Error>> {
/// 	let emitter = Emitter::served(served, EmitDeadline::default());
/// 	let notice = OpaqueFrame { id: "notice", order: 1, payload: b"ping" }.build()?;
///
/// 	let settled = emitter.until_settled(&notice).await?;
/// 	if let Settled::Refused(cause) = settled {
/// 		eprintln!("the peer refused the notice: {cause}");
/// 	}
/// 	Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct Emitter {
	handle: MuxHandle,
	clock: RacingClock,
	deadline: EmitDeadline,
}

impl Emitter {
	/// The emitter of the served connection `served`, whose every emit ends
	/// within `deadline` on [`ServedMux::clock`], the clock of its writer.
	#[must_use]
	pub fn served(served: &ServedMux, deadline: EmitDeadline) -> Self {
		let handle = served.handle().clone();
		let clock = served.clock().clone();
		Self { handle, clock, deadline }
	}

	/// The emitter of the dialed link that `handle` drives, whose every emit
	/// ends within `deadline` on `clock`, the clock of the writer half of the
	/// link.
	#[must_use]
	pub fn new(handle: MuxHandle, clock: RacingClock, deadline: EmitDeadline) -> Self {
		Self { handle, clock, deadline }
	}

	/// Emit `frame` until the emit settles, within the deadline of this
	/// emitter.
	///
	/// An emit that finds every local stream slot in flight waits for a free
	/// slot, then emits again, inside the same deadline.
	///
	/// # Errors
	///
	/// - The [`LinkLost`] of an emit or a wait for a stream slot that counts as the end of the
	///   link, or of a deadline that passed first.
	pub async fn until_settled(&self, frame: &Frame) -> Result<Settled, LinkLost> {
		let mut paced = self.paced();
		paced.until_settled(frame).await
	}

	/// This emitter with one timer for every emit of a party that emits many
	/// times, such as the lane of one subscription.
	pub(crate) fn paced(&self) -> Paced<'_> {
		let timer = self.clock.timer();
		Paced { emitter: self, timer }
	}

	/// Emit `frame` until the emit settles, with no deadline of its own.
	async fn attempts(&self, frame: &Frame) -> Result<Settled, LinkLost> {
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

/// An [`Emitter`] and the one timer that bounds each of its emits, so a
/// party that emits many times makes its sleep once.
pub(crate) struct Paced<'e> {
	emitter: &'e Emitter,
	timer: Timer,
}

impl Paced<'_> {
	/// Emit `frame` until the emit settles, within the deadline of the
	/// emitter. See [`Emitter::until_settled`].
	///
	/// # Errors
	///
	/// - The errors of [`Emitter::until_settled`].
	pub(crate) async fn until_settled(&mut self, frame: &Frame) -> Result<Settled, LinkLost> {
		let Self { emitter, timer } = self;
		let attempts = pin!(emitter.attempts(frame));
		let bounded = timer.within(emitter.deadline.0, attempts).await;
		bounded.unwrap_or_else(|lapse| Err(LinkLost::lapsed(lapse)))
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
	fn lapsed(lapse: Lapse) -> Self {
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
	/// - An answer settles the emit.
	/// - A refusal of the peer ([`TransportError::transit_status`]) refuses one frame.
	/// - An exhausted session budget refuses one frame.
	/// - An exhausted stream cap waits.
	/// - Every other failure counts as the end of the link.
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
	use std::sync::Arc;

	use tightbeam::clock::{Clock, ManualClock};
	use tightbeam::transport::handshake::negotiation::MuxSettings;
	use tightbeam::transport::multiplex::SpawnedMux;
	use tightbeam_ws::serve::ServedMux;
	use tokio::task::JoinHandle;
	use tokio::time::timeout;

	use super::*;
	use crate::frame::OpaqueFrame;
	use crate::testing::nodes::{waits, Accepting, SHORT};
	use crate::testing::{Dial, Loopback, PATIENCE};

	/// The frame every test emits.
	fn notice() -> Frame {
		let notice = OpaqueFrame { id: "notice", order: 1, payload: b"ping" };
		notice.build().expect("the notice builds")
	}

	/// The server end of one loopback link under `dial`, spawned, with its
	/// client end beside it.
	async fn opened(dial: &Dial) -> (ServedMux, SpawnedMux) {
		let opened = Loopback::open(dial).await;
		let Loopback { server, client } = opened.expect("a loopback link opens");
		(server.spawn(), client)
	}

	/// The emitter of the server end of `served` under `deadline`.
	fn emitter_of(served: &ServedMux, deadline: Duration) -> Emitter {
		let deadline = EmitDeadline::new(deadline).expect("test deadlines are above zero");
		Emitter::served(served, deadline)
	}

	/// The emitter of the server end of a link under `settings`, whose client
	/// answers every stream with `Ok`. The returned guard keeps both ends
	/// alive.
	async fn answered(settings: MuxSettings) -> (Emitter, impl Sized) {
		let dial = Dial { settings, ..Dial::default() };
		let (served, client) = opened(&dial).await;
		let SpawnedMux { handle, responder, drivers } = client;
		let answering: JoinHandle<_> = tokio::spawn(responder.serve_with(Accepting));

		let emitter = emitter_of(&served, DEFAULT_OPERATION_TIMEOUT);
		(emitter, (served, handle, drivers, answering.abort_handle()))
	}

	#[test]
	fn an_emit_deadline_is_above_zero() {
		assert_eq!(EmitDeadline::new(Duration::ZERO), None);
	}

	#[tokio::test]
	async fn an_emit_the_peer_never_answers_ends_at_its_deadline_on_the_clock_of_the_link() {
		let clock = Arc::new(ManualClock::default());
		let dial = Dial { clock: Arc::clone(&clock) as Arc<dyn Clock>, ..Dial::default() };
		let (served, _silent) = opened(&dial).await;
		let emitter = emitter_of(&served, SHORT);
		let notice = notice();

		let mut settling = core::pin::pin!(emitter.until_settled(&notice));
		let parked = waits(settling.as_mut()).await;
		clock.advance(SHORT + Duration::from_secs(1));

		let settled = timeout(PATIENCE, settling).await;
		assert!(parked);
		assert!(matches!(settled, Ok(Err(LinkLost(_)))));
	}

	#[tokio::test]
	async fn a_budget_exhausted_emit_settles_as_refused() {
		let unfunded = MuxSettings::symmetric(4).with_send_budget(Some(0));
		let (emitter, _peer) = answered(unfunded).await;
		let notice = notice();

		let settling = emitter.until_settled(&notice);
		let settled = timeout(PATIENCE, settling).await;
		assert!(matches!(settled, Ok(Ok(Settled::Refused(_)))));
	}

	#[tokio::test]
	async fn a_closed_link_emit_returns_link_lost() {
		let (served, client) = opened(&Dial::default()).await;
		let emitter = emitter_of(&served, DEFAULT_OPERATION_TIMEOUT);
		drop(client);

		let notice = notice();
		let settling = emitter.until_settled(&notice);
		let settled = timeout(PATIENCE, settling).await;
		assert!(matches!(settled, Ok(Err(LinkLost(_)))));
	}

	#[tokio::test]
	async fn a_full_stream_cap_waits_then_emits() -> Result<(), TransportError> {
		let (emitter, _peer) = answered(MuxSettings::symmetric(1)).await;
		let held = emitter.handle.open_stream()?;
		let notice = notice();

		let mut settling = core::pin::pin!(emitter.until_settled(&notice));
		let parked = waits(settling.as_mut()).await;
		drop(held);

		let settled = timeout(PATIENCE, settling).await;
		assert!(parked);
		assert!(matches!(settled, Ok(Ok(Settled::Answered(None)))));
		Ok(())
	}
}
