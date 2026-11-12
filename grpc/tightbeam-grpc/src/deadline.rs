//! The deadlines of an edge and of its adapter, and the unix time of its
//! coupler, on the clock that each one runs on, as `docs/grpc.md` (Edge
//! profile, and Backend adapter) states it.

use core::future::Future;
use core::pin::{pin, Pin};
use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::Arc;
#[cfg(feature = "couple")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "couple")]
use tightbeam::clock::UnixMillis;
use tightbeam::clock::{Clock, Lapse, MonotonicInstant};

/// An instant on a clock, which bounds each wait up to it by the time left.
/// An instant past the range of the clock lies beyond every reading.
#[derive(Clone, Debug)]
pub(crate) struct Deadline {
	clock: Arc<dyn Clock>,
	at: Option<MonotonicInstant>,
}

impl Deadline {
	/// The deadline `span` from now on `clock`.
	pub(crate) fn after(clock: &Arc<dyn Clock>, span: Duration) -> Self {
		Self { clock: Arc::clone(clock), at: clock.monotonic().checked_add(span) }
	}

	/// A deadline on `clock` beyond every reading.
	pub(crate) fn unbounded(clock: &Arc<dyn Clock>) -> Self {
		Self { clock: Arc::clone(clock), at: None }
	}

	/// The sooner of this deadline and `span` from now on its clock.
	#[cfg(feature = "couple")]
	#[must_use]
	pub(crate) fn sooner(self, span: Duration) -> Self {
		let own = self.clock.monotonic().checked_add(span);
		let at = match (self.at, own) {
			(Some(at), Some(own)) => Some(at.min(own)),
			(at, own) => at.or(own),
		};
		Self { at, ..self }
	}

	/// The time left until the deadline, zero once it passed, or `None` for
	/// one beyond every reading.
	pub(crate) fn left(&self) -> Option<Duration> {
		let now = self.clock.monotonic();
		self.at.map(|at| at.saturating_duration_since(now))
	}

	/// Whether the deadline passed.
	pub(crate) fn passed(&self) -> bool {
		self.at.is_some_and(|at| self.clock.monotonic() >= at)
	}

	/// Run `work` until it ends, or until the deadline passes on its clock,
	/// by `within` on the clock for the time left. A deadline beyond every
	/// reading runs the work unbounded.
	///
	/// # Errors
	///
	/// - [`Lapse::Passed`] -- the deadline passed before `work` ended.
	/// - [`Lapse::NoTimer`] -- the polling thread has no timer for the clock.
	pub(crate) async fn bound<F: Future>(&self, work: F) -> Result<F::Output, Lapse> {
		let work = pin!(work);
		let Some(left) = self.left() else {
			return Ok(work.await);
		};

		self.clock.within(left, work).await
	}

	/// A sleep that ends at the deadline, which a poll holds across its wakes.
	pub(crate) fn sleep(&self) -> DeadlineSleep {
		let deadline = self.clone();
		let sleep = Box::pin(async move {
			match deadline.left() {
				Some(left) => deadline.clock.sleep(left).await,
				None => core::future::pending().await,
			}
		});
		DeadlineSleep { deadline: self.clone(), sleep }
	}
}

/// The sleep of a [`Deadline`], which ends at the instant of the deadline
/// however late its first poll comes, and at any poll once the deadline
/// passed.
pub(crate) struct DeadlineSleep {
	deadline: Deadline,
	sleep: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl Future for DeadlineSleep {
	type Output = ();

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
		let this = self.get_mut();
		if this.deadline.passed() {
			return Poll::Ready(());
		}

		this.sleep.as_mut().poll(cx)
	}
}

/// The clock of a coupler as the unix time that it judges the claims and the
/// bearer tokens of its callers at.
#[cfg(feature = "couple")]
#[derive(Clone, Debug)]
pub(crate) struct WallClock(Arc<dyn Clock>);

#[cfg(feature = "couple")]
impl WallClock {
	/// The unix time of `clock`.
	pub(crate) fn of(clock: &Arc<dyn Clock>) -> Self {
		Self(Arc::clone(clock))
	}

	/// The current unix time.
	pub(crate) fn unix(&self) -> UnixMillis {
		self.0.unix()
	}

	/// The current unix time as the [`SystemTime`] that a claim ledger and a
	/// bearer token are judged at.
	pub(crate) fn now(&self) -> SystemTime {
		UNIX_EPOCH + Duration::from_millis(self.unix().get())
	}
}

/// The sleep that a poll waits on under the deadline of its holder, made
/// again when that deadline moves.
#[derive(Default)]
pub(crate) struct DeadlineTimer(Option<DeadlineSleep>);

impl DeadlineTimer {
	/// Whether `deadline` passed, on the sleep of the timer, which the timer
	/// makes at the first poll under `deadline`.
	pub(crate) fn poll_passed(&mut self, deadline: &Deadline, cx: &mut Context<'_>) -> bool {
		let sleep = match &mut self.0 {
			Some(sleep) if sleep.deadline.at == deadline.at => sleep,
			_ => self.0.insert(deadline.sleep()),
		};

		Pin::new(sleep).poll(cx).is_ready()
	}
}
