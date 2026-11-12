//! The event watch of a scenario, as `docs/ws.md` (Test support) states it.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tightbeam::instrumentation::{BoundedMemorySink, EventSink, TbEvent};
use tightbeam::trace::{IntoEventLabel, TraceCollector, TraceConfig};
use tokio::sync::watch;

use super::error::{Error, Result};

/// A count of each event label that a trace records, which wakes the waiters
/// of a label as the trace records it.
///
/// - A scenario keeps its watch in a `static`, because `tb_scenario!` builds
///   its config and its parties apart.
/// - [`Self::trace`] gives the trace that the config of the scenario takes.
/// - [`Self::recorded`] waits until a trace of the watch records an event, or
///   until the patience of the watch passes.
///
/// # Examples
///
/// ```
/// use tightbeam::instrumentation::events;
/// use tightbeam_ws::testing::EventWatch;
///
/// static EVENTS: EventWatch = EventWatch::new();
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), tightbeam::TightBeamError> {
/// let trace = EVENTS.trace();
/// trace.emit_event(events::GATE_ACCEPT)?;
/// EVENTS.recorded(events::GATE_ACCEPT, 1).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
pub struct EventWatch {
	/// The count of each label, which the waiters of the label watch.
	labels: Mutex<BTreeMap<Cow<'static, str>, watch::Sender<usize>>>,
}

impl EventWatch {
	/// How long [`Self::recorded`] waits for a count before it fails.
	pub const PATIENCE: Duration = Duration::from_secs(10);

	/// A watch that has counted no event.
	#[must_use]
	pub const fn new() -> Self {
		Self { labels: Mutex::new(BTreeMap::new()) }
	}

	/// A trace that retains its events in the default bounded buffer, and
	/// counts each event on this watch.
	///
	/// A connection trace that splits from it counts on this watch too, and
	/// retains its events in a buffer of its own, as the default sink does.
	#[must_use]
	pub fn trace(&'static self) -> TraceCollector {
		TraceCollector::from(TraceConfig::default().with_sink(Watched::on(self)))
	}

	/// Wait until a trace of this watch has recorded `event` `times` times.
	///
	/// # Errors
	///
	/// - [`Error::Unrecorded`] -- the patience of the watch passed before the
	///   count.
	pub async fn recorded(&self, event: impl IntoEventLabel, times: usize) -> Result<()> {
		let label = event.into_label();
		let mut count = self.counter(label.clone()).subscribe();

		// The watch keeps the sender of each label, so the channel stays open
		// while this call borrows the watch. The count that the wait leaves
		// behind decides, so a record at the deadline still answers `Ok`.
		let reached = count.wait_for(|recorded| *recorded >= times);
		let _ = tokio::time::timeout(Self::PATIENCE, reached).await;

		let recorded = *count.borrow();
		if recorded >= times {
			return Ok(());
		}

		Err(Error::Unrecorded { label, times, recorded })
	}

	/// Count one record of `label`, and wake each waiter of the label.
	fn count(&self, label: Cow<'static, str>) {
		self.counter(label).send_modify(|recorded| *recorded += 1);
	}

	/// The count of `label`, which starts at zero.
	fn counter(&self, label: Cow<'static, str>) -> watch::Sender<usize> {
		let mut labels = self.lock();
		let counter = labels.entry(label).or_insert_with(|| watch::Sender::new(0));
		counter.clone()
	}

	/// A count changes in one step, so a poisoned lock still holds whole
	/// counts.
	fn lock(&self) -> MutexGuard<'_, BTreeMap<Cow<'static, str>, watch::Sender<usize>>> {
		self.labels.lock().unwrap_or_else(PoisonError::into_inner)
	}
}

/// The sink of a trace of an [`EventWatch`]: it counts each event on the
/// watch, and retains the event in a bounded buffer.
struct Watched {
	watch: &'static EventWatch,
	retained: BoundedMemorySink,
}

impl Watched {
	/// A sink that counts on `watch`, with an empty buffer.
	fn on(watch: &'static EventWatch) -> Self {
		Self { watch, retained: BoundedMemorySink::default() }
	}

	/// The count key of `event`: the URN of a record that the event API wrote,
	/// and the label of every other labelled record.
	fn label(event: &TbEvent) -> Cow<'static, str> {
		match &event.label {
			Some(label) if !event.is_from_event_api() => label.clone(),
			_ => IntoEventLabel::into_label(&event.urn),
		}
	}
}

impl EventSink for Watched {
	fn emit(&self, event: TbEvent) {
		self.watch.count(Self::label(&event));
		self.retained.emit(event);
	}

	fn drain(&self) -> Vec<TbEvent> {
		self.retained.drain()
	}

	fn overflowed(&self) -> bool {
		self.retained.overflowed()
	}

	fn sibling(&self) -> Option<Arc<dyn EventSink>> {
		Some(Arc::new(Self::on(self.watch)))
	}
}
