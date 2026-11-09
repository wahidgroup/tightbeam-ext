//! The audit trail of one served connection, which the registry, its
//! subscriptions, and its command routes share.

use std::borrow::Cow;

use tightbeam::policy::TransitStatus;
use tightbeam::trace::EventValue;
#[cfg(feature = "instrument")]
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::urn::Urn;
use tightbeam_ws::serve::ServedMux;

use crate::events;
use crate::topic::Topic;

/// The audit trail of one served connection: the trace of the transport that
/// its link was accepted on, under the `instrument` feature. A connection with
/// no trace, or a build without the feature, records nothing.
///
/// A build of tightbeam without its `testing` feature keeps the label of
/// each event and drops its value, so the label of each record carries what
/// the record names, and the value repeats it for the spec of a scenario.
///
/// The trace refuses an event only under the fault that the `testing-fault`
/// feature of tightbeam injects. A refused event costs the record alone, and
/// the decision it records stands, so each record drops that refusal.
#[derive(Default)]
pub(crate) struct ConnectionAudit {
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
}

impl ConnectionAudit {
	/// The audit trail of `served`.
	pub(crate) fn of(served: &ServedMux) -> Self {
		#[cfg(feature = "instrument")]
		let audit = Self { trace: served.trace() };
		#[cfg(not(feature = "instrument"))]
		let audit = {
			let _ = served;
			Self {}
		};

		audit
	}

	/// A trail that records on the trace of this one.
	pub(crate) fn share(&self) -> Self {
		#[cfg(feature = "instrument")]
		let shared = Self { trace: self.trace.as_ref().map(TraceCollector::share) };
		#[cfg(not(feature = "instrument"))]
		let shared = Self {};

		shared
	}

	/// The registry admitted the connection under the number `connection`.
	pub(crate) fn admitted(&self, connection: u64) {
		self.record(events::CONNECTION_ADMITTED, || connection.to_string(), connection);
	}

	/// The connection under the number `connection` left the registry, with
	/// `subscriptions` live.
	pub(crate) fn left(&self, connection: u64, subscriptions: u64) {
		self.record(events::CONNECTION_LEFT, || connection.to_string(), subscriptions);
	}

	/// The delivery policy expelled the connection with `reason`.
	pub(crate) fn expelled(&self, reason: GoAwayReason) {
		let name = reason.as_str();
		self.record(events::CONNECTION_EXPELLED, || name, name);
	}

	/// The wire command `command` took no effect, and answers `status`.
	pub(crate) fn refused(&self, command: &'static str, status: TransitStatus) {
		self.record(events::COMMAND_REFUSED, || format!("{command} {}", status.as_str()), status);
	}

	/// A subscription to `topic` dropped an update, its `dropped`th so far.
	pub(crate) fn dropped(&self, topic: &Topic, dropped: u64) {
		self.record(events::UPDATE_DROPPED, || topic.as_str().to_owned(), dropped);
	}

	/// Record `event` with the label that `label` builds, which runs only for
	/// a trail with a trace, and `value`. See the type for why a refused
	/// record is dropped.
	fn record<L, V>(&self, event: Urn<'static>, label: impl FnOnce() -> L, value: V)
	where
		L: Into<Cow<'static, str>>,
		V: Into<EventValue>,
	{
		#[cfg(feature = "instrument")]
		if let Some(trace) = &self.trace {
			let _ = trace.emit_event_with_value(event, label(), value);
		}

		#[cfg(not(feature = "instrument"))]
		let _ = (event, label, value.into());
	}
}
