//! The audit trail of one served connection. The page `docs/pubsub.md`
//! (Connection serve) lists its events.

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

/// The departure of one connection from its registry, as its trail records it.
#[derive(Clone, Copy)]
pub(crate) struct Departure {
	/// The number the registry admitted the connection under.
	pub(crate) connection: u64,
	/// The count of the subscriptions the connection held as it left.
	pub(crate) subscriptions: u64,
}

/// The audit trail of one served connection: the trace of the transport that
/// its link was accepted on, under the `instrument` feature.
///
/// A refused record costs the record alone, and the decision it records
/// stands, so each record drops the refusal.
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

	/// The connection of `departure` left the registry.
	pub(crate) fn left(&self, departure: &Departure) {
		let Departure { connection, subscriptions } = *departure;
		self.record(events::CONNECTION_LEFT, || connection.to_string(), subscriptions);
	}

	/// The registry expelled the connection with `reason`.
	pub(crate) fn expelled(&self, reason: GoAwayReason) {
		let name = reason.as_str();
		self.record(events::CONNECTION_EXPELLED, || name, name);
	}

	/// The command `command` took no effect, and answers `status`.
	pub(crate) fn refused(&self, command: &'static str, status: TransitStatus) {
		self.record(events::COMMAND_REFUSED, || format!("{command} {}", status.as_str()), status);
	}

	/// A subscription to `topic` dropped an update, its `dropped`th so far.
	pub(crate) fn dropped(&self, topic: &Topic, dropped: u64) {
		self.record(events::UPDATE_DROPPED, || topic.as_str().to_owned(), dropped);
	}

	/// Record `event` with the label that `label` builds, which runs only for
	/// a trail with a trace, and `value`.
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
