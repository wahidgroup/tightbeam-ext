//! Live execution tracing, injected the way upstream tightbeam feeds its
//! colony components: a shareable collector handle is injected at
//! construction and the component emits catalogued events from inside
//! its real code paths.
//!
//! A [`TraceHandle`] wraps a [`TraceCollector`]. The default handle is
//! an isolated collector nobody observes, so untraced deployments pay
//! one `Arc` per component and no coordination. Verification runs
//! inject a shared handle (usually a `share()` of a `tb_scenario!`
//! collector), then check the recorded event stream against assertion
//! specs and CSP process models - the trace is the live execution.
//!
//! Every recordable event is a [`TraceEvent`] from a catalog (this
//! crate's lives in [`events`]): an assertion label the verification
//! framework counts and fault-injects on, paired with a URN naming the
//! event kind the way upstream's `instrumentation::events` does. With
//! the `instrument` feature on, each recording also lands on the
//! instrumentation plane under its URN, which is what `tb_assert_spec!`
//! `events:` ordering blocks verify against.
//!
//! Events accumulate in the collector until its owner drains them, so
//! long-lived deployments should inject handles for bounded
//! verification windows rather than process lifetimes.

use tightbeam::trace::TraceCollector;
use tightbeam::utils::urn::Urn;

use crate::error::Result;

/// One catalogued trace event: an assertion label for spec counting
/// and fault injection, plus a URN identifying the event kind on the
/// instrumentation plane, upstream-style
/// (`urn:tightbeam:<component>:event/<kind>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceEvent {
	label: &'static str,
	nss: &'static str,
}

impl TraceEvent {
	/// Catalog a new event kind under `urn:tightbeam:<nss>`.
	pub const fn new(label: &'static str, nss: &'static str) -> Self {
		Self { label, nss }
	}

	/// The assertion label the verification framework counts.
	pub const fn label(&self) -> &'static str {
		self.label
	}

	/// The URN naming this event kind on the instrumentation plane.
	pub const fn urn(&self) -> Urn<'static> {
		Urn::new("tightbeam", self.nss)
	}
}

/// The transport and session event catalog:
/// `urn:tightbeam:mpc:event/<kind>`.
pub mod events {
	use super::TraceEvent;

	/// A party-to-party link came up (dial or accept).
	pub const LINK_UP: TraceEvent = TraceEvent::new("link_up", "mpc:event/link-up");
	/// A client-to-party link came up.
	pub const CLIENT_LINK_UP: TraceEvent = TraceEvent::new("client_link_up", "mpc:event/client-link-up");
	/// A party link stayed dead after backpressure retries.
	pub const LINK_DEAD: TraceEvent = TraceEvent::new("link_dead", "mpc:event/link-dead");
	/// A client link stayed dead after backpressure retries.
	pub const CLIENT_LINK_DEAD: TraceEvent = TraceEvent::new("client_link_dead", "mpc:event/client-link-dead");
	/// A dead link is being re-established.
	pub const REDIAL: TraceEvent = TraceEvent::new("redial", "mpc:event/redial");
	/// A send hit stream exhaustion and is waiting for a slot.
	pub const SEND_SATURATED: TraceEvent = TraceEvent::new("send_saturated", "mpc:event/send-saturated");

	/// Preprocessing entered.
	pub const PREPROCESS: TraceEvent = TraceEvent::new("preprocess", "mpc:event/preprocess");
	/// Preprocessing produced its material.
	pub const PREPROCESS_OK: TraceEvent = TraceEvent::new("preprocess_ok", "mpc:event/preprocess-ok");
	/// Preprocessing failed and the round rewound.
	pub const PREPROCESS_FAIL: TraceEvent = TraceEvent::new("preprocess_fail", "mpc:event/preprocess-fail");
	/// Input collection entered.
	pub const COLLECT: TraceEvent = TraceEvent::new("collect", "mpc:event/collect");
	/// Input collection failed and the round rewound.
	pub const COLLECT_FAIL: TraceEvent = TraceEvent::new("collect_fail", "mpc:event/collect-fail");
	/// Online computation entered.
	pub const COMPUTE: TraceEvent = TraceEvent::new("compute", "mpc:event/compute");
	/// Online computation failed and the round rewound.
	pub const COMPUTE_FAIL: TraceEvent = TraceEvent::new("compute_fail", "mpc:event/compute-fail");
	/// Output delivery entered.
	pub const OUTPUT: TraceEvent = TraceEvent::new("output", "mpc:event/output");
	/// Output delivery finished.
	pub const OUTPUT_OK: TraceEvent = TraceEvent::new("output_ok", "mpc:event/output-ok");
	/// Output delivery failed and the round rewound.
	pub const OUTPUT_FAIL: TraceEvent = TraceEvent::new("output_fail", "mpc:event/output-fail");
	/// The consumer started waiting for result shares.
	pub const WAIT_OUTPUT: TraceEvent = TraceEvent::new("wait_output", "mpc:event/wait-output");
	/// The consumer reconstructed the output.
	pub const OUTPUT_RECOVERED: TraceEvent = TraceEvent::new("output_recovered", "mpc:event/output-recovered");

	/// The catalog's URNs as bare constants, because `tb_assert_spec!`
	/// `events:` ordering blocks take identifiers that must resolve to
	/// [`Urn`](tightbeam::utils::urn::Urn) values.
	pub mod kind {
		use tightbeam::utils::urn::Urn;

		pub const LINK_UP: Urn<'static> = super::LINK_UP.urn();
		pub const CLIENT_LINK_UP: Urn<'static> = super::CLIENT_LINK_UP.urn();
		pub const LINK_DEAD: Urn<'static> = super::LINK_DEAD.urn();
		pub const CLIENT_LINK_DEAD: Urn<'static> = super::CLIENT_LINK_DEAD.urn();
		pub const REDIAL: Urn<'static> = super::REDIAL.urn();
		pub const SEND_SATURATED: Urn<'static> = super::SEND_SATURATED.urn();
		pub const PREPROCESS: Urn<'static> = super::PREPROCESS.urn();
		pub const PREPROCESS_OK: Urn<'static> = super::PREPROCESS_OK.urn();
		pub const PREPROCESS_FAIL: Urn<'static> = super::PREPROCESS_FAIL.urn();
		pub const COLLECT: Urn<'static> = super::COLLECT.urn();
		pub const COLLECT_FAIL: Urn<'static> = super::COLLECT_FAIL.urn();
		pub const COMPUTE: Urn<'static> = super::COMPUTE.urn();
		pub const COMPUTE_FAIL: Urn<'static> = super::COMPUTE_FAIL.urn();
		pub const OUTPUT: Urn<'static> = super::OUTPUT.urn();
		pub const OUTPUT_OK: Urn<'static> = super::OUTPUT_OK.urn();
		pub const OUTPUT_FAIL: Urn<'static> = super::OUTPUT_FAIL.urn();
		pub const WAIT_OUTPUT: Urn<'static> = super::WAIT_OUTPUT.urn();
		pub const OUTPUT_RECOVERED: Urn<'static> = super::OUTPUT_RECOVERED.urn();
	}
}

/// A shareable handle onto one trace collector.
#[derive(Debug, Default)]
pub struct TraceHandle {
	collector: TraceCollector,
}

impl TraceHandle {
	/// Record one catalogued event: its URN on the assertion plane,
	/// and (under `instrument`) the same URN on the instrumentation plane.
	///
	/// Fails only when the collector's verification layer injects a
	/// fault at the label; callers propagate that failure through
	/// their real error paths so injected faults exercise the same
	/// recovery code genuine failures do.
	pub fn event(&self, event: &TraceEvent) -> Result<()> {
		self.collector.event(event.urn())?;

		#[cfg(feature = "instrument")]
		self.collector.emit(event.urn(), event.label);

		Ok(())
	}

	/// The underlying collector, for draining or inspection.
	pub fn collector(&self) -> &TraceCollector {
		&self.collector
	}
}

/// Cloning shares the underlying collector: every clone records into
/// the same event stream, which is what lets one injected handle
/// observe a whole component tree.
impl Clone for TraceHandle {
	fn clone(&self) -> Self {
		Self { collector: self.collector.share() }
	}
}

impl From<TraceCollector> for TraceHandle {
	fn from(collector: TraceCollector) -> Self {
		Self { collector }
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const PHASE: TraceEvent = TraceEvent::new("phase", "mpc:event/phase");

	#[test]
	fn events_land_in_the_collector() {
		let handle = TraceHandle::default();
		let recorded = handle.event(&PHASE);
		assert!(recorded.is_ok());
		assert_eq!(handle.collector().drain_assertions().len(), 1);
	}

	#[test]
	fn clones_share_one_event_stream() {
		let handle = TraceHandle::default();
		let clone = handle.clone();
		let recorded = clone.event(&PHASE);
		assert!(recorded.is_ok());
		assert_eq!(handle.collector().drain_assertions().len(), 1);
	}

	#[test]
	fn default_handles_are_isolated() {
		let first = TraceHandle::default();
		let second = TraceHandle::default();
		let recorded = first.event(&PHASE);
		assert!(recorded.is_ok());
		assert!(second.collector().drain_assertions().is_empty());
	}

	#[cfg(feature = "instrument")]
	#[test]
	fn recordings_land_on_the_instrumentation_plane_under_their_urn() {
		let handle = TraceHandle::default();
		let recorded = handle.event(&PHASE);
		assert!(recorded.is_ok());
		// The assertion plane auto-emits its own bookkeeping event, so
		// the catalogued URN is counted rather than the whole stream.
		let events = handle.collector().drain_events();
		let count = events.iter().filter(|event| event.urn == PHASE.urn()).count();
		assert_eq!(count, 1);
	}
}
