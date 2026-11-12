//! The waits of [`EventWatch`] on the counts of its trace, as tightbeam
//! scenarios.
//!
//! [`EventWatch`]: tightbeam_ws::testing::EventWatch

#![cfg(feature = "testing")]

use tightbeam::instrumentation::events;
use tightbeam::testing::{ScenarioConfig, SetupEnv};
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn};
use tightbeam_ws::testing::{Error, EventWatch};

/// Whether a wait past the count of the trace answered `Unrecorded` with the
/// count that the trace reached.
const UNRECORDED: Urn<'static> = urn!("test", "event:event-watch/unrecorded");

tb_assert_spec! {
	pub UnrecordedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::GATE_ACCEPT, exactly!(1)),
			(UNRECORDED, exactly!(1), equals!(true))
		]
	}
}

/// The events of the scenario of a count that the trace never reaches.
static UNRECORDED_EVENTS: EventWatch = EventWatch::new();

// A wait ends at the count that the trace records. A wait for a count that
// the trace never reaches answers `Unrecorded` when the patience of the watch
// passes, on a paused clock that advances to the deadline.
tb_scenario! {
	name: a_wait_past_the_count_of_the_trace_answers_unrecorded,
	config: ScenarioConfig::builder().with_trace(UNRECORDED_EVENTS.trace()).with_spec(UnrecordedSpec::latest()).build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			tokio::time::pause();
			trace.emit_event(events::GATE_ACCEPT)?;
			UNRECORDED_EVENTS.recorded(events::GATE_ACCEPT, 1).await?;

			let missed = UNRECORDED_EVENTS.recorded(events::GATE_ACCEPT, 2).await;
			let unrecorded = matches!(missed, Err(Error::Unrecorded { times: 2, recorded: 1, .. }));
			trace.event_with(UNRECORDED, &[], unrecorded)?;
			Ok(())
		}
	}
}
