//! Full consumer flow over the session lifecycle, run as a verification
//! scenario: five party nodes and one networked consumer on localhost
//! TCP square the consumer's inputs.
//!
//! The scenario collector is threaded into party 0 and the consumer, so
//! the assertion spec counts the live phase sequence those hosts emit.
//! Secrets never travel in the clear: only shares and masked values
//! cross the mutually-authenticated multiplexed tightbeam links.

mod common;

use core::time::Duration;

use ark_bls12_381::Fr;
use tightbeam::testing::{ScenarioConfig, SetupEnv};
use tightbeam::{exactly, tb_assert_spec, tb_scenario};
use tightbeam_mpc::events::kind::{
	COLLECT, COMPUTE, OUTPUT, OUTPUT_OK, OUTPUT_RECOVERED, PREPROCESS, PREPROCESS_OK, WAIT_OUTPUT,
};
use tightbeam_mpc::TraceHandle;

use common::{square_round, SquareRound};

const PARTIES: usize = 5;
const THRESHOLD: usize = 1;
const CONSUMER: usize = 100;
const INPUTS: [u64; 2] = [10, 20];
const INSTANCE: u32 = 222;

tb_assert_spec! {
	pub ConsumerRoundSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PREPROCESS, exactly!(1)),
			(PREPROCESS_OK, exactly!(1)),
			(COLLECT, exactly!(1)),
			(COMPUTE, exactly!(1)),
			(OUTPUT, exactly!(1)),
			(OUTPUT_OK, exactly!(1)),
			(WAIT_OUTPUT, exactly!(1)),
			(OUTPUT_RECOVERED, exactly!(1))
		],
		// Party 0's phase order only; consumer waits interleave freely.
		events: [PREPROCESS, PREPROCESS_OK, COLLECT, COMPUTE, OUTPUT, OUTPUT_OK]
	}
}

tb_scenario! {
	name: consumer_provides_inputs_and_receives_outputs_over_tightbeam,
	config: ScenarioConfig::builder().with_spec(ConsumerRoundSpec::latest()).build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let params = SquareRound {
				parties: PARTIES,
				threshold: THRESHOLD,
				consumer: CONSUMER,
				inputs: &INPUTS,
				instance: INSTANCE,
				stage_deadline: Duration::from_secs(30),
				preprocess_deadline: Duration::from_secs(90),
				client_ready: Duration::from_secs(10),
				input_wait: Duration::from_secs(10),
				engine_timeout: Duration::from_secs(60),
			};
			let recovered = square_round(params, TraceHandle::from(trace.share())).await?;
			let expected: Vec<Fr> = INPUTS.iter().map(|value| Fr::from(value * value)).collect();
			assert_eq!(recovered, expected, "the consumer recovers exactly the squared inputs");
			Ok(())
		}
	}
}
