//! Live-trace verification of the full VM pipeline.
//!
//! One consumer and three parties run a complete program over localhost
//! TCP - submission, digest agreement, preprocessing, input derivation,
//! execution with a load-bearing reveal, output delivery, and
//! reconstruction. The scenario collector is injected into the consumer
//! and the first party, so the assertion spec counts the exact
//! lifecycle events the hosts emitted while doing the real work:
//! the submission handshake, every session round transition, and the
//! interpreter's execution events.

mod common;

use std::sync::Arc;

use ark_bls12_381::Fr;
use stoffelcrypto::common::rbc::rbc::Avid;
use stoffelcrypto::honeybadger::SessionId;
use tightbeam::testing::{ScenarioConfig, SetupEnv};
use tightbeam::{exactly, tb_assert_spec, tb_scenario};
use tightbeam_mpc::events::kind::{
	COLLECT, COMPUTE, OUTPUT, OUTPUT_OK, OUTPUT_RECOVERED, PREPROCESS, PREPROCESS_OK, WAIT_OUTPUT,
};
use tightbeam_vm::events::kind::{ADMIT, ECHO_OK, PROGRAM_END, PROGRAM_START, REVEAL, SUBMIT};
use tightbeam_vm::{ProgramBuilder, TraceHandle, ValidProgram, VmConsumer};

use common::{
	await_hosts, scenario_error, spawn_runs, topology, Outcome, CONSUMER, OUTPUT_DEADLINE, RUN_DEADLINE,
	SUBMIT_DEADLINE,
};

const PARTIES: usize = 3;
const THRESHOLD: usize = 0;
const INPUTS: [u64; 2] = [2, 3];

/// out = (x * x) * open(x * x), element-wise: the reveal output feeds
/// the final rescale, so a wrong reveal corrupts the asserted values.
fn build_program() -> Outcome<ValidProgram> {
	let mut builder = ProgramBuilder::default();
	let x = builder.input(CONSUMER, INPUTS.len() as u32);
	let squared = builder.mul(x, x);
	let opened = builder.reveal(squared);
	let rescaled = builder.mul_clear(squared, opened);

	builder.output(CONSUMER, rescaled);
	builder.build().map_err(scenario_error)
}

/// Submit, run, and reconstruct with `trace` on the consumer and party 0.
async fn run_pipeline(program: ValidProgram, inputs: Vec<Fr>, trace: TraceHandle) -> Outcome<Vec<Fr>> {
	let (networks, client_net) = topology(PARTIES).await?;
	let party_runs = spawn_runs(networks, THRESHOLD, trace.clone());

	let mut consumer = VmConsumer::new(Arc::clone(&client_net))
		.map_err(scenario_error)?
		.with_trace(trace);
	consumer.submit(&program, SUBMIT_DEADLINE).await.map_err(scenario_error)?;

	let mut session = consumer
		.open_session::<Fr, Avid<SessionId>>(&program, THRESHOLD, inputs)
		.map_err(scenario_error)?;
	let recovered = session.wait_output(OUTPUT_DEADLINE).await.map_err(scenario_error)?;

	await_hosts(party_runs, RUN_DEADLINE).await?;
	Ok(recovered)
}

tb_assert_spec! {
	pub PipelineSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(SUBMIT, exactly!(1)),
			(ADMIT, exactly!(1)),
			(ECHO_OK, exactly!(1)),
			(PREPROCESS, exactly!(1)),
			(PREPROCESS_OK, exactly!(1)),
			(COLLECT, exactly!(1)),
			(COMPUTE, exactly!(1)),
			(PROGRAM_START, exactly!(1)),
			(REVEAL, exactly!(1)),
			(PROGRAM_END, exactly!(1)),
			(OUTPUT, exactly!(1)),
			(OUTPUT_OK, exactly!(1)),
			(WAIT_OUTPUT, exactly!(1)),
			(OUTPUT_RECOVERED, exactly!(1))
		],
		// Causally ordered chain only: the consumer's submission, then
		// party 0's strictly sequential lifecycle. Consumer-side waits
		// interleave with party events in no fixed order and stay out.
		events: [
			SUBMIT, ADMIT, PREPROCESS, PREPROCESS_OK, COLLECT, COMPUTE,
			PROGRAM_START, REVEAL, PROGRAM_END, OUTPUT, OUTPUT_OK
		]
	}
}

tb_scenario! {
	name: the_live_pipeline_emits_its_full_lifecycle,
	config: ScenarioConfig::builder().with_spec(PipelineSpec::latest()).build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let inputs: Vec<Fr> = INPUTS.iter().map(|value| Fr::from(*value)).collect();
			let recovered = run_pipeline(build_program()?, inputs, TraceHandle::from(trace.share())).await?;
			let expected: Vec<Fr> = INPUTS.iter().map(|value| Fr::from(value.pow(4))).collect();
			assert_eq!(recovered, expected, "the recovered values must be x^4 per element");
			Ok(())
		}
	}
}
