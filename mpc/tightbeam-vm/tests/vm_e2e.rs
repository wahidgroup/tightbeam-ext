//! Full VM flow over localhost TCP, run as verification scenarios:
//! a consumer builds and submits a bytecode program, five parties
//! validate it, agree on its digest, execute it against the
//! HoneyBadger engine, and the consumer reconstructs the result.
//!
//! The scenario collector observes the consumer and party 0, so each
//! assertion spec counts the exact lifecycle events one host pair
//! emitted while doing the real work. The programs make every
//! interactive instruction load-bearing: reveal output feeds later
//! clear arithmetic, so a wrong `Reveal` (or `MulS`) corrupts the
//! final values the scenarios assert on.

mod common;

use std::sync::Arc;

use ark_bls12_381::Fr;
use stoffelcrypto::common::rbc::rbc::Avid;
use stoffelcrypto::honeybadger::SessionId;
use tightbeam::testing::{ScenarioConfig, SetupEnv};
use tightbeam::{absent, exactly, tb_assert_spec, tb_scenario};
use tightbeam_mpc::events::kind::{
	COLLECT, COMPUTE, OUTPUT, OUTPUT_OK, OUTPUT_RECOVERED, PREPROCESS, PREPROCESS_OK, WAIT_OUTPUT,
};
use tightbeam_vm::events::kind::{ADMIT, ECHO_OK, PROGRAM_END, PROGRAM_START, REFUSE, REVEAL, SUBMIT};
use tightbeam_vm::{ControlMessage, FixedPrecision, ProgramBuilder, TraceHandle, ValidProgram, VmConsumer, VmError};
use tokio::time::timeout;

use common::{
	await_hosts, party_config, scenario_error, spawn_runs, topology, Outcome, Party, CONSUMER, OUTPUT_DEADLINE,
	RUN_DEADLINE, SUBMIT_DEADLINE,
};

const PARTIES: usize = 5;
const THRESHOLD: usize = 1;
const INPUTS: [u64; 2] = [10, 20];

/// out = (x * x) * open(x * x) + [5, 7], element-wise over two inputs.
fn build_program() -> Outcome<ValidProgram> {
	let mut builder = ProgramBuilder::default();
	let x = builder.input(CONSUMER, INPUTS.len() as u32);
	let squared = builder.mul(x, x);
	let opened = builder.reveal(squared);
	let rescaled = builder.mul_clear(squared, opened);
	let offsets = builder.constants([5, 7]);
	let shifted = builder.add_clear(rescaled, offsets);
	builder.output(CONSUMER, shifted);

	builder.build().map_err(scenario_error)
}

/// out = fp_div(fp_mul(x, x), 2.0) at (k = 16, f = 4).
///
/// The raw values divide exactly by `2^f` at every truncation, so the
/// probabilistic rounding bit is always zero and the assertion is
/// deterministic.
fn build_fixed_point_program() -> Outcome<ValidProgram> {
	let precision = FixedPrecision { k: 16, f: 4 };
	let mut builder = ProgramBuilder::default();
	let x = builder.input(CONSUMER, 1);
	let squared = builder.fp_mul(x, x, precision);
	let halved = builder.fp_div(squared, 32, precision);

	builder.output(CONSUMER, halved);

	builder.build().map_err(scenario_error)
}

/// Submit `program`, feed `inputs`, and return the reconstructed
/// output once every party host survived to the end.
async fn run_program(program: ValidProgram, inputs: Vec<Fr>, trace: TraceHandle) -> Outcome<Vec<Fr>> {
	let (networks, client_net) = topology(PARTIES).await?;
	let party_runs = spawn_runs(networks, THRESHOLD, trace.clone());

	let mut consumer = VmConsumer::new(client_net).map_err(scenario_error)?.with_trace(trace);
	consumer.submit(&program, SUBMIT_DEADLINE).await.map_err(scenario_error)?;

	let mut session = consumer
		.open_session::<Fr, Avid<SessionId>>(&program, THRESHOLD, inputs)
		.map_err(scenario_error)?;
	let recovered = session.wait_output(OUTPUT_DEADLINE).await.map_err(scenario_error)?;

	await_hosts(party_runs, RUN_DEADLINE).await?;

	Ok(recovered)
}

tb_assert_spec! {
	pub FullProgramSpec,
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
	name: a_submitted_program_runs_end_to_end,
	config: ScenarioConfig::builder().with_spec(FullProgramSpec::latest()).build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let inputs: Vec<Fr> = INPUTS.iter().map(|value| Fr::from(*value)).collect();
			let recovered = run_program(build_program()?, inputs, TraceHandle::from(trace.share())).await?;

			// (x^2) * open(x^2) + offset = x^4 + offset
			let expected: Vec<Fr> = INPUTS
				.iter()
				.zip([5u64, 7u64])
				.map(|(value, offset)| Fr::from(value.pow(4) + offset))
				.collect();
			assert_eq!(recovered, expected, "the recovered values must be x^4 + offset per element");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub FixedPointSpec,
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
			(REVEAL, absent!()),
			(PROGRAM_END, exactly!(1)),
			(OUTPUT, exactly!(1)),
			(OUTPUT_OK, exactly!(1)),
			(WAIT_OUTPUT, exactly!(1)),
			(OUTPUT_RECOVERED, exactly!(1))
		],
		// The same party-0 chain as the full program, without a reveal:
		// the fixed-point pipeline is truncation-only.
		events: [
			SUBMIT, ADMIT, PREPROCESS, PREPROCESS_OK, COLLECT, COMPUTE,
			PROGRAM_START, PROGRAM_END, OUTPUT, OUTPUT_OK
		]
	}
}

tb_scenario! {
	name: a_fixed_point_program_runs_end_to_end,
	config: ScenarioConfig::builder().with_spec(FixedPointSpec::latest()).build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			// x = 5.5 (raw 88 at f = 4).
			let inputs = vec![Fr::from(88u64)];
			let recovered =
				run_program(build_fixed_point_program()?, inputs, TraceHandle::from(trace.share())).await?;

			// (5.5 * 5.5) / 2.0 = 15.125, raw 242 at f = 4.
			assert_eq!(
				recovered,
				vec![Fr::from(242u64)],
				"the recovered value must be (x * x) / 2 in fixed point"
			);
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub RejectionSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(REFUSE, exactly!(1)),
			(ADMIT, absent!())
		],
		// The raw garbage bypasses VmConsumer, so the only catalogued
		// event on the wire is party 0's refusal.
		events: [REFUSE]
	}
}

tb_scenario! {
	name: malformed_submissions_are_rejected_with_an_echo,
	config: ScenarioConfig::builder().with_spec(RejectionSpec::latest()).build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (networks, client_net) = topology(PARTIES).await?;

			let network = Arc::clone(&networks[0]);
			let config = party_config(THRESHOLD, TraceHandle::from(trace.share()));
			let verdict = tokio::spawn(async move { Party::receive(network, config).await });

			let garbage = ControlMessage::Submit { program: b"not a der program".to_vec() }
				.encode()
				.map_err(scenario_error)?;
			client_net.send_control(0, &garbage).await.map_err(scenario_error)?;

			let mut control = client_net
				.take_control_inbox()
				.ok_or_else(|| scenario_error("the control inbox was already taken"))?;
			let (sender, raw) = timeout(SUBMIT_DEADLINE, control.recv())
				.await
				.map_err(scenario_error)?
				.ok_or_else(|| scenario_error("the control lane closed before the echo"))?;
			let echo = ControlMessage::decode(&raw).map_err(scenario_error)?;

			assert_eq!(sender, 0, "the echo must come from the rejecting party");
			assert!(
				matches!(echo, ControlMessage::Echo { accept: false, .. }),
				"the party must reject the malformed program, got {echo:?}"
			);

			// The refusal itself is validated by the spec shape above:
			// one `refuse`, no `admit`. Here the host error surface just
			// has to stay typed.
			let refusal =
				timeout(SUBMIT_DEADLINE, verdict).await.map_err(scenario_error)?.map_err(scenario_error)?.err();
			assert!(
				matches!(refusal, Some(VmError::Codec(_))),
				"a garbage submission must surface as a codec error, got {refusal:?}"
			);
			Ok(())
		}
	}
}
