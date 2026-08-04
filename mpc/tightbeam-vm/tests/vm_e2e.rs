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

use aes::Aes128;
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use cipher::{BlockEncrypt, KeyInit};
use stoffelcrypto::common::rbc::rbc::Avid;
use stoffelcrypto::honeybadger::SessionId;
use tightbeam::testing::{ScenarioConfig, SetupEnv};
use tightbeam::{absent, exactly, tb_assert_spec, tb_scenario};
use tightbeam_mpc::events::kind::{
	COLLECT, COMPUTE, OUTPUT, OUTPUT_OK, OUTPUT_RECOVERED, PREPROCESS, PREPROCESS_OK, WAIT_OUTPUT,
};
use tightbeam_vm::circuits::aes128::{encrypt_block, BLOCK_LEN};
use tightbeam_vm::events::kind::{ADMIT, BIT_DEC, ECHO_OK, PROGRAM_END, PROGRAM_START, REFUSE, REVEAL, SUBMIT};
use tightbeam_vm::{
	ControlMessage, FixedPrecision, ProgramBuilder, Secret, TraceHandle, ValidProgram, VmConsumer, VmError,
};
use tokio::time::timeout;

use common::{
	await_hosts, party_config, scenario_error, spawn_runs, topology, Outcome, Party, CONSUMER, OUTPUT_DEADLINE,
	RUN_DEADLINE, SUBMIT_DEADLINE,
};
use tightbeam_vm::VmPartyConfig;

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

/// out = lt(x, 5) at width 8: the mask-and-reveal `BitDec` and its
/// ripple-borrow-subtractor against a public bound lifted into a
/// secret via a local zero (`x - x`, no round) plus one `AddC`.
fn build_lt_program() -> Outcome<ValidProgram> {
	const WIDTH: u8 = 8;
	let mut builder = ProgramBuilder::default();
	let x = builder.input(CONSUMER, 1);
	let zero = builder.sub(x, x);
	let bound_clear = builder.constants([5u64]);
	let bound = builder.add_clear(zero, bound_clear);
	let less = builder.lt(x, bound, WIDTH);
	builder.output(CONSUMER, Secret::from(less));

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
	pub BitDecSpec,
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
			(BIT_DEC, exactly!(1)),
			(REVEAL, absent!()),
			(PROGRAM_END, exactly!(1)),
			(OUTPUT, exactly!(1)),
			(OUTPUT_OK, exactly!(1)),
			(WAIT_OUTPUT, exactly!(1)),
			(OUTPUT_RECOVERED, exactly!(1))
		],
		// The same party-0 chain as the full program, with the
		// interactive `BitDec` mask-and-reveal round standing in for
		// the explicit `Reveal` the other pipelines use.
		events: [
			SUBMIT, ADMIT, PREPROCESS, PREPROCESS_OK, COLLECT, COMPUTE,
			PROGRAM_START, BIT_DEC, PROGRAM_END, OUTPUT, OUTPUT_OK
		]
	}
}

tb_scenario! {
	name: a_bit_decomposed_comparison_runs_end_to_end,
	config: ScenarioConfig::builder().with_spec(BitDecSpec::latest()).build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let inputs = vec![Fr::from(3u64)];
			let trace = TraceHandle::from(trace.share());
			let program = build_lt_program()?;

			let recovered = run_program(program, inputs, trace).await?;
			assert_eq!(recovered, vec![Fr::from(1u64)], "lt(3, 5) over 8 bits must be 1");
			Ok(())
		}
	}
}

/// AES-128 one-block encrypt: secret key + plaintext in, ciphertext out.
///
/// FIPS 197 Appendix C.1 vector. The circuit expands into thousands of
/// bit-gate rounds, so the AES-specific deadlines below dwarf the
/// smaller suites.
fn build_aes128_program() -> Outcome<ValidProgram> {
	let mut builder = ProgramBuilder::default();
	let inputs = builder.input_bytes(CONSUMER, BLOCK_LEN * 2);
	let key = inputs.slice(0, BLOCK_LEN);
	let block = inputs.slice(BLOCK_LEN, BLOCK_LEN);

	let ciphertext = encrypt_block(&mut builder, key, block);
	builder.output(CONSUMER, ciphertext);

	builder.build().map_err(scenario_error)
}

fn field_byte(share: &Fr) -> u8 {
	let bytes = share.into_bigint().to_bytes_le();
	match bytes.first() {
		Some(byte) => *byte,
		None => 0,
	}
}

fn aes_party_config(threshold: usize, trace: TraceHandle) -> VmPartyConfig {
	// Debug builds generate tens of thousands of Beaver triples before
	// the first online S-box. Keep client readiness short, but leave
	// input collection and engine timeouts large enough that a long
	// preprocess cannot starve collect_inputs or HB sessions.
	VmPartyConfig {
		threshold,
		submission_deadline: SUBMIT_DEADLINE,
		client_ready_deadline: std::time::Duration::from_secs(60),
		input_wait: std::time::Duration::from_secs(20 * 60),
		reveal_deadline: std::time::Duration::from_secs(5 * 60),
		engine_timeout: std::time::Duration::from_secs(30 * 60),
		trace,
	}
}

fn spawn_aes_runs(
	networks: Vec<std::sync::Arc<tightbeam_mpc::TightbeamNetwork>>,
	threshold: usize,
	trace: TraceHandle,
) -> Vec<tokio::task::JoinHandle<Outcome<Party>>> {
	use ark_std::rand::rngs::{OsRng, StdRng};
	use ark_std::rand::SeedableRng;

	let mut traces = vec![trace];
	traces.resize_with(networks.len(), TraceHandle::default);
	networks
		.into_iter()
		.zip(traces)
		.map(|(network, trace)| {
			tokio::spawn(async move {
				let mut party: Party = Party::receive(network, aes_party_config(threshold, trace))
					.await
					.map_err(scenario_error)?;
				let mut rng = StdRng::from_rng(OsRng).map_err(scenario_error)?;
				party.run(&mut rng).await.map_err(scenario_error)?;
				Ok(party)
			})
		})
		.collect()
}

/// Measure HoneyBadger control-lane reveal cost for batched opens of
/// 16 and 160 shares on 5-party localhost. Timings feed the TinyTable
/// online-floor note in the research-spike artifact.
#[tokio::test]
async fn reveal_batch_costs_are_measurable_on_localhost() {
	async fn time_reveal_batch(width: u32) -> Outcome<std::time::Duration> {
		let mut builder = ProgramBuilder::default();
		let secrets = builder.input(CONSUMER, width);
		let opened = builder.reveal(secrets);
		// Keep the opened values load-bearing so a skipped Reveal fails.
		let shifted = builder.add_clear(secrets, opened);
		builder.output(CONSUMER, shifted);
		let program = builder.build().map_err(scenario_error)?;

		let inputs: Vec<Fr> = (0..width).map(|index| Fr::from(u64::from(index + 1))).collect();
		let started = std::time::Instant::now();
		let recovered = run_program(program, inputs, TraceHandle::default()).await?;
		let elapsed = started.elapsed();
		assert_eq!(recovered.len(), width as usize, "reveal width must round-trip");
		Ok(elapsed)
	}

	let batch_16 = match time_reveal_batch(16).await {
		Ok(elapsed) => elapsed,
		Err(error) => panic!("16-open reveal batch must finish: {error}"),
	};
	let batch_160 = match time_reveal_batch(160).await {
		Ok(elapsed) => elapsed,
		Err(error) => panic!("160-open reveal batch must finish: {error}"),
	};

	eprintln!("reveal batch 16:  {batch_16:?}");
	eprintln!("reveal batch 160: {batch_160:?}");
	assert!(batch_16.as_secs_f64() > 0.0, "16-open batch must record a positive duration");
	assert!(batch_160.as_secs_f64() > 0.0, "160-open batch must record a positive duration");
}

/// HoneyBadger mesh AES-128 one-block encrypt vs the clear `aes` crate.
///
/// Uses the TinyTable LUT path. Exit gate: preprocess plus online must
/// finish within 10 minutes on 5-party localhost.
#[tokio::test]
async fn an_aes128_block_encrypts_end_to_end() {
	// FIPS 197 Appendix C.1.
	const KEY: [u8; 16] = [
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	];
	const PLAIN: [u8; 16] = [
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	];
	// Wait ceiling must cover `aes_party_config` input_wait / engine
	// timeouts. The product assert below still gates wall clock.
	const AES_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30 * 60);
	const AES_GATE: std::time::Duration = std::time::Duration::from_secs(10 * 60);

	let mut values = Vec::with_capacity((BLOCK_LEN * 2) as usize);
	values.extend(KEY.iter().map(|byte| Fr::from(u64::from(*byte))));
	values.extend(PLAIN.iter().map(|byte| Fr::from(u64::from(*byte))));

	let program = match build_aes128_program() {
		Ok(program) => program,
		Err(error) => panic!("AES program must build: {error}"),
	};
	let (networks, client_net) = match topology(PARTIES).await {
		Ok(mesh) => mesh,
		Err(error) => panic!("topology must form: {error}"),
	};
	let party_runs = spawn_aes_runs(networks, THRESHOLD, TraceHandle::default());

	let mut consumer = match VmConsumer::new(client_net) {
		Ok(consumer) => consumer,
		Err(error) => panic!("consumer must construct: {error}"),
	};
	if let Err(error) = consumer.submit(&program, SUBMIT_DEADLINE).await {
		panic!("submit must succeed: {error}");
	}

	let mut session = match consumer.open_session::<Fr, Avid<SessionId>>(&program, THRESHOLD, values) {
		Ok(session) => session,
		Err(error) => panic!("session must open: {error}"),
	};
	let started = std::time::Instant::now();
	let recovered = match session.wait_output(AES_DEADLINE).await {
		Ok(values) => values,
		Err(error) => panic!("output must arrive: {error}"),
	};
	if let Err(error) = await_hosts(party_runs, AES_DEADLINE).await {
		panic!("party hosts must finish: {error}");
	}
	let elapsed = started.elapsed();
	eprintln!("AES LUT mesh e2e elapsed: {elapsed:?}");
	assert!(
		elapsed <= AES_GATE,
		"AES LUT mesh e2e must finish within 10 minutes, took {elapsed:?}"
	);

	let mut reference = PLAIN;
	let cipher = match Aes128::new_from_slice(&KEY) {
		Ok(cipher) => cipher,
		Err(error) => panic!("AES-128 key length is fixed: {error}"),
	};
	cipher.encrypt_block((&mut reference).into());

	let recovered_bytes: Vec<u8> = recovered.iter().map(field_byte).collect();
	assert_eq!(
		recovered_bytes.as_slice(),
		reference.as_slice(),
		"HoneyBadger AES-128 must match the clear reference"
	);
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
