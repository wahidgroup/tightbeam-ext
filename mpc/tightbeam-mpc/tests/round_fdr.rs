//! Model-checks the session round lifecycle with FDR exploration and
//! fault injection, then binds the model to live execution.
//!
//! [`tightbeam_mpc::Round`] enforces phase order locally; this suite
//! models that machine as a CSP process spec and verifies it two ways:
//!
//! - Seeded FDR exploration with faults injected on every forward
//!   transition proves the model is deadlock-free and never reaches an
//!   invalid state, exhaustively rather than by listing wrong-round
//!   cases by hand.
//! - The happy-path scenario runs a real three-party round over
//!   localhost TCP with the scenario collector injected into party 0
//!   and the consumer, so the trace that must refine the spec is the
//!   phase sequence those hosts actually performed.
//!
//! The recovery scenario stays model-driven: tightbeam's runtime fault
//! injection has no public setter yet, so the failure back-edges are
//! replayed from the spec rather than forced on a live session.

mod common;

use core::time::Duration;
use std::sync::Arc;

use ark_bls12_381::Fr;
use tightbeam::testing::fdr::FdrConfig;
use tightbeam::testing::{FaultModel, InjectionStrategy, ScenarioConfig, SetupEnv, TestHooks};
use tightbeam::utils::BasisPoints;
use tightbeam::TightBeamError;
use tightbeam::{at_least, exactly, tb_assert_spec, tb_gen_process_types, tb_process_spec, tb_scenario};
use tightbeam_mpc::events::kind::{
	COLLECT, COLLECT_FAIL, COMPUTE, COMPUTE_FAIL, OUTPUT, OUTPUT_FAIL, OUTPUT_OK, PREPROCESS, PREPROCESS_FAIL,
	PREPROCESS_OK,
};
use tightbeam_mpc::TraceHandle;

use common::{square_round, SquareRound};
use round_lifecycle::States;

const PARTIES: usize = 3;
const THRESHOLD: usize = 0;
const CONSUMER: usize = 100;
const INPUTS: [u64; 2] = [3, 4];
const INSTANCE: u32 = 41;
const STAGE_DEADLINE: Duration = Duration::from_secs(60);

tb_process_spec! {
	/// The PartySession round machine from tightbeam-mpc's session
	/// module: forward phases plus the failure back-edges each phase
	/// method takes when its engine call errors.
	pub RoundLifecycle,
	events {
		observable {
			PREPROCESS,
			PREPROCESS_OK,
			PREPROCESS_FAIL,
			COLLECT,
			COLLECT_FAIL,
			COMPUTE,
			COMPUTE_FAIL,
			OUTPUT,
			OUTPUT_OK,
			OUTPUT_FAIL,
		}
		hidden { }
	}
	states {
		Idle => { PREPROCESS => Preprocessing },
		Preprocessing => {
			PREPROCESS_OK => Ready,
			PREPROCESS_FAIL => Idle,
		},
		Ready => { COLLECT => Input },
		Input => {
			COLLECT_FAIL => Ready,
			COMPUTE => Computing,
		},
		Computing => {
			COMPUTE_FAIL => Input,
			OUTPUT => Output,
		},
		Output => {
			OUTPUT_OK => Finished,
			OUTPUT_FAIL => Computing,
		},
		Finished => { },
	}
	terminal { Finished }
	annotations { description: "HoneyBadger session round lifecycle" }
}

tb_gen_process_types!(RoundLifecycle, Idle, Preprocessing, Ready, Input, Computing, Output, Finished);

/// A protocol phase failed mid-round (injected).
#[derive(Debug, Clone, Copy)]
struct PhaseFault {
	phase: &'static str,
}

impl core::fmt::Display for PhaseFault {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "injected {} failure", self.phase)
	}
}

impl From<PhaseFault> for TightBeamError {
	fn from(fault: PhaseFault) -> Self {
		TightBeamError::InjectedFault(Box::new(fault))
	}
}

/// Faults on every forward transition: each phase can fail exactly
/// where the session's engine calls can.
fn phase_fault_model() -> FaultModel {
	FaultModel::from(InjectionStrategy::Deterministic)
		.with_fault(
			States::Preprocessing,
			PREPROCESS_OK,
			|| PhaseFault { phase: "preprocessing" },
			BasisPoints::new(3000),
		)
		.with_fault(States::Input, COMPUTE, || PhaseFault { phase: "input" }, BasisPoints::new(3000))
		.with_fault(
			States::Computing,
			OUTPUT,
			|| PhaseFault { phase: "computing" },
			BasisPoints::new(3000),
		)
		.with_fault(
			States::Output,
			OUTPUT_OK,
			|| PhaseFault { phase: "output" },
			BasisPoints::new(3000),
		)
}

fn round_fdr_config() -> FdrConfig {
	FdrConfig {
		seeds: 64,
		max_depth: 48,
		max_internal_run: 8,
		timeout_ms: 5000,
		specs: vec![RoundLifecycle::process()],
		fail_fast: false,
		expect_failure: false,
		fault_model: Some(phase_fault_model()),
		..Default::default()
	}
}

tb_assert_spec! {
	pub HappyPathSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PREPROCESS, exactly!(1)),
			(PREPROCESS_OK, exactly!(1)),
			(COLLECT, exactly!(1)),
			(COMPUTE, exactly!(1)),
			(OUTPUT, exactly!(1)),
			(OUTPUT_OK, exactly!(1))
		],
		// The observed party's phases are strictly sequential, so the
		// instrumented URN stream must carry them in round order.
		events: [PREPROCESS, PREPROCESS_OK, COLLECT, COMPUTE, OUTPUT, OUTPUT_OK]
	}
}

tb_scenario! {
	name: the_live_round_survives_fault_injection,
	config: ScenarioConfig::builder()
		.with_spec(HappyPathSpec::latest())
		.with_csp(RoundLifecycle::process())
		.with_fdr(round_fdr_config())
		.with_hooks(TestHooks {
			on_pass: Some(Arc::new(|result| {
				let verdict = result.fdr_verdict.as_ref().expect("FDR exploration must produce a verdict");
				assert!(verdict.passed, "the round model must hold under fault injection");
				assert!(verdict.deadlock_free, "no round state may deadlock");
				assert!(verdict.divergence_free, "the round machine has no hidden loops to diverge in");
				assert!(
					!verdict.faults_injected.is_empty(),
					"deterministic injection must exercise the failure back-edges"
				);
				assert!(verdict.trace_refines, "the live round trace must refine the spec");
				Ok(())
			})),
			on_fail: None,
		})
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let params = SquareRound {
				parties: PARTIES,
				threshold: THRESHOLD,
				consumer: CONSUMER,
				inputs: &INPUTS,
				instance: INSTANCE,
				stage_deadline: STAGE_DEADLINE,
				preprocess_deadline: STAGE_DEADLINE,
				client_ready: Duration::from_secs(10),
				input_wait: Duration::from_secs(10),
				engine_timeout: Duration::from_secs(60),
			};
			let recovered = square_round(params, TraceHandle::from(trace.share())).await?;
			let expected: Vec<Fr> = INPUTS.iter().map(|value| Fr::from(value * value)).collect();
			assert_eq!(recovered, expected, "the live round must square the inputs");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub RecoveryPathSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PREPROCESS, exactly!(2)),
			(PREPROCESS_FAIL, exactly!(1)),
			(PREPROCESS_OK, exactly!(1)),
			(COLLECT, at_least!(1)),
			(COMPUTE, exactly!(2)),
			(COMPUTE_FAIL, exactly!(1)),
			(OUTPUT, exactly!(1)),
			(OUTPUT_OK, exactly!(1))
		]
	}
}

tb_scenario! {
	name: failure_back_edges_refine_the_round_model,
	config: ScenarioConfig::builder()
		.with_spec(RecoveryPathSpec::latest())
		.with_csp(RoundLifecycle::process())
		.with_fdr(round_fdr_config())
		.with_hooks(TestHooks {
			on_pass: Some(Arc::new(|result| {
				let verdict = result.fdr_verdict.as_ref().expect("FDR exploration must produce a verdict");
				assert!(verdict.passed, "the recovery trace must stay within the model");
				assert!(
					verdict.trace_refines,
					"retry-after-failure is a legal path through the round machine"
				);
				Ok(())
			})),
			on_fail: None,
		})
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// Preprocessing fails once and retries (Preprocessing -> Idle),
			// then a compute failure rewinds to Input before succeeding -
			// the exact back-edges preprocess() and compute() take on error.
			trace.event(PREPROCESS)?;
			trace.event(PREPROCESS_FAIL)?;
			trace.event(PREPROCESS)?;
			trace.event(PREPROCESS_OK)?;
			trace.event(COLLECT)?;
			trace.event(COMPUTE)?;
			trace.event(COMPUTE_FAIL)?;
			trace.event(COMPUTE)?;
			trace.event(OUTPUT)?;
			trace.event(OUTPUT_OK)?;
			Ok(())
		}
	}
}
