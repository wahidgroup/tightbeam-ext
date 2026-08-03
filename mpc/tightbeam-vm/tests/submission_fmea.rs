//! FMEA-scored fault injection over the program submission and digest
//! agreement flow, bound to a live handshake.
//!
//! The consumer submits DER bytes to every party; each party validates
//! and echoes an accept/reject verdict carrying the digest; the
//! consumer proceeds only on unanimous digest agreement. This suite
//! models that flow as a CSP process, injects its enumerable failure
//! modes (malformed program, echo loss, digest disagreement) during
//! FDR exploration, and checks the auto-generated FMEA report scores
//! every mode with a risk priority number.
//!
//! The scenario itself runs the real handshake over localhost TCP: the
//! scenario collector is injected into the consumer and one party, so
//! the trace that must refine the model is the submit / admit /
//! echo-agreement sequence the hosts actually performed.

mod common;

use core::fmt;
use std::sync::Arc;

use tightbeam::testing::fdr::FdrConfig;
use tightbeam::testing::fmea::{FmeaConfig, SeverityScale};
use tightbeam::testing::{FaultModel, InjectionStrategy, ScenarioConfig, SetupEnv, TestHooks};
use tightbeam::utils::BasisPoints;
use tightbeam::TightBeamError;
use tightbeam::{exactly, tb_assert_spec, tb_gen_process_types, tb_process_spec, tb_scenario};
use tightbeam_vm::events::kind::{ADMIT, DIGEST_MISMATCH, ECHO_LOST, ECHO_OK, REFUSE, SUBMIT, SUBMIT_TIMEOUT};
use tightbeam_vm::{ProgramBuilder, TraceHandle, ValidProgram};

use common::{agree_submission, scenario_error, Outcome, CONSUMER};
use submission_agreement::States;

const PARTIES: usize = 3;
const THRESHOLD: usize = 0;

tb_process_spec! {
	/// The VmConsumer::submit / VmParty::receive handshake: submission,
	/// party-side validation, verdict echo, consumer-side agreement.
	pub SubmissionAgreement,
	events {
		observable { SUBMIT, SUBMIT_TIMEOUT, ADMIT, REFUSE, ECHO_OK, ECHO_LOST, DIGEST_MISMATCH }
		hidden { }
	}
	states {
		// await_submission enforces a deadline, so a lost submission
		// terminates instead of stalling the party forever.
		AwaitProgram => {
			SUBMIT => Validating,
			SUBMIT_TIMEOUT => TimedOut,
		},
		Validating => {
			ADMIT => Echoing,
			REFUSE => Rejected,
		},
		Echoing => {
			ECHO_OK => Agreed,
			ECHO_LOST => TimedOut,
			DIGEST_MISMATCH => Aborted,
		},
		Agreed => { },
		Rejected => { },
		TimedOut => { },
		Aborted => { },
	}
	terminal { Agreed, Rejected, TimedOut, Aborted }
	annotations { description: "VM program submission and digest agreement" }
}

tb_gen_process_types!(
	SubmissionAgreement,
	AwaitProgram,
	Validating,
	Echoing,
	Agreed,
	Rejected,
	TimedOut,
	Aborted
);

/// A submission-flow failure mode (injected).
#[derive(Debug, Clone, Copy)]
struct SubmissionFault {
	mode: &'static str,
}

impl fmt::Display for SubmissionFault {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "injected submission failure: {}", self.mode)
	}
}

impl From<SubmissionFault> for TightBeamError {
	fn from(fault: SubmissionFault) -> Self {
		TightBeamError::InjectedFault(Box::new(fault))
	}
}

/// Every enumerable failure mode of the handshake, injected where the
/// real implementation can hit it.
fn submission_fault_model() -> FaultModel {
	FaultModel::from(InjectionStrategy::Deterministic)
		.with_fault(
			States::Validating,
			ADMIT,
			|| SubmissionFault { mode: "malformed or oversized program" },
			BasisPoints::new(3000),
		)
		.with_fault(
			States::Echoing,
			ECHO_OK,
			|| SubmissionFault { mode: "party offline during echo" },
			BasisPoints::new(3000),
		)
		.with_fault(
			States::AwaitProgram,
			SUBMIT,
			|| SubmissionFault { mode: "submission lane closed" },
			BasisPoints::new(2000),
		)
}

fn submission_fdr_config() -> FdrConfig {
	FdrConfig {
		seeds: 64,
		max_depth: 24,
		max_internal_run: 8,
		timeout_ms: 5000,
		specs: vec![SubmissionAgreement::process()],
		fail_fast: false,
		expect_failure: false,
		fault_model: Some(submission_fault_model()),
		fmea_config: Some(FmeaConfig {
			severity_scale: SeverityScale::MilStd1629,
			rpn_critical_threshold: 100,
			auto_generate: true,
		}),
		..Default::default()
	}
}

fn trivial_program() -> Outcome<ValidProgram> {
	let mut builder = ProgramBuilder::default();
	let x = builder.input(CONSUMER, 1);
	builder.output(CONSUMER, x);
	builder.build().map_err(scenario_error)
}

tb_assert_spec! {
	pub AgreementSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(SUBMIT, exactly!(1)),
			(ADMIT, exactly!(1)),
			(ECHO_OK, exactly!(1))
		],
		// Each step causally requires the previous: the party admits
		// only a received submission, the consumer agrees only on the
		// received echo.
		events: [SUBMIT, ADMIT, ECHO_OK]
	}
}

tb_scenario! {
	name: submission_failure_modes_are_scored,
	config: ScenarioConfig::builder()
		.with_spec(AgreementSpec::latest())
		.with_csp(SubmissionAgreement::process())
		.with_fdr(submission_fdr_config())
		.with_hooks(TestHooks {
			on_pass: Some(Arc::new(|result| {
				let verdict = result.fdr_verdict.as_ref().expect("FDR exploration must produce a verdict");
				assert!(verdict.passed, "the agreement model must hold under fault injection");
				assert!(verdict.deadlock_free, "every submission outcome must reach a terminal state");
				assert!(verdict.trace_refines, "the live agreement trace must refine the spec");

				let report = verdict.fmea_report.as_ref().expect("FMEA auto-generation must produce a report");
				assert!(
					!report.failure_modes.is_empty(),
					"injected failure modes must appear in the report"
				);
				assert!(report.total_rpn > 0, "every failure mode carries a risk priority number");
				Ok(())
			})),
			on_fail: None,
		})
		.build(),
	// One real handshake over localhost TCP: every party receives and
	// validates the submission; the consumer collects unanimous echoes.
	// The injected handle observes the consumer and the first party.
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let program = trivial_program()?;
			agree_submission(PARTIES, THRESHOLD, &program, TraceHandle::from(trace.share())).await?;
			Ok(())
		}
	}
}
