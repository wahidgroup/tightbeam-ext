//! AFL fuzz target for the untrusted program decoder.
//!
//! `ValidProgram::from_der` is the boundary where arbitrary consumer
//! bytes enter a party, so it must never panic and must be canonical:
//! any program it admits re-validates from its own wire bytes to the
//! identical digest. A violation of either property panics, which AFL
//! records as a crash.
//!
//! Build and run with cargo-afl:
//!
//! ```text
//! cargo afl build --bin fuzz_program_decode --features fuzz
//! mkdir -p fuzz_in && printf 'seed' > fuzz_in/seed
//! cargo afl fuzz -i fuzz_in -o fuzz_out target/debug/fuzz_program_decode
//! ```

// Outside AFL, tb_scenario! still smoke-runs exec once with an empty
// oracle so the harness type-checks under cargo check / clippy.
use tightbeam::testing::SetupEnv;
use tightbeam::utils::urn::Urn;
use tightbeam::TightBeamError;
use tightbeam::{at_least, exactly, tb_assert_spec, tb_process_spec, tb_scenario};
use tightbeam_vm::ValidProgram;

/// Bytes arrived at the decoder boundary.
const BYTES: Urn<'static> = Urn::new("tightbeam", "vm:event/decode-bytes");
/// The validator admitted the program.
const ACCEPT: Urn<'static> = Urn::new("tightbeam", "vm:event/decode-accept");
/// The validator rejected the program.
const REJECT: Urn<'static> = Urn::new("tightbeam", "vm:event/decode-reject");

tb_process_spec! {
	/// One decode attempt: bytes arrive, the validator judges them.
	pub DecodePipeline,
	events {
		observable { BYTES, ACCEPT, REJECT }
		hidden { }
	}
	states {
		Feed => { BYTES => Judging },
		Judging => {
			ACCEPT => Done,
			REJECT => Done,
		},
		Done => { },
	}
	terminal { Done }
	annotations { description: "Untrusted VM program decoding" }
}

tb_assert_spec! {
	pub DecodeSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(BYTES, exactly!(1)),
			(ACCEPT, at_least!(0)),
			(REJECT, at_least!(0))
		]
	}
}

tb_scenario! {
	fuzz: afl,
	csp: DecodePipeline,
	config: tightbeam::testing::ScenarioConfig::builder()
		.with_spec(DecodeSpec::latest())
		.with_csp(DecodePipeline::process())
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| -> Result<(), TightBeamError> {
			let Ok(input) = trace.oracle().fuzz_input() else {
				return Ok(());
			};

			trace.event(BYTES)?;
			match ValidProgram::from_der(&input) {
				Ok(program) => {
					// Canonical DER: an admitted program re-validates
					// from its own bytes to the identical digest.
					let reparsed = ValidProgram::from_der(program.bytes());
					assert!(
						matches!(&reparsed, Ok(second) if second.digest() == program.digest()),
						"an admitted program must re-validate to the same digest"
					);
					trace.event(ACCEPT)?;
				}
				Err(_) => {
					trace.event(REJECT)?;
				}
			}
			Ok(())
		}
	}
}
