//! Integration: emit discovers wasm pairs from fixture `.d.ts` inputs, as a
//! tightbeam scenario whose spec grades the pairs it discovered.
#![cfg(not(target_arch = "wasm32"))]

use std::fs;
use std::io;
use std::path::PathBuf;

use tightbeam::testing::SetupEnv;
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn, TightBeamError};
use tightbeam_asn::emit::CodecPairs;

/// The names of the codec pairs that a parse discovered, joined by commas.
const DISCOVERED: Urn<'static> = urn!("test", "event:asn-emit/discovered");

/// The fixture `name`. `sample.d.ts` is the parser input of the refusal path,
/// an encode with no decode, which a real wasm build never declares.
fn fixture(name: &str) -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

tb_assert_spec! {
	pub CodecPairsSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(DISCOVERED, exactly!(1), equals!("Doc,StatusReport"))
		]
	}
}

// Only the types with both an encode and a decode export are discovered.
tb_scenario! {
	name: sample_dts_discovers_codec_pairs,
	spec: CodecPairsSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| -> Result<(), TightBeamError> {
			let dts = fs::read_to_string(fixture("sample.d.ts"))?;
			let pairs: CodecPairs = dts.parse().map_err(io::Error::other)?;
			trace.event_with(DISCOVERED, &[], pairs.names().join(","))?;
			Ok(())
		}
	}
}
