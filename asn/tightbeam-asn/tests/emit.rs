//! Integration: emit discovers wasm pairs from fixture `.d.ts` inputs.

use std::fs;
use std::path::PathBuf;

use tightbeam_asn::emit::{CodecPairs, EmitError};

/// The fixture `name`. `sample.d.ts` is the parser input of the refusal path,
/// an encode with no decode, which a real wasm build never declares.
fn fixture(name: &str) -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

#[test]
fn sample_dts_discovers_codec_pairs() -> Result<(), EmitError> {
	let dts = fs::read_to_string(fixture("sample.d.ts"))?;
	let pairs: CodecPairs = dts.parse()?;
	assert_eq!(
		pairs.names(),
		[String::from("Doc"), String::from("StatusReport")],
		"only types with both encode and decode exports are discovered"
	);
	Ok(())
}
