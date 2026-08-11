//! Integration: emit discovers wasm pairs from fixture `.d.ts` inputs.

use std::fs;
use std::path::PathBuf;

use tightbeam_asn::emit::{discover_pairs, EmitError};

fn fixture(name: &str) -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

#[test]
fn sample_dts_discovers_codec_pairs() -> Result<(), EmitError> {
	let dts = fs::read_to_string(fixture(concat!("sample", ".d.ts")))?;
	let names = discover_pairs(&dts)?;
	assert_eq!(
		names,
		vec![String::from("Doc"), String::from("StatusReport")],
		"only types with both encode and decode exports are discovered"
	);
	Ok(())
}
