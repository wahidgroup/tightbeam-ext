//! Golden emit: fixture `.d.ts` pairs become the expected MessageCodec module.

use std::path::PathBuf;

use tightbeam_asn::emit::{discover_pairs, emit_codecs_ts, EmitError, EmitOptions};

fn fixture(name: &str) -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

#[test]
fn sample_dts_matches_expected_codecs_ts() -> Result<(), EmitError> {
	let dts_name = concat!("sample", ".d.ts");
	let expected_name = concat!("expected_codecs", ".ts");
	let dts = std::fs::read_to_string(fixture(dts_name))?;
	let names = discover_pairs(&dts)?;
	let opts = EmitOptions {
		import: concat!("#", "apollyon-asn").to_owned(),
		init_import: Some(concat!("./asnInit", ".js").to_owned()),
		message_codec_from: concat!("@wahidgroup/tightbeam-ws-", "client").to_owned(),
	};

	let actual = emit_codecs_ts(&names, &opts);
	let expected = std::fs::read_to_string(fixture(expected_name))?;
	assert_eq!(actual, expected, "generated codecs module must match fixture");
	Ok(())
}
