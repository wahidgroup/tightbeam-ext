//! The two hazards of a handshake on `wasm32-unknown-unknown`, the host
//! clock and the RNG, as the tests section of `docs/ws-wasm.md` describes.
#![cfg(target_arch = "wasm32")]

use tightbeam::time::OffsetDateTime;
use tightbeam_ws_wasm::build::HpkeSecp256k1Encryptor;
use wasm_bindgen_test::wasm_bindgen_test;

/// SEC1-compressed encoding of the secp256k1 generator point `G`, used as a
/// valid recipient public key so the encryptor reaches its RNG-backed path.
const G_COMPRESSED: [u8; 33] = [
	0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B,
	0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
];

#[wasm_bindgen_test]
fn now_utc_resolves_the_host_clock() {
	let timestamp = OffsetDateTime::now_utc().unix_timestamp();
	assert!(
		timestamp > 1_700_000_000,
		"the host clock must yield a current unix timestamp, got {timestamp}"
	);
}

/// Seal `content` to the generator point, expecting every step so the test
/// body stays assertion-only.
fn generator_ciphertext(content: &[u8]) -> Vec<u8> {
	let encryptor = HpkeSecp256k1Encryptor::from_sec1(G_COMPRESSED).expect("the recipient public key should parse");
	let sealed = encryptor
		.seal(content, None)
		.expect("HPKE seal should drive OsRng without panicking");

	sealed.ciphertext().to_vec()
}

#[wasm_bindgen_test]
fn hpke_seal_resolves_the_host_rng() {
	let ciphertext = generator_ciphertext(b"wasm-rng-proof");
	assert!(!ciphertext.is_empty(), "HPKE ciphertext must be non-empty");
}
