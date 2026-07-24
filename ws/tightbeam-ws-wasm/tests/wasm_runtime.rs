//! Headless-browser runtime proof that tightbeam's two target-specific
//! handshake hazards work on `wasm32-unknown-unknown`:
//!
//! 1. Clock: `OffsetDateTime::now_utc()`
//! 2. RNG: `OsRng` (browser `getrandom/js`)
//!
//! Both panic on wasm without the `wasm` (getrandom/js) and `time/wasm-bindgen`
//! feature wiring; passing here proves that wiring at runtime.
#![cfg(target_arch = "wasm32")]

use tightbeam::crypto::aead::Encryptor;
use tightbeam::crypto::ecies::EciesEncryptor;
use tightbeam::time::OffsetDateTime;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

/// SEC1-compressed encoding of the secp256k1 generator point `G`, used as a
/// valid recipient public key so the encryptor reaches its RNG-backed path.
const G_COMPRESSED: [u8; 33] = [
	0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B,
	0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
];

#[wasm_bindgen_test]
fn now_utc_resolves_browser_clock() {
	let timestamp = OffsetDateTime::now_utc().unix_timestamp();
	assert!(
		timestamp > 1_700_000_000,
		"browser clock must yield a current unix timestamp, got {timestamp}"
	);
}

/// Encrypt `content` for the generator point, expecting every step so
/// the test body stays assertion-only.
fn generator_ciphertext(content: &[u8]) -> Vec<u8> {
	let encryptor = EciesEncryptor::from_bytes(G_COMPRESSED).expect("the recipient public key should parse");
	let info = encryptor
		.encrypt_content(content, [0u8; 12], None)
		.expect("ECIES encrypt should drive OsRng without panicking");

	let ciphertext = info.encrypted_content.expect("the encrypted content should be present");
	ciphertext.as_bytes().to_vec()
}

#[wasm_bindgen_test]
fn ecies_encrypt_resolves_browser_rng() {
	let ciphertext = generator_ciphertext(b"wasm-rng-proof");
	assert!(!ciphertext.is_empty(), "ECIES ciphertext must be non-empty");
}
