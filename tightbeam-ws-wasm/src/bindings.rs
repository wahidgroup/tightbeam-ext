//! The `wasm-bindgen` surface for the browser.
//!
//! Lets a webapp construct a tightbeam frame from an application payload and
//! ship it over the socket. These bindings are generic and transport-only.

use wasm_bindgen::prelude::*;

use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
use tightbeam::der::asn1::OctetString;
use tightbeam::matrix::MatrixDyn;
use tightbeam::{AlgorithmIdentifierOwned, DigestInfo, MessagePriority, ObjectIdentifier, Version};

use crate::build::{self, FrameConfig, FrameSummary, SignerKind};

/// secp256k1 private keys are 32 octets.
const SECP256K1_KEY_LEN: usize = 32;

/// Map a frame-version ordinal (`0..=3`) to a [`Version`].
fn version_from_ordinal(ordinal: u8) -> Option<Version> {
	match ordinal {
		0 => Some(Version::V0),
		1 => Some(Version::V1),
		2 => Some(Version::V2),
		3 => Some(Version::V3),
		_ => None,
	}
}

/// Map a message-priority ordinal (`0..=5`) to a [`MessagePriority`].
fn priority_from_ordinal(ordinal: u8) -> Option<MessagePriority> {
	match ordinal {
		0 => Some(MessagePriority::LowEffort),
		1 => Some(MessagePriority::Standard),
		2 => Some(MessagePriority::HighThroughput),
		3 => Some(MessagePriority::LowLatency),
		4 => Some(MessagePriority::Expedited),
		5 => Some(MessagePriority::NetworkControl),
		_ => None,
	}
}

/// Build a [`DigestInfo`] from a dotted algorithm OID and raw digest octets.
fn digest_info(algorithm_oid: &str, digest: &[u8]) -> Result<DigestInfo, JsError> {
	let oid: ObjectIdentifier = algorithm_oid
		.parse()
		.map_err(|_| JsError::new("previousHash.algorithmOid is not a valid OID"))?;
	let algorithm = AlgorithmIdentifierOwned { oid, parameters: None };
	let digest = OctetString::new(digest).map_err(|error| JsError::new(&error.to_string()))?;
	Ok(DigestInfo { algorithm, digest })
}

/// Stateful, byte-level frame assembler mirroring tightbeam's `FrameBuilder`.
///
/// Construct it, apply the desired `with*` setters in any order, then call
/// [`FrameComposer::build`] to obtain the frame DER. `build` consumes the
/// composer.
#[wasm_bindgen]
#[derive(Default)]
pub struct FrameComposer {
	config: FrameConfig,
}

#[wasm_bindgen]
impl FrameComposer {
	/// Create an empty composer (cleartext V0 by default).
	#[wasm_bindgen(constructor)]
	pub fn new() -> FrameComposer {
		FrameComposer::default()
	}

	/// Pin the protocol version by ordinal (`V0` -> 0, ..., `V3` -> 3).
	#[wasm_bindgen(js_name = withVersion)]
	pub fn with_version(&mut self, ordinal: u8) -> Result<(), JsError> {
		let version = version_from_ordinal(ordinal).ok_or_else(|| JsError::new("version ordinal must be in 0..=3"))?;
		self.config.version = Some(version);
		Ok(())
	}

	/// Set the opaque message identifier.
	#[wasm_bindgen(js_name = withId)]
	pub fn with_id(&mut self, id: Vec<u8>) {
		self.config.id = id;
	}

	/// Set the monotonic order (Unix seconds).
	#[wasm_bindgen(js_name = withOrder)]
	pub fn with_order(&mut self, order: u64) {
		self.config.order = order;
	}

	/// Set the opaque message body.
	#[wasm_bindgen(js_name = withMessage)]
	pub fn with_message(&mut self, message: Vec<u8>) {
		self.config.message = message;
	}

	/// Set the body content-type OID (dotted form).
	#[wasm_bindgen(js_name = withContentOid)]
	pub fn with_content_oid(&mut self, oid: &str) -> Result<(), JsError> {
		let oid: ObjectIdentifier = oid.parse().map_err(|_| JsError::new("contentOid is not a valid OID"))?;
		self.config.content_oid = Some(oid);
		Ok(())
	}

	/// Set the message priority by ordinal (`LowEffort` -> 0, ...).
	#[wasm_bindgen(js_name = withPriority)]
	pub fn with_priority(&mut self, ordinal: u8) -> Result<(), JsError> {
		let priority =
			priority_from_ordinal(ordinal).ok_or_else(|| JsError::new("priority ordinal must be in 0..=5"))?;
		self.config.priority = Some(priority);
		Ok(())
	}

	/// Set the time-to-live in seconds.
	#[wasm_bindgen(js_name = withLifetime)]
	pub fn with_lifetime(&mut self, seconds: u64) {
		self.config.lifetime = Some(seconds);
	}

	/// Link this frame to a parent by content digest (algorithm OID + digest).
	#[wasm_bindgen(js_name = withPreviousHash)]
	pub fn with_previous_hash(&mut self, algorithm_oid: &str, digest: Vec<u8>) -> Result<(), JsError> {
		self.config.previous_hash = Some(digest_info(algorithm_oid, &digest)?);
		Ok(())
	}

	/// Set an N×N control matrix from row-major bytes (`data.len() == n * n`).
	#[wasm_bindgen(js_name = withMatrix)]
	pub fn with_matrix(&mut self, n: u8, data: Vec<u8>) -> Result<(), JsError> {
		let matrix =
			MatrixDyn::from_row_major(n, data).ok_or_else(|| JsError::new("matrix data length must equal n*n"))?;
		self.config.matrix = Some(matrix);
		Ok(())
	}

	/// Commit to the message body with sha3-256 message integrity. The salt may
	/// be empty.
	#[wasm_bindgen(js_name = withMessageHasher)]
	pub fn with_message_hasher(&mut self, salt: Vec<u8>) {
		self.config.message_integrity_salt = Some(salt);
	}

	/// Witness the envelope with sha3-256 frame integrity.
	#[wasm_bindgen(js_name = withWitnessHasher)]
	pub fn with_witness_hasher(&mut self) {
		self.config.frame_integrity = true;
	}

	/// Sign the assembled frame with a local secp256k1 key (32 octets).
	#[wasm_bindgen(js_name = withSigner)]
	pub fn with_signer(&mut self, key_bytes: Vec<u8>) -> Result<(), JsError> {
		let array: [u8; SECP256K1_KEY_LEN] = key_bytes
			.try_into()
			.map_err(|_| JsError::new("secp256k1 key must be 32 octets"))?;
		let key = Secp256k1SigningKey::from_bytes(&array.into()).map_err(|error| JsError::new(&error.to_string()))?;
		self.config.signer = Some(SignerKind::Secp256k1(key));
		Ok(())
	}

	/// Assemble the configured frame and return the frame DER. Consumes the
	/// composer.
	#[wasm_bindgen(js_name = build)]
	pub fn build(self) -> Result<Vec<u8>, JsError> {
		self.config.build().map_err(|error| JsError::new(&error.to_string()))
	}
}

/// Wrap a payload (an already-encoded message body) in a cleartext tightbeam
/// frame, returning the frame DER ready for [`crate::WsClient::request`].
#[wasm_bindgen(js_name = sealFrame)]
pub fn seal_frame(message_der: Vec<u8>, id: Vec<u8>, order: u64) -> Result<Vec<u8>, JsError> {
	build::seal_frame(message_der, id, order).map_err(|error| JsError::new(&error.to_string()))
}

/// Extract the payload body from a tightbeam frame DER.
#[wasm_bindgen(js_name = openFrame)]
pub fn open_frame(frame_der: Vec<u8>) -> Result<Vec<u8>, JsError> {
	build::open_frame(frame_der).map_err(|error| JsError::new(&error.to_string()))
}

/// Read-only view of a decoded frame: body, metadata, and security markers.
///
/// Returned by [`inspect_frame`] so a caller can confirm what a peer echoed
/// back. The fields are copied out of the frame; the view owns its bytes.
#[wasm_bindgen]
pub struct FrameView {
	summary: FrameSummary,
}

#[wasm_bindgen]
impl FrameView {
	/// Protocol version ordinal (`V0` -> 0, ..., `V3` -> 3).
	#[wasm_bindgen(getter)]
	pub fn version(&self) -> u8 {
		self.summary.version
	}

	/// Opaque message identifier.
	#[wasm_bindgen(getter)]
	pub fn id(&self) -> Vec<u8> {
		self.summary.id.clone()
	}

	/// Monotonic order (Unix seconds).
	#[wasm_bindgen(getter)]
	pub fn order(&self) -> u64 {
		self.summary.order
	}

	/// Opaque message body.
	#[wasm_bindgen(getter)]
	pub fn body(&self) -> Vec<u8> {
		self.summary.body.clone()
	}

	/// The frame carries a non-repudiation signature.
	#[wasm_bindgen(getter)]
	pub fn signed(&self) -> bool {
		self.summary.signed
	}

	/// The metadata commits to the body (message integrity).
	#[wasm_bindgen(getter, js_name = messageIntegrity)]
	pub fn message_integrity(&self) -> bool {
		self.summary.message_integrity
	}

	/// The envelope is witnessed (frame integrity).
	#[wasm_bindgen(getter, js_name = frameIntegrity)]
	pub fn frame_integrity(&self) -> bool {
		self.summary.frame_integrity
	}
}

/// Decode a tightbeam frame DER into a [`FrameView`] for inspection.
#[wasm_bindgen(js_name = inspectFrame)]
pub fn inspect_frame(frame_der: Vec<u8>) -> Result<FrameView, JsError> {
	let summary = build::inspect_frame(frame_der).map_err(|error| JsError::new(&error.to_string()))?;
	Ok(FrameView { summary })
}
