//! The `wasm-bindgen` surface for the browser and Node.

use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

use tightbeam::asn1::{AlgorithmIdentifierOwned, ObjectIdentifier};
use tightbeam::der::asn1::OctetString;
use tightbeam::matrix::MatrixDyn;
use tightbeam::oids::{
	AES_256_GCM, COMPRESSION_ZLIB, COMPRESSION_ZSTD, DATA, DHKEM_SECP256K1, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256,
};
use tightbeam::{DigestInfo, MessagePriority, Version};

use crate::build::{self, FrameConfig, FrameSummary};

/// Move `bytes` into a JS `Uint8Array` (one boundary copy).
fn bytes_to_js(bytes: Vec<u8>) -> JsValue {
	Uint8Array::from(bytes.as_slice()).into()
}

/// Set an owned byte field on `object` when `value` is `Some`.
fn set_bytes(object: &Object, key: &str, value: Option<Vec<u8>>) {
	if let Some(bytes) = value {
		let _ = Reflect::set(object, &JsValue::from_str(key), &bytes_to_js(bytes));
	}
}

/// Set an owned string field on `object` when `value` is `Some`.
fn set_string(object: &Object, key: &str, value: Option<String>) {
	if let Some(text) = value {
		let _ = Reflect::set(object, &JsValue::from_str(key), &JsValue::from(text));
	}
}

/// Consume a [`FrameSummary`] into one JS object. Field names match the
/// legacy [`FrameView`] getters (`bodyDer`, `matrixN`, ...).
fn summary_into_js(summary: FrameSummary) -> JsValue {
	let object = Object::new();
	let _ = Reflect::set(
		&object,
		&JsValue::from_str("version"),
		&JsValue::from(f64::from(summary.version)),
	);
	let _ = Reflect::set(&object, &JsValue::from_str("id"), &bytes_to_js(summary.id));
	let _ = Reflect::set(&object, &JsValue::from_str("order"), &JsValue::from(summary.order));
	let _ = Reflect::set(&object, &JsValue::from_str("bodyDer"), &bytes_to_js(summary.body_der));
	if let Some(priority) = summary.priority {
		let _ = Reflect::set(&object, &JsValue::from_str("priority"), &JsValue::from(f64::from(priority)));
	}
	if let Some(lifetime) = summary.lifetime {
		let _ = Reflect::set(&object, &JsValue::from_str("lifetime"), &JsValue::from(lifetime));
	}

	set_string(&object, "previousHashAlgorithmOid", summary.previous_hash_algorithm_oid);
	set_bytes(&object, "previousHashDigest", summary.previous_hash_digest);

	if let Some(matrix_n) = summary.matrix_n {
		let _ = Reflect::set(&object, &JsValue::from_str("matrixN"), &JsValue::from(f64::from(matrix_n)));
	}

	set_bytes(&object, "matrixData", summary.matrix_data);
	set_string(&object, "messageIntegrityAlgorithmOid", summary.message_integrity_algorithm_oid);
	set_bytes(&object, "messageIntegrityDigest", summary.message_integrity_digest);
	set_string(&object, "frameIntegrityAlgorithmOid", summary.frame_integrity_algorithm_oid);
	set_bytes(&object, "frameIntegrityDigest", summary.frame_integrity_digest);
	set_string(&object, "compactnessAlgorithmOid", summary.compactness_algorithm_oid);
	set_bytes(&object, "compactnessParametersDer", summary.compactness_parameters_der);
	set_string(&object, "compactnessContentOid", summary.compactness_content_oid);
	set_string(&object, "confidentialityAlgorithmOid", summary.confidentiality_algorithm_oid);
	set_bytes(&object, "confidentialityEnvelopeDer", summary.confidentiality_envelope_der);
	set_string(&object, "signatureAlgorithmOid", summary.signature_algorithm_oid);
	set_string(&object, "signatureDigestAlgorithmOid", summary.signature_digest_algorithm_oid);
	set_bytes(&object, "signature", summary.signature);
	object.into()
}

/// Parse a dotted algorithm OID from the boundary.
fn oid_from(dotted: &str, path: &str) -> Result<ObjectIdentifier, JsError> {
	dotted
		.parse()
		.map_err(|_| JsError::new(&format!("{path} is not a valid dotted OID")))
}

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
	let oid = oid_from(algorithm_oid, "previousHash.algorithmOid")?;
	let algorithm = AlgorithmIdentifierOwned { oid, parameters: None };
	let digest = OctetString::new(digest).map_err(|error| JsError::new(&error.to_string()))?;

	Ok(DigestInfo { algorithm, digest })
}

// ---------------------------------------------------------------------------
// Structure operations (algorithm-agnostic).
// ---------------------------------------------------------------------------

/// Stateful, byte-level structural frame assembler.
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

	/// Set the frame order stamp.
	///
	/// The value is protocol-opaque. Any monotonic scheme works, such as a
	/// Unix timestamp or a dense per-channel counter. When omitted, the
	/// build defaults it to the current Unix time in seconds.
	#[wasm_bindgen(js_name = withOrder)]
	pub fn with_order(&mut self, order: u64) {
		self.config.order = order;
	}

	/// Set the frame body DER. Wrap raw payload bytes with `bodyPreimage` for
	/// the profile opaque body.
	#[wasm_bindgen(js_name = withMessage)]
	pub fn with_message(&mut self, body_der: Vec<u8>) {
		self.config.message = body_der;
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

	/// Assemble the structural frame and return the frame DER. Consumes the
	/// composer.
	#[wasm_bindgen(js_name = build)]
	pub fn build(self) -> Result<Vec<u8>, JsError> {
		self.config.build().map_err(|error| JsError::new(&error.to_string()))
	}
}

/// The DER encoding of the frame body wrapping `message`: the preimage a
/// caller hashes (message integrity) or encrypts (confidentiality).
#[wasm_bindgen(js_name = bodyPreimage)]
pub fn body_preimage(message: Vec<u8>) -> Result<Vec<u8>, JsError> {
	build::body_preimage(message).map_err(|error| JsError::new(&error.to_string()))
}

/// Decode a frame-body DER (a cleartext body, or the plaintext recovered
/// from a confidential one) back into the opaque message bytes.
#[wasm_bindgen(js_name = decodeBody)]
pub fn decode_body(body_der: Vec<u8>) -> Result<Vec<u8>, JsError> {
	build::decode_body(body_der).map_err(|error| JsError::new(&error.to_string()))
}

/// The message-commitment preimage over `body_der` under `salt` (tightbeam's
/// commitment framing). Hash it with any digest and install the result via
/// `setMessageIntegrity`. An empty salt commits in plain-digest mode, and any
/// other salt MUST carry at least 16 octets.
#[wasm_bindgen(js_name = commitmentPreimage)]
pub fn commitment_preimage(salt: Vec<u8>, body_der: Vec<u8>) -> Result<Vec<u8>, JsError> {
	build::commitment_preimage(salt, body_der).map_err(|error| JsError::new(&error.to_string()))
}

/// Install a message-integrity commitment: the digest of
/// `commitmentPreimage` under the caller's algorithm OID (V2+ frames).
#[wasm_bindgen(js_name = setMessageIntegrity)]
pub fn set_message_integrity(frame_der: Vec<u8>, algorithm_oid: &str, digest: Vec<u8>) -> Result<Vec<u8>, JsError> {
	let oid = oid_from(algorithm_oid, "messageIntegrity.algorithmOid")?;
	build::set_message_integrity(frame_der, oid, digest).map_err(|error| JsError::new(&error.to_string()))
}

/// Replace the frame body with `ciphertext` and install `envelope_der`, the
/// DER `AuthEnvelopedData` that seals it, its content detached (V1+ frames).
#[wasm_bindgen(js_name = setConfidentiality)]
pub fn set_confidentiality(frame_der: Vec<u8>, envelope_der: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, JsError> {
	build::set_confidentiality(frame_der, envelope_der, ciphertext).map_err(|error| JsError::new(&error.to_string()))
}

/// Replace the frame body with `compressed` and record the compactness info
/// (any version): the caller's compression algorithm OID, its DER-encoded
/// parameters, and the content-type OID of the uncompressed body (defaults
/// to `id-data`).
#[wasm_bindgen(js_name = setCompactness)]
pub fn set_compactness(
	frame_der: Vec<u8>,
	content_oid: Option<String>,
	algorithm_oid: &str,
	parameters_der: Option<Vec<u8>>,
	compressed: Vec<u8>,
) -> Result<Vec<u8>, JsError> {
	let content_oid = match content_oid {
		Some(dotted) => Some(oid_from(&dotted, "contentOid")?),
		None => None,
	};
	let algorithm_oid = oid_from(algorithm_oid, "compactness.algorithmOid")?;

	build::set_compactness(frame_der, content_oid, algorithm_oid, parameters_der, compressed)
		.map_err(|error| JsError::new(&error.to_string()))
}

/// The frame-integrity (witness) preimage bytes: hash them with any digest
/// and install the result via `attachWitness`.
#[wasm_bindgen(js_name = witnessInput)]
pub fn witness_input(frame_der: Vec<u8>) -> Result<Vec<u8>, JsError> {
	build::witness_input(frame_der).map_err(|error| JsError::new(&error.to_string()))
}

/// Install a frame-integrity witness: the digest of `witnessInput` under the
/// caller's algorithm OID (V2+ frames).
#[wasm_bindgen(js_name = attachWitness)]
pub fn attach_witness(frame_der: Vec<u8>, algorithm_oid: &str, digest: Vec<u8>) -> Result<Vec<u8>, JsError> {
	let oid = oid_from(algorithm_oid, "frameIntegrity.algorithmOid")?;
	build::attach_witness(frame_der, oid, digest).map_err(|error| JsError::new(&error.to_string()))
}

/// The to-be-signed bytes of a frame (everything but the signature field).
/// Call after `attachWitness`. The signature covers the witness.
#[wasm_bindgen(js_name = tbsBytes)]
pub fn tbs_bytes(frame_der: Vec<u8>) -> Result<Vec<u8>, JsError> {
	build::tbs_bytes(frame_der).map_err(|error| JsError::new(&error.to_string()))
}

/// The digest the key named by `signer_key_id` signs for this frame: the
/// digest of its CMS signed attributes, which bind `tbsBytes`. Sign it
/// directly, with no rehash, and install the result via `attachSignature`.
#[wasm_bindgen(js_name = signingPrehash)]
pub fn signing_prehash(frame_der: Vec<u8>, signer_key_id: Vec<u8>) -> Result<Vec<u8>, JsError> {
	build::signing_prehash(frame_der, signer_key_id).map_err(|error| JsError::new(&error.to_string()))
}

/// The digest a verifier checks this signed frame's signature against.
#[wasm_bindgen(js_name = signaturePrehash)]
pub fn signature_prehash(frame_der: Vec<u8>) -> Result<Vec<u8>, JsError> {
	build::signature_prehash(frame_der).map_err(|error| JsError::new(&error.to_string()))
}

/// Attach `signature`, a DER `ECDSA-Sig-Value` over `signingPrehash`, to an
/// unsigned frame (V1+ frames). `signer_key_id` is the subject key identifier
/// that names the signer's certificate.
#[wasm_bindgen(js_name = attachSignature)]
pub fn attach_signature(frame_der: Vec<u8>, signature: Vec<u8>, signer_key_id: Vec<u8>) -> Result<Vec<u8>, JsError> {
	build::attach_signature(frame_der, signature, signer_key_id).map_err(|error| JsError::new(&error.to_string()))
}

/// Read-only view of a decoded frame: body, metadata, and the carried
/// security infos (algorithm OIDs + artifacts) for caller-side verification.
///
/// Prefer [`FrameView::take_fields`] (or [`inspect_frame_fields`]) so the
/// summary moves into JS once. Getters clone and are for ad-hoc inspection.
#[wasm_bindgen]
pub struct FrameView {
	summary: Option<FrameSummary>,
}

#[wasm_bindgen]
impl FrameView {
	/// Move every field into one plain object and empty this view.
	///
	/// Field names match the getters (`bodyDer`, `matrixN`, ...). A second
	/// call rejects with `FrameViewConsumed`.
	#[wasm_bindgen(js_name = takeFields, unchecked_return_type = "InspectedFrame")]
	pub fn take_fields(&mut self) -> Result<JsValue, JsError> {
		let summary = self
			.summary
			.take()
			.ok_or_else(|| JsError::new("FrameViewConsumed: fields already taken"))?;
		Ok(summary_into_js(summary))
	}

	/// Protocol version ordinal (`V0` -> 0, ..., `V3` -> 3).
	#[wasm_bindgen(getter)]
	pub fn version(&self) -> u8 {
		self.summary.as_ref().map(|summary| summary.version).unwrap_or(0)
	}

	/// Opaque message identifier.
	#[wasm_bindgen(getter)]
	pub fn id(&self) -> Vec<u8> {
		self.summary.as_ref().map(|summary| summary.id.clone()).unwrap_or_default()
	}

	/// Frame order stamp.
	///
	/// The value is protocol-opaque. Any monotonic scheme works, such as a
	/// Unix timestamp or a dense per-channel counter. When omitted at build
	/// time, the profile defaults to the current Unix time in seconds.
	#[wasm_bindgen(getter)]
	pub fn order(&self) -> u64 {
		self.summary.as_ref().map(|summary| summary.order).unwrap_or(0)
	}

	/// The raw frame body: the sender's body DER when cleartext, the
	/// ciphertext when confidential. Decode a profile opaque body with
	/// `decodeBody`. Typed bodies decode under the caller's schema.
	#[wasm_bindgen(getter, js_name = bodyDer)]
	pub fn body_der(&self) -> Vec<u8> {
		self.summary
			.as_ref()
			.map(|summary| summary.body_der.clone())
			.unwrap_or_default()
	}

	/// Message priority ordinal (`LowEffort` -> 0, ...), when present (V2+).
	#[wasm_bindgen(getter)]
	pub fn priority(&self) -> Option<u8> {
		self.summary.as_ref().and_then(|summary| summary.priority)
	}

	/// Time-to-live in seconds, when present (V2+).
	#[wasm_bindgen(getter)]
	pub fn lifetime(&self) -> Option<u64> {
		self.summary.as_ref().and_then(|summary| summary.lifetime)
	}

	/// Parent-link digest algorithm OID (dotted form), when present (V2+).
	#[wasm_bindgen(getter, js_name = previousHashAlgorithmOid)]
	pub fn previous_hash_algorithm_oid(&self) -> Option<String> {
		self.summary
			.as_ref()
			.and_then(|summary| summary.previous_hash_algorithm_oid.clone())
	}

	/// Parent-link digest octets, when present (V2+).
	#[wasm_bindgen(getter, js_name = previousHashDigest)]
	pub fn previous_hash_digest(&self) -> Option<Vec<u8>> {
		self.summary.as_ref().and_then(|summary| summary.previous_hash_digest.clone())
	}

	/// Control-matrix dimension N, when present (V3+).
	#[wasm_bindgen(getter, js_name = matrixN)]
	pub fn matrix_n(&self) -> Option<u8> {
		self.summary.as_ref().and_then(|summary| summary.matrix_n)
	}

	/// Control-matrix row-major bytes, when present (V3+).
	#[wasm_bindgen(getter, js_name = matrixData)]
	pub fn matrix_data(&self) -> Option<Vec<u8>> {
		self.summary.as_ref().and_then(|summary| summary.matrix_data.clone())
	}

	/// Message-commitment digest algorithm OID, when committed.
	#[wasm_bindgen(getter, js_name = messageIntegrityAlgorithmOid)]
	pub fn message_integrity_algorithm_oid(&self) -> Option<String> {
		self.summary
			.as_ref()
			.and_then(|summary| summary.message_integrity_algorithm_oid.clone())
	}

	/// Message-commitment digest octets, when committed.
	#[wasm_bindgen(getter, js_name = messageIntegrityDigest)]
	pub fn message_integrity_digest(&self) -> Option<Vec<u8>> {
		self.summary
			.as_ref()
			.and_then(|summary| summary.message_integrity_digest.clone())
	}

	/// Witness digest algorithm OID, when witnessed.
	#[wasm_bindgen(getter, js_name = frameIntegrityAlgorithmOid)]
	pub fn frame_integrity_algorithm_oid(&self) -> Option<String> {
		self.summary
			.as_ref()
			.and_then(|summary| summary.frame_integrity_algorithm_oid.clone())
	}

	/// Witness digest octets, when witnessed.
	#[wasm_bindgen(getter, js_name = frameIntegrityDigest)]
	pub fn frame_integrity_digest(&self) -> Option<Vec<u8>> {
		self.summary.as_ref().and_then(|summary| summary.frame_integrity_digest.clone())
	}

	/// Body-compression algorithm OID, when compressed.
	#[wasm_bindgen(getter, js_name = compactnessAlgorithmOid)]
	pub fn compactness_algorithm_oid(&self) -> Option<String> {
		self.summary
			.as_ref()
			.and_then(|summary| summary.compactness_algorithm_oid.clone())
	}

	/// Body-compression algorithm parameters DER, when compressed and
	/// present.
	#[wasm_bindgen(getter, js_name = compactnessParametersDer)]
	pub fn compactness_parameters_der(&self) -> Option<Vec<u8>> {
		self.summary
			.as_ref()
			.and_then(|summary| summary.compactness_parameters_der.clone())
	}

	/// Content-type OID of the uncompressed body, when compressed.
	#[wasm_bindgen(getter, js_name = compactnessContentOid)]
	pub fn compactness_content_oid(&self) -> Option<String> {
		self.summary
			.as_ref()
			.and_then(|summary| summary.compactness_content_oid.clone())
	}

	/// Content-encryption algorithm OID, when confidential.
	#[wasm_bindgen(getter, js_name = confidentialityAlgorithmOid)]
	pub fn confidentiality_algorithm_oid(&self) -> Option<String> {
		self.summary
			.as_ref()
			.and_then(|summary| summary.confidentiality_algorithm_oid.clone())
	}

	/// DER `AuthEnvelopedData` that seals the body, when confidential.
	#[wasm_bindgen(getter, js_name = confidentialityEnvelopeDer)]
	pub fn confidentiality_envelope_der(&self) -> Option<Vec<u8>> {
		self.summary
			.as_ref()
			.and_then(|summary| summary.confidentiality_envelope_der.clone())
	}

	/// Signature algorithm OID, when signed.
	#[wasm_bindgen(getter, js_name = signatureAlgorithmOid)]
	pub fn signature_algorithm_oid(&self) -> Option<String> {
		self.summary
			.as_ref()
			.and_then(|summary| summary.signature_algorithm_oid.clone())
	}

	/// Signature digest algorithm OID, when signed.
	#[wasm_bindgen(getter, js_name = signatureDigestAlgorithmOid)]
	pub fn signature_digest_algorithm_oid(&self) -> Option<String> {
		self.summary
			.as_ref()
			.and_then(|summary| summary.signature_digest_algorithm_oid.clone())
	}

	/// DER signature octets, when signed.
	#[wasm_bindgen(getter)]
	pub fn signature(&self) -> Option<Vec<u8>> {
		self.summary.as_ref().and_then(|summary| summary.signature.clone())
	}
}

/// Decode a tightbeam frame DER into a [`FrameView`] for inspection.
#[wasm_bindgen(js_name = inspectFrame)]
pub fn inspect_frame(frame_der: Vec<u8>) -> Result<FrameView, JsError> {
	let summary = build::inspect_frame(frame_der).map_err(|error| JsError::new(&error.to_string()))?;
	Ok(FrameView { summary: Some(summary) })
}

/// TypeScript shape returned by [`inspect_frame_fields`].
#[wasm_bindgen(typescript_custom_section)]
const INSPECTED_FRAME_TS: &'static str = r#"
export interface InspectedFrame {
	version: number;
	id: Uint8Array;
	order: bigint;
	bodyDer: Uint8Array;
	priority?: number;
	lifetime?: bigint;
	previousHashAlgorithmOid?: string;
	previousHashDigest?: Uint8Array;
	matrixN?: number;
	matrixData?: Uint8Array;
	messageIntegrityAlgorithmOid?: string;
	messageIntegrityDigest?: Uint8Array;
	frameIntegrityAlgorithmOid?: string;
	frameIntegrityDigest?: Uint8Array;
	compactnessAlgorithmOid?: string;
	compactnessParametersDer?: Uint8Array;
	compactnessContentOid?: string;
	confidentialityAlgorithmOid?: string;
	confidentialityEnvelopeDer?: Uint8Array;
	signatureAlgorithmOid?: string;
	signatureDigestAlgorithmOid?: string;
	signature?: Uint8Array;
}
"#;

/// Decode a frame DER and return every field in one plain object.
///
/// Same shape as [`FrameView::take_fields`], without retaining a view.
#[wasm_bindgen(js_name = inspectFrameFields, unchecked_return_type = "InspectedFrame")]
pub fn inspect_frame_fields(frame_der: Vec<u8>) -> Result<JsValue, JsError> {
	let summary = build::inspect_frame(frame_der).map_err(|error| JsError::new(&error.to_string()))?;
	Ok(summary_into_js(summary))
}

// ---------------------------------------------------------------------------
// Tightbeam profile primitives (SHA3-256 / secp256k1 / AES-256-GCM / HPKE).
// ---------------------------------------------------------------------------

/// TypeScript shape of the [`profile_oids`] table.
#[wasm_bindgen(typescript_custom_section)]
const PROFILE_OIDS_TS: &'static str = r#"
/**
 * The dotted OIDs of the tightbeam profile (`tightbeam::oids`).
 *
 * # Sources
 *
 * - RFC 8878, Zstandard compression:
 *   <https://datatracker.ietf.org/doc/html/rfc8878>
 * - RFC 3274, Compressed Data Content Type:
 *   <https://datatracker.ietf.org/doc/html/rfc3274>
 * - RFC 9629, Using Key Encapsulation Mechanism (KEM) Algorithms in CMS:
 *   <https://datatracker.ietf.org/doc/html/rfc9629>
 */
export interface ProfileOids {
	/**
	 * SHA3-256, the profile digest.
	 */
	readonly sha3_256: string;
	/**
	 * secp256k1 ECDSA over SHA3-256, the profile signature.
	 */
	readonly ecdsaWithSha3_256: string;
	/**
	 * AES-256-GCM, the profile symmetric cipher.
	 */
	readonly aes256Gcm: string;
	/**
	 * DHKEM over secp256k1, the profile recipient KEM.
	 */
	readonly dhkemSecp256k1: string;
	/**
	 * Zstandard, the profile compression.
	 */
	readonly zstd: string;
	/**
	 * zlib, interoperable with `CompressionStream("deflate")`.
	 */
	readonly zlib: string;
	/**
	 * id-data: the content type recorded in the compactness info and in an
	 * envelope when the caller names none.
	 */
	readonly data: string;
}
"#;

/// The dotted OIDs of the tightbeam profile, read from the `tightbeam`
/// crate's constants so downstream copies of the table can be checked
/// against the engine instead of restated by hand.
#[wasm_bindgen(js_name = profileOids, unchecked_return_type = "ProfileOids")]
pub fn profile_oids() -> Result<JsValue, JsValue> {
	let entries: [(&str, ObjectIdentifier); 7] = [
		("sha3_256", HASH_SHA3_256),
		("ecdsaWithSha3_256", SIGNER_ECDSA_WITH_SHA3_256),
		("aes256Gcm", AES_256_GCM),
		("dhkemSecp256k1", DHKEM_SECP256K1),
		("zstd", COMPRESSION_ZSTD),
		("zlib", COMPRESSION_ZLIB),
		("data", DATA),
	];

	let table = Object::new();
	for (key, oid) in entries {
		let dotted = JsValue::from_str(&oid.to_string());
		Reflect::set(&table, &JsValue::from_str(key), &dotted)?;
	}

	Ok(table.into())
}
