//! The `wasm-bindgen` surface for the browser and Node.

use wasm_bindgen::prelude::*;

use tightbeam::der::asn1::OctetString;
use tightbeam::matrix::MatrixDyn;
use tightbeam::{AlgorithmIdentifierOwned, DigestInfo, MessagePriority, ObjectIdentifier, Version};

use crate::build::{self, FrameConfig, FrameSummary};

/// secp256k1 private keys are 32 octets.
const SECP256K1_KEY_LEN: usize = 32;

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
/// `setMessageIntegrity`.
#[wasm_bindgen(js_name = commitmentPreimage)]
pub fn commitment_preimage(salt: Vec<u8>, body_der: Vec<u8>) -> Vec<u8> {
	build::commitment_preimage(salt, body_der)
}

/// Install a message-integrity commitment: the digest of
/// `commitmentPreimage` under the caller's algorithm OID (V2+ frames).
#[wasm_bindgen(js_name = setMessageIntegrity)]
pub fn set_message_integrity(frame_der: Vec<u8>, algorithm_oid: &str, digest: Vec<u8>) -> Result<Vec<u8>, JsError> {
	let oid = oid_from(algorithm_oid, "messageIntegrity.algorithmOid")?;
	build::set_message_integrity(frame_der, oid, digest).map_err(|error| JsError::new(&error.to_string()))
}

/// Replace the frame body with `ciphertext` and record the confidentiality
/// info (V1+ frames): the caller's encryption algorithm OID, its DER-encoded
/// parameters (e.g. the nonce; pass `undefined` when the scheme has none),
/// and the plaintext content-type OID (defaults to `id-data`).
#[wasm_bindgen(js_name = setConfidentiality)]
pub fn set_confidentiality(
	frame_der: Vec<u8>,
	content_oid: Option<String>,
	algorithm_oid: &str,
	parameters_der: Option<Vec<u8>>,
	ciphertext: Vec<u8>,
) -> Result<Vec<u8>, JsError> {
	let content_oid = match content_oid {
		Some(dotted) => Some(oid_from(&dotted, "contentOid")?),
		None => None,
	};
	let algorithm_oid = oid_from(algorithm_oid, "confidentiality.algorithmOid")?;

	build::set_confidentiality(frame_der, content_oid, algorithm_oid, parameters_der, ciphertext)
		.map_err(|error| JsError::new(&error.to_string()))
}

/// The frame-integrity (witness) preimage bytes: hash them with any digest
/// and install the result via `attachWitness`. Call after all metadata
/// mutations; the witness covers the final envelope.
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
/// Sign them with any scheme and install the result via `attachSignature`.
/// Call after `attachWitness`; the signature covers the witness.
#[wasm_bindgen(js_name = tbsBytes)]
pub fn tbs_bytes(frame_der: Vec<u8>) -> Result<Vec<u8>, JsError> {
	build::tbs_bytes(frame_der).map_err(|error| JsError::new(&error.to_string()))
}

/// Attach a detached signature over `tbsBytes` to an unsigned frame (V1+
/// frames), identified by the caller's signature and digest algorithm OIDs
/// plus a subject-key-identifier octet string naming the signer.
#[wasm_bindgen(js_name = attachSignature)]
pub fn attach_signature(
	frame_der: Vec<u8>,
	signature: Vec<u8>,
	signature_algorithm_oid: &str,
	digest_algorithm_oid: &str,
	signer_key_id: Vec<u8>,
) -> Result<Vec<u8>, JsError> {
	let signature_oid = oid_from(signature_algorithm_oid, "signature.algorithmOid")?;
	let digest_oid = oid_from(digest_algorithm_oid, "signature.digestAlgorithmOid")?;

	build::attach_signature(frame_der, signature, signature_oid, digest_oid, signer_key_id)
		.map_err(|error| JsError::new(&error.to_string()))
}

/// Read-only view of a decoded frame: body, metadata, and the carried
/// security infos (algorithm OIDs + artifacts) for caller-side verification.
///
/// Returned by [`inspect_frame`]. The fields are copied out of the frame;
/// the view owns its bytes.
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

	/// Opaque message body: the decoded payload when cleartext, the raw
	/// ciphertext when confidential.
	#[wasm_bindgen(getter)]
	pub fn body(&self) -> Vec<u8> {
		self.summary.body.clone()
	}

	/// Message priority ordinal (`LowEffort` -> 0, ...), when present (V2+).
	#[wasm_bindgen(getter)]
	pub fn priority(&self) -> Option<u8> {
		self.summary.priority
	}

	/// Time-to-live in seconds, when present (V2+).
	#[wasm_bindgen(getter)]
	pub fn lifetime(&self) -> Option<u64> {
		self.summary.lifetime
	}

	/// Parent-link digest algorithm OID (dotted form), when present (V2+).
	#[wasm_bindgen(getter, js_name = previousHashAlgorithmOid)]
	pub fn previous_hash_algorithm_oid(&self) -> Option<String> {
		self.summary.previous_hash_algorithm_oid.clone()
	}

	/// Parent-link digest octets, when present (V2+).
	#[wasm_bindgen(getter, js_name = previousHashDigest)]
	pub fn previous_hash_digest(&self) -> Option<Vec<u8>> {
		self.summary.previous_hash_digest.clone()
	}

	/// Control-matrix dimension N, when present (V3+).
	#[wasm_bindgen(getter, js_name = matrixN)]
	pub fn matrix_n(&self) -> Option<u8> {
		self.summary.matrix_n
	}

	/// Control-matrix row-major bytes, when present (V3+).
	#[wasm_bindgen(getter, js_name = matrixData)]
	pub fn matrix_data(&self) -> Option<Vec<u8>> {
		self.summary.matrix_data.clone()
	}

	/// Message-commitment digest algorithm OID, when committed.
	#[wasm_bindgen(getter, js_name = messageIntegrityAlgorithmOid)]
	pub fn message_integrity_algorithm_oid(&self) -> Option<String> {
		self.summary.message_integrity_algorithm_oid.clone()
	}

	/// Message-commitment digest octets, when committed.
	#[wasm_bindgen(getter, js_name = messageIntegrityDigest)]
	pub fn message_integrity_digest(&self) -> Option<Vec<u8>> {
		self.summary.message_integrity_digest.clone()
	}

	/// Witness digest algorithm OID, when witnessed.
	#[wasm_bindgen(getter, js_name = frameIntegrityAlgorithmOid)]
	pub fn frame_integrity_algorithm_oid(&self) -> Option<String> {
		self.summary.frame_integrity_algorithm_oid.clone()
	}

	/// Witness digest octets, when witnessed.
	#[wasm_bindgen(getter, js_name = frameIntegrityDigest)]
	pub fn frame_integrity_digest(&self) -> Option<Vec<u8>> {
		self.summary.frame_integrity_digest.clone()
	}

	/// Body-encryption algorithm OID, when confidential.
	#[wasm_bindgen(getter, js_name = confidentialityAlgorithmOid)]
	pub fn confidentiality_algorithm_oid(&self) -> Option<String> {
		self.summary.confidentiality_algorithm_oid.clone()
	}

	/// Body-encryption algorithm parameters DER (e.g. the nonce), when
	/// confidential and present.
	#[wasm_bindgen(getter, js_name = confidentialityParametersDer)]
	pub fn confidentiality_parameters_der(&self) -> Option<Vec<u8>> {
		self.summary.confidentiality_parameters_der.clone()
	}

	/// Signature algorithm OID, when signed.
	#[wasm_bindgen(getter, js_name = signatureAlgorithmOid)]
	pub fn signature_algorithm_oid(&self) -> Option<String> {
		self.summary.signature_algorithm_oid.clone()
	}

	/// Signature digest algorithm OID, when signed.
	#[wasm_bindgen(getter, js_name = signatureDigestAlgorithmOid)]
	pub fn signature_digest_algorithm_oid(&self) -> Option<String> {
		self.summary.signature_digest_algorithm_oid.clone()
	}

	/// Raw signature octets, when signed.
	#[wasm_bindgen(getter)]
	pub fn signature(&self) -> Option<Vec<u8>> {
		self.summary.signature.clone()
	}
}

/// Decode a tightbeam frame DER into a [`FrameView`] for inspection.
#[wasm_bindgen(js_name = inspectFrame)]
pub fn inspect_frame(frame_der: Vec<u8>) -> Result<FrameView, JsError> {
	let summary = build::inspect_frame(frame_der).map_err(|error| JsError::new(&error.to_string()))?;
	Ok(FrameView { summary })
}

// ---------------------------------------------------------------------------
// Tightbeam profile primitives (SHA3-256 / secp256k1 / AES-256-GCM / ECIES).
// ---------------------------------------------------------------------------

/// SHA3-256 digest of `data` - the profile hasher.
#[wasm_bindgen(js_name = sha3_256)]
pub fn sha3_256(data: Vec<u8>) -> Vec<u8> {
	build::sha3_256_digest(data)
}

/// Derive the SEC1 compressed public key for a raw 32-byte secp256k1 signing
/// key, for verifying frames signed with that key.
#[wasm_bindgen(js_name = derivePublicKey)]
pub fn derive_public_key(key_bytes: Vec<u8>) -> Result<Vec<u8>, JsError> {
	let array: [u8; SECP256K1_KEY_LEN] = key_bytes
		.try_into()
		.map_err(|_| JsError::new("secp256k1 key must be 32 octets"))?;

	build::derive_public_key(array).map_err(|error| JsError::new(&error.to_string()))
}

/// Sign the SHA3-256 digest of `tbs` with a raw 32-byte secp256k1 signing
/// key, returning the raw 64-byte `r || s` signature accepted by
/// `attachSignature` - the profile signer.
#[wasm_bindgen(js_name = signTbs)]
pub fn sign_tbs(key_bytes: Vec<u8>, tbs: Vec<u8>) -> Result<Vec<u8>, JsError> {
	let array: [u8; SECP256K1_KEY_LEN] = key_bytes
		.try_into()
		.map_err(|_| JsError::new("secp256k1 key must be 32 octets"))?;

	build::sign_tbs(array, tbs).map_err(|error| JsError::new(&error.to_string()))
}

/// The subject-key-identifier octets naming a secp256k1 signer (for
/// `attachSignature`), derived from its SEC1-encoded public key.
#[wasm_bindgen(js_name = profileSignerId)]
pub fn profile_signer_id(public_key_sec1: Vec<u8>) -> Result<Vec<u8>, JsError> {
	build::profile_signer_id(public_key_sec1).map_err(|error| JsError::new(&error.to_string()))
}

/// Verify a frame's non-repudiation signature against a SEC1-encoded
/// secp256k1 public key (33-byte compressed or 65-byte uncompressed) under
/// the profile scheme (ECDSA over SHA3-256).
///
/// Resolves on a valid signature; a missing signature, an algorithm
/// mismatch, or a bad signature all throw. Frames signed under other schemes
/// verify caller-side from `tbsBytes` and the carried signature.
#[wasm_bindgen(js_name = verifySignature)]
pub fn verify_signature(frame_der: Vec<u8>, public_key_sec1: Vec<u8>) -> Result<(), JsError> {
	build::verify_signature(frame_der, public_key_sec1).map_err(|error| JsError::new(&error.to_string()))
}

/// A sealed body produced by a profile encryptor: the pieces
/// `setConfidentiality` installs.
#[wasm_bindgen]
pub struct SealedBody {
	inner: build::SealedBody,
}

#[wasm_bindgen]
impl SealedBody {
	/// The encryption algorithm OID (dotted form).
	#[wasm_bindgen(getter, js_name = algorithmOid)]
	pub fn algorithm_oid(&self) -> String {
		self.inner.algorithm_oid.clone()
	}

	/// The algorithm parameters DER (e.g. the nonce), when the scheme has
	/// any.
	#[wasm_bindgen(getter, js_name = parametersDer)]
	pub fn parameters_der(&self) -> Option<Vec<u8>> {
		self.inner.parameters_der.clone()
	}

	/// The ciphertext replacing the frame body.
	#[wasm_bindgen(getter)]
	pub fn ciphertext(&self) -> Vec<u8> {
		self.inner.ciphertext.clone()
	}
}

/// Seal a `bodyPreimage` under AES-256-GCM with a 32-byte key - the profile
/// symmetric encryptor.
#[wasm_bindgen(js_name = sealAes256Gcm)]
pub fn seal_aes_256_gcm(key: Vec<u8>, plaintext: Vec<u8>) -> Result<SealedBody, JsError> {
	let inner = build::seal_aes_256_gcm(key, plaintext).map_err(|error| JsError::new(&error.to_string()))?;
	Ok(SealedBody { inner })
}

/// Open an AES-256-GCM sealed body with the shared 32-byte key, returning
/// the plaintext body DER (decode it with `decodeBody`).
#[wasm_bindgen(js_name = openAes256Gcm)]
pub fn open_aes_256_gcm(
	key: Vec<u8>,
	parameters_der: Option<Vec<u8>>,
	ciphertext: Vec<u8>,
) -> Result<Vec<u8>, JsError> {
	build::open_aes_256_gcm(key, parameters_der, ciphertext).map_err(|error| JsError::new(&error.to_string()))
}

/// Seal a `bodyPreimage` to the holder of the secp256k1 key behind this SEC1
/// public key - the profile asymmetric encryptor (ECIES: secp256k1 +
/// HKDF-SHA3-256 + AES-256-GCM).
#[wasm_bindgen(js_name = sealEciesSecp256k1)]
pub fn seal_ecies_secp256k1(recipient_public_key: Vec<u8>, plaintext: Vec<u8>) -> Result<SealedBody, JsError> {
	let inner = build::seal_ecies_secp256k1(recipient_public_key, plaintext)
		.map_err(|error| JsError::new(&error.to_string()))?;
	Ok(SealedBody { inner })
}

/// Open an ECIES sealed body with the raw 32-byte recipient secret key,
/// returning the plaintext body DER (decode it with `decodeBody`).
#[wasm_bindgen(js_name = openEciesSecp256k1)]
pub fn open_ecies_secp256k1(
	secret_key: Vec<u8>,
	parameters_der: Option<Vec<u8>>,
	ciphertext: Vec<u8>,
) -> Result<Vec<u8>, JsError> {
	if secret_key.len() != SECP256K1_KEY_LEN {
		return Err(JsError::new("secp256k1 secret key must be 32 octets"));
	}

	build::open_ecies_secp256k1(secret_key, parameters_der, ciphertext)
		.map_err(|error| JsError::new(&error.to_string()))
}
