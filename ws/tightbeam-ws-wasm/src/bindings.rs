//! The `wasm-bindgen` surface for the browser and Node.

use core::str::FromStr;

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use tightbeam::asn1::ObjectIdentifier;
use tightbeam::crypto::commitment::CommitmentSalt as EngineSalt;
use tightbeam::crypto::subtle::ConstantTimeEq;
use tightbeam::matrix::MatrixDyn;
use tightbeam::oids::{
	AES_256_GCM, COMPRESSION_ZLIB, COMPRESSION_ZSTD, DATA, DHKEM_SECP256K1, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256,
};

use crate::build::{
	self, BodyDer, Compactness, CompactnessSummary, ConfidentialitySummary, DigestSummary, FrameConfig, FrameSummary,
	MatrixSummary, NamedDigest, SecurityField, SignatureSummary, SignerKeyId,
};
use crate::compress::ZstdCompression;
use crate::fault::{JsFault, RefusalCode, TransportCode};
use crate::metadata::{PriorityLabel, VersionLabel};
use crate::promise::{JsBytes, Record, WholeNumber};

/// TypeScript shapes of the frame fields the engine reads and reports.
#[wasm_bindgen(typescript_custom_section)]
const FRAME_FIELDS_TS: &'static str = r#"
/**
 * An N×N control matrix (V3+), stored row-major as exactly `n * n` octets.
 */
export interface FrameMatrix {
	/**
	 * Dimension N, in `1..=255`.
	 */
	readonly n: number;
	/**
	 * Row-major bytes of length `n * n`.
	 */
	readonly data: Uint8Array;
}

/**
 * The compactness info carried by a compressed frame: how the body was
 * compressed.
 */
export interface CompactnessInfo {
	/**
	 * The body-compression algorithm.
	 */
	readonly algorithmOid: Oid;
	/**
	 * The DER-encoded algorithm parameters, when the scheme has any.
	 */
	readonly parametersDer?: Uint8Array;
	/**
	 * The content type of the uncompressed body.
	 */
	readonly contentOid: Oid;
}

/**
 * The confidentiality info carried by an encrypted frame: the CMS envelope
 * that seals the body ciphertext.
 */
export interface ConfidentialityInfo {
	/**
	 * The content-encryption algorithm.
	 */
	readonly algorithmOid: Oid;
	/**
	 * The DER `AuthEnvelopedData`, its content detached into the frame body.
	 */
	readonly envelopeDer: Uint8Array;
}

/**
 * The non-repudiation signature carried by a signed frame.
 */
export interface SignatureInfo {
	/**
	 * The signature algorithm.
	 */
	readonly algorithmOid: Oid;
	/**
	 * The digest the signature is computed over.
	 */
	readonly digestAlgorithmOid: Oid;
	/**
	 * The DER signature octets.
	 */
	readonly signature: Uint8Array;
}

/**
 * Every field of a decoded frame. Each security field arrives whole or not
 * at all.
 */
export interface InspectedFrame {
	/**
	 * The protocol version.
	 */
	readonly version: Version;
	/**
	 * The opaque message identifier.
	 */
	readonly id: Uint8Array;
	/**
	 * The order stamp of the frame.
	 */
	readonly order: bigint;
	/**
	 * The DER of the frame body, as the frame carries it.
	 */
	readonly bodyDer: Uint8Array;
	/**
	 * The message priority.
	 */
	readonly priority?: MessagePriority;
	/**
	 * The time to live, in seconds.
	 */
	readonly lifetime?: bigint;
	/**
	 * The content digest of the parent frame.
	 */
	readonly previousFrame?: DigestInfo;
	/**
	 * The N×N control matrix (V3+).
	 */
	readonly matrix?: FrameMatrix;
	/**
	 * The message-integrity commitment over the body.
	 */
	readonly messageIntegrity?: DigestInfo;
	/**
	 * The frame-integrity witness over the metadata.
	 */
	readonly frameIntegrity?: DigestInfo;
	/**
	 * How the body compressed.
	 */
	readonly compactness?: CompactnessInfo;
	/**
	 * The envelope that seals the body.
	 */
	readonly confidentiality?: ConfidentialityInfo;
	/**
	 * The non-repudiation signature over the frame.
	 */
	readonly signature?: SignatureInfo;
}

/**
 * A compressed frame body: the pieces installed in the frame's compactness
 * info alongside the compressed bytes. The compressor names its algorithm
 * once, and the compactness info records `id-data` as the content type of
 * the uncompressed body.
 */
export interface CompressedBody {
	/**
	 * The DER-encoded algorithm parameters, when the scheme has any.
	 */
	readonly parametersDer?: Uint8Array;
	/**
	 * The compressed bytes replacing the frame body.
	 */
	readonly data: Uint8Array;
}
"#;

/// A digest a frame carries, admitted under the rule of [`NamedDigest`].
impl TryFrom<DigestSummary> for DigestInfo {
	type Error = JsFault;

	/// # Errors
	///
	/// - `EmptyDigest` -- the carried digest holds no octets.
	fn try_from(summary: DigestSummary) -> Result<Self, Self::Error> {
		let inner = NamedDigest::new(summary.algorithm_oid, summary.digest)?;
		Ok(Self { inner })
	}
}

impl From<MatrixSummary> for JsValue {
	fn from(summary: MatrixSummary) -> Self {
		let record = Record::new();
		record.set("n", f64::from(summary.n()));
		record.set_bytes("data", summary.data());
		record.into()
	}
}

impl From<CompactnessSummary> for JsValue {
	fn from(summary: CompactnessSummary) -> Self {
		let parameters = summary.parameters_der.map(|der| Uint8Array::from(der.as_slice()));

		let record = Record::new();
		record.set("algorithmOid", Oid::from(summary.algorithm_oid));
		record.set_present("parametersDer", parameters);
		record.set("contentOid", Oid::from(summary.content_oid));
		record.into()
	}
}

impl From<ConfidentialitySummary> for JsValue {
	fn from(summary: ConfidentialitySummary) -> Self {
		let record = Record::new();
		record.set("algorithmOid", Oid::from(summary.algorithm_oid));
		record.set_bytes("envelopeDer", &summary.envelope_der);
		record.into()
	}
}

impl From<SignatureSummary> for JsValue {
	fn from(summary: SignatureSummary) -> Self {
		let record = Record::new();
		record.set("algorithmOid", Oid::from(summary.algorithm_oid));
		record.set("digestAlgorithmOid", Oid::from(summary.digest_algorithm_oid));
		record.set_bytes("signature", &summary.signature);
		record.into()
	}
}

/// One plain object in the `InspectedFrame` shape: each security field whole,
/// or absent.
impl TryFrom<FrameSummary> for JsValue {
	type Error = JsFault;

	/// # Errors
	///
	/// - `EmptyDigest` -- a digest field of the frame holds no octets.
	fn try_from(summary: FrameSummary) -> Result<Self, Self::Error> {
		let previous_frame = summary.previous_frame.map(DigestInfo::try_from).transpose()?;
		let message_integrity = summary.message_integrity.map(DigestInfo::try_from).transpose()?;
		let frame_integrity = summary.frame_integrity.map(DigestInfo::try_from).transpose()?;

		let record = Record::new();
		record.set("version", VersionLabel::from(summary.version));
		record.set_bytes("id", &summary.id);
		record.set("order", summary.order);
		record.set_bytes("bodyDer", &summary.body_der);
		record.set_present("priority", summary.priority.map(PriorityLabel::from));
		record.set_present("lifetime", summary.lifetime);
		record.set_present("previousFrame", previous_frame);
		record.set_present("matrix", summary.matrix);
		record.set_present("messageIntegrity", message_integrity);
		record.set_present("frameIntegrity", frame_integrity);
		record.set_present("compactness", summary.compactness);
		record.set_present("confidentiality", summary.confidentiality);
		record.set_present("signature", summary.signature);
		Ok(record.into())
	}
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

	/// Pin the protocol version.
	///
	/// # Errors
	///
	/// - `InvalidVersion` -- `version` is no member of `Version`.
	#[wasm_bindgen(js_name = withVersion)]
	pub fn with_version(
		&mut self,
		#[wasm_bindgen(unchecked_param_type = "Version")] version: JsValue,
	) -> Result<(), JsFault> {
		let version = VersionLabel::try_from(&version)?;
		self.config.with_version(version.into());
		Ok(())
	}

	/// Set the opaque message identifier.
	#[wasm_bindgen(js_name = withId)]
	pub fn with_id(&mut self, id: JsBytes) -> Result<(), JsFault> {
		self.config.with_id(id.read()?);
		Ok(())
	}

	/// Set the frame order stamp.
	///
	/// The value is protocol-opaque. Any monotonic scheme works, such as a
	/// Unix timestamp or a dense per-channel counter. When omitted, the
	/// build defaults it to the current Unix time in seconds.
	///
	/// # Errors
	///
	/// - `InvalidOrder` -- `order` is no whole number or `bigint` that a `u64` holds.
	#[wasm_bindgen(js_name = withOrder)]
	pub fn with_order(
		&mut self,
		#[wasm_bindgen(unchecked_param_type = "bigint | number")] order: JsValue,
	) -> Result<(), JsFault> {
		let order = WholeNumber::u64_at(&order);
		let refusal = || {
			TransportCode::InvalidOrder
				.because("must be a whole number from 0 to 2^64-1")
				.at("order")
		};
		let order = order.ok_or_else(refusal)?;

		self.config.with_order(order);
		Ok(())
	}

	/// Set the frame body DER. Wrap raw payload bytes with `OpaqueCodec.encode`
	/// for the profile opaque body.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- `bodyDer` is not a `Uint8Array`.
	/// - `SerializationError` -- `bodyDer` is not one DER value.
	#[wasm_bindgen(js_name = withMessage)]
	pub fn with_message(&mut self, body_der: JsBytes) -> Result<(), JsFault> {
		let body = BodyDer::try_from(body_der.read()?)?;
		self.config.with_message(body);
		Ok(())
	}

	/// Set the message priority (V2+).
	///
	/// # Errors
	///
	/// - `InvalidPriority` -- `priority` is no member of `MessagePriority`.
	#[wasm_bindgen(js_name = withPriority)]
	pub fn with_priority(
		&mut self,
		#[wasm_bindgen(unchecked_param_type = "MessagePriority")] priority: JsValue,
	) -> Result<(), JsFault> {
		let priority = PriorityLabel::try_from(&priority)?;
		self.config.with_priority(priority.into());
		Ok(())
	}

	/// Set the time-to-live in seconds.
	///
	/// # Errors
	///
	/// - `InvalidLifetime` -- `seconds` is no whole number or `bigint` that a `u64` holds.
	#[wasm_bindgen(js_name = withLifetime)]
	pub fn with_lifetime(
		&mut self,
		#[wasm_bindgen(unchecked_param_type = "bigint | number")] seconds: JsValue,
	) -> Result<(), JsFault> {
		let seconds = WholeNumber::u64_at(&seconds);
		let refusal = || {
			RefusalCode::InvalidLifetime
				.because("must be a whole number from 0 to 2^64-1")
				.at("lifetime")
		};
		let seconds = seconds.ok_or_else(refusal)?;

		self.config.with_lifetime(seconds);
		Ok(())
	}

	/// Link this frame to a parent by the digest of its content.
	#[wasm_bindgen(js_name = withPreviousHash)]
	pub fn with_previous_hash(&mut self, parent: &DigestInfo) {
		self.config.with_previous_hash(parent.inner.clone());
	}

	/// Set an N×N control matrix from row-major bytes (`data.len() == n * n`).
	///
	/// # Errors
	///
	/// - `InvalidMatrixDimension` -- `n` is no whole number from 1 to 255, so a string or a
	///   `bool` is refused as well.
	/// - `InvalidMatrixData` -- `data` does not hold `n * n` octets.
	/// - `InvalidBytes` -- `data` is not a `Uint8Array`.
	#[wasm_bindgen(js_name = withMatrix)]
	pub fn with_matrix(
		&mut self,
		#[wasm_bindgen(unchecked_param_type = "number")] n: JsValue,
		data: JsBytes,
	) -> Result<(), JsFault> {
		let dimension = WholeNumber::read::<u8>(&n).filter(|dimension| *dimension > 0);
		let refusal = || {
			RefusalCode::InvalidMatrixDimension
				.because("must be a whole number from 1 to 255")
				.at("matrix.n")
		};
		let dimension = dimension.ok_or_else(refusal)?;

		let matrix = MatrixDyn::from_row_major(dimension, data.read()?);
		let matrix =
			matrix.ok_or_else(|| RefusalCode::InvalidMatrixData.because("must hold n*n octets").at("matrix.data"))?;

		self.config.with_matrix(matrix);
		Ok(())
	}

	/// Declare that the caller installs a message-integrity commitment after
	/// the build, so the version floor counts it.
	#[wasm_bindgen(js_name = declareMessageIntegrity)]
	pub fn declare_message_integrity(&mut self) {
		self.config.declare(SecurityField::MessageIntegrity);
	}

	/// Declare that the caller seals the body after the build, so the
	/// version floor counts the confidentiality info.
	#[wasm_bindgen(js_name = declareConfidentiality)]
	pub fn declare_confidentiality(&mut self) {
		self.config.declare(SecurityField::Confidentiality);
	}

	/// Declare that the caller installs a frame-integrity witness after the
	/// build, so the version floor counts it.
	#[wasm_bindgen(js_name = declareFrameIntegrity)]
	pub fn declare_frame_integrity(&mut self) {
		self.config.declare(SecurityField::FrameIntegrity);
	}

	/// Declare that the caller signs the frame after the build, so the
	/// version floor counts the signature.
	#[wasm_bindgen(js_name = declareNonrepudiation)]
	pub fn declare_nonrepudiation(&mut self) {
		self.config.declare(SecurityField::Nonrepudiation);
	}

	/// Assemble the structural frame, ready for its security steps. Consumes
	/// the composer.
	///
	/// The frame carries the pinned version, or the floor of its structural
	/// and declared fields. A pin below that floor throws an error whose
	/// `code` is `UnsupportedField`.
	#[wasm_bindgen(js_name = build)]
	pub fn build(self) -> Result<FrameAssembly, JsFault> {
		let assembly = self.config.assemble()?;
		Ok(FrameAssembly { inner: assembly })
	}
}

/// One frame, decoded once and held between its assembly steps.
///
/// Each step that installs a field consumes this object and returns the next
/// one. The engine refuses a step behind a later one the frame holds, with
/// the code `InstallOutOfOrder`, and a field the frame's version forbids,
/// with the code `UnsupportedField`.
#[wasm_bindgen]
pub struct FrameAssembly {
	inner: build::FrameAssembly,
}

#[wasm_bindgen]
impl FrameAssembly {
	/// Decode the frame that `frameDer` encodes.
	#[wasm_bindgen(js_name = decode)]
	pub fn decode(frame_der: JsBytes) -> Result<FrameAssembly, JsFault> {
		let inner = build::FrameAssembly::decode(frame_der.read()?)?;
		Ok(FrameAssembly { inner })
	}

	/// The DER of the frame.
	#[wasm_bindgen(js_name = encode)]
	pub fn encode(&self) -> Result<Vec<u8>, JsFault> {
		Ok(self.inner.encode()?)
	}

	/// Every field of the frame in one plain object.
	///
	/// # Errors
	///
	/// - `EmptyDigest` -- a digest field of the frame holds no octets.
	#[wasm_bindgen(js_name = summary, unchecked_return_type = "InspectedFrame")]
	pub fn summary(&self) -> Result<JsValue, JsFault> {
		let summary = self.inner.summary()?;
		JsValue::try_from(summary)
	}

	/// The message-commitment preimage over the body this frame holds, under
	/// `salt`. Hash it with any digest and install the result with
	/// `withMessageIntegrity`.
	///
	/// # Errors
	///
	/// - `CommitmentSpent` -- the salt moved out of `salt`.
	/// - `OpaqueBody` -- the frame is sealed or compressed, so its body still needs a decrypt
	///   or an inflate.
	/// - `SerializationError` -- the plaintext body is not one DER value.
	#[wasm_bindgen(js_name = commitmentPreimage)]
	pub fn commitment_preimage(&self, salt: &CommitmentSalt) -> Result<Vec<u8>, JsFault> {
		let salt = salt.salt()?;
		Ok(self.inner.commitment_preimage(salt)?)
	}

	/// Install a message-integrity commitment: `digest`, the digest of
	/// `commitmentPreimage` that `algorithmOid` produced (V1+ frames). The
	/// step builds the digest itself, so no digest handle outlives it.
	///
	/// # Errors
	///
	/// - `EmptyDigest` -- `digest` holds no octets.
	/// - `InvalidBytes` -- `digest` is not a `Uint8Array`.
	#[wasm_bindgen(js_name = withMessageIntegrity)]
	pub fn with_message_integrity(self, algorithm_oid: &Oid, digest: JsBytes) -> Result<FrameAssembly, JsFault> {
		let commitment = NamedDigest::new(algorithm_oid.value(), digest.read()?)?;
		let inner = self.inner.with_message_integrity(commitment)?;
		Ok(FrameAssembly { inner })
	}

	/// Replace the frame body with `data`, which `algorithmOid` compressed,
	/// and record how it compressed (any version). The content type of the
	/// uncompressed body is `id-data`.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- `data`, or a present `parametersDer`, is not a `Uint8Array`.
	#[wasm_bindgen(js_name = withCompactness)]
	pub fn with_compactness(
		self,
		algorithm_oid: &Oid,
		data: JsBytes,
		#[wasm_bindgen(unchecked_param_type = "Uint8Array | undefined")] parameters_der: JsValue,
	) -> Result<FrameAssembly, JsFault> {
		let parameters = Record::present(parameters_der);
		let parameters_der = parameters.map(|der| JsBytes::read_value(&der, "parametersDer")).transpose()?;
		let compactness = Compactness {
			algorithm_oid: algorithm_oid.inner,
			parameters_der,
			content_oid: None,
			compressed: data.read()?,
		};

		let inner = self.inner.with_compactness(compactness)?;
		Ok(FrameAssembly { inner })
	}

	/// The body DER of this frame, inflated by the engine zstd within
	/// `maxOutput`, the ceiling that `ZstdCompression.ceiling` answered: the
	/// step a cleartext compressed frame takes before its body decodes. A frame
	/// that carries no compactness answers its body.
	///
	/// # Errors
	///
	/// - `InvalidMaxOutput` -- `maxOutput` is no whole, non-negative number that the target
	///   holds.
	/// - `CompressionError` -- the engine zstd refuses the body. The refusal travels inside the
	///   error of the inflate path, which the engine does not take apart.
	/// - `InvalidMetadata`, `UnexpectedAlgorithm` -- the compactness info names another
	///   algorithm, or parameters that the engine zstd refuses.
	/// - `Router` -- the frame is sealed, so its body opens through a decrypt.
	#[wasm_bindgen(js_name = inflate)]
	pub fn inflate(
		&self,
		#[wasm_bindgen(unchecked_param_type = "number")] max_output: JsValue,
	) -> Result<Vec<u8>, JsFault> {
		let zstd = ZstdCompression::within(&max_output)?;
		Ok(self.inner.inflate(&zstd)?)
	}

	/// Replace the frame body with the `ciphertext` of `sealed` and install
	/// its `envelopeDer`, the DER `AuthEnvelopedData` that seals it, its
	/// content detached (V1+ frames).
	#[wasm_bindgen(js_name = withConfidentiality)]
	pub fn with_confidentiality(
		self,
		#[wasm_bindgen(unchecked_param_type = "EncryptedBody")] sealed: JsValue,
	) -> Result<FrameAssembly, JsFault> {
		let sealed = build::SealedBody::try_from(&sealed)?;
		let inner = self.inner.with_confidentiality(sealed)?;
		Ok(FrameAssembly { inner })
	}

	/// The frame-integrity (witness) preimage: hash it with any digest and
	/// install the result with `withWitness`.
	#[wasm_bindgen(js_name = witnessPreimage)]
	pub fn witness_preimage(&self) -> Result<Vec<u8>, JsFault> {
		Ok(self.inner.witness_preimage()?)
	}

	/// Install a frame-integrity witness: `digest`, the digest of
	/// `witnessPreimage` that `algorithmOid` produced (V1+ frames). The step
	/// builds the digest itself, so no digest handle outlives it.
	///
	/// # Errors
	///
	/// - `EmptyDigest` -- `digest` holds no octets.
	/// - `InvalidBytes` -- `digest` is not a `Uint8Array`.
	#[wasm_bindgen(js_name = withWitness)]
	pub fn with_witness(self, algorithm_oid: &Oid, digest: JsBytes) -> Result<FrameAssembly, JsFault> {
		let witness = NamedDigest::new(algorithm_oid.value(), digest.read()?)?;
		let inner = self.inner.with_witness(witness)?;
		Ok(FrameAssembly { inner })
	}

	/// The to-be-signed bytes of the frame (everything but the signature).
	#[wasm_bindgen(js_name = tbs)]
	pub fn tbs(&self) -> Result<Vec<u8>, JsFault> {
		Ok(self.inner.tbs()?)
	}

	/// Draft the signature that the key named by `signerId` owes this frame.
	/// Consumes this frame, which the draft holds until `Signing.complete`
	/// returns it signed. Sign the `prehash` of the draft.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- `signerId` is not a `Uint8Array`.
	/// - `EmptySignerId` -- `signerId` holds no octets.
	#[wasm_bindgen(js_name = signing)]
	pub fn signing(self, signer_id: JsBytes) -> Result<Signing, JsFault> {
		let signer_id = signer_id.read()?;
		let signer = SignerKeyId::try_from(signer_id)?;

		let inner = self.inner.signing(&signer)?;
		Ok(Signing { inner })
	}

	/// The digest a verifier checks the frame's signature against.
	#[wasm_bindgen(js_name = signaturePrehash)]
	pub fn signature_prehash(&self) -> Result<Vec<u8>, JsFault> {
		Ok(self.inner.signature_prehash()?)
	}
}

/// A frame that awaits the signature of one key, drafted by
/// `FrameAssembly.signing`, which names the key once.
#[wasm_bindgen]
pub struct Signing {
	inner: build::Signing,
}

#[wasm_bindgen]
impl Signing {
	/// The digest the key signs directly, with no rehash: the digest of the
	/// CMS signed attributes, which bind the frame's `tbs`.
	#[wasm_bindgen(getter, js_name = prehash)]
	pub fn prehash(&self) -> Vec<u8> {
		self.inner.prehash().to_vec()
	}

	/// Attach `signature`, a DER `ECDSA-Sig-Value` over `prehash`, and
	/// return the signed frame (V1+ frames). Consumes this draft.
	#[wasm_bindgen(js_name = complete)]
	pub fn complete(self, signature: JsBytes) -> Result<FrameAssembly, JsFault> {
		let signature = signature.read()?;

		let inner = self.inner.complete(signature)?;
		Ok(FrameAssembly { inner })
	}
}

/// A commitment salt, parsed once: empty for a plain digest, or at least 16
/// octets that hide the body.
///
/// A salt commits one frame. [`take`](Self::take) moves the salt into a new
/// handle and leaves this one an empty shell, which frees as any handle does.
/// A holder that disposes its own handle therefore never reaches the salt it
/// gave away, and an empty shell refuses every read with `CommitmentSpent`.
#[wasm_bindgen]
pub struct CommitmentSalt {
	inner: Option<EngineSalt>,
}

impl CommitmentSalt {
	/// The salt this handle holds.
	///
	/// # Errors
	///
	/// - `CommitmentSpent` -- the salt moved out of this handle.
	pub(crate) fn salt(&self) -> Result<&EngineSalt, JsFault> {
		let held = self.inner.as_ref();
		held.ok_or_else(|| RefusalCode::CommitmentSpent.because("the salt moved out of this handle"))
	}
}

#[wasm_bindgen]
impl CommitmentSalt {
	/// Parse `salt`.
	///
	/// # Errors
	///
	/// - `InvalidSaltLength` -- a non-empty `salt` is too short to hide the body.
	/// - `InvalidBytes` -- `salt` is not a `Uint8Array`.
	#[wasm_bindgen(js_name = parse)]
	pub fn parse(salt: JsBytes) -> Result<CommitmentSalt, JsFault> {
		let inner = EngineSalt::parse(salt.read()?)?;
		Ok(CommitmentSalt { inner: Some(inner) })
	}

	/// Move the salt into a new handle, and leave this handle an empty shell.
	///
	/// # Errors
	///
	/// - `CommitmentSpent` -- the salt moved out of this handle already.
	#[wasm_bindgen(js_name = take)]
	pub fn take(&mut self) -> Result<CommitmentSalt, JsFault> {
		let inner = self.inner.take();
		let refusal = || RefusalCode::CommitmentSpent.because("the salt moved out of this handle already");
		let inner = inner.ok_or_else(refusal)?;
		Ok(CommitmentSalt { inner: Some(inner) })
	}

	/// The message-commitment preimage over the detached `bodyDer` under this
	/// salt (tightbeam's commitment framing), for an opening. Hash it with any
	/// digest. `FrameAssembly.commitmentPreimage` reads the body a frame holds.
	///
	/// # Errors
	///
	/// - `CommitmentSpent` -- the salt moved out of this handle.
	/// - `InvalidBytes` -- `bodyDer` is not a `Uint8Array`.
	/// - `SerializationError` -- `bodyDer` is not one DER value.
	#[wasm_bindgen(js_name = preimage)]
	pub fn preimage(&self, body_der: JsBytes) -> Result<Vec<u8>, JsFault> {
		let salt = self.salt()?;
		let body = BodyDer::try_from(body_der.read()?)?;
		Ok(body.commitment_preimage(salt))
	}
}

/// The codec of the profile opaque body: raw message octets wrapped as a
/// frame body DER.
#[wasm_bindgen]
pub struct OpaqueCodec;

#[wasm_bindgen]
impl OpaqueCodec {
	/// The frame body DER that wraps `message`: the preimage a caller hashes
	/// (message integrity) or encrypts (confidentiality).
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- `message` is not a `Uint8Array`.
	/// - `SerializationError` -- `message` exceeds the DER length limit.
	#[wasm_bindgen(js_name = encode)]
	pub fn encode(message: JsBytes) -> Result<Vec<u8>, JsFault> {
		let body = BodyDer::opaque(message.read()?)?;
		Ok(body.into_bytes())
	}

	/// The message octets of a frame body DER: a cleartext body, or the
	/// plaintext recovered from a confidential one.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- `bodyDer` is not a `Uint8Array`.
	/// - `SerializationError` -- the octets are no opaque body.
	#[wasm_bindgen(js_name = decode)]
	pub fn decode(body_der: JsBytes) -> Result<Vec<u8>, JsFault> {
		let body_der = body_der.read()?;
		let body = BodyDer::try_from(body_der)?;
		Ok(body.opaque_message()?)
	}
}

/// An object identifier, parsed once from its dotted form.
///
/// [`parse`](Self::parse) is the one way JavaScript makes one, and every
/// engine method that names an algorithm takes one by reference, so a
/// dotted string reaches the engine once.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Oid {
	inner: ObjectIdentifier,
}

impl From<ObjectIdentifier> for Oid {
	fn from(inner: ObjectIdentifier) -> Self {
		Self { inner }
	}
}

impl Oid {
	/// Read the dotted object identifier that `value` holds, which `field`
	/// names in a refusal. The one parse of a dotted OID in the engine.
	///
	/// # Errors
	///
	/// - `InvalidOid` -- `value` is no string, or no dotted object identifier the engine encodes.
	pub(crate) fn read(value: &JsValue, field: &str) -> Result<ObjectIdentifier, JsFault> {
		let dotted = value.as_string();
		let parsed = dotted.as_deref().map(ObjectIdentifier::from_str);

		let refusal = || RefusalCode::InvalidOid.because("is not a dotted object identifier").at(field);
		parsed.and_then(Result::ok).ok_or_else(refusal)
	}

	/// The object identifier this handle holds.
	pub(crate) fn value(&self) -> ObjectIdentifier {
		self.inner
	}
}

#[wasm_bindgen]
impl Oid {
	/// Parse `dotted`, such as `1.2.840.113549.1.7.1`.
	///
	/// # Errors
	///
	/// - `InvalidOid` -- `dotted` is no string, or no dotted object identifier the engine encodes.
	#[wasm_bindgen(js_name = parse)]
	pub fn parse(#[wasm_bindgen(unchecked_param_type = "string")] dotted: JsValue) -> Result<Oid, JsFault> {
		let inner = Self::read(&dotted, "oid")?;
		Ok(Self { inner })
	}

	/// The dotted form.
	#[wasm_bindgen(js_name = toString)]
	pub fn dotted(&self) -> String {
		self.inner.to_string()
	}

	/// Whether `other` names the same object identifier.
	#[wasm_bindgen(js_name = equals)]
	pub fn equals(&self, other: &Oid) -> bool {
		self.inner == other.inner
	}

	/// A handle of its own that names the same object identifier, for a
	/// holder that keeps it past the hold of the caller.
	#[wasm_bindgen(js_name = clone)]
	pub fn copy(&self) -> Oid {
		*self
	}
}

/// The outcome of judging a recomputed digest against a carried one.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestVerdict {
	/// The recomputed digest equals the carried one.
	Verified = "verified",
	/// The hasher implements another algorithm than the digest names.
	AlgorithmMismatch = "algorithm-mismatch",
	/// The recomputed digest differs from the carried one.
	Mismatch = "mismatch",
}

/// A digest and the algorithm that produced it: a digest field of a frame,
/// or a detached commitment. It holds at least one octet.
///
/// It is the one place that judges a recomputed digest against a carried
/// one.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DigestInfo {
	inner: NamedDigest,
}

#[wasm_bindgen]
impl DigestInfo {
	/// The digest `digest` that the algorithm `algorithmOid` produced, such as
	/// a received commitment. The engine keeps its own copy of the octets.
	///
	/// # Errors
	///
	/// - `EmptyDigest` -- `digest` holds no octets.
	/// - `InvalidBytes` -- `digest` is not a `Uint8Array`.
	#[wasm_bindgen(js_name = of)]
	pub fn of(algorithm_oid: &Oid, digest: JsBytes) -> Result<DigestInfo, JsFault> {
		let inner = NamedDigest::new(algorithm_oid.value(), digest.read()?)?;
		Ok(Self { inner })
	}

	/// The algorithm that produced the digest.
	#[wasm_bindgen(getter, js_name = algorithmOid)]
	pub fn algorithm_oid(&self) -> Oid {
		Oid::from(self.inner.algorithm_oid())
	}

	/// A copy of the digest octets.
	#[wasm_bindgen(getter, js_name = digest)]
	pub fn digest(&self) -> Vec<u8> {
		self.inner.digest().to_vec()
	}

	/// A handle of its own that holds the same digest, for a holder that
	/// keeps it past the hold of the caller.
	#[wasm_bindgen(js_name = clone)]
	pub fn copy(&self) -> DigestInfo {
		self.clone()
	}

	/// Judge this digest against `recomputed`, the digest that the algorithm
	/// `algorithmOid` produced over the preimage.
	///
	/// The verdict is `algorithm-mismatch` when `algorithmOid` names another
	/// algorithm than this digest. Otherwise the octets compare in constant
	/// time, so the time taken does not reveal where they first differ.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- `recomputed` is not a `Uint8Array`.
	#[wasm_bindgen(js_name = verdict)]
	pub fn verdict(&self, algorithm_oid: &Oid, recomputed: JsBytes) -> Result<DigestVerdict, JsFault> {
		if algorithm_oid.value() != self.inner.algorithm_oid() {
			return Ok(DigestVerdict::AlgorithmMismatch);
		}

		let recomputed = recomputed.read()?;
		let equal: bool = self.inner.digest().ct_eq(&recomputed).into();
		if equal {
			return Ok(DigestVerdict::Verified);
		}

		Ok(DigestVerdict::Mismatch)
	}
}

// ---------------------------------------------------------------------------
// Tightbeam profile primitives (SHA3-256 / secp256k1 / AES-256-GCM / HPKE).
// ---------------------------------------------------------------------------

/// The object identifiers of the tightbeam profile, read from the `tightbeam`
/// crate's constants, so no copy of the table is restated by hand.
///
/// # Sources
///
/// - RFC 8878, Zstandard compression:
///   <https://datatracker.ietf.org/doc/html/rfc8878>
/// - RFC 3274, Compressed Data Content Type:
///   <https://datatracker.ietf.org/doc/html/rfc3274>
/// - RFC 9629, Using Key Encapsulation Mechanism (KEM) Algorithms in CMS:
///   <https://datatracker.ietf.org/doc/html/rfc9629>
#[wasm_bindgen]
pub struct ProfileOids;

#[wasm_bindgen]
impl ProfileOids {
	/// The profile table.
	#[wasm_bindgen(js_name = read)]
	pub fn read() -> ProfileOids {
		ProfileOids
	}

	/// SHA3-256, the profile digest.
	#[wasm_bindgen(getter, js_name = sha3_256)]
	pub fn sha3_256(&self) -> Oid {
		Oid::from(HASH_SHA3_256)
	}

	/// secp256k1 ECDSA over SHA3-256, the profile signature.
	#[wasm_bindgen(getter, js_name = ecdsaWithSha3_256)]
	pub fn ecdsa_with_sha3_256(&self) -> Oid {
		Oid::from(SIGNER_ECDSA_WITH_SHA3_256)
	}

	/// AES-256-GCM, the profile symmetric cipher.
	#[wasm_bindgen(getter, js_name = aes256Gcm)]
	pub fn aes256_gcm(&self) -> Oid {
		Oid::from(AES_256_GCM)
	}

	/// DHKEM over secp256k1, the profile recipient KEM.
	#[wasm_bindgen(getter, js_name = dhkemSecp256k1)]
	pub fn dhkem_secp256k1(&self) -> Oid {
		Oid::from(DHKEM_SECP256K1)
	}

	/// Zstandard, the profile compression.
	#[wasm_bindgen(getter, js_name = zstd)]
	pub fn zstd(&self) -> Oid {
		Oid::from(COMPRESSION_ZSTD)
	}

	/// zlib, interoperable with `CompressionStream("deflate")`.
	#[wasm_bindgen(getter, js_name = zlib)]
	pub fn zlib(&self) -> Oid {
		Oid::from(COMPRESSION_ZLIB)
	}

	/// id-data: the content type recorded in the compactness info, and in an
	/// envelope when the caller names none.
	#[wasm_bindgen(getter, js_name = data)]
	pub fn data(&self) -> Oid {
		Oid::from(DATA)
	}
}

#[cfg(test)]
mod tests {
	use js_sys::{BigInt, Uint8Array};
	use wasm_bindgen::{JsCast, JsValue};
	use wasm_bindgen_test::wasm_bindgen_test;

	use super::{CommitmentSalt, DigestInfo, FrameAssembly, FrameComposer, Oid, OpaqueCodec};
	use crate::fault::Refused;
	use crate::promise::JsBytes;

	/// The dotted form of SHA3-256, the profile digest.
	const SHA3_256: &str = "2.16.840.1.101.3.4.2.8";

	/// A salt long enough to hide the body.
	const HIDING_SALT: [u8; 16] = [0x5A; 16];

	/// `octets` as a JavaScript byte parameter.
	fn bytes(octets: &[u8]) -> JsBytes {
		Uint8Array::from(octets).unchecked_into()
	}

	/// SHA3-256, the profile digest, parsed once.
	fn sha3_256() -> Oid {
		let parsed = Oid::parse(JsValue::from_str(SHA3_256));
		parsed.expect("the profile digest OID should parse")
	}

	/// The profile opaque body of one octet.
	fn body_der() -> Vec<u8> {
		let body = OpaqueCodec::encode(bytes(&[7]));
		body.expect("one octet should wrap")
	}

	/// A V2 frame between its assembly steps, which takes every digest field.
	fn assembly() -> FrameAssembly {
		let mut composer = FrameComposer::new();
		let pinned = composer.with_version(JsValue::from_f64(2.0));
		pinned.expect("V2 is a version");

		let built = composer.build();
		built.expect("a V2 composer should build")
	}

	/// 2 to the power 64 as a JavaScript `bigint`, one past the `u64` range.
	fn past_u64() -> JsValue {
		let bound = BigInt::from(u64::MAX) + BigInt::from(1u8);
		bound.into()
	}

	#[wasm_bindgen_test]
	fn an_oid_parses_once_and_crosses_as_a_handle() {
		let oid = sha3_256();
		let first = DigestInfo::of(&oid, bytes(&[1])).map(|digest| digest.algorithm_oid());
		let second = DigestInfo::of(&oid, bytes(&[2])).map(|digest| digest.algorithm_oid());
		assert_eq!(first.ok(), Some(oid));
		assert_eq!(second.ok(), Some(oid));
	}

	#[wasm_bindgen_test]
	fn a_value_that_is_no_dotted_string_is_no_oid() {
		let number = Oid::parse(JsValue::from_f64(1.0)).code();
		let word = Oid::parse(JsValue::from_str("sha3")).code();

		let codes = [number.as_deref(), word.as_deref()];
		assert_eq!(codes, [Some("InvalidOid"); 2]);
	}

	#[wasm_bindgen_test]
	fn an_empty_digest_is_refused_for_each_digest_field() {
		let previous_hash = DigestInfo::of(&sha3_256(), bytes(&[])).code();
		let message_integrity = assembly().with_message_integrity(&sha3_256(), bytes(&[])).code();
		let frame_integrity = assembly().with_witness(&sha3_256(), bytes(&[])).code();

		let codes = [
			previous_hash.as_deref(),
			message_integrity.as_deref(),
			frame_integrity.as_deref(),
		];
		assert_eq!(codes, [Some("EmptyDigest"); 3]);
	}

	#[wasm_bindgen_test]
	fn an_order_or_lifetime_past_u64_is_refused() {
		let mut composer = FrameComposer::new();
		let order_bigint = composer.with_order(past_u64()).code();
		let order_number = composer.with_order(JsValue::from_f64(18_446_744_073_709_551_616.0)).code();
		let lifetime_bigint = composer.with_lifetime(past_u64()).code();
		let lifetime_number = composer.with_lifetime(JsValue::from_f64(-1.0)).code();

		let codes = [
			order_bigint.as_deref(),
			order_number.as_deref(),
			lifetime_bigint.as_deref(),
			lifetime_number.as_deref(),
		];
		let expected = [
			Some("InvalidOrder"),
			Some("InvalidOrder"),
			Some("InvalidLifetime"),
			Some("InvalidLifetime"),
		];
		assert_eq!(codes, expected);
	}

	#[wasm_bindgen_test]
	fn an_order_or_lifetime_inside_u64_is_admitted() {
		let mut composer = FrameComposer::new();
		let order = composer.with_order(BigInt::from(u64::MAX).into());
		let lifetime = composer.with_lifetime(JsValue::from_f64(60.0));

		assert!(order.is_ok());
		assert!(lifetime.is_ok());
	}

	#[wasm_bindgen_test]
	fn an_out_of_range_version_or_priority_is_refused_with_a_code() {
		let mut composer = FrameComposer::new();
		let version = composer.with_version(JsValue::from_f64(4.0)).code();
		let version_fraction = composer.with_version(JsValue::from_f64(1.5)).code();
		let priority = composer.with_priority(JsValue::from_f64(6.0)).code();
		let priority_word = composer.with_priority(JsValue::from_str("Standard")).code();

		let codes = [
			version.as_deref(),
			version_fraction.as_deref(),
			priority.as_deref(),
			priority_word.as_deref(),
		];
		let expected = [
			Some("InvalidVersion"),
			Some("InvalidVersion"),
			Some("InvalidPriority"),
			Some("InvalidPriority"),
		];
		assert_eq!(codes, expected);
	}

	#[wasm_bindgen_test]
	fn a_matrix_dimension_that_is_no_number_is_refused() {
		let mut composer = FrameComposer::new();
		let string = composer.with_matrix(JsValue::from_str("1"), bytes(&[1])).code();
		let boolean = composer.with_matrix(JsValue::TRUE, bytes(&[1])).code();

		let codes = [string.as_deref(), boolean.as_deref()];
		assert_eq!(codes, [Some("InvalidMatrixDimension"); 2]);
	}

	#[wasm_bindgen_test]
	fn the_builder_reads_the_salt_it_was_given() {
		let mut given = CommitmentSalt::parse(bytes(&HIDING_SALT)).expect("a hiding salt should parse");
		let taken = given.take().expect("a parsed salt should move once");
		let reference = CommitmentSalt::parse(bytes(&HIDING_SALT)).expect("a hiding salt should parse");

		let through_taken = taken.preimage(bytes(&body_der()));
		let through_reference = reference.preimage(bytes(&body_der()));
		assert_eq!(through_taken.ok(), through_reference.ok());
	}

	#[wasm_bindgen_test]
	fn a_taken_salt_leaves_an_empty_shell() {
		let mut given = CommitmentSalt::parse(bytes(&HIDING_SALT)).expect("a hiding salt should parse");
		let _taken = given.take();

		let second = given.take().code();
		let preimage = given.preimage(bytes(&body_der())).code();

		let codes = [second.as_deref(), preimage.as_deref()];
		assert_eq!(codes, [Some("CommitmentSpent"); 2]);
	}
}
