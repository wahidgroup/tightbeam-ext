//! Frame assembly and structural security operations over opaque message bytes.

use std::sync::Arc;

use tightbeam::asn1::{AuthEnvelopedData, ObjectIdentifier, WireDer};
use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::cms::compressed_data::CompressedData;
use tightbeam::cms::content_info::CmsVersion;
use tightbeam::cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
use tightbeam::crypto::aead::{Aes256GcmOid, DecryptContent, Encryptor};
use tightbeam::crypto::cms::{BareKemKey, KemRecipient};
use tightbeam::crypto::commitment::CommitmentSalt;
use tightbeam::crypto::hash::{Digest as _, Sha3_256};
use tightbeam::crypto::hpke::{HpkeDecryptor, HpkeEncryptor};
use tightbeam::crypto::k256::{PublicKey, Secp256k1};
use tightbeam::crypto::key::{Aes256GcmKeyProvider, DiffieHellman, Secp256k1KeyProvider};
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey};
use tightbeam::crypto::sign::{CmsSigner, PrehashSigner, SignedContent, SignerInfoDraft};
use tightbeam::crypto::x509::utils::Skid;
use tightbeam::der::asn1::OctetString;
use tightbeam::der::{
	Any, Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag, TagNumber, Tagged,
	Writer,
};
use tightbeam::matrix::{MatrixDyn, MatrixLike};
use tightbeam::oids::DATA;
use tightbeam::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned};
use tightbeam::{Beamable, DigestInfo, Frame, MessagePriority, TightBeamError, Version};

/// Opaque payload wrapper carried as the frame body.
#[derive(Beamable, Clone, Debug, PartialEq, Eq, Sequence)]
#[beam(min_version = "V0")]
struct OpaqueBody {
	body: OctetString,
}

/// Structural frame specification: metadata only, no cryptography. Security
/// artifacts are installed afterwards with the `set_*` / `attach_*`
/// operations.
#[derive(Default)]
pub struct FrameConfig {
	/// Protocol version. When `None`, uses the floor for the structural
	/// fields. Callers configuring security afterwards MUST pin the version
	/// themselves, since this config never sees those fields.
	pub version: Option<Version>,
	/// Opaque message identifier.
	pub id: Vec<u8>,
	/// Frame order stamp.
	///
	/// The value is protocol-opaque. Any monotonic scheme works, such as a
	/// Unix timestamp or a dense per-channel counter. When omitted, the
	/// build defaults it to the current Unix time in seconds.
	pub order: u64,
	/// The frame body as DER: any `Message` encoding the peer expects.
	/// Callers without an ASN.1 schema wrap raw payload bytes with
	/// [`body_preimage`] (the opaque profile body).
	pub message: Vec<u8>,
	/// Message priority (V2+).
	pub priority: Option<MessagePriority>,
	/// Time-to-live in seconds (V2+).
	pub lifetime: Option<u64>,
	/// Parent-frame link by content digest (V2+).
	pub previous_hash: Option<DigestInfo>,
	/// N×N control matrix (V3+).
	pub matrix: Option<MatrixDyn>,
}

impl FrameConfig {
	/// Lowest frame version that admits the configured structural fields.
	///
	/// The matrix requires V3. Priority, lifetime, and previous-hash require
	/// V2. A bare payload stays at V0.
	fn effective_version(&self) -> Version {
		if let Some(version) = self.version {
			return version;
		}

		if self.matrix.is_some() {
			return Version::V3;
		}

		if self.priority.is_some() || self.lifetime.is_some() || self.previous_hash.is_some() {
			return Version::V2;
		}

		Version::V0
	}

	/// Assemble the structural frame and return its DER.
	///
	/// `message` is installed as the frame body. The builder never
	/// re-encodes it, so any `Message` schema round-trips bit-exactly.
	pub fn build(self) -> Result<Vec<u8>, TightBeamError> {
		// The upstream builder requires a typed message. Build with an
		// empty placeholder body, then install the caller's body DER.
		let placeholder = OpaqueBody { body: OctetString::new([])? };

		let mut builder = FrameBuilder::<OpaqueBody>::from(self.effective_version())
			.with_id(self.id)
			.with_order(self.order)
			.with_message(placeholder);

		if let Some(priority) = self.priority {
			builder = builder.with_priority(priority);
		}
		if let Some(lifetime) = self.lifetime {
			builder = builder.with_lifetime(lifetime);
		}
		if let Some(previous_hash) = self.previous_hash {
			builder = builder.with_previous_hash(previous_hash);
		}
		if let Some(matrix) = self.matrix {
			builder = builder.with_matrix_dyn(matrix);
		}

		let frame = builder.build()?;
		let mut wire = WireFrame::parse(frame.to_der()?)?;
		wire.set_message(self.message)?;
		wire.finish()
	}
}

/// The DER encoding of the frame body wrapping `message` - the preimage a
/// caller hashes (message integrity) or encrypts (confidentiality).
pub fn body_preimage(message: impl AsRef<[u8]>) -> Result<Vec<u8>, TightBeamError> {
	let body = OpaqueBody { body: OctetString::new(message.as_ref())? };
	Ok(body.to_der()?)
}

/// Decode a frame-body DER (a cleartext body, or the plaintext recovered
/// from a confidential one) back into the opaque message bytes.
pub fn decode_body(body_der: impl AsRef<[u8]>) -> Result<Vec<u8>, TightBeamError> {
	Ok(OpaqueBody::from_der(body_der.as_ref())?.body.into_bytes())
}

/// Preimage prefix of a commitment that only binds its body.
const PLAIN_COMMITMENT: u8 = 0x00;
/// Preimage prefix of a commitment that hides its body behind a salt.
const HIDING_COMMITMENT: u8 = 0x01;

/// The message-commitment preimage over `body_der` under `salt`:
/// `0x00 || body DER` for an empty salt, or
/// `0x01 || len(salt) as u64 BE || salt || body DER` otherwise.
///
/// The mode byte keeps a hiding commitment and a plain digest of one body
/// apart, and the length frame keeps distinct `(salt, body)` pairs from
/// colliding. Hash this with any digest and install the result via
/// [`set_message_integrity`].
///
/// # Errors
///
/// - [`TightBeamError::InvalidSaltLength`] -- a non-empty `salt` is too short
///   to hide the body.
pub fn commitment_preimage(salt: impl AsRef<[u8]>, body_der: impl AsRef<[u8]>) -> Result<Vec<u8>, TightBeamError> {
	let salt = salt.as_ref();
	let body = body_der.as_ref();
	let parsed = CommitmentSalt::parse(salt)?;

	let mut buffer = Vec::with_capacity(9 + salt.len() + body.len());
	match parsed {
		CommitmentSalt::Plain => buffer.push(PLAIN_COMMITMENT),
		CommitmentSalt::Hiding(_) => {
			buffer.push(HIDING_COMMITMENT);
			buffer.extend_from_slice(&(salt.len() as u64).to_be_bytes());
			buffer.extend_from_slice(salt);
		}
	}

	buffer.extend_from_slice(body);
	Ok(buffer)
}

/// A SEQUENCE held as its raw components.
///
/// A [`Frame`] keeps its fields private, so a caller-side digest, envelope,
/// or body reaches a frame through its encoding. Each component stays the TLV
/// it arrived as, so a splice leaves every other field byte-identical.
struct RawSequence(Vec<Any>);

impl FixedTag for RawSequence {
	const TAG: Tag = Tag::Sequence;
}

impl<'a> DecodeValue<'a> for RawSequence {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
		reader.read_nested(header.length, |reader| {
			let mut components = Vec::new();
			while !reader.is_finished() {
				components.push(Any::decode(reader)?);
			}

			Ok(Self(components))
		})
	}
}

impl EncodeValue for RawSequence {
	fn value_len(&self) -> der::Result<Length> {
		self.0
			.iter()
			.try_fold(Length::ZERO, |total, component| total + component.encoded_len()?)
	}

	fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
		self.0.iter().try_for_each(|component| component.encode(writer))
	}
}

impl RawSequence {
	/// Place the EXPLICIT `[number]` field around `value`, in tag order among
	/// the context fields that close a tightbeam SEQUENCE, in place of the
	/// field that holds the number.
	fn set_tagged(&mut self, number: TagNumber, value: &impl Encode) -> Result<(), TightBeamError> {
		let tag = Tag::ContextSpecific { constructed: true, number };
		let field = Any::new(tag, value.to_der()?)?;

		let at_or_past =
			|component: &Any| matches!(component.tag(), Tag::ContextSpecific { number: held, .. } if held >= number);
		let position = self.0.iter().position(at_or_past).unwrap_or(self.0.len());

		match self.0.get_mut(position) {
			Some(held) if held.tag() == tag => *held = field,
			_ => self.0.insert(position, field),
		}

		Ok(())
	}
}

/// Position of the body in a `Frame` SEQUENCE: `version`, `metadata`, `message`.
const FRAME_MESSAGE: usize = 2;
/// Position of the metadata in a `Frame` SEQUENCE.
const FRAME_METADATA: usize = 1;
/// Position of the optional compactness in a `Metadata` SEQUENCE: `id`, `order`, `compactness`.
const METADATA_COMPACTNESS: usize = 2;

/// The context tag of `integrity` in `Frame`, and of the commitment in `Metadata`.
const INTEGRITY_FIELD: TagNumber = TagNumber::N0;
/// The context tag of `confidentiality` in `Metadata`.
const CONFIDENTIALITY_FIELD: TagNumber = TagNumber::N1;

/// A frame encoding open for a splice, as its components and those of its
/// metadata.
struct WireFrame {
	frame: RawSequence,
	metadata: RawSequence,
}

impl WireFrame {
	/// Split `frame_der`, refusing bytes that do not encode a [`Frame`].
	fn parse(frame_der: impl AsRef<[u8]>) -> Result<Self, TightBeamError> {
		let frame_der = frame_der.as_ref();
		Frame::from_der(frame_der)?;

		let frame = RawSequence::from_der(frame_der)?;
		let metadata = frame.0.get(FRAME_METADATA).ok_or(TightBeamError::InvalidMetadata)?;
		let metadata = RawSequence::from_der(&metadata.to_der()?)?;

		Ok(Self { frame, metadata })
	}

	/// Replace the body octets.
	fn set_message(&mut self, message: Vec<u8>) -> Result<(), TightBeamError> {
		let message = Any::from_der(&OctetString::new(message)?.to_der()?)?;
		let held = self.frame.0.get_mut(FRAME_MESSAGE).ok_or(TightBeamError::InvalidBody)?;
		*held = message;

		Ok(())
	}

	/// Place `compactness` after `order`, in place of the one the frame holds.
	fn set_compactness(&mut self, compactness: &CompressedData) -> Result<(), TightBeamError> {
		let field = Any::from_der(&compactness.to_der()?)?;
		let components = &mut self.metadata.0;

		match components.get_mut(METADATA_COMPACTNESS) {
			Some(held) if held.tag() == Tag::Sequence => *held = field,
			_ => components.insert(METADATA_COMPACTNESS, field),
		}

		Ok(())
	}

	/// The encoding of `SEQUENCE { version, metadata }`, the preimage of the
	/// frame-integrity digest.
	fn witness_input(&self) -> Result<Vec<u8>, TightBeamError> {
		let version = self.frame.0.first().ok_or(TightBeamError::InvalidMetadata)?.clone();
		let metadata = Any::from_der(&self.metadata.to_der()?)?;
		Ok(RawSequence(vec![version, metadata]).to_der()?)
	}

	/// Reassemble the frame, and refuse a result [`Frame`] would refuse, such
	/// as a field below its version.
	fn finish(mut self) -> Result<Vec<u8>, TightBeamError> {
		let metadata = Any::from_der(&self.metadata.to_der()?)?;
		let held = self.frame.0.get_mut(FRAME_METADATA).ok_or(TightBeamError::InvalidMetadata)?;
		*held = metadata;

		let spliced = self.frame.to_der()?;
		Frame::from_der(&spliced)?;

		Ok(spliced)
	}
}

/// Build a parameterless `AlgorithmIdentifier` from an OID.
fn algorithm(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid, parameters: None }
}

/// Install a message-integrity commitment: the digest of
/// [`commitment_preimage`] under the caller's algorithm (V1+ frames).
pub fn set_message_integrity(
	frame_der: impl AsRef<[u8]>,
	algorithm_oid: ObjectIdentifier,
	digest: impl AsRef<[u8]>,
) -> Result<Vec<u8>, TightBeamError> {
	let digest = OctetString::new(digest.as_ref())?;
	let commitment = DigestInfo { algorithm: algorithm(algorithm_oid), digest };

	let mut wire = WireFrame::parse(frame_der)?;
	wire.metadata.set_tagged(INTEGRITY_FIELD, &commitment)?;
	wire.finish()
}

/// Replace the frame body with `ciphertext` and install `envelope_der`, the
/// `AuthEnvelopedData` that seals it (V1+ frames).
///
/// The ciphertext travels detached from the envelope (RFC 5652 §6.1). The
/// envelope carries the content type, the recipient, and the tag.
pub fn set_confidentiality(
	frame_der: impl AsRef<[u8]>,
	envelope_der: impl AsRef<[u8]>,
	ciphertext: Vec<u8>,
) -> Result<Vec<u8>, TightBeamError> {
	let envelope = WireDer::<AuthEnvelopedData>::try_from(envelope_der.as_ref())?;
	let mut wire = WireFrame::parse(frame_der)?;
	wire.metadata.set_tagged(CONFIDENTIALITY_FIELD, envelope.value())?;
	wire.set_message(ciphertext)?;
	wire.finish()
}

/// Replace the frame body with `compressed` and record the compactness info
/// (any version): the caller's compression algorithm OID, its DER-encoded
/// parameters when the scheme has any, and the content type of the
/// uncompressed body (defaults to `id-data`, the type of an opaque frame
/// body, RFC 3274 §1.1).
///
/// Call before [`set_confidentiality`]: peers encrypt the compressed bytes
/// and decompress after decrypting.
pub fn set_compactness(
	frame_der: impl AsRef<[u8]>,
	content_oid: Option<ObjectIdentifier>,
	algorithm_oid: ObjectIdentifier,
	parameters_der: Option<Vec<u8>>,
	compressed: Vec<u8>,
) -> Result<Vec<u8>, TightBeamError> {
	let parameters = match parameters_der {
		Some(der) => Some(Any::from_der(&der)?),
		None => None,
	};

	let compactness = CompressedData {
		version: CmsVersion::V0,
		compression_alg: AlgorithmIdentifierOwned { oid: algorithm_oid, parameters },
		encap_content_info: EncapsulatedContentInfo { econtent_type: content_oid.unwrap_or(DATA), econtent: None },
	};

	let mut wire = WireFrame::parse(frame_der)?;
	wire.set_compactness(&compactness)?;
	wire.set_message(compressed)?;
	wire.finish()
}

/// The frame-integrity (witness) preimage bytes for a frame: hash them with
/// any digest and install the result via [`attach_witness`].
///
/// Call after all metadata mutations ([`set_message_integrity`],
/// [`set_confidentiality`]): the witness covers the final envelope.
pub fn witness_input(frame_der: impl AsRef<[u8]>) -> Result<Vec<u8>, TightBeamError> {
	WireFrame::parse(frame_der)?.witness_input()
}

/// Install a frame-integrity witness: the digest of [`witness_input`] under
/// the caller's algorithm (V1+ frames).
pub fn attach_witness(
	frame_der: impl AsRef<[u8]>,
	algorithm_oid: ObjectIdentifier,
	digest: impl AsRef<[u8]>,
) -> Result<Vec<u8>, TightBeamError> {
	let digest = OctetString::new(digest.as_ref())?;
	let witness = DigestInfo { algorithm: algorithm(algorithm_oid), digest };

	let mut wire = WireFrame::parse(frame_der)?;
	wire.frame.set_tagged(INTEGRITY_FIELD, &witness)?;
	wire.finish()
}

/// The to-be-signed bytes of a frame (everything but the signature field).
///
/// Call after [`attach_witness`]: the signature covers the witness.
pub fn tbs_bytes(frame_der: impl AsRef<[u8]>) -> Result<Vec<u8>, TightBeamError> {
	let frame = Frame::from_der(frame_der.as_ref())?;
	frame.to_tbs()
}

/// The `SignerIdentifier` of a subject key identifier (RFC 5652 §5.3).
fn signer_identifier(signer_key_id: impl AsRef<[u8]>) -> Result<SignerIdentifier, TightBeamError> {
	let key_id = OctetString::new(signer_key_id.as_ref())?;
	Ok(SignerIdentifier::SubjectKeyIdentifier(key_id.into()))
}

/// The CMS `SignerInfo` a frame's signature completes, over the TBS of
/// `frame` under the profile signature.
fn signature_draft(frame: &Frame, sid: SignerIdentifier) -> Result<SignerInfoDraft, TightBeamError> {
	let tbs = frame.to_tbs()?;
	Ok(CmsSigner::draft::<Secp256k1Signature>(sid, SignedContent::data(&tbs))?)
}

/// The digest a signer's key signs for `frame_der`: the digest of the DER of
/// the CMS signed attributes, which bind the content type, the digest of the
/// TBS, and the algorithms (RFC 5652 §5.4, RFC 6211).
///
/// `signer_key_id` is the subject key identifier that names the signer. Sign
/// the digest directly, with no rehash, and install the result via
/// [`attach_signature`].
pub fn signing_prehash(
	frame_der: impl AsRef<[u8]>,
	signer_key_id: impl AsRef<[u8]>,
) -> Result<Vec<u8>, TightBeamError> {
	let frame = Frame::from_der(frame_der.as_ref())?;
	let draft = signature_draft(&frame, signer_identifier(signer_key_id)?)?;

	Ok(draft.prehash().to_vec())
}

/// The digest a verifier checks a signed frame's signature against, drawn
/// from the frame's own signer and TBS.
///
/// The digest binds the signed attributes the profile requires, so a
/// signature that verifies over it covers this frame.
pub fn signature_prehash(frame_der: impl AsRef<[u8]>) -> Result<Vec<u8>, TightBeamError> {
	let frame = Frame::from_der(frame_der.as_ref())?;
	let signer_info = frame.nonrepudiation().ok_or(TightBeamError::MissingSignature)?;
	let draft = signature_draft(&frame, signer_info.sid.clone())?;

	Ok(draft.prehash().to_vec())
}

/// Attach `signature`, the signer's DER `ECDSA-Sig-Value` over
/// [`signing_prehash`], to an unsigned frame (V1+ frames).
pub fn attach_signature(
	frame_der: impl AsRef<[u8]>,
	signature: impl AsRef<[u8]>,
	signer_key_id: impl AsRef<[u8]>,
) -> Result<Vec<u8>, TightBeamError> {
	let mut frame = Frame::from_der(frame_der.as_ref())?;
	let draft = signature_draft(&frame, signer_identifier(signer_key_id)?)?;

	frame.attach_signer_info(draft.complete(signature, None)?)?;
	Ok(frame.to_der()?)
}

/// Decoded view of a frame: its body, metadata, and the carried security
/// infos (algorithm OIDs + artifacts) a caller needs to verify with its own
/// cryptography.
pub struct FrameSummary {
	/// Protocol version ordinal (`V0` -> 0, ..., `V3` -> 3).
	pub version: u8,
	/// Opaque message identifier.
	pub id: Vec<u8>,
	/// Frame order stamp.
	///
	/// The value is protocol-opaque. Any monotonic scheme works, such as a
	/// Unix timestamp or a dense per-channel counter. When omitted at build
	/// time, the profile defaults to the current Unix time in seconds.
	pub order: u64,
	/// The raw frame body: the caller's body DER when cleartext, or the
	/// ciphertext when confidential. Decode a profile opaque body with
	/// [`decode_body`]. Typed bodies decode under the caller's schema.
	pub body_der: Vec<u8>,
	/// Message priority ordinal (`LowEffort` -> 0, ...), when present (V2+).
	pub priority: Option<u8>,
	/// Time-to-live in seconds, when present (V2+).
	pub lifetime: Option<u64>,
	/// Parent-link digest algorithm OID (dotted form), when present (V2+).
	pub previous_hash_algorithm_oid: Option<String>,
	/// Parent-link digest octets, when present (V2+).
	pub previous_hash_digest: Option<Vec<u8>>,
	/// Control-matrix dimension N, when present (V3+).
	pub matrix_n: Option<u8>,
	/// Control-matrix row-major bytes, when present (V3+).
	pub matrix_data: Option<Vec<u8>>,
	/// Body-compression algorithm OID, when compressed.
	pub compactness_algorithm_oid: Option<String>,
	/// Body-compression algorithm parameters DER, when compressed and present.
	pub compactness_parameters_der: Option<Vec<u8>>,
	/// Content-type OID of the uncompressed body, when compressed.
	pub compactness_content_oid: Option<String>,
	/// Message-commitment digest algorithm OID, when committed.
	pub message_integrity_algorithm_oid: Option<String>,
	/// Message-commitment digest octets, when committed.
	pub message_integrity_digest: Option<Vec<u8>>,
	/// Witness digest algorithm OID, when witnessed.
	pub frame_integrity_algorithm_oid: Option<String>,
	/// Witness digest octets, when witnessed.
	pub frame_integrity_digest: Option<Vec<u8>>,
	/// Content-encryption algorithm OID, when confidential.
	pub confidentiality_algorithm_oid: Option<String>,
	/// DER `AuthEnvelopedData` that seals the body, when confidential. The
	/// ciphertext travels in the body, detached from it.
	pub confidentiality_envelope_der: Option<Vec<u8>>,
	/// Signature algorithm OID, when signed.
	pub signature_algorithm_oid: Option<String>,
	/// Signature digest algorithm OID, when signed.
	pub signature_digest_algorithm_oid: Option<String>,
	/// DER signature octets, when signed.
	pub signature: Option<Vec<u8>>,
}

/// The dotted algorithm OID and the digest octets of an optional digest.
fn digest_fields(info: Option<&DigestInfo>) -> (Option<String>, Option<Vec<u8>>) {
	let algorithm_oid = info.map(|info| info.algorithm.oid.to_string());
	let digest = info.map(|info| info.digest.as_bytes().to_vec());

	(algorithm_oid, digest)
}

/// Decode a frame DER into a [`FrameSummary`].
pub fn inspect_frame(frame_der: impl AsRef<[u8]>) -> Result<FrameSummary, TightBeamError> {
	let frame = Frame::from_der(frame_der.as_ref())?;
	let metadata = frame.metadata();

	let compactness = metadata.compactness();
	let compactness_parameters_der = compactness
		.and_then(|info| info.compression_alg.parameters.as_ref())
		.map(Encode::to_der)
		.transpose()?;

	let confidentiality = metadata.confidentiality();
	let confidentiality_envelope_der = confidentiality.map(Encode::to_der).transpose()?;
	let confidentiality_algorithm_oid =
		confidentiality.map(|envelope| envelope.auth_encrypted_content_info.content_enc_alg.oid.to_string());

	let (previous_hash_algorithm_oid, previous_hash_digest) = digest_fields(metadata.previous_frame());
	let (message_integrity_algorithm_oid, message_integrity_digest) = digest_fields(metadata.integrity());
	let (frame_integrity_algorithm_oid, frame_integrity_digest) = digest_fields(frame.integrity());

	let matrix = metadata.matrix();
	let signature = frame.nonrepudiation();

	Ok(FrameSummary {
		version: frame.version() as u8,
		id: metadata.id().to_vec(),
		order: metadata.order(),
		body_der: frame.message().to_vec(),
		priority: metadata.priority().map(|priority| priority as u8),
		lifetime: metadata.lifetime(),
		previous_hash_algorithm_oid,
		previous_hash_digest,
		matrix_n: matrix.map(MatrixLike::n),
		matrix_data: matrix.map(|entry| entry.as_bytes().to_vec()),
		compactness_algorithm_oid: compactness.map(|info| info.compression_alg.oid.to_string()),
		compactness_parameters_der,
		compactness_content_oid: compactness.map(|info| info.encap_content_info.econtent_type.to_string()),
		message_integrity_algorithm_oid,
		message_integrity_digest,
		frame_integrity_algorithm_oid,
		frame_integrity_digest,
		confidentiality_algorithm_oid,
		confidentiality_envelope_der,
		signature_algorithm_oid: signature.map(|info| info.signature_algorithm.oid.to_string()),
		signature_digest_algorithm_oid: signature.map(|info| info.digest_alg.oid.to_string()),
		signature: signature.map(|info| info.signature.as_bytes().to_vec()),
	})
}

// ---------------------------------------------------------------------------
// Tightbeam profile primitives (SHA3-256 / secp256k1 / AES-256-GCM / HPKE).
// Conveniences only: the structure path above accepts any digest and any
// envelope.
// ---------------------------------------------------------------------------

/// SHA3-256 digest of `data` - the profile hasher.
pub fn sha3_256_digest(data: impl AsRef<[u8]>) -> Vec<u8> {
	Sha3_256::digest(data.as_ref()).to_vec()
}

/// Sign `prehash` with a profile secp256k1 signing key, with no rehash, as a
/// DER `ECDSA-Sig-Value`.
pub fn sign_prehash(key: &Secp256k1SigningKey, prehash: impl AsRef<[u8]>) -> Result<Vec<u8>, TightBeamError> {
	let signature: Secp256k1Signature = key.sign_prehash(prehash.as_ref())?;
	Ok(signature.to_bytes().to_vec())
}

/// Subject-key-identifier octets for a profile secp256k1 verifying key, by
/// RFC 7093 §2 method 1.
///
/// `tightbeam::cert!` writes the same identifier into each certificate, so a
/// signature under this identifier names the certificate of the key.
pub fn signer_id(key: &Secp256k1VerifyingKey) -> Result<Vec<u8>, TightBeamError> {
	let spki = SubjectPublicKeyInfoOwned::from_key(*key)?;
	Ok(Skid::of_public_key(&spki).as_bytes().to_vec())
}

/// Verify a frame's non-repudiation signature under a pinned profile key.
///
/// The key is the trust decision, so the check reads no certificate. The
/// signature verifies over the signed attributes, which bind the frame's TBS.
pub fn verify_signature(key: &Secp256k1VerifyingKey, frame_der: impl AsRef<[u8]>) -> Result<(), TightBeamError> {
	let frame = Frame::from_der(frame_der.as_ref())?;
	let signer_info = frame.nonrepudiation().ok_or(TightBeamError::MissingSignature)?;
	let tbs = frame.to_tbs()?;

	CmsSigner::verify::<Secp256k1Signature, _>(signer_info, key, SignedContent::data(&tbs))?;
	Ok(())
}

/// A sealed body produced by a profile encryptor: the pieces
/// [`set_confidentiality`] installs.
pub struct SealedBody {
	/// The content-encryption algorithm OID (dotted form).
	pub algorithm_oid: String,
	/// The DER `AuthEnvelopedData`, its content detached.
	pub envelope_der: Vec<u8>,
	/// The ciphertext replacing the frame body.
	pub ciphertext: Vec<u8>,
}

/// Detach the encrypted content of `envelope` into the [`SealedBody`] pieces.
fn sealed_body(mut envelope: AuthEnvelopedData) -> Result<SealedBody, TightBeamError> {
	let ciphertext = envelope.take_content()?.to_vec();
	let algorithm_oid = envelope.auth_encrypted_content_info.content_enc_alg.oid.to_string();
	let envelope_der = envelope.to_der()?;

	Ok(SealedBody { algorithm_oid, envelope_der, ciphertext })
}

/// Open `ciphertext` under `decryptor`, against the envelope that seals it.
async fn opened(
	decryptor: &impl DecryptContent,
	envelope_der: impl AsRef<[u8]>,
	mut ciphertext: Vec<u8>,
) -> Result<Vec<u8>, TightBeamError> {
	let sealed = WireDer::<AuthEnvelopedData>::try_from(envelope_der.as_ref())?;
	decryptor.decrypt_content(&sealed, &mut ciphertext).await?;

	Ok(ciphertext)
}

/// Profile key-encryption key: a 32-byte shared key that wraps a fresh
/// AES-256-GCM content key per seal, in a `KEKRecipientInfo` named by
/// `key_id` (RFC 5652 §6.2.3).
pub struct Aes256GcmKey {
	provider: Aes256GcmKeyProvider,
}

impl Aes256GcmKey {
	/// Construct from a raw 32-byte key and the identifier that names it to
	/// every holder.
	pub fn new(key: impl AsRef<[u8]>, key_id: impl AsRef<[u8]>) -> Result<Self, TightBeamError> {
		let key = key.as_ref().to_vec();
		let provider = Aes256GcmKeyProvider::new(key, key_id.as_ref().to_vec())?;
		Ok(Self { provider })
	}

	/// Seal `plaintext` (a [`body_preimage`]) of type `content_oid`, or
	/// `id-data` without one, under a fresh content key.
	pub fn seal(
		&self,
		plaintext: impl AsRef<[u8]>,
		content_oid: Option<ObjectIdentifier>,
	) -> Result<SealedBody, TightBeamError> {
		let sealed = Encryptor::<Aes256GcmOid>::encrypt_content(&self.provider, plaintext.as_ref(), content_oid, None);
		sealed_body(sealed?)
	}

	/// Open a sealed body, returning the plaintext body DER.
	pub async fn open(&self, envelope_der: impl AsRef<[u8]>, ciphertext: Vec<u8>) -> Result<Vec<u8>, TightBeamError> {
		opened(&self.provider, envelope_der, ciphertext).await
	}
}

/// Profile HPKE encryptor (DHKEM over secp256k1, an AES-256-GCM content key,
/// and a `KEMRecipientInfo` per RFC 9629).
pub struct HpkeSecp256k1Encryptor {
	inner: HpkeEncryptor<DefaultCryptoProvider>,
}

impl HpkeSecp256k1Encryptor {
	/// Construct from the recipient's SEC1 public key.
	pub fn from_sec1(recipient_public_key: impl AsRef<[u8]>) -> Result<Self, TightBeamError> {
		let key = Secp256k1VerifyingKey::from_sec1_bytes(recipient_public_key.as_ref())?;
		let spki = key.to_public_key_der()?;
		let inner = HpkeEncryptor::new(KemRecipient::bare(spki.as_bytes())?);

		Ok(Self { inner })
	}

	/// Seal `plaintext` of type `content_oid`, or `id-data` without one, to
	/// the recipient under a fresh ephemeral key.
	pub fn seal(
		&self,
		plaintext: impl AsRef<[u8]>,
		content_oid: Option<ObjectIdentifier>,
	) -> Result<SealedBody, TightBeamError> {
		let sealed = Encryptor::<Aes256GcmOid>::encrypt_content(&self.inner, plaintext.as_ref(), content_oid, None);
		sealed_body(sealed?)
	}
}

/// Profile HPKE decryptor holding the recipient secp256k1 secret.
pub struct HpkeSecp256k1Decryptor {
	inner: HpkeDecryptor<DefaultCryptoProvider>,
}

impl HpkeSecp256k1Decryptor {
	/// Construct from a raw 32-byte recipient secret key.
	pub fn new(secret_key: impl AsRef<[u8]>) -> Result<Self, TightBeamError> {
		let signing_key = Secp256k1SigningKey::from_slice(secret_key.as_ref())?;
		let public = PublicKey::from(signing_key.verifying_key());

		let backend: Arc<dyn DiffieHellman<Secp256k1>> = Arc::new(Secp256k1KeyProvider::from(signing_key));
		let inner = HpkeDecryptor::new(BareKemKey::new(public, backend)?);

		Ok(Self { inner })
	}

	/// Open a sealed body, returning the plaintext body DER.
	pub async fn open(&self, envelope_der: impl AsRef<[u8]>, ciphertext: Vec<u8>) -> Result<Vec<u8>, TightBeamError> {
		opened(&self.inner, envelope_der, ciphertext).await
	}
}

#[cfg(test)]
mod tests {
	use der::asn1::OctetString;
	use tightbeam::asn1::AlgorithmIdentifierOwned;
	use tightbeam::core::IntegrityVerdict;
	use tightbeam::crypto::commitment::Opening;
	use tightbeam::crypto::hash::Sha3_256;
	use tightbeam::crypto::key::Aes256GcmKeyProvider;
	use tightbeam::crypto::profiles::DefaultCryptoProvider;
	use tightbeam::crypto::secret::ToInsecure;
	use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
	use tightbeam::crypto::x509::{KeyPurposes, PeerCertificate, Signing};
	use tightbeam::der::{Decode, Encode, Sequence};
	use tightbeam::matrix::{MatrixDyn, MatrixLike};
	use tightbeam::oids::{AES_256_GCM, DHKEM_SECP256K1, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256};
	use tightbeam::testing::TestCertificate;
	use tightbeam::{Beamable, DigestInfo, Frame, MessagePriority, Version};

	use tightbeam::compress::{Compressor, Inflator, ZstdCompression};

	use tightbeam::spki::EncodePublicKey;

	use super::{
		attach_signature, attach_witness, body_preimage, commitment_preimage, decode_body, inspect_frame,
		set_compactness, set_confidentiality, set_message_integrity, sha3_256_digest, sign_prehash, signature_prehash,
		signer_id, signing_prehash, verify_signature, witness_input, Aes256GcmKey, FrameConfig, HpkeSecp256k1Decryptor,
		HpkeSecp256k1Encryptor, OpaqueBody,
	};

	type TestResult = core::result::Result<(), Box<dyn core::error::Error>>;
	type AnyResult<T> = core::result::Result<T, Box<dyn core::error::Error>>;

	fn sample_message() -> Vec<u8> {
		b"opaque-message-body".to_vec()
	}

	/// The profile body DER wrapping [`sample_message`].
	fn sample_body() -> AnyResult<Vec<u8>> {
		Ok(body_preimage(sample_message())?)
	}

	fn signing_key() -> AnyResult<Secp256k1SigningKey> {
		Ok(Secp256k1SigningKey::from_bytes(&[1u8; 32].into())?)
	}

	fn base_config(id: &[u8], order: u64) -> AnyResult<FrameConfig> {
		Ok(FrameConfig { id: id.to_vec(), order, message: sample_body()?, ..Default::default() })
	}

	fn seal_frame(id: &[u8], order: u64) -> AnyResult<Vec<u8>> {
		Ok(base_config(id, order)?.build()?)
	}

	fn open_frame(frame_der: impl AsRef<[u8]>) -> AnyResult<Vec<u8>> {
		let frame = Frame::from_der(frame_der.as_ref())?;
		Ok(decode_body(frame.message())?)
	}

	/// A salt long enough to hide a body.
	const HIDING_SALT: &[u8] = b"tbws-commitment-salt";

	/// The identifier that names the shared key of the AEAD fixtures.
	const KEY_ID: &[u8] = b"tbws/test/kek/v1";

	fn frame_from(config: FrameConfig) -> AnyResult<Frame> {
		Ok(Frame::from_der(&config.build()?)?)
	}

	/// Drive the full caller-side pipeline with the profile primitives, the
	/// way the TS builder does: commit, witness, then sign detached.
	fn signed_frame(id: &[u8], order: u64, key: &Secp256k1SigningKey) -> AnyResult<Vec<u8>> {
		let config = FrameConfig { version: Some(Version::V2), ..base_config(id, order)? };
		let der = config.build()?;

		let commitment = sha3_256_digest(commitment_preimage([], sample_body()?)?);
		let der = set_message_integrity(&der, HASH_SHA3_256, commitment)?;

		let witness = sha3_256_digest(witness_input(&der)?);
		let der = attach_witness(&der, HASH_SHA3_256, witness)?;

		let sid = signer_id(key.verifying_key())?;
		let signature = sign_prehash(key, signing_prehash(&der, &sid)?)?;

		Ok(attach_signature(&der, signature, sid)?)
	}

	#[test]
	fn seal_then_open_round_trips_message() -> TestResult {
		let frame_der = seal_frame(b"msg-1", 7)?;
		let recovered = open_frame(&frame_der)?;
		assert_eq!(recovered, sample_message());
		Ok(())
	}

	#[test]
	fn cleartext_frame_carries_metadata() -> TestResult {
		let frame_der = seal_frame(b"id-9", 42)?;
		let frame = Frame::from_der(&frame_der)?;
		assert_eq!(frame.metadata().id(), b"id-9");
		assert_eq!(frame.metadata().order(), 42);
		assert!(frame.integrity().is_none());
		assert!(frame.nonrepudiation().is_none());
		Ok(())
	}

	#[test]
	fn config_defaults_to_v0_cleartext() -> TestResult {
		let frame = frame_from(base_config(b"plain", 1)?)?;
		assert_eq!(frame.version(), Version::V0);
		assert!(frame.nonrepudiation().is_none());
		Ok(())
	}

	#[test]
	fn config_applies_v2_metadata() -> TestResult {
		let config = FrameConfig {
			priority: Some(MessagePriority::LowLatency),
			lifetime: Some(60),
			..base_config(b"meta", 9)?
		};

		let frame = frame_from(config)?;
		assert_eq!(frame.version(), Version::V2);
		assert_eq!(frame.metadata().priority(), Some(MessagePriority::LowLatency));
		assert_eq!(frame.metadata().lifetime(), Some(60));
		Ok(())
	}

	#[test]
	fn config_matrix_requires_v3() -> TestResult {
		let matrix = MatrixDyn::from_row_major(2, vec![0, 1, 1, 0]).ok_or("matrix dims")?;
		let config = FrameConfig { matrix: Some(matrix), ..base_config(b"matrix", 1)? };

		let frame = frame_from(config)?;
		assert_eq!(frame.version(), Version::V3);

		let recovered_matrix = frame.metadata().matrix().ok_or("matrix present")?;
		assert_eq!(recovered_matrix.n(), 2);
		Ok(())
	}

	#[test]
	fn config_pins_explicit_version() -> TestResult {
		let config = FrameConfig { version: Some(Version::V2), ..base_config(b"pinned", 3)? };
		let frame = frame_from(config)?;
		assert_eq!(frame.version(), Version::V2);
		Ok(())
	}

	#[test]
	fn inspect_reports_cleartext_metadata() -> TestResult {
		let frame_der = seal_frame(b"view-1", 11)?;
		let summary = inspect_frame(&frame_der)?;
		assert_eq!(summary.version, 0);
		assert_eq!(summary.id, b"view-1");
		assert_eq!(summary.order, 11);
		assert_eq!(summary.body_der, sample_body()?);
		assert_eq!(decode_body(&summary.body_der)?, sample_message());
		assert_eq!(summary.signature_algorithm_oid, None);
		assert_eq!(summary.message_integrity_algorithm_oid, None);
		assert_eq!(summary.frame_integrity_algorithm_oid, None);
		assert_eq!(summary.confidentiality_algorithm_oid, None);
		Ok(())
	}

	#[test]
	fn inspect_reports_v2_metadata_and_matrix() -> TestResult {
		let algorithm = AlgorithmIdentifierOwned { oid: "2.16.840.1.101.3.4.2.10".parse()?, parameters: None };
		let digest_octets = vec![0xAAu8; 32];
		let previous = DigestInfo { algorithm, digest: OctetString::new(digest_octets.as_slice())? };
		let matrix = MatrixDyn::from_row_major(2, vec![0, 1, 1, 0]).ok_or("matrix dims")?;

		let config = FrameConfig {
			priority: Some(MessagePriority::Expedited),
			lifetime: Some(300),
			previous_hash: Some(previous),
			matrix: Some(matrix),
			..base_config(b"rich", 21)?
		};

		let summary = inspect_frame(config.build()?)?;
		assert_eq!(summary.priority, Some(4));
		assert_eq!(summary.lifetime, Some(300));
		assert_eq!(summary.previous_hash_algorithm_oid.as_deref(), Some("2.16.840.1.101.3.4.2.10"));
		assert_eq!(summary.previous_hash_digest, Some(digest_octets));
		assert_eq!(summary.matrix_n, Some(2));
		assert_eq!(summary.matrix_data, Some(vec![0, 1, 1, 0]));
		Ok(())
	}

	#[test]
	fn inspect_omits_absent_metadata() -> TestResult {
		let summary = inspect_frame(seal_frame(b"bare", 1)?)?;
		assert_eq!(summary.priority, None);
		assert_eq!(summary.lifetime, None);
		assert_eq!(summary.compactness_algorithm_oid, None);
		assert_eq!(summary.previous_hash_algorithm_oid, None);
		assert_eq!(summary.previous_hash_digest, None);
		assert_eq!(summary.matrix_n, None);
		assert_eq!(summary.matrix_data, None);
		Ok(())
	}

	#[test]
	fn signed_frame_carries_security_infos() -> TestResult {
		let summary = inspect_frame(signed_frame(b"signed-1", 5, &signing_key()?)?)?;
		assert_eq!(summary.signature_algorithm_oid.as_deref(), Some("2.16.840.1.101.3.4.3.10"));
		assert_eq!(
			summary.signature_digest_algorithm_oid.as_deref(),
			Some("2.16.840.1.101.3.4.2.8")
		);
		assert_eq!(
			summary.message_integrity_algorithm_oid.as_deref(),
			Some("2.16.840.1.101.3.4.2.8")
		);
		assert_eq!(summary.frame_integrity_algorithm_oid.as_deref(), Some("2.16.840.1.101.3.4.2.8"));
		assert!(summary.signature.is_some());
		Ok(())
	}

	#[test]
	fn signed_frame_body_opens() -> TestResult {
		let frame_der = signed_frame(b"signed-2", 5, &signing_key()?)?;
		assert_eq!(open_frame(&frame_der)?, sample_message());
		Ok(())
	}

	#[test]
	fn signed_frame_verifies_with_tightbeam() -> TestResult {
		let key = signing_key()?;
		let frame = Frame::from_der(&signed_frame(b"signed-3", 5, &key)?)?;

		// The signature names the certificate of the key, so tightbeam's own
		// certificate path resolves and verifies it.
		let certificate = TestCertificate::self_signed(&key);
		let signer = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(certificate, KeyPurposes::HOUSE.signer)?;
		frame.verify(&signer)?;
		Ok(())
	}

	#[test]
	fn the_verifier_prehash_is_the_signer_prehash() -> TestResult {
		let key = signing_key()?;
		let sid = signer_id(key.verifying_key())?;

		let der = FrameConfig { version: Some(Version::V1), ..base_config(b"prehash", 1)? }.build()?;
		let prehash = signing_prehash(&der, &sid)?;
		let signed = attach_signature(&der, sign_prehash(&key, &prehash)?, &sid)?;

		assert_eq!(signature_prehash(&signed)?, prehash);
		Ok(())
	}

	#[test]
	fn verify_signature_accepts_signer_key() -> TestResult {
		let key = signing_key()?;
		let frame_der = signed_frame(b"sig-ok", 1, &key)?;

		verify_signature(key.verifying_key(), &frame_der)?;
		Ok(())
	}

	#[test]
	fn signing_key_spki_matches_encode_public_key() -> TestResult {
		let key = signing_key()?;
		let spki = key.verifying_key().to_public_key_der()?.into_vec();
		assert_eq!(spki.len(), 88);
		assert_eq!(spki[23], 0x04);
		Ok(())
	}

	#[test]
	fn verify_signature_rejects_wrong_key() -> TestResult {
		let frame_der = signed_frame(b"sig-bad", 1, &signing_key()?)?;
		let other = Secp256k1SigningKey::from_bytes(&[2u8; 32].into())?;
		assert!(verify_signature(other.verifying_key(), &frame_der).is_err());
		Ok(())
	}

	#[test]
	fn verify_signature_rejects_unsigned_frame() -> TestResult {
		let frame_der = seal_frame(b"unsigned", 1)?;
		assert!(verify_signature(signing_key()?.verifying_key(), &frame_der).is_err());
		Ok(())
	}

	/// A signature that is no DER `ECDSA-Sig-Value` never reaches the frame.
	#[test]
	fn a_compact_signature_is_refused_at_attach() -> TestResult {
		let key = signing_key()?;
		let frame_der = FrameConfig { version: Some(Version::V1), ..base_config(b"junk", 1)? }.build()?;
		let sid = signer_id(key.verifying_key())?;

		assert!(attach_signature(&frame_der, [0u8; 64], sid).is_err());
		Ok(())
	}

	/// A frame below V1 carries no signature, so the attach refuses it.
	#[test]
	fn a_v0_frame_refuses_a_signature() -> TestResult {
		let key = signing_key()?;
		let frame_der = seal_frame(b"v0", 1)?;
		let sid = signer_id(key.verifying_key())?;
		let signature = sign_prehash(&key, signing_prehash(&frame_der, &sid)?)?;

		assert!(attach_signature(&frame_der, signature, sid).is_err());
		Ok(())
	}

	/// A signature over one frame fails on another.
	#[test]
	fn a_signature_does_not_transfer_between_frames() -> TestResult {
		let key = signing_key()?;
		let sid = signer_id(key.verifying_key())?;

		let first = FrameConfig { version: Some(Version::V1), ..base_config(b"first", 1)? }.build()?;
		let second = FrameConfig { version: Some(Version::V1), ..base_config(b"second", 1)? }.build()?;
		let signature = sign_prehash(&key, signing_prehash(&first, &sid)?)?;

		let moved = attach_signature(&second, signature, sid)?;
		assert!(verify_signature(key.verifying_key(), &moved).is_err());
		Ok(())
	}

	/// The caller-side commitment (preimage + digest + install) must satisfy
	/// tightbeam's own commitment verdict: pins the preimage framing.
	#[test]
	fn caller_side_commitment_verifies_with_tightbeam() -> TestResult {
		let salt = HIDING_SALT;
		let der = FrameConfig { version: Some(Version::V2), ..base_config(b"mi", 1)? }.build()?;

		let commitment = sha3_256_digest(commitment_preimage(salt, body_preimage(sample_message())?)?);
		let der = set_message_integrity(&der, HASH_SHA3_256, commitment)?;

		let frame = Frame::from_der(&der)?;
		let body = OpaqueBody::from_der(frame.message())?;
		let (_, opening) = Opening::prove::<Sha3_256, _>(&body, salt)?;
		assert!(matches!(
			frame.message_commitment_verdict::<Sha3_256>(&opening)?,
			IntegrityVerdict::Verified
		));
		Ok(())
	}

	/// The caller-side witness (input + digest + install) must satisfy
	/// tightbeam's own frame-integrity verdict: pins the scaffold encoding.
	#[test]
	fn caller_side_witness_verifies_with_tightbeam() -> TestResult {
		let der = FrameConfig { version: Some(Version::V2), ..base_config(b"fi", 1)? }.build()?;

		let witness = sha3_256_digest(witness_input(&der)?);
		let der = attach_witness(&der, HASH_SHA3_256, witness)?;

		let frame = Frame::from_der(&der)?;
		assert!(matches!(
			frame.frame_integrity_verdict::<Sha3_256>()?,
			IntegrityVerdict::Verified
		));
		Ok(())
	}

	#[test]
	fn tampered_witness_reports_mismatch() -> TestResult {
		let der = FrameConfig { version: Some(Version::V2), ..base_config(b"fi-bad", 1)? }.build()?;
		let der = attach_witness(&der, HASH_SHA3_256, [0u8; 32])?;

		let frame = Frame::from_der(&der)?;
		assert!(matches!(
			frame.frame_integrity_verdict::<Sha3_256>()?,
			IntegrityVerdict::Mismatch
		));
		Ok(())
	}

	/// A caller-sealed body must open with tightbeam's own decryptor: pins
	/// the detached envelope layout.
	#[tokio::test]
	async fn caller_side_aead_seal_opens_with_tightbeam() -> TestResult {
		let key = [0x42u8; 32];
		let der = FrameConfig { version: Some(Version::V1), ..base_config(b"sealed", 8)? }.build()?;

		let aes = Aes256GcmKey::new(key, KEY_ID)?;
		let sealed = aes.seal(body_preimage(sample_message())?, None)?;
		assert_eq!(sealed.algorithm_oid, AES_256_GCM.to_string());

		let der = set_confidentiality(&der, &sealed.envelope_der, sealed.ciphertext)?;

		let summary = inspect_frame(&der)?;
		assert_eq!(summary.confidentiality_algorithm_oid, Some(AES_256_GCM.to_string()));
		assert_eq!(summary.confidentiality_envelope_der, Some(sealed.envelope_der));
		assert_ne!(summary.body_der, sample_body()?);

		let holder = Aes256GcmKeyProvider::new(key.to_vec(), KEY_ID.to_vec())?;
		let frame = Frame::from_der(&der)?;
		let plaintext = frame.decrypt_bytes(&holder).await?.to_insecure();
		assert_eq!(decode_body(&plaintext)?, sample_message());
		Ok(())
	}

	/// A frame tightbeam seals must open under the caller-side key.
	#[tokio::test]
	async fn tightbeam_seal_opens_on_the_caller_side() -> TestResult {
		let key = [0x42u8; 32];
		let holder = Aes256GcmKeyProvider::new(key.to_vec(), KEY_ID.to_vec())?;

		let body = OpaqueBody { body: OctetString::new(sample_message())? };
		let frame = tightbeam::compose! {
			V1: id: "native-sealed",
				order: 2u64,
				message: body,
				confidentiality: holder
		}?;

		let summary = inspect_frame(frame.to_der()?)?;
		let envelope = summary.confidentiality_envelope_der.ok_or("the frame is sealed")?;
		let opened = Aes256GcmKey::new(key, KEY_ID)?.open(envelope, summary.body_der).await?;
		assert_eq!(decode_body(opened)?, sample_message());
		Ok(())
	}

	#[tokio::test]
	async fn aead_seal_open_round_trips() -> TestResult {
		let aes = Aes256GcmKey::new([0x42u8; 32], KEY_ID)?;
		let preimage = body_preimage(sample_message())?;

		let sealed = aes.seal(&preimage, None)?;
		let opened = aes.open(sealed.envelope_der, sealed.ciphertext).await?;
		assert_eq!(opened, preimage);
		Ok(())
	}

	#[tokio::test]
	async fn aead_open_rejects_wrong_key() -> TestResult {
		let sealed = Aes256GcmKey::new([0x42u8; 32], KEY_ID)?.seal(body_preimage(sample_message())?, None)?;
		let other = Aes256GcmKey::new([0x43u8; 32], KEY_ID)?;
		assert!(other.open(sealed.envelope_der, sealed.ciphertext).await.is_err());
		Ok(())
	}

	#[tokio::test]
	async fn aead_open_rejects_a_tampered_body() -> TestResult {
		let aes = Aes256GcmKey::new([0x42u8; 32], KEY_ID)?;
		let sealed = aes.seal(body_preimage(sample_message())?, None)?;

		let mut tampered = sealed.ciphertext;
		*tampered.first_mut().ok_or("the seal holds ciphertext")? ^= 0x01;
		assert!(aes.open(sealed.envelope_der, tampered).await.is_err());
		Ok(())
	}

	#[tokio::test]
	async fn hpke_seal_open_round_trips() -> TestResult {
		let recipient_public = signing_key()?.verifying_key().to_sec1_bytes().to_vec();
		let preimage = body_preimage(sample_message())?;

		let sealed = HpkeSecp256k1Encryptor::from_sec1(&recipient_public)?.seal(&preimage, None)?;
		assert_eq!(sealed.algorithm_oid, AES_256_GCM.to_string());

		let opened = HpkeSecp256k1Decryptor::new([1u8; 32])?
			.open(sealed.envelope_der, sealed.ciphertext)
			.await?;
		assert_eq!(opened, preimage);
		Ok(())
	}

	#[tokio::test]
	async fn hpke_open_rejects_wrong_secret() -> TestResult {
		let recipient_public = signing_key()?.verifying_key().to_sec1_bytes().to_vec();
		let encryptor = HpkeSecp256k1Encryptor::from_sec1(&recipient_public)?;
		let sealed = encryptor.seal(body_preimage(sample_message())?, None)?;

		let stranger = HpkeSecp256k1Decryptor::new([2u8; 32])?;
		assert!(stranger.open(sealed.envelope_der, sealed.ciphertext).await.is_err());
		Ok(())
	}

	/// A splice of a sealed body keeps the frame gate: V0 forbids confidentiality.
	#[test]
	fn a_v0_frame_refuses_an_envelope() -> TestResult {
		let der = seal_frame(b"v0-sealed", 1)?;
		let sealed = Aes256GcmKey::new([0x42u8; 32], KEY_ID)?.seal(sample_body()?, None)?;

		assert!(set_confidentiality(&der, sealed.envelope_der, sealed.ciphertext).is_err());
		Ok(())
	}

	/// Bytes that are no envelope never reach a frame.
	#[test]
	fn a_malformed_envelope_is_refused() -> TestResult {
		let der = FrameConfig { version: Some(Version::V1), ..base_config(b"bad-seal", 1)? }.build()?;
		assert!(set_confidentiality(&der, [0x30, 0x00], vec![1, 2, 3]).is_err());
		Ok(())
	}

	#[test]
	fn profile_oids() {
		assert_eq!(HASH_SHA3_256.to_string(), "2.16.840.1.101.3.4.2.8");
		assert_eq!(SIGNER_ECDSA_WITH_SHA3_256.to_string(), "2.16.840.1.101.3.4.3.10");
		assert_eq!(AES_256_GCM.to_string(), "2.16.840.1.101.3.4.1.46");
		assert_eq!(DHKEM_SECP256K1.to_string(), "1.3.6.1.4.1.64586.2.3");
	}

	#[test]
	fn commitment_preimage_marks_its_mode() -> TestResult {
		let body = vec![0xBBu8; 4];

		let plain = commitment_preimage([], &body)?;
		assert_eq!(plain.first(), Some(&0x00));
		assert_eq!(&plain[1..], body.as_slice());

		let salt = [0xAAu8; 16];
		let framed = commitment_preimage(salt, &body)?;
		assert_eq!(framed.first(), Some(&0x01));
		assert_eq!(&framed[1..9], &16u64.to_be_bytes());
		assert_eq!(&framed[9..25], &salt);
		assert_eq!(&framed[25..], body.as_slice());
		Ok(())
	}

	#[test]
	fn commitment_preimage_refuses_a_salt_too_short_to_hide() {
		assert!(commitment_preimage([0xAAu8; 15], [0xBBu8; 4]).is_err());
	}

	#[test]
	fn body_preimage_round_trips_through_decode() -> TestResult {
		let preimage = body_preimage(sample_message())?;
		assert_eq!(decode_body(preimage)?, sample_message());
		Ok(())
	}

	/// A caller-side zstd compression (compress + install) must carry the
	/// exact compactness info tightbeam's own compressor emits, and inflate
	/// with tightbeam's inflator: pins the compactness wire layout.
	#[test]
	fn caller_side_compression_inflates_with_tightbeam() -> TestResult {
		let der = seal_frame(b"packed", 5)?;

		let compressor = ZstdCompression::default();
		let (compressed, info) = compressor.compress(&sample_body()?, None)?;
		let der = set_compactness(&der, None, info.compression_alg.oid, None, compressed)?;

		let mut frame = Frame::from_der(&der)?;
		assert_eq!(frame.metadata().compactness(), Some(&info));

		let _opened = frame.inflate_in_place(&compressor)?;
		assert_eq!(decode_body(frame.message())?, sample_message());
		Ok(())
	}

	/// A body compressed by the TypeScript profile `ZstdCompression` must
	/// inflate with tightbeam's inflator: pins the cross-layer zstd wire
	/// format, one zstd frame with nothing after it.
	///
	/// Fixture: `new ZstdCompression().compress(payload)` from
	/// `ws/client/src/compress.ts` over [`interop_payload`].
	#[test]
	fn typescript_zstd_stream_inflates_with_tightbeam() -> TestResult {
		const FIXTURE_HEX: &str = "28b52ffd6020006d0100440274696768746265616d207a73746420696e746572\
			6f70206669787475726520626f6479200100cc1f4a3d01";

		let compressed = bytes_from_hex(FIXTURE_HEX)?;
		let inflated = ZstdCompression::default().decompress(&compressed)?;
		assert_eq!(inflated, interop_payload());
		Ok(())
	}

	/// The shared payload of the TypeScript/Rust zstd interop fixtures.
	fn interop_payload() -> Vec<u8> {
		"tightbeam zstd interop fixture body ".repeat(8).into_bytes()
	}

	/// The commitment `Opening::prove::<Sha3_256>` publishes over the
	/// shared opening fixture: pins the detached-commitment digest the TS.
	#[test]
	fn opening_commitment_matches_typescript_fixture() -> TestResult {
		const FIXTURE_HEX: &str = "678bec1605c349a2af6ceaa627569d31d57759ee2fbeffd2ac33026df930e04e";

		let body = OpaqueBody { body: OctetString::new(opening_payload())? };
		let (commitment, opening) = Opening::prove::<Sha3_256, _>(&body, opening_salt())?;

		let digest = commitment.digest.as_bytes();
		let published: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
		assert_eq!(published, FIXTURE_HEX);
		assert!(opening.verify::<Sha3_256>(&commitment)?);
		Ok(())
	}

	/// The shared payload of the TypeScript/Rust opening interop fixture.
	fn opening_payload() -> Vec<u8> {
		b"tightbeam opening interop fixture body".to_vec()
	}

	/// The shared salt of the TypeScript/Rust opening interop fixture.
	fn opening_salt() -> Vec<u8> {
		b"opening-interop-salt".to_vec()
	}

	/// Decode a fixture hex string (whitespace tolerated).
	fn bytes_from_hex(hex: &str) -> AnyResult<Vec<u8>> {
		let compact: String = hex.chars().filter(|character| !character.is_whitespace()).collect();
		let mut bytes = Vec::with_capacity(compact.len() / 2);
		for index in (0..compact.len()).step_by(2) {
			bytes.push(u8::from_str_radix(&compact[index..index + 2], 16)?);
		}

		Ok(bytes)
	}

	/// A compressed-then-sealed body must open through tightbeam's own
	/// decrypt-and-inflate pipeline: pins the compress-before-encrypt order.
	#[tokio::test]
	async fn compressed_then_sealed_body_decrypts_with_tightbeam() -> TestResult {
		let key = [0x42u8; 32];
		let der = FrameConfig { version: Some(Version::V1), ..base_config(b"packed-sealed", 6)? }.build()?;

		let compressor = ZstdCompression::default();
		let (compressed, info) = compressor.compress(&sample_body()?, None)?;
		let der = set_compactness(&der, None, info.compression_alg.oid, None, compressed.clone())?;

		let sealed = Aes256GcmKey::new(key, KEY_ID)?.seal(&compressed, None)?;
		let der = set_confidentiality(&der, sealed.envelope_der, sealed.ciphertext)?;

		let holder = Aes256GcmKeyProvider::new(key.to_vec(), KEY_ID.to_vec())?;
		let mut frame = Frame::from_der(&der)?;
		let _opened = frame.decrypt_in_place(&holder, Some(&compressor)).await?;
		assert_eq!(decode_body(frame.message())?, sample_message());
		Ok(())
	}

	#[test]
	fn inspect_reports_compactness() -> TestResult {
		let der = seal_frame(b"packed-view", 7)?;

		let compressor = ZstdCompression::default();
		let (compressed, info) = compressor.compress(&sample_body()?, None)?;
		let der = set_compactness(&der, None, info.compression_alg.oid, None, compressed.clone())?;

		let summary = inspect_frame(&der)?;
		assert_eq!(summary.compactness_algorithm_oid.as_deref(), Some("1.3.6.1.4.1.64586.2.1"));
		assert_eq!(summary.compactness_content_oid.as_deref(), Some("1.2.840.113549.1.7.1"));
		assert_eq!(summary.compactness_parameters_der, None);
		assert_eq!(summary.body_der, compressed);
		Ok(())
	}

	/// A typed message schema, standing in for any peer-defined `Message`
	/// body that is not the profile opaque wrapper.
	#[derive(Beamable, Clone, Debug, PartialEq, Eq, Sequence)]
	#[beam(min_version = "V0")]
	struct Doc {
		title: String,
	}

	/// A caller-supplied typed body DER must land in the frame and
	/// decode under the peer's schema: pins the raw body path.
	#[test]
	fn typed_body_round_trips_through_raw_path() -> TestResult {
		let doc = Doc { title: "typed-body".into() };
		let body_der = doc.to_der()?;

		let config = FrameConfig { message: body_der.clone(), ..base_config(b"typed", 1)? };
		let frame = Frame::from_der(&config.build()?)?;
		assert_eq!(frame.message(), body_der);
		assert_eq!(Doc::from_der(frame.message())?, doc);
		Ok(())
	}

	/// A caller-side commitment over a typed body must satisfy tightbeam's
	/// verdict computed from the typed message itself.
	#[test]
	fn typed_body_commitment_verifies_with_tightbeam() -> TestResult {
		let salt = HIDING_SALT;
		let doc = Doc { title: "committed".into() };
		let body_der = doc.to_der()?;

		let config = FrameConfig {
			version: Some(Version::V2),
			message: body_der.clone(),
			..base_config(b"typed-mi", 1)?
		};

		let der = config.build()?;
		let commitment = sha3_256_digest(commitment_preimage(salt, &body_der)?);
		let der = set_message_integrity(&der, HASH_SHA3_256, commitment)?;

		let frame = Frame::from_der(&der)?;
		let (_, opening) = Opening::prove::<Sha3_256, _>(&doc, salt)?;
		assert!(matches!(
			frame.message_commitment_verdict::<Sha3_256>(&opening)?,
			IntegrityVerdict::Verified
		));
		Ok(())
	}
}
