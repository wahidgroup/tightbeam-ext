//! Frame assembly and structural security operations over opaque message bytes.

use der::asn1::OctetString;
use der::{Decode, Sequence};

use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::cms::enveloped_data::EncryptedContentInfo;
use tightbeam::cms::signed_data::SignerIdentifier;
use tightbeam::crypto::aead::{AeadCore, Aes256Gcm, Decryptor, Encryptor, KeyInit};
use tightbeam::crypto::ecies::{EciesDecryptor, EciesEncryptor, EciesSecp256k1Oid};
use tightbeam::crypto::hash::{Digest as _, Sha3_256};
use tightbeam::crypto::k256::SecretKey;
use tightbeam::crypto::secret::ToInsecure;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey};
use tightbeam::crypto::sign::{secp256k1_signer_identifier, sign_canonical, SignerInfoExt};
use tightbeam::der::oid::AssociatedOid;
use tightbeam::der::{Any, Encode, EncodeValue, FixedTag, Length, Tag, Writer};
use tightbeam::matrix::MatrixDyn;
use tightbeam::oids::DATA;
use tightbeam::random::OsRng;
use tightbeam::{
	AlgorithmIdentifierOwned, Beamable, DigestInfo, Frame, MessagePriority, ObjectIdentifier, SignerInfo,
	TightBeamError, Version,
};

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
	/// Protocol version; when `None` uses the floor for the structural
	/// fields. Callers configuring security afterwards MUST pin the version
	/// themselves, since this config never sees those fields.
	pub version: Option<Version>,
	/// Opaque message identifier.
	pub id: Vec<u8>,
	/// Monotonic order (Unix seconds).
	pub order: u64,
	/// Opaque message body.
	pub message: Vec<u8>,
	/// Message priority (V2+).
	pub priority: Option<MessagePriority>,
	/// Time-to-live in seconds (V2+).
	pub lifetime: Option<u64>,
	/// Parent-frame link by content digest (V2+).
	pub previous_hash: Option<DigestInfo>,
	/// N×N control matrix (V2+).
	pub matrix: Option<MatrixDyn>,
}

impl FrameConfig {
	/// Lowest frame version that admits the structural fields. The matrix is
	/// a V3 feature; priority, lifetime, and previous-hash are V2 features; a
	/// bare payload stays at V0.
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
	pub fn build(self) -> Result<Vec<u8>, TightBeamError> {
		let body = OpaqueBody { body: OctetString::new(self.message.as_slice())? };

		let mut builder = FrameBuilder::<OpaqueBody>::from(self.effective_version())
			.with_id(self.id)
			.with_order(self.order)
			.with_message(body);

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
		Ok(frame.to_der()?)
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

/// The message-commitment preimage over `body_der` under `salt`
/// (`commit_digest`): the bare body DER for an empty salt, or
/// `len(salt) as u64 BE || salt || body DER` otherwise (length framing keeps
/// distinct `(salt, body)` pairs from colliding).
///
/// Hash this with any digest and install the result via
/// [`set_message_integrity`].
pub fn commitment_preimage(salt: impl AsRef<[u8]>, body_der: impl AsRef<[u8]>) -> Vec<u8> {
	let salt = salt.as_ref();
	let body_der = body_der.as_ref();
	if salt.is_empty() {
		return body_der.to_vec();
	}

	let mut buffer = Vec::with_capacity(8 + salt.len() + body_der.len());
	buffer.extend_from_slice(&(salt.len() as u64).to_be_bytes());
	buffer.extend_from_slice(salt);
	buffer.extend_from_slice(body_der);
	buffer
}

/// Decode a frame DER, apply `mutate`, and re-encode.
fn rewrite_frame(
	frame_der: impl AsRef<[u8]>,
	mutate: impl FnOnce(&mut Frame) -> Result<(), TightBeamError>,
) -> Result<Vec<u8>, TightBeamError> {
	let mut frame = Frame::from_der(frame_der.as_ref())?;
	mutate(&mut frame)?;
	Ok(frame.to_der()?)
}

/// Build a parameterless `AlgorithmIdentifier` from an OID.
fn algorithm(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid, parameters: None }
}

/// Install a message-integrity commitment: the digest of
/// [`commitment_preimage`] under the caller's algorithm (V2+ frames).
pub fn set_message_integrity(
	frame_der: impl AsRef<[u8]>,
	algorithm_oid: ObjectIdentifier,
	digest: impl AsRef<[u8]>,
) -> Result<Vec<u8>, TightBeamError> {
	let digest = OctetString::new(digest.as_ref())?;
	rewrite_frame(frame_der, |frame| {
		frame.metadata.integrity = Some(DigestInfo { algorithm: algorithm(algorithm_oid), digest });
		Ok(())
	})
}

/// Replace the frame body with `ciphertext` and record the confidentiality
/// info (V1+ frames): the caller's encryption algorithm OID, its DER-encoded
/// parameters (e.g. the nonce), and the content type of the plaintext
/// (defaults to `id-data`).
pub fn set_confidentiality(
	frame_der: impl AsRef<[u8]>,
	content_oid: Option<ObjectIdentifier>,
	algorithm_oid: ObjectIdentifier,
	parameters_der: Option<Vec<u8>>,
	ciphertext: Vec<u8>,
) -> Result<Vec<u8>, TightBeamError> {
	let parameters = match parameters_der {
		Some(der) => Some(Any::from_der(&der)?),
		None => None,
	};

	rewrite_frame(frame_der, move |frame| {
		frame.metadata.confidentiality = Some(EncryptedContentInfo {
			content_type: content_oid.unwrap_or(DATA),
			content_enc_alg: AlgorithmIdentifierOwned { oid: algorithm_oid, parameters },
			encrypted_content: None,
		});
		frame.message = ciphertext;
		Ok(())
	})
}

/// The frame-integrity preimage: the envelope (version + metadata, message
/// excluded), encoded exactly as tightbeam's witness scaffold. Borrowing the
/// frame's own derived encoders keeps the preimage from drifting.
struct WitnessScaffold<'a> {
	version: &'a Version,
	metadata: &'a tightbeam::Metadata,
}

impl FixedTag for WitnessScaffold<'_> {
	const TAG: Tag = Tag::Sequence;
}

impl EncodeValue for WitnessScaffold<'_> {
	fn value_len(&self) -> tightbeam::der::Result<Length> {
		self.version.encoded_len()? + self.metadata.encoded_len()?
	}

	fn encode_value(&self, writer: &mut impl Writer) -> tightbeam::der::Result<()> {
		self.version.encode(writer)?;
		self.metadata.encode(writer)
	}
}

/// The frame-integrity (witness) preimage bytes for a frame: hash them with
/// any digest and install the result via [`attach_witness`].
///
/// Call after all metadata mutations ([`set_message_integrity`],
/// [`set_confidentiality`]): the witness covers the final envelope.
pub fn witness_input(frame_der: impl AsRef<[u8]>) -> Result<Vec<u8>, TightBeamError> {
	let frame = Frame::from_der(frame_der.as_ref())?;
	let scaffold = WitnessScaffold { version: &frame.version, metadata: &frame.metadata };
	Ok(scaffold.to_der()?)
}

/// Install a frame-integrity witness: the digest of [`witness_input`] under
/// the caller's algorithm (V2+ frames).
pub fn attach_witness(
	frame_der: impl AsRef<[u8]>,
	algorithm_oid: ObjectIdentifier,
	digest: impl AsRef<[u8]>,
) -> Result<Vec<u8>, TightBeamError> {
	let digest = OctetString::new(digest.as_ref())?;
	rewrite_frame(frame_der, |frame| {
		frame.integrity = Some(DigestInfo { algorithm: algorithm(algorithm_oid), digest });
		Ok(())
	})
}

/// The to-be-signed bytes of a frame (everything but the signature field).
/// Sign them with any scheme and install the result via [`attach_signature`].
///
/// Call after [`attach_witness`]: the signature covers the witness.
pub fn tbs_bytes(frame_der: impl AsRef<[u8]>) -> Result<Vec<u8>, TightBeamError> {
	let frame = Frame::from_der(frame_der.as_ref())?;
	frame.to_tbs()
}

/// Attach a detached signature over [`tbs_bytes`] to an unsigned frame (V1+
/// frames), identified by the caller's signature and digest algorithm OIDs
/// plus a subject-key-identifier octet string naming the signer.
pub fn attach_signature(
	frame_der: impl AsRef<[u8]>,
	signature: impl AsRef<[u8]>,
	signature_algorithm_oid: ObjectIdentifier,
	digest_algorithm_oid: ObjectIdentifier,
	signer_key_id: impl AsRef<[u8]>,
) -> Result<Vec<u8>, TightBeamError> {
	let sid = SignerIdentifier::SubjectKeyIdentifier(OctetString::new(signer_key_id.as_ref())?.into());
	let signer_info = SignerInfo::from_parts(
		signature.as_ref(),
		algorithm(signature_algorithm_oid),
		algorithm(digest_algorithm_oid),
		sid,
	)?;

	rewrite_frame(frame_der, |frame| {
		frame.nonrepudiation = Some(signer_info);
		Ok(())
	})
}

/// Decoded view of a frame: its body, metadata, and the carried security
/// infos (algorithm OIDs + artifacts) a caller needs to verify with its own
/// cryptography.
pub struct FrameSummary {
	/// Protocol version ordinal (`V0` -> 0, ..., `V3` -> 3).
	pub version: u8,
	/// Opaque message identifier.
	pub id: Vec<u8>,
	/// Monotonic order (Unix seconds).
	pub order: u64,
	/// Opaque message body: the decoded payload when cleartext, the raw
	/// ciphertext when confidential.
	pub body: Vec<u8>,
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
	/// Message-commitment digest algorithm OID, when committed.
	pub message_integrity_algorithm_oid: Option<String>,
	/// Message-commitment digest octets, when committed.
	pub message_integrity_digest: Option<Vec<u8>>,
	/// Witness digest algorithm OID, when witnessed.
	pub frame_integrity_algorithm_oid: Option<String>,
	/// Witness digest octets, when witnessed.
	pub frame_integrity_digest: Option<Vec<u8>>,
	/// Body-encryption algorithm OID, when confidential.
	pub confidentiality_algorithm_oid: Option<String>,
	/// Body-encryption algorithm parameters DER (e.g. the nonce), when
	/// confidential and present.
	pub confidentiality_parameters_der: Option<Vec<u8>>,
	/// Signature algorithm OID, when signed.
	pub signature_algorithm_oid: Option<String>,
	/// Signature digest algorithm OID, when signed.
	pub signature_digest_algorithm_oid: Option<String>,
	/// Raw signature octets, when signed.
	pub signature: Option<Vec<u8>>,
}

/// Decode a frame DER into a [`FrameSummary`].
///
/// No cryptography runs; a cleartext body is the decoded payload, an
/// encrypted body is surfaced as ciphertext alongside its confidentiality
/// info.
pub fn inspect_frame(frame_der: impl AsRef<[u8]>) -> Result<FrameSummary, TightBeamError> {
	let frame = Frame::from_der(frame_der.as_ref())?;
	let metadata = &frame.metadata;

	// An encrypted body is ciphertext, not an OpaqueBody encoding; surface
	// it as-is for the caller's decryptor.
	let confidentiality = metadata.confidentiality.as_ref();
	let body = if confidentiality.is_some() {
		frame.message.clone()
	} else {
		OpaqueBody::from_der(&frame.message)?.body.into_bytes()
	};

	let confidentiality_parameters_der = confidentiality
		.and_then(|info| info.content_enc_alg.parameters.as_ref())
		.map(Encode::to_der)
		.transpose()?;

	Ok(FrameSummary {
		version: frame.version as u8,
		id: metadata.id.clone(),
		order: metadata.order,
		body,
		priority: metadata.priority.map(|priority| priority as u8),
		lifetime: metadata.lifetime,
		previous_hash_algorithm_oid: metadata.previous_frame.as_ref().map(|digest| digest.algorithm.oid.to_string()),
		previous_hash_digest: metadata.previous_frame.as_ref().map(|digest| digest.digest.as_bytes().to_vec()),
		matrix_n: metadata.matrix.as_ref().map(|matrix| matrix.n),
		matrix_data: metadata.matrix.as_ref().map(|matrix| matrix.data.clone()),
		message_integrity_algorithm_oid: metadata.integrity.as_ref().map(|info| info.algorithm.oid.to_string()),
		message_integrity_digest: metadata.integrity.as_ref().map(|info| info.digest.as_bytes().to_vec()),
		frame_integrity_algorithm_oid: frame.integrity.as_ref().map(|info| info.algorithm.oid.to_string()),
		frame_integrity_digest: frame.integrity.as_ref().map(|info| info.digest.as_bytes().to_vec()),
		confidentiality_algorithm_oid: confidentiality.map(|info| info.content_enc_alg.oid.to_string()),
		confidentiality_parameters_der,
		signature_algorithm_oid: frame
			.nonrepudiation
			.as_ref()
			.map(|info| info.signature_algorithm.oid.to_string()),
		signature_digest_algorithm_oid: frame.nonrepudiation.as_ref().map(|info| info.digest_alg.oid.to_string()),
		signature: frame.nonrepudiation.as_ref().map(|info| info.signature.as_bytes().to_vec()),
	})
}

// ---------------------------------------------------------------------------
// Tightbeam profile primitives (SHA3-256 / secp256k1 / AES-256-GCM / ECIES).
// Conveniences only: the structure path above accepts any algorithm.
// ---------------------------------------------------------------------------

/// SHA3-256 digest of `data` - the profile hasher.
pub fn sha3_256_digest(data: impl AsRef<[u8]>) -> Vec<u8> {
	Sha3_256::digest(data.as_ref()).to_vec()
}

/// Derive the SEC1 compressed public key for a raw 32-byte secp256k1 signing
/// key, for verifying frames signed with that key.
pub fn derive_public_key(key_bytes: [u8; 32]) -> Result<Vec<u8>, TightBeamError> {
	let key = Secp256k1SigningKey::from_bytes(&key_bytes.into())?;
	Ok(key.verifying_key().to_sec1_bytes().into_vec())
}

/// Sign the SHA3-256 digest of `tbs` with a raw 32-byte secp256k1 signing
/// key, returning the raw 64-byte `r || s` signature accepted by
/// [`attach_signature`] - the profile signer.
pub fn sign_tbs(key_bytes: [u8; 32], tbs: impl AsRef<[u8]>) -> Result<Vec<u8>, TightBeamError> {
	let key = Secp256k1SigningKey::from_bytes(&key_bytes.into())?;
	let signature: Secp256k1Signature = sign_canonical::<Sha3_256, _>(&key, tbs.as_ref())?;
	Ok(signature.to_bytes().to_vec())
}

/// The subject-key-identifier octets naming a secp256k1 signer (the SHA3-256
/// digest of its SPKI encoding, truncated to 20 octets).
pub fn profile_signer_id(public_key_sec1: impl AsRef<[u8]>) -> Result<Vec<u8>, TightBeamError> {
	let key = Secp256k1VerifyingKey::from_sec1_bytes(public_key_sec1.as_ref())?;
	match secp256k1_signer_identifier(&key)? {
		SignerIdentifier::SubjectKeyIdentifier(skid) => Ok(skid.0.as_bytes().to_vec()),
		SignerIdentifier::IssuerAndSerialNumber(_) => Err(TightBeamError::SignatureEncodingError),
	}
}

/// Verify a frame's non-repudiation signature against a SEC1-encoded
/// secp256k1 public key under the profile scheme (ECDSA over SHA3-256).
///
/// `Ok(())` means the signature is valid; a missing signature, an algorithm
/// mismatch, or a bad signature are all errors. Frames signed under other
/// schemes verify caller-side from [`tbs_bytes`] and the carried signature.
pub fn verify_signature(frame_der: impl AsRef<[u8]>, public_key_sec1: impl AsRef<[u8]>) -> Result<(), TightBeamError> {
	let frame = Frame::from_der(frame_der.as_ref())?;
	let key = Secp256k1VerifyingKey::from_sec1_bytes(public_key_sec1.as_ref())?;
	frame.verify::<Secp256k1Signature, Sha3_256>(&key)
}

/// A sealed body produced by a profile encryptor: the pieces
/// [`set_confidentiality`] installs.
pub struct SealedBody {
	/// The encryption algorithm OID (dotted form).
	pub algorithm_oid: String,
	/// The algorithm parameters DER (e.g. the nonce), when the scheme has
	/// any.
	pub parameters_der: Option<Vec<u8>>,
	/// The ciphertext replacing the frame body.
	pub ciphertext: Vec<u8>,
}

/// Split an [`EncryptedContentInfo`] into the [`SealedBody`] pieces.
fn sealed_body(mut info: EncryptedContentInfo) -> Result<SealedBody, TightBeamError> {
	let ciphertext = info
		.encrypted_content
		.take()
		.ok_or(TightBeamError::MissingEncryptionInfo)?
		.into_bytes();
	let parameters_der = info.content_enc_alg.parameters.as_ref().map(Encode::to_der).transpose()?;

	Ok(SealedBody { algorithm_oid: info.content_enc_alg.oid.to_string(), parameters_der, ciphertext })
}

/// Rebuild the [`EncryptedContentInfo`] a profile decryptor opens.
fn encrypted_info(
	algorithm_oid: ObjectIdentifier,
	parameters_der: Option<Vec<u8>>,
	ciphertext: Vec<u8>,
) -> Result<EncryptedContentInfo, TightBeamError> {
	let parameters = match parameters_der {
		Some(der) => Some(Any::from_der(&der)?),
		None => None,
	};

	Ok(EncryptedContentInfo {
		content_type: DATA,
		content_enc_alg: AlgorithmIdentifierOwned { oid: algorithm_oid, parameters },
		encrypted_content: Some(OctetString::new(ciphertext)?),
	})
}

/// Seal `plaintext` (a [`body_preimage`]) under AES-256-GCM with a 32-byte
/// key - the profile symmetric encryptor.
pub fn seal_aes_256_gcm(key: impl AsRef<[u8]>, plaintext: impl AsRef<[u8]>) -> Result<SealedBody, TightBeamError> {
	let cipher = Aes256Gcm::new_from_slice(key.as_ref())?;
	let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
	let info = Encryptor::<Aes256GcmOidMarker>::encrypt_content(&cipher, plaintext.as_ref(), nonce, None)?;
	sealed_body(info)
}

/// Open an AES-256-GCM sealed body with the shared 32-byte key, returning
/// the plaintext body DER (decode it with [`decode_body`]).
pub fn open_aes_256_gcm(
	key: impl AsRef<[u8]>,
	parameters_der: Option<Vec<u8>>,
	ciphertext: Vec<u8>,
) -> Result<Vec<u8>, TightBeamError> {
	let cipher = Aes256Gcm::new_from_slice(key.as_ref())?;
	let info = encrypted_info(tightbeam::oids::AES_256_GCM, parameters_der, ciphertext)?;
	Ok(cipher.decrypt_content(&info)?.to_insecure()?.to_vec())
}

/// Seal `plaintext` (a [`body_preimage`]) to the holder of the secp256k1 key
/// behind this SEC1 public key - the profile asymmetric encryptor (ECIES:
/// secp256k1 + HKDF-SHA3-256 + AES-256-GCM).
pub fn seal_ecies_secp256k1(
	recipient_public_key: impl AsRef<[u8]>,
	plaintext: impl AsRef<[u8]>,
) -> Result<SealedBody, TightBeamError> {
	let encryptor = EciesEncryptor::from_bytes(recipient_public_key.as_ref())?;
	let info = encryptor.encrypt_content(plaintext.as_ref(), [], None)?;
	sealed_body(info)
}

/// Open an ECIES sealed body with the raw 32-byte recipient secret key,
/// returning the plaintext body DER (decode it with [`decode_body`]).
pub fn open_ecies_secp256k1(
	secret_key: impl AsRef<[u8]>,
	parameters_der: Option<Vec<u8>>,
	ciphertext: Vec<u8>,
) -> Result<Vec<u8>, TightBeamError> {
	let decryptor = EciesDecryptor::new(SecretKey::from_slice(secret_key.as_ref())?);
	let info = encrypted_info(EciesSecp256k1Oid::OID, parameters_der, ciphertext)?;
	Ok(decryptor.decrypt_content(&info)?.to_insecure()?.to_vec())
}

/// Marker binding the profile AEAD OID for the generic [`Encryptor`] call.
struct Aes256GcmOidMarker;

impl AssociatedOid for Aes256GcmOidMarker {
	const OID: ObjectIdentifier = tightbeam::oids::AES_256_GCM;
}

#[cfg(test)]
mod tests {
	use der::asn1::OctetString;
	use tightbeam::crypto::aead::{Aes256Gcm, KeyInit};
	use tightbeam::crypto::commitment::Opening;
	use tightbeam::crypto::hash::Sha3_256;
	use tightbeam::crypto::secret::ToInsecure;
	use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
	use tightbeam::der::oid::AssociatedOid;
	use tightbeam::der::Decode;
	use tightbeam::matrix::MatrixDyn;
	use tightbeam::oids::{AES_256_GCM, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256};
	use tightbeam::{
		AlgorithmIdentifierOwned, DigestInfo, Frame, IntegrityVerdict, MessagePriority, ObjectIdentifier, Version,
	};

	use super::{
		attach_signature, attach_witness, body_preimage, commitment_preimage, decode_body, derive_public_key,
		inspect_frame, open_aes_256_gcm, open_ecies_secp256k1, profile_signer_id, seal_aes_256_gcm,
		seal_ecies_secp256k1, set_confidentiality, set_message_integrity, sha3_256_digest, sign_tbs, tbs_bytes,
		verify_signature, witness_input, FrameConfig, OpaqueBody,
	};

	type TestResult = core::result::Result<(), Box<dyn core::error::Error>>;
	type AnyResult<T> = core::result::Result<T, Box<dyn core::error::Error>>;

	fn sample_message() -> Vec<u8> {
		b"opaque-message-body".to_vec()
	}

	fn signing_key() -> AnyResult<Secp256k1SigningKey> {
		Ok(Secp256k1SigningKey::from_bytes(&[1u8; 32].into())?)
	}

	fn base_config(id: &[u8], order: u64) -> FrameConfig {
		FrameConfig { id: id.to_vec(), order, message: sample_message(), ..Default::default() }
	}

	fn seal_frame(id: &[u8], order: u64) -> AnyResult<Vec<u8>> {
		Ok(base_config(id, order).build()?)
	}

	fn open_frame(frame_der: impl AsRef<[u8]>) -> AnyResult<Vec<u8>> {
		let frame = Frame::from_der(frame_der.as_ref())?;
		Ok(decode_body(&frame.message)?)
	}

	fn frame_from(config: FrameConfig) -> AnyResult<Frame> {
		Ok(Frame::from_der(&config.build()?)?)
	}

	/// Drive the full caller-side pipeline with the profile primitives, the
	/// way the TS builder does: commit, witness, then sign detached.
	fn signed_frame(id: &[u8], order: u64, key_bytes: [u8; 32]) -> AnyResult<Vec<u8>> {
		let config = FrameConfig { version: Some(Version::V2), ..base_config(id, order) };
		let der = config.build()?;

		let commitment = sha3_256_digest(commitment_preimage([], body_preimage(sample_message())?));
		let der = set_message_integrity(&der, HASH_SHA3_256, commitment)?;

		let witness = sha3_256_digest(witness_input(&der)?);
		let der = attach_witness(&der, HASH_SHA3_256, witness)?;

		let signature = sign_tbs(key_bytes, tbs_bytes(&der)?)?;
		let public_key = derive_public_key(key_bytes)?;
		let signer_id = profile_signer_id(&public_key)?;

		Ok(attach_signature(
			&der,
			signature,
			SIGNER_ECDSA_WITH_SHA3_256,
			HASH_SHA3_256,
			signer_id,
		)?)
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
		assert_eq!(frame.metadata.id, b"id-9");
		assert_eq!(frame.metadata.order, 42);
		assert!(frame.integrity.is_none());
		assert!(frame.nonrepudiation.is_none());
		Ok(())
	}

	#[test]
	fn config_defaults_to_v0_cleartext() -> TestResult {
		let frame = frame_from(base_config(b"plain", 1))?;
		assert_eq!(frame.version, Version::V0);
		assert!(frame.nonrepudiation.is_none());
		Ok(())
	}

	#[test]
	fn config_applies_v2_metadata() -> TestResult {
		let config = FrameConfig {
			priority: Some(MessagePriority::LowLatency),
			lifetime: Some(60),
			..base_config(b"meta", 9)
		};

		let frame = frame_from(config)?;
		assert_eq!(frame.version, Version::V2);
		assert_eq!(frame.metadata.priority, Some(MessagePriority::LowLatency));
		assert_eq!(frame.metadata.lifetime, Some(60));
		Ok(())
	}

	#[test]
	fn config_matrix_requires_v3() -> TestResult {
		let matrix = MatrixDyn::from_row_major(2, vec![0, 1, 1, 0]).ok_or("matrix dims")?;
		let config = FrameConfig { matrix: Some(matrix), ..base_config(b"matrix", 1) };

		let frame = frame_from(config)?;
		assert_eq!(frame.version, Version::V3);

		let recovered_matrix = frame.metadata.matrix.as_ref().ok_or("matrix present")?;
		assert_eq!(recovered_matrix.n, 2);
		Ok(())
	}

	#[test]
	fn config_pins_explicit_version() -> TestResult {
		let config = FrameConfig { version: Some(Version::V2), ..base_config(b"pinned", 3) };
		let frame = frame_from(config)?;
		assert_eq!(frame.version, Version::V2);
		Ok(())
	}

	#[test]
	fn inspect_reports_cleartext_metadata() -> TestResult {
		let frame_der = seal_frame(b"view-1", 11)?;
		let summary = inspect_frame(&frame_der)?;
		assert_eq!(summary.version, 0);
		assert_eq!(summary.id, b"view-1");
		assert_eq!(summary.order, 11);
		assert_eq!(summary.body, sample_message());
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
			..base_config(b"rich", 21)
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
		assert_eq!(summary.previous_hash_algorithm_oid, None);
		assert_eq!(summary.previous_hash_digest, None);
		assert_eq!(summary.matrix_n, None);
		assert_eq!(summary.matrix_data, None);
		Ok(())
	}

	#[test]
	fn signed_frame_carries_security_infos() -> TestResult {
		let summary = inspect_frame(signed_frame(b"signed-1", 5, [1u8; 32])?)?;
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
		let frame_der = signed_frame(b"signed-2", 5, [1u8; 32])?;
		assert_eq!(open_frame(&frame_der)?, sample_message());
		Ok(())
	}

	#[test]
	fn signed_frame_verifies_with_tightbeam() -> TestResult {
		let key = signing_key()?;
		let verifying_key = *key.verifying_key();
		let frame = Frame::from_der(&signed_frame(b"signed-3", 5, [1u8; 32])?)?;

		frame.verify::<Secp256k1Signature, Sha3_256>(&verifying_key)?;
		Ok(())
	}

	#[test]
	fn verify_signature_accepts_signer_key() -> TestResult {
		let public_key = signing_key()?.verifying_key().to_sec1_bytes();
		let frame_der = signed_frame(b"sig-ok", 1, [1u8; 32])?;

		verify_signature(&frame_der, &public_key)?;
		Ok(())
	}

	#[test]
	fn derived_public_key_verifies_signature() -> TestResult {
		let secret = [1u8; 32];
		let public_key = derive_public_key(secret)?;
		let frame_der = signed_frame(b"sig-derived", 1, secret)?;

		verify_signature(&frame_der, &public_key)?;
		Ok(())
	}

	#[test]
	fn verify_signature_rejects_wrong_key() -> TestResult {
		let frame_der = signed_frame(b"sig-bad", 1, [1u8; 32])?;
		let other = Secp256k1SigningKey::from_bytes(&[2u8; 32].into())?;
		let public_key = other.verifying_key().to_sec1_bytes();

		assert!(verify_signature(&frame_der, &public_key).is_err());
		Ok(())
	}

	#[test]
	fn verify_signature_rejects_unsigned_frame() -> TestResult {
		let frame_der = seal_frame(b"unsigned", 1)?;
		let public_key = signing_key()?.verifying_key().to_sec1_bytes();
		assert!(verify_signature(&frame_der, &public_key).is_err());
		Ok(())
	}

	/// The structure path is algorithm-agnostic, so garbage bytes attach;
	/// verification is where they must fail.
	#[test]
	fn garbage_signature_attaches_but_fails_verification() -> TestResult {
		let frame_der = seal_frame(b"junk", 1)?;
		let public_key = signing_key()?.verifying_key().to_sec1_bytes();
		let signer_id = profile_signer_id(&public_key)?;

		let signed = attach_signature(&frame_der, [0u8; 64], SIGNER_ECDSA_WITH_SHA3_256, HASH_SHA3_256, signer_id)?;
		assert!(verify_signature(&signed, &public_key).is_err());
		Ok(())
	}

	/// The caller-side commitment (preimage + digest + install) must satisfy
	/// tightbeam's own commitment verdict: pins the preimage framing.
	#[test]
	fn caller_side_commitment_verifies_with_tightbeam() -> TestResult {
		let salt = b"pepper";
		let der = FrameConfig { version: Some(Version::V2), ..base_config(b"mi", 1) }.build()?;

		let commitment = sha3_256_digest(commitment_preimage(salt, body_preimage(sample_message())?));
		let der = set_message_integrity(&der, HASH_SHA3_256, commitment)?;

		let frame = Frame::from_der(&der)?;
		let body = OpaqueBody::from_der(&frame.message)?;
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
		let der = FrameConfig { version: Some(Version::V2), ..base_config(b"fi", 1) }.build()?;

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
		let der = FrameConfig { version: Some(Version::V2), ..base_config(b"fi-bad", 1) }.build()?;
		let der = attach_witness(&der, HASH_SHA3_256, [0u8; 32])?;

		let frame = Frame::from_der(&der)?;
		assert!(matches!(
			frame.frame_integrity_verdict::<Sha3_256>()?,
			IntegrityVerdict::Mismatch
		));
		Ok(())
	}

	/// A caller-sealed AES-256-GCM body must open with tightbeam's own
	/// decryptor: pins the EncryptedContentInfo layout.
	#[test]
	fn caller_side_aead_seal_opens_with_tightbeam() -> TestResult {
		let key = [0x42u8; 32];
		let der = FrameConfig { version: Some(Version::V1), ..base_config(b"sealed", 8) }.build()?;

		let sealed = seal_aes_256_gcm(key, body_preimage(sample_message())?)?;
		assert_eq!(sealed.algorithm_oid, AES_256_GCM.to_string());

		let der = set_confidentiality(
			&der,
			None,
			sealed.algorithm_oid.parse::<ObjectIdentifier>()?,
			sealed.parameters_der,
			sealed.ciphertext,
		)?;

		let summary = inspect_frame(&der)?;
		assert_eq!(summary.confidentiality_algorithm_oid, Some(AES_256_GCM.to_string()));
		assert_ne!(summary.body, sample_message());

		let cipher = Aes256Gcm::new_from_slice(&key)?;
		let frame = Frame::from_der(&der)?;
		let plaintext = frame.decrypt_bytes(&cipher)?.to_insecure()?;
		assert_eq!(decode_body(&plaintext)?, sample_message());
		Ok(())
	}

	#[test]
	fn aead_seal_open_round_trips() -> TestResult {
		let key = [0x42u8; 32];
		let preimage = body_preimage(sample_message())?;

		let sealed = seal_aes_256_gcm(key, &preimage)?;
		let opened = open_aes_256_gcm(key, sealed.parameters_der, sealed.ciphertext)?;
		assert_eq!(opened, preimage);
		Ok(())
	}

	#[test]
	fn aead_open_rejects_wrong_key() -> TestResult {
		let sealed = seal_aes_256_gcm([0x42u8; 32], body_preimage(sample_message())?)?;
		assert!(open_aes_256_gcm([0x43u8; 32], sealed.parameters_der, sealed.ciphertext).is_err());
		Ok(())
	}

	#[test]
	fn ecies_seal_open_round_trips() -> TestResult {
		let recipient_public = signing_key()?.verifying_key().to_sec1_bytes().to_vec();
		let preimage = body_preimage(sample_message())?;

		let sealed = seal_ecies_secp256k1(&recipient_public, &preimage)?;
		assert_eq!(sealed.algorithm_oid, "1.3.132.1.12.0");

		let opened = open_ecies_secp256k1([1u8; 32], sealed.parameters_der, sealed.ciphertext)?;
		assert_eq!(opened, preimage);
		Ok(())
	}

	#[test]
	fn ecies_open_rejects_wrong_secret() -> TestResult {
		let recipient_public = signing_key()?.verifying_key().to_sec1_bytes().to_vec();
		let sealed = seal_ecies_secp256k1(&recipient_public, body_preimage(sample_message())?)?;
		assert!(open_ecies_secp256k1([2u8; 32], sealed.parameters_der, sealed.ciphertext).is_err());
		Ok(())
	}

	#[test]
	fn profile_oids() {
		assert_eq!(HASH_SHA3_256.to_string(), "2.16.840.1.101.3.4.2.8");
		assert_eq!(SIGNER_ECDSA_WITH_SHA3_256.to_string(), "2.16.840.1.101.3.4.3.10");
		assert_eq!(AES_256_GCM.to_string(), "2.16.840.1.101.3.4.1.46");
		assert_eq!(super::EciesSecp256k1Oid::OID.to_string(), "1.3.132.1.12.0");
	}

	#[test]
	fn commitment_preimage_frames_nonempty_salt() {
		let body = vec![0xBBu8; 4];
		assert_eq!(commitment_preimage([], &body), body);

		let framed = commitment_preimage(b"salt", &body);
		assert_eq!(&framed[..8], &4u64.to_be_bytes());
		assert_eq!(&framed[8..12], b"salt");
		assert_eq!(&framed[12..], body.as_slice());
	}

	#[test]
	fn body_preimage_round_trips_through_decode() -> TestResult {
		let preimage = body_preimage(sample_message())?;
		assert_eq!(decode_body(preimage)?, sample_message());
		Ok(())
	}
}
