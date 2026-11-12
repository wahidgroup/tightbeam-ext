//! Frame assembly and structural security operations over opaque message bytes.

use core::time::Duration;
use std::collections::BTreeSet;
use std::sync::Arc;

use tightbeam::asn1::{AuthEnvelopedData, GatedField, ObjectIdentifier, WireDer};
use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::clock::UnixMillis;
use tightbeam::cms::compressed_data::CompressedData;
use tightbeam::cms::content_info::CmsVersion;
use tightbeam::cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier, SignerInfo};
use tightbeam::core::IntegrityVerdict;
use tightbeam::crypto::aead::{Aes256GcmOid, DecryptContent, Encryptor};
use tightbeam::crypto::cms::{BareKemKey, KemRecipient};
use tightbeam::crypto::commitment::CommitmentSalt;
use tightbeam::crypto::hash::ConstantTimeDigest;
use tightbeam::crypto::hpke::{HpkeDecryptor, HpkeEncryptor};
use tightbeam::crypto::k256::{PublicKey, Secp256k1};
use tightbeam::crypto::key::{Aes256GcmKeyProvider, DiffieHellman, Secp256k1KeyProvider};
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey};
use tightbeam::crypto::sign::{CmsSigner, SignedContent, SignerInfoDraft};
use tightbeam::crypto::x509::utils::Skid;
use tightbeam::der::asn1::OctetString;
use tightbeam::der::{Any, Decode, Encode};
use tightbeam::matrix::MatrixDyn;
use tightbeam::oids::DATA;
use tightbeam::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned};
use tightbeam::{DigestInfo, Errorizable, Frame, MessagePriority, Opaque, TightBeamError, Version, ZeroizingBytes};

/// A value that a build type refuses at construction.
///
/// The variant name is the `code` that a JavaScript caller reads.
///
/// # Examples
///
/// ```
/// use tightbeam::oids::HASH_SHA3_256;
/// use tightbeam_ws_wasm::build::{BuildRefusal, NamedDigest};
///
/// let refused = NamedDigest::new(HASH_SHA3_256, Vec::new());
/// assert!(matches!(refused, Err(BuildRefusal::EmptyDigest)));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Errorizable)]
pub enum BuildRefusal {
	/// A digest holds no octets, so it commits to nothing.
	#[error("a digest must hold at least one octet")]
	EmptyDigest,
	/// A signer key identifier holds no octets, so it names no certificate.
	#[error("a signer key identifier must name the certificate of the key")]
	EmptySignerId,
	/// The frame builds at another version than the caller asserted.
	#[error("the frame builds as {built:?}, not the asserted {asserted:?}")]
	VersionMismatch {
		/// The version the caller asserted.
		asserted: Version,
		/// The version the frame builds at.
		built: Version,
	},
}

/// A build or decode step that the engine refuses: a rule of this crate, or
/// an error of tightbeam.
#[derive(Debug, Errorizable)]
pub enum StepError {
	/// A rule of this crate refuses the value.
	#[error("{0}")]
	#[from]
	Refused(BuildRefusal),
	/// tightbeam refuses the step.
	#[error("{0}")]
	#[from]
	Engine(TightBeamError),
}

impl From<tightbeam::der::Error> for StepError {
	fn from(error: tightbeam::der::Error) -> Self {
		Self::Engine(TightBeamError::from(error))
	}
}

/// A security field that a caller installs after the structural build.
///
/// A [`FrameConfig`] declares each one in advance, so the version floor
/// counts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityField {
	/// The message commitment in `Metadata.integrity`.
	MessageIntegrity,
	/// The envelope that seals the body, in `Metadata.confidentiality`.
	Confidentiality,
	/// The witness in `Frame.integrity`.
	FrameIntegrity,
	/// The signature in `Frame.nonrepudiation`.
	Nonrepudiation,
}

/// The version-gated field that each security field is.
impl From<SecurityField> for GatedField {
	fn from(field: SecurityField) -> Self {
		match field {
			SecurityField::MessageIntegrity => Self::MessageIntegrity,
			SecurityField::Confidentiality => Self::Confidentiality,
			SecurityField::FrameIntegrity => Self::FrameIntegrity,
			SecurityField::Nonrepudiation => Self::Nonrepudiation,
		}
	}
}

/// The security fields that a build declares, each one at most once.
///
/// # Examples
///
/// ```
/// use tightbeam::Version;
/// use tightbeam_ws_wasm::build::{SecurityField, SecurityFields};
///
/// let mut declared = SecurityFields::default();
/// assert_eq!(declared.since(), Version::V0);
///
/// declared.insert(SecurityField::Nonrepudiation);
/// declared.insert(SecurityField::Nonrepudiation);
/// assert_eq!(declared.since(), Version::V1);
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecurityFields(BTreeSet<SecurityField>);

impl SecurityFields {
	/// Declare `field`. A field declared twice stays declared once.
	pub fn insert(&mut self, field: SecurityField) {
		self.0.insert(field);
	}

	/// The first version that carries every declared field, the latest
	/// [`GatedField::since`] among them, or V0 when none is declared.
	#[must_use]
	pub fn since(&self) -> Version {
		let floors = self.gated().map(GatedField::since);
		floors.fold(Version::V0, Version::later)
	}

	/// The gated field of each declared field.
	fn gated(&self) -> impl Iterator<Item = GatedField> + '_ {
		self.0.iter().copied().map(GatedField::from)
	}
}

/// Structural frame specification: metadata only, no cryptography.
///
/// The [`FrameAssembly`] steps install the security artifacts afterwards, and
/// [`declare`](Self::declare) names each one in advance so the version floor
/// counts it.
///
/// # Examples
///
/// ```
/// use tightbeam::Version;
/// use tightbeam_ws_wasm::build::{BodyDer, FrameConfig, SecurityField};
///
/// let body = BodyDer::opaque(*b"body")?;
/// let mut config = FrameConfig::default();
/// config.with_id(*b"id").with_message(body).declare(SecurityField::FrameIntegrity);
///
/// let summary = config.assemble()?.summary()?;
/// assert_eq!(summary.version, Version::V1);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Default)]
pub struct FrameConfig {
	version: Option<Version>,
	asserted: Option<Version>,
	declared: SecurityFields,
	id: Option<Vec<u8>>,
	order: Option<u64>,
	message: Option<BodyDer>,
	priority: Option<MessagePriority>,
	lifetime: Option<u64>,
	previous_hash: Option<NamedDigest>,
	matrix: Option<MatrixDyn>,
}

impl FrameConfig {
	/// Pin the protocol version. Without a pin, the build uses the floor of
	/// the structural and the declared fields.
	pub fn with_version(&mut self, version: Version) -> &mut Self {
		self.version = Some(version);
		self
	}

	/// Assert the version the frame builds at, so the assembly refuses
	/// another version before any security step runs.
	pub fn assert_version(&mut self, version: Version) -> &mut Self {
		self.asserted = Some(version);
		self
	}

	/// Set the opaque message identifier. A frame without one is refused at
	/// the assembly, as tightbeam refuses it.
	pub fn with_id(&mut self, id: impl Into<Vec<u8>>) -> &mut Self {
		self.id = Some(id.into());
		self
	}

	/// Set the frame order stamp.
	///
	/// The value is protocol-opaque. Any monotonic scheme works, such as a
	/// Unix timestamp or a dense per-channel counter. Without one, the build
	/// stamps the current Unix time in seconds.
	pub fn with_order(&mut self, order: u64) -> &mut Self {
		self.order = Some(order);
		self
	}

	/// Set the frame body: the DER of any `Message` encoding the peer
	/// expects. Callers without an ASN.1 schema wrap raw payload bytes with
	/// [`BodyDer::opaque`], the opaque profile body. Without one, the frame
	/// carries the empty opaque body.
	pub fn with_message(&mut self, body: BodyDer) -> &mut Self {
		self.message = Some(body);
		self
	}

	/// Set the message priority (V2+).
	pub fn with_priority(&mut self, priority: MessagePriority) -> &mut Self {
		self.priority = Some(priority);
		self
	}

	/// Set the time-to-live in seconds (V2+).
	pub fn with_lifetime(&mut self, seconds: u64) -> &mut Self {
		self.lifetime = Some(seconds);
		self
	}

	/// Link the frame to a parent by its content digest (V2+).
	pub fn with_previous_hash(&mut self, parent: NamedDigest) -> &mut Self {
		self.previous_hash = Some(parent);
		self
	}

	/// Set the N×N control matrix (V3+).
	pub fn with_matrix(&mut self, matrix: MatrixDyn) -> &mut Self {
		self.matrix = Some(matrix);
		self
	}

	/// Declare that the caller installs `field` after the build, so the
	/// version floor counts it.
	pub fn declare(&mut self, field: SecurityField) -> &mut Self {
		self.declared.insert(field);
		self
	}

	/// The gated fields that the structural fields of this config set.
	fn structural_fields(&self) -> impl Iterator<Item = GatedField> {
		let structural = [
			self.priority.as_ref().map(|_| GatedField::Priority),
			self.lifetime.map(|_| GatedField::Lifetime),
			self.previous_hash.as_ref().map(|_| GatedField::PreviousFrame),
			self.matrix.as_ref().map(|_| GatedField::Matrix),
		];

		structural.into_iter().flatten()
	}

	/// The version the frame carries: the pinned version, or the floor of its
	/// gated fields, which is the latest [`GatedField::since`] among them.
	///
	/// - A frame with no gated field stays at V0.
	/// - tightbeam refuses a structural field that a pin forbids as it builds.
	/// - A declared field installs after the build, so this check refuses a declared field before any
	///   security step runs.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnsupportedField`] -- the pinned version is below
	///   the floor of a declared field.
	fn effective_version(&self) -> Result<Version, TightBeamError> {
		let Some(version) = self.version else {
			let structural = self.structural_fields().map(GatedField::since);
			let floor = structural.fold(self.declared.since(), Version::later);
			return Ok(floor);
		};

		let refused = self.declared.gated().find(|field| !version.allows(*field));
		if let Some(field) = refused {
			return Err(TightBeamError::UnsupportedField { field, version });
		}

		Ok(version)
	}

	/// The version the frame builds at, once it matches the asserted one.
	///
	/// # Errors
	///
	/// - The errors of [`Self::effective_version`].
	/// - [`BuildRefusal::VersionMismatch`] -- the frame builds at another
	///   version than [`Self::assert_version`] named.
	fn checked_version(&self) -> Result<Version, StepError> {
		let built = self.effective_version()?;
		match self.asserted {
			Some(asserted) if asserted != built => Err(BuildRefusal::VersionMismatch { asserted, built }.into()),
			_ => Ok(built),
		}
	}

	/// The order the frame carries: the configured stamp, or the current Unix
	/// time in seconds.
	///
	/// The builder leaves an unset order to the caller on a build with no host
	/// clock, such as `wasm32`, so this config decides it on every target.
	fn stamped_order(&self) -> u64 {
		self.order.unwrap_or_else(|| {
			let now = UnixMillis::now();
			Duration::from_millis(now.get()).as_secs()
		})
	}

	/// Assemble the structural frame, ready for the [`FrameAssembly`] steps.
	///
	/// The configured body is installed as the frame body byte for byte, so
	/// any `Message` schema round-trips bit-exactly.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnsupportedField`] -- the pinned version is below the floor of a
	///   requested field.
	/// - [`BuildRefusal::VersionMismatch`] -- the frame builds at another version than the
	///   asserted one.
	/// - [`TightBeamError::BuildError`] -- the config names no id.
	pub fn assemble(self) -> Result<FrameAssembly, StepError> {
		let version = self.checked_version()?;
		let order = self.stamped_order();

		// The upstream builder requires a typed message. Build with the empty
		// opaque body, then install the caller's body DER.
		let placeholder = Opaque::new(Vec::new())?;
		let mut builder = FrameBuilder::<Opaque>::from(version)
			.with_order(order)
			.with_message(placeholder);

		if let Some(id) = self.id {
			builder = builder.with_id(id);
		}
		if let Some(priority) = self.priority {
			builder = builder.with_priority(priority);
		}
		if let Some(lifetime) = self.lifetime {
			builder = builder.with_lifetime(lifetime);
		}

		let parent = self.previous_hash;
		if let Some(previous_hash) = parent.clone() {
			builder = builder.with_previous_hash(previous_hash.into_info()?);
		}
		if let Some(matrix) = self.matrix {
			builder = builder.with_matrix_dyn(matrix);
		}

		let frame = builder.build()?;
		let digests = CarriedDigests { previous_frame: parent, ..CarriedDigests::default() };
		let Some(body) = self.message else {
			return Ok(FrameAssembly { frame, digests });
		};

		let frame = frame.with_body(body.into_bytes())?;
		Ok(FrameAssembly { frame, digests })
	}

	/// Assemble the structural frame and return its DER.
	///
	/// # Errors
	///
	/// - The errors of [`Self::assemble`] and [`FrameAssembly::encode`].
	pub fn build(self) -> Result<Vec<u8>, StepError> {
		Ok(self.assemble()?.encode()?)
	}
}

/// The DER of a frame body: the preimage a caller commits to and seals, and
/// the octets a peer decodes under its own schema. It holds exactly one DER
/// value.
///
/// # Examples
///
/// ```
/// use tightbeam::TightBeamError;
/// use tightbeam_ws_wasm::build::BodyDer;
///
/// let body = BodyDer::try_from(vec![0x04, 0x02, 0x68, 0x69])?;
/// assert_eq!(body.as_bytes(), [0x04, 0x02, 0x68, 0x69]);
///
/// let trailing = BodyDer::try_from(vec![0x04, 0x00, 0x00]);
/// assert!(matches!(trailing, Err(TightBeamError::SerializationError(_))));
/// # Ok::<(), TightBeamError>(())
/// ```
pub struct BodyDer(Vec<u8>);

/// Admit octets that hold exactly one DER value.
impl TryFrom<Vec<u8>> for BodyDer {
	type Error = TightBeamError;

	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- `der` is not one DER value: it is empty, it
	///   breaks the DER rules, or bytes follow the value.
	fn try_from(der: Vec<u8>) -> Result<Self, Self::Error> {
		Any::from_der(&der)?;
		Ok(Self(der))
	}
}

impl BodyDer {
	/// The profile opaque body that wraps `message`.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- `message` exceeds the DER length limit.
	pub fn opaque(message: impl Into<Vec<u8>>) -> Result<Self, TightBeamError> {
		let body = Opaque::new(message)?;
		Ok(Self(body.to_der()?))
	}

	/// The message octets of a profile opaque body: a cleartext body, or the
	/// plaintext recovered from a confidential one.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the octets are no opaque body.
	pub fn opaque_message(&self) -> Result<Vec<u8>, TightBeamError> {
		Ok(Opaque::from_der(&self.0)?.into_bytes())
	}

	/// The message-commitment preimage over this body under `salt`, in the
	/// layout that [`CommitmentSalt::preimage`] states:
	///
	/// - `0x00 || body DER` for an empty salt.
	/// - `0x01 || len(salt) as u64 BE || salt || body DER` otherwise.
	///
	/// A caller hashes it with any digest and installs the digest with
	/// [`FrameAssembly::with_message_integrity`].
	pub fn commitment_preimage(&self, salt: &CommitmentSalt) -> Vec<u8> {
		let mut preimage = Vec::new();
		salt.preimage(&self.0, |part| preimage.extend_from_slice(part));
		preimage
	}

	/// A view of the one DER value that the parse admitted.
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}

	/// The one DER value that the parse admitted, moved out for a frame to
	/// carry.
	pub fn into_bytes(self) -> Vec<u8> {
		self.0
	}
}

/// A digest that the caller computed under an algorithm it names, as a frame
/// carries it in each digest field: the parent link, the message commitment,
/// and the witness. It holds at least one octet.
///
/// # Examples
///
/// ```
/// use tightbeam::oids::HASH_SHA3_256;
/// use tightbeam_ws_wasm::build::{BuildRefusal, NamedDigest};
///
/// let digest = NamedDigest::new(HASH_SHA3_256, [0xAA; 32])?;
/// # drop(digest);
/// # Ok::<(), BuildRefusal>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedDigest {
	algorithm_oid: ObjectIdentifier,
	digest: Vec<u8>,
}

impl NamedDigest {
	/// The digest `digest` under the algorithm that `algorithm_oid` names.
	///
	/// # Errors
	///
	/// - [`BuildRefusal::EmptyDigest`] -- `digest` holds no octets.
	pub fn new(algorithm_oid: ObjectIdentifier, digest: impl Into<Vec<u8>>) -> Result<Self, BuildRefusal> {
		let digest = digest.into();
		if digest.is_empty() {
			return Err(BuildRefusal::EmptyDigest);
		}

		Ok(Self { algorithm_oid, digest })
	}

	/// The algorithm that produced the digest.
	#[must_use]
	pub fn algorithm_oid(&self) -> ObjectIdentifier {
		self.algorithm_oid
	}

	/// The digest octets, at least one.
	#[must_use]
	pub fn digest(&self) -> &[u8] {
		&self.digest
	}

	/// Judge `recomputed`, the digest that `algorithm_oid` produced over the
	/// preimage, against this digest.
	///
	/// - The algorithm decides first, because it is public.
	/// - The octets then compare in constant time through [`ConstantTimeDigest`], the one home of that
	///   comparison in tightbeam.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- `recomputed` exceeds the DER length limit.
	pub fn verdict(
		&self,
		algorithm_oid: ObjectIdentifier,
		recomputed: impl Into<Vec<u8>>,
	) -> Result<IntegrityVerdict, TightBeamError> {
		if algorithm_oid != self.algorithm_oid {
			return Ok(IntegrityVerdict::AlgorithmMismatch);
		}

		let carried = Self::info(self.algorithm_oid, self.digest.clone())?;
		let recomputed = Self::info(algorithm_oid, recomputed.into())?;
		if carried.digest_matches(&recomputed) {
			return Ok(IntegrityVerdict::Verified);
		}

		Ok(IntegrityVerdict::Mismatch)
	}

	/// The `DigestInfo` that a frame carries: the digest under a
	/// parameterless `AlgorithmIdentifier`.
	fn into_info(self) -> Result<DigestInfo, TightBeamError> {
		Self::info(self.algorithm_oid, self.digest)
	}

	/// `digest` under the parameterless `AlgorithmIdentifier` of
	/// `algorithm_oid`.
	fn info(algorithm_oid: ObjectIdentifier, digest: Vec<u8>) -> Result<DigestInfo, TightBeamError> {
		let algorithm = AlgorithmIdentifierOwned { oid: algorithm_oid, parameters: None };
		let digest = OctetString::new(digest)?;
		Ok(DigestInfo { algorithm, digest })
	}
}

/// A digest that a frame carries, admitted under the rule of
/// [`NamedDigest::new`].
impl TryFrom<&DigestInfo> for NamedDigest {
	type Error = BuildRefusal;

	/// # Errors
	///
	/// - [`BuildRefusal::EmptyDigest`] -- the carried digest holds no octets.
	fn try_from(info: &DigestInfo) -> Result<Self, Self::Error> {
		Self::new(info.algorithm.oid, info.digest.as_bytes())
	}
}

/// A body that a caller's compressor produced, and how it compressed it
/// (RFC 3274).
pub struct Compactness {
	/// The compression algorithm.
	pub algorithm_oid: ObjectIdentifier,
	/// The DER parameters of the algorithm, when the scheme has any.
	pub parameters_der: Option<Vec<u8>>,
	/// The content type of the uncompressed body, or `id-data`, the type of
	/// an opaque frame body, when `None` (RFC 3274 § 1.1).
	pub content_oid: Option<ObjectIdentifier>,
	/// The compressed octets that replace the frame body.
	pub compressed: Vec<u8>,
}

/// The compactness info that describes the compressed body.
impl TryFrom<&Compactness> for CompressedData {
	type Error = TightBeamError;

	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the parameters are no DER.
	fn try_from(compactness: &Compactness) -> Result<Self, Self::Error> {
		let parameters = match &compactness.parameters_der {
			Some(der) => Some(Any::from_der(der)?),
			None => None,
		};

		let compression_alg = AlgorithmIdentifierOwned { oid: compactness.algorithm_oid, parameters };
		let econtent_type = compactness.content_oid.unwrap_or(DATA);
		let encap_content_info = EncapsulatedContentInfo { econtent_type, econtent: None };

		Ok(Self { version: CmsVersion::V0, compression_alg, encap_content_info })
	}
}

/// The subject key identifier that names a signer's certificate in a frame's
/// `SignerInfo` (RFC 5652 § 5.3). It holds at least one octet.
///
/// # Examples
///
/// ```
/// use tightbeam_ws_wasm::build::{BuildRefusal, SignerKeyId};
///
/// let refused = SignerKeyId::try_from(Vec::new());
/// assert!(matches!(refused, Err(BuildRefusal::EmptySignerId)));
/// ```
pub struct SignerKeyId(Vec<u8>);

/// Admit the identifier octets that a caller names a key by.
impl TryFrom<Vec<u8>> for SignerKeyId {
	type Error = BuildRefusal;

	/// # Errors
	///
	/// - [`BuildRefusal::EmptySignerId`] -- `octets` is empty.
	fn try_from(octets: Vec<u8>) -> Result<Self, Self::Error> {
		if octets.is_empty() {
			return Err(BuildRefusal::EmptySignerId);
		}

		Ok(Self(octets))
	}
}

impl SignerKeyId {
	/// The identifier of a profile secp256k1 verifying key, by RFC 7093 § 2
	/// method 1.
	///
	/// `tightbeam::cert!` writes the same identifier into each certificate, so
	/// a signature under this identifier names the certificate of the key.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SpkiError`] -- the key does not encode as a `SubjectPublicKeyInfo`.
	pub fn of(key: &Secp256k1VerifyingKey) -> Result<Self, TightBeamError> {
		let spki = SubjectPublicKeyInfoOwned::from_key(*key)?;
		Ok(Self(Skid::of_public_key(&spki).as_bytes().to_vec()))
	}

	/// The identifier octets.
	pub fn into_bytes(self) -> Vec<u8> {
		self.0
	}

	/// The `SignerIdentifier` this identifier names.
	fn signer_identifier(&self) -> Result<SignerIdentifier, TightBeamError> {
		let key_id = OctetString::new(self.0.as_slice())?;
		Ok(SignerIdentifier::SubjectKeyIdentifier(key_id.into()))
	}
}

/// A frame that awaits the signature of one key: the frame, and the CMS
/// `SignerInfo` drafted over it, which names the key.
///
/// - [`FrameAssembly::signing`] consumes the frame to draft it.
/// - The key signs [`prehash`](Self::prehash).
/// - [`complete`](Self::complete) consumes the draft to attach the signature, so a draft completes the
///   frame it was drafted over, and it completes that frame once.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
/// use tightbeam::crypto::sign::PrehashSigner;
/// use tightbeam::Version;
/// use tightbeam_ws_wasm::build::{BodyDer, FrameConfig, SignerKeyId};
///
/// let key = Secp256k1SigningKey::from_bytes(&[1u8; 32].into())?;
/// let signer = SignerKeyId::of(key.verifying_key())?;
///
/// let mut config = FrameConfig::default();
/// config.with_id(*b"id").with_version(Version::V1).with_message(BodyDer::opaque(*b"body")?);
/// let signing = config.assemble()?.signing(&signer)?;
///
/// let signature: Secp256k1Signature = key.sign_prehash(signing.prehash())?;
/// let signed = signing.complete(signature.to_bytes())?;
/// signed.verify_signature(key.verifying_key())?;
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Signing {
	assembly: FrameAssembly,
	draft: SignerInfoDraft,
}

impl Signing {
	/// The digest of the DER of the CMS signed attributes, which bind the
	/// content type, the digest of the TBS, and the algorithms (RFC 5652 §
	/// 5.4, RFC 6211). The key signs it directly, with no rehash.
	#[must_use]
	pub fn prehash(&self) -> &[u8] {
		self.draft.prehash()
	}

	/// Attach `signature`, a DER `ECDSA-Sig-Value` over
	/// [`prehash`](Self::prehash), and return the signed frame (V1+ frames).
	///
	/// # Errors
	///
	/// - [`TightBeamError::SignatureError`] -- the signature is no DER `ECDSA-Sig-Value`.
	/// - [`TightBeamError::UnsupportedField`] -- the frame's version predates signatures.
	pub fn complete(self, signature: impl AsRef<[u8]>) -> Result<FrameAssembly, TightBeamError> {
		let Self { assembly, draft } = self;
		let signer_info = draft.complete(signature, None)?;

		let FrameAssembly { mut frame, digests } = assembly;
		frame.attach_signer_info(signer_info)?;
		Ok(FrameAssembly { frame, digests })
	}
}

/// A frame between two assembly steps. The caller's own cryptography runs
/// between the steps, so each step installs or reads one field.
///
/// - A step that installs a field refuses a field that the version of the frame forbids.
/// - A step refuses to run behind a later step that the frame holds.
///
/// The steps run in the order of tightbeam's [`InstallStep`]:
///
/// 1. The message commitment.
/// 2. The compactness.
/// 3. The confidentiality.
/// 4. The witness.
/// 5. The signature.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::commitment::CommitmentSalt;
/// use tightbeam::crypto::hash::{Digest, Sha3_256};
/// use tightbeam::oids::HASH_SHA3_256;
/// use tightbeam_ws_wasm::build::{BodyDer, FrameConfig, NamedDigest, SecurityField};
///
/// let body = BodyDer::opaque(*b"body")?;
/// let mut config = FrameConfig::default();
/// config.with_id(*b"id").with_message(body);
/// config.declare(SecurityField::MessageIntegrity).declare(SecurityField::FrameIntegrity);
/// let assembly = config.assemble()?;
///
/// // The commitment comes first, because the witness covers it.
/// let salt = CommitmentSalt::parse([])?;
/// let preimage = assembly.commitment_preimage(&salt)?;
/// let commitment = NamedDigest::new(HASH_SHA3_256, Sha3_256::digest(&preimage).to_vec())?;
/// let assembly = assembly.with_message_integrity(commitment)?;
///
/// let preimage = assembly.witness_preimage()?;
/// let witness = NamedDigest::new(HASH_SHA3_256, Sha3_256::digest(&preimage).to_vec())?;
/// let assembly = assembly.with_witness(witness)?;
///
/// let frame_der = assembly.encode()?;
/// assert!(!frame_der.is_empty());
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
///
/// [`InstallStep`]: tightbeam::asn1::InstallStep
pub struct FrameAssembly {
	frame: Frame,
	digests: CarriedDigests,
}

/// The digests a frame carries, each admitted once as a [`NamedDigest`]: as
/// the frame decodes, or as the step that installs it runs.
#[derive(Clone, Default)]
struct CarriedDigests {
	previous_frame: Option<NamedDigest>,
	message_integrity: Option<NamedDigest>,
	frame_integrity: Option<NamedDigest>,
}

impl FrameAssembly {
	/// Decode the frame that `frame_der` encodes, and admit each digest it
	/// carries as a [`NamedDigest`].
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the octets are no frame.
	/// - [`BuildRefusal::EmptyDigest`] -- a digest the frame carries holds no octets.
	pub fn decode(frame_der: impl AsRef<[u8]>) -> Result<Self, StepError> {
		let frame = Frame::from_der(frame_der.as_ref())?;
		let metadata = frame.metadata();
		let admitted = |carried: Option<&DigestInfo>| carried.map(NamedDigest::try_from).transpose();

		let digests = CarriedDigests {
			previous_frame: admitted(metadata.previous_frame())?,
			message_integrity: admitted(metadata.integrity())?,
			frame_integrity: admitted(frame.integrity())?,
		};
		Ok(Self { frame, digests })
	}

	/// The DER of the frame.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the frame exceeds the DER length limit.
	pub fn encode(&self) -> Result<Vec<u8>, TightBeamError> {
		Ok(self.frame.to_der()?)
	}

	/// The message-commitment preimage over the body this frame holds, under
	/// `salt`, in the layout that [`CommitmentSalt::preimage`] states.
	///
	/// - A caller hashes it with any digest and installs the digest with
	///   [`with_message_integrity`](Self::with_message_integrity).
	/// - Read the preimage before any step that replaces the body, because the commitment covers the body
	///   as the caller wrote it.
	///
	/// # Errors
	///
	/// - [`TightBeamError::OpaqueBody`] -- the frame is sealed or compressed, so its body still
	///   needs a decrypt or an inflate.
	/// - [`TightBeamError::SerializationError`] -- the plaintext body is not one DER value.
	pub fn commitment_preimage(&self, salt: &CommitmentSalt) -> Result<Vec<u8>, TightBeamError> {
		let body = self.plain_body()?;
		Ok(body.commitment_preimage(salt))
	}

	/// The plaintext body of the frame. The frame decides from its own
	/// confidentiality and compactness whether the body is plaintext.
	///
	/// # Errors
	///
	/// - [`TightBeamError::OpaqueBody`] -- the body still needs a decrypt or an inflate.
	/// - [`TightBeamError::SerializationError`] -- the body is not one DER value.
	fn plain_body(&self) -> Result<BodyDer, TightBeamError> {
		if let Some(transform) = self.frame.body_transform() {
			return Err(TightBeamError::OpaqueBody(transform));
		}

		BodyDer::try_from(self.frame.message().to_vec())
	}

	/// Install a message-integrity commitment: the digest of
	/// [`commitment_preimage`](Self::commitment_preimage), under the caller's
	/// algorithm (V1+ frames).
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnsupportedField`] -- the frame's version predates the field.
	/// - [`TightBeamError::InstallOutOfOrder`] -- the frame holds a later step.
	pub fn with_message_integrity(self, commitment: NamedDigest) -> Result<Self, TightBeamError> {
		let Self { frame, mut digests } = self;
		let frame = frame.with_message_integrity(commitment.clone().into_info()?)?;

		digests.message_integrity = Some(commitment);
		Ok(Self { frame, digests })
	}

	/// Replace the frame body with the compressed body and record how it
	/// compressed (any version).
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the parameters are no DER.
	/// - [`TightBeamError::InstallOutOfOrder`] -- the frame holds a later step.
	/// - [`TightBeamError::InvalidMetadata`] -- the compactness info is malformed.
	pub fn with_compactness(self, compactness: Compactness) -> Result<Self, TightBeamError> {
		let described = CompressedData::try_from(&compactness)?;
		let Self { frame, digests } = self;

		let frame = frame.with_compactness(described, compactness.compressed)?;
		Ok(Self { frame, digests })
	}

	/// Replace the frame body with the ciphertext of `sealed` and install its
	/// envelope, the `AuthEnvelopedData` that seals it (V1+ frames).
	///
	/// The ciphertext travels detached from the envelope (RFC 5652 § 6.1). The
	/// envelope carries the content type, the recipient, and the tag.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnsupportedField`] -- the frame's version predates the field.
	/// - [`TightBeamError::InstallOutOfOrder`] -- the frame holds a later step.
	/// - [`TightBeamError::InvalidMetadata`] -- the envelope carries the ciphertext inside it.
	pub fn with_confidentiality(self, sealed: SealedBody) -> Result<Self, TightBeamError> {
		let Self { frame, digests } = self;
		let frame = frame.with_confidentiality(sealed.envelope, sealed.ciphertext)?;
		Ok(Self { frame, digests })
	}

	/// The frame-integrity (witness) preimage: hash it with any digest and
	/// install the result with [`with_witness`](Self::with_witness).
	///
	/// Read it after every metadata step, because the witness covers the final
	/// envelope.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the metadata does not encode.
	pub fn witness_preimage(&self) -> Result<Vec<u8>, TightBeamError> {
		let mut preimage = Vec::new();
		self.frame.witness_preimage(|part| preimage.extend_from_slice(part))?;
		Ok(preimage)
	}

	/// Install a frame-integrity witness: the digest of
	/// [`witness_preimage`](Self::witness_preimage) under the caller's
	/// algorithm (V1+ frames).
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnsupportedField`] -- the frame's version predates the field.
	/// - [`TightBeamError::InstallOutOfOrder`] -- the frame holds a later step.
	pub fn with_witness(self, witness: NamedDigest) -> Result<Self, TightBeamError> {
		let Self { frame, mut digests } = self;
		let frame = frame.with_frame_integrity(witness.clone().into_info()?)?;

		digests.frame_integrity = Some(witness);
		Ok(Self { frame, digests })
	}

	/// The to-be-signed octets of the frame: everything but the signature.
	///
	/// Read them after [`with_witness`](Self::with_witness), because the
	/// signature covers the witness.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the frame does not encode.
	pub fn tbs(&self) -> Result<Vec<u8>, TightBeamError> {
		self.frame.to_tbs()
	}

	/// Draft the signature that the key `signer` names owes this frame, and
	/// hold the frame until it completes. Sign its
	/// [`prehash`](Signing::prehash) and attach the signature with
	/// [`complete`](Signing::complete).
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the frame or its signed attributes do not
	///   encode.
	pub fn signing(self, signer: &SignerKeyId) -> Result<Signing, TightBeamError> {
		let sid = signer.signer_identifier()?;
		let draft = self.signature_draft(sid)?;

		Ok(Signing { assembly: self, draft })
	}

	/// The digest a verifier checks the frame's signature against, drawn from
	/// the frame's own signer and TBS.
	///
	/// The digest binds the signed attributes the profile requires, so a
	/// signature that verifies over it covers this frame.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingSignature`] -- the frame is unsigned.
	/// - [`TightBeamError::SerializationError`] -- the frame or its signed attributes do not
	///   encode.
	pub fn signature_prehash(&self) -> Result<Vec<u8>, TightBeamError> {
		let signer_info = self.frame.nonrepudiation().ok_or(TightBeamError::MissingSignature)?;
		let draft = self.signature_draft(signer_info.sid.clone())?;
		Ok(draft.prehash().to_vec())
	}

	/// Verify the frame's non-repudiation signature under a pinned profile
	/// key, over the signed attributes, which bind the frame's TBS.
	///
	/// The key is the trust decision, so the check reads the key alone.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingSignature`] -- the frame is unsigned.
	/// - [`TightBeamError::SignatureError`] -- the signature does not verify under `key`.
	pub fn verify_signature(&self, key: &Secp256k1VerifyingKey) -> Result<(), TightBeamError> {
		let signer_info = self.frame.nonrepudiation().ok_or(TightBeamError::MissingSignature)?;
		let tbs = self.frame.to_tbs()?;

		CmsSigner::verify::<Secp256k1Signature, _>(signer_info, key, SignedContent::data(&tbs))?;
		Ok(())
	}

	/// The octets the frame body holds now: the body DER, its compressed form
	/// once the compactness step ran, or its ciphertext once sealed.
	#[must_use]
	pub fn body(&self) -> &[u8] {
		self.frame.message()
	}

	/// The body, the metadata, and the carried security fields of the frame,
	/// for a caller that verifies with its own cryptography.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- a carried field does not encode.
	pub fn summary(&self) -> Result<FrameSummary, TightBeamError> {
		let frame = &self.frame;
		let metadata = frame.metadata();
		let digests = self.digests.clone();

		Ok(FrameSummary {
			version: frame.version(),
			id: metadata.id().to_vec(),
			order: metadata.order(),
			body: FrameBody::of(frame)?,
			priority: metadata.priority(),
			lifetime: metadata.lifetime(),
			previous_frame: digests.previous_frame,
			matrix: metadata.matrix().cloned(),
			message_integrity: digests.message_integrity,
			frame_integrity: digests.frame_integrity,
			signature: frame.nonrepudiation().map(|signed| SignatureSummary::from(&**signed)),
		})
	}

	/// The CMS `SignerInfo` that the frame's signature completes, naming
	/// `sid`, over the TBS under the profile signature.
	fn signature_draft(&self, sid: SignerIdentifier) -> Result<SignerInfoDraft, TightBeamError> {
		let tbs = self.frame.to_tbs()?;
		Ok(CmsSigner::draft::<Secp256k1Signature>(sid, SignedContent::data(&tbs))?)
	}
}

/// The body, the metadata, and the carried security fields of one frame, as
/// a caller reads them to verify with its own cryptography.
///
/// Each security field arrives whole or not at all, so each field holds its
/// algorithm and its octets together.
pub struct FrameSummary {
	/// Protocol version.
	pub version: Version,
	/// Opaque message identifier.
	pub id: Vec<u8>,
	/// Frame order stamp.
	///
	/// The value is protocol-opaque. Any monotonic scheme works, such as a
	/// Unix timestamp or a dense per-channel counter. When omitted at build
	/// time, the profile defaults to the current Unix time in seconds.
	pub order: u64,
	/// The body, and the layer a reader reverses first.
	pub body: FrameBody,
	/// Message priority, when present (V2+).
	pub priority: Option<MessagePriority>,
	/// Time-to-live in seconds, when present (V2+).
	pub lifetime: Option<u64>,
	/// The parent-frame link by content digest, when present (V2+).
	pub previous_frame: Option<NamedDigest>,
	/// The control matrix, when present (V3+).
	pub matrix: Option<MatrixDyn>,
	/// The message commitment, when committed.
	pub message_integrity: Option<NamedDigest>,
	/// The witness, when witnessed.
	pub frame_integrity: Option<NamedDigest>,
	/// The non-repudiation signature, when signed.
	pub signature: Option<SignatureSummary>,
}

/// The body a frame carries, by the layer a reader reverses first, in the
/// order of tightbeam's `Frame::body_transform`: the seal before the
/// compression.
pub enum FrameBody {
	/// A cleartext body that decodes as it is.
	Plain(Vec<u8>),
	/// A cleartext body that a reader inflates before it decodes.
	Compressed {
		/// The compressed octets.
		data: Vec<u8>,
		/// How the body compressed.
		compactness: CompactnessSummary,
	},
	/// A sealed body that a reader opens first, and inflates next when the
	/// sender compressed it before the seal.
	Sealed {
		/// The ciphertext, detached from its envelope.
		ciphertext: Vec<u8>,
		/// The envelope that seals the body.
		confidentiality: ConfidentialitySummary,
		/// How the body compressed under the seal, when it did.
		compactness: Option<CompactnessSummary>,
	},
}

impl FrameBody {
	/// The body of `frame`, with the layer its confidentiality and
	/// compactness name.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- a carried info does not encode.
	fn of(frame: &Frame) -> Result<Self, TightBeamError> {
		let metadata = frame.metadata();
		let octets = frame.message().to_vec();
		let compactness = metadata.compactness().map(CompactnessSummary::try_from).transpose()?;

		let body = match (metadata.confidentiality(), compactness) {
			(Some(envelope), compactness) => {
				let confidentiality = ConfidentialitySummary::try_from(envelope)?;
				Self::Sealed { ciphertext: octets, confidentiality, compactness }
			}
			(None, Some(compactness)) => Self::Compressed { data: octets, compactness },
			(None, None) => Self::Plain(octets),
		};

		Ok(body)
	}
}

/// How a carried body compressed.
pub struct CompactnessSummary {
	/// The compression algorithm OID.
	pub algorithm_oid: ObjectIdentifier,
	/// The DER parameters of the algorithm, when present.
	pub parameters_der: Option<Vec<u8>>,
	/// The content-type OID of the uncompressed body.
	pub content_oid: ObjectIdentifier,
}

impl TryFrom<&CompressedData> for CompactnessSummary {
	type Error = TightBeamError;

	fn try_from(info: &CompressedData) -> Result<Self, Self::Error> {
		let parameters = info.compression_alg.parameters.as_ref();
		let parameters_der = parameters.map(Encode::to_der).transpose()?;

		Ok(Self {
			algorithm_oid: info.compression_alg.oid,
			parameters_der,
			content_oid: info.encap_content_info.econtent_type,
		})
	}
}

/// The envelope that seals a carried body.
pub struct ConfidentialitySummary {
	/// The content-encryption algorithm OID.
	pub algorithm_oid: ObjectIdentifier,
	/// The content type that the envelope authenticates for the sealed body.
	pub content_oid: ObjectIdentifier,
	/// The DER `AuthEnvelopedData`. The ciphertext travels in the body,
	/// detached from it.
	pub envelope_der: Vec<u8>,
}

impl TryFrom<&AuthEnvelopedData> for ConfidentialitySummary {
	type Error = TightBeamError;

	fn try_from(envelope: &AuthEnvelopedData) -> Result<Self, Self::Error> {
		let content = &envelope.auth_encrypted_content_info;
		let algorithm_oid = content.content_enc_alg.oid;
		let content_oid = content.content_type;
		let envelope_der = envelope.to_der()?;
		Ok(Self { algorithm_oid, content_oid, envelope_der })
	}
}

/// A carried non-repudiation signature.
pub struct SignatureSummary {
	/// The signature algorithm OID.
	pub algorithm_oid: ObjectIdentifier,
	/// The OID of the digest the signature covers.
	pub digest_algorithm_oid: ObjectIdentifier,
	/// The DER signature octets.
	pub signature: Vec<u8>,
}

impl From<&SignerInfo> for SignatureSummary {
	fn from(info: &SignerInfo) -> Self {
		Self {
			algorithm_oid: info.signature_algorithm.oid,
			digest_algorithm_oid: info.digest_alg.oid,
			signature: info.signature.as_bytes().to_vec(),
		}
	}
}

/// A sealed body: the envelope that seals it, parsed once, and the
/// ciphertext that replaces the frame body. A profile encryptor produces
/// one, and a caller with its own scheme names each piece.
pub struct SealedBody {
	/// The `AuthEnvelopedData`, its content detached.
	envelope: WireDer<AuthEnvelopedData>,
	/// The ciphertext replacing the frame body.
	ciphertext: Vec<u8>,
}

/// Detach the encrypted content of an envelope into the pieces.
impl TryFrom<AuthEnvelopedData> for SealedBody {
	type Error = TightBeamError;

	fn try_from(mut envelope: AuthEnvelopedData) -> Result<Self, Self::Error> {
		let ciphertext = envelope.take_content()?.to_vec();
		let envelope = WireDer::new(envelope)?;

		Ok(Self { envelope, ciphertext })
	}
}

impl SealedBody {
	/// The pieces a caller's own scheme produced: the DER of the envelope,
	/// parsed once here, and the ciphertext.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- `envelope_der` is no `AuthEnvelopedData`.
	pub fn new(envelope_der: &[u8], ciphertext: Vec<u8>) -> Result<Self, TightBeamError> {
		let envelope = WireDer::try_from(envelope_der)?;
		Ok(Self { envelope, ciphertext })
	}

	/// The DER of the envelope, its content detached.
	pub fn envelope_der(&self) -> &[u8] {
		self.envelope.der()
	}

	/// The ciphertext that replaces the frame body.
	#[must_use]
	pub fn ciphertext(&self) -> &[u8] {
		&self.ciphertext
	}

	/// The content-encryption algorithm OID that the envelope names.
	#[must_use]
	pub fn algorithm_oid(&self) -> ObjectIdentifier {
		let info = &self.envelope.value().auth_encrypted_content_info;
		info.content_enc_alg.oid
	}

	/// Open the ciphertext under `decryptor`, against the envelope that seals
	/// it, returning the octets that were sealed.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a `decryptor` that refuses the envelope or the ciphertext.
	async fn open(self, decryptor: &impl DecryptContent) -> Result<Vec<u8>, TightBeamError> {
		let Self { envelope, mut ciphertext } = self;
		decryptor.decrypt_content(&envelope, &mut ciphertext).await?;

		Ok(ciphertext)
	}
}

/// A shared key that the profile cipher refuses.
#[derive(Debug, Errorizable)]
pub enum SharedKeyRefusal {
	/// The key identifier holds no octets, so it names no key.
	#[error("a shared key identifier must name the key")]
	EmptyKeyId,
	/// tightbeam refuses the key, such as a key that is not 32 octets.
	#[error("{0}")]
	#[from]
	Key(TightBeamError),
}

/// Profile key-encryption key: a 32-byte shared key that wraps a fresh
/// AES-256-GCM content key per seal, in a `KEKRecipientInfo` named by its
/// key identifier (RFC 5652 § 6.2.3).
///
/// # Examples
///
/// ```
/// use tightbeam::ZeroizingBytes;
/// use tightbeam_ws_wasm::build::{Aes256GcmKey, SharedKeyRefusal};
///
/// let key = ZeroizingBytes::new(vec![0x42; 32]);
/// let refused = Aes256GcmKey::new(key, Vec::new());
/// assert!(matches!(refused, Err(SharedKeyRefusal::EmptyKeyId)));
/// ```
pub struct Aes256GcmKey {
	provider: Aes256GcmKeyProvider,
}

impl Aes256GcmKey {
	/// The raw 32-byte `key`, named by `key_id`, the identifier an envelope
	/// carries in the clear to name the key to every holder.
	///
	/// The buffer that holds the key wipes once the provider reads it, or once
	/// this call refuses it.
	///
	/// # Errors
	///
	/// - [`SharedKeyRefusal::EmptyKeyId`] -- `key_id` is empty, so it names no key.
	/// - [`SharedKeyRefusal::Key`] -- tightbeam refuses the key, which is not 32 octets.
	pub fn new(key: ZeroizingBytes, key_id: impl Into<Vec<u8>>) -> Result<Self, SharedKeyRefusal> {
		let key_id = key_id.into();
		if key_id.is_empty() {
			return Err(SharedKeyRefusal::EmptyKeyId);
		}

		let provider = Aes256GcmKeyProvider::new(key, key_id).map_err(TightBeamError::from)?;
		Ok(Self { provider })
	}

	/// Seal `plaintext` of type `content_oid`, or `id-data` without one,
	/// under a fresh content key.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a seal that fails, such as a random source, a key wrap or a content
	///   cipher that fails, or an envelope past a DER length.
	pub fn seal(
		&self,
		plaintext: impl AsRef<[u8]>,
		content_oid: Option<ObjectIdentifier>,
	) -> Result<SealedBody, TightBeamError> {
		let sealed = Encryptor::<Aes256GcmOid>::encrypt_content(&self.provider, plaintext.as_ref(), content_oid, None);
		SealedBody::try_from(sealed?)
	}

	/// Open a sealed body, returning the octets that were sealed.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of an envelope or a ciphertext that the key refuses, such as an envelope that
	///   names another key, or a ciphertext that fails its tag.
	pub async fn open(&self, sealed: SealedBody) -> Result<Vec<u8>, TightBeamError> {
		sealed.open(&self.provider).await
	}
}

/// Profile HPKE encryptor (DHKEM over secp256k1, an AES-256-GCM content key,
/// and a `KEMRecipientInfo` per RFC 9629).
pub struct HpkeSecp256k1Encryptor {
	inner: HpkeEncryptor<DefaultCryptoProvider>,
}

impl HpkeSecp256k1Encryptor {
	/// Construct from the recipient's SEC1 public key.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of octets that are no secp256k1 point.
	pub fn from_sec1(recipient_public_key: impl AsRef<[u8]>) -> Result<Self, TightBeamError> {
		let key = Secp256k1VerifyingKey::from_sec1_bytes(recipient_public_key.as_ref())?;
		let spki = key.to_public_key_der()?;
		let inner = HpkeEncryptor::new(KemRecipient::bare(spki.as_bytes())?);

		Ok(Self { inner })
	}

	/// Seal `plaintext` of type `content_oid`, or `id-data` without one, to
	/// the recipient under a fresh ephemeral key.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a key agreement or a content cipher that fails.
	pub fn seal(
		&self,
		plaintext: impl AsRef<[u8]>,
		content_oid: Option<ObjectIdentifier>,
	) -> Result<SealedBody, TightBeamError> {
		let sealed = Encryptor::<Aes256GcmOid>::encrypt_content(&self.inner, plaintext.as_ref(), content_oid, None);
		SealedBody::try_from(sealed?)
	}
}

/// Profile HPKE decryptor holding the recipient secp256k1 secret.
pub struct HpkeSecp256k1Decryptor {
	inner: HpkeDecryptor<DefaultCryptoProvider>,
}

impl HpkeSecp256k1Decryptor {
	/// Construct from the recipient's secret key.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a key that forms no KEM recipient key.
	pub fn new(signing_key: Secp256k1SigningKey) -> Result<Self, TightBeamError> {
		let public = PublicKey::from(signing_key.verifying_key());
		let backend: Arc<dyn DiffieHellman<Secp256k1>> = Arc::new(Secp256k1KeyProvider::from(signing_key));

		let inner = HpkeDecryptor::new(BareKemKey::new(public, backend)?);
		Ok(Self { inner })
	}

	/// Open a sealed body, returning the octets that were sealed.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of an envelope or a ciphertext that the recipient refuses, such as an
	///   envelope that names another recipient, or a ciphertext that fails its tag.
	pub async fn open(&self, sealed: SealedBody) -> Result<Vec<u8>, TightBeamError> {
		sealed.open(&self.inner).await
	}
}

// The tests run on the host: they use the host-only tokio and zstd.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
	use std::time::{SystemTime, UNIX_EPOCH};

	use tightbeam::asn1::{BodyTransform, GatedField};
	use tightbeam::builder::error::{BuildError, MetadataError};
	use tightbeam::core::IntegrityVerdict;
	use tightbeam::crypto::commitment::{CommitmentSalt, Opening};
	use tightbeam::crypto::hash::{Digest as _, Sha3_256};
	use tightbeam::crypto::key::Aes256GcmKeyProvider;
	use tightbeam::crypto::profiles::DefaultCryptoProvider;
	use tightbeam::crypto::secret::ToInsecure;
	use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
	use tightbeam::crypto::sign::PrehashSigner;
	use tightbeam::crypto::x509::{KeyPurposes, PeerCertificate, Signing};
	use tightbeam::der::asn1::OctetString;
	use tightbeam::der::{Decode, Encode, Sequence};
	use tightbeam::matrix::{MatrixDyn, MatrixLike};
	use tightbeam::oids::{AES_256_GCM, DATA, DHKEM_SECP256K1, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256};
	use tightbeam::spki::AlgorithmIdentifierOwned;
	use tightbeam::testing::{unhex, TestCertificate};
	use tightbeam::{
		tb_cases, Beamable, DigestInfo, Frame, MessagePriority, Opaque, TightBeamError, Version, ZeroizingBytes,
	};

	use tightbeam::compress::{Compressor, ZstdCompression};

	use tightbeam::spki::EncodePublicKey;

	use super::{
		Aes256GcmKey, BodyDer, BuildRefusal, Compactness, CompactnessSummary, ConfidentialitySummary, FrameAssembly,
		FrameBody, FrameConfig, FrameSummary, HpkeSecp256k1Decryptor, HpkeSecp256k1Encryptor, NamedDigest, SealedBody,
		SecurityField, SignerKeyId, StepError,
	};

	type TestResult = core::result::Result<(), Box<dyn core::error::Error>>;
	type AnyResult<T> = core::result::Result<T, Box<dyn core::error::Error>>;

	fn sample_message() -> Vec<u8> {
		b"opaque-message-body".to_vec()
	}

	/// The profile body DER wrapping [`sample_message`].
	fn sample_body() -> AnyResult<Vec<u8>> {
		Ok(BodyDer::opaque(sample_message())?.into_bytes())
	}

	/// [`sample_body`] as the body a frame config takes.
	fn sample_body_der() -> AnyResult<BodyDer> {
		Ok(BodyDer::opaque(sample_message())?)
	}

	fn signing_key() -> AnyResult<Secp256k1SigningKey> {
		Ok(Secp256k1SigningKey::from_bytes(&[1u8; 32].into())?)
	}

	fn base_config(id: &[u8], order: u64) -> AnyResult<FrameConfig> {
		let mut config = FrameConfig::default();
		config.with_id(id).with_order(order).with_message(sample_body_der()?);
		Ok(config)
	}

	/// The [`base_config`] of `id` and `order`, pinned at `version`.
	fn pinned_config(id: &[u8], order: u64, version: Version) -> AnyResult<FrameConfig> {
		let mut config = base_config(id, order)?;
		config.with_version(version);
		Ok(config)
	}

	fn seal_frame(id: &[u8], order: u64) -> AnyResult<Vec<u8>> {
		Ok(base_config(id, order)?.build()?)
	}

	fn open_frame(frame_der: impl AsRef<[u8]>) -> AnyResult<Vec<u8>> {
		let frame = Frame::from_der(frame_der.as_ref())?;
		let body = BodyDer::try_from(frame.message().to_vec())?;
		Ok(body.opaque_message()?)
	}

	/// The current Unix time in seconds, from the host clock.
	fn unix_seconds() -> AnyResult<u64> {
		Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
	}

	/// The SHA3-256 digest of `preimage`, named the way a caller-side hasher
	/// names it.
	fn sha3_digest(preimage: impl AsRef<[u8]>) -> AnyResult<NamedDigest> {
		let digest = Sha3_256::digest(preimage.as_ref()).to_vec();
		Ok(NamedDigest::new(HASH_SHA3_256, digest)?)
	}

	/// The DER `ECDSA-Sig-Value` of `key` over `prehash`, with no rehash.
	fn sign(key: &Secp256k1SigningKey, prehash: impl AsRef<[u8]>) -> AnyResult<Vec<u8>> {
		let signature: Secp256k1Signature = key.sign_prehash(prehash.as_ref())?;
		Ok(signature.to_bytes().to_vec())
	}

	/// The summary of the frame that `frame_der` encodes.
	fn summary_of(frame_der: impl AsRef<[u8]>) -> AnyResult<FrameSummary> {
		Ok(FrameAssembly::decode(frame_der)?.summary()?)
	}

	/// The octets of a cleartext body.
	fn plain_body(body: FrameBody) -> AnyResult<Vec<u8>> {
		let FrameBody::Plain(der) = body else {
			return Err("the body is not cleartext".into());
		};

		Ok(der)
	}

	/// The ciphertext of a sealed body and the envelope that seals it.
	fn sealed_body(body: FrameBody) -> AnyResult<(Vec<u8>, ConfidentialitySummary)> {
		let FrameBody::Sealed { ciphertext, confidentiality, .. } = body else {
			return Err("the body is not sealed".into());
		};

		Ok((ciphertext, confidentiality))
	}

	/// The octets of a compressed cleartext body and how it compressed.
	fn compressed_body(body: FrameBody) -> AnyResult<(Vec<u8>, CompactnessSummary)> {
		let FrameBody::Compressed { data, compactness } = body else {
			return Err("the body is not compressed cleartext".into());
		};

		Ok((data, compactness))
	}

	/// A salt long enough to hide a body.
	const HIDING_SALT: &[u8] = b"tbws-commitment-salt";

	/// The identifier that names the shared key of the AEAD fixtures.
	const KEY_ID: &[u8] = b"tbws/test/kek/v1";

	/// A shared key of 32 `fill` octets, named by [`KEY_ID`].
	fn shared_key(fill: u8) -> Aes256GcmKey {
		let key = ZeroizingBytes::new(vec![fill; 32]);
		let shared = Aes256GcmKey::new(key, KEY_ID);
		shared.expect("the fixture key names itself")
	}

	fn frame_from(config: FrameConfig) -> AnyResult<Frame> {
		Ok(Frame::from_der(&config.build()?)?)
	}

	/// Drive the full caller-side pipeline with the profile primitives, the
	/// way the TS builder does: commit, witness, then sign detached.
	fn signed_frame(id: &[u8], order: u64, key: &Secp256k1SigningKey) -> AnyResult<Vec<u8>> {
		let der = pinned_config(id, order, Version::V2)?.build()?;

		let salt = CommitmentSalt::parse([])?;
		let body = BodyDer::try_from(sample_body()?)?;
		let commitment = sha3_digest(body.commitment_preimage(&salt))?;
		let der = FrameAssembly::decode(&der)?.with_message_integrity(commitment)?.encode()?;

		let witness = sha3_digest(FrameAssembly::decode(&der)?.witness_preimage()?)?;
		let der = FrameAssembly::decode(&der)?.with_witness(witness)?.encode()?;

		let signer = SignerKeyId::of(key.verifying_key())?;
		let signing = FrameAssembly::decode(&der)?.signing(&signer)?;
		let signature = sign(key, signing.prehash())?;

		Ok(signing.complete(signature)?.encode()?)
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
	fn a_frame_without_an_id_is_refused() -> TestResult {
		let mut config = FrameConfig::default();
		config.with_order(1).with_message(sample_body_der()?);

		let refused = config.assemble();
		let missing_id = matches!(
			refused,
			Err(StepError::Engine(TightBeamError::BuildError(BuildError::InvalidMetadata(
				MetadataError::MissingId
			))))
		);
		assert!(missing_id);
		Ok(())
	}

	#[test]
	fn an_omitted_order_stamps_the_unix_time() -> TestResult {
		let before = unix_seconds()?;
		let mut config = FrameConfig::default();
		config.with_id(*b"unstamped").with_message(sample_body_der()?);

		let summary = summary_of(config.build()?)?;
		assert!(summary.order >= before);
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
		let mut config = base_config(b"meta", 9)?;
		config.with_priority(MessagePriority::LowLatency).with_lifetime(60);

		let frame = frame_from(config)?;
		assert_eq!(frame.version(), Version::V2);
		assert_eq!(frame.metadata().priority(), Some(MessagePriority::LowLatency));
		assert_eq!(frame.metadata().lifetime(), Some(60));
		Ok(())
	}

	#[test]
	fn config_matrix_requires_v3() -> TestResult {
		let matrix = MatrixDyn::from_row_major(2, vec![0, 1, 1, 0]).ok_or("matrix dims")?;
		let mut config = base_config(b"matrix", 1)?;
		config.with_matrix(matrix);

		let frame = frame_from(config)?;
		assert_eq!(frame.version(), Version::V3);

		let recovered_matrix = frame.metadata().matrix().ok_or("matrix present")?;
		assert_eq!(recovered_matrix.n(), 2);
		Ok(())
	}

	#[test]
	fn config_pins_explicit_version() -> TestResult {
		let config = pinned_config(b"pinned", 3, Version::V2)?;
		let frame = frame_from(config)?;
		assert_eq!(frame.version(), Version::V2);
		Ok(())
	}

	// A declared security field lifts the floor to the version the engine
	// first carries it at.
	tb_cases! {
		fn a_declared_field_sets_the_floor_of_the_engine(field: SecurityField) -> TestResult {
			let mut config = base_config(b"declared", 1)?;
			config.declare(field);

			let frame = frame_from(config)?;
			assert_eq!(frame.version(), GatedField::from(field).since());
			Ok(())
		}
		cases {
			message_integrity => SecurityField::MessageIntegrity,
			confidentiality => SecurityField::Confidentiality,
			frame_integrity => SecurityField::FrameIntegrity,
			nonrepudiation => SecurityField::Nonrepudiation,
		}
	}

	/// The floor is the latest version among the structural and the declared
	/// fields.
	#[test]
	fn the_floor_is_the_latest_gated_field() -> TestResult {
		let mut config = base_config(b"latest", 1)?;
		config
			.with_priority(MessagePriority::Standard)
			.declare(SecurityField::Nonrepudiation);

		let frame = frame_from(config)?;
		assert_eq!(frame.version(), Version::V2);
		Ok(())
	}

	/// A pinned version below a declared field refuses before any security
	/// operation runs.
	#[test]
	fn a_pin_below_a_declared_field_is_refused() -> TestResult {
		let mut config = pinned_config(b"below", 1, Version::V0)?;
		config.declare(SecurityField::Confidentiality);

		let refused = config.build();
		assert!(matches!(
			refused,
			Err(StepError::Engine(TightBeamError::UnsupportedField {
				field: GatedField::Confidentiality,
				version: Version::V0
			}))
		));
		Ok(())
	}

	/// An asserted version that the frame misses refuses at the assembly,
	/// before any security step runs.
	#[test]
	fn an_asserted_version_the_frame_misses_is_refused() -> TestResult {
		let mut config = base_config(b"asserted", 1)?;
		config.declare(SecurityField::Nonrepudiation).assert_version(Version::V0);

		let refused = config.assemble();
		let mismatch = BuildRefusal::VersionMismatch { asserted: Version::V0, built: Version::V1 };
		assert!(matches!(refused, Err(StepError::Refused(refusal)) if refusal == mismatch));
		Ok(())
	}

	#[test]
	fn a_decoded_frame_that_carries_an_empty_digest_is_refused() -> TestResult {
		let algorithm = AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None };
		let empty = DigestInfo { algorithm, digest: OctetString::new(Vec::new())? };
		let frame = tightbeam::compose! {
			V2: id: "empty-parent",
				order: 1u64,
				message: Opaque::new(sample_message())?,
				previous_frame: empty
		}?;

		let refused = FrameAssembly::decode(frame.to_der()?);
		assert!(matches!(refused, Err(StepError::Refused(BuildRefusal::EmptyDigest))));
		Ok(())
	}

	// The algorithm decides first, and the octets compare after it.
	tb_cases! {
		fn a_digest_judges_a_recomputed_digest((algorithm, recomputed, verdict): (&str, Vec<u8>, IntegrityVerdict)) -> TestResult {
			let carried = NamedDigest::new(HASH_SHA3_256, [0xAA; 32])?;

			let judged = carried.verdict(algorithm.parse()?, recomputed)?;
			assert_eq!(judged, verdict);
			Ok(())
		}
		cases {
			verified => ("2.16.840.1.101.3.4.2.8", vec![0xAA; 32], IntegrityVerdict::Verified),
			mismatch => ("2.16.840.1.101.3.4.2.8", vec![0xAB; 32], IntegrityVerdict::Mismatch),
			algorithm_mismatch => ("2.16.840.1.101.3.4.2.10", vec![0xAA; 32], IntegrityVerdict::AlgorithmMismatch),
		}
	}

	#[test]
	fn inspect_reports_cleartext_metadata() -> TestResult {
		let frame_der = seal_frame(b"view-1", 11)?;
		let summary = summary_of(&frame_der)?;
		assert_eq!(summary.version, Version::V0);
		assert_eq!(summary.id, b"view-1");
		assert_eq!(summary.order, 11);
		assert!(summary.signature.is_none());
		assert!(summary.message_integrity.is_none());
		assert!(summary.frame_integrity.is_none());

		let body = plain_body(summary.body)?;
		assert_eq!(body, sample_body()?);
		assert_eq!(BodyDer::try_from(body)?.opaque_message()?, sample_message());
		Ok(())
	}

	#[test]
	fn inspect_reports_v2_metadata_and_matrix() -> TestResult {
		let digest_octets = vec![0xAAu8; 32];
		let previous = NamedDigest::new("2.16.840.1.101.3.4.2.10".parse()?, digest_octets.clone())?;
		let matrix = MatrixDyn::from_row_major(2, vec![0, 1, 1, 0]).ok_or("matrix dims")?;

		let mut config = base_config(b"rich", 21)?;
		config.with_priority(MessagePriority::Expedited).with_lifetime(300);
		config.with_previous_hash(previous).with_matrix(matrix);

		let summary = summary_of(config.build()?)?;
		let previous_frame = summary.previous_frame.ok_or("the frame links its parent")?;
		let matrix = summary.matrix.ok_or("the frame carries a matrix")?;
		assert_eq!(summary.priority, Some(MessagePriority::Expedited));
		assert_eq!(summary.lifetime, Some(300));
		assert_eq!(previous_frame.algorithm_oid().to_string(), "2.16.840.1.101.3.4.2.10");
		assert_eq!(previous_frame.digest(), digest_octets);
		assert_eq!(matrix.n(), 2);
		assert_eq!(matrix.as_bytes(), [0, 1, 1, 0]);
		Ok(())
	}

	#[test]
	fn inspect_omits_absent_metadata() -> TestResult {
		let summary = summary_of(seal_frame(b"bare", 1)?)?;
		assert_eq!(summary.priority, None);
		assert_eq!(summary.lifetime, None);
		assert!(matches!(summary.body, FrameBody::Plain(_)));
		assert!(summary.previous_frame.is_none());
		assert!(summary.matrix.is_none());
		Ok(())
	}

	#[test]
	fn signed_frame_carries_security_infos() -> TestResult {
		let summary = summary_of(signed_frame(b"signed-1", 5, &signing_key()?)?)?;
		let signature = summary.signature.ok_or("the frame is signed")?;
		let message_integrity = summary.message_integrity.ok_or("the frame is committed")?;
		let frame_integrity = summary.frame_integrity.ok_or("the frame is witnessed")?;
		assert_eq!(signature.algorithm_oid.to_string(), "2.16.840.1.101.3.4.3.10");
		assert_eq!(signature.digest_algorithm_oid.to_string(), "2.16.840.1.101.3.4.2.8");
		assert_eq!(message_integrity.algorithm_oid().to_string(), "2.16.840.1.101.3.4.2.8");
		assert_eq!(frame_integrity.algorithm_oid().to_string(), "2.16.840.1.101.3.4.2.8");
		assert!(!signature.signature.is_empty());
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
		let signer = SignerKeyId::of(key.verifying_key())?;

		let der = pinned_config(b"prehash", 1, Version::V1)?.build()?;
		let signing = FrameAssembly::decode(&der)?.signing(&signer)?;
		let prehash = signing.prehash().to_vec();
		let signature = sign(&key, &prehash)?;
		let signed = signing.complete(signature)?;

		assert_eq!(signed.signature_prehash()?, prehash);
		Ok(())
	}

	#[test]
	fn verify_signature_accepts_signer_key() -> TestResult {
		let key = signing_key()?;
		let frame_der = signed_frame(b"sig-ok", 1, &key)?;

		FrameAssembly::decode(&frame_der)?.verify_signature(key.verifying_key())?;
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

		let verified = FrameAssembly::decode(&frame_der)?.verify_signature(other.verifying_key());
		assert!(verified.is_err());
		Ok(())
	}

	#[test]
	fn verify_signature_rejects_unsigned_frame() -> TestResult {
		let frame_der = seal_frame(b"unsigned", 1)?;

		let verified = FrameAssembly::decode(&frame_der)?.verify_signature(signing_key()?.verifying_key());
		assert!(matches!(verified, Err(TightBeamError::MissingSignature)));
		Ok(())
	}

	/// A compact signature of 64 raw octets is no DER `ECDSA-Sig-Value`, the
	/// one form the attach takes.
	#[test]
	fn a_compact_signature_is_refused_at_attach() -> TestResult {
		let key = signing_key()?;
		let frame_der = pinned_config(b"junk", 1, Version::V1)?.build()?;
		let signer = SignerKeyId::of(key.verifying_key())?;
		let signing = FrameAssembly::decode(&frame_der)?.signing(&signer)?;

		let attached = signing.complete([0u8; 64]);
		assert!(attached.is_err());
		Ok(())
	}

	/// A frame below V1 carries no signature, so the attach refuses it.
	#[test]
	fn a_v0_frame_refuses_a_signature() -> TestResult {
		let key = signing_key()?;
		let frame_der = seal_frame(b"v0", 1)?;
		let signer = SignerKeyId::of(key.verifying_key())?;
		let signing = FrameAssembly::decode(&frame_der)?.signing(&signer)?;
		let signature = sign(&key, signing.prehash())?;

		let attached = signing.complete(signature);
		assert!(attached.is_err());
		Ok(())
	}

	/// The caller-side commitment (preimage + digest + install) must satisfy
	/// tightbeam's own commitment verdict: pins the preimage framing.
	#[test]
	fn caller_side_commitment_verifies_with_tightbeam() -> TestResult {
		let salt = CommitmentSalt::parse(HIDING_SALT)?;
		let der = pinned_config(b"mi", 1, Version::V2)?.build()?;
		let assembly = FrameAssembly::decode(&der)?;

		let commitment = sha3_digest(assembly.commitment_preimage(&salt)?)?;
		let der = assembly.with_message_integrity(commitment)?.encode()?;

		let frame = Frame::from_der(&der)?;
		let body = Opaque::from_der(frame.message())?;
		let (_, opening) = Opening::prove::<Sha3_256, _>(&body, HIDING_SALT)?;
		let verdict = frame.message_commitment_verdict::<Sha3_256>(&opening)?;
		assert!(matches!(verdict, IntegrityVerdict::Verified));
		Ok(())
	}

	/// The caller-side witness (input + digest + install) must satisfy
	/// tightbeam's own frame-integrity verdict: pins the scaffold encoding.
	#[test]
	fn caller_side_witness_verifies_with_tightbeam() -> TestResult {
		let der = pinned_config(b"fi", 1, Version::V2)?.build()?;
		let witness = sha3_digest(FrameAssembly::decode(&der)?.witness_preimage()?)?;
		let der = FrameAssembly::decode(&der)?.with_witness(witness)?.encode()?;

		let frame = Frame::from_der(&der)?;
		let verdict = frame.frame_integrity_verdict::<Sha3_256>()?;
		assert!(matches!(verdict, IntegrityVerdict::Verified));
		Ok(())
	}

	#[test]
	fn tampered_witness_reports_mismatch() -> TestResult {
		let der = pinned_config(b"fi-bad", 1, Version::V2)?.build()?;
		let witness = NamedDigest::new(HASH_SHA3_256, vec![0u8; 32])?;
		let der = FrameAssembly::decode(&der)?.with_witness(witness)?.encode()?;

		let frame = Frame::from_der(&der)?;
		let verdict = frame.frame_integrity_verdict::<Sha3_256>()?;
		assert!(matches!(verdict, IntegrityVerdict::Mismatch));
		Ok(())
	}

	/// A caller-sealed body must open with tightbeam's own decryptor: pins
	/// the detached envelope layout.
	#[tokio::test]
	async fn caller_side_aead_seal_opens_with_tightbeam() -> TestResult {
		let key = [0x42u8; 32];
		let der = pinned_config(b"sealed", 8, Version::V1)?.build()?;

		let aes = shared_key(0x42);
		let sealed = aes.seal(sample_body()?, None)?;
		assert_eq!(sealed.algorithm_oid(), AES_256_GCM);

		let envelope_der = sealed.envelope_der().to_vec();
		let der = FrameAssembly::decode(&der)?.with_confidentiality(sealed)?.encode()?;

		let (ciphertext, confidentiality) = sealed_body(summary_of(&der)?.body)?;
		assert_eq!(confidentiality.algorithm_oid, AES_256_GCM);
		assert_eq!(confidentiality.content_oid, DATA);
		assert_eq!(confidentiality.envelope_der, envelope_der);
		assert_ne!(ciphertext, sample_body()?);

		let holder = Aes256GcmKeyProvider::new(key.to_vec(), KEY_ID.to_vec())?;
		let frame = Frame::from_der(&der)?;
		let plaintext = frame.decrypt_bytes(&holder).await?.to_insecure();
		assert_eq!(BodyDer::try_from(plaintext.to_vec())?.opaque_message()?, sample_message());
		Ok(())
	}

	/// A frame tightbeam seals must open under the caller-side key.
	#[tokio::test]
	async fn tightbeam_seal_opens_on_the_caller_side() -> TestResult {
		let key = [0x42u8; 32];
		let holder = Aes256GcmKeyProvider::new(key.to_vec(), KEY_ID.to_vec())?;

		let body = Opaque::new(sample_message())?;
		let frame = tightbeam::compose! {
			V1: id: "native-sealed",
				order: 2u64,
				message: body,
				confidentiality: holder
		}?;

		let (ciphertext, confidentiality) = sealed_body(summary_of(frame.to_der()?)?.body)?;
		let sealed_body = SealedBody::new(&confidentiality.envelope_der, ciphertext)?;

		let opened = shared_key(0x42).open(sealed_body).await?;
		assert_eq!(BodyDer::try_from(opened)?.opaque_message()?, sample_message());
		Ok(())
	}

	#[tokio::test]
	async fn aead_seal_open_round_trips() -> TestResult {
		let aes = shared_key(0x42);
		let preimage = sample_body()?;

		let sealed = aes.seal(&preimage, None)?;
		let opened = aes.open(sealed).await?;
		assert_eq!(opened, preimage);
		Ok(())
	}

	#[tokio::test]
	async fn aead_open_rejects_wrong_key() -> TestResult {
		let sealed = shared_key(0x42).seal(sample_body()?, None)?;
		let other = shared_key(0x43);
		assert!(other.open(sealed).await.is_err());
		Ok(())
	}

	#[tokio::test]
	async fn aead_open_rejects_a_tampered_body() -> TestResult {
		let aes = shared_key(0x42);
		let sealed = aes.seal(sample_body()?, None)?;
		let mut ciphertext = sealed.ciphertext().to_vec();
		*ciphertext.first_mut().ok_or("the seal holds ciphertext")? ^= 0x01;

		let tampered = SealedBody::new(sealed.envelope_der(), ciphertext)?;
		assert!(aes.open(tampered).await.is_err());
		Ok(())
	}

	#[tokio::test]
	async fn hpke_seal_open_round_trips() -> TestResult {
		let recipient_public = signing_key()?.verifying_key().to_sec1_bytes().to_vec();
		let preimage = sample_body()?;

		let sealed = HpkeSecp256k1Encryptor::from_sec1(&recipient_public)?.seal(&preimage, None)?;
		assert_eq!(sealed.algorithm_oid(), AES_256_GCM);

		let opened = HpkeSecp256k1Decryptor::new(signing_key()?)?.open(sealed).await?;
		assert_eq!(opened, preimage);
		Ok(())
	}

	#[tokio::test]
	async fn hpke_open_rejects_wrong_secret() -> TestResult {
		let recipient_public = signing_key()?.verifying_key().to_sec1_bytes().to_vec();
		let encryptor = HpkeSecp256k1Encryptor::from_sec1(&recipient_public)?;
		let sealed = encryptor.seal(sample_body()?, None)?;

		let stranger_key = Secp256k1SigningKey::from_bytes(&[2u8; 32].into())?;
		let stranger = HpkeSecp256k1Decryptor::new(stranger_key)?;
		assert!(stranger.open(sealed).await.is_err());
		Ok(())
	}

	/// A splice of a sealed body keeps the frame gate: V0 forbids
	/// confidentiality.
	#[test]
	fn a_v0_frame_refuses_an_envelope() -> TestResult {
		let der = seal_frame(b"v0-sealed", 1)?;
		let sealed = shared_key(0x42).seal(sample_body()?, None)?;

		let installed = FrameAssembly::decode(&der)?.with_confidentiality(sealed);
		assert!(installed.is_err());
		Ok(())
	}

	/// A sealed frame refuses a commitment preimage, even when its ciphertext
	/// happens to parse as one DER value.
	#[test]
	fn a_sealed_frame_whose_ciphertext_parses_as_der_is_refused() -> TestResult {
		let der = pinned_config(b"sealed-der", 1, Version::V1)?.build()?;
		let sealed = shared_key(0x42).seal(sample_body()?, None)?;
		let der_ciphertext = SealedBody::new(sealed.envelope_der(), vec![0x04, 0x01, 0xAA])?;
		let assembly = FrameAssembly::decode(&der)?.with_confidentiality(der_ciphertext)?;

		let refused = assembly.commitment_preimage(&CommitmentSalt::parse([])?);
		assert!(matches!(refused, Err(TightBeamError::OpaqueBody(BodyTransform::Decrypt))));
		Ok(())
	}

	/// `SealedBody::new` parses the envelope once, so bytes that are no
	/// `AuthEnvelopedData` refuse there.
	#[test]
	fn a_malformed_envelope_is_refused() {
		let sealed = SealedBody::new(&[0x30, 0x00], vec![1, 2, 3]);
		assert!(sealed.is_err());
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
		let body = vec![0x04, 0x02, 0xBB, 0xBB];
		let salt = [0xAAu8; 16];
		let body_der = BodyDer::try_from(body.clone())?;

		let plain = body_der.commitment_preimage(&CommitmentSalt::parse([])?);
		assert_eq!(plain.first(), Some(&0x00));
		assert_eq!(&plain[1..], body.as_slice());

		let framed = body_der.commitment_preimage(&CommitmentSalt::parse(salt)?);
		assert_eq!(framed.first(), Some(&0x01));
		assert_eq!(&framed[1..9], &16u64.to_be_bytes());
		assert_eq!(&framed[9..25], &salt);
		assert_eq!(&framed[25..], body.as_slice());
		Ok(())
	}

	// A body holds exactly one DER value, so octets that hold none, or more
	// than one, refuse with `SerializationError`.
	tb_cases! {
		fn a_body_that_is_not_one_der_value_is_refused(octets: Vec<u8>) {
			let refused = BodyDer::try_from(octets);
			assert!(matches!(refused, Err(TightBeamError::SerializationError(_))));
		}
		cases {
			empty => Vec::new(),
			truncated => vec![0x04, 0x05, 0xBB],
			trailing => vec![0x04, 0x01, 0xBB, 0x00],
		}
	}

	#[test]
	fn body_preimage_round_trips_through_decode() -> TestResult {
		let preimage = BodyDer::opaque(sample_message())?;
		assert_eq!(preimage.opaque_message()?, sample_message());
		Ok(())
	}

	/// A caller-side zstd compression (compress + install) must carry the
	/// exact compactness info tightbeam's own compressor emits, and inflate
	/// with tightbeam's inflator: pins the encoded layout of the compactness
	/// info.
	#[test]
	fn caller_side_compression_inflates_with_tightbeam() -> TestResult {
		let der = seal_frame(b"packed", 5)?;

		let compressor = ZstdCompression::default();
		let (compressed, info) = compressor.compress(&sample_body()?, None)?;
		let compactness = Compactness {
			algorithm_oid: info.compression_alg.oid,
			parameters_der: None,
			content_oid: None,
			compressed,
		};

		let der = FrameAssembly::decode(&der)?.with_compactness(compactness)?.encode()?;
		let mut frame = Frame::from_der(&der)?;
		assert_eq!(frame.metadata().compactness(), Some(&info));

		let _opened = frame.inflate_in_place(&compressor)?;
		assert_eq!(BodyDer::try_from(frame.message().to_vec())?.opaque_message()?, sample_message());
		Ok(())
	}

	/// The commitment that `Opening::prove::<Sha3_256>` publishes over the
	/// shared opening fixture is the digest that `commitment.test.ts` pins.
	#[test]
	fn opening_commitment_matches_typescript_fixture() -> TestResult {
		const FIXTURE_HEX: &str = "678bec1605c349a2af6ceaa627569d31d57759ee2fbeffd2ac33026df930e04e";

		let body = Opaque::new(opening_payload())?;
		let (commitment, opening) = Opening::prove::<Sha3_256, _>(&body, opening_salt())?;

		assert_eq!(commitment.digest.as_bytes(), unhex(FIXTURE_HEX));
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

	/// A compressed-then-sealed body must open through tightbeam's own
	/// decrypt-and-inflate pipeline: pins the compress-before-encrypt order.
	#[tokio::test]
	async fn compressed_then_sealed_body_decrypts_with_tightbeam() -> TestResult {
		let key = [0x42u8; 32];
		let der = pinned_config(b"packed-sealed", 6, Version::V1)?.build()?;

		let compressor = ZstdCompression::default();
		let (compressed, info) = compressor.compress(&sample_body()?, None)?;
		let sealed = shared_key(0x42).seal(&compressed, None)?;
		let compactness = Compactness {
			algorithm_oid: info.compression_alg.oid,
			parameters_der: None,
			content_oid: None,
			compressed,
		};

		let assembly = FrameAssembly::decode(&der)?.with_compactness(compactness)?;
		let der = assembly.with_confidentiality(sealed)?.encode()?;

		let holder = Aes256GcmKeyProvider::new(key.to_vec(), KEY_ID.to_vec())?;
		let mut frame = Frame::from_der(&der)?;
		let _opened = frame.decrypt_in_place(&holder, Some(&compressor)).await?;
		assert_eq!(BodyDer::try_from(frame.message().to_vec())?.opaque_message()?, sample_message());
		Ok(())
	}

	#[test]
	fn inspect_reports_compactness() -> TestResult {
		let der = seal_frame(b"packed-view", 7)?;

		let compressor = ZstdCompression::default();
		let (compressed, info) = compressor.compress(&sample_body()?, None)?;
		let compactness = Compactness {
			algorithm_oid: info.compression_alg.oid,
			parameters_der: None,
			content_oid: None,
			compressed: compressed.clone(),
		};
		let der = FrameAssembly::decode(&der)?.with_compactness(compactness)?.encode()?;

		let (data, compactness) = compressed_body(summary_of(&der)?.body)?;
		assert_eq!(compactness.algorithm_oid.to_string(), "1.3.6.1.4.1.64586.2.1");
		assert_eq!(compactness.content_oid.to_string(), "1.2.840.113549.1.7.1");
		assert_eq!(compactness.parameters_der, None);
		assert_eq!(data, compressed);
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

		let mut config = base_config(b"typed", 1)?;
		config.with_message(BodyDer::try_from(body_der.clone())?);

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

		let mut config = pinned_config(b"typed-mi", 1, Version::V2)?;
		config.with_message(BodyDer::try_from(body_der.clone())?);

		let der = config.build()?;
		let body = BodyDer::try_from(body_der)?;
		let commitment = sha3_digest(body.commitment_preimage(&CommitmentSalt::parse(salt)?))?;
		let der = FrameAssembly::decode(&der)?.with_message_integrity(commitment)?.encode()?;

		let frame = Frame::from_der(&der)?;
		let (_, opening) = Opening::prove::<Sha3_256, _>(&doc, salt)?;
		assert!(matches!(
			frame.message_commitment_verdict::<Sha3_256>(&opening)?,
			IntegrityVerdict::Verified
		));
		Ok(())
	}
}
