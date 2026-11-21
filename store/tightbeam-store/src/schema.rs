//! The metadata of a stored frame that a driver indexes: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#the-metadata-schema).

use core::fmt;

use tightbeam::cms::enveloped_data::{KekIdentifier, KeyAgreeRecipientIdentifier, RecipientIdentifier};
use tightbeam::crypto::hash::{Digest, Sha3_256};
use tightbeam::der::Encode;

// The contract suite builds the rows of this release.
#[cfg(any(test, feature = "testing"))]
use {
	crate::error::StoreError,
	crate::row_key::RowKey,
	std::collections::BTreeSet,
	tightbeam::asn1::KemRecipientInfo,
	tightbeam::cms::enveloped_data::RecipientInfo,
	tightbeam::der::Decode,
	tightbeam::oids::ORI_KEM,
	tightbeam::utils::digest,
	tightbeam::{Frame, TightBeamError},
};

/// The longest value of a bytes field other than `row_id`, in bytes.
pub(crate) const MAX_BYTES: usize = 100;

/// The most recipients of one frame: the most `RecipientInfo` values that
/// tightbeam admits in one seal.
#[cfg(any(test, feature = "testing"))]
const MAX_RECIPIENTS: usize = 32;

/// The revision of how the core derives each value from a frame: SHA3-256
/// for the digest and each principal, and the key of each recipient kind.
/// A change of a derivation raises it, which changes the schema version.
const DERIVATION: u8 = 1;

/// The offset basis of the FNV-1a hash of a schema version.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

/// The prime of the FNV-1a hash of a schema version.
const FNV_PRIME: u64 = 0x0100_0000_01b3;

/// One queryable fact of a stored frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Field {
	/// The id of the row: `metadata.id`.
	RowId,
	/// The order of the frame: `metadata.order`.
	Order,
	/// The protocol version of the frame.
	Version,
	/// The SHA3-256 `DigestInfo` DER of the stored frame.
	Digest,
	/// The `DigestInfo` DER of the frame this frame follows.
	Previous,
	/// The `DigestInfo` DER of the message commitment.
	Commitment,
	/// The SHA3-256 of the signer identifier DER.
	Signer,
	/// The SHA3-256 of one [`RecipientKey`] of the seal.
	Recipient,
	/// The priority of the frame.
	Priority,
	/// The lifetime of the frame, as its writer means it.
	Lifetime,
	/// One [`Protection`] the frame carries.
	Protection,
}

impl Field {
	/// Every field, in the order of [`Schema::CURRENT`].
	pub const ALL: [Self; 11] = [
		Self::RowId,
		Self::Order,
		Self::Version,
		Self::Digest,
		Self::Previous,
		Self::Commitment,
		Self::Signer,
		Self::Recipient,
		Self::Priority,
		Self::Lifetime,
		Self::Protection,
	];

	/// The name of this field in `docs/store.md`.
	pub const fn name(self) -> &'static str {
		self.shape().0
	}

	/// The kind of the values of this field.
	pub const fn kind(self) -> FieldKind {
		self.shape().1
	}

	/// How many values of this field one row holds.
	pub const fn cardinality(self) -> Cardinality {
		self.shape().2
	}

	/// What the values of this field name.
	pub const fn role(self) -> Role {
		self.shape().3
	}

	/// The row of this field in the schema table.
	const fn shape(self) -> (&'static str, FieldKind, Cardinality, Role) {
		match self {
			Self::RowId => ("row_id", FieldKind::Bytes, Cardinality::One, Role::Key),
			Self::Order => ("order", FieldKind::U64, Cardinality::One, Role::Attribute),
			Self::Version => ("version", FieldKind::Ordinal, Cardinality::One, Role::Attribute),
			Self::Digest => ("digest", FieldKind::Bytes, Cardinality::One, Role::Identity),
			Self::Previous => ("previous", FieldKind::Bytes, Cardinality::Optional, Role::Reference),
			Self::Commitment => ("commitment", FieldKind::Bytes, Cardinality::Optional, Role::Attribute),
			Self::Signer => ("signer", FieldKind::Bytes, Cardinality::Optional, Role::Principal),
			Self::Recipient => ("recipient", FieldKind::Bytes, Cardinality::Many, Role::Principal),
			Self::Priority => ("priority", FieldKind::Ordinal, Cardinality::Optional, Role::Attribute),
			Self::Lifetime => ("lifetime", FieldKind::U64, Cardinality::Optional, Role::Attribute),
			Self::Protection => ("protection", FieldKind::Ordinal, Cardinality::Many, Role::Attribute),
		}
	}
}

impl fmt::Display for Field {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.name())
	}
}

/// The kind of the values of a [`Field`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldKind {
	/// Bytes, compared unsigned lexicographic.
	Bytes,
	/// A `u64`, compared unsigned.
	U64,
	/// A `u8` ordinal, compared by the declaration order of its enum:
	/// tightbeam's `Version` and `MessagePriority`, and [`Protection`].
	Ordinal,
}

/// How many values of a [`Field`] one row holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cardinality {
	/// Exactly one.
	One,
	/// None or one.
	Optional,
	/// Any number.
	Many,
}

/// What the values of a [`Field`] name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
	/// The row within its table.
	Key,
	/// A fact of the frame alone.
	Attribute,
	/// The frame itself, which [`Role::Reference`] values point at.
	Identity,
	/// The [`Role::Identity`] value of another frame of the table.
	Reference,
	/// A principal that many frames share.
	Principal,
}

/// One protection a frame carries, the value domain of [`Field::Protection`].
/// Its value is the ordinal of its declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protection {
	/// The frame carries a signature.
	Signed,
	/// The body is sealed to its recipients.
	Sealed,
	/// The body is compressed.
	Compressed,
	/// The metadata carries a message commitment.
	MessageIntegrity,
	/// The frame carries a frame integrity digest.
	FrameIntegrity,
}

impl Protection {
	/// Every protection, in the order of its ordinal.
	pub const ALL: [Self; 5] = [
		Self::Signed,
		Self::Sealed,
		Self::Compressed,
		Self::MessageIntegrity,
		Self::FrameIntegrity,
	];

	/// The name of this protection.
	pub const fn name(self) -> &'static str {
		match self {
			Self::Signed => "signed",
			Self::Sealed => "sealed",
			Self::Compressed => "compressed",
			Self::MessageIntegrity => "message_integrity",
			Self::FrameIntegrity => "frame_integrity",
		}
	}
}

impl From<Protection> for FieldValue {
	/// The [`Field::Protection`] value of `protection`.
	fn from(protection: Protection) -> Self {
		Self::Ordinal(protection as u8)
	}
}

/// One value of a [`Field`], of the [`FieldKind`] of its field.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldValue {
	/// The value of a [`FieldKind::Bytes`] field.
	Bytes(Vec<u8>),
	/// The value of a [`FieldKind::U64`] field.
	U64(u64),
	/// The value of a [`FieldKind::Ordinal`] field.
	Ordinal(u8),
}

impl FieldValue {
	/// The kind of this value.
	pub const fn kind(&self) -> FieldKind {
		match self {
			Self::Bytes(_) => FieldKind::Bytes,
			Self::U64(_) => FieldKind::U64,
			Self::Ordinal(_) => FieldKind::Ordinal,
		}
	}
}

/// The fields every table holds, which a native driver builds its model from.
///
/// # Examples
///
/// ```
/// use tightbeam_store::{Field, Schema};
///
/// assert_eq!(Schema::CURRENT.fields()[0], Field::RowId);
/// assert_ne!(Schema::CURRENT.version(), 0);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schema {
	fields: &'static [Field],
	hints: &'static [&'static [Field]],
}

impl Schema {
	/// The schema of this release.
	pub const CURRENT: Self = Self {
		fields: &Field::ALL,
		hints: &[
			&[Field::Order, Field::RowId],
			&[Field::Digest, Field::Order, Field::RowId],
			&[Field::Previous, Field::Order, Field::RowId],
			&[Field::Commitment, Field::Order, Field::RowId],
			&[Field::Signer, Field::Order, Field::RowId],
			&[Field::Recipient, Field::Order, Field::RowId],
			&[Field::Priority, Field::Order, Field::RowId],
			&[Field::Lifetime, Field::RowId],
			&[Field::RowId],
		],
	};

	/// A schema that no release holds, which the contract suite prepares to
	/// see a driver refuse it.
	#[cfg(any(test, feature = "testing"))]
	pub(crate) const FOREIGN: Self = Self { fields: &[Field::RowId], hints: &[] };

	/// The version of this schema: an FNV-1a hash of its field table, the
	/// protections in the order of their values, and the revision of how each
	/// value is derived, so a change of any changes it.
	pub const fn version(&self) -> u64 {
		let mut hash = FNV_OFFSET;
		let mut index = 0;
		while index < self.fields.len() {
			let field = self.fields[index];
			let shape = [field.kind() as u8, field.cardinality() as u8, field.role() as u8, 0xff];
			hash = Self::fnv(Self::fnv(hash, field.name().as_bytes()), &shape);
			index += 1;
		}

		let mut index = 0;
		while index < Protection::ALL.len() {
			hash = Self::fnv(Self::fnv(hash, Protection::ALL[index].name().as_bytes()), &[0xff]);
			index += 1;
		}

		Self::fnv(hash, &[DERIVATION])
	}

	/// The fields of each row.
	pub const fn fields(&self) -> &'static [Field] {
		self.fields
	}

	/// The access paths that the store keeps cheap, each as the fields of one
	/// index, in key order.
	pub const fn index_hints(&self) -> &'static [&'static [Field]] {
		self.hints
	}

	/// `hash` extended with `bytes`, in a `const` context.
	const fn fnv(mut hash: u64, bytes: &[u8]) -> u64 {
		let mut index = 0;
		while index < bytes.len() {
			hash ^= bytes[index] as u64;
			hash = hash.wrapping_mul(FNV_PRIME);
			index += 1;
		}

		hash
	}
}

/// The key of one recipient of a seal, from its CMS identifier.
///
/// A `kekri` recipient is its key identifier. A `ktri`, a KEM `ori`, and each
/// `kari` recipient are the DER of their recipient identifier. A `pwri`
/// recipient has no key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RecipientKey(Vec<u8>);

impl RecipientKey {
	/// The [`Field::Recipient`] value of this key: its SHA3-256.
	pub fn principal(&self) -> FieldValue {
		FieldValue::Bytes(Sha3_256::digest(&self.0).to_vec())
	}
}

#[cfg(any(test, feature = "testing"))]
impl RecipientKey {
	/// The keys of `info`: none for a `pwri` or a foreign `ori`, one each for
	/// the recipients of a `kari`.
	fn of(info: &RecipientInfo) -> Result<Vec<Self>, TightBeamError> {
		let keys = match info {
			RecipientInfo::Ktri(ktri) => vec![Self::try_from(&ktri.rid)?],
			RecipientInfo::Kari(kari) => {
				let keys = kari.recipient_enc_keys.iter().map(|key| Self::try_from(&key.rid));
				keys.collect::<Result<_, _>>()?
			}
			RecipientInfo::Kekri(kekri) => vec![Self::from(&kekri.kek_id)],
			RecipientInfo::Ori(ori) if ori.ori_type == ORI_KEM => {
				let kem = KemRecipientInfo::from_der(&ori.ori_value.to_der()?)?;
				vec![Self::try_from(&kem.rid)?]
			}
			RecipientInfo::Ori(_) | RecipientInfo::Pwri(_) => Vec::new(),
		};

		Ok(keys)
	}
}

impl TryFrom<&RecipientIdentifier> for RecipientKey {
	type Error = tightbeam::der::Error;

	/// The key of a `ktri` or KEM `ori` recipient.
	fn try_from(rid: &RecipientIdentifier) -> Result<Self, Self::Error> {
		rid.to_der().map(Self)
	}
}

impl TryFrom<&KeyAgreeRecipientIdentifier> for RecipientKey {
	type Error = tightbeam::der::Error;

	/// The key of one `kari` recipient.
	fn try_from(rid: &KeyAgreeRecipientIdentifier) -> Result<Self, Self::Error> {
		rid.to_der().map(Self)
	}
}

impl From<&KekIdentifier> for RecipientKey {
	/// The key of a `kekri` recipient.
	fn from(kek_id: &KekIdentifier) -> Self {
		Self(kek_id.kek_identifier.as_bytes().to_vec())
	}
}

/// The values of each [`Field`] of one stored frame, which the core derives
/// from the frame alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Projection {
	values: [Vec<FieldValue>; Field::ALL.len()],
}

impl Projection {
	/// The values of `field`, as many as its [`Cardinality`] admits.
	pub fn values(&self, field: Field) -> &[FieldValue] {
		&self.values[field as usize]
	}

	/// Each value with its field, in the order of [`Field::ALL`].
	pub fn iter(&self) -> impl Iterator<Item = (Field, &FieldValue)> {
		Field::ALL
			.into_iter()
			.flat_map(move |field| self.values(field).iter().map(move |value| (field, value)))
	}
}

#[cfg(any(test, feature = "testing"))]
impl Projection {
	/// The projection of `frame` at `key`, and the DER of the frame.
	///
	/// # Errors
	///
	/// - [`StoreError::FieldLength`] -- a `previous` or `commitment` value holds more than 100 bytes.
	/// - [`StoreError::FieldCount`] -- the seal names more than 32 recipients.
	/// - [`StoreError::Frame`] -- the frame, a digest, or a recipient identifier does not encode.
	pub(crate) fn of(key: &RowKey, frame: &Frame) -> Result<(Self, Vec<u8>), StoreError> {
		let framing = |error: TightBeamError| StoreError::Frame(error);
		let encoding = |error: tightbeam::der::Error| StoreError::Frame(error.into());
		let metadata = frame.metadata();
		let bytes = frame.to_der().map_err(encoding)?;
		let digested = digest::<Sha3_256>(&bytes).map_err(framing)?.to_der().map_err(encoding)?;
		let previous = metadata.previous_frame().map(Encode::to_der).transpose().map_err(encoding)?;
		let commitment = metadata.integrity().map(Encode::to_der).transpose().map_err(encoding)?;
		let previous = Self::bounded(Field::Previous, previous)?;
		let commitment = Self::bounded(Field::Commitment, commitment)?;
		let recipients = Self::recipients(frame)?;
		let row_id: &[u8] = key.row_id().as_ref();
		let protections = [
			(Protection::Signed, frame.nonrepudiation().is_some()),
			(Protection::Sealed, metadata.confidentiality().is_some()),
			(Protection::Compressed, metadata.compactness().is_some()),
			(Protection::MessageIntegrity, metadata.integrity().is_some()),
			(Protection::FrameIntegrity, frame.integrity().is_some()),
		];

		let values = Field::ALL.map(|field| match field {
			Field::RowId => vec![FieldValue::Bytes(row_id.to_vec())],
			Field::Order => vec![FieldValue::U64(metadata.order())],
			Field::Version => vec![FieldValue::Ordinal(frame.version() as u8)],
			Field::Digest => vec![FieldValue::Bytes(digested.clone())],
			Field::Previous => previous.clone(),
			Field::Commitment => commitment.clone(),
			Field::Signer => frame
				.signer_id()
				.map(|id| FieldValue::Bytes(Sha3_256::digest(id).to_vec()))
				.into_iter()
				.collect(),
			Field::Recipient => recipients.clone(),
			Field::Priority => metadata
				.priority()
				.map(|priority| FieldValue::Ordinal(priority as u8))
				.into_iter()
				.collect(),
			Field::Lifetime => metadata.lifetime().map(FieldValue::U64).into_iter().collect(),
			Field::Protection => protections
				.into_iter()
				.filter(|(_, carried)| *carried)
				.map(|(protection, _)| FieldValue::from(protection))
				.collect(),
		});

		Ok((Self { values }, bytes))
	}

	/// The distinct [`Field::Recipient`] values of the seal of `frame`, in
	/// byte order.
	///
	/// # Errors
	///
	/// - [`StoreError::FieldCount`] -- the seal names more than 32 recipients.
	/// - [`StoreError::Frame`] -- a recipient identifier does not encode.
	fn recipients(frame: &Frame) -> Result<Vec<FieldValue>, StoreError> {
		let Some(sealed) = frame.metadata().confidentiality() else {
			return Ok(Vec::new());
		};

		Self::principals(sealed.recipient_infos.0.iter())
	}

	/// The distinct [`Field::Recipient`] values of `infos`, in byte order.
	///
	/// # Errors
	///
	/// - [`StoreError::FieldCount`] -- `infos` name more than 32 recipients.
	/// - [`StoreError::Frame`] -- a recipient identifier does not encode.
	fn principals<'a>(infos: impl IntoIterator<Item = &'a RecipientInfo>) -> Result<Vec<FieldValue>, StoreError> {
		let mut keys = Vec::new();
		for info in infos {
			keys.extend(RecipientKey::of(info).map_err(StoreError::Frame)?);
			if keys.len() > MAX_RECIPIENTS {
				return Err(StoreError::FieldCount { field: Field::Recipient });
			}
		}

		let principals: BTreeSet<FieldValue> = keys.iter().map(RecipientKey::principal).collect();
		Ok(principals.into_iter().collect())
	}

	/// The values of the bytes field `field` from `bytes`.
	///
	/// # Errors
	///
	/// - [`StoreError::FieldLength`] -- `bytes` holds more than 100 bytes.
	fn bounded(field: Field, bytes: Option<Vec<u8>>) -> Result<Vec<FieldValue>, StoreError> {
		match bytes {
			Some(bytes) if bytes.len() > MAX_BYTES => Err(StoreError::FieldLength { field, length: bytes.len() }),
			Some(bytes) => Ok(vec![FieldValue::Bytes(bytes)]),
			None => Ok(Vec::new()),
		}
	}
}

#[cfg(test)]
mod tests {
	use tightbeam::builder::{FrameBuilder, TypeBuilder};
	use tightbeam::cms::cert::IssuerAndSerialNumber;
	use tightbeam::cms::content_info::CmsVersion;
	use tightbeam::cms::enveloped_data::{
		KekRecipientInfo, KeyAgreeRecipientInfo, KeyTransRecipientInfo, OriginatorIdentifierOrKey, OtherRecipientInfo,
		PasswordRecipientInfo, RecipientEncryptedKey, RecipientKeyIdentifier,
	};
	use tightbeam::compress::ZstdCompression;
	use tightbeam::crypto::sign::ecdsa::Secp256k1Signature;
	use tightbeam::der::asn1::{ObjectIdentifier, OctetString};
	use tightbeam::der::Any;
	use tightbeam::oids::DATA;
	use tightbeam::spki::AlgorithmIdentifierOwned;
	use tightbeam::testing::{SeededStream, TestIdentity, TestKey, TestMessage};
	use tightbeam::x509::ext::pkix::SubjectKeyIdentifier;
	use tightbeam::x509::name::Name;
	use tightbeam::x509::serial_number::SerialNumber;
	use tightbeam::{DigestInfo, MessagePriority, Version};

	use super::*;
	use crate::frame_type::FrameType;
	use crate::row_id::RowId;

	/// The key identifier of the key-encryption key of the test cipher.
	const KEK_ID: &[u8] = b"tb/test/kek/v1";

	/// An object identifier of no recipient kind of the store.
	const FOREIGN_ORI: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.7");

	/// The builder of a frame of `version` under the id `leaf` at order 7.
	fn builder(version: Version) -> FrameBuilder<TestMessage> {
		FrameBuilder::from(version)
			.with_message(TestMessage::sample(None))
			.with_id("leaf")
			.with_order(7)
	}

	/// The digest of the frame that the test frames follow.
	fn parent() -> DigestInfo {
		digest::<Sha3_256>(b"parent").expect("a SHA3-256 digest builds")
	}

	/// The frames of the tests, by name.
	fn frame(name: &str) -> Frame {
		let builder = match name {
			"plain" => builder(Version::V0),
			"first" => builder(Version::V1),
			"chained" => builder(Version::V2)
				.with_priority(MessagePriority::Expedited)
				.with_lifetime(3600)
				.with_previous_hash(parent()),
			"committed" => builder(Version::V1).with_message_hasher::<Sha3_256>(b""),
			"witnessed" => builder(Version::V1).with_witness_hasher::<Sha3_256>(),
			"signed" => builder(Version::V1)
				.with_signer::<Secp256k1Signature, _>(TestIdentity::certified(TestKey::insecure_fixed_signing())),
			"sealed" => {
				let (_, cipher) = TestKey::insecure_fixed_cipher();
				builder(Version::V1).with_encryptor(cipher).with_rng(SeededStream(0))
			}
			"compressed" => builder(Version::V1).with_compression(ZstdCompression::default()),
			_ => unreachable!("no test frame is named {name}"),
		};

		builder.build().expect("each test frame builds")
	}

	/// The key of the test frames.
	fn key() -> RowKey {
		let row_id = RowId::from(*b"leaf");
		RowKey::new(FrameType::from_static("colony-leaf"), row_id).expect("the test key builds")
	}

	/// The projection of the test frame `name`.
	fn projected(name: &str) -> Result<Projection, StoreError> {
		Projection::of(&key(), &frame(name)).map(|(projection, _)| projection)
	}

	// Each field projects the metadata of a frame that it names.
	tightbeam::tb_cases! {
		fn a_frame_projects_each_field((name, field, expected): (&str, Field, Vec<FieldValue>)) -> Result<(), StoreError> {
			assert_eq!(projected(name)?.values(field), expected);
			Ok(())
		}
		cases {
			row_id => ("plain", Field::RowId, vec![FieldValue::Bytes(b"leaf".to_vec())]),
			order => ("plain", Field::Order, vec![FieldValue::U64(7)]),
			version_0 => ("plain", Field::Version, vec![FieldValue::Ordinal(0)]),
			version_1 => ("first", Field::Version, vec![FieldValue::Ordinal(1)]),
			version_2 => ("chained", Field::Version, vec![FieldValue::Ordinal(2)]),
			previous => ("chained", Field::Previous, vec![FieldValue::Bytes(parent().to_der().unwrap_or_default())]),
			no_previous => ("plain", Field::Previous, vec![]),
			priority => ("chained", Field::Priority, vec![FieldValue::Ordinal(4)]),
			no_priority => ("plain", Field::Priority, vec![]),
			lifetime => ("chained", Field::Lifetime, vec![FieldValue::U64(3600)]),
			no_lifetime => ("plain", Field::Lifetime, vec![]),
			recipient => ("sealed", Field::Recipient, vec![FieldValue::Bytes(Sha3_256::digest(KEK_ID).to_vec())]),
			no_recipient => ("plain", Field::Recipient, vec![]),
			no_signer => ("plain", Field::Signer, vec![]),
			no_commitment => ("plain", Field::Commitment, vec![]),
			no_protection => ("plain", Field::Protection, vec![]),
			signed => ("signed", Field::Protection, vec![FieldValue::Ordinal(0)]),
			sealed => ("sealed", Field::Protection, vec![FieldValue::Ordinal(1)]),
			compressed => ("compressed", Field::Protection, vec![FieldValue::Ordinal(2)]),
			committed => ("committed", Field::Protection, vec![FieldValue::Ordinal(3)]),
			witnessed => ("witnessed", Field::Protection, vec![FieldValue::Ordinal(4)]),
		}
	}

	// The digest is the SHA3-256 of the frame DER that the projection hands
	// back, the commitment is the DER of the metadata commitment, and the
	// signer is the SHA3-256 of the identifier of the signature.
	#[test]
	fn a_frame_projects_its_digests() -> Result<(), Box<dyn core::error::Error>> {
		let plain = frame("plain");
		let (projection, bytes) = Projection::of(&key(), &plain)?;
		let hashed = plain.compute_hash::<Sha3_256>()?.to_der()?;
		assert_eq!(bytes, plain.to_der()?);
		assert_eq!(projection.values(Field::Digest), [FieldValue::Bytes(hashed)]);

		let committed = frame("committed");
		let commitment = committed.metadata().integrity().map(Encode::to_der).transpose()?;
		assert_eq!(
			projected("committed")?.values(Field::Commitment),
			[FieldValue::Bytes(commitment.unwrap_or_default())]
		);

		let signed = frame("signed");
		let sid = signed.nonrepudiation().map(|signature| signature.sid.to_der()).transpose()?;
		let hashed = FieldValue::Bytes(Sha3_256::digest(sid.unwrap_or_default()).to_vec());
		assert_eq!(projected("signed")?.values(Field::Signer), [hashed]);
		Ok(())
	}

	/// An algorithm of the recipient infos of the tests.
	fn algorithm() -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: DATA, parameters: None }
	}

	/// An octet string of `bytes`.
	fn octets(bytes: &[u8]) -> OctetString {
		OctetString::new(bytes).expect("a short octet string builds")
	}

	/// The recipient identifier of a certificate of serial `serial`.
	fn issued(serial: u8) -> RecipientIdentifier {
		let serial_number = SerialNumber::new(&[serial]).expect("a one-byte serial builds");
		RecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber { issuer: Name::default(), serial_number })
	}

	/// The recipient info of a key transport to `rid`.
	fn ktri(rid: RecipientIdentifier) -> RecipientInfo {
		RecipientInfo::Ktri(KeyTransRecipientInfo {
			version: CmsVersion::V0,
			rid,
			key_enc_alg: algorithm(),
			enc_key: octets(b"wrapped"),
		})
	}

	/// The recipient info of a key agreement with the recipients of `ids`.
	fn kari(ids: &[&[u8]]) -> RecipientInfo {
		let recipient_enc_keys = ids
			.iter()
			.map(|id| {
				let subject_key_identifier = SubjectKeyIdentifier(octets(id));
				let identifier = RecipientKeyIdentifier { subject_key_identifier, date: None, other: None };
				RecipientEncryptedKey {
					rid: KeyAgreeRecipientIdentifier::RKeyId(identifier),
					enc_key: octets(b"wrapped"),
				}
			})
			.collect();
		let originator = OriginatorIdentifierOrKey::SubjectKeyIdentifier(SubjectKeyIdentifier(octets(b"sender")));
		RecipientInfo::Kari(KeyAgreeRecipientInfo {
			version: CmsVersion::V3,
			originator,
			ukm: None,
			key_enc_alg: algorithm(),
			recipient_enc_keys,
		})
	}

	/// The recipient info of a key-encryption key of id `id`.
	fn kekri(id: &[u8]) -> RecipientInfo {
		let kek_id = KekIdentifier { kek_identifier: octets(id), date: None, other: None };
		RecipientInfo::Kekri(KekRecipientInfo {
			version: CmsVersion::V4,
			kek_id,
			key_enc_alg: algorithm(),
			encrypted_key: octets(b"wrapped"),
		})
	}

	/// The recipient info of a KEM recipient `rid`.
	fn kem(rid: RecipientIdentifier) -> RecipientInfo {
		let kem = KemRecipientInfo {
			version: CmsVersion::V0,
			rid,
			kem: algorithm(),
			kemct: octets(b"ciphertext"),
			kdf: algorithm(),
			kek_length: 32,
			ukm: None,
			wrap: algorithm(),
			encrypted_key: octets(b"wrapped"),
		};
		let ori_value = Any::encode_from(&kem).expect("a KEM recipient info encodes");
		RecipientInfo::Ori(OtherRecipientInfo { ori_type: ORI_KEM, ori_value })
	}

	/// The DER of `rid`.
	fn der(rid: &impl Encode) -> Vec<u8> {
		rid.to_der().expect("a recipient identifier encodes")
	}

	// Each recipient kind keys its recipients as the schema names them, and a
	// KEM value that holds no KEM recipient info does not project.
	tightbeam::tb_cases! {
		fn a_recipient_info_keys_its_recipients((info, expected): (RecipientInfo, Option<Vec<Vec<u8>>>)) {
			let keys = RecipientKey::of(&info).ok().map(|keys| keys.into_iter().map(|key| key.0).collect::<Vec<_>>());
			assert_eq!(keys, expected);
		}
		cases {
			ktri_issued => (ktri(issued(7)), Some(vec![der(&issued(7))])),
			ktri_by_key_id => (
				ktri(RecipientIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(octets(b"ski")))),
				Some(vec![der(&RecipientIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(octets(b"ski"))))]),
			),
			kari_of_two => (kari(&[b"left", b"right"]), Some(kari_keys(&[b"left", b"right"]))),
			kekri => (kekri(b"kek"), Some(vec![b"kek".to_vec()])),
			kem => (kem(issued(9)), Some(vec![der(&issued(9))])),
			pwri => (
				RecipientInfo::Pwri(PasswordRecipientInfo { version: CmsVersion::V0, key_derivation_alg: None, key_enc_alg: algorithm(), enc_key: octets(b"wrapped") }),
				Some(vec![]),
			),
			foreign_ori => (
				RecipientInfo::Ori(OtherRecipientInfo { ori_type: FOREIGN_ORI, ori_value: Any::encode_from(&octets(b"x")).expect("an octet string encodes") }),
				Some(vec![]),
			),
			kem_of_junk => (
				RecipientInfo::Ori(OtherRecipientInfo { ori_type: ORI_KEM, ori_value: Any::encode_from(&octets(b"x")).expect("an octet string encodes") }),
				None,
			),
		}
	}

	/// The DER of the `kari` recipient identifiers of `ids`.
	fn kari_keys(ids: &[&[u8]]) -> Vec<Vec<u8>> {
		let RecipientInfo::Kari(info) = kari(ids) else {
			return Vec::new();
		};

		info.recipient_enc_keys.iter().map(|key| der(&key.rid)).collect()
	}

	// The recipients of a seal project once each, in byte order, and a seal of
	// more than 32 recipients does not project.
	tightbeam::tb_cases! {
		fn a_seal_projects_distinct_recipients((infos, expected): (Vec<RecipientInfo>, Option<usize>)) {
			let principals = Projection::principals(&infos);
			let sorted = principals.as_ref().map(|values| values.windows(2).all(|pair| pair[0] < pair[1]));
			assert_eq!(principals.as_ref().ok().map(Vec::len), expected);
			assert!(matches!(principals, Ok(_) | Err(StoreError::FieldCount { field: Field::Recipient })));
			assert!(sorted.unwrap_or(true));
		}
		cases {
			two_kinds_of_one_recipient => (vec![ktri(issued(7)), kem(issued(7)), kekri(b"kek")], Some(2)),
			a_kari_of_one_recipient_twice => (vec![kari(&[b"same", b"same"])], Some(1)),
			thirty_two => (vec![kari(&[b"k".as_slice(); 31]), kekri(b"other")], Some(2)),
			thirty_three => (vec![kari(&[b"k".as_slice(); 32]), kekri(b"other")], None),
		}
	}

	// A bytes value of 100 bytes projects, and one of 101 does not, in each
	// field that a frame bounds.
	tightbeam::tb_cases! {
		fn a_bytes_field_holds_100_bytes((field, length, refused): (Field, usize, bool)) {
			let bounded = Projection::bounded(field, Some(vec![0xab; length]));
			let expected = refused.then_some((field, length));
			let answered = match bounded {
				Err(StoreError::FieldLength { field, length }) => Some((field, length)),
				_ => None,
			};
			assert_eq!(answered, expected);
		}
		cases {
			previous_at_the_bound => (Field::Previous, MAX_BYTES, false),
			previous_past_the_bound => (Field::Previous, MAX_BYTES + 1, true),
			commitment_at_the_bound => (Field::Commitment, MAX_BYTES, false),
			commitment_past_the_bound => (Field::Commitment, MAX_BYTES + 1, true),
		}
	}

	// A frame whose `previous` digest holds more than 100 bytes does not
	// project.
	#[test]
	fn a_long_previous_digest_does_not_project() -> Result<(), TightBeamError> {
		let algorithm = parent().algorithm;
		let digest = OctetString::new(vec![0xab; MAX_BYTES])?;
		let frame = builder(Version::V2)
			.with_previous_hash(DigestInfo { algorithm, digest })
			.build()?;

		let projected = Projection::of(&key(), &frame);
		assert!(matches!(projected, Err(StoreError::FieldLength { field: Field::Previous, .. })));
		Ok(())
	}

	// The values of a projection iterate by field, in the order of the schema.
	#[test]
	fn a_projection_iterates_by_field() -> Result<(), StoreError> {
		let projection = projected("chained")?;
		let fields: Vec<Field> = projection.iter().map(|(field, _)| field).collect();
		let expected = [
			Field::RowId,
			Field::Order,
			Field::Version,
			Field::Digest,
			Field::Previous,
			Field::Priority,
			Field::Lifetime,
		];
		assert_eq!(fields, expected);
		Ok(())
	}

	// Each field carries its row of the schema table.
	tightbeam::tb_cases! {
		fn a_field_carries_its_row((field, row): (Field, (&str, FieldKind, Cardinality, Role))) {
			assert_eq!((field.name(), field.kind(), field.cardinality(), field.role()), row);
			assert_eq!(field.to_string(), row.0);
		}
		cases {
			row_id => (Field::RowId, ("row_id", FieldKind::Bytes, Cardinality::One, Role::Key)),
			order => (Field::Order, ("order", FieldKind::U64, Cardinality::One, Role::Attribute)),
			version => (Field::Version, ("version", FieldKind::Ordinal, Cardinality::One, Role::Attribute)),
			digest => (Field::Digest, ("digest", FieldKind::Bytes, Cardinality::One, Role::Identity)),
			previous => (Field::Previous, ("previous", FieldKind::Bytes, Cardinality::Optional, Role::Reference)),
			commitment => (Field::Commitment, ("commitment", FieldKind::Bytes, Cardinality::Optional, Role::Attribute)),
			signer => (Field::Signer, ("signer", FieldKind::Bytes, Cardinality::Optional, Role::Principal)),
			recipient => (Field::Recipient, ("recipient", FieldKind::Bytes, Cardinality::Many, Role::Principal)),
			priority => (Field::Priority, ("priority", FieldKind::Ordinal, Cardinality::Optional, Role::Attribute)),
			lifetime => (Field::Lifetime, ("lifetime", FieldKind::U64, Cardinality::Optional, Role::Attribute)),
			protection => (Field::Protection, ("protection", FieldKind::Ordinal, Cardinality::Many, Role::Attribute)),
		}
	}

	// Each protection is the value of its ordinal, under its name.
	tightbeam::tb_cases! {
		fn a_protection_is_its_ordinal((protection, ordinal, name): (Protection, u8, &str)) {
			assert_eq!(Protection::ALL[usize::from(ordinal)], protection);
			assert_eq!(FieldValue::from(protection), FieldValue::Ordinal(ordinal));
			assert_eq!(protection.name(), name);
		}
		cases {
			signed => (Protection::Signed, 0, "signed"),
			sealed => (Protection::Sealed, 1, "sealed"),
			compressed => (Protection::Compressed, 2, "compressed"),
			message_integrity => (Protection::MessageIntegrity, 3, "message_integrity"),
			frame_integrity => (Protection::FrameIntegrity, 4, "frame_integrity"),
		}
	}

	// Each value names its kind.
	tightbeam::tb_cases! {
		fn a_value_names_its_kind((value, kind): (FieldValue, FieldKind)) {
			assert_eq!(value.kind(), kind);
		}
		cases {
			bytes => (FieldValue::Bytes(vec![1]), FieldKind::Bytes),
			number => (FieldValue::U64(1), FieldKind::U64),
			ordinal => (FieldValue::Ordinal(1), FieldKind::Ordinal),
		}
	}

	// The FNV-1a hash of a schema version answers the published test vectors.
	tightbeam::tb_cases! {
		fn the_version_hash_is_fnv_1a((bytes, hash): (&[u8], u64)) {
			assert_eq!(Schema::fnv(FNV_OFFSET, bytes), hash);
		}
		cases {
			empty => (b"", 0xcbf2_9ce4_8422_2325),
			one_byte => (b"a", 0xaf63_dc4c_8601_ec8c),
			a_word => (b"foobar", 0x8594_4171_f739_67e8),
		}
	}

	// The schema of this release holds every field and its persisted version,
	// a foreign schema holds another, and each index hint ends at the row id,
	// which breaks every tie.
	#[test]
	fn the_current_schema_holds_every_field() {
		assert_eq!(Schema::CURRENT.fields(), Field::ALL);
		assert_eq!(Schema::CURRENT.version(), CURRENT_VERSION);
		assert_ne!(Schema::CURRENT.version(), Schema::FOREIGN.version());
		assert!(Schema::CURRENT
			.index_hints()
			.iter()
			.all(|hint| hint.last() == Some(&Field::RowId)));
	}

	/// The version that backends of this release hold.
	const CURRENT_VERSION: u64 = 0xfaf0_490e_50cc_b45e;
}
