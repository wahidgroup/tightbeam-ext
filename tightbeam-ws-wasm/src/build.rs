//! Frame assembly over opaque message bytes.
//!
//! TODO:
//! Security operations are concrete (no generics cross the wasm boundary):
//! the [`FrameConfig`] collects algorithm-fixed selections (secp256k1 /
//! sha3-256 / aes-256-gcm under the tightbeam profile) and drives the builder.

use der::asn1::OctetString;
use der::{Decode, Sequence};

use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
use tightbeam::der::Encode;
use tightbeam::matrix::MatrixDyn;
use tightbeam::{Beamable, DigestInfo, Frame, MessagePriority, ObjectIdentifier, TightBeamError, Version};

/// Opaque payload wrapper carried as the frame body.
#[derive(Beamable, Clone, Debug, PartialEq, Eq, Sequence)]
#[beam(min_version = "V0")]
struct OpaqueBody {
	body: OctetString,
}

/// A concrete signer selection. The variant fixes both the key and its
/// signature algorithm, so the wasm boundary never sees a generic.
/// TODO: Add more signer kinds.
#[derive(Clone)]
pub enum SignerKind {
	/// secp256k1 ECDSA over sha3-256 (the tightbeam profile signature).
	Secp256k1(Secp256k1SigningKey),
}

/// The options for building a frame.
#[derive(Default)]
pub struct FrameOptions<'a> {
	/// Sign the assembled frame (sets `nonrepudiation`).
	pub signer: Option<&'a SignerKind>,
	/// Commit to the message body with sha3-256 (sets `metadata.integrity`).
	pub message_integrity: bool,
	/// Witness the envelope with sha3-256 (sets `frame.integrity`).
	pub frame_integrity: bool,
}

/// Full frame specification. Every optional field maps one-to-one to a
/// [`FrameBuilder`] `with_*` method; absent fields are simply not applied. The
/// version is derived from the requested fields unless pinned explicitly.
#[derive(Default)]
pub struct FrameConfig {
	/// Protocol version; when `None` uses the floor for the requested fields
	pub version: Option<Version>,
	/// Opaque message identifier.
	pub id: Vec<u8>,
	/// Monotonic order (Unix seconds).
	pub order: u64,
	/// Opaque message body.
	pub message: Vec<u8>,
	/// Body content-type OID.
	pub content_oid: Option<ObjectIdentifier>,
	/// Message priority (V2+).
	pub priority: Option<MessagePriority>,
	/// Time-to-live in seconds (V2+).
	pub lifetime: Option<u64>,
	/// Parent-frame link by content digest (V2+).
	pub previous_hash: Option<DigestInfo>,
	/// N×N control matrix (V2+).
	pub matrix: Option<MatrixDyn>,
	/// Message-body integrity salt (`Some` enables sha3-256 commitment; the
	/// salt may be empty).
	pub message_integrity_salt: Option<Vec<u8>>,
	/// Witness the envelope with sha3-256 frame integrity (V2+).
	pub frame_integrity: bool,
	/// Local (in-process) signer (V1+).
	pub signer: Option<SignerKind>,
}

impl FrameConfig {
	/// Lowest frame version that admits the requested fields. The matrix is a
	/// V3 feature; integrity, priority, lifetime, and previous-hash are V2
	/// features; signing is a V1 feature; a bare payload stays at V0.
	fn effective_version(&self) -> Version {
		if let Some(version) = self.version {
			return version;
		}

		if self.matrix.is_some() {
			return Version::V3;
		}

		if self.message_integrity_salt.is_some()
			|| self.frame_integrity
			|| self.priority.is_some()
			|| self.lifetime.is_some()
			|| self.previous_hash.is_some()
		{
			return Version::V2;
		}

		if self.signer.is_some() {
			return Version::V1;
		}

		Version::V0
	}

	/// Assemble the frame, applying every configured field, and return DER.
	pub fn build(self) -> Result<Vec<u8>, TightBeamError> {
		let body = OpaqueBody { body: OctetString::new(self.message.as_slice())? };

		let mut builder = FrameBuilder::<OpaqueBody>::from(self.effective_version())
			.with_id(self.id)
			.with_order(self.order)
			.with_message(body);

		if let Some(oid) = self.content_oid {
			builder = builder.with_content_oid(oid);
		}
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
		if let Some(salt) = self.message_integrity_salt {
			builder = builder.with_message_hasher::<Sha3_256>(salt);
		}
		if self.frame_integrity {
			builder = builder.with_witness_hasher::<Sha3_256>();
		}
		if let Some(SignerKind::Secp256k1(key)) = self.signer {
			builder = builder.with_signer::<Secp256k1Signature, _>(key);
		}

		let frame = builder.build()?;
		Ok(frame.to_der()?)
	}
}

/// Build a tightbeam frame around `message`, applying the requested security
/// operations, and return the frame DER ready for the transport.
pub fn build_frame(
	message: impl AsRef<[u8]>,
	id: impl AsRef<[u8]>,
	order: u64,
	options: FrameOptions<'_>,
) -> Result<Vec<u8>, TightBeamError> {
	let message_integrity_salt = if options.message_integrity {
		Some(Vec::new())
	} else {
		None
	};

	let config = FrameConfig {
		id: id.as_ref().to_vec(),
		order,
		message: message.as_ref().to_vec(),
		message_integrity_salt,
		frame_integrity: options.frame_integrity,
		signer: options.signer.cloned(),
		..Default::default()
	};

	config.build()
}

/// Wrap a payload in a cleartext frame (no signing or integrity), returning DER.
pub fn seal_frame(message: impl AsRef<[u8]>, id: impl AsRef<[u8]>, order: u64) -> Result<Vec<u8>, TightBeamError> {
	build_frame(message, id, order, FrameOptions::default())
}

/// Extract the payload body from a frame DER.
///
/// TODO:
/// Decodes the [`OpaqueBody`] wrapper produced by [`build_frame`]; the frame
/// must be cleartext (this layer performs no decryption).
pub fn open_frame(frame_der: impl AsRef<[u8]>) -> Result<Vec<u8>, TightBeamError> {
	let frame = Frame::from_der(frame_der.as_ref())?;
	let body = OpaqueBody::from_der(&frame.message)?;
	Ok(body.body.into_bytes())
}

/// Decoded view of a frame: its body plus the metadata and security markers a
/// caller needs to confirm what survived a round-trip.
pub struct FrameSummary {
	/// Protocol version ordinal (`V0` -> 0, ..., `V3` -> 3).
	pub version: u8,
	/// Opaque message identifier.
	pub id: Vec<u8>,
	/// Monotonic order (Unix seconds).
	pub order: u64,
	/// Opaque message body.
	pub body: Vec<u8>,
	/// The frame carries a non-repudiation signature.
	pub signed: bool,
	/// The metadata commits to the body (message integrity).
	pub message_integrity: bool,
	/// The envelope is witnessed (frame integrity).
	pub frame_integrity: bool,
}

/// Decode a frame DER into a [`FrameSummary`].
///
/// Like [`open_frame`], the frame must be cleartext (no decryption is
/// performed); the body is the [`OpaqueBody`] payload.
pub fn inspect_frame(frame_der: impl AsRef<[u8]>) -> Result<FrameSummary, TightBeamError> {
	let frame = Frame::from_der(frame_der.as_ref())?;
	let body = OpaqueBody::from_der(&frame.message)?;

	Ok(FrameSummary {
		version: frame.version as u8,
		id: frame.metadata.id.clone(),
		order: frame.metadata.order,
		body: body.body.into_bytes(),
		signed: frame.nonrepudiation.is_some(),
		message_integrity: frame.metadata.integrity.is_some(),
		frame_integrity: frame.integrity.is_some(),
	})
}

#[cfg(test)]
mod tests {
	use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
	use tightbeam::der::Decode;
	use tightbeam::matrix::MatrixDyn;
	use tightbeam::{Frame, MessagePriority, ObjectIdentifier, Version};

	use super::{build_frame, inspect_frame, open_frame, seal_frame, FrameConfig, FrameOptions, SignerKind};

	type TestResult = core::result::Result<(), Box<dyn core::error::Error>>;

	fn sample_message() -> Vec<u8> {
		b"opaque-message-body".to_vec()
	}

	fn signing_key() -> Result<Secp256k1SigningKey, Box<dyn core::error::Error>> {
		Ok(Secp256k1SigningKey::from_bytes(&[1u8; 32].into())?)
	}

	fn secured_options(signer: &SignerKind) -> FrameOptions<'_> {
		FrameOptions { signer: Some(signer), message_integrity: true, frame_integrity: true }
	}

	fn frame_from(config: FrameConfig) -> Result<Frame, Box<dyn core::error::Error>> {
		Ok(Frame::from_der(&config.build()?)?)
	}

	#[test]
	fn seal_then_open_round_trips_message() -> TestResult {
		let message = sample_message();

		let frame_der = seal_frame(&message, b"msg-1", 7)?;
		let recovered = open_frame(&frame_der)?;

		assert_eq!(recovered, message);
		Ok(())
	}

	#[test]
	fn cleartext_frame_carries_metadata() -> TestResult {
		let frame_der = seal_frame(sample_message(), b"id-9", 42)?;
		let frame = Frame::from_der(&frame_der)?;

		assert_eq!(frame.metadata.id, b"id-9");
		assert_eq!(frame.metadata.order, 42);
		assert!(frame.integrity.is_none());
		assert!(frame.nonrepudiation.is_none());
		Ok(())
	}

	#[test]
	fn signed_frame_verifies_and_opens() -> TestResult {
		let message = sample_message();
		let key = signing_key()?;
		let verifying_key = *key.verifying_key();

		let signer = SignerKind::Secp256k1(key);
		let frame_der = build_frame(&message, b"signed-1", 5, secured_options(&signer))?;
		let frame = Frame::from_der(&frame_der)?;

		assert!(frame.nonrepudiation.is_some());
		assert!(frame.integrity.is_some());
		assert!(frame.metadata.integrity.is_some());
		frame.verify::<Secp256k1Signature>(&verifying_key)?;

		let recovered = open_frame(&frame_der)?;
		assert_eq!(recovered, message);
		Ok(())
	}

	#[test]
	fn inspect_reports_cleartext_metadata() -> TestResult {
		let message = sample_message();

		let frame_der = seal_frame(&message, b"view-1", 11)?;
		let summary = inspect_frame(&frame_der)?;

		assert_eq!(summary.version, 0);
		assert_eq!(summary.id, b"view-1");
		assert_eq!(summary.order, 11);
		assert_eq!(summary.body, message);
		assert!(!summary.signed);
		assert!(!summary.message_integrity);
		assert!(!summary.frame_integrity);
		Ok(())
	}

	#[test]
	fn inspect_reports_security_markers() -> TestResult {
		let signer = SignerKind::Secp256k1(signing_key()?);
		let frame_der = build_frame(sample_message(), b"view-2", 12, secured_options(&signer))?;
		let summary = inspect_frame(&frame_der)?;

		assert!(summary.signed);
		assert!(summary.message_integrity);
		assert!(summary.frame_integrity);
		Ok(())
	}

	#[test]
	fn config_defaults_to_v0_cleartext() -> TestResult {
		let config = FrameConfig { id: b"plain".to_vec(), order: 1, message: sample_message(), ..Default::default() };

		let frame = frame_from(config)?;

		assert_eq!(frame.version, Version::V0);
		assert!(frame.nonrepudiation.is_none());
		Ok(())
	}

	#[test]
	fn config_applies_v2_metadata() -> TestResult {
		let oid: ObjectIdentifier = "1.2.840.10045.4.3.4".parse()?;

		let config = FrameConfig {
			id: b"meta".to_vec(),
			order: 9,
			message: sample_message(),
			content_oid: Some(oid),
			priority: Some(MessagePriority::LowLatency),
			lifetime: Some(60),
			message_integrity_salt: Some(Vec::new()),
			frame_integrity: true,
			..Default::default()
		};

		let frame = frame_from(config)?;

		assert_eq!(frame.version, Version::V2);
		assert_eq!(frame.metadata.priority, Some(MessagePriority::LowLatency));
		assert_eq!(frame.metadata.lifetime, Some(60));
		assert!(frame.metadata.integrity.is_some());
		assert!(frame.integrity.is_some());
		Ok(())
	}

	#[test]
	fn config_matrix_requires_v3() -> TestResult {
		let matrix = MatrixDyn::from_row_major(2, vec![0, 1, 1, 0]).ok_or("matrix dims")?;

		let config = FrameConfig {
			id: b"matrix".to_vec(),
			order: 1,
			message: sample_message(),
			matrix: Some(matrix),
			..Default::default()
		};

		let frame = frame_from(config)?;

		assert_eq!(frame.version, Version::V3);
		let recovered_matrix = frame.metadata.matrix.as_ref().ok_or("matrix present")?;
		assert_eq!(recovered_matrix.n, 2);
		Ok(())
	}

	#[test]
	fn config_pins_explicit_version() -> TestResult {
		let config = FrameConfig {
			version: Some(Version::V2),
			id: b"pinned".to_vec(),
			order: 3,
			message: sample_message(),
			..Default::default()
		};

		let frame = frame_from(config)?;

		assert_eq!(frame.version, Version::V2);
		Ok(())
	}
}
