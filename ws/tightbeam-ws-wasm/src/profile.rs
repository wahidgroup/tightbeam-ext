//! Encapsulated tightbeam-profile crypto for the wasm boundary.
//!
//! Curve- and algorithm-specific operations live on typed owners
//! (`Secp256k1SigningKey`, `Aes256Gcm`, …). Module-level free functions do
//! not take raw key material.

use std::rc::Rc;

use js_sys::{Promise, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use tightbeam::asn1::ObjectIdentifier;
use tightbeam::crypto::sign::ecdsa::{
	Secp256k1SigningKey as ProfileSigningKey, Secp256k1VerifyingKey as ProfileVerifyingKey,
};
use tightbeam::spki::EncodePublicKey;
use tightbeam::TightBeamError;

use crate::build::{
	self, Aes256GcmKey, HpkeSecp256k1Decryptor as ProfileHpkeDecryptor, HpkeSecp256k1Encryptor as ProfileHpkeEncryptor,
};

/// secp256k1 private keys are 32 octets.
const SECP256K1_KEY_LEN: usize = 32;

/// A sealed body produced by a profile encryptor: the pieces
/// `setConfidentiality` installs.
#[wasm_bindgen]
pub struct SealedBody {
	inner: build::SealedBody,
}

#[wasm_bindgen]
impl SealedBody {
	/// The content-encryption algorithm OID (dotted form).
	#[wasm_bindgen(getter, js_name = algorithmOid)]
	pub fn algorithm_oid(&self) -> String {
		self.inner.algorithm_oid.clone()
	}

	/// The DER `AuthEnvelopedData`, its content detached.
	#[wasm_bindgen(getter, js_name = envelopeDer)]
	pub fn envelope_der(&self) -> Vec<u8> {
		self.inner.envelope_der.clone()
	}

	/// The ciphertext replacing the frame body.
	#[wasm_bindgen(getter)]
	pub fn ciphertext(&self) -> Vec<u8> {
		self.inner.ciphertext.clone()
	}
}

/// Surface an open as a promise of the plaintext body DER.
fn plaintext_promise(
	opening: impl core::future::Future<Output = Result<Vec<u8>, TightBeamError>> + 'static,
) -> Promise {
	future_to_promise(async move {
		let plaintext = opening.await.map_err(|error| JsError::new(&error.to_string()))?;
		Ok(Uint8Array::from(plaintext.as_slice()).into())
	})
}

/// Parse an optional dotted content-type OID from the boundary.
fn content_oid_from(content_oid: Option<String>) -> Result<Option<ObjectIdentifier>, JsError> {
	match content_oid {
		Some(dotted) => {
			let oid = dotted
				.parse()
				.map_err(|_| JsError::new("contentOid is not a valid dotted OID"))?;
			Ok(Some(oid))
		}
		None => Ok(None),
	}
}

/// Profile SHA3-256 hasher.
#[wasm_bindgen(js_name = Sha3_256)]
pub struct Sha3_256;

#[wasm_bindgen]
impl Sha3_256 {
	/// SHA3-256 digest of `data`.
	#[wasm_bindgen]
	pub fn digest(data: Vec<u8>) -> Vec<u8> {
		build::sha3_256_digest(data)
	}
}

/// Local secp256k1 ECDSA signing key for the tightbeam profile.
#[wasm_bindgen(js_name = Secp256k1SigningKey)]
pub struct Secp256k1SigningKey {
	inner: ProfileSigningKey,
}

#[wasm_bindgen]
impl Secp256k1SigningKey {
	/// Construct from a raw 32-byte secp256k1 scalar.
	#[wasm_bindgen(js_name = fromBytes)]
	pub fn from_bytes(key_bytes: Vec<u8>) -> Result<Secp256k1SigningKey, JsError> {
		let array: [u8; SECP256K1_KEY_LEN] = key_bytes
			.try_into()
			.map_err(|_| JsError::new("secp256k1 key must be 32 octets"))?;
		let inner = ProfileSigningKey::from_bytes(&array.into()).map_err(|error| JsError::new(&error.to_string()))?;

		Ok(Secp256k1SigningKey { inner })
	}

	/// SEC1 compressed public key for this signing key.
	#[wasm_bindgen(js_name = derivePublicKey)]
	pub fn derive_public_key(&self) -> Vec<u8> {
		self.inner.verifying_key().to_sec1_bytes().into_vec()
	}

	/// DER SubjectPublicKeyInfo (uncompressed SEC1; profile `EncodePublicKey`).
	#[wasm_bindgen(js_name = toSpkiDer)]
	pub fn to_spki_der(&self) -> Result<Vec<u8>, JsError> {
		self.inner
			.verifying_key()
			.to_public_key_der()
			.map(|der| der.into_vec())
			.map_err(|error| JsError::new(&error.to_string()))
	}

	/// Subject-key-identifier octets for `signingPrehash` and
	/// `attachSignature`.
	#[wasm_bindgen(js_name = signerId)]
	pub fn signer_id(&self) -> Result<Vec<u8>, JsError> {
		build::signer_id(self.inner.verifying_key()).map_err(|error| JsError::new(&error.to_string()))
	}

	/// Sign `prehash` directly, with no rehash, as a DER `ECDSA-Sig-Value`.
	#[wasm_bindgen(js_name = signPrehash)]
	pub fn sign_prehash(&self, prehash: Vec<u8>) -> Result<Vec<u8>, JsError> {
		build::sign_prehash(&self.inner, prehash).map_err(|error| JsError::new(&error.to_string()))
	}
}

/// secp256k1 ECDSA verifying key for the tightbeam profile.
#[wasm_bindgen(js_name = Secp256k1VerifyingKey)]
pub struct Secp256k1VerifyingKey {
	inner: ProfileVerifyingKey,
}

#[wasm_bindgen]
impl Secp256k1VerifyingKey {
	/// Construct from a SEC1 point (33-byte compressed or 65-byte uncompressed).
	#[wasm_bindgen(js_name = fromSec1Bytes)]
	pub fn from_sec1_bytes(sec1: Vec<u8>) -> Result<Secp256k1VerifyingKey, JsError> {
		let inner = ProfileVerifyingKey::from_sec1_bytes(&sec1).map_err(|error| JsError::new(&error.to_string()))?;

		Ok(Secp256k1VerifyingKey { inner })
	}

	/// SEC1 encoding of this public key.
	#[wasm_bindgen(js_name = toSec1Bytes)]
	pub fn to_sec1_bytes(&self) -> Vec<u8> {
		self.inner.to_sec1_bytes().into_vec()
	}

	/// Subject-key-identifier octets naming this verifying key.
	#[wasm_bindgen(js_name = signerId)]
	pub fn signer_id(&self) -> Result<Vec<u8>, JsError> {
		build::signer_id(&self.inner).map_err(|error| JsError::new(&error.to_string()))
	}

	/// Verify a frame's non-repudiation signature under the profile scheme.
	#[wasm_bindgen(js_name = verifyFrame)]
	pub fn verify_frame(&self, frame_der: Vec<u8>) -> Result<(), JsError> {
		build::verify_signature(&self.inner, frame_der).map_err(|error| JsError::new(&error.to_string()))
	}
}

/// Profile key-encryption key: a 32-byte shared key, named by `keyId`, that
/// wraps a fresh AES-256-GCM content key per seal.
#[wasm_bindgen(js_name = Aes256Gcm)]
pub struct Aes256Gcm {
	inner: Rc<Aes256GcmKey>,
}

#[wasm_bindgen]
impl Aes256Gcm {
	/// Construct from a raw 32-byte key and the identifier that names it to
	/// every holder.
	#[wasm_bindgen(js_name = fromKey)]
	pub fn from_key(key: Vec<u8>, key_id: Vec<u8>) -> Result<Aes256Gcm, JsError> {
		let inner = Aes256GcmKey::new(key, key_id).map_err(|error| JsError::new(&error.to_string()))?;
		Ok(Aes256Gcm { inner: Rc::new(inner) })
	}

	/// Seal `plaintext` of type `content_oid` under a fresh content key.
	#[wasm_bindgen]
	pub fn seal(&self, plaintext: Vec<u8>, content_oid: Option<String>) -> Result<SealedBody, JsError> {
		let content_oid = content_oid_from(content_oid)?;
		let sealed = self.inner.seal(plaintext, content_oid);
		let sealed = sealed.map_err(|error| JsError::new(&error.to_string()))?;

		Ok(SealedBody { inner: sealed })
	}

	/// Open a sealed body with this key.
	#[wasm_bindgen(unchecked_return_type = "Promise<Uint8Array>")]
	pub fn open(&self, envelope_der: Vec<u8>, ciphertext: Vec<u8>) -> Promise {
		let inner = Rc::clone(&self.inner);
		plaintext_promise(async move { inner.open(envelope_der, ciphertext).await })
	}
}

/// Profile HPKE encryptor (DHKEM over secp256k1 with an AES-256-GCM content
/// key).
#[wasm_bindgen(js_name = HpkeSecp256k1Encryptor)]
pub struct HpkeSecp256k1Encryptor {
	inner: ProfileHpkeEncryptor,
}

#[wasm_bindgen]
impl HpkeSecp256k1Encryptor {
	/// Construct from the recipient's SEC1 public key.
	#[wasm_bindgen(js_name = fromBytes)]
	pub fn from_bytes(recipient_public_key: Vec<u8>) -> Result<HpkeSecp256k1Encryptor, JsError> {
		let inner =
			ProfileHpkeEncryptor::from_sec1(recipient_public_key).map_err(|error| JsError::new(&error.to_string()))?;
		Ok(HpkeSecp256k1Encryptor { inner })
	}

	/// Seal `plaintext` of type `content_oid` to the recipient under a fresh
	/// ephemeral key.
	#[wasm_bindgen]
	pub fn seal(&self, plaintext: Vec<u8>, content_oid: Option<String>) -> Result<SealedBody, JsError> {
		let content_oid = content_oid_from(content_oid)?;
		let sealed = self.inner.seal(plaintext, content_oid);
		let sealed = sealed.map_err(|error| JsError::new(&error.to_string()))?;
		Ok(SealedBody { inner: sealed })
	}
}

/// Profile HPKE decryptor holding the recipient secp256k1 secret.
#[wasm_bindgen(js_name = HpkeSecp256k1Decryptor)]
pub struct HpkeSecp256k1Decryptor {
	inner: Rc<ProfileHpkeDecryptor>,
}

#[wasm_bindgen]
impl HpkeSecp256k1Decryptor {
	/// Construct from a raw 32-byte recipient secret key.
	#[wasm_bindgen(js_name = fromBytes)]
	pub fn from_bytes(secret_key: Vec<u8>) -> Result<HpkeSecp256k1Decryptor, JsError> {
		let inner = ProfileHpkeDecryptor::new(secret_key).map_err(|error| JsError::new(&error.to_string()))?;
		Ok(HpkeSecp256k1Decryptor { inner: Rc::new(inner) })
	}

	/// Open a body sealed to this recipient.
	#[wasm_bindgen(unchecked_return_type = "Promise<Uint8Array>")]
	pub fn open(&self, envelope_der: Vec<u8>, ciphertext: Vec<u8>) -> Promise {
		let inner = Rc::clone(&self.inner);
		plaintext_promise(async move { inner.open(envelope_der, ciphertext).await })
	}
}
