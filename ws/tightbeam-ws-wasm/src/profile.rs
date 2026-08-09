//! Encapsulated tightbeam-profile crypto for the wasm boundary.
//!
//! Curve- and algorithm-specific operations live on typed owners
//! (`Secp256k1SigningKey`, `Aes256Gcm`, …). Module-level free functions do
//! not take raw key material.

use wasm_bindgen::prelude::*;

use tightbeam::crypto::sign::ecdsa::{
	Secp256k1SigningKey as ProfileSigningKey, Secp256k1VerifyingKey as ProfileVerifyingKey,
};
use tightbeam::spki::EncodePublicKey;

use crate::build::{
	self, Aes256GcmKey, EciesSecp256k1Decryptor as ProfileEciesDecryptor,
	EciesSecp256k1Encryptor as ProfileEciesEncryptor,
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

	/// Subject-key-identifier octets for `attachSignature`.
	#[wasm_bindgen(js_name = signerId)]
	pub fn signer_id(&self) -> Result<Vec<u8>, JsError> {
		build::signer_id(self.inner.verifying_key()).map_err(|error| JsError::new(&error.to_string()))
	}

	/// Sign the SHA3-256 digest of `tbs` as compact 64-byte `r || s`.
	#[wasm_bindgen(js_name = signTbs)]
	pub fn sign_tbs(&self, tbs: Vec<u8>) -> Result<Vec<u8>, JsError> {
		build::sign_tbs(&self.inner, tbs).map_err(|error| JsError::new(&error.to_string()))
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

/// Profile AES-256-GCM under a 32-byte shared key.
#[wasm_bindgen(js_name = Aes256Gcm)]
pub struct Aes256Gcm {
	inner: Aes256GcmKey,
}

#[wasm_bindgen]
impl Aes256Gcm {
	/// Construct from a raw 32-byte key.
	#[wasm_bindgen(js_name = fromKey)]
	pub fn from_key(key: Vec<u8>) -> Result<Aes256Gcm, JsError> {
		let inner = Aes256GcmKey::new(key).map_err(|error| JsError::new(&error.to_string()))?;
		Ok(Aes256Gcm { inner })
	}

	/// Seal `plaintext` under a fresh nonce.
	#[wasm_bindgen]
	pub fn seal(&self, plaintext: Vec<u8>) -> Result<SealedBody, JsError> {
		let sealed = self.inner.seal(plaintext).map_err(|error| JsError::new(&error.to_string()))?;
		Ok(SealedBody { inner: sealed })
	}

	/// Open a sealed body with this key.
	#[wasm_bindgen]
	pub fn open(&self, parameters_der: Option<Vec<u8>>, ciphertext: Vec<u8>) -> Result<Vec<u8>, JsError> {
		self.inner
			.open(parameters_der, ciphertext)
			.map_err(|error| JsError::new(&error.to_string()))
	}
}

/// Profile ECIES encryptor (secp256k1 + HKDF-SHA3-256 + AES-256-GCM).
#[wasm_bindgen(js_name = EciesSecp256k1Encryptor)]
pub struct EciesSecp256k1Encryptor {
	inner: ProfileEciesEncryptor,
}

#[wasm_bindgen]
impl EciesSecp256k1Encryptor {
	/// Construct from the recipient's SEC1 public key.
	#[wasm_bindgen(js_name = fromBytes)]
	pub fn from_bytes(recipient_public_key: Vec<u8>) -> Result<EciesSecp256k1Encryptor, JsError> {
		let inner =
			ProfileEciesEncryptor::from_sec1(recipient_public_key).map_err(|error| JsError::new(&error.to_string()))?;
		Ok(EciesSecp256k1Encryptor { inner })
	}

	/// Seal `plaintext` to the recipient under a fresh ephemeral key.
	#[wasm_bindgen]
	pub fn seal(&self, plaintext: Vec<u8>) -> Result<SealedBody, JsError> {
		let sealed = self.inner.seal(plaintext).map_err(|error| JsError::new(&error.to_string()))?;
		Ok(SealedBody { inner: sealed })
	}
}

/// Profile ECIES decryptor holding the recipient secp256k1 secret.
#[wasm_bindgen(js_name = EciesSecp256k1Decryptor)]
pub struct EciesSecp256k1Decryptor {
	inner: ProfileEciesDecryptor,
}

#[wasm_bindgen]
impl EciesSecp256k1Decryptor {
	/// Construct from a raw 32-byte recipient secret key.
	#[wasm_bindgen(js_name = fromBytes)]
	pub fn from_bytes(secret_key: Vec<u8>) -> Result<EciesSecp256k1Decryptor, JsError> {
		let inner = ProfileEciesDecryptor::new(secret_key).map_err(|error| JsError::new(&error.to_string()))?;
		Ok(EciesSecp256k1Decryptor { inner })
	}

	/// Open a body sealed to this recipient.
	#[wasm_bindgen]
	pub fn open(&self, parameters_der: Option<Vec<u8>>, ciphertext: Vec<u8>) -> Result<Vec<u8>, JsError> {
		self.inner
			.open(parameters_der, ciphertext)
			.map_err(|error| JsError::new(&error.to_string()))
	}
}
