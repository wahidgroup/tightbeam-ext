//! Encapsulated tightbeam-profile crypto for the wasm boundary.
//!
//! Curve- and algorithm-specific operations live on typed owners
//! (`Secp256k1SigningKey`, `Aes256Gcm`, …). Module-level free functions do
//! not take raw key material.

use core::future::Future;
use std::rc::Rc;

use js_sys::{Promise, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use tightbeam::crypto::hash::{Digest as _, Sha3_256 as ProfileSha3_256};
use tightbeam::crypto::sign::ecdsa::{
	Secp256k1Signature, Secp256k1SigningKey as ProfileSigningKey, Secp256k1VerifyingKey as ProfileVerifyingKey,
};
use tightbeam::crypto::sign::PrehashSigner;
use tightbeam::spki::EncodePublicKey;
use tightbeam::{TightBeamError, ZeroizingBytes};

use crate::bindings::Oid;
use crate::build::{
	self, Aes256GcmKey, FrameAssembly, HpkeSecp256k1Decryptor as ProfileHpkeDecryptor,
	HpkeSecp256k1Encryptor as ProfileHpkeEncryptor, SharedKey, SignerKeyId,
};
use crate::fault::{JsFault, RefusalCode};
use crate::promise::{JsBytes, Record};

/// secp256k1 private keys are 32 octets.
const SECP256K1_KEY_LEN: usize = 32;

/// TypeScript shapes the profile owners take and give.
#[wasm_bindgen(typescript_custom_section)]
const PROFILE_TS: &'static str = r#"
/**
 * A shared key-encryption key and the identifier that names it to every
 * holder, each in a field of its own name.
 */
export interface SharedKey {
	/**
	 * The raw 32-byte key.
	 */
	readonly key: Uint8Array;
	/**
	 * The identifier an envelope carries in the clear to name the key.
	 */
	readonly keyId: Uint8Array;
}

/**
 * A sealed frame body: the CMS envelope recorded in the frame's
 * confidentiality info, and the ciphertext that replaces the body. The
 * ciphertext travels detached from the envelope (RFC 5652 § 6.1), and the
 * envelope names the content-encryption algorithm.
 *
 * # Sources
 *
 * - RFC 5083, CMS Authenticated-Enveloped-Data Content Type:
 *   <https://datatracker.ietf.org/doc/html/rfc5083>
 */
export interface EncryptedBody {
	/**
	 * The DER `AuthEnvelopedData`: the recipient, the content type, the
	 * nonce, and the tag, with its content detached.
	 */
	readonly envelopeDer: Uint8Array;
	/**
	 * The ciphertext.
	 */
	readonly ciphertext: Uint8Array;
}
"#;

/// A sealed body produced by a profile encryptor: the pieces
/// `withConfidentiality` installs.
#[wasm_bindgen]
pub struct SealedBody {
	inner: build::SealedBody,
}

#[wasm_bindgen]
impl SealedBody {
	/// The content-encryption algorithm that the parsed envelope names.
	#[wasm_bindgen(getter, js_name = algorithmOid)]
	pub fn algorithm_oid(&self) -> Oid {
		Oid::from(self.inner.algorithm_oid())
	}

	/// Move the pieces into one plain `EncryptedBody`, consuming this body.
	///
	/// The body is spent once its pieces move, so a later call on it throws.
	#[wasm_bindgen(js_name = takePieces, unchecked_return_type = "EncryptedBody")]
	pub fn take_pieces(self) -> JsValue {
		let record = Record::new();
		record.set_bytes("envelopeDer", self.inner.envelope_der());
		record.set_bytes("ciphertext", self.inner.ciphertext());
		record.into()
	}
}

/// A sealed body as JavaScript hands it over: an object that names its
/// pieces, so that they cannot swap. A caller's own scheme seals a body of
/// this shape.
impl TryFrom<&JsValue> for build::SealedBody {
	type Error = JsFault;

	/// Read the pieces that a JavaScript sealed body names, and parse its
	/// envelope once.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- a piece is not a `Uint8Array`.
	/// - `SerializationError` -- `envelopeDer` is no `AuthEnvelopedData`.
	fn try_from(value: &JsValue) -> Result<Self, Self::Error> {
		let envelope_der = JsBytes::read_member(value, "sealed.envelopeDer")?;
		let ciphertext = JsBytes::read_member(value, "sealed.ciphertext")?;
		Ok(Self::new(&envelope_der, ciphertext)?)
	}
}

/// A promise of the plaintext body DER that `opening`, an open of a sealed
/// body, recovers.
fn plaintext_promise(opening: impl Future<Output = Result<Vec<u8>, TightBeamError>> + 'static) -> Promise {
	future_to_promise(async move {
		let plaintext = opening.await.map_err(JsFault::from)?;
		Ok(Uint8Array::from(plaintext.as_slice()).into())
	})
}

/// Profile SHA3-256 hasher.
#[wasm_bindgen(js_name = Sha3_256)]
pub struct Sha3_256;

#[wasm_bindgen]
impl Sha3_256 {
	/// SHA3-256 digest of `data`.
	#[wasm_bindgen]
	pub fn digest(data: JsBytes) -> Result<Vec<u8>, JsFault> {
		let data = data.read()?;
		Ok(ProfileSha3_256::digest(&data).to_vec())
	}
}

/// Local secp256k1 ECDSA signing key for the tightbeam profile.
#[wasm_bindgen(js_name = Secp256k1SigningKey)]
pub struct Secp256k1SigningKey {
	inner: ProfileSigningKey,
}

impl Secp256k1SigningKey {
	/// Read the raw 32-octet secp256k1 `scalar`, the one parse of a profile
	/// signing key. The wasm copy of the scalar wipes once the key holds it.
	///
	/// # Errors
	///
	/// - `InvalidSigningKey` -- the scalar is not 32 octets, or names no key.
	pub(crate) fn from_scalar(scalar: ZeroizingBytes) -> Result<Self, JsFault> {
		let sized = <&[u8; SECP256K1_KEY_LEN]>::try_from(scalar.as_slice());
		let sized = sized.map_err(|_| RefusalCode::InvalidSigningKey.because("a secp256k1 key is 32 octets"))?;
		let inner = ProfileSigningKey::from_bytes(sized.into());
		let inner = inner.map_err(|error| RefusalCode::InvalidSigningKey.because(error))?;
		Ok(Self { inner })
	}

	/// The profile key this object holds.
	pub(crate) fn into_inner(self) -> ProfileSigningKey {
		self.inner
	}
}

#[wasm_bindgen]
impl Secp256k1SigningKey {
	/// Construct from a raw 32-byte secp256k1 scalar. The wasm copy of the
	/// scalar wipes once the key holds it.
	///
	/// # Errors
	///
	/// - `InvalidSigningKey` -- the scalar is not 32 octets, or names no key.
	/// - `InvalidBytes` -- `keyBytes` is not a `Uint8Array`.
	#[wasm_bindgen(js_name = fromBytes)]
	pub fn from_bytes(key_bytes: JsBytes) -> Result<Secp256k1SigningKey, JsFault> {
		let scalar = ZeroizingBytes::new(key_bytes.read()?);
		Self::from_scalar(scalar)
	}

	/// SEC1 compressed public key for this signing key.
	#[wasm_bindgen(js_name = derivePublicKey)]
	pub fn derive_public_key(&self) -> Vec<u8> {
		self.inner.verifying_key().to_sec1_bytes().into_vec()
	}

	/// DER SubjectPublicKeyInfo (uncompressed SEC1; profile `EncodePublicKey`).
	#[wasm_bindgen(js_name = toSpkiDer)]
	pub fn to_spki_der(&self) -> Result<Vec<u8>, JsFault> {
		let spki = self.inner.verifying_key().to_public_key_der();
		let spki = spki.map_err(TightBeamError::from)?;
		Ok(spki.into_vec())
	}

	/// Subject-key-identifier octets for `FrameAssembly.signing`.
	#[wasm_bindgen(js_name = signerId)]
	pub fn signer_id(&self) -> Result<Vec<u8>, JsFault> {
		let signer = SignerKeyId::of(self.inner.verifying_key())?;
		Ok(signer.into_bytes())
	}

	/// Sign `prehash` directly, with no rehash, as a DER `ECDSA-Sig-Value`.
	///
	/// # Errors
	///
	/// - `InvalidPrehash` -- the key cannot sign `prehash`.
	/// - `InvalidBytes` -- `prehash` is not a `Uint8Array`.
	#[wasm_bindgen(js_name = signPrehash)]
	pub fn sign_prehash(&self, prehash: JsBytes) -> Result<Vec<u8>, JsFault> {
		let prehash = prehash.read()?;
		let signature: Result<Secp256k1Signature, _> = self.inner.sign_prehash(&prehash);
		let signature = signature.map_err(|error| RefusalCode::InvalidPrehash.because(error))?;
		Ok(signature.to_bytes().to_vec())
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
	///
	/// # Errors
	///
	/// - `InvalidVerifyingKey` -- the octets name no secp256k1 point.
	/// - `InvalidBytes` -- `sec1` is not a `Uint8Array`.
	#[wasm_bindgen(js_name = fromSec1Bytes)]
	pub fn from_sec1_bytes(sec1: JsBytes) -> Result<Secp256k1VerifyingKey, JsFault> {
		let sec1 = sec1.read()?;
		let inner = ProfileVerifyingKey::from_sec1_bytes(&sec1);
		let inner = inner.map_err(|error| RefusalCode::InvalidVerifyingKey.because(error))?;
		Ok(Secp256k1VerifyingKey { inner })
	}

	/// SEC1 encoding of this public key.
	#[wasm_bindgen(js_name = toSec1Bytes)]
	pub fn to_sec1_bytes(&self) -> Vec<u8> {
		self.inner.to_sec1_bytes().into_vec()
	}

	/// Subject-key-identifier octets naming this verifying key.
	#[wasm_bindgen(js_name = signerId)]
	pub fn signer_id(&self) -> Result<Vec<u8>, JsFault> {
		let signer = SignerKeyId::of(&self.inner)?;
		Ok(signer.into_bytes())
	}

	/// Verify a frame's non-repudiation signature under the profile scheme.
	#[wasm_bindgen(js_name = verifyFrame)]
	pub fn verify_frame(&self, frame_der: JsBytes) -> Result<(), JsFault> {
		let assembly = FrameAssembly::decode(frame_der.read()?)?;
		Ok(assembly.verify_signature(&self.inner)?)
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
	/// Construct from a shared key and the identifier that names it to every
	/// holder. The wasm copy of the key wipes once the cipher holds it.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- `shared.key` or `shared.keyId` is not a `Uint8Array`.
	/// - `EmptyKeyId` -- `shared.keyId` is empty, so it names no key.
	/// - `KeyError` -- the key is not 32 octets.
	#[wasm_bindgen(js_name = fromKey)]
	pub fn from_key(#[wasm_bindgen(unchecked_param_type = "SharedKey")] shared: JsValue) -> Result<Aes256Gcm, JsFault> {
		let key = ZeroizingBytes::new(JsBytes::read_member(&shared, "shared.key")?);
		let key_id = JsBytes::read_member(&shared, "shared.keyId")?;
		let shared = SharedKey::new(key, key_id).map_err(|refusal| JsFault::from(refusal).at("shared.keyId"))?;

		let inner = Aes256GcmKey::new(shared).map_err(|error| JsFault::from(error).at("shared.key"))?;
		Ok(Aes256Gcm { inner: Rc::new(inner) })
	}

	/// Seal `plaintext`, a body of the content type `contentOid`, under a
	/// fresh content key.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- `plaintext` is not a `Uint8Array`.
	#[wasm_bindgen]
	pub fn seal(&self, plaintext: JsBytes, content_oid: &Oid) -> Result<SealedBody, JsFault> {
		let sealed = self.inner.seal(plaintext.read()?, Some(content_oid.value()))?;
		Ok(SealedBody { inner: sealed })
	}

	/// Open a sealed body with this key.
	#[wasm_bindgen(unchecked_return_type = "Promise<Uint8Array>")]
	pub fn open(
		&self,
		#[wasm_bindgen(unchecked_param_type = "EncryptedBody")] sealed: JsValue,
	) -> Result<Promise, JsFault> {
		let sealed = build::SealedBody::try_from(&sealed)?;
		let inner = Rc::clone(&self.inner);

		let opening = async move { inner.open(sealed).await };
		Ok(plaintext_promise(opening))
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
	///
	/// # Errors
	///
	/// - `InvalidVerifyingKey` -- the octets name no secp256k1 point.
	/// - `InvalidBytes` -- `recipientPublicKey` is not a `Uint8Array`.
	#[wasm_bindgen(js_name = fromBytes)]
	pub fn from_bytes(recipient_public_key: JsBytes) -> Result<HpkeSecp256k1Encryptor, JsFault> {
		let recipient_public_key = recipient_public_key.read()?;
		let inner = ProfileHpkeEncryptor::from_sec1(recipient_public_key);
		let inner = inner.map_err(|error| RefusalCode::InvalidVerifyingKey.because(error))?;
		Ok(HpkeSecp256k1Encryptor { inner })
	}

	/// Seal `plaintext`, a body of the content type `contentOid`, to the
	/// recipient under a fresh ephemeral key.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- `plaintext` is not a `Uint8Array`.
	#[wasm_bindgen]
	pub fn seal(&self, plaintext: JsBytes, content_oid: &Oid) -> Result<SealedBody, JsFault> {
		let sealed = self.inner.seal(plaintext.read()?, Some(content_oid.value()))?;
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
	/// Construct from a raw 32-byte recipient secret key. The wasm copy of
	/// the key wipes once the decryptor holds it.
	///
	/// # Errors
	///
	/// - `InvalidSigningKey` -- the secret is not 32 octets, or names no key.
	/// - `InvalidBytes` -- `secretKey` is not a `Uint8Array`.
	#[wasm_bindgen(js_name = fromBytes)]
	pub fn from_bytes(secret_key: JsBytes) -> Result<HpkeSecp256k1Decryptor, JsFault> {
		let scalar = ZeroizingBytes::new(secret_key.read()?);
		let signing_key = Secp256k1SigningKey::from_scalar(scalar)?;

		let inner = ProfileHpkeDecryptor::new(signing_key.into_inner());
		let inner = inner.map_err(|error| RefusalCode::InvalidSigningKey.because(error))?;
		Ok(HpkeSecp256k1Decryptor { inner: Rc::new(inner) })
	}

	/// Open a body sealed to this recipient.
	#[wasm_bindgen(unchecked_return_type = "Promise<Uint8Array>")]
	pub fn open(
		&self,
		#[wasm_bindgen(unchecked_param_type = "EncryptedBody")] sealed: JsValue,
	) -> Result<Promise, JsFault> {
		let sealed = build::SealedBody::try_from(&sealed)?;
		let inner = Rc::clone(&self.inner);

		let opening = async move { inner.open(sealed).await };
		Ok(plaintext_promise(opening))
	}
}

#[cfg(test)]
mod tests {
	use js_sys::{Object, Reflect, Uint8Array};
	use wasm_bindgen::{JsCast, JsValue};
	use wasm_bindgen_test::wasm_bindgen_test;

	use tightbeam::oids::{AES_256_GCM, DATA};

	use super::{Aes256Gcm, HpkeSecp256k1Decryptor, Secp256k1SigningKey};
	use crate::bindings::Oid;
	use crate::build;
	use crate::fault::Refused;
	use crate::promise::JsBytes;

	/// An object that names `value` as its `name` member and one octet as its
	/// `other` member.
	fn pieces(name: &str, value: JsValue, other: &str) -> JsValue {
		let object = Object::new();
		let one = Uint8Array::from([1u8].as_slice());
		let named = Reflect::set(&object, &JsValue::from_str(name), &value);
		named.expect("the object should take the member");

		let filled = Reflect::set(&object, &JsValue::from_str(other), &one);
		filled.expect("the object should take the other member");

		object.into()
	}

	/// `octets` as a JavaScript byte parameter.
	fn bytes(octets: &[u8]) -> JsBytes {
		Uint8Array::from(octets).unchecked_into()
	}

	#[wasm_bindgen_test]
	fn a_31_octet_scalar_is_refused_by_both_key_paths() {
		let scalar = [1u8; 31];
		let signing_key = Secp256k1SigningKey::from_bytes(bytes(&scalar)).code();
		let decryptor = HpkeSecp256k1Decryptor::from_bytes(bytes(&scalar)).code();

		let codes = [signing_key.as_deref(), decryptor.as_deref()];
		assert_eq!(codes, [Some("InvalidSigningKey"); 2]);
	}

	/// A `SharedKey` object of `key`, named by `key_id`.
	fn shared_key(key: &[u8], key_id: &[u8]) -> JsValue {
		let object = Object::new();
		let keyed = Reflect::set(&object, &JsValue::from_str("key"), &Uint8Array::from(key));
		keyed.expect("the object should take the key");

		let named = Reflect::set(&object, &JsValue::from_str("keyId"), &Uint8Array::from(key_id));
		named.expect("the object should take the key identifier");

		object.into()
	}

	#[wasm_bindgen_test]
	fn a_shared_key_without_an_id_is_refused() {
		let refused = Aes256Gcm::from_key(shared_key(&[0x42; 32], &[]));
		assert_eq!(refused.code().as_deref(), Some("EmptyKeyId"));
	}

	#[wasm_bindgen_test]
	fn a_sealed_body_reports_its_envelope_algorithm() {
		let cipher = Aes256Gcm::from_key(shared_key(&[0x42; 32], b"topic"));
		let cipher = cipher.expect("a 32-octet key with an id should wrap");
		let sealed = cipher.seal(bytes(&[0x04, 0x00]), &Oid::from(DATA));

		let algorithm = sealed.map(|sealed| sealed.algorithm_oid());
		assert_eq!(algorithm.ok(), Some(Oid::from(AES_256_GCM)));
	}

	#[wasm_bindgen_test]
	fn a_numeric_envelope_is_no_sealed_body() {
		let sealed = pieces("envelopeDer", JsValue::from_f64(7.0), "ciphertext");
		let parsed = build::SealedBody::try_from(&sealed);
		assert_eq!(parsed.code().as_deref(), Some("InvalidBytes"));
	}

	#[wasm_bindgen_test]
	fn a_numeric_key_is_no_shared_key() {
		let shared = pieces("key", JsValue::from_f64(32.0), "keyId");
		let parsed = Aes256Gcm::from_key(shared);
		assert_eq!(parsed.code().as_deref(), Some("InvalidBytes"));
	}
}
