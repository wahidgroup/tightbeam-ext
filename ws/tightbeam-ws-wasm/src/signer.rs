//! JavaScript-backed transport signing. Compiled only for `wasm32` targets.
//!
//! Adapts an external JavaScript signer to tightbeam's [`SigningKeyProvider`]
//! so mutual authentication never needs raw key bytes. The signer is
//! duck-typed: any object with an `algorithmOid` string, a `publicKeyDer`
//! byte getter, and an async `signPrehash` method qualifies.

use std::sync::Arc;

use js_sys::{Promise, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use tightbeam::crypto::key::{KeyError, SigningKeyProvider};
use tightbeam::crypto::sign::Error as SignatureError;
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::{AlgorithmIdentifierOwned, ObjectIdentifier};

use crate::fault::{to_js, validation};

#[wasm_bindgen(typescript_custom_section)]
const TRANSPORT_SIGNER_TS: &'static str = r#"
/**
 * External transport signer for mutual authentication.
 *
 * Algorithm-agnostic: receives the handshake transcript prehash (already
 * digested under the session profile) and must sign it directly (no
 * rehash), returning whatever signature encoding the peer's profile
 * verifies. The shipped default-profile build expects a secp256k1
 * signature as 64-byte `r || s`. Custom-profile builds expect their own
 * profile's encoding. Backed by WebAuthn, wallets, KMS bridges, or any
 * custom key store. The private key never crosses into wasm.
 *
 * `publicKeyDer` MUST be the SubjectPublicKeyInfo DER encoding carried
 * in the client certificate. Receipt countersign SID is derived from
 * those bytes and MUST match the certificate SPKI digest.
 */
export interface TransportSigner {
	/**
	 * Dotted signature-algorithm OID under the session profile.
	 *
	 * The default profile expects `2.16.840.1.101.3.4.3.10`
	 * (ecdsa-with-SHA3-256).
	 */
	readonly algorithmOid: string;
	/**
	 * DER-encoded SubjectPublicKeyInfo for the signing key.
	 *
	 * MUST match the SPKI in the presented client certificate byte-for-byte
	 * (typically uncompressed SEC1 for the profile's EncodePublicKey path).
	 */
	readonly publicKeyDer: Uint8Array;
	/**
	 * Sign the handshake transcript prehash.
	 *
	 * Resolves with the profile signature encoding. The default profile
	 * expects 64-byte compact `r || s`.
	 */
	signPrehash(prehash: Uint8Array): Promise<Uint8Array> | Uint8Array;
}
"#;

#[wasm_bindgen]
extern "C" {
	/// External signer contract, duck-typed from JavaScript.
	///
	/// Algorithm-agnostic: the prehash handed to `signPrehash` is the
	/// transcript digest the handshake computed under the session profile.
	/// The signer MUST sign it directly (no rehash) and return the
	/// signature encoding the peer's profile verifies.
	#[wasm_bindgen(js_name = TransportSigner, typescript_type = "TransportSigner")]
	pub type TransportSigner;

	/// Dotted signature-algorithm OID (e.g. `2.16.840.1.101.3.4.3.10`).
	#[wasm_bindgen(method, getter, js_name = algorithmOid)]
	fn algorithm_oid(this: &TransportSigner) -> String;

	/// DER-encoded SubjectPublicKeyInfo for the signing key.
	#[wasm_bindgen(method, getter, js_name = publicKeyDer)]
	fn public_key_der(this: &TransportSigner) -> Uint8Array;

	/// Sign the given prehash. Returns the signature bytes or a promise of them.
	#[wasm_bindgen(method, catch, js_name = signPrehash)]
	fn sign_prehash(this: &TransportSigner, prehash: Uint8Array) -> Result<JsValue, JsValue>;
}

/// Programmatic failures when adapting a JavaScript signer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignerFault {
	PublicKeyMismatch,
	EmptySignature,
	MissingLength,
	NonIntegerLength,
	NonNumericByte,
	ByteOutOfRange,
	JsRejected,
}

impl SignerFault {
	fn code(self) -> &'static str {
		match self {
			Self::PublicKeyMismatch => "PublicKeyMismatch",
			Self::EmptySignature => "EmptySignature",
			Self::MissingLength => "MissingLength",
			Self::NonIntegerLength => "NonIntegerLength",
			Self::NonNumericByte => "NonNumericByte",
			Self::ByteOutOfRange => "ByteOutOfRange",
			Self::JsRejected => "ExternalSignerRejected",
		}
	}

	fn message(self) -> &'static str {
		match self {
			Self::PublicKeyMismatch => "signer publicKeyDer must equal certificate SPKI DER",
			Self::EmptySignature => "signPrehash returned an empty signature",
			Self::MissingLength => "signPrehash result has no length",
			Self::NonIntegerLength => "signPrehash length must be an integer",
			Self::NonNumericByte => "signPrehash byte is not a number",
			Self::ByteOutOfRange => "signPrehash byte out of range",
			Self::JsRejected => "external signer rejected the prehash",
		}
	}
}

impl core::fmt::Display for SignerFault {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.write_str(self.message())
	}
}

impl std::error::Error for SignerFault {}

/// [`SigningKeyProvider`] backed by a JavaScript [`TransportSigner`].
///
/// The algorithm OID and public key are captured eagerly so construction
/// fails fast on a malformed signer. Only `signPrehash` crosses the JS
/// boundary per handshake.
pub struct JsSigningKeyProvider {
	signer: TransportSigner,
	algorithm: AlgorithmIdentifierOwned,
	public_key_der: Vec<u8>,
}

impl JsSigningKeyProvider {
	/// Capture the signer's static material and wrap it as a provider.
	///
	/// `cert_spki` is the SubjectPublicKeyInfo DER from the client
	/// certificate. Construction fails when the signer's `publicKeyDer`
	/// differs, so receipt SID and certificate identity stay bound.
	pub fn new(signer: TransportSigner, cert_spki: &[u8]) -> Result<Self, JsValue> {
		let oid: ObjectIdentifier = signer.algorithm_oid().parse().map_err(to_js)?;
		let algorithm = AlgorithmIdentifierOwned { oid, parameters: None };
		let public_key_der = signer.public_key_der().to_vec();
		if public_key_der.as_slice() != cert_spki {
			return Err(validation(
				SignerFault::PublicKeyMismatch.code(),
				SignerFault::PublicKeyMismatch.message(),
			));
		}

		Ok(Self { signer, algorithm, public_key_der })
	}

	/// Erase to the trait object the handshake key manager consumes.
	pub fn into_provider(self) -> Arc<dyn SigningKeyProvider> {
		Arc::new(self)
	}
}

impl core::fmt::Debug for JsSigningKeyProvider {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("JsSigningKeyProvider")
			.field("algorithm", &self.algorithm)
			.finish_non_exhaustive()
	}
}

impl SigningKeyProvider for JsSigningKeyProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.algorithm.clone()
	}

	fn to_public_key_bytes(&self) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let public_key_der = self.public_key_der.clone();
		Box::pin(async move { Ok(public_key_der) })
	}

	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let argument = Uint8Array::from(prehash);
		let invoked = self.signer.sign_prehash(argument);

		Box::pin(async move {
			let returned = invoked.map_err(|_| key_fault(SignerFault::JsRejected))?;

			// resolve() adopts thenables and passes plain values through,
			// so synchronous signers work unchanged.
			let promise = Promise::resolve(&returned);
			let settled = JsFuture::from(promise).await.map_err(|_| key_fault(SignerFault::JsRejected))?;

			let signature = bytes_from_array_like(&settled)?;
			if signature.is_empty() {
				return Err(key_fault(SignerFault::EmptySignature));
			}

			Ok(signature)
		})
	}
}

/// Copy bytes from a `Uint8Array` or array-like by index.
///
/// Prefer this over `Uint8Array::to_vec` at the Vitest/Vite boundary:
/// cross-realm typed arrays can report a length and still yield empty
/// or truncated buffers through the typed-array view APIs.
fn bytes_from_array_like(value: &JsValue) -> Result<Vec<u8>, KeyError> {
	let length = Reflect::get(value, &JsValue::from_str("length"))
		.map_err(|_| key_fault(SignerFault::MissingLength))?
		.as_f64()
		.ok_or_else(|| key_fault(SignerFault::MissingLength))?;
	if length < 0.0 || length.fract() != 0.0 {
		return Err(key_fault(SignerFault::NonIntegerLength));
	}

	let length = length as u32;
	let mut bytes = Vec::with_capacity(length as usize);
	for index in 0..length {
		let entry = Reflect::get_u32(value, index).map_err(|_| key_fault(SignerFault::NonNumericByte))?;
		let byte = entry.as_f64().ok_or_else(|| key_fault(SignerFault::NonNumericByte))?;
		if !(0.0..=255.0).contains(&byte) || byte.fract() != 0.0 {
			return Err(key_fault(SignerFault::ByteOutOfRange));
		}

		bytes.push(byte as u8);
	}

	Ok(bytes)
}

fn key_fault(fault: SignerFault) -> KeyError {
	KeyError::SignatureError(SignatureError::from_source(fault))
}
