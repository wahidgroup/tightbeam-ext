//! JavaScript-backed transport signing. Compiled only for `wasm32` targets.
//!
//! Adapts an external JavaScript signer to tightbeam's [`SigningKeyProvider`]
//! so mutual authentication never needs raw key bytes. The signer is
//! duck-typed: any object with an `algorithmOid` string, a `publicKeyDer`
//! byte getter, and an async `signPrehash` method qualifies.

use std::sync::Arc;

use js_sys::{Promise, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use tightbeam::crypto::key::{KeyError, SigningKeyProvider};
use tightbeam::crypto::sign::Error as SignatureError;
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::{AlgorithmIdentifierOwned, ObjectIdentifier};

use crate::fault::to_js;

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
 */
export interface TransportSigner {
	/** Dotted signature-algorithm OID (e.g. `1.2.840.10045.4.3.2`). */
	readonly algorithmOid: string;
	/** DER-encoded SubjectPublicKeyInfo for the signing key. */
	readonly publicKeyDer: Uint8Array;
	/** Sign the given prehash, resolving with the signature bytes. */
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

	/// Dotted signature-algorithm OID (e.g. `1.2.840.10045.4.3.2`).
	#[wasm_bindgen(method, getter, js_name = algorithmOid)]
	fn algorithm_oid(this: &TransportSigner) -> String;

	/// DER-encoded SubjectPublicKeyInfo for the signing key.
	#[wasm_bindgen(method, getter, js_name = publicKeyDer)]
	fn public_key_der(this: &TransportSigner) -> Uint8Array;

	/// Sign the given prehash. Returns the signature bytes or a promise of them.
	#[wasm_bindgen(method, catch, js_name = signPrehash)]
	fn sign_prehash(this: &TransportSigner, prehash: Uint8Array) -> Result<JsValue, JsValue>;
}

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
	pub fn new(signer: TransportSigner) -> Result<Self, JsValue> {
		let oid: ObjectIdentifier = signer.algorithm_oid().parse().map_err(to_js)?;
		let algorithm = AlgorithmIdentifierOwned { oid, parameters: None };
		let public_key_der = signer.public_key_der().to_vec();

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
			let returned = invoked.map_err(external_key_error)?;

			// resolve() adopts thenables and passes plain values through,
			// so synchronous signers work unchanged.
			let promise = Promise::resolve(&returned);
			let settled = JsFuture::from(promise).await.map_err(external_key_error)?;

			let signature = Uint8Array::from(settled).to_vec();
			Ok(signature)
		})
	}
}

/// Wrap a JavaScript signer failure as a [`KeyError`], preserving its
/// message as the signature error source.
fn external_key_error(cause: JsValue) -> KeyError {
	let message = match cause.as_string() {
		Some(text) => text,
		None => format!("{cause:?}"),
	};

	let source = ExternalSignerError { message };
	KeyError::SignatureError(SignatureError::from_source(source))
}

/// JavaScript-side signing failure carried across the wasm boundary.
#[derive(Debug)]
struct ExternalSignerError {
	message: String,
}

impl core::fmt::Display for ExternalSignerError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "external signer failed: {}", self.message)
	}
}

impl std::error::Error for ExternalSignerError {}
