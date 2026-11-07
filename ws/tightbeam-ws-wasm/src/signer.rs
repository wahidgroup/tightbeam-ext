//! JavaScript-backed transport signing. Compiled only for `wasm32` targets.
//!
//! Adapts an external JavaScript signer to tightbeam's [`SigningKeyProvider`]
//! so mutual authentication never needs raw key bytes. The signer is
//! duck-typed: any object with an `algorithmOid` string, a `publicKeyDer`
//! `Uint8Array`, and a `signPrehash` method that resolves with a `Uint8Array`
//! qualifies. [`JsSigningKeyProvider::new`] refuses any other shape.

use std::sync::Arc;

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use tightbeam::asn1::AlgorithmIdentifierOwned;
use tightbeam::crypto::key::{KeyBackend, KeyError, SigningKeyProvider};
use tightbeam::crypto::profiles::SigningProvider;
use tightbeam::crypto::sign::{Error as SignatureError, SigningIdentity};
use tightbeam::der::Decode;
use tightbeam::marker::MaybeSendFuture;
use tightbeam::spki::DecodePublicKey;
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;

use crate::bindings::Oid;
use crate::fault::{JsFault, RefusalCode, TransportCode};
use crate::promise::{JsBytes, Record, Returned};

#[wasm_bindgen(typescript_custom_section)]
const TRANSPORT_SIGNER_TS: &'static str = r#"
/**
 * External transport signer for mutual authentication.
 *
 * Algorithm-agnostic: receives the handshake prehash (already digested
 * under the session profile) and must sign it directly (no rehash),
 * returning the signature encoding the session profile names. The shipped
 * default-profile build expects a DER `ECDSA-Sig-Value` over secp256k1.
 * Custom-profile builds expect their own profile's encoding. Backed by
 * WebAuthn, wallets, KMS bridges, or any custom key store. The private key
 * never crosses into wasm.
 *
 * `publicKeyDer` MUST encode the key of the client certificate, or the
 * dial refuses the signer.
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
	 * MUST encode the same key as the SPKI in the presented client
	 * certificate.
	 */
	readonly publicKeyDer: Uint8Array;
	/**
	 * Sign the handshake transcript prehash.
	 *
	 * Resolves with the profile signature encoding. The default profile
	 * expects a DER `ECDSA-Sig-Value` (RFC 3279 § 2.2.3).
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

	/// Dotted signature-algorithm OID (e.g. `2.16.840.1.101.3.4.3.10`), as
	/// the signer hands it over.
	#[wasm_bindgen(method, getter, js_name = algorithmOid)]
	fn algorithm_oid(this: &TransportSigner) -> JsValue;

	/// DER-encoded SubjectPublicKeyInfo for the signing key, as the signer
	/// hands it over.
	#[wasm_bindgen(method, getter, js_name = publicKeyDer)]
	fn public_key_der(this: &TransportSigner) -> JsValue;

	/// Sign the given prehash. Returns the signature bytes or a promise of them.
	#[wasm_bindgen(method, catch, js_name = signPrehash)]
	fn sign_prehash(this: &TransportSigner, prehash: Uint8Array) -> Result<JsValue, JsValue>;
}

/// Programmatic failures when adapting a JavaScript signer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignerFault {
	EmptySignature,
	NotBytes,
	JsRejected,
}

impl SignerFault {
	fn message(self) -> &'static str {
		match self {
			Self::EmptySignature => "signPrehash returned an empty signature",
			Self::NotBytes => "signPrehash must resolve with a Uint8Array",
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

/// The key error of a signer fault: a signature error whose source is the
/// fault.
impl From<SignerFault> for KeyError {
	fn from(fault: SignerFault) -> Self {
		Self::SignatureError(SignatureError::from_source(fault))
	}
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
	///
	/// [`SigningIdentity::with_provider`] pairs the provider with a
	/// certificate, and refuses a key the certificate does not carry.
	///
	/// # Errors
	///
	/// - `InvalidSigner` -- `signPrehash` is not a function.
	/// - `InvalidOid` -- `algorithmOid` is no dotted object identifier.
	/// - `InvalidBytes` -- `publicKeyDer` is not a `Uint8Array`.
	pub fn new(signer: TransportSigner) -> Result<Self, JsFault> {
		let sign = Record::member(&signer, "signer.signPrehash");
		if !sign.is_function() {
			return Err(RefusalCode::InvalidSigner
				.because("must be a function")
				.at("signer.signPrehash"));
		}

		let oid = Oid::read(&signer.algorithm_oid(), "signer.algorithmOid")?;
		let algorithm = AlgorithmIdentifierOwned { oid, parameters: None };

		let public_key = signer.public_key_der();
		let public_key_der = JsBytes::read_value(&public_key, "signer.publicKeyDer")?;

		Ok(Self { signer, algorithm, public_key_der })
	}

	/// Erase to the trait object a signing identity consumes.
	pub fn into_provider(self) -> Arc<dyn SigningKeyProvider> {
		Arc::new(self)
	}

	/// Pair the certificate in `cert_der` with `signer` under the signature
	/// algorithm of the compile-time provider `P`: the key stays in
	/// JavaScript, and only OIDs and signature bytes cross the boundary.
	///
	/// The signer's output MUST verify under `P`'s signature algorithm.
	/// Custom-profile builds pair this with [`BrowserSocket::pinned`].
	///
	/// [`BrowserSocket::pinned`]: crate::protocol::BrowserSocket::pinned
	///
	/// # Errors
	///
	/// - The errors of [`Self::new`] and [`Self::into_identity`].
	pub fn identity<P>(signer: TransportSigner, cert_der: &[u8]) -> Result<SigningIdentity, JsFault>
	where
		P: SigningProvider + 'static,
		P::VerifyingKey: DecodePublicKey + PartialEq,
	{
		Self::new(signer)?.into_identity::<P>(cert_der)
	}

	/// Pair the certificate in `cert_der` with this signer under the
	/// signature algorithm of the compile-time provider `P`.
	///
	/// # Errors
	///
	/// - `InvalidCertificate` -- `cert_der` is no DER certificate.
	/// - `Signer` -- the signer names another algorithm than `P`, its key is no key of `P`, or
	///   the certificate carries another key than the signer's.
	/// - `CertificateValidationError` -- the certificate is refused for signing.
	pub fn into_identity<P>(self, cert_der: &[u8]) -> Result<SigningIdentity, JsFault>
	where
		P: SigningProvider + 'static,
		P::VerifyingKey: DecodePublicKey + PartialEq,
	{
		let certificate = Certificate::from_der(cert_der);
		let certificate = certificate.map_err(|error| TransportCode::InvalidCertificate.because(error))?;

		let identity = SigningIdentity::with_provider::<P>(certificate, self.into_provider());
		identity.map_err(|error| JsFault::from(TightBeamError::from(error)))
	}
}

impl core::fmt::Debug for JsSigningKeyProvider {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("JsSigningKeyProvider")
			.field("algorithm", &self.algorithm)
			.finish_non_exhaustive()
	}
}

impl KeyBackend for JsSigningKeyProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.algorithm.clone()
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		Ok(self.public_key_der.clone())
	}
}

impl SigningKeyProvider for JsSigningKeyProvider {
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let argument = Uint8Array::from(prehash);
		let invoked = self.signer.sign_prehash(argument).map(Returned::from);

		Box::pin(async move {
			let returned = invoked.map_err(|_| SignerFault::JsRejected)?;
			let settled = returned.settle().await.map_err(|_| SignerFault::JsRejected)?;

			let signature = JsBytes::recognize(&settled).ok_or(SignerFault::NotBytes)?;
			if signature.is_empty() {
				return Err(SignerFault::EmptySignature.into());
			}

			Ok(signature)
		})
	}
}

#[cfg(test)]
mod tests {
	use core::error::Error;

	use js_sys::Function;
	use tightbeam::crypto::key::{KeyError, SigningKeyProvider};
	use wasm_bindgen::{JsCast, JsValue};
	use wasm_bindgen_test::wasm_bindgen_test;

	use super::{JsSigningKeyProvider, SignerFault};

	/// A signer whose `signPrehash` resolves with an array of numbers.
	fn array_signer() -> JsSigningKeyProvider {
		let body = "return { algorithmOid: '2.16.840.1.101.3.4.3.10', publicKeyDer: new Uint8Array(1), \
		            signPrehash: () => Promise.resolve([1, 2, 3]) }";
		let signer = Function::new_no_args(body).call0(&JsValue::UNDEFINED);
		let signer = signer.expect("the signer should build");

		JsSigningKeyProvider::new(signer.unchecked_into()).expect("the signer should be shaped")
	}

	/// The signer fault that a refused signature carries as its source.
	fn fault_of(signed: Result<Vec<u8>, KeyError>) -> Option<SignerFault> {
		let Err(KeyError::SignatureError(error)) = signed else {
			return None;
		};

		let source = error.source()?;
		source.downcast_ref().copied()
	}

	#[wasm_bindgen_test]
	async fn an_array_signature_is_refused() {
		let signed = array_signer().sign_prehash(&[0u8; 32]).await;
		assert_eq!(fault_of(signed), Some(SignerFault::NotBytes));
	}
}
