//! The JavaScript signer of mutual authentication, as the browser transport
//! section of `docs/ws-wasm.md` describes.

use std::sync::Arc;

use js_sys::{Function, Uint8Array};
use wasm_bindgen::prelude::*;

use tightbeam::asn1::AlgorithmIdentifierOwned;
use tightbeam::crypto::key::{KeyBackend, KeyError, SigningKeyProvider};
use tightbeam::crypto::profiles::SigningProvider;
use tightbeam::crypto::sign::{Error as SignatureError, SigningIdentity};
use tightbeam::marker::MaybeSendFuture;
use tightbeam::spki::DecodePublicKey;
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;

use crate::bindings::Oid;
use crate::fault::JsFault;
use crate::promise::{Callback, JsBytes, Record, Returned};

#[wasm_bindgen(typescript_custom_section)]
const TRANSPORT_SIGNER_TS: &'static str = r#"
/**
 * An external signer for mutual authentication, such as WebAuthn, a wallet,
 * or a KMS bridge, whose private key stays in its JavaScript backend.
 *
 * - The signer signs the handshake prehash directly, with no rehash, in the
 *   signature encoding of the session profile: a DER `ECDSA-Sig-Value` over
 *   secp256k1 for the shipped build.
 * - `publicKeyDer` MUST encode the key of the client certificate, or the dial
 *   refuses the signer.
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
	 *
	 * @throws any error of the implementation, which fails the handshake.
	 */
	readonly signPrehash: (prehash: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}
"#;

#[wasm_bindgen]
extern "C" {
	/// An external signer as JavaScript hands it over, which
	/// [`JsSigningKeyProvider::new`] reads once.
	#[wasm_bindgen(js_name = TransportSigner, typescript_type = "TransportSigner")]
	pub type TransportSigner;

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
/// The construction reads the algorithm OID, the public key, and the
/// `signPrehash` function once, so each handshake calls the function that
/// construction admitted.
pub struct JsSigningKeyProvider {
	signer: TransportSigner,
	sign: Function,
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
	/// - `InvalidCallback` -- `signPrehash` is not a function.
	/// - `InvalidOid` -- `algorithmOid` is no dotted object identifier.
	/// - `InvalidBytes` -- `publicKeyDer` is not a `Uint8Array`.
	pub fn new(signer: TransportSigner) -> Result<Self, JsFault> {
		let sign = Callback::read(&Record::member(&signer, "signPrehash"), "signer.signPrehash")?;
		let oid = Oid::read(&Record::member(&signer, "algorithmOid"), "signer.algorithmOid")?;
		let algorithm = AlgorithmIdentifierOwned { oid, parameters: None };

		let public_key_der = JsBytes::read_member(&signer, "signer.publicKeyDer")?;
		Ok(Self { signer, sign, algorithm, public_key_der })
	}

	/// Erase to the trait object a signing identity consumes.
	pub fn into_provider(self) -> Arc<dyn SigningKeyProvider> {
		Arc::new(self)
	}

	/// Pair `certificate` with `signer` under the signature algorithm of the
	/// compile-time provider `P`: the key stays in JavaScript, and only OIDs
	/// and signature bytes cross the boundary.
	///
	/// - The signer's output MUST verify under `P`'s signature algorithm.
	/// - Custom-profile builds pair this with [`BrowserSocket::pinned`].
	///
	/// [`BrowserSocket::pinned`]: crate::protocol::BrowserSocket::pinned
	///
	/// # Errors
	///
	/// - The errors of [`Self::new`] and [`Self::into_identity`].
	pub fn identity<P>(signer: TransportSigner, certificate: Certificate) -> Result<SigningIdentity, JsFault>
	where
		P: SigningProvider + 'static,
		P::VerifyingKey: DecodePublicKey + PartialEq,
	{
		Self::new(signer)?.into_identity::<P>(certificate)
	}

	/// Pair `certificate` with this signer under the signature algorithm of
	/// the compile-time provider `P`.
	///
	/// # Errors
	///
	/// - `Signer` -- the signer names another algorithm than `P`, its key is no key of `P`, or
	///   the certificate carries another key than the signer's.
	/// - `CertificateValidationError` -- the certificate is refused for signing.
	pub fn into_identity<P>(self, certificate: Certificate) -> Result<SigningIdentity, JsFault>
	where
		P: SigningProvider + 'static,
		P::VerifyingKey: DecodePublicKey + PartialEq,
	{
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
		let invoked = self.sign.call1(&self.signer, &argument).map(Returned::from);

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

	use js_sys::{Function, Reflect};
	use tightbeam::crypto::key::{KeyError, SigningKeyProvider};
	use wasm_bindgen::{JsCast, JsValue};
	use wasm_bindgen_test::wasm_bindgen_test;

	use super::{JsSigningKeyProvider, SignerFault};
	use crate::loopback::settled;

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
	async fn a_signer_signs_with_the_function_it_was_admitted_with() {
		let body = "return { algorithmOid: '2.16.840.1.101.3.4.3.10', publicKeyDer: new Uint8Array(1), \
		            signPrehash: () => new Uint8Array([1]) }";
		let signer = Function::new_no_args(body).call0(&JsValue::UNDEFINED);
		let signer = signer.expect("the signer should build");
		let provider = JsSigningKeyProvider::new(signer.clone().unchecked_into()).expect("the signer should be shaped");

		let replaced = Reflect::set(&signer, &JsValue::from_str("signPrehash"), &JsValue::from_f64(7.0));
		replaced.expect("the signer should take a new member");

		let signed = settled(provider.sign_prehash(&[0u8; 32])).await;
		assert_eq!(signed.ok(), Some(vec![1]));
	}

	#[wasm_bindgen_test]
	async fn an_array_signature_is_refused() {
		let signed = settled(array_signer().sign_prehash(&[0u8; 32])).await;
		assert_eq!(fault_of(signed), Some(SignerFault::NotBytes));
	}
}
