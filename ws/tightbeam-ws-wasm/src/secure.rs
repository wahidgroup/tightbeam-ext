//! Encrypted transport assembly for the browser WebSocket client.
//! Compiled only for `wasm32` targets.
//!
//! Builds tightbeam's transport-level ECIES machinery over a `gloo`
//! WebSocket ([`GlooStream`]) for the multiplexed client (`MuxWsClient`).
//!
//! The session profile is a compile-time choice, exactly as with a native
//! tightbeam-rs transport: [`build_transport_with`] assembles the transport
//! for any [`CryptoProvider`] monomorphization, while the shipped bindings
//! instantiate the tightbeam default profile.

use std::sync::Arc;

use gloo_net::websocket::futures::WebSocket;
use wasm_bindgen::prelude::*;

use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
use tightbeam::der::{Decode, Encode};
use tightbeam::transport::handshake::HandshakeKeyManager;
use tightbeam::transport::X509ClientConfig;
use tightbeam::x509::Certificate;
use tightbeam::Frame;

use crate::fault::to_js;
use crate::signer::{JsSigningKeyProvider, TransportSigner};
use crate::socket::{open_observed, SocketMonitor};
use crate::stream::{GlooStream, WsTransport};

/// Encode an optional response frame back to DER for JavaScript.
pub(crate) fn response_der(response: Option<Frame>) -> Result<Option<Vec<u8>>, JsValue> {
	match response {
		Some(frame) => Ok(Some(frame.to_der().map_err(to_js)?)),
		None => Ok(None),
	}
}

/// Client material for mutual authentication, as raw profile bytes.
pub(crate) struct ClientIdentity<'a> {
	pub(crate) cert_der: &'a [u8],
	pub(crate) signing_key: &'a [u8],
}

/// Client identity material decoded for the target provider, presented to
/// the server for mutual authentication.
pub struct ClientCredentials<P: CryptoProvider> {
	/// The certificate presented to the server.
	pub certificate: Arc<Certificate>,
	/// The signing capability proving possession of the certificate key.
	pub key_manager: Arc<HandshakeKeyManager<P>>,
}

impl<P> ClientCredentials<P>
where
	P: CryptoProvider + Send + Sync + 'static,
{
	/// Decode a certificate plus external signer into credentials for any
	/// compile-time crypto provider: the key stays in JavaScript, only OIDs
	/// and signature bytes cross the boundary.
	///
	/// The signer's output MUST verify under `P`'s signature algorithm.
	/// Custom-profile builds pair this with [`build_transport_with`].
	pub fn from_signer(cert_der: &[u8], signer: TransportSigner) -> Result<Self, JsValue> {
		let certificate = Certificate::from_der(cert_der).map_err(to_js)?;
		let provider = JsSigningKeyProvider::new(signer)?.into_provider();
		let key_manager = HandshakeKeyManager::new(provider);

		let credentials = Self { certificate: Arc::new(certificate), key_manager: Arc::new(key_manager) };
		Ok(credentials)
	}
}

/// Build the tightbeam-profile trust store: a single anchor pinning
/// `server_cert_der`, validated under SHA3-256 digests and the secp256k1
/// certificate policy (matching [`DefaultCryptoProvider`]).
pub fn profile_trust_store(server_cert_der: &[u8]) -> Result<Arc<dyn CertificateTrust>, JsValue> {
	let server_cert = Certificate::from_der(server_cert_der).map_err(to_js)?;
	let store = CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
		.with_certificate(server_cert)
		.map_err(to_js)?
		.build();

	let trust_store: Arc<dyn CertificateTrust> = Arc::new(store);
	Ok(trust_store)
}

/// Assemble an encrypted transport for any compile-time crypto provider
/// over an already-opened `socket`: attach the trust store, and optionally
/// present client credentials for mutual authentication.
///
/// The provider is chosen by the caller's monomorphization. The trust store
/// MUST validate under the same algorithms or every handshake fails. Custom
/// profile builds pair this with their own `#[wasm_bindgen]` bindings. The
/// shipped bindings use [`DefaultCryptoProvider`] with [`profile_trust_store`]
/// and open their socket through the lifecycle observer.
pub fn build_transport_with<P>(
	socket: WebSocket,
	trust_store: Arc<dyn CertificateTrust>,
	credentials: Option<ClientCredentials<P>>,
) -> WsTransport<P>
where
	P: CryptoProvider + Send + Sync,
{
	let stream = GlooStream::from(socket);
	let mut transport = WsTransport::<P>::from(stream).with_trust_store(trust_store);
	if let Some(credentials) = credentials {
		transport = transport.with_client_identity(credentials.certificate, credentials.key_manager);
	}

	transport
}

/// Decode profile identity bytes into credentials for the default provider.
///
/// The `Arc` satisfies tightbeam's shared-ownership API. Wasm is
/// single-threaded, so the missing `Send + Sync` never matters.
#[allow(clippy::arc_with_non_send_sync)]
fn profile_credentials(identity: ClientIdentity<'_>) -> Result<ClientCredentials<DefaultCryptoProvider>, JsValue> {
	let certificate = Arc::new(Certificate::from_der(identity.cert_der).map_err(to_js)?);
	let signing_key = signing_key_from_bytes(identity.signing_key)?;
	let key_manager = Arc::new(HandshakeKeyManager::from(signing_key));

	let credentials = ClientCredentials { certificate, key_manager };
	Ok(credentials)
}

/// Assemble the default-profile encrypted transport from raw DER inputs,
/// returning the transport plus the socket's lifecycle monitor.
pub(crate) fn build_transport(
	url: &str,
	server_cert_der: &[u8],
	identity: Option<ClientIdentity<'_>>,
) -> Result<(WsTransport, SocketMonitor), JsValue> {
	let trust_store = profile_trust_store(server_cert_der)?;
	let credentials = match identity {
		Some(identity) => Some(profile_credentials(identity)?),
		None => None,
	};

	let observed = open_observed(url)?;
	let transport = build_transport_with(observed.socket, trust_store, credentials);
	Ok((transport, observed.monitor))
}

/// Assemble the default-profile mutually-authenticated transport with an
/// external signer proving possession of the client certificate key.
pub(crate) fn build_signer_transport(
	url: &str,
	server_cert_der: &[u8],
	client_cert_der: &[u8],
	signer: TransportSigner,
) -> Result<(WsTransport, SocketMonitor), JsValue> {
	let trust_store = profile_trust_store(server_cert_der)?;
	let credentials = ClientCredentials::<DefaultCryptoProvider>::from_signer(client_cert_der, signer)?;

	let observed = open_observed(url)?;
	let transport = build_transport_with(observed.socket, trust_store, Some(credentials));
	Ok((transport, observed.monitor))
}

/// Decode a raw 32-byte secp256k1 scalar into a signing key.
fn signing_key_from_bytes(bytes: &[u8]) -> Result<Secp256k1SigningKey, JsValue> {
	let scalar: [u8; 32] = bytes
		.try_into()
		.map_err(|_| JsValue::from_str("secp256k1 signing key must be exactly 32 bytes"))?;

	Secp256k1SigningKey::from_bytes(&scalar.into()).map_err(to_js)
}
