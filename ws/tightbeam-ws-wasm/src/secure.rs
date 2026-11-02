//! Encrypted transport assembly for the browser WebSocket client.
//! Compiled only for `wasm32` targets.
//!
//! Builds tightbeam's transport-level HPKE machinery over a `gloo`
//! WebSocket ([`GlooStream`]) for the multiplexed client (`MuxWsClient`).
//!
//! The session profile is a compile-time choice, exactly as with a native
//! tightbeam-rs transport: [`build_transport_with`] assembles the transport
//! for any [`HandshakeProvider`] monomorphization, while the shipped bindings
//! instantiate the tightbeam default profile.

use std::sync::Arc;

use gloo_net::websocket::futures::WebSocket;
use wasm_bindgen::prelude::*;

use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::KeyCurves;
use tightbeam::der::{Decode, Encode};
use tightbeam::transport::handshake::HandshakeProvider;
use tightbeam::x509::Certificate;
use tightbeam::Frame;

use crate::clock::BrowserClock;
use crate::fault::{to_js, transport_to_js, validation};
use crate::protocol::BrowserSocket;
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

/// Build the tightbeam-profile trust store: a single anchor pinning
/// `server_cert_der`, validated under the secp256k1 certificate policy
/// (matching [`DefaultCryptoProvider`]) on the host's clock.
pub fn profile_trust_store(server_cert_der: &[u8]) -> Result<Arc<dyn CertificateTrust>, JsValue> {
	let server_cert = Certificate::from_der(server_cert_der).map_err(to_js)?;
	let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation)
		.with_clock(Arc::new(BrowserClock));
	let store = builder.with_certificate(server_cert).map_err(to_js)?.build();

	let trust_store: Arc<dyn CertificateTrust> = Arc::new(store);
	Ok(trust_store)
}

/// Assemble an encrypted transport for any compile-time crypto provider
/// over an already-opened `socket`: attach the trust store, and optionally
/// present `identity` for mutual authentication.
///
/// The provider is chosen by the caller's monomorphization. The trust store
/// MUST validate under the same algorithms or every handshake fails. Custom
/// profile builds pair this with their own `#[wasm_bindgen]` bindings. The
/// shipped bindings use [`DefaultCryptoProvider`] with [`profile_trust_store`]
/// and open their socket through the lifecycle observer.
pub fn build_transport_with<P>(
	socket: WebSocket,
	trust_store: Arc<dyn CertificateTrust>,
	identity: Option<SigningIdentity>,
) -> Result<WsTransport<P>, JsValue>
where
	P: HandshakeProvider,
{
	BrowserSocket::pinned(GlooStream::from(socket), trust_store, identity).map_err(transport_to_js)
}

/// A cleartext transport over `socket`, on the host's clock. It carries no
/// confidentiality, integrity, or peer authentication.
pub(crate) fn cleartext_transport(socket: WebSocket) -> Result<WsTransport, JsValue> {
	BrowserSocket::cleartext(GlooStream::from(socket)).map_err(transport_to_js)
}

/// Decode profile identity bytes into the identity of the default provider.
///
/// The `Arc` satisfies tightbeam's shared-ownership API. Wasm is
/// single-threaded, so the missing `Send + Sync` never matters.
#[allow(clippy::arc_with_non_send_sync)]
fn profile_identity(identity: ClientIdentity<'_>) -> Result<SigningIdentity, JsValue> {
	let certificate = Certificate::from_der(identity.cert_der).map_err(to_js)?;
	let signing_key = signing_key_from_bytes(identity.signing_key)?;
	let provider = Arc::new(Secp256k1KeyProvider::from(signing_key));

	SigningIdentity::new(certificate, provider).map_err(to_js)
}

/// Assemble the default-profile encrypted transport from raw DER inputs,
/// returning the transport plus the socket's lifecycle monitor.
pub(crate) fn build_transport(
	url: &str,
	server_cert_der: &[u8],
	identity: Option<ClientIdentity<'_>>,
) -> Result<(WsTransport, SocketMonitor), JsValue> {
	let trust_store = profile_trust_store(server_cert_der)?;
	let identity = match identity {
		Some(identity) => Some(profile_identity(identity)?),
		None => None,
	};

	let observed = open_observed(url)?;
	let transport = build_transport_with(observed.socket, trust_store, identity)?;
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
	let identity = JsSigningKeyProvider::identity::<DefaultCryptoProvider>(signer, client_cert_der)?;

	let observed = open_observed(url)?;
	let transport = build_transport_with(observed.socket, trust_store, Some(identity))?;
	Ok((transport, observed.monitor))
}

/// Decode a raw 32-byte secp256k1 scalar into a signing key.
fn signing_key_from_bytes(bytes: &[u8]) -> Result<Secp256k1SigningKey, JsValue> {
	let scalar: [u8; 32] = bytes
		.try_into()
		.map_err(|_| validation("InvalidSigningKey", "secp256k1 signing key must be exactly 32 bytes"))?;

	Secp256k1SigningKey::from_bytes(&scalar.into()).map_err(to_js)
}
