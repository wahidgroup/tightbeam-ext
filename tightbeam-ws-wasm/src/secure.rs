//! Encrypted browser WebSocket client. Compiled only for `wasm32` targets.
//!
//! Drives tightbeam's transport-level ECIES handshake over a `gloo` WebSocket
//! ([`GlooStream`]). The server is always authenticated by pinning its
//! certificate in a single-anchor trust store. Supplying a client certificate
//! and signing key additionally performs mutual authentication.

use std::sync::Arc;

use gloo_net::websocket::futures::WebSocket;
use wasm_bindgen::prelude::*;

use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
use tightbeam::der::{Decode, Encode};
use tightbeam::transport::handshake::HandshakeKeyManager;
use tightbeam::transport::{MessageEmitter, X509ClientConfig};
use tightbeam::x509::Certificate;
use tightbeam::Frame;

use crate::stream::{GlooStream, WsTransport};

/// A tightbeam client over a single encrypted browser WebSocket session.
#[wasm_bindgen]
pub struct SecureWsClient {
	transport: WsTransport,
}

#[wasm_bindgen]
impl SecureWsClient {
	/// Open a server-authenticated session to `url`, pinning `server_cert_der`
	/// as the sole trusted server certificate. The ECIES handshake runs lazily
	/// on the first [`request`](Self::request).
	#[wasm_bindgen(js_name = connect)]
	pub fn connect(url: &str, server_cert_der: &[u8]) -> Result<SecureWsClient, JsValue> {
		let transport = build_transport(url, server_cert_der, None)?;
		Ok(Self { transport })
	}

	/// Open a mutually-authenticated session: as [`connect`](Self::connect),
	/// additionally presenting `client_cert_der` and the raw 32-byte secp256k1
	/// `client_signing_key` so the server can authenticate this client.
	#[wasm_bindgen(js_name = connectMutual)]
	pub fn connect_mutual(
		url: &str,
		server_cert_der: &[u8],
		client_cert_der: &[u8],
		client_signing_key: &[u8],
	) -> Result<SecureWsClient, JsValue> {
		let identity = ClientIdentity { cert_der: client_cert_der, signing_key: client_signing_key };
		let transport = build_transport(url, server_cert_der, Some(identity))?;
		Ok(Self { transport })
	}

	/// Send a DER-encoded tightbeam [`Frame`] over the encrypted session and
	/// resolve with the DER-encoded response frame, or `undefined` when the
	/// server returned no payload. The first call performs the handshake.
	#[wasm_bindgen(js_name = request)]
	pub async fn request(&mut self, frame_der: Vec<u8>) -> Result<Option<Vec<u8>>, JsValue> {
		let frame = Frame::from_der(&frame_der).map_err(to_js)?;
		let response = self.transport.emit(frame, None).await.map_err(to_js)?;

		match response {
			Some(frame) => Ok(Some(frame.to_der().map_err(to_js)?)),
			None => Ok(None),
		}
	}
}

/// Client material for mutual authentication.
struct ClientIdentity<'a> {
	cert_der: &'a [u8],
	signing_key: &'a [u8],
}

/// Assemble the encrypted transport: open the socket, pin the server
/// certificate, and optionally attach a client identity for mutual auth.
fn build_transport(
	url: &str,
	server_cert_der: &[u8],
	identity: Option<ClientIdentity<'_>>,
) -> Result<WsTransport, JsValue> {
	let socket = WebSocket::open(url).map_err(to_js)?;
	let server_cert = Certificate::from_der(server_cert_der).map_err(to_js)?;

	let trust_store: Arc<dyn CertificateTrust> = Arc::new(
		CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
			.with_certificate(server_cert)
			.map_err(to_js)?
			.build(),
	);

	let mut transport = GlooStream::from(socket).into_transport().with_trust_store(trust_store);

	if let Some(identity) = identity {
		let client_cert = Certificate::from_der(identity.cert_der).map_err(to_js)?;
		let key_manager = HandshakeKeyManager::from(signing_key_from_bytes(identity.signing_key)?);
		transport = transport.with_client_identity(client_cert, key_manager);
	}

	Ok(transport)
}

/// Decode a raw 32-byte secp256k1 scalar into a signing key.
fn signing_key_from_bytes(bytes: &[u8]) -> Result<Secp256k1SigningKey, JsValue> {
	let scalar: [u8; 32] = bytes
		.try_into()
		.map_err(|_| JsValue::from_str("secp256k1 signing key must be exactly 32 bytes"))?;

	Secp256k1SigningKey::from_bytes(&scalar.into()).map_err(to_js)
}

/// Surface any displayable error to JavaScript as a string `JsValue`.
fn to_js<E: core::fmt::Display>(error: E) -> JsValue {
	JsValue::from_str(&error.to_string())
}
