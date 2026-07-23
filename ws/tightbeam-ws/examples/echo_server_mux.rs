//! Multiplexed encrypted echo server for the tightbeam WebSocket transport.
//!
//! Negotiates HTTP/2-style stream multiplexing during the ECIES handshake,
//! splits each connection into exclusive halves, and serves concurrent
//! client streams with an echo handler.
//!
//! Two-way behavior: a request whose frame id starts with `call-me` makes
//! the server initiate its own stream back to the client carrying the same
//! frame. The client's answer becomes the response on the original stream.
//! A `sink` id accepts without a response frame, a `drain-calm` id drains
//! the session. Everything else echoes.
//!
//! When `TBWS_CLIENT_CERT` is set, the server additionally requires mutual
//! authentication, pinning that certificate as the only accepted client.
//!
//! Environment:
//!   - `TBWS_SERVER_CERT`     path to the server certificate DER
//!   - `TBWS_SERVER_KEY`      path to the raw 32-byte server signing key
//!   - `TBWS_CLIENT_CERT`     optional path to a pinned client certificate DER
//!   - `ECHO_WS_PORT`         listen port (default `9100`)
//!   - `MUX_PEER_STREAMS`     client-initiated concurrency cap (default `8`)

use std::env;
use std::fs;
use std::sync::Arc;

use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::x509::policy::{CertificateValidation, RuntimeCertificatePinning};
use tightbeam::der::{Decode, Encode};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::handshake::TcpHandshakeState;
use tightbeam::transport::multiplex::{MuxRole, MuxTransport};
use tightbeam::transport::state::EncryptedProtocolState;
use tightbeam::transport::{EncryptedMessageIO, EncryptedProtocol, MessageIO, WireEnvelope};
use tightbeam::x509::Certificate;
use tightbeam_ws::io::WsTransport;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{echo_stream, env_u32, Identity};
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The transport an accepted WebSocket connection follows.
type ServerTransport = WsTransport<MaybeTlsStream<TcpStream>>;

/// Handshake message ceiling: ECIES completes in two client messages, so
/// anything beyond a small bound is a protocol violation.
const MAX_HANDSHAKE_MESSAGES: usize = 4;

/// Drive the server-side ECIES handshake to completion over cleartext
/// containers, bounded by [`MAX_HANDSHAKE_MESSAGES`].
async fn serve_handshake(transport: &mut ServerTransport) -> Result<(), BoxError> {
	for _ in 0..MAX_HANDSHAKE_MESSAGES {
		if transport.to_handshake_state() == TcpHandshakeState::Complete {
			return Ok(());
		}

		let wire_bytes = transport.read_envelope().await?;
		let wire_envelope = WireEnvelope::from_der(&wire_bytes)?;
		let WireEnvelope::Cleartext(envelope) = wire_envelope else {
			return Err("handshake containers must be cleartext".into());
		};

		let handshake_bytes = envelope.to_der()?;
		transport.perform_server_handshake(&handshake_bytes).await?;
	}

	if transport.to_handshake_state() == TcpHandshakeState::Complete {
		return Ok(());
	}

	Err("handshake did not complete within the message ceiling".into())
}

/// Serve one multiplexed connection until it ends.
async fn serve_connection(mut transport: ServerTransport, peer_cap: u32) -> Result<(), BoxError> {
	transport = transport.with_mux_offer(Some(TransportOffer::mux(peer_cap)));
	serve_handshake(&mut transport).await?;

	let settings = transport.negotiated_mux().ok_or("the client did not negotiate multiplexing")?;
	let (reader, writer) = transport.into_split()?;

	let mux = MuxTransport::new(reader, writer, MuxRole::Server, settings);
	let (handle, reader_driver, writer_driver, responder) = mux.into_parts();

	let reader_task = tokio::spawn(reader_driver.drive());
	let writer_task = tokio::spawn(writer_driver.drive());

	let outcome = responder.serve(move |frame| echo_stream(handle.clone(), frame)).await;

	reader_task.abort();
	writer_task.abort();
	outcome?;
	Ok(())
}

/// Pin the client certificate at `path` as the only accepted client identity.
fn client_validators(path: &str) -> Result<Vec<Arc<dyn CertificateValidation>>, BoxError> {
	let cert = Certificate::from_der(&fs::read(path)?)?;
	let pinning = RuntimeCertificatePinning::<Sha3_256>::from_certificates([cert])?;

	Ok(vec![Arc::new(pinning)])
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port = env_u32("ECHO_WS_PORT", 9100);
	let peer_cap = env_u32("MUX_PEER_STREAMS", 8);
	let bind_addr = TightBeamSocketAddr(format!("0.0.0.0:{port}").parse()?);

	let identity = Identity::from_env()?;
	let mut config = identity.server_config();

	let mut mode = "server-auth";
	if let Ok(client_cert) = env::var("TBWS_CLIENT_CERT") {
		config = config.with_client_validators(client_validators(&client_cert)?);
		mode = "mutual-auth";
	}

	let (listener, bound) = <WsListener as EncryptedProtocol>::bind_with(bind_addr, config).await?;

	println!(
		"[echo-mux] multiplexed encrypted ({mode}) tightbeam-ws echo server listening on ws://{}",
		bound.0
	);

	loop {
		// A failed WebSocket upgrade is a per-connection fault (bad
		// handshake, probe, abrupt teardown), never server-fatal.
		let (transport, peer) = match listener.accept().await {
			Ok(accepted) => accepted,
			Err(error) => {
				eprintln!("[echo-mux] accept failed: {error}");
				continue;
			}
		};

		tokio::spawn(async move {
			if let Err(error) = serve_connection(transport, peer_cap).await {
				eprintln!("[echo-mux] connection from {peer} ended: {error}");
			}
		});
	}
}
