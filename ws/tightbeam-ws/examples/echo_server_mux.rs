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
//! When `TBWS_PAYWALL=1`, the server installs the demo budget authorizer
//! and requires mutual auth (`TBWS_CLIENT_CERT`).
//!
//! Body dispatch (`TBWS_ECHO_BODY`):
//!   - unset / `streaming` - [`EchoFrames`] (unary Frame echo + `openStream`)
//!   - `duplex`            - `serve_duplex` (chunk echo for `openDuplex`)
//!   - `unary`             - classic reassembled `serve` (Frame only)
//!
//! Environment:
//!   - `TBWS_SERVER_CERT`     path to the server certificate DER
//!   - `TBWS_SERVER_KEY`      path to the raw 32-byte server signing key
//!   - `TBWS_CLIENT_CERT`     optional path to a pinned client certificate DER
//!   - `TBWS_PAYWALL`         enable demo session-budget paywall
//!   - `TBWS_MUX_BUDGET_C2S`  client→server credit ceiling (default `4096`)
//!   - `TBWS_MUX_BUDGET_S2C`  server→client credit ceiling (default `4096`)
//!   - `TBWS_ECHO_BODY`       `streaming` (default) | `duplex` | `unary`
//!   - `ECHO_WS_PORT`         listen port (default `9100`)
//!   - `MUX_PEER_STREAMS`     client-initiated concurrency cap (default `8`)

use std::env;
use std::fs;
use std::sync::Arc;

use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::x509::policy::{CertificateValidation, RuntimeCertificatePinning};
use tightbeam::der::Decode;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::handshake::negotiation::{TransportAuthorizer, TransportOffer};
use tightbeam::transport::multiplex::MuxRole;
use tightbeam::transport::EncryptedProtocol;
use tightbeam::x509::Certificate;
use tightbeam_ws::io::WsTransport;
use tightbeam_ws::mux::assemble_mux;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{
	budget_ceiling, echo_duplex, echo_stream, env_u32, paywall_enabled, serve_handshake, DemoPaywall, EchoFrames,
	Identity,
};
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The transport an accepted WebSocket connection follows.
type ServerTransport = WsTransport<MaybeTlsStream<TcpStream>>;

/// Serve one multiplexed connection until it ends.
async fn serve_connection(
	mut transport: ServerTransport,
	peer_cap: u32,
	authorizer: Option<Arc<dyn TransportAuthorizer>>,
) -> Result<(), BoxError> {
	let mut offer = TransportOffer::mux(peer_cap);
	if authorizer.is_some() {
		offer = offer.with_budgets(budget_ceiling());
	}

	transport = transport.with_mux_offer(Some(offer));
	if let Some(authorizer) = authorizer {
		transport = transport.with_transport_authorizer(authorizer);
	}

	serve_handshake(&mut transport).await?;

	let mux = assemble_mux(transport, MuxRole::Server)?;
	let (handle, reader_driver, writer_driver, responder) = mux.into_parts();

	let reader_task = tokio::spawn(reader_driver.drive());
	let writer_task = tokio::spawn(writer_driver.drive());

	let body_mode = env::var("TBWS_ECHO_BODY").unwrap_or_else(|_| "streaming".into());
	let outcome = match body_mode.as_str() {
		"unary" => responder.serve(move |frame| echo_stream(handle.clone(), frame)).await,
		"duplex" => responder.serve_duplex(echo_duplex).await,
		_ => responder.serve_with(EchoFrames::new(handle)).await,
	};

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
	let paywall = paywall_enabled();

	let identity = Identity::from_env()?;
	let mut config = identity.server_config();

	let mut mode = "server-auth";
	let client_cert = env::var("TBWS_CLIENT_CERT");
	if paywall && client_cert.is_err() {
		return Err("TBWS_PAYWALL requires TBWS_CLIENT_CERT (mutual auth)".into());
	}
	if let Ok(client_cert) = client_cert {
		config = config.with_client_validators(client_validators(&client_cert)?);
		mode = "mutual-auth";
	}

	let authorizer = if paywall {
		mode = "mutual-auth+paywall";
		Some(DemoPaywall::shared()?)
	} else {
		None
	};

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

		let authorizer = authorizer.clone();
		tokio::spawn(async move {
			if let Err(error) = serve_connection(transport, peer_cap, authorizer).await {
				eprintln!("[echo-mux] connection from {peer} ended: {error}");
			}
		});
	}
}
