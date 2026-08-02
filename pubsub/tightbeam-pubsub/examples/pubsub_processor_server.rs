//! Backend payload processor servlet for the processed-board demo.
//!
//! Runs only as a backend process: browsers never reach it. The demo
//! server's `RelayBackplane` dials it over a multiplexed encrypted
//! tightbeam-ws connection and relays every publish through it. The
//! servlet answers each request with the transformed inner frame,
//! which is what the registry then sequences and fans out.
//!
//! Each relayed payload is a full tightbeam frame (the frame-in-frame
//! pattern) whose body is a JSON note. The servlet lifts the inner
//! frame, uppercases the note's `text`, and rebuilds an unsigned inner
//! frame around the transformed note: mid-stream transformation and the
//! publisher's signature are mutually exclusive by design. The rebuilt
//! body is sealed under the demo's pre-shared AES-256-GCM key, so the
//! server encrypts messages back to subscribers holding the key.
//!
//! Environment:
//!   - `TBWS_SERVER_CERT`       path to the server certificate DER
//!   - `TBWS_SERVER_KEY`        path to the raw 32-byte server signing key
//!   - `TBWS_CLIENT_CERT`       required when `TBWS_PAYWALL=1`
//!   - `TBWS_PAYWALL`           enable demo session-budget paywall
//!   - `PUBSUB_PROCESSOR_PORT`  listen port (default `9111`)
//!   - `MUX_STREAMS`            client-initiated concurrency cap (default `8`)

use std::env;
use std::error::Error;
use std::fs;
use std::sync::Arc;

use serde_json::Value;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::x509::policy::{CertificateValidation, RuntimeCertificatePinning};
use tightbeam::der::{Decode, Encode};
use tightbeam::policy::TransitStatus;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::handshake::negotiation::{TransportAuthorizer, TransportOffer};
use tightbeam::transport::multiplex::MuxRole;
use tightbeam::transport::{EncryptedProtocol, ResponsePackage};
use tightbeam::x509::Certificate;
use tightbeam::Frame;
use tightbeam_pubsub::opaque_payload;
use tightbeam_pubsub::testing::{command_frame, sealed_command_frame};
use tightbeam_ws::io::WsTransport;
use tightbeam_ws::mux::assemble_mux;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{budget_ceiling, env_u32, paywall_enabled, serve_handshake, DemoPaywall, Identity};
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;

type BoxError = Box<dyn Error + Send + Sync>;

/// The transport an accepted WebSocket connection follows.
type ServerTransport = WsTransport<MaybeTlsStream<TcpStream>>;

/// The demo's pre-shared, deterministic AES-256-GCM key. Subscribers
/// declare it in their envelope (`sealed(Aes256Gcm.fromKey(...))`). A
/// production servlet would provision per-topic keys instead.
const PROCESSED_TOPIC_KEY: [u8; 32] = [0x07; 32];

/// Uppercase the `text` of the JSON note carried by the inner frame in
/// `payload`, and return the DER of a rebuilt (unsigned) inner frame
/// whose body is sealed under [`PROCESSED_TOPIC_KEY`].
fn transformed(payload: &[u8]) -> Result<Vec<u8>, BoxError> {
	let inner = Frame::from_der(payload)?;
	let body = opaque_payload(&inner)?;

	let mut note: Value = serde_json::from_slice(&body)?;
	let object = note.as_object_mut().ok_or("the note payload must be a JSON object")?;
	let text = object.get("text").and_then(Value::as_str).ok_or("the note has no text field")?;
	let uppercased = text.to_uppercase();

	object.insert("text".to_owned(), Value::String(uppercased));

	let id = String::from_utf8_lossy(&inner.metadata.id).into_owned();
	let rebuilt = sealed_command_frame(&id, inner.metadata.order, &serde_json::to_vec(&note)?, &PROCESSED_TOPIC_KEY)?;
	Ok(rebuilt.to_der()?)
}

/// Answer one relayed publish: transform the inner frame's note.
async fn process_stream(frame: Arc<Frame>) -> ResponsePackage {
	let Ok(payload) = opaque_payload(&frame) else {
		return ResponsePackage::new(TransitStatus::InvalidArgument, None);
	};

	let processed = match transformed(&payload) {
		Ok(processed) => processed,
		Err(error) => {
			eprintln!("[pubsub-processor] transform failed: {error}");
			return ResponsePackage::new(TransitStatus::InvalidArgument, None);
		}
	};

	let id = String::from_utf8_lossy(&frame.metadata.id).into_owned();
	match command_frame(&id, frame.metadata.order, &processed) {
		Ok(answer) => ResponsePackage::new(TransitStatus::Ok, Some(answer)),
		Err(error) => {
			eprintln!("[pubsub-processor] answer build failed: {error}");
			ResponsePackage::new(TransitStatus::Internal, None)
		}
	}
}

/// Serve one multiplexed encrypted connection until it ends.
async fn serve_connection(
	mut transport: ServerTransport,
	cap: u32,
	authorizer: Option<Arc<dyn TransportAuthorizer>>,
) -> Result<(), BoxError> {
	let mut offer = TransportOffer::mux(cap);
	if authorizer.is_some() {
		offer = offer.with_budgets(budget_ceiling());
	}

	transport = transport.with_mux_offer(Some(offer));
	if let Some(authorizer) = authorizer {
		transport = transport.with_transport_authorizer(authorizer);
	}

	serve_handshake(&mut transport).await?;

	let mux = assemble_mux(transport, MuxRole::Server)?;
	let (_handle, reader_driver, writer_driver, responder) = mux.into_parts();

	let reader_task = tokio::spawn(reader_driver.drive());
	let writer_task = tokio::spawn(writer_driver.drive());
	let outcome = responder.serve(process_stream).await;

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
	let port = env_u32("PUBSUB_PROCESSOR_PORT", 9111);
	let cap = env_u32("MUX_STREAMS", 8);
	let bind_addr = TightBeamSocketAddr(format!("0.0.0.0:{port}").parse()?);
	let paywall = paywall_enabled();

	let identity = Identity::from_env()?;
	let mut config = identity.server_config();
	if paywall {
		let client_cert =
			env::var("TBWS_CLIENT_CERT").map_err(|_| "TBWS_PAYWALL requires TBWS_CLIENT_CERT (mutual auth)")?;
		config = config.with_client_validators(client_validators(&client_cert)?);
	}

	let authorizer = if paywall {
		Some(DemoPaywall::shared()?)
	} else {
		None
	};

	let (listener, bound) = <WsListener as EncryptedProtocol>::bind_with(bind_addr, config).await?;
	println!(
		"[pubsub-processor] encrypted payload processor servlet listening on ws://{}",
		bound.0
	);

	loop {
		// A failed WebSocket upgrade is a per-connection fault (bad
		// handshake, probe, abrupt teardown), never server-fatal.
		let (transport, peer) = match listener.accept().await {
			Ok(accepted) => accepted,
			Err(error) => {
				eprintln!("[pubsub-processor] accept failed: {error}");
				continue;
			}
		};

		let authorizer = authorizer.clone();
		tokio::spawn(async move {
			if let Err(error) = serve_connection(transport, cap, authorizer).await {
				eprintln!("[pubsub-processor] connection from {peer} ended: {error}");
			}
		});
	}
}
