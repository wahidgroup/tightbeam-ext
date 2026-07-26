//! Backend payload processor servlet for the processed-board demo.
//!
//! Runs only as a backend process: browsers never reach it. The demo
//! server's `RelayBackplane` dials it over a multiplexed encrypted
//! tightbeam-ws connection and relays every publish through it; the
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
//!   - `PUBSUB_PROCESSOR_PORT`  listen port (default `9111`)
//!   - `MUX_STREAMS`            client-initiated concurrency cap (default `8`)

use std::sync::Arc;

use serde_json::Value;
use tightbeam::der::{Decode, Encode};
use tightbeam::policy::TransitStatus;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::multiplex::{MuxRole, MuxTransport};
use tightbeam::transport::{EncryptedProtocol, ResponsePackage};
use tightbeam::Frame;
use tightbeam_pubsub::opaque_payload;
use tightbeam_pubsub::testing::{command_frame, sealed_command_frame};
use tightbeam_ws::io::WsTransport;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{env_u32, serve_handshake, Identity};
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The transport an accepted WebSocket connection follows.
type ServerTransport = WsTransport<MaybeTlsStream<TcpStream>>;

/// The demo's pre-shared, deterministic AES-256-GCM key. Subscribers
/// declare it in their envelope (`sealed(Aes256Gcm.fromKey(...))`); a
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
async fn serve_connection(transport: ServerTransport, cap: u32) -> Result<(), BoxError> {
	let offer = TransportOffer::mux(cap);
	let mut transport = transport.with_mux_offer(Some(offer));

	serve_handshake(&mut transport).await?;

	let settings = transport.negotiated_mux().ok_or("the client did not negotiate multiplexing")?;
	let (reader, writer) = transport.into_split()?;

	let mux = MuxTransport::new(reader, writer, MuxRole::Server, settings);
	let (_handle, reader_driver, writer_driver, responder) = mux.into_parts();

	let reader_task = tokio::spawn(reader_driver.drive());
	let writer_task = tokio::spawn(writer_driver.drive());
	let outcome = responder.serve(process_stream).await;

	reader_task.abort();
	writer_task.abort();
	outcome?;

	Ok(())
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port = env_u32("PUBSUB_PROCESSOR_PORT", 9111);
	let cap = env_u32("MUX_STREAMS", 8);
	let bind_addr = TightBeamSocketAddr(format!("0.0.0.0:{port}").parse()?);

	let identity = Identity::from_env()?;
	let (listener, bound) = <WsListener as EncryptedProtocol>::bind_with(bind_addr, identity.server_config()).await?;
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

		tokio::spawn(async move {
			if let Err(error) = serve_connection(transport, cap).await {
				eprintln!("[pubsub-processor] connection from {peer} ended: {error}");
			}
		});
	}
}
