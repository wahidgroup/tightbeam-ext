//! Multiplexed cleartext echo server for the tightbeam WebSocket transport.
//!
//! The server serves each client stream with the handler that `TBWS_ECHO_BODY`
//! selects. In the `streaming` and `unary` modes, a frame id can select a
//! command in place of the echo, as [`echo_stream`] lists.
//!
//! Both endpoints MUST configure the same concurrency cap, because no handshake
//! negotiates it. The connection carries NO confidentiality or integrity
//! protection.
//!
//! Environment:
//!   - `ECHO_WS_PORT`     listen port (default `9101`)
//!   - `MUX_STREAMS`      symmetric concurrency cap (default `8`)
//!   - `TBWS_ECHO_BODY`   `streaming` (default) | `duplex` | `unary`

use std::env;

use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::{MuxRole, MuxTransport};
use tightbeam_ws::io::WsTransport;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{echo_duplex, echo_stream, env_u32, EchoFrames};
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The transport an accepted WebSocket connection follows.
type ServerTransport = WsTransport<MaybeTlsStream<TcpStream>>;

/// Serve one multiplexed cleartext connection until it ends.
async fn serve_connection(transport: ServerTransport, cap: u32) -> Result<(), BoxError> {
	let (reader, writer) = transport.into_split()?;

	let mux = MuxTransport::new(reader, writer, MuxRole::Server, MuxSettings::symmetric(cap));
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

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port = env_u32("ECHO_WS_PORT", 9101);
	let cap = env_u32("MUX_STREAMS", 8);
	let addr = format!("0.0.0.0:{port}");

	let listener = WsListener::bind_cleartext(&addr).await?;
	println!("[echo-mux-clear] multiplexed cleartext tightbeam-ws echo server listening on ws://{addr}");

	loop {
		// A failed WebSocket upgrade is a per-connection fault (bad
		// handshake, probe, abrupt teardown), never server-fatal.
		let (transport, peer) = match listener.accept().await {
			Ok(accepted) => accepted,
			Err(error) => {
				eprintln!("[echo-mux-clear] accept failed: {error}");
				continue;
			}
		};

		tokio::spawn(async move {
			if let Err(error) = serve_connection(transport, cap).await {
				eprintln!("[echo-mux-clear] connection from {peer} ended: {error}");
			}
		});
	}
}
