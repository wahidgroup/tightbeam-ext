//! Multiplexed cleartext echo server for the tightbeam WebSocket transport.
//!
//! Splits each connection into exclusive cleartext halves and serves concurrent
//! client streams with the shared echo handler. Cleartext multiplexing has no
//! handshake negotiation: both endpoints MUST configure the same symmetric
//! concurrency cap, or their enforcement diverges. The connection carries NO
//! confidentiality or integrity protection.
//!
//! Two-way behavior: a request whose frame id starts with `call-me` makes the
//! server initiate its own stream back to the client carrying the same frame.
//! The client's answer becomes the response on the original stream. A `sink`
//! id accepts without a response frame, a `drain-calm` id drains the session.
//! Everything else echoes.
//!
//! Environment:
//!   - `ECHO_WS_PORT`     listen port (default `9101`)
//!   - `MUX_STREAMS`      symmetric concurrency cap (default `8`)

use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::{MuxRole, MuxTransport};
use tightbeam_ws::io::WsTransport;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{echo_stream, env_u32};
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The transport an accepted WebSocket connection rides on.
type ServerTransport = WsTransport<MaybeTlsStream<TcpStream>>;

/// Serve one multiplexed cleartext connection until it ends.
async fn serve_connection(transport: ServerTransport, cap: u32) -> Result<(), BoxError> {
	let (reader, writer) = transport.into_split_cleartext()?;

	let mux = MuxTransport::new(reader, writer, MuxRole::Server, MuxSettings::symmetric(cap));
	let (handle, reader_driver, writer_driver, responder) = mux.into_parts();

	let reader_task = tokio::spawn(reader_driver.drive());
	let writer_task = tokio::spawn(writer_driver.drive());

	let outcome = responder.serve(move |frame| echo_stream(handle.clone(), frame)).await;

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

	let listener = WsListener::bind(&addr).await?;
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
