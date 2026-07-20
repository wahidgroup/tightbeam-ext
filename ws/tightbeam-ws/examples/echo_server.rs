//! Echo server for the tightbeam WebSocket transport.
//!
//! Serves [`WsListener`] and echoes each received frame back as the response,
//! so a client observes a full request/response round-trip. The companion e2e
//! example app builds a frame in TypeScript and sends it here.
//!
//! The listen port is read from `ECHO_WS_PORT` (default `9100`). Setting
//! `ECHO_WS_MODE=sink` accepts each frame without returning a response
//! message, so a client observes the empty-response path.

use std::env;

use tightbeam::Frame;
use tightbeam_ws::protocol::WsListener;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port = env::var("ECHO_WS_PORT")
		.ok()
		.and_then(|value| value.parse::<u16>().ok())
		.unwrap_or(9100);
	let sink = env::var("ECHO_WS_MODE").is_ok_and(|mode| mode == "sink");
	let addr = format!("0.0.0.0:{port}");

	let listener = WsListener::bind(&addr).await?;
	println!("[echo] tightbeam-ws echo server listening on ws://{addr} (sink: {sink})");

	let server = tightbeam::server! {
		protocol WsListener: listener,
		handle: move |message: Frame| async move {
			if sink {
				return Ok(None);
			}

			Ok(Some(message))
		}
	};

	server.await?;
	Ok(())
}
