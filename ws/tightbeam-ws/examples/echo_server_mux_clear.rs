//! Multiplexed cleartext echo server for the tightbeam WebSocket transport.
//!
//! The server serves each client stream with the [`EchoBody`] that
//! `TBWS_ECHO_BODY` names. In the `streaming` and `unary` bodies, a frame id
//! can select an [`EchoCommand`] in place of the echo.
//!
//! Both endpoints MUST configure the same concurrency cap, because no handshake
//! negotiates it. The connection carries NO confidentiality or integrity
//! protection.
//!
//! Environment:
//!   - `ECHO_WS_PORT`     listen port (default `9101`)
//!   - `TBWS_ECHO_BODY`   the [`EchoBody`] to serve (default `streaming`)
//!   - `MUX_STREAMS`      the symmetric concurrency cap, which [`DemoConfig`] reads
//!
//! [`EchoCommand`]: tightbeam_ws::testing::EchoCommand

use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam_ws::io::WsTransport;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::serve::AcceptedLink;
use tightbeam_ws::testing::{DemoConfig, EchoBody, EnvVar};
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The transport an accepted WebSocket connection follows.
type ServerTransport = WsTransport<MaybeTlsStream<TcpStream>>;

/// The variable that sets the listen port.
const PORT: EnvVar = EnvVar::new("ECHO_WS_PORT");

/// One accepted cleartext connection of the echo server.
struct EchoConnection(ServerTransport);

impl EchoConnection {
	/// Serve the connection with `body` until it ends, under `cap` streams
	/// each way.
	async fn serve(self, cap: u32, body: EchoBody) -> Result<(), BoxError> {
		let settings = MuxSettings::symmetric(cap);
		let link = AcceptedLink::cleartext(self.0, settings)?;
		body.serve(link.spawn()).await?;
		Ok(())
	}
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port = PORT.parsed_or(9101u32)?;
	let demo = DemoConfig::from_env()?;
	let cap = demo.streams();
	let body = EchoBody::from_env()?;
	let addr = format!("0.0.0.0:{port}");

	let listener = WsListener::bind_cleartext(&addr).await?;
	println!("[echo-mux-clear] multiplexed cleartext tightbeam-ws echo server listening on ws://{addr}");

	loop {
		// A failed accept is the listener's own fault, such as a descriptor
		// shortage, and it clears on retry.
		let (transport, peer) = match listener.accept().await {
			Ok(accepted) => accepted,
			Err(error) => {
				eprintln!("[echo-mux-clear] accept failed: {error}");
				continue;
			}
		};

		tokio::spawn(async move {
			let connection = EchoConnection(transport);
			if let Err(error) = connection.serve(cap, body).await {
				eprintln!("[echo-mux-clear] connection from {peer} ended: {error}");
			}
		});
	}
}
