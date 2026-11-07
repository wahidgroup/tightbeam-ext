//! Multiplexed encrypted echo server for the tightbeam WebSocket transport.
//!
//! The server offers multiplexing in the HPKE handshake and serves each client
//! stream with the [`EchoBody`] that `TBWS_ECHO_BODY` names. In the `streaming`
//! and `unary` bodies, a frame id can select an [`EchoCommand`] in place of the
//! echo.
//!
//! The [`DemoConfig`] of the environment decides the [`Security`] of every
//! connection: server-auth, mutual-auth when `TBWS_CLIENT_CERT` names a client
//! certificate to pin, and the demo session-budget paywall on top of mutual
//! auth when `TBWS_PAYWALL` is on.
//!
//! Environment:
//!   - `TBWS_SERVER_CERT`  path to the server certificate DER, beside its key
//!   - `TBWS_ECHO_BODY`    the [`EchoBody`] to serve (default `streaming`)
//!   - `ECHO_WS_PORT`      listen port (default `9100`)
//!   - the variables of [`DemoConfig`]
//!
//! [`EchoCommand`]: tightbeam_ws::testing::EchoCommand
//! [`Security`]: tightbeam_ws::testing::Security

use std::sync::Arc;

use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::multiplex::MuxAcceptor;
use tightbeam::transport::EncryptedProtocol;
use tightbeam_ws::io::WsTransport;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::serve::AcceptedLink;
use tightbeam_ws::testing::{DemoConfig, EchoBody, EnvVar, Identity};
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The transport an accepted WebSocket connection follows.
type ServerTransport = WsTransport<MaybeTlsStream<TcpStream>>;

/// The variable that sets the listen port.
const PORT: EnvVar = EnvVar::new("ECHO_WS_PORT");

/// One accepted encrypted connection of the echo server, and the demo
/// configuration that meters it.
struct EchoConnection {
	transport: ServerTransport,
	demo: Arc<DemoConfig>,
}

impl EchoConnection {
	/// Serve the connection with `body` until it ends.
	async fn serve(self, body: EchoBody) -> Result<(), BoxError> {
		let Self { transport, demo } = self;

		let mut transport = demo.meter(transport);
		transport.negotiate_mux().await?;

		let link = AcceptedLink::accepted(transport)?;
		body.serve(link.spawn()).await?;
		Ok(())
	}
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port = PORT.parsed_or(9100u32)?;
	let body = EchoBody::from_env()?;
	let bind_addr = TightBeamSocketAddr(format!("0.0.0.0:{port}").parse()?);
	let demo = Arc::new(DemoConfig::from_env()?);

	let identity = Identity::from_env()?;
	let config = demo.security().server_config(&identity)?;
	let (listener, bound) = <WsListener as EncryptedProtocol>::bind_with(bind_addr, config).await?;

	println!(
		"[echo-mux] multiplexed encrypted ({}) tightbeam-ws echo server listening on ws://{}",
		demo.security(),
		bound.0
	);

	loop {
		// A failed accept is the listener's own fault, such as a descriptor
		// shortage, and it clears on retry.
		let (transport, peer) = match listener.accept().await {
			Ok(accepted) => accepted,
			Err(error) => {
				eprintln!("[echo-mux] accept failed: {error}");
				continue;
			}
		};

		let connection = EchoConnection { transport, demo: Arc::clone(&demo) };
		tokio::spawn(async move {
			if let Err(error) = connection.serve(body).await {
				eprintln!("[echo-mux] connection from {peer} ended: {error}");
			}
		});
	}
}
