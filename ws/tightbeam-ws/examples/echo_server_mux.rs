//! The multiplexed encrypted echo server of the e2e stack, as `docs/ws.md`
//! (Demo servers) states it.

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

/// The transport of an accepted WebSocket connection.
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
	let port: u16 = PORT.parsed()?;
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
		let (transport, peer) = listener.accept().await?;
		let connection = EchoConnection { transport, demo: Arc::clone(&demo) };
		tokio::spawn(async move {
			if let Err(error) = connection.serve(body).await {
				eprintln!("[echo-mux] connection from {peer} ended: {error}");
			}
		});
	}
}
