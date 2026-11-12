//! The multiplexed cleartext echo server of the e2e stack, as `docs/ws.md`
//! (Demo servers) states it.

use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam_ws::io::WsTransport;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::serve::AcceptedLink;
use tightbeam_ws::testing::{DemoConfig, EchoBody, EnvVar};
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The transport of an accepted WebSocket connection.
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
	let port: u16 = PORT.parsed()?;
	let demo = DemoConfig::from_env()?;
	let cap = demo.streams();
	let body = EchoBody::from_env()?;
	let addr = format!("0.0.0.0:{port}");

	let listener = WsListener::bind_cleartext(&addr).await?;
	println!("[echo-mux-clear] multiplexed cleartext tightbeam-ws echo server listening on ws://{addr}");

	loop {
		let (transport, peer) = listener.accept().await?;
		tokio::spawn(async move {
			let connection = EchoConnection(transport);
			if let Err(error) = connection.serve(cap, body).await {
				eprintln!("[echo-mux-clear] connection from {peer} ended: {error}");
			}
		});
	}
}
