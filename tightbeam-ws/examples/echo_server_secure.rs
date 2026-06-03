//! Encrypted echo server for the tightbeam WebSocket transport.
//!
//! Loads a server identity from DER fixtures (see the `gen_certs` example),
//! binds an ECIES-encrypted [`WsListener`] via [`EncryptedProtocol::bind_with`],
//! and echoes each received frame back over the encrypted channel. The browser
//! `SecureWsClient` pins the same server certificate to authenticate the peer.
//!
//! Environment:
//!   - `TBWS_SERVER_CERT`  path to the server certificate DER
//!   - `TBWS_SERVER_KEY`   path to the raw 32-byte server signing key
//!   - `ECHO_WS_PORT`      listen port (default `9100`)

use std::env;
use std::fs;

use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::EncryptedProtocol;
use tightbeam::Frame;
use tightbeam_ws::fixtures::{Identity, SIGNING_KEY_LEN};
use tightbeam_ws::protocol::WsListener;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn load_server_identity() -> Result<Identity, BoxError> {
	let cert_der = fs::read(env::var("TBWS_SERVER_CERT")?)?;
	let key_bytes = fs::read(env::var("TBWS_SERVER_KEY")?)?;
	let key: [u8; SIGNING_KEY_LEN] = key_bytes.as_slice().try_into()?;
	Ok(Identity::from_der(&cert_der, &key)?)
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port = env::var("ECHO_WS_PORT")
		.ok()
		.and_then(|value| value.parse::<u16>().ok())
		.unwrap_or(9100);
	let bind_addr = TightBeamSocketAddr(format!("0.0.0.0:{port}").parse()?);

	let identity = load_server_identity()?;
	let (listener, bound) = <WsListener as EncryptedProtocol>::bind_with(bind_addr, identity.server_config()).await?;
	println!("[echo-secure] encrypted tightbeam-ws echo server listening on ws://{}", bound.0);

	let server = tightbeam::server! {
		protocol WsListener: listener,
		handle: move |message: Frame| async move { Ok(Some(message)) }
	};

	server.await?;
	Ok(())
}
