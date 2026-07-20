//! Encrypted echo server for the tightbeam WebSocket transport.
//!
//! Loads a server identity from DER fixtures (see the `gen_certs` example),
//! binds an ECIES-encrypted [`WsListener`] via [`EncryptedProtocol::bind_with`],
//! and echoes each received frame back over the encrypted channel. The browser
//! `SecureWsClient` pins the same server certificate to authenticate the peer.
//!
//! When `TBWS_CLIENT_CERT` is set, the server additionally requires mutual
//! authentication, pinning that certificate as the only accepted client.
//!
//! Environment:
//!   - `TBWS_SERVER_CERT`  path to the server certificate DER
//!   - `TBWS_SERVER_KEY`   path to the raw 32-byte server signing key
//!   - `TBWS_CLIENT_CERT`  optional path to a pinned client certificate DER
//!   - `ECHO_WS_PORT`      listen port (default `9100`)

use std::env;
use std::fs;
use std::sync::Arc;

use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::x509::policy::{CertificateValidation, RuntimeCertificatePinning};
use tightbeam::der::Decode;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::EncryptedProtocol;
use tightbeam::x509::Certificate;
use tightbeam::Frame;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{Identity, SIGNING_KEY_LEN};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn load_server_identity() -> Result<Identity, BoxError> {
	let cert_der = fs::read(env::var("TBWS_SERVER_CERT")?)?;
	let key_bytes = fs::read(env::var("TBWS_SERVER_KEY")?)?;
	let key: [u8; SIGNING_KEY_LEN] = key_bytes.as_slice().try_into()?;

	Ok(Identity::from_der(&cert_der, &key)?)
}

/// Pin the client certificate at `path` as the only accepted client identity.
fn client_validators(path: &str) -> Result<Vec<Arc<dyn CertificateValidation>>, BoxError> {
	let cert = Certificate::from_der(&fs::read(path)?)?;
	let pinning = RuntimeCertificatePinning::<Sha3_256>::from_certificates([cert])?;

	Ok(vec![Arc::new(pinning)])
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port = env::var("ECHO_WS_PORT")
		.ok()
		.and_then(|value| value.parse::<u16>().ok())
		.unwrap_or(9100);
	let bind_addr = TightBeamSocketAddr(format!("0.0.0.0:{port}").parse()?);

	let identity = load_server_identity()?;
	let mut config = identity.server_config();

	let mut mode = "server-auth";
	if let Ok(client_cert) = env::var("TBWS_CLIENT_CERT") {
		config = config.with_client_validators(client_validators(&client_cert)?);
		mode = "mutual-auth";
	}

	let (listener, bound) = <WsListener as EncryptedProtocol>::bind_with(bind_addr, config).await?;
	println!(
		"[echo-secure] encrypted ({mode}) tightbeam-ws echo server listening on ws://{}",
		bound.0
	);

	let server = tightbeam::server! {
		protocol WsListener: listener,
		handle: move |message: Frame| async move { Ok(Some(message)) }
	};

	server.await?;
	Ok(())
}
