//! Encrypted round-trip driven by DER identity fixtures.
//!
//! Proves the fixtures are loadable and drive a real ECIES handshake: mint a
//! server identity, serialize it to a DER certificate + raw key, reload it the
//! way the echo server and browser client do, then complete an encrypted frame
//! round-trip over the WebSocket transport using only the public surface.

#![cfg(feature = "fixtures")]

use std::time::Duration;

use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::create_v0_tightbeam;
use tightbeam::transport::EncryptedProtocol;
use tightbeam_ws::fixtures::Identity;
use tightbeam_ws::protocol::WsListener;

mod common;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_round_trip_over_der_fixtures() -> Result<(), BoxError> {
	// 1. Mint a server identity, then round-trip it through the DER certificate
	//    and raw key bytes exactly as the generator writes and peers reload.
	let minted = Identity::mint_root("CN=fixture echo,O=tightbeam-ws,C=US", 1, Duration::from_secs(3600))?;
	let cert_der = minted.certificate_der()?;
	let key_bytes = minted.signing_key_bytes();
	let identity = Identity::from_der(&cert_der, &key_bytes)?;

	// 2. Bind an encrypted server presenting the reloaded identity.
	let bind_addr = TightBeamSocketAddr("127.0.0.1:0".parse()?);
	let (server, addr) = <WsListener as EncryptedProtocol>::bind_with(bind_addr, identity.server_config()).await?;

	// 3. Client pins the reloaded server certificate and round-trips a frame.
	let trust_store = identity.trust_anchor()?;
	let expected = create_v0_tightbeam(None, None);
	common::echo_round_trip(server, addr, trust_store, expected).await
}
