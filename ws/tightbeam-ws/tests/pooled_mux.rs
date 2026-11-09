//! Pooled multiplexing over the WebSocket transport, as a tightbeam scenario.
//!
//! Proves [`PersistentConnection`] wires WebSocket endpoints into tightbeam's
//! `ConnectionPool`: one encrypted, mux-negotiated WebSocket connection serves
//! unary, streaming, and duplex interactions through a pooled lease against a
//! `server!` service. The shared spec grades the one dial of the pool, the
//! one connection the server accepts, and the gate verdict of each stream.
//!
//! [`PersistentConnection`]: tightbeam::transport::PersistentConnection

#![cfg(feature = "testing")]

use std::time::Duration;

use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::tb_scenario;
use tightbeam::testing::{ClientEnv, SetupEnv, TestFrame};
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::EncryptedProtocol;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::specs::PooledMuxSpec;
use tightbeam_ws::testing::{EchoService, Identity, PoolEchoes};

/// The identity of the pooled server, which its pool pins.
fn server_identity() -> Identity {
	let minted = Identity::mint("CN=pooled echo,O=tightbeam-ws,C=US", 1, Duration::from_secs(3600));
	minted.expect("a test identity mints")
}

// One pooled WebSocket carries every stream kind: the pool dials once, each
// end completes one handshake, and the server accepts the one connection and
// admits each stream.
tb_scenario! {
	name: one_pooled_ws_connection_serves_multiple_stream_kinds,
	spec: PooledMuxSpec,
	environment ServiceClient {
		worker_threads: 2,
		context: server_identity(),
		server: |SetupEnv { trace, context }| async move {
			let loopback = TightBeamSocketAddr("127.0.0.1:0".parse()?);
			let (listener, addr) = <WsListener as EncryptedProtocol>::bind_with(loopback, context.server_config()?).await?;
			Ok((EchoService::serve(listener, Some(TransportOffer::mux(8)), &trace), addr))
		},
		client: |ClientEnv { trace, context, addr }| async move {
			let expected = TestFrame::v0(None, None);
			let echoes = EchoService::through_pool::<WsListener>(addr, context.trust_anchor()?, &expected, &trace).await?;
			assert_eq!(echoes, PoolEchoes::of(&expected), "one pooled WebSocket MUST carry every stream kind unchanged");
			Ok(())
		}
	}
}
