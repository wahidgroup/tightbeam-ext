//! Pooled multiplexing over the tunnel, as a tightbeam scenario.
//!
//! Proves [`PersistentConnection`] wires tunnel endpoints into tightbeam's
//! `ConnectionPool`: one encrypted, mux-negotiated tunnel serves unary,
//! streaming, and duplex interactions through a pooled lease against a
//! `server!` service. The shared spec grades the one dial of the pool, the
//! one connection the server accepts, and the gate verdict of each stream.
//!
//! [`PersistentConnection`]: tightbeam::transport::PersistentConnection

use std::time::Duration;

use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::tb_scenario;
use tightbeam::testing::{ClientEnv, SetupEnv, TestFrame};
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::EncryptedProtocol;
use tightbeam_grpc::protocol::{GrpcAddr, GrpcListener};
use tightbeam_ws::testing::specs::PooledMuxSpec;
use tightbeam_ws::testing::{EchoService, Identity, PoolEchoes};

/// The identity of the pooled server, which its pool pins.
fn server_identity() -> Identity {
	let minted = Identity::mint("CN=pooled echo,O=tightbeam-grpc,C=US", 1, Duration::from_secs(3600));
	minted.expect("a test identity mints")
}

// One pooled tunnel carries every stream kind: the pool dials once, each end
// completes one handshake, and the server accepts the one connection and
// admits each stream.
tb_scenario! {
	name: one_pooled_grpc_connection_serves_multiple_stream_kinds,
	spec: PooledMuxSpec,
	environment ServiceClient {
		worker_threads: 2,
		context: server_identity(),
		server: |SetupEnv { trace, context }| async move {
			let bind: GrpcAddr = "127.0.0.1:0".parse()?;
			let (listener, _bound) = <GrpcListener as EncryptedProtocol>::bind_with(bind, context.server_config()?).await?;
			let addr = TightBeamSocketAddr(listener.local_addr());
			Ok((EchoService::serve(listener, Some(TransportOffer::mux(8)), &trace), addr))
		},
		client: |ClientEnv { trace, context, addr }| async move {
			let expected = TestFrame::v0(None, None);
			let through = EchoService::through_pool::<GrpcListener>(GrpcAddr::from(addr.0), context.trust_anchor()?, &expected, &trace);
			let echoes = through.await?;
			assert_eq!(echoes, PoolEchoes::of(&expected), "one pooled tunnel MUST carry every stream kind unchanged");
			Ok(())
		}
	}
}
