//! One pooled, multiplexed tunnel through tightbeam's `ConnectionPool`.

mod support;

use tightbeam::tb_scenario;
use tightbeam::testing::{ClientEnv, SetupEnv, TestFrame};
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam_grpc::edge::H2c;
use tightbeam_grpc::protocol::{GrpcAddr, GrpcListener};
use tightbeam_ws::testing::specs::PooledMuxSpec;
use tightbeam_ws::testing::{EchoService, PoolEchoes};

use support::{server_identity, EchoServer};

// One pooled tunnel carries every stream kind: the pool dials once, each end
// completes one handshake, and the server accepts the one connection and
// admits each stream.
tb_scenario! {
	name: one_pooled_grpc_connection_serves_multiple_stream_kinds,
	spec: PooledMuxSpec,
	environment ServiceClient {
		worker_threads: 2,
		context: server_identity("CN=pooled echo,O=tightbeam-grpc,C=US"),
		server: |SetupEnv { trace, context }| async move {
			EchoServer::encrypted::<H2c>(context.server_config(), Some(TransportOffer::mux(8)), &trace).await
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
