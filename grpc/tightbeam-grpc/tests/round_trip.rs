//! Round trips over the tunnel, through the shared echo of `server!`, graded
//! by the shared specs of `tightbeam-ws`.

mod support;

use tightbeam::testing::{ClientEnv, SetupEnv, TestFrame};
use tightbeam::transport::policy::RestartLinearBackoff;
use tightbeam::{client, tb_scenario};
use tightbeam_grpc::edge::H2c;
use tightbeam_grpc::protocol::{GrpcAddr, GrpcListener};
use tightbeam_ws::testing::specs::{CleartextRoundTripSpec, EncryptedRoundTripSpec};
use tightbeam_ws::testing::EchoService;

use support::{server_identity, EchoServer};

// tightbeam's `server!` and `client!` macros drive a cleartext tunnel: the
// server accepts the one connection, and its gate admits the one request.
tb_scenario! {
	name: cleartext_round_trip_drives_grpc_macros,
	spec: CleartextRoundTripSpec,
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move { EchoServer::cleartext::<H2c>(&trace).await },
		client: |ClientEnv { addr, .. }| async move {
			let mut client = client! {
				connect GrpcListener: GrpcAddr::from(addr.0),
				cleartext,
				policies: {
					restart_policy: RestartLinearBackoff::default(),
				}
			};

			let message = TestFrame::v0(None, None);
			let reply = client.emit(message.clone(), None).await?;
			assert_eq!(reply, Some(message), "the server MUST echo the frame sent over the tunnel");
			Ok(())
		}
	}
}

// One HPKE handshake completes at each end over the tunnel, and the gate
// admits the one encrypted request.
tb_scenario! {
	name: encrypted_round_trip_over_grpc,
	spec: EncryptedRoundTripSpec,
	environment ServiceClient {
		context: server_identity("CN=tunnel echo,O=tightbeam-grpc,C=US"),
		server: |SetupEnv { trace, context }| async move { EchoServer::encrypted::<H2c>(context.server_config(), None, &trace).await },
		client: |ClientEnv { trace, addr, context }| async move {
			let expected = TestFrame::v0(None, None);
			let exchanged = EchoService::exchange::<GrpcListener, _, _>(GrpcAddr::from(addr.0), context.trust_anchor()?, expected.clone(), &trace);
			let reply = exchanged.await?;
			assert_eq!(reply, Some(expected), "the encrypted server MUST echo the frame back over the tunnel");
			Ok(())
		}
	}
}
