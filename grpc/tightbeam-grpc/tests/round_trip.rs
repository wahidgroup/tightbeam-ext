//! End-to-end round trips over the tunnel, as tightbeam scenarios.
//!
//! Each scenario serves the shared echo through `server!`, which records the
//! session of every accepted tunnel on the trace of the scenario, and the
//! shared spec of its suite grades that trace:
//!
//! - The cleartext case drives the `client!` macro, which takes no trace, so
//!   its spec grades the one connection the server accepts and the one
//!   request its gate admits.
//! - The encrypted case sends its frame on a dialed transport that records on
//!   the trace, so its spec grades one HPKE handshake at each end through the
//!   `Protocol` / `EncryptedProtocol` / `AsyncListenerTrait` implementations.

use std::time::Duration;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::{ClientEnv, SetupEnv, TestFrame};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::policy::RestartLinearBackoff;
use tightbeam::transport::EncryptedProtocol;
use tightbeam::{client, tb_scenario, TightBeamError};
use tightbeam_grpc::protocol::{GrpcAddr, GrpcListener};
use tightbeam_ws::testing::specs::{CleartextRoundTripSpec, EncryptedRoundTripSpec};
use tightbeam_ws::testing::{EchoService, Identity};
use tokio::task::JoinHandle;

/// The server of a scenario, and the socket address it bound.
type Served = Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError>;

/// The shared echo on `listener`, which offers no multiplexing and records
/// each session on `trace`.
fn echo(listener: GrpcListener, trace: &TraceCollector) -> Served {
	let addr = TightBeamSocketAddr(listener.local_addr());
	Ok((EchoService::serve(listener, None, trace), addr))
}

/// The identity of the encrypted server, which its client pins.
fn server_identity() -> Identity {
	let minted = Identity::mint("CN=tunnel echo,O=tightbeam-grpc,C=US", 1, Duration::from_secs(3600));
	minted.expect("a test identity mints")
}

// tightbeam's `server!` and `client!` macros drive a cleartext tunnel: the
// server accepts the one connection, and its gate admits the one request.
tb_scenario! {
	name: cleartext_round_trip_drives_grpc_macros,
	spec: CleartextRoundTripSpec,
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move {
			let listener = GrpcListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await?;
			echo(listener, &trace)
		},
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
		context: server_identity(),
		server: |SetupEnv { trace, context }| async move {
			let bind: GrpcAddr = "127.0.0.1:0".parse()?;
			let (listener, _bound) = <GrpcListener as EncryptedProtocol>::bind_with(bind, context.server_config()?).await?;
			echo(listener, &trace)
		},
		client: |ClientEnv { trace, addr, context }| async move {
			let expected = TestFrame::v0(None, None);
			let exchanged = EchoService::exchange::<GrpcListener, _, _>(GrpcAddr::from(addr.0), context.trust_anchor()?, expected.clone(), &trace);
			let reply = exchanged.await?;
			assert_eq!(reply, Some(expected), "the encrypted server MUST echo the frame back over the tunnel");
			Ok(())
		}
	}
}
