//! End-to-end round trips over the WebSocket transport, as a tightbeam
//! scenario.
//!
//! This exercises the public surface only: the cleartext case proves
//! tightbeam's `server!` / `client!` macros drive a WebSocket transport.
//! `client!` takes no trace, so the shared spec grades the server side: the
//! one connection the shared echo accepts, and the one request its gate
//! admits. The encrypted cases live in `encrypted_fixtures.rs`.

#![cfg(feature = "testing")]

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::{ClientEnv, SetupEnv, TestFrame};
use tightbeam::transport::policy::RestartLinearBackoff;
use tightbeam::{client, tb_scenario};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::specs::CleartextRoundTripSpec;
use tightbeam_ws::testing::EchoService;

// tightbeam's `server!` and `client!` macros drive a cleartext WebSocket: the
// server accepts the one connection, and its gate admits the one request.
tb_scenario! {
	name: cleartext_round_trip_drives_ws_macros,
	spec: CleartextRoundTripSpec,
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move {
			let listener = WsListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await?;
			let addr = TightBeamSocketAddr(listener.local_addr()?);
			Ok((EchoService::serve(listener, None, &trace), addr))
		},
		client: |ClientEnv { addr, .. }| async move {
			let mut client = client! {
				connect WsListener: addr,
				cleartext,
				policies: {
					restart_policy: RestartLinearBackoff::default(),
				}
			};

			let message = TestFrame::v0(None, None);
			let reply = client.emit(message.clone(), None).await?;
			assert_eq!(reply, Some(message), "the server MUST echo the frame sent over the WebSocket");
			Ok(())
		}
	}
}
