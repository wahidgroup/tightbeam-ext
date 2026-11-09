//! The accept path of [`WsListener`] under stalled and failed upgrades, as
//! tightbeam scenarios.
//!
//! Each case serves the shared echo on a cleartext listener, which records
//! each session on the trace, and ends with one exchange of a tightbeam client
//! within [`PROMPT`]. The spec grades the sessions the listener accepted and
//! the one request its gate admitted, so a hostile peer that never upgrades
//! shows as a connection that never reached the caller.

#![cfg(feature = "testing")]

use core::time::Duration;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::instrumentation::events;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::{ClientEnv, SetupEnv, TestFrame};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::policy::RestartLinearBackoff;
use tightbeam::{client, exactly, tb_assert_spec, tb_scenario, TightBeamError};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::EchoService;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::{yield_now, JoinHandle};
use tokio::time::timeout;

/// How long a healthy exchange may take on loopback.
const PROMPT: Duration = Duration::from_secs(2);

/// The server of a scenario, and the socket address it bound.
type Served = Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError>;

/// The shared echo on `listener`, which records each session on `trace`.
fn echo(listener: WsListener, trace: &TraceCollector) -> Served {
	let addr = TightBeamSocketAddr(listener.local_addr()?);
	Ok((EchoService::serve(listener, None, trace), addr))
}

/// The shared echo on a cleartext listener on an ephemeral loopback port.
async fn bound_echo(trace: &TraceCollector) -> Served {
	let listener = WsListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await?;
	echo(listener, trace)
}

/// One exchange of a tightbeam client with the echo at `addr` within
/// [`PROMPT`].
async fn still_serves(addr: TightBeamSocketAddr) -> Result<(), TightBeamError> {
	let exchange = async {
		let mut client = client! {
			connect WsListener: addr,
			cleartext,
			policies: {
				restart_policy: RestartLinearBackoff::default(),
			}
		};

		let message = TestFrame::v0(None, None);
		let reply = client.emit(message.clone(), None).await?;
		assert_eq!(
			reply,
			Some(message),
			"the listener MUST serve the client beside the hostile peer"
		);
		Ok(())
	};

	timeout(PROMPT, exchange)
		.await
		.map_err(|elapsed| TightBeamError::IoError(elapsed.into()))?
}

tb_assert_spec! {
	pub OneSessionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CONNECTION_ACCEPTED, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(1))
		]
	}
}

// A peer that connects and never sends its upgrade delays no other
// connection, and never becomes a session. The deadline of the exchange
// grades the delay: an exchange that the stall holds past `PROMPT` fails the
// scenario.
tb_scenario! {
	name: a_stalled_upgrade_delays_no_other_connection,
	spec: OneSessionSpec,
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move { bound_echo(&trace).await },
		client: |ClientEnv { addr, .. }| async move {
			// A hostile peer: a real client never stalls before its upgrade,
			// and the server under test is real.
			let _stalled = TcpStream::connect(addr.0).await?;
			still_serves(addr).await
		}
	}
}

// A request with no upgrade ends at the listener, never reaches the accept
// loop as a session, and leaves the listener serving.
tb_scenario! {
	name: a_failed_upgrade_never_reaches_the_caller,
	spec: OneSessionSpec,
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move { bound_echo(&trace).await },
		client: |ClientEnv { addr, .. }| async move {
			// A hostile peer: a real client never sends a request with no
			// upgrade, and the server under test is real.
			let mut refused = TcpStream::connect(addr.0).await?;
			refused.write_all(b"GET / HTTP/1.1\r\n\r\n").await?;

			// The listener ends the refused connection, so its read reaches
			// the end of the stream before the client dials.
			let mut answer = Vec::new();
			let ended = timeout(PROMPT, refused.read_to_end(&mut answer)).await;
			ended.map_err(|elapsed| TightBeamError::IoError(elapsed.into()))??;
			still_serves(addr).await
		}
	}
}

// A dropped listener releases its port: a listener that binds the same
// address afterwards serves on it.
tb_scenario! {
	name: a_dropped_listener_releases_its_port,
	spec: OneSessionSpec,
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move {
			let first = WsListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await?;
			let addr = first.local_addr()?;
			drop(first);

			let rebound = timeout(PROMPT, async {
				loop {
					let rebinding = WsListener::<DefaultCryptoProvider>::bind_cleartext(addr.to_string());
					if let Ok(listener) = rebinding.await {
						return listener;
					}

					yield_now().await;
				}
			});

			let rebound = rebound.await.map_err(|elapsed| TightBeamError::IoError(elapsed.into()))?;
			assert_eq!(rebound.local_addr()?, addr, "the rebound listener MUST hold the released address");
			echo(rebound, &trace)
		},
		client: |ClientEnv { addr, .. }| async move { still_serves(addr).await }
	}
}
