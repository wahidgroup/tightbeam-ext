//! Tightbeam scenarios of the accept path of [`WsListener`], as `docs/ws.md`
//! (Test support) states.

#![cfg(feature = "testing")]

pub mod support;

use std::sync::Arc;

use tightbeam::clock::ManualClock;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::instrumentation::events;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::{ClientEnv, SetupEnv, TestFrame};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::policy::RestartLinearBackoff;
use tightbeam::transport::{EndpointConfig, TransportLimits};
use tightbeam::urn::Urn;
use tightbeam::{client, exactly, tb_assert_spec, tb_scenario, urn, TightBeamError};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::EchoService;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::{yield_now, JoinHandle};

use support::bounded;

/// Whether a stalled socket read the end of its stream once the clock of the
/// bind passed the handshake deadline.
const STALL_ENDED: Urn<'static> = urn!("test", "event:ws-accept/stall-ended");

/// The server of a scenario, and the socket address it bound.
type Served = Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError>;

/// The shared echo on `listener`, which records each session on `trace`.
fn echo(listener: WsListener, trace: &TraceCollector) -> Served {
	let addr = TightBeamSocketAddr(listener.local_addr());
	Ok((EchoService::serve(listener, None, trace), addr))
}

/// The shared echo on a cleartext listener on an ephemeral loopback port.
async fn bound_echo(trace: &TraceCollector) -> Served {
	let listener = WsListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await?;
	echo(listener, trace)
}

/// One exchange of a tightbeam client with the echo at `addr`, within the
/// patience of [`bounded`].
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

	bounded(exchange).await?
}

tb_assert_spec! {
	/// One session of the shared echo: the connection of the client is the
	/// one connection that the listener accepts, and its gate admits the one
	/// request.
	pub OneSessionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CONNECTION_ACCEPTED, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(1))
		]
	}
}

// A request with no upgrade ends at the listener, the accept loop yields the
// session of the client alone, and the listener keeps serving.
tb_scenario! {
	name: a_failed_upgrade_never_reaches_the_caller,
	spec: OneSessionSpec,
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move { bound_echo(&trace).await },
		client: |ClientEnv { addr, .. }| async move {
			// A hostile peer: a real client never sends a request with no
			// upgrade, and the server under test is real.
			let mut refused = bounded(TcpStream::connect(addr.0)).await??;
			refused.write_all(b"GET / HTTP/1.1\r\n\r\n").await?;

			// The listener ends the refused connection, so its read reaches
			// the end of the stream before the client dials.
			let mut answer = Vec::new();
			bounded(refused.read_to_end(&mut answer)).await??;
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
			let addr = first.local_addr();
			drop(first);

			let rebound = bounded(async {
				loop {
					let rebinding = WsListener::<DefaultCryptoProvider>::bind_cleartext(addr.to_string());
					if let Ok(listener) = rebinding.await {
						return listener;
					}

					yield_now().await;
				}
			});

			let rebound = rebound.await?;
			assert_eq!(rebound.local_addr(), addr, "the rebound listener MUST hold the released address");
			echo(rebound, &trace)
		},
		client: |ClientEnv { addr, .. }| async move { still_serves(addr).await }
	}
}

tb_assert_spec! {
	/// One session of the shared echo beside a stalled peer, and the end of the
	/// stalled socket at the handshake deadline of the endpoint.
	pub StallEndSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CONNECTION_ACCEPTED, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(1)),
			(STALL_ENDED, exactly!(1), equals!(true))
		]
	}
}

/// A clock that the case moves, and the limits of the endpoint that the
/// listener of the case binds on that clock.
#[derive(Default)]
struct Clocked {
	clock: Arc<ManualClock>,
	limits: TransportLimits,
}

// A peer that never sends its upgrade delays no other connection, and its
// upgrade ends at the handshake deadline on the clock of the bind. The listener
// accepts in order, so the session of the client, which connects after the
// stall, orders the move of the clock after the accept of the stalled socket.
tb_scenario! {
	name: a_stalled_upgrade_delays_no_other_connection_and_ends_at_its_deadline,
	spec: StallEndSpec,
	environment ServiceClient {
		context: Clocked::default(),
		server: |SetupEnv { trace, context }| async move {
			let endpoint = EndpointConfig::cleartext().with_limits(context.limits)?;
			let clock = context.clock.clone();
			let listener = WsListener::<DefaultCryptoProvider>::bind("127.0.0.1:0", endpoint, clock).await?;
			echo(listener, &trace)
		},
		client: |ClientEnv { trace, context, addr }| async move {
			// A hostile peer: a real client never stalls before its upgrade,
			// and the server under test is real.
			let mut stalled = bounded(TcpStream::connect(addr.0)).await??;
			still_serves(addr).await?;

			context.clock.advance(context.limits.handshake_timeout);

			let mut byte = [0_u8; 1];
			let read = bounded(stalled.read(&mut byte)).await?;
			trace.event_with(STALL_ENDED, &[], matches!(read, Ok(0)))?;
			Ok(())
		}
	}
}
