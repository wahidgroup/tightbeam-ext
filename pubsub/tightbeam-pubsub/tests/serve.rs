//! The served connection behind [`PubsubCommands::serve`], as tightbeam
//! scenarios: the link it accepts, the tasks it owns, and the peer it
//! registers under.
//!
//! The link and task cases run over the in-memory link, because they prove
//! the link that [`MemoryLink::served`] builds from its parts. A mux built
//! from parts cannot record on a trace, since upstream attaches the trace of a
//! mux through a crate-private constructor, so these cases record what they
//! observe, and the spec grades it. The peer cases accept one loopback dial
//! over a real handshake on transports that record on the trace, so the
//! registry admits the connection under the peer that the handshake proved,
//! and the subscribe policy records whether that peer is the whole pinned
//! identity.

use core::future::pending;
use core::time::Duration;
use std::io;
use std::sync::{Arc, Weak};

use tightbeam::clock::{Clock, MonotonicInstant, SystemClock, Timing, UnixMillis};
use tightbeam::marker::MaybeSendFuture;
use tightbeam::policy::SessionContext;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::{ClientEnv, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::{MuxAcceptor, MuxDispatch, MuxDrivers, MuxRole};
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, EncryptedMessageIO, EncryptedProtocol};
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn, TightBeamError};
use tightbeam_pubsub::events::CONNECTION_ADMITTED;
use tightbeam_pubsub::testing::{MemoryLink, OpaqueFrame};
use tightbeam_pubsub::{AccessVerdict, PubsubCommands, RegistryView, SubscribePolicy, Topic, TopicRegistry, Unrouted};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::serve::{AcceptedLink, LinkError};
use tightbeam_ws::testing::{Identity, Security};
use tokio::task::{yield_now, JoinHandle};
use tokio::time::sleep;

/// Whether the client drivers of a link ended after its serve dropped.
const DRIVERS_ENDED: Urn<'static> = urn!("test", "event:pubsub-serve/drivers-ended");

/// Whether the last strong reference behind the clock of a link went away.
const CLOCK_RELEASED: Urn<'static> = urn!("test", "event:pubsub-serve/clock-released");

/// Whether a link whose writer clock parks was refused for it.
const PARKING_REFUSED: Urn<'static> = urn!("test", "event:pubsub-serve/parking-refused");

/// Which identity of the kind the peer certificate that the subscribe policy
/// read is, as `Security::peer_identity` names it: `pinned` or `none`.
const POLICY_PEER: Urn<'static> = urn!("test", "event:pubsub-serve/policy-peer");

/// The stream cap that both ends offer.
const STREAMS: u32 = 4;

/// How long each identity stays valid.
const VALIDITY: Duration = Duration::from_secs(3600);

/// The server of a scenario, and the socket address it bound.
type Served = Result<(JoinHandle<Result<(), TightBeamError>>, TightBeamSocketAddr), TightBeamError>;

/// Refuses every interaction through the defaults of the trait.
struct Closed;

impl MuxDispatch for Closed {}

/// Poll until the reader of `drivers` ends, or give up.
async fn ended(drivers: &MuxDrivers) -> bool {
	for _ in 0..200 {
		if drivers.is_finished() {
			return true;
		}

		sleep(Duration::from_millis(10)).await;
	}

	false
}

/// Yield until the last strong reference behind `clock` is gone, or give up.
async fn released(clock: &Weak<dyn Clock>) -> bool {
	for _ in 0..64 {
		if clock.strong_count() == 0 {
			return true;
		}

		yield_now().await;
	}

	false
}

/// How long a served end waits for its client to answer its first keepalive
/// probe, so the keepalive sleeps out its interval when the serve drops.
const PROBED: Duration = Duration::from_millis(50);

tb_assert_spec! {
	pub DroppedServeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(DRIVERS_ENDED, exactly!(1), equals!(true)),
			(CLOCK_RELEASED, exactly!(1), equals!(true))
		]
	}
}

// A dropped serve future ends the drivers of its link and its keepalive, so
// the client drivers end and the last reference to the link clock goes away.
tb_scenario! {
	name: a_dropped_serve_future_ends_its_drivers_and_keepalive,
	spec: DroppedServeSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let clock: Arc<dyn Clock> = Arc::new(SystemClock);
			let witness = Arc::downgrade(&clock);
			let linked = MemoryLink::new(clock).served(MuxSettings::symmetric(STREAMS));
			let (client, server) = linked.map_err(io::Error::other)?;
			let client = client.spawn();
			let serving = tokio::spawn(server.spawn().serve(Closed, pending()));
			sleep(PROBED).await;

			serving.abort();
			// The abort ends the serve, and its outcome is the cancellation.
			let _ = serving.await;
			trace.event_with(DRIVERS_ENDED, &[], ended(&client.drivers).await)?;
			drop(client);

			trace.event_with(CLOCK_RELEASED, &[], released(&witness).await)?;
			Ok(())
		}
	}
}

/// The system clock, reporting that its sleep parks the thread, as a clock
/// with no timer on the runtime does. The system clock itself races on every
/// tokio thread, so no stock clock reaches this refusal.
#[derive(Debug)]
struct Parking(SystemClock);

impl Clock for Parking {
	fn unix(&self) -> UnixMillis {
		self.0.unix()
	}

	fn monotonic(&self) -> MonotonicInstant {
		self.0.monotonic()
	}

	fn sleep(&self, span: Duration) -> MaybeSendFuture<'_, ()> {
		self.0.sleep(span)
	}

	fn timing(&self) -> Timing {
		Timing::Parks
	}
}

tb_assert_spec! {
	pub ParkingClockSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PARKING_REFUSED, exactly!(1), equals!(true))
		]
	}
}

// A link whose writer clock parks is refused, because no emit deadline and no
// keepalive could race a wait on it.
tb_scenario! {
	name: a_link_whose_writer_clock_parks_is_refused,
	spec: ParkingClockSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let link = MemoryLink::new(Arc::new(Parking(SystemClock)));
			let refused = link.served(MuxSettings::symmetric(STREAMS));
			trace.event_with(PARKING_REFUSED, &[], matches!(refused, Err(LinkError::ClockCannotRace(Timing::Parks))))?;
			Ok(())
		}
	}
}

/// Allows every topic, and records which identity of the security kind of its
/// case the peer certificate of each session it authorizes is.
///
/// It is a user implementation of the public `SubscribePolicy` port, and it
/// records what crossed the boundary.
struct PeerOf {
	trace: TraceCollector,
	case: Arc<Case>,
}

impl SubscribePolicy for PeerOf {
	fn authorize(&self, _registry: RegistryView<'_>, session: &SessionContext, _topic: &Topic) -> AccessVerdict {
		let peer = self.case.security.peer_identity(session.peer_certificate());
		// The trace refuses an event only under an injected fault, which no
		// scenario here injects.
		let _ = self.trace.event_with(POLICY_PEER, &[], peer.as_str());
		AccessVerdict::Allow
	}
}

/// The identity of a server or a client.
fn identity(subject: &str, serial: u32) -> Identity {
	let minted = Identity::mint(subject, serial, VALIDITY);
	minted.expect("the identity mints")
}

/// One served dial of a security kind: the identity of the server, and the
/// kind.
struct Case {
	server: Identity,
	security: Security,
}

impl Case {
	/// A case of `security` against the one server identity of this file.
	fn of(security: Security) -> Self {
		let server = identity("CN=pubsub serve server,O=tightbeam-pubsub,C=US", 1);
		Self { server, security }
	}

	/// The kind that pins the client identity of this file.
	fn mutual() -> Self {
		let client = identity("CN=pubsub serve client,O=tightbeam-pubsub,C=US", 2);
		Self::of(Security::Mutual { pinned: client })
	}

	/// Bind a server of this kind on loopback, and on a task accept one dial
	/// on a transport that records on `trace` and serve it through a registry
	/// whose subscribe policy records the peer it authorizes.
	async fn serve(case: Arc<Self>, trace: TraceCollector) -> Served {
		let config = case.security.server_config(&case.server)?;
		let loopback = TightBeamSocketAddr("127.0.0.1:0".parse()?);
		let (listener, addr) = <WsListener as EncryptedProtocol>::bind_with(loopback, config).await?;

		let policy = PeerOf { trace: trace.share(), case: Arc::clone(&case) };
		let commands = PubsubCommands::new(TopicRegistry::default(), policy);
		let serving = tokio::spawn(async move {
			let (transport, _peer) = listener.accept().await?;
			let mut metered = case.security.meter(transport.with_trace(trace), STREAMS);
			metered.negotiate_mux().await?;

			let link = AcceptedLink::accepted(metered).map_err(io::Error::other)?;
			commands.serve(link, Unrouted).await?;
			Ok(())
		});

		Ok((serving, addr))
	}

	/// Dial `addr` under this kind, pinning the server, on a transport that
	/// records on `trace`, and subscribe to one topic.
	async fn subscribe(&self, addr: TightBeamSocketAddr, trace: &TraceCollector) -> Result<(), TightBeamError> {
		let trust = self.server.trust_anchor()?;
		let mut builder = ClientBuilder::<WsListener>::builder().with_trust_store(trust);
		if let Some(client) = self.security.client_identity() {
			builder = builder.with_client_identity(client.signing_identity()?);
		}

		let dialed = builder.connect(addr).await?;
		let traced = dialed.into_transport().with_trace(trace.share());
		let mut transport = self.security.meter_dial(traced, STREAMS, 1);
		transport.perform_client_handshake().await?;

		let mux = transport.into_mux(MuxRole::Client)?.spawn();
		let command = OpaqueFrame { id: "sub/prices", order: 1, payload: b"" }.build()?;
		mux.handle.emit_on_stream(&command).await?;
		Ok(())
	}
}

tb_assert_spec! {
	pub HandshakePeerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CONNECTION_ADMITTED, exactly!(1)),
			(POLICY_PEER, exactly!(1), equals!("pinned"))
		]
	}
}

// A served connection registers under the peer that its handshake proved, so
// the subscribe policy reads the client certificate.
tb_scenario! {
	name: a_served_connection_registers_under_its_handshake_peer,
	spec: HandshakePeerSpec,
	environment ServiceClient {
		context: Case::mutual(),
		server: |SetupEnv { trace, context }| Case::serve(context, trace),
		client: |ClientEnv { trace, context, addr }| async move { context.subscribe(addr, &trace).await }
	}
}

tb_assert_spec! {
	pub AnonymousPeerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CONNECTION_ADMITTED, exactly!(1)),
			(POLICY_PEER, exactly!(1), equals!("none"))
		]
	}
}

// An anonymous connection registers with no peer, so the subscribe policy
// reads no certificate.
tb_scenario! {
	name: an_anonymous_connection_registers_with_no_peer,
	spec: AnonymousPeerSpec,
	environment ServiceClient {
		context: Case::of(Security::ServerAuth),
		server: |SetupEnv { trace, context }| Case::serve(context, trace),
		client: |ClientEnv { trace, context, addr }| async move { context.subscribe(addr, &trace).await }
	}
}
