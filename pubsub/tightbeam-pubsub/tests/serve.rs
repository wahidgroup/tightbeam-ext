//! The served connection behind [`PubsubCommands::serve`]: the link it
//! accepts, the tasks it owns, and the peer it registers under.
//!
//! The link and task cases run over the in-memory link. The peer cases accept
//! one loopback dial over a real handshake, so the registry reads the peer
//! that the handshake proved.

use core::future::pending;
use core::time::Duration;
use std::sync::{Arc, OnceLock, Weak};

use tightbeam::clock::{Clock, MonotonicInstant, SystemClock, Timing, UnixMillis};
use tightbeam::marker::MaybeSendFuture;
use tightbeam::policy::SessionContext;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::{MuxAcceptor, MuxDispatch, MuxDrivers, MuxRole};
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, EncryptedMessageIO, EncryptedProtocol};
use tightbeam::x509::Certificate;
use tightbeam_pubsub::testing::{MemoryLink, OpaqueFrame};
use tightbeam_pubsub::{AccessVerdict, PubsubCommands, RegistryView, SubscribePolicy, Topic, TopicRegistry, Unrouted};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::serve::{AcceptedLink, LinkError};
use tightbeam_ws::testing::{Identity, Security};
use tokio::task::yield_now;
use tokio::time::sleep;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The stream cap that both ends offer.
const STREAMS: u32 = 4;

/// How long each identity stays valid.
const VALIDITY: Duration = Duration::from_secs(3600);

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

#[tokio::test]
async fn a_dropped_serve_future_ends_its_drivers_and_keepalive() {
	let clock: Arc<dyn Clock> = Arc::new(SystemClock);
	let witness = Arc::downgrade(&clock);
	let linked = MemoryLink::new(clock).served(MuxSettings::symmetric(STREAMS));
	let (client, server) = linked.expect("a link on the system clock races on a tokio thread");
	let client = client.spawn();
	let serving = tokio::spawn(server.spawn().serve(Closed, pending()));
	sleep(PROBED).await;

	serving.abort();
	let _ = serving.await;
	let drivers_ended = ended(&client.drivers).await;
	drop(client);

	assert!(drivers_ended);
	assert!(released(&witness).await);
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

#[tokio::test]
async fn a_link_whose_writer_clock_parks_is_refused() {
	let link = MemoryLink::new(Arc::new(Parking(SystemClock)));
	let refused = link.served(MuxSettings::symmetric(STREAMS));
	assert!(matches!(refused, Err(LinkError::ClockCannotRace(Timing::Parks))));
}

/// Allows every topic, and keeps the peer certificate of the first session
/// it authorizes.
///
/// It is a user implementation of the public `SubscribePolicy` port, and it
/// records what crossed the boundary.
#[derive(Clone, Default)]
struct PeerOf(Arc<OnceLock<Option<Certificate>>>);

impl SubscribePolicy for PeerOf {
	fn authorize(&self, _registry: RegistryView<'_>, session: &SessionContext, _topic: &Topic) -> AccessVerdict {
		let peer = session.peer_certificate().cloned();
		let _ = self.0.set(peer);
		AccessVerdict::Allow
	}
}

/// The identity of a server or a client.
fn identity(subject: &str, serial: u32) -> Identity {
	let minted = Identity::mint(subject, serial, VALIDITY);
	minted.expect("the identity mints")
}

/// Accept one dial on `listener`, a server of `security`, and serve it
/// through `commands` until it ends.
async fn serve_one(
	listener: WsListener,
	security: Arc<Security>,
	commands: PubsubCommands<PeerOf>,
) -> Result<(), BoxError> {
	let (transport, _peer) = listener.accept().await?;
	let mut metered = security.meter(transport, STREAMS);
	metered.negotiate_mux().await?;

	let link = AcceptedLink::accepted(metered)?;
	commands.serve(link, Unrouted).await?;
	Ok(())
}

/// Dial `addr` under `security`, pinning `server`, and subscribe to one
/// topic.
async fn subscribe(addr: TightBeamSocketAddr, server: &Identity, security: &Security) -> Result<(), BoxError> {
	let trust = server.trust_anchor()?;
	let mut builder = ClientBuilder::<WsListener>::builder().with_trust_store(trust);
	if let Some(client) = security.client_identity() {
		builder = builder.with_client_identity(client.signing_identity()?);
	}

	let dialed = builder.connect(addr).await?;
	let mut transport = security.meter_dial(dialed.into_transport(), STREAMS, 1);
	transport.perform_client_handshake().await?;

	let mux = transport.into_mux(MuxRole::Client)?.spawn();
	let command = OpaqueFrame { id: "sub/prices", order: 1, payload: b"" }.build()?;
	mux.handle.emit_on_stream(&command).await?;
	Ok(())
}

/// Serve one dial on a server of `security`, subscribe through it, and return
/// the peer certificate that the subscribe policy read, or `None` when the
/// policy authorized nothing.
async fn served_peer(security: Security) -> Result<Option<Option<Certificate>>, BoxError> {
	let server = identity("CN=pubsub serve server,O=tightbeam-pubsub,C=US", 1);
	let config = security.server_config(&server)?;
	let loopback = TightBeamSocketAddr("127.0.0.1:0".parse()?);
	let (listener, addr) = <WsListener as EncryptedProtocol>::bind_with(loopback, config).await?;

	let security = Arc::new(security);
	let policy = PeerOf::default();
	let commands = PubsubCommands::new(TopicRegistry::default(), policy.clone());
	let serving = tokio::spawn(serve_one(listener, Arc::clone(&security), commands));
	subscribe(addr, &server, &security).await?;
	serving.abort();

	let peer = policy.0.get().cloned();
	Ok(peer)
}

#[tokio::test]
async fn a_served_connection_registers_under_its_handshake_peer() -> Result<(), BoxError> {
	let client = identity("CN=pubsub serve client,O=tightbeam-pubsub,C=US", 2);
	let certificate = client.certificate().clone();
	let security = Security::Mutual { pinned: client };

	let peer = served_peer(security).await?;
	assert_eq!(peer, Some(Some(certificate)));
	Ok(())
}

#[tokio::test]
async fn an_anonymous_connection_registers_with_no_peer() -> Result<(), BoxError> {
	let peer = served_peer(Security::ServerAuth).await?;
	assert_eq!(peer, Some(None));
	Ok(())
}
