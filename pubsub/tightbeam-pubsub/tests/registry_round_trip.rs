//! Integration coverage over public interfaces only, as tightbeam scenarios.
//!
//! Each peer dials a WebSocket server on loopback over a real handshake. The
//! server side wires a [`TopicRegistry`] behind [`PubsubCommands`] exactly
//! like the demo server, and the client side drives the wire commands a
//! TypeScript subscriber would send. Both transports of each peer record on
//! the trace of the scenario, and so does the audit trail of each served
//! connection ([`tightbeam_pubsub::events`]), so a spec grades what the
//! registry decided: the connections it let go or expelled, the commands it
//! refused, and the updates it dropped. The client asserts what each update
//! carried.

use core::num::NonZeroUsize;
use std::io;
use std::sync::Arc;

use der::{Decode, Encode};
use tightbeam::instrumentation::events;
use tightbeam::policy::{SessionContext, TransitStatus};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::{ScenarioConfig, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::transport::error::{TransportError, TransportFailure};
use tightbeam::transport::multiplex::{MuxAcceptor, MuxHandle, MuxRole};
use tightbeam::transport::{ClientBuilder, EncryptedMessageIO, EncryptedProtocol, ResponsePackage};
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario, Frame, Opaque, TightBeamError};
use tightbeam_pubsub::events::{
	COMMAND_REFUSED, CONNECTION_ADMITTED, CONNECTION_EXPELLED, CONNECTION_LEFT, UPDATE_DROPPED,
};
use tightbeam_pubsub::testing::OpaqueFrame;
use tightbeam_pubsub::{
	AccessVerdict, AllowAll, Backplane, DeliveryPolicy, DeliveryVerdict, DropOldest, Local, PublishError,
	PubsubCommands, RegistryOptions, RegistryView, SubscribePolicy, Topic, TopicRegistry, Unrouted,
};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::serve::AcceptedLink;
use tightbeam_ws::testing::{Identity, ReadOutcome, Security};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::sync::Semaphore;
use tokio::task::{yield_now, JoinHandle};
use tokio::time::{sleep, timeout, Duration};

/// Symmetric stream cap that both ends of a peer offer.
const CAP: u32 = 4;

/// Bound every await so a regression fails instead of hanging.
const DEADLINE: Duration = Duration::from_secs(5);

/// How long each server identity stays valid.
const VALIDITY: Duration = Duration::from_secs(3600);

/// Forbid every topic under `forbidden/`.
struct DenyForbidden;

impl SubscribePolicy for DenyForbidden {
	fn authorize(&self, _registry: RegistryView<'_>, _session: &SessionContext, topic: &Topic) -> AccessVerdict {
		if topic.as_str().starts_with("forbidden/") {
			return AccessVerdict::Forbid;
		}
		AccessVerdict::Allow
	}
}

/// How a peer connects: the stream cap both ends offer, and the permits its
/// update acknowledgments start with. One permit acks at once, and zero
/// stalls every ack until the scenario grants permits.
#[derive(Clone, Copy)]
struct Wiring {
	streams: u32,
	ack_permits: usize,
}

impl Wiring {
	/// The cap of [`CAP`] streams, with acks that run at once.
	const PROMPT: Self = Self { streams: CAP, ack_permits: 1 };

	/// The cap of [`CAP`] streams, with every ack stalled.
	const STALLED: Self = Self { streams: CAP, ack_permits: 0 };
}

/// One client wired to a registry-backed server over a WebSocket: the handle
/// sends commands, the receiver observes server-initiated updates, the
/// semaphore gates update acknowledgments, and the task serves the server
/// side.
struct Peer {
	handle: MuxHandle,
	updates: UnboundedReceiver<Arc<Frame>>,
	ack_gate: Arc<Semaphore>,
	serving: JoinHandle<()>,
}

impl Peer {
	/// Connect one peer to `registry` under `policy`, wiring the server side
	/// the way the demo server does, with both transports recording on
	/// `trace`.
	async fn connect<P>(
		registry: &TopicRegistry,
		policy: P,
		wiring: Wiring,
		trace: &TraceCollector,
	) -> Result<Self, TightBeamError>
	where
		P: SubscribePolicy + 'static,
	{
		let server = Identity::mint("CN=pubsub registry server,O=tightbeam-pubsub,C=US", 1, VALIDITY)?;
		let config = Security::ServerAuth.server_config(&server)?;
		let loopback = TightBeamSocketAddr("127.0.0.1:0".parse()?);
		let (listener, addr) = <WsListener as EncryptedProtocol>::bind_with(loopback, config).await?;

		let commands = PubsubCommands::new(registry.clone(), policy).with_publish(AllowAll);
		let serving = tokio::spawn(Self::serve(listener, commands, wiring.streams, trace.share()));

		let builder = ClientBuilder::<WsListener>::builder().with_trust_store(server.trust_anchor()?);
		let dialed = builder.connect(addr).await?;
		let traced = dialed.into_transport().with_trace(trace.share());
		let mut transport = Security::ServerAuth.meter_dial(traced, wiring.streams, 1);
		transport.perform_client_handshake().await?;

		let client = transport.into_mux(MuxRole::Client)?;
		let (handle, reader, writer, responder) = client.into_parts();
		tokio::spawn(reader.drive());
		tokio::spawn(writer.drive());

		let (sender, updates) = unbounded_channel();
		let ack_gate = Arc::new(Semaphore::new(wiring.ack_permits));
		let serve_gate = Arc::clone(&ack_gate);
		tokio::spawn(responder.serve(move |frame| {
			let sender = sender.clone();
			let gate = Arc::clone(&serve_gate);
			async move {
				let _ = sender.send(Arc::clone(&frame));
				let permit = gate.acquire().await.expect("the ack gate should stay open");
				drop(permit);

				ResponsePackage::new(TransitStatus::Ok, None)
			}
		}));

		Ok(Self { handle, updates, ack_gate, serving })
	}

	/// Accept the one dial on `listener` under the server-auth kind, on a
	/// transport that records on `trace`, and serve it through `commands`
	/// until it ends.
	async fn serve<P>(listener: WsListener, commands: PubsubCommands<P>, streams: u32, trace: TraceCollector)
	where
		P: SubscribePolicy + 'static,
	{
		let served = async {
			let (transport, _peer) = listener.accept().await?;
			let mut metered = Security::ServerAuth.meter(transport.with_trace(trace), streams);
			metered.negotiate_mux().await?;

			let link = AcceptedLink::accepted(metered).map_err(io::Error::other)?;
			commands.serve(link, Unrouted).await?;
			Ok::<(), TightBeamError>(())
		};

		// The client of the peer reads every failure of the serve as the end of
		// its link, so the serve itself has no one else to report to.
		let _ = served.await;
	}

	/// Drop the server's serve future, as an accept loop that aborts its
	/// handlers does, and wait until the future is gone.
	async fn drop_serve(&mut self) {
		self.serving.abort();
		let _ = (&mut self.serving).await;
	}

	/// Emit one command stream and return its outcome.
	async fn request(&self, id: &str) -> Result<Option<Frame>, TransportError> {
		self.request_with(id, &[]).await
	}

	/// Emit one command stream carrying `payload` and return its outcome.
	async fn request_with(&self, id: &str, payload: &[u8]) -> Result<Option<Frame>, TransportError> {
		let frame = OpaqueFrame { id, order: 1, payload };
		let command = frame.build().expect("command frames build from valid input");
		self.handle.emit_on_stream(&command).await
	}

	/// The next server-initiated update, within the deadline.
	async fn next_update(&mut self) -> Arc<Frame> {
		timeout(DEADLINE, self.updates.recv())
			.await
			.expect("an update should arrive within the deadline")
			.expect("the update channel should stay open")
	}

	/// Emit one command stream, expecting the peer to accept it.
	async fn granted(&self, id: &str) {
		self.request(id).await.expect("the command should be accepted");
	}

	/// Emit one command stream carrying `payload`, expecting acceptance.
	async fn granted_with(&self, id: &str, payload: &[u8]) {
		self.request_with(id, payload).await.expect("the command should be accepted");
	}
}

/// A delivery policy that returns one fixed verdict.
struct FixedVerdict(DeliveryVerdict);

impl DeliveryPolicy for FixedVerdict {
	fn on_full(&self, _registry: RegistryView<'_>, _topic: &Topic, _dropped_so_far: u64) -> DeliveryVerdict {
		self.0
	}
}

/// A queue capacity of `updates`.
fn capacity(updates: usize) -> NonZeroUsize {
	NonZeroUsize::new(updates).expect("test capacities are above zero")
}

/// A default registry with one peer granted the `sub/` command in `name`.
async fn subscribed(name: &str, trace: &TraceCollector) -> Result<(TopicRegistry, Peer), TightBeamError> {
	let registry = TopicRegistry::default();
	let peer = Peer::connect(&registry, AllowAll, Wiring::PROMPT, trace).await?;
	peer.granted(name).await;
	Ok((registry, peer))
}

/// Publish `payload` to `name` through `registry`, expecting acceptance.
fn published(registry: &TopicRegistry, name: &str, payload: &[u8]) {
	let topic = Topic::fixture(name);
	registry.publish(&topic, payload).expect("the publish should be accepted");
}

/// Publish a full frame to `name` through `registry`, expecting acceptance.
fn published_frame(registry: &TopicRegistry, name: &str, inner: &Frame) {
	registry
		.publish_frame(&Topic::fixture(name), inner)
		.expect("the frame publish should be accepted");
}

/// Build an application frame to carry as a topic payload.
fn inner_frame(id: &str, order: u64, payload: &[u8]) -> Frame {
	let frame = OpaqueFrame { id, order, payload };
	frame.build().expect("the inner frame should build")
}

/// Encode a frame, expecting well-formed DER.
fn der_of(frame: &Frame) -> Vec<u8> {
	frame.to_der().expect("the frame should encode")
}

/// Decode a relayed payload back into a frame.
fn frame_of(payload: &[u8]) -> Frame {
	Frame::from_der(payload).expect("the payload should decode as a frame")
}

/// Quiesce `registry`, expecting the signaled subscriber count.
fn quiesced(registry: &TopicRegistry) -> usize {
	registry.quiesce().expect("quiesce should signal every subscriber")
}

/// Decode the opaque body, expecting a well-formed update.
fn payload_of(update: &Frame) -> Vec<u8> {
	let body = update.decode_message::<Opaque>().expect("update bodies should decode");
	body.into_bytes()
}

/// Assert one update's wrapper stamps and payload.
fn expect_update(update: &Frame, id: &[u8], order: u64, payload: &[u8]) {
	assert_eq!(update.metadata().id(), id, "the update should route by the topic id");
	assert_eq!(update.metadata().order(), order, "the update should carry the dense stamp");
	assert_eq!(payload_of(update), payload, "the payload should round-trip");
}

/// The refusal status a command rejected with.
fn refusal(outcome: Result<Option<Frame>, TransportError>) -> TransportFailure {
	match outcome {
		Err(TransportError::OperationFailed(failure)) => failure,
		other => panic!("expected a peer refusal, got {other:?}"),
	}
}

tb_assert_spec! {
	pub RoundTripSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COMMAND_REFUSED, exactly!(0)),
			(UPDATE_DROPPED, exactly!(0))
		]
	}
}

// A subscriber reads three updates in their dense order, and the registry
// refuses no command and drops no update. Its unsubscribe leaves the topic
// with no subscriber, and a publish snapshots the subscribers of its topic as
// it runs, so the publish after it reaches nobody.
tb_scenario! {
	name: subscribe_publish_unsubscribe_round_trip,
	spec: RoundTripSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let registry = TopicRegistry::default();
			let mut peer = Peer::connect(&registry, AllowAll, Wiring::PROMPT, &trace).await?;

			let subscribed = peer.request("sub/prices").await;
			assert!(subscribed.is_ok(), "the sub/ command should be accepted: {subscribed:?}");

			for payload in [b"one".as_slice(), b"two", b"three"] {
				published(&registry, "prices", payload);
			}

			for (order, payload) in [(1, b"one".as_slice()), (2, b"two"), (3, b"three")] {
				let update = peer.next_update().await;
				expect_update(&update, b"prices", order, payload);
			}

			let unsubscribed = peer.request("unsub/prices").await;
			assert!(unsubscribed.is_ok(), "the unsub/ command should be accepted: {unsubscribed:?}");

			let subscribers = registry.view().subscriber_count(&Topic::fixture("prices"));
			assert_eq!(subscribers, 0, "an unsubscribe should leave the topic with no subscriber");
			published(&registry, "prices", b"four");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub OneUpdateTwoPeersSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COMMAND_REFUSED, exactly!(0)),
			(UPDATE_DROPPED, exactly!(0))
		]
	}
}

// A wire publish from one peer reaches the subscriber on another.
tb_scenario! {
	name: wire_publish_reaches_every_subscriber,
	spec: OneUpdateTwoPeersSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (registry, mut subscriber) = subscribed("sub/prices", &trace).await?;
			let publisher = Peer::connect(&registry, AllowAll, Wiring::PROMPT, &trace).await?;

			let outcome = publisher.request_with("pub/prices", b"tick").await;
			assert!(outcome.is_ok(), "the pub/ command should be accepted: {outcome:?}");

			let update = subscriber.next_update().await;
			expect_update(&update, b"prices", 1, b"tick");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub OneUpdateSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(UPDATE_DROPPED, exactly!(0))
		]
	}
}

// A published frame relays as the payload of one update, with the id and the
// order of the application frame untouched.
tb_scenario! {
	name: publish_frame_relays_the_inner_frame_untouched,
	spec: OneUpdateSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (registry, mut peer) = subscribed("sub/orders", &trace).await?;

			let inner = inner_frame("order-42", 7, b"fill");
			published_frame(&registry, "orders", &inner);

			let update = peer.next_update().await;
			expect_update(&update, b"orders", 1, &der_of(&inner));

			let application = frame_of(&payload_of(&update));
			assert_eq!(application.metadata().id(), b"order-42", "the inner id should stay the application's");
			assert_eq!(application.metadata().order(), 7, "the inner order should stay the application's");
			Ok(())
		}
	}
}

// A wire publish of a frame payload relays its DER to the subscriber
// unchanged.
tb_scenario! {
	name: wire_publish_relays_a_frame_payload,
	spec: OneUpdateTwoPeersSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (registry, mut subscriber) = subscribed("sub/orders", &trace).await?;
			let publisher = Peer::connect(&registry, AllowAll, Wiring::PROMPT, &trace).await?;

			let inner_der = der_of(&inner_frame("order-42", 7, b"fill"));
			publisher.granted_with("pub/orders", &inner_der).await;

			let update = subscriber.next_update().await;
			expect_update(&update, b"orders", 1, &inner_der);
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub FanOutSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(UPDATE_DROPPED, exactly!(0))
		]
	}
}

// One publish fans out to both subscribers of its topic.
tb_scenario! {
	name: fan_out_reaches_every_subscriber,
	spec: FanOutSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (registry, mut first) = subscribed("sub/prices", &trace).await?;
			let mut second = Peer::connect(&registry, AllowAll, Wiring::PROMPT, &trace).await?;
			second.granted("sub/prices").await;

			published(&registry, "prices", b"tick");

			for peer in [&mut first, &mut second] {
				let update = peer.next_update().await;
				expect_update(&update, b"prices", 1, b"tick");
			}
			Ok(())
		}
	}
}

/// Two registries ("nodes") sharing one backplane, each serving one peer.
async fn two_nodes(trace: &TraceCollector) -> Result<(TopicRegistry, TopicRegistry, Peer, Peer), TightBeamError> {
	let backplane: Arc<dyn Backplane> = Arc::new(Local::default());
	let node_a =
		TopicRegistry::new(RegistryOptions { backplane: Arc::clone(&backplane), ..RegistryOptions::default() });
	let node_b = TopicRegistry::new(RegistryOptions { backplane, ..RegistryOptions::default() });

	let on_a = Peer::connect(&node_a, AllowAll, Wiring::PROMPT, trace).await?;
	let on_b = Peer::connect(&node_b, AllowAll, Wiring::PROMPT, trace).await?;
	Ok((node_a, node_b, on_a, on_b))
}

// A publish on one node of a shared backplane reaches the subscribers of
// every node.
tb_scenario! {
	name: shared_backplane_reaches_subscribers_on_every_node,
	spec: FanOutSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (node_a, _node_b, mut on_a, mut on_b) = two_nodes(&trace).await?;
			on_a.granted("sub/prices").await;
			on_b.granted("sub/prices").await;

			published(&node_a, "prices", b"tick");

			for peer in [&mut on_a, &mut on_b] {
				let update = peer.next_update().await;
				expect_update(&update, b"prices", 1, b"tick");
			}
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub QuiescedNodeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(UPDATE_DROPPED, exactly!(0))
		]
	}
}

// A quiesced node completes its topics with `end/`, and the sibling node
// keeps serving dense orders across it, with no update dropped.
tb_scenario! {
	name: quiescing_one_node_leaves_the_backplane_live,
	spec: QuiescedNodeSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (node_a, node_b, mut on_a, mut on_b) = two_nodes(&trace).await?;
			on_a.granted("sub/prices").await;
			on_b.granted("sub/prices").await;
			published(&node_a, "prices", b"tick");
			on_a.next_update().await;
			on_b.next_update().await;

			quiesced(&node_a);

			let end = on_a.next_update().await;
			assert_eq!(end.metadata().id(), b"end/prices", "the quiesced node should complete its topics");
			assert_eq!(end.metadata().order(), 1, "end/ carries the last committed order");

			published(&node_b, "prices", b"tock");

			let update = on_b.next_update().await;
			assert_eq!(update.metadata().order(), 2, "the live node should see dense orders across the sibling's quiesce");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ForbiddenTopicSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COMMAND_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied))
		]
	}
}

// A topic that the subscribe policy forbids answers `PermissionDenied`, and the
// registry records the refusal of the `sub/` command.
tb_scenario! {
	name: a_forbidden_topic_answers_permission_denied,
	spec: ForbiddenTopicSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let registry = TopicRegistry::default();
			let peer = Peer::connect(&registry, DenyForbidden, Wiring::PROMPT, &trace).await?;

			let refused = refusal(peer.request("sub/forbidden/keys").await);
			assert_eq!(refused, TransportFailure::PermissionDenied, "a policy-forbidden topic should answer PermissionDenied");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub EmptyTopicSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COMMAND_REFUSED, exactly!(1), equals!(TransitStatus::InvalidArgument))
		]
	}
}

// An empty topic answers `InvalidArgument`, and the registry records the
// refusal of the `sub/` command.
tb_scenario! {
	name: an_empty_topic_answers_invalid_argument,
	spec: EmptyTopicSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let registry = TopicRegistry::default();
			let peer = Peer::connect(&registry, DenyForbidden, Wiring::PROMPT, &trace).await?;

			let refused = refusal(peer.request("sub/").await);
			assert_eq!(refused, TransportFailure::InvalidArgument, "an empty topic should answer InvalidArgument");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub NoCommandSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COMMAND_REFUSED, exactly!(0))
		]
	}
}

// A stream that names no command falls through to the application routes,
// which answer `Unimplemented`, so the registry refuses no command.
tb_scenario! {
	name: a_non_command_stream_falls_through_to_the_app,
	spec: NoCommandSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let registry = TopicRegistry::default();
			let peer = Peer::connect(&registry, DenyForbidden, Wiring::PROMPT, &trace).await?;

			let refused = refusal(peer.request("no-such-command").await);
			assert_eq!(refused, TransportFailure::Unimplemented, "a non-command stream should fall through to the app handler");
			Ok(())
		}
	}
}

// Quiesce completes the topic of its one subscriber, which reads `end/`, and
// refuses new subscriptions with `Unavailable` and new publishes.
tb_assert_spec! {
	pub QuiesceSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COMMAND_REFUSED, exactly!(1), equals!(TransitStatus::Unavailable))
		]
	}
}

tb_scenario! {
	name: quiesce_completes_topics_and_refuses_new_work,
	spec: QuiesceSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (registry, mut peer) = subscribed("sub/prices", &trace).await?;

			let signaled = quiesced(&registry);
			assert_eq!(signaled, 1, "the one subscriber should be signaled");

			let end = peer.next_update().await;
			assert_eq!(end.metadata().id(), b"end/prices", "quiesce should complete the topic");

			let refused = peer.request("sub/chat").await;
			assert_eq!(refusal(refused), TransportFailure::Unavailable, "a draining registry should answer Unavailable");
			let late = registry.publish(&Topic::fixture("prices"), b"late");
			assert!(matches!(late, Err(PublishError::Draining)), "a draining registry should refuse publishes");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub SlowConsumerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(UPDATE_DROPPED, exactly!(1), equals!(1u64))
		]
	}
}

// A slow consumer under `DropOldest` loses the oldest queued update and keeps
// reading: the fourth update evicts the second, the subscription records its
// one drop, and the reader sees a gap where the dropped one stood.
tb_scenario! {
	name: slow_consumer_drops_oldest_and_continues,
	spec: SlowConsumerSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let options = RegistryOptions { queue_capacity: capacity(2), delivery: Arc::new(DropOldest), ..RegistryOptions::default() };
			let registry = TopicRegistry::new(options);

			// Zero permits: the client receives updates but stalls every ack.
			let mut peer = Peer::connect(&registry, AllowAll, Wiring::STALLED, &trace).await?;
			peer.granted("sub/prices").await;

			// The first update is in flight (received, unacknowledged) before
			// the burst, so the queue state during the burst is deterministic.
			published(&registry, "prices", b"1");

			let first = peer.next_update().await;
			assert_eq!(first.metadata().order(), 1, "the first update should be in flight");

			// Capacity 2: updates 2 and 3 queue, update 4 evicts update 2.
			for payload in [b"2".as_slice(), b"3", b"4"] {
				published(&registry, "prices", payload);
			}

			peer.ack_gate.add_permits(16);

			let after_gap = peer.next_update().await;
			let last = peer.next_update().await;
			assert_eq!(
				[after_gap.metadata().order(), last.metadata().order()],
				[3, 4],
				"the oldest queued update should be dropped, revealing a gap"
			);
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub DroppedServeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CONNECTION_LEFT, exactly!(1), equals!(1u64)),
			(ReadOutcome::EVENT, exactly!(1), equals!("closed"))
		]
	}
}

tb_process_spec! {
	/// A connection whose serve drops, in order: the registry admits it, the
	/// drop of the serve takes it out of the registry, and only then does its
	/// client read the closed link.
	pub DroppedServeProcess,
	events {
		observable { CONNECTION_ADMITTED, CONNECTION_LEFT, ReadOutcome::EVENT }
		hidden { }
	}
	states {
		Connecting => { CONNECTION_ADMITTED => Serving },
		Serving => { CONNECTION_LEFT => Left },
		Left => { ReadOutcome::EVENT => Closed },
		Closed => { }
	}
	terminal { Closed }
}

// A dropped serve leaves the registry with the one subscription it held, and
// ends its link, so the next command reads the closed connection. The
// registry lets the connection go as the serve drops, so no registration
// outlives the serve that the client sees end.
tb_scenario! {
	name: a_dropped_serve_leaves_no_registration_and_ends_its_link,
	config: ScenarioConfig::builder().with_spec(DroppedServeSpec::latest()).with_csp(DroppedServeProcess).build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (registry, mut peer) = subscribed("sub/prices", &trace).await?;

			peer.drop_serve().await;

			let after = timeout(DEADLINE, peer.request("sub/chat")).await;
			let after = after.map_err(|elapsed| TightBeamError::IoError(elapsed.into()))?;
			ReadOutcome::record(&after, &trace)?;
			assert_eq!(registry.view().subscriber_count(&Topic::fixture("prices")), 0, "the dropped serve should leave the registry");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub StreamSlotSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(UPDATE_DROPPED, exactly!(0))
		]
	}
}

// On a link of one stream, an update of one topic waits for the slot that
// the in-flight update of another topic holds, and arrives once it frees,
// with no update dropped.
tb_scenario! {
	name: an_update_waits_for_the_stream_slot_another_topic_holds,
	spec: StreamSlotSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let registry = TopicRegistry::default();
			let wiring = Wiring { streams: 1, ack_permits: 0 };
			let mut peer = Peer::connect(&registry, AllowAll, wiring, &trace).await?;
			peer.granted("sub/prices").await;
			peer.granted("sub/chat").await;
			published(&registry, "prices", b"tick");
			let holding = peer.next_update().await;

			published(&registry, "chat", b"hello");
			yield_now().await;
			peer.ack_gate.add_permits(2);

			let waited = peer.next_update().await;
			expect_update(&holding, b"prices", 1, b"tick");
			expect_update(&waited, b"chat", 1, b"hello");
			Ok(())
		}
	}
}

/// Poll until the peer observes a GoAway, or give up.
async fn goaway_of(handle: &MuxHandle) -> Option<GoAwayReason> {
	for _ in 0..100 {
		if let Some(reason) = handle.goaway_reason() {
			return Some(reason);
		}

		sleep(Duration::from_millis(10)).await;
	}

	None
}

tb_assert_spec! {
	pub ExpelledSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CONNECTION_EXPELLED, exactly!(1), equals!("enhance-your-calm")),
			(CONNECTION_LEFT, exactly!(1), equals!(1u64)),
			(events::MUX_GOAWAY_SENT, exactly!(1)),
			(events::MUX_GOAWAY_RECV, exactly!(1)),
			(UPDATE_DROPPED, exactly!(0))
		]
	}
}

tb_process_spec! {
	/// An expelled connection, in order: the registry admits it, expels it,
	/// and lets it go, and only then does the server send the GoAway that the
	/// client receives.
	pub ExpelledProcess,
	events {
		observable {
			CONNECTION_ADMITTED,
			CONNECTION_EXPELLED,
			CONNECTION_LEFT,
			events::MUX_GOAWAY_SENT,
			events::MUX_GOAWAY_RECV
		}
		hidden { }
	}
	states {
		Connecting => { CONNECTION_ADMITTED => Serving },
		Serving => { CONNECTION_EXPELLED => Expelled },
		Expelled => { CONNECTION_LEFT => Departed },
		Departed => { events::MUX_GOAWAY_SENT => Draining },
		Draining => { events::MUX_GOAWAY_RECV => Drained },
		Drained => { }
	}
	terminal { Drained }
}

// A connection whose delivery policy votes it off goes away with
// `EnhanceYourCalm` and leaves the registry. The peer stalls every ack, so the
// first update stays in flight, the second fills the queue of one, and the
// third makes the delivery policy vote the connection off, with no update
// dropped. The spec counts each step once, and the process grades that the
// registry records the expulsion and the departure before the GoAway leaves.
tb_scenario! {
	name: an_expelled_connection_goes_away_with_enhance_your_calm,
	config: ScenarioConfig::builder().with_spec(ExpelledSpec::latest()).with_csp(ExpelledProcess).build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let options = RegistryOptions {
				queue_capacity: capacity(1),
				delivery: Arc::new(FixedVerdict(DeliveryVerdict::Disconnect)),
				..RegistryOptions::default()
			};

			let registry = TopicRegistry::new(options);
			let mut peer = Peer::connect(&registry, AllowAll, Wiring::STALLED, &trace).await?;
			peer.granted("sub/prices").await;

			published(&registry, "prices", b"one");
			peer.next_update().await;
			published(&registry, "prices", b"two");
			published(&registry, "prices", b"three");

			let reason = goaway_of(&peer.handle).await;
			assert_eq!(reason, Some(GoAwayReason::EnhanceYourCalm));
			assert_eq!(registry.view().subscriber_count(&Topic::fixture("prices")), 0);
			Ok(())
		}
	}
}
