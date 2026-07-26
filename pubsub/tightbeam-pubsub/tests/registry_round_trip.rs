//! Integration coverage over public interfaces only: a real client/server
//! mux pair runs in-process over the in-memory envelope link, the server
//! side wires a [`TopicRegistry`] behind [`PubsubCommands`] exactly like
//! the demo server, and the client side drives the wire commands a
//! TypeScript subscriber would send.

use std::sync::Arc;

use der::{Decode, Encode};
use tightbeam::policy::TransitStatus;
use tightbeam::transport::error::{TransportError, TransportFailure};
use tightbeam::transport::multiplex::MuxHandle;
use tightbeam::transport::ResponsePackage;
use tightbeam::Frame;
use tightbeam_pubsub::testing::{command_frame, memory_mux_pair};
use tightbeam_pubsub::{
	opaque_payload, serve_connection, unrouted, AccessVerdict, AllowAll, Backplane, DropOldest, Local, PublishError,
	PubsubCommands, RegistryOptions, SubscribePolicy, Topic, TopicRegistry,
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

/// Symmetric stream cap for the in-memory pair.
const CAP: u32 = 4;

/// Bound every await so a regression fails instead of hanging.
const DEADLINE: Duration = Duration::from_secs(5);

/// Forbid every topic under `forbidden/`.
struct DenyForbidden;

impl SubscribePolicy for DenyForbidden {
	fn authorize(&self, _identity: Option<&[u8]>, topic: &Topic) -> AccessVerdict {
		if topic.as_str().starts_with("forbidden/") {
			return AccessVerdict::Forbid;
		}
		AccessVerdict::Allow
	}
}

/// One in-process client wired to a registry-backed server: the handle
/// sends commands, the receiver observes server-initiated updates, and
/// the semaphore gates update acknowledgments.
struct Peer {
	handle: MuxHandle,
	updates: UnboundedReceiver<Arc<Frame>>,
	ack_gate: Arc<Semaphore>,
}

impl Peer {
	/// Emit one command stream and return its outcome.
	async fn request(&self, id: &str) -> Result<Option<Frame>, TransportError> {
		self.request_with(id, &[]).await
	}

	/// Emit one command stream carrying `payload` and return its outcome.
	async fn request_with(&self, id: &str, payload: &[u8]) -> Result<Option<Frame>, TransportError> {
		let command = command_frame(id, 1, payload).expect("command frames build from valid input");
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

/// Connect one peer to `registry` through an in-memory mux pair, wiring
/// the server side the way the demo server does. `ack_permits` gates the
/// client's update acknowledgments: 1 acks immediately, 0 stalls until the
/// test grants permits.
async fn connect<P>(registry: &TopicRegistry, policy: P, ack_permits: usize) -> Peer
where
	P: SubscribePolicy + 'static,
{
	let (client, server) = memory_mux_pair(CAP);

	let commands = PubsubCommands::new(registry.clone(), policy).with_publish(AllowAll);
	tokio::spawn(async move {
		let _ = serve_connection(server, commands, unrouted).await;
	});

	let (client_handle, client_reader, client_writer, client_responder) = client.into_parts();
	tokio::spawn(client_reader.drive());
	tokio::spawn(client_writer.drive());

	let (sender, updates) = unbounded_channel();
	let ack_gate = Arc::new(Semaphore::new(ack_permits));
	let serve_gate = Arc::clone(&ack_gate);
	tokio::spawn(async move {
		let _ = client_responder
			.serve(move |frame| {
				let sender = sender.clone();
				let gate = Arc::clone(&serve_gate);
				async move {
					let _ = sender.send(Arc::clone(&frame));
					let permit = gate.acquire().await.expect("the ack gate should stay open");
					drop(permit);

					ResponsePackage::new(TransitStatus::Ok, None)
				}
			})
			.await;
	});

	Peer { handle: client_handle, updates, ack_gate }
}

fn topic(name: &str) -> Topic {
	name.parse().expect("test topics are valid")
}

/// A default registry with one peer granted the `sub/` command in `name`.
async fn subscribed(name: &str) -> (TopicRegistry, Peer) {
	let registry = TopicRegistry::default();
	let peer = connect(&registry, AllowAll, 1).await;
	peer.granted(name).await;
	(registry, peer)
}

/// Publish `payload` to `name` through `registry`, expecting acceptance.
fn published(registry: &TopicRegistry, name: &str, payload: &[u8]) {
	registry.publish(&topic(name), payload).expect("the publish should be accepted");
}

/// Publish a full frame to `name` through `registry`, expecting acceptance.
fn published_frame(registry: &TopicRegistry, name: &str, inner: &Frame) {
	registry
		.publish_frame(&topic(name), inner)
		.expect("the frame publish should be accepted");
}

/// Build an application frame to carry as a topic payload.
fn inner_frame(id: &str, order: u64, payload: &[u8]) -> Frame {
	command_frame(id, order, payload).expect("the inner frame should build")
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
	opaque_payload(update).expect("update bodies should decode")
}

/// Assert one update's wrapper stamps and payload.
fn expect_update(update: &Frame, id: &[u8], order: u64, payload: &[u8]) {
	assert_eq!(update.metadata.id, id, "the update should route by the topic id");
	assert_eq!(update.metadata.order, order, "the update should carry the dense stamp");
	assert_eq!(payload_of(update), payload, "the payload should round-trip");
}

/// The refusal status a command rejected with.
fn refusal(outcome: Result<Option<Frame>, TransportError>) -> TransportFailure {
	match outcome {
		Err(TransportError::OperationFailed(failure)) => failure,
		other => panic!("expected a peer refusal, got {other:?}"),
	}
}

#[tokio::test]
async fn subscribe_publish_unsubscribe_round_trip() {
	let registry = TopicRegistry::default();
	let mut peer = connect(&registry, AllowAll, 1).await;

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

	published(&registry, "prices", b"four");

	assert_eq!(
		registry.subscriber_count(&topic("prices")),
		0,
		"a publish after unsubscribe should reach nobody"
	);
}

#[tokio::test]
async fn wire_publish_reaches_every_subscriber() {
	let (registry, mut subscriber) = subscribed("sub/prices").await;
	let publisher = connect(&registry, AllowAll, 1).await;

	let outcome = publisher.request_with("pub/prices", b"tick").await;
	assert!(outcome.is_ok(), "the pub/ command should be accepted: {outcome:?}");

	let update = subscriber.next_update().await;
	expect_update(&update, b"prices", 1, b"tick");
}

#[tokio::test]
async fn publish_frame_relays_the_inner_frame_untouched() {
	let (registry, mut peer) = subscribed("sub/orders").await;

	let inner = inner_frame("order-42", 7, b"fill");
	published_frame(&registry, "orders", &inner);

	let update = peer.next_update().await;
	expect_update(&update, b"orders", 1, &der_of(&inner));

	let application = frame_of(&payload_of(&update));
	assert_eq!(
		application.metadata.id, b"order-42",
		"the inner id should stay the application's"
	);
	assert_eq!(application.metadata.order, 7, "the inner order should stay the application's");
}

#[tokio::test]
async fn wire_publish_relays_a_frame_payload() {
	let (registry, mut subscriber) = subscribed("sub/orders").await;
	let publisher = connect(&registry, AllowAll, 1).await;

	let inner_der = der_of(&inner_frame("order-42", 7, b"fill"));
	publisher.granted_with("pub/orders", &inner_der).await;

	let update = subscriber.next_update().await;
	expect_update(&update, b"orders", 1, &inner_der);
}

#[tokio::test]
async fn fan_out_reaches_every_subscriber() {
	let (registry, mut first) = subscribed("sub/prices").await;
	let mut second = connect(&registry, AllowAll, 1).await;
	second.granted("sub/prices").await;

	published(&registry, "prices", b"tick");

	for peer in [&mut first, &mut second] {
		let update = peer.next_update().await;
		expect_update(&update, b"prices", 1, b"tick");
	}
}

/// Two registries ("nodes") sharing one backplane, each serving one peer.
async fn two_nodes() -> (TopicRegistry, TopicRegistry, Peer, Peer) {
	let backplane: Arc<dyn Backplane> = Arc::new(Local::default());
	let node_a =
		TopicRegistry::new(RegistryOptions { backplane: Arc::clone(&backplane), ..RegistryOptions::default() });
	let node_b = TopicRegistry::new(RegistryOptions { backplane, ..RegistryOptions::default() });

	let on_a = connect(&node_a, AllowAll, 1).await;
	let on_b = connect(&node_b, AllowAll, 1).await;
	(node_a, node_b, on_a, on_b)
}

#[tokio::test]
async fn shared_backplane_reaches_subscribers_on_every_node() {
	let (node_a, _node_b, mut on_a, mut on_b) = two_nodes().await;
	on_a.granted("sub/prices").await;
	on_b.granted("sub/prices").await;

	published(&node_a, "prices", b"tick");

	for peer in [&mut on_a, &mut on_b] {
		let update = peer.next_update().await;
		expect_update(&update, b"prices", 1, b"tick");
	}
}

#[tokio::test]
async fn quiescing_one_node_leaves_the_backplane_live() {
	let (node_a, node_b, mut on_a, mut on_b) = two_nodes().await;
	on_a.granted("sub/prices").await;
	on_b.granted("sub/prices").await;
	published(&node_a, "prices", b"tick");
	on_a.next_update().await;
	on_b.next_update().await;

	quiesced(&node_a);

	let end = on_a.next_update().await;
	assert_eq!(end.metadata.id, b"end/prices", "the quiesced node should complete its topics");

	published(&node_b, "prices", b"tock");
	let update = on_b.next_update().await;
	assert_eq!(update.metadata.order, 2, "the live node should continue the dense sequence");
}

#[tokio::test]
async fn command_refusals_carry_their_statuses() {
	let registry = TopicRegistry::default();
	let peer = connect(&registry, DenyForbidden, 1).await;

	assert_eq!(
		refusal(peer.request("sub/forbidden/keys").await),
		TransportFailure::PermissionDenied,
		"a policy-forbidden topic should answer PermissionDenied"
	);
	assert_eq!(
		refusal(peer.request("sub/").await),
		TransportFailure::InvalidArgument,
		"an empty topic should answer InvalidArgument"
	);
	assert_eq!(
		refusal(peer.request("no-such-command").await),
		TransportFailure::Unimplemented,
		"a non-command stream should fall through to the app handler"
	);
}

#[tokio::test]
async fn quiesce_completes_topics_and_refuses_new_work() {
	let (registry, mut peer) = subscribed("sub/prices").await;

	let signaled = quiesced(&registry);
	assert_eq!(signaled, 1, "the one subscriber should be signaled");

	let end = peer.next_update().await;
	assert_eq!(end.metadata.id, b"end/prices", "quiesce should complete the topic");

	let refused = peer.request("sub/chat").await;
	assert_eq!(
		refusal(refused),
		TransportFailure::Unavailable,
		"a draining registry should answer Unavailable"
	);
	assert!(
		matches!(registry.publish(&topic("prices"), b"late"), Err(PublishError::Draining)),
		"a draining registry should refuse publishes"
	);
}

#[tokio::test]
async fn slow_consumer_drops_oldest_and_continues() {
	let options = RegistryOptions { queue_capacity: 2, delivery: Arc::new(DropOldest), ..RegistryOptions::default() };
	let registry = TopicRegistry::new(options);

	// Zero permits: the client receives updates but stalls every ack.
	let mut peer = connect(&registry, AllowAll, 0).await;
	peer.granted("sub/prices").await;

	// The first update is in flight (received, unacknowledged) before
	// the burst, so the queue state during the burst is deterministic.
	published(&registry, "prices", b"1");

	let first = peer.next_update().await;
	assert_eq!(first.metadata.order, 1, "the first update should be in flight");

	// Capacity 2: updates 2 and 3 queue, update 4 evicts update 2.
	for payload in [b"2".as_slice(), b"3", b"4"] {
		published(&registry, "prices", payload);
	}

	peer.ack_gate.add_permits(16);

	let after_gap = peer.next_update().await;
	let last = peer.next_update().await;
	assert_eq!(
		[after_gap.metadata.order, last.metadata.order],
		[3, 4],
		"the oldest queued update should be dropped, revealing a gap"
	);
}
