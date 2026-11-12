//! Integration coverage over public interfaces, as tightbeam scenarios over
//! loopback peers. The page `docs/pubsub.md` (Testing) states what each spec
//! grades.

mod support;

use core::num::NonZeroUsize;
use std::sync::Arc;

use der::{Decode, Encode};
use support::DEADLINE;
use tightbeam::clock::{Clock, ManualClock};
use tightbeam::instrumentation::events;
use tightbeam::policy::{SessionContext, TransitStatus};
use tightbeam::testing::{ScenarioConfig, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::transport::error::{TransportError, TransportFailure};
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario, Frame, Opaque, TightBeamError};
use tightbeam_pubsub::events::{
	COMMAND_REFUSED, CONNECTION_ADMITTED, CONNECTION_EXPELLED, CONNECTION_LEFT, UPDATE_DROPPED,
};
use tightbeam_pubsub::testing::{Dial, Peer};
use tightbeam_pubsub::{
	AccessVerdict, AllowAll, Backplane, DeliveryPolicy, DeliveryVerdict, Drained, DropOldest, EmitDeadline, Local,
	OpaqueFrame, PublishError, PubsubCommands, RegistryOptions, RegistryView, SubscribePolicy, Topic, TopicRegistry,
};
use tightbeam_ws::testing::{EventWatch, ReadOutcome};
use tokio::time::{timeout, Duration};

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

/// The commands of `registry` under `policy`, with client publish on, as the
/// demo server builds them.
fn commands<P: SubscribePolicy + 'static>(registry: &TopicRegistry, policy: P) -> PubsubCommands<P> {
	PubsubCommands::new(registry.clone(), policy).with_publish(AllowAll)
}

/// A peer of `registry` under `policy` that acks each update at once, on a
/// link whose transports record on `trace`.
async fn connected<P: SubscribePolicy + 'static>(
	registry: &TopicRegistry,
	policy: P,
	trace: &TraceCollector,
) -> Result<Peer, TightBeamError> {
	Peer::connect(&commands(registry, policy), &Dial::traced(trace)).await
}

/// A peer of `registry` that holds every ack, on a link whose transports
/// record on `trace`.
async fn stalled(registry: &TopicRegistry, trace: &TraceCollector) -> Result<Peer, TightBeamError> {
	Peer::stalled(&commands(registry, AllowAll), &Dial::traced(trace)).await
}

/// Emit one command stream, expecting the server to accept it.
async fn granted(peer: &Peer, id: &str) {
	peer.request(id, b"").await.expect("the command should be accepted");
}

/// The next update of `peer`, within the deadline.
async fn next_update(peer: &mut Peer) -> Arc<Frame> {
	timeout(DEADLINE, peer.next_update())
		.await
		.expect("an update should arrive within the deadline")
		.expect("the update channel should stay open")
}

/// The reason of the GoAway that `peer` reads, within the deadline.
async fn goaway(peer: &Peer) -> Option<GoAwayReason> {
	timeout(DEADLINE, peer.goaway()).await.ok().flatten()
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
	let peer = connected(&registry, AllowAll, trace).await?;
	granted(&peer, name).await;
	Ok((registry, peer))
}

/// Publish `payload` to `name` through `registry`, expecting acceptance.
async fn published(registry: &TopicRegistry, name: &str, payload: &[u8]) {
	let topic: Topic = name.parse().expect("the name should be a topic");
	let outcome = registry.publish(&topic, payload).await;
	outcome.expect("the publish should be accepted");
}

/// Publish a full frame to `name` through `registry`, expecting acceptance.
async fn published_frame(registry: &TopicRegistry, name: &str, inner: &Frame) {
	let outcome = registry
		.publish_frame(&name.parse::<Topic>().expect("the name should be a topic"), inner)
		.await;
	outcome.expect("the frame publish should be accepted");
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

/// Drain `registry`, expecting every end frame to build.
async fn drained(registry: &TopicRegistry) -> Drained {
	registry.drain().await.expect("every end frame should build")
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
fn refusal(outcome: Result<Option<Frame>, TightBeamError>) -> TransportFailure {
	match outcome {
		Err(TightBeamError::TransportError(TransportError::OperationFailed(failure))) => failure,
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
			let mut peer = connected(&registry, AllowAll, &trace).await?;

			let subscribed = peer.request("sub/prices", b"").await;
			assert!(subscribed.is_ok(), "the sub/ command should be accepted: {subscribed:?}");

			for payload in [b"one".as_slice(), b"two", b"three"] {
				published(&registry, "prices", payload).await;
			}

			for (order, payload) in [(1, b"one".as_slice()), (2, b"two"), (3, b"three")] {
				let update = next_update(&mut peer).await;
				expect_update(&update, b"prices", order, payload);
			}

			let unsubscribed = peer.request("unsub/prices", b"").await;
			assert!(unsubscribed.is_ok(), "the unsub/ command should be accepted: {unsubscribed:?}");

			let subscribers = registry.view().subscriber_count(&"prices".parse::<Topic>().expect("the name should be a topic"));
			assert_eq!(subscribers, 0, "an unsubscribe should leave the topic with no subscriber");
			published(&registry, "prices", b"four").await;
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

// A `pub/` command of one peer reaches the subscriber on another.
tb_scenario! {
	name: a_publish_command_reaches_every_subscriber,
	spec: OneUpdateTwoPeersSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (registry, mut subscriber) = subscribed("sub/prices", &trace).await?;
			let publisher = connected(&registry, AllowAll, &trace).await?;

			let outcome = publisher.request("pub/prices", b"tick").await;
			assert!(outcome.is_ok(), "the pub/ command should be accepted: {outcome:?}");

			let update = next_update(&mut subscriber).await;
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
			published_frame(&registry, "orders", &inner).await;

			let update = next_update(&mut peer).await;
			expect_update(&update, b"orders", 1, &der_of(&inner));

			let application = frame_of(&payload_of(&update));
			assert_eq!(application.metadata().id(), b"order-42", "the inner id should stay the application's");
			assert_eq!(application.metadata().order(), 7, "the inner order should stay the application's");
			Ok(())
		}
	}
}

// A `pub/` command whose payload is a frame relays its DER to the subscriber
// unchanged.
tb_scenario! {
	name: a_publish_command_relays_a_frame_payload,
	spec: OneUpdateTwoPeersSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (registry, mut subscriber) = subscribed("sub/orders", &trace).await?;
			let publisher = connected(&registry, AllowAll, &trace).await?;

			let inner_der = der_of(&inner_frame("order-42", 7, b"fill"));
			publisher.request("pub/orders", &inner_der).await.expect("the command should be accepted");

			let update = next_update(&mut subscriber).await;
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
			let mut second = connected(&registry, AllowAll, &trace).await?;
			granted(&second, "sub/prices").await;

			published(&registry, "prices", b"tick").await;

			for peer in [&mut first, &mut second] {
				let update = next_update(peer).await;
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

	let on_a = connected(&node_a, AllowAll, trace).await?;
	let on_b = connected(&node_b, AllowAll, trace).await?;
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
			granted(&on_a, "sub/prices").await;
			granted(&on_b, "sub/prices").await;

			published(&node_a, "prices", b"tick").await;

			for peer in [&mut on_a, &mut on_b] {
				let update = next_update(peer).await;
				expect_update(&update, b"prices", 1, b"tick");
			}
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub DrainedNodeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(UPDATE_DROPPED, exactly!(0))
		]
	}
}

// A drained node completes its topics with `end/`, and the sibling node
// keeps serving dense orders across it, with no update dropped.
tb_scenario! {
	name: draining_one_node_leaves_the_backplane_live,
	spec: DrainedNodeSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (node_a, node_b, mut on_a, mut on_b) = two_nodes(&trace).await?;
			granted(&on_a, "sub/prices").await;
			granted(&on_b, "sub/prices").await;
			published(&node_a, "prices", b"tick").await;
			next_update(&mut on_a).await;
			next_update(&mut on_b).await;

			drained(&node_a).await;

			let end = next_update(&mut on_a).await;
			assert_eq!(end.metadata().id(), b"end/prices", "the drained node should complete its topics");
			assert_eq!(end.metadata().order(), 1, "end/ carries the last committed order");

			published(&node_b, "prices", b"tock").await;

			let update = next_update(&mut on_b).await;
			assert_eq!(update.metadata().order(), 2, "the live node should see dense orders across the sibling's drain");
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
			let peer = connected(&registry, DenyForbidden, &trace).await?;

			let refused = refusal(peer.request("sub/forbidden/keys", b"").await);
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
			let peer = connected(&registry, DenyForbidden, &trace).await?;

			let refused = refusal(peer.request("sub/", b"").await);
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
			let peer = connected(&registry, DenyForbidden, &trace).await?;

			let refused = refusal(peer.request("no-such-command", b"").await);
			assert_eq!(refused, TransportFailure::Unimplemented, "a non-command stream should fall through to the app handler");
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
			let mut peer = stalled(&registry, &trace).await?;
			granted(&peer, "sub/prices").await;

			// The first update is in flight (received, unacknowledged) before
			// the burst, so the queue state during the burst is deterministic.
			published(&registry, "prices", b"1").await;

			let first = next_update(&mut peer).await;
			assert_eq!(first.metadata().order(), 1, "the first update should be in flight");

			// Capacity 2: updates 2 and 3 queue, update 4 evicts update 2.
			for payload in [b"2".as_slice(), b"3", b"4"] {
				published(&registry, "prices", payload).await;
			}

			peer.grant(16);

			let after_gap = next_update(&mut peer).await;
			let last = next_update(&mut peer).await;
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

// A dropped serve takes its connection out of the registry with the one
// subscription it held, and only then does the client read the closed link.
tb_scenario! {
	name: a_dropped_serve_leaves_no_registration_and_ends_its_link,
	config: ScenarioConfig::builder().with_spec(DroppedServeSpec::latest()).with_csp(DroppedServeProcess).build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (registry, mut peer) = subscribed("sub/prices", &trace).await?;

			peer.drop_serve().await;

			let after = peer.request("sub/chat", b"").await;
			ReadOutcome::record(&after.map_err(TransportError::from), &trace)?;
			assert_eq!(registry.view().subscriber_count(&"prices".parse::<Topic>().expect("the name should be a topic")), 0, "the dropped serve should leave the registry");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub StreamSlotSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_STREAMS_EXHAUSTED, exactly!(1)),
			(UPDATE_DROPPED, exactly!(0))
		]
	}
}

/// The events of the scenario of a held stream slot.
static SLOT_EVENTS: EventWatch = EventWatch::new();

// On a link of one stream, an update of one topic waits for the slot that
// the in-flight update of another topic holds, and arrives once it frees,
// with no update dropped. The ack frees the slot only after the mux records
// the full cap.
tb_scenario! {
	name: an_update_waits_for_the_stream_slot_another_topic_holds,
	config: ScenarioConfig::builder().with_trace(SLOT_EVENTS.trace()).with_spec(StreamSlotSpec::latest()).build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let registry = TopicRegistry::default();
			let dial = Dial { settings: MuxSettings::symmetric(1), ..Dial::traced(&trace) };
			let mut peer = Peer::stalled(&commands(&registry, AllowAll), &dial).await?;
			granted(&peer, "sub/prices").await;
			granted(&peer, "sub/chat").await;
			published(&registry, "prices", b"tick").await;
			let holding = next_update(&mut peer).await;

			published(&registry, "chat", b"hello").await;
			SLOT_EVENTS.recorded(events::MUX_STREAMS_EXHAUSTED, 1).await?;
			peer.grant(2);

			let waited = next_update(&mut peer).await;
			expect_update(&holding, b"prices", 1, b"tick");
			expect_update(&waited, b"chat", 1, b"hello");
			Ok(())
		}
	}
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
// `EnhanceYourCalm` and leaves the registry, with no update dropped. The peer
// holds every ack, so the third update finds the queue of one full.
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
			let mut peer = stalled(&registry, &trace).await?;
			granted(&peer, "sub/prices").await;

			published(&registry, "prices", b"one").await;
			next_update(&mut peer).await;
			published(&registry, "prices", b"two").await;
			published(&registry, "prices", b"three").await;

			let reason = goaway(&peer).await;
			assert_eq!(reason, Some(GoAwayReason::EnhanceYourCalm));
			assert_eq!(registry.view().subscriber_count(&"prices".parse::<Topic>().expect("the name should be a topic")), 0);
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub LapsedEmitSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CONNECTION_EXPELLED, exactly!(1), equals!("enhance-your-calm")),
			(CONNECTION_LEFT, exactly!(1), equals!(1u64)),
			(events::MUX_GOAWAY_SENT, exactly!(1)),
			(events::MUX_GOAWAY_RECV, exactly!(1))
		]
	}
}

tb_process_spec! {
	/// A connection whose emit runs past the emit deadline, in order: the
	/// registry admits it, expels it, and lets it go, and only then does the
	/// server send the GoAway that the client receives.
	pub LapsedEmitProcess,
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

/// The emit deadline of the scenario that advances a manual clock past it,
/// twice [`DEADLINE`], so only the advance ends the emit within the bound.
const SHORT: Duration = Duration::from_secs(DEADLINE.as_secs() * 2);

// An emit past the emit deadline on the clock of its link expels the whole
// connection with `EnhanceYourCalm`, so the client reads a GoAway.
tb_scenario! {
	name: an_emit_past_the_deadline_expels_its_connection,
	config: ScenarioConfig::builder().with_spec(LapsedEmitSpec::latest()).with_csp(LapsedEmitProcess).build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let clock = Arc::new(ManualClock::default());
			let emit_deadline = EmitDeadline::new(SHORT).expect("the deadline is above zero");
			let registry = TopicRegistry::new(RegistryOptions { emit_deadline, ..RegistryOptions::default() });
			let dial = Dial { clock: Arc::clone(&clock) as Arc<dyn Clock>, ..Dial::traced(&trace) };
			let mut peer = Peer::stalled(&commands(&registry, AllowAll), &dial).await?;
			granted(&peer, "sub/prices").await;
			published(&registry, "prices", b"tick").await;
			next_update(&mut peer).await;

			clock.advance(SHORT + Duration::from_secs(1));

			let reason = goaway(&peer).await;
			assert_eq!(reason, Some(GoAwayReason::EnhanceYourCalm), "a lapsed emit should expel its connection");
			assert_eq!(registry.view().subscriber_count(&"prices".parse::<Topic>().expect("the name should be a topic")), 0);
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub DrainSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COMMAND_REFUSED, exactly!(1), equals!(TransitStatus::Unavailable)),
			(CONNECTION_EXPELLED, exactly!(1), equals!("shutdown")),
			(CONNECTION_LEFT, exactly!(1), equals!(0u64)),
			(events::MUX_GOAWAY_SENT, exactly!(1)),
			(events::MUX_GOAWAY_RECV, exactly!(1)),
			(UPDATE_DROPPED, exactly!(0))
		]
	}
}

tb_process_spec! {
	/// A drained connection, in order: the registry admits it, refuses its
	/// command while the drain waits for its `end/`, dismisses it, and lets
	/// it go, and only then does the server send the GoAway that the client
	/// receives.
	pub DrainProcess,
	events {
		observable {
			CONNECTION_ADMITTED,
			COMMAND_REFUSED,
			CONNECTION_EXPELLED,
			CONNECTION_LEFT,
			events::MUX_GOAWAY_SENT,
			events::MUX_GOAWAY_RECV
		}
		hidden { }
	}
	states {
		Connecting => { CONNECTION_ADMITTED => Serving },
		Serving => { COMMAND_REFUSED => Completing },
		Completing => { CONNECTION_EXPELLED => Dismissed },
		Dismissed => { CONNECTION_LEFT => Departed },
		Departed => { events::MUX_GOAWAY_SENT => Draining },
		Draining => { events::MUX_GOAWAY_RECV => Drained },
		Drained => { }
	}
	terminal { Drained }
}

// A drain completes the topic of its one subscriber and refuses new work
// while that `end/` waits for its ack. Once the subscriber acks the `end/`,
// the drain dismisses the connection with a `Shutdown` GoAway.
tb_scenario! {
	name: a_drain_completes_every_topic_then_dismisses_every_connection,
	config: ScenarioConfig::builder().with_spec(DrainSpec::latest()).with_csp(DrainProcess).build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let registry = TopicRegistry::default();
			let mut peer = stalled(&registry, &trace).await?;
			granted(&peer, "sub/prices").await;

			let draining = registry.clone();
			let drain = tokio::spawn(async move { draining.drain().await });
			let end = next_update(&mut peer).await;
			let refused = refusal(peer.request("sub/chat", b"").await);
			let late = registry.publish(&"prices".parse::<Topic>().expect("the name should be a topic"), b"late").await;
			peer.grant(1);

			let reason = goaway(&peer).await;
			let drained = timeout(DEADLINE, drain).await;
			assert_eq!(end.metadata().id(), b"end/prices", "the drain should complete the topic");
			assert_eq!(refused, TransportFailure::Unavailable, "a draining registry should answer Unavailable");
			assert!(matches!(late, Err(PublishError::Draining)), "a draining registry should refuse publishes");
			assert_eq!(reason, Some(GoAwayReason::Shutdown), "the drain should dismiss the connection");
			assert!(matches!(drained, Ok(Ok(Ok(Drained { completed: 1, dismissed: 1 })))));
			Ok(())
		}
	}
}
