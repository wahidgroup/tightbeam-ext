# The Topic Registry and Its Commands

This page specifies `tightbeam-pubsub`, topic membership and publish fan-out over the tightbeam mux:

- topic names and their validation
- the registry, its options, and its publish calls
- the delivery policy of a full queue
- the subscribe and publish policies
- the command dispatcher and the serve of one connection
- the emitter of a link
- the drain of a registry
- the backplane and its contract
- the command convention that the TypeScript client answers
- the `testing` feature

It drills down from the [tightbeam-pubsub README](../pubsub/tightbeam-pubsub/README.md) for engineers who build on the registry or review it. The README holds what each part is for and the standards it follows. The client half has its own page, [The Subscription Client](pubsub-client.md). Every Rust sample on this page compiles as a doctest of `tightbeam-pubsub`, and the TypeScript sample compiles in [`pubsub/client/src/docs.test.ts`](../pubsub/client/src/docs.test.ts), which reads it from this page.

## Contents

- [Topics](#topics)
- [Registry](#registry)
- [Delivery policy](#delivery-policy)
- [Access policies](#access-policies)
- [Connection serve](#connection-serve)
- [Emitter](#emitter)
- [Drain](#drain)
- [Backplane](#backplane)
- [Command convention](#command-convention)
- [Testing](#testing)
- [Sources](#sources)

## Topics

A `Topic` is a validated name with exact-match semantics: no wildcards and no shared subscriptions. A name MAY carry a `/`-separated hierarchy by convention, and the parse reads no segment. The parse admits a name under these rules:

| Rule                                                 | `TopicError` on a break |
| ---------------------------------------------------- | ----------------------- |
| The octets are UTF-8                                 | `NotUtf8`               |
| The name is not empty                                | `Empty`                 |
| The name holds at most `Topic::MAX_LEN` (256) octets | `TooLong`               |
| The name starts with no reserved command prefix      | `ReservedPrefix`        |

```rust
use tightbeam_pubsub::Topic;

assert_eq!(Topic::MAX_LEN, 256);
```

The reserved prefixes are `SUB_PREFIX` (`sub/`), `UNSUB_PREFIX` (`unsub/`), `PUB_PREFIX` (`pub/`), and `END_PREFIX` (`end/`), so the id of every update differs from the id of every command. `MAX_LEN` bounds the memory that one name holds, because the registry keeps each subscribed name and the backplane keeps a counter for each published name. A `Topic` clones cheaply, because its inner string sits behind an `Arc`.

## Registry

`TopicRegistry` owns membership and publishing. It builds every update frame itself, so no stamp depends on a caller:

- `publish(&topic, payload)` wraps the bytes in an update frame. It stamps the topic into `metadata.id` and a dense sequence for the topic into `metadata.order`, and it resolves once the backplane answered.
- `publish_frame(&topic, &frame)` relays a full tightbeam frame with its bytes unchanged as the payload. The signatures, commitments, encryption, and compression that a publisher applied hold end to end, because the registry carries the inner frame as opaque bytes. The TypeScript client decodes such a payload with the `framed` codec of its engine.
- `OpaqueFrame` builds one frame of the profile: an `Opaque` body under an id and an order. A topic update, an `end/<topic>` completion, and each client command all take this shape, and the body matches the opaque profile of the TypeScript client.

`RegistryOptions` bounds what one connection holds. Each count is a `NonZeroUsize`:

| Field                              | Default                               | Bounds                                                                                                                                                                         |
| ---------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `queue_capacity`                   | 32                                    | The updates queued for one subscription                                                                                                                                        |
| `max_subscriptions_per_connection` | 64                                    | The live subscriptions of one connection. A repeat `sub/` of a held topic keeps its one count                                                                                  |
| `connection_queue_bytes`           | `MAX_MUX_CONNECTION_REASSEMBLY_BYTES` | The payload octets queued or in flight across every subscription of one connection. An update that does not fit counts as a full queue                                         |
| `emit_deadline`                    | 30 s                                  | How long one emit of a connection may take, on the clock of its link: each update, and each emit through `ConnectionContext::emitter`. An update past it expels its connection |
| `delivery`                         | `DropOldest`                          | The [delivery policy](#delivery-policy) of a full queue                                                                                                                        |
| `backplane`                        | `Local`                               | Sequencing and distribution ([Backplane](#backplane))                                                                                                                          |

```rust
use std::time::Duration;

use tightbeam::constants::MAX_MUX_CONNECTION_REASSEMBLY_BYTES;
use tightbeam_pubsub::{EmitDeadline, RegistryOptions};

let options = RegistryOptions::default();
assert_eq!(options.queue_capacity.get(), 32);
assert_eq!(options.max_subscriptions_per_connection.get(), 64);
assert_eq!(options.connection_queue_bytes.get(), MAX_MUX_CONNECTION_REASSEMBLY_BYTES);
assert_eq!(Some(options.emit_deadline), EmitDeadline::new(Duration::from_secs(30)));
```

A subscription arrives only as a `sub/` command, so its refusals are the answers of the [command convention](#command-convention). A publish fails with a `PublishError`:

| Error                       | Cause                                                                             |
| --------------------------- | --------------------------------------------------------------------------------- |
| `PublishError::Draining`    | The registry is draining, or every node that answered drains                      |
| `PublishError::Build`       | The update frame failed to build                                                  |
| `PublishError::TopicLimit`  | The topic is new, and the backplane has no room for its counter                   |
| `PublishError::Unavailable` | The distribution fabric of a multi-node backplane failed, with a `BackplaneFault` |

```rust
# use tightbeam::Frame;
# use tightbeam_pubsub::{Topic, TopicRegistry};
# async fn publish(registry: &TopicRegistry, payload: &[u8], signed_frame: Frame) -> Result<(), Box<dyn std::error::Error>> {
let topic: Topic = "prices/spot".parse()?;

// Bytes: the registry wraps them in an update frame, stamping the topic
// into `metadata.id` and a dense per-topic sequence into `metadata.order`.
registry.publish(&topic, payload).await?;

// Frame in frame: a full tightbeam frame relays byte-for-byte as the
// payload. Publisher-applied signatures, commitments, encryption, and
// compression survive end to end (the TS client decodes with `engine.framed`),
// and the registry carries the inner frame as opaque bytes.
registry.publish_frame(&topic, &signed_frame).await?;
# Ok(())
# }
```

## Delivery policy

A full queue, or a full byte budget of the connection, is the one backpressure signal of the registry. A `DeliveryPolicy` decides the fate of an update that does not fit. Its `on_full(registry, topic, dropped_so_far)` answers a `DeliveryVerdict`:

| Verdict      | Effect                                                             |
| ------------ | ------------------------------------------------------------------ |
| `DropOldest` | Drop the oldest queued update to make room for the new one         |
| `DropNew`    | Drop the new update and keep the queue as it is                    |
| `Disconnect` | Drop the whole connection of the subscriber, which cannot catch up |

- The `DropOldest` policy is the default, and it always answers `DropOldest`. It evicts one queued update, and when that frees too little of the byte budget, the new update drops as with `DropNew`. The registry counts each drop.
- The fan-out of a topic offers each update to the queue of each subscriber and goes on, so a slow client holds back only its own queue.
- Every drop is a gap at the gate of the client ([The Subscription Client](pubsub-client.md#ordering-and-gaps)).
- The registry asks with no registry lock held, during a delivery of its backplane. It lends a `RegistryView` for the reads that a verdict weighs, and the view reaches no backplane.

## Access policies

A `SubscribePolicy` owns the `PermissionDenied` decision for a `sub/` command, and a `PublishPolicy` owns it for a `pub/` command. Each exposes `authorize(registry, session, &Topic)` and answers an `AccessVerdict`, `Allow` or `Forbid`, and `Forbid` answers `PermissionDenied`.

- `session` names the peer that the handshake of the connection proved. A mutual-auth peer carries its validated certificate, through `SessionContext::peer_certificate`, and an anonymous peer carries none.
- Every policy callback borrows a `RegistryView` for its reads, and no policy holds the registry.
- `AllowAll` implements both traits and allows every subscription and every publish.
- `PubsubCommands::new(registry, policy)` takes the subscribe policy. Client publish is off until `with_publish(policy)` installs a publish policy. Without one, a `pub/` frame falls through to the application like any other unary stream.

```rust
# use tightbeam::policy::SessionContext;
# use tightbeam_pubsub::{AccessVerdict, AllowAll, PubsubCommands, RegistryView, SubscribePolicy, Topic, TopicRegistry};
struct DenySecrets;

impl SubscribePolicy for DenySecrets {
	fn authorize(&self, _registry: RegistryView<'_>, _session: &SessionContext, topic: &Topic) -> AccessVerdict {
		if topic.as_str().starts_with("secrets/") {
			return AccessVerdict::Forbid;
		}

		AccessVerdict::Allow
	}
}

# let registry = TopicRegistry::default();
// Client publish is opt-in. Without `with_publish`, `pub/` frames fall
// through to the application like any other unary stream.
let commands = PubsubCommands::new(registry, DenySecrets).with_publish(AllowAll);
```

## Connection serve

`PubsubCommands` answers the client commands inside a serve handler, and every other unary stream falls through to the routes of the application. A streaming or duplex stream answers `Unimplemented`. `PubsubCommands::serve(link, routes)` runs the whole ceremony of one connection over a `tightbeam_ws::serve::AcceptedLink` ([The WebSocket Transport](ws.md#accepted-links)): the mux, the drivers, the keepalive, the transport gate, the registration, the dispatch, and the cleanup.

- `AcceptedLink::accepted` takes a transport whose server handshake completed. It keeps the transport gate, the peer that the handshake proved, and the in-band rekey context of a metered session. The connection registers under that peer.
- A link whose writer clock cannot race a wait on the runtime fails with `LinkError::ClockCannotRace`, because its emit deadlines and its keepalive could not run.
- Any other link that must outlive the read deadline of a quiet session runs `MuxHandle::keep_alive`.
- `routes` is an `AppRoutes` handler: every `async fn(ConnectionContext, Arc<Frame>) -> ResponsePackage`, and every closure of that shape. `Unrouted` serves a command-only connection, so every stream that no command claims answers `Unimplemented`.
- `ConnectionContext` names the served connection: its emitter (`emitter`), and its standing (`session`). `session` answers the peer that the handshake proved while the registry holds the connection, and `None` once the connection left or was expelled, as the commands read it. Only the serve builds a context, so a context always belongs to the registry that admitted its connection.

Under the `instrument` feature, each served connection records its audit trail in `tightbeam_pubsub::events`:

- The trail records on the trace of the transport that its link was accepted on (`ServedMux::trace`), beside the gate verdict of each call. A transport with no trace, or a build without the feature, records nothing.
- The trail records decisions alone, and no event for each update, so a publish to many subscribers leaves the gate verdicts and the handshakes in a bounded trace.
- A build of tightbeam without its `testing` feature keeps the label of each event and drops its value, so the label carries what the event names, and the value repeats it for the spec of a scenario.

| Event                 | Recorded when                                                                                                                                     | Label                                                            | Value                                         |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------- |
| `CONNECTION_ADMITTED` | The registry admits the connection                                                                                                                | The number the registry admits it under                          | The same number                               |
| `CONNECTION_LEFT`     | The connection leaves, because its serve ended or it was expelled                                                                                 | The number the registry admitted it under                        | The count of subscriptions it held            |
| `CONNECTION_EXPELLED` | The registry expels the connection for a cause that [`events.rs`](../pubsub/tightbeam-pubsub/src/events.rs) lists, ahead of its `CONNECTION_LEFT` | The name of its GoAway reason, `enhance-your-calm` or `shutdown` | The same name                                 |
| `COMMAND_REFUSED`     | A command takes no effect                                                                                                                         | The command and the status, such as `sub PermissionDenied`       | The status it answers                         |
| `UPDATE_DROPPED`      | The delivery policy drops an update of a full queue, or the peer or the session budget refuses one                                                | The topic                                                        | The count of drops of the subscription so far |

The registry records each departure once it released its lock, so no sink of the trail runs under the lock.

```rust
# use std::sync::Arc;
# use tightbeam::policy::TransitStatus;
# use tightbeam::transport::multiplex::MuxAcceptor;
# use tightbeam::transport::ResponsePackage;
# use tightbeam::Frame;
# use tightbeam_pubsub::{AllowAll, ConnectionContext, PubsubCommands, SubscribePolicy, TopicRegistry};
# use tightbeam_ws::serve::AcceptedLink;
# async fn application_routes(_context: ConnectionContext, _frame: Arc<Frame>) -> ResponsePackage {
# 	ResponsePackage::new(TransitStatus::NotFound, None)
# }
# async fn serve<T>(registry: TopicRegistry, policy: impl SubscribePolicy + 'static, mut transport: T) -> Result<(), Box<dyn std::error::Error>>
# where
# 	T: MuxAcceptor,
# 	T::EnvelopeReader: Send,
# 	T::EnvelopeWriter: Send,
# {
# transport.negotiate_mux().await?;
let commands = PubsubCommands::new(registry, policy).with_publish(AllowAll);

// One call runs the drivers, the keepalive, the gate, the registration, the
// command dispatch, and the cleanup. The application handler receives every
// unary stream that the commands leave alone.
let link = AcceptedLink::accepted(transport)?;
commands
	.serve(link, move |context, frame| application_routes(context, frame))
	.await?;
# Ok(())
# }
```

## Emitter

`Emitter` owns the `MuxHandle` of one link, the clock of its writer, and an `EmitDeadline`. It sorts each failed `MuxHandle::emit_on_stream` once, by what the failure costs the link. The registry emits through it, and an application emits beside it through `ConnectionContext::emitter`, under the `emit_deadline` of the registry.

- `Emitter::served(&served, deadline)` builds the emitter of a served connection on `ServedMux::clock`, the clock of its writer.
- `Emitter::new(handle, clock, deadline)` builds the emitter of a dialed link on `clock`, the `RacingClock` of its writer half.
- `EmitDeadline::new(span)` refuses a zero span. The default is the operation timeout of a tightbeam session, 30 s.

```rust
use std::time::Duration;

use tightbeam::constants::DEFAULT_OPERATION_TIMEOUT;
use tightbeam_pubsub::EmitDeadline;

assert_eq!(DEFAULT_OPERATION_TIMEOUT, Duration::from_secs(30));
assert_eq!(EmitDeadline::new(DEFAULT_OPERATION_TIMEOUT), Some(EmitDeadline::default()));
```

`Emitter::until_settled(&frame)` emits until the emit settles, and it waits out a full stream cap inside the same deadline. It answers one of three outcomes:

- `Settled::Answered(Option<Box<Frame>>)`: the peer accepted the frame, with the frame it answered, if any.
- `Settled::Refused(TransportError)`: only this frame is lost, because the peer answered with a refusal or the session budget cannot carry the frame until a renewal restores it. The link stays up.
- `LinkLost`: the error of an emit that counts as the end of the link. An emit past its deadline counts so, as a peer that never answers does.

## Drain

`TopicRegistry::drain` runs the drain of a registry as a saga of acts:

1. Refuse new subscriptions and publishes, and freeze the topic set.
2. Build the `end/<topic>` of every topic at its `Backplane::last_order`, so a drain burns no order and the other nodes on the backplane keep a dense sequence.
3. Queue each `end/<topic>` behind every update that its subscribers hold. From here the drain only goes forward.
4. Wait until every lane is empty, so every `end/<topic>` left. Every waiter wakes, and each emit runs under the emit deadline, so the wait ends.
5. Dismiss every served connection with a `Shutdown` GoAway. A connection admitted after step 3 is dismissed at its admission.

- An `end/<topic>` that fails to encode cancels the drain at step 2, so the registry takes subscriptions and publishes again. The failure is the signature of upstream `FrameBuilder::build`, and an end frame of a valid topic builds.
- A drain that meets another in flight waits for its outcome.
- A repeat, or a drain whose future dropped during step 4, completes nothing and runs steps 4 and 5 again.
- `Drained` reports the subscriptions that the drain completed and the connections that it dismissed.

```rust
# use tightbeam_pubsub::{Drained, TopicRegistry};
# async fn shut_down(registry: &TopicRegistry) -> Result<Drained, Box<dyn std::error::Error>> {
// end/<topic> everywhere, every push out, then a Shutdown GoAway per connection.
let drained = registry.drain().await?;
# Ok(drained)
# }
```

## Backplane

The registry owns local fan-out: the lanes, the queues, and the delivery policies. It delegates two decisions to its `Backplane`: who assigns the dense order of a topic, and how a publish reaches other nodes. `Local` answers both in process, and it is the default. A backplane reaches each registry through the `NodeSink` that it is attached, which holds no ownership of the registry, so a dropped registry leaves distribution on its own.

Every backplane meets this contract:

- Orders are dense (`1, 2, 3, ...`) for each topic across every node, because the client gate reads a hole as message loss. Redis `INCR` and `XADD` qualify. A raw Postgres sequence does not, because a rollback leaves a hole, so a locked counter row serves instead.
- Deliveries of one topic reach each node one at a time, in order, because the registry relies on arrival order that matches stamp order. `Local` holds the turn of the topic across its delivery, and a remote implementation gets the same from a single consumer task.
- Every attached node that does not drain observes every accepted update, the own updates of the publishing node included. A `DeliverError::Draining` refusal means that the node is leaving, so the publish stands when another node accepted. A `DeliverError::Build` refusal fails the publish.
- The order stamp burns when at least one node accepted. A publish that every node refuses leaves the counter as it was, so no subscriber sees a gap for an update that no node fanned out.
- `Backplane::last_order` answers the order of the last accepted update of a topic.
- The counter of a topic leaves only while no attached node has a member of that topic (`NodeSink::has_members`). The next publish then restarts the topic at 1, which every client reads as fresh.
- `Backplane::publish` resolves with its outcome once every node answered, in the one `PublishError` set that the registry answers with, so each refusal reaches the publisher. A multi-node backplane reports a fault of its fabric as `PublishError::Unavailable` with a `BackplaneFault`.
- A publish whose update no node can build fails with `PublishError::Build` and burns no order.

`testing::BackplaneConformance` checks seven clauses of the contract against real registries, each on a fresh fabric with one backplane for each node:

- Orders are dense across nodes.
- Racing publishes reach every node in order.
- A draining node leaves the others dense.
- A refusal everywhere burns no order.
- An update that no node builds fails and burns no order.
- A counter with a live member stays.
- The last order is the last delivered.

Three facts of the contract stay with the tests of each driver: a `DeliverError::Build` refusal that fails a publish that another node accepted, the restart at order 1 of a topic whose counter left, and a fault of the fabric that answers `PublishError::Unavailable`.

The registry reports each topic that loses its last local member in one of two ways:

- `Backplane::vacated`, called with no registry lock held and outside every delivery. A backplane that wraps `Local` passes the report on.
- `Delivered::into_vacated`, the answer of `NodeSink::deliver` for the topics that a delivery itself vacated, when its delivery policy expelled a connection.

`Local` counts at most 65,536 topics (`DEFAULT_MAX_TOPICS`), and `Local::with_max_topics` sets another limit. A publish to a new topic at the limit evicts the counter of a topic with no member on any attached sink and no publish in flight, and that topic restarts at order 1:

1. The candidates are the new counters, the counted topics that the registry reports in either way above, the free topics that a sweep found beside the one it took, and an evicted counter that a refused publish restores. Each candidate costs at most one question for each sink.
2. When no candidate is free, a sweep asks about every counted topic, so a member that left with no report frees its counter too. A sweep runs at the first publish after as many refusals as there are counted topics, so it asks each sink at most one question per refusal before it.
3. When every counted topic has a member, the publish fails with `PublishError::TopicLimit`.

The stamp of the publish evicts the counter in the lock section that found it free, so a racing publish of the evicted topic counts from 1. A publish that every node refuses restores the counter, unless a publish counted its topic again. A delivery that unwinds inside a node, such as through a panic of its delivery policy, still settles its publish, and the order burns, because that node may have queued the update. The registry expels each connection as its vote lands, so a connection that the policy voted off before the unwind leaves, and the sweep of step 2 frees the topics it vacated.

One shared `Local` spans the registries of one process. An implementation over Redis, Postgres, or NATS spans machines under the same contract, and it swaps in through `RegistryOptions` with no change to the encoded frames or the TypeScript client. Egress to other channels, such as web push, email, or SNS, attaches as another consumer of the same bus, beside the registry.

```rust
# use std::sync::Arc;
# use tightbeam_pubsub::{Backplane, Local, RegistryOptions, TopicRegistry};
let backplane: Arc<dyn Backplane> = Arc::new(Local::default());

// Every node hands the same backplane to its registry: a publish on any
// node reaches subscribers on all of them with one dense stamp.
let registry = TopicRegistry::new(RegistryOptions {
	backplane: Arc::clone(&backplane),
	..RegistryOptions::default()
});
```

## Command convention

The convention adds no transport protocol and no broker. A subscription is an ordinary command stream that the client initiates, and an update is a push that the server initiates. Any carrier of the tightbeam mux therefore carries it, WebSocket or raw TCP. A topic name travels in `Frame.metadata.id` as UTF-8 bytes, and each answer is a `TransitStatus` from the gRPC canonical registry.

| Direction        | Frame id        | Meaning                                                      | Answer                                                                                                 |
| ---------------- | --------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| Client to server | `sub/<topic>`   | Subscribe                                                    | `Ok`, or `PermissionDenied`, `Unavailable`, `ResourceExhausted`, or `InvalidArgument`                  |
| Client to server | `unsub/<topic>` | Unsubscribe. A repeat or unknown topic still answers `Ok`    | `Ok`, or `InvalidArgument` for a name that is no topic                                                 |
| Client to server | `pub/<topic>`   | Publish the body payload, once a publish policy is installed | `Ok`, or `PermissionDenied`, `Unavailable`, `ResourceExhausted`, `InvalidArgument`, or `Internal`      |
| Server to client | `<topic>`       | Update: the payload in the body, the sequence in `order`     | `Ok`, or `ResourceExhausted`, `Unimplemented`, or `Unknown`. The server counts each refusal as a drop  |
| Server to client | `end/<topic>`   | Completion, at a drain                                       | `Ok`, or the answer of the fallback, `Unimplemented` by default, for a topic with no live subscription |

The answer of an `unsub/` leaves once the delivery task of the subscription has ended, so no update of that subscription follows the answer on the connection.

A command meets each refusal for one cause:

| Answer              | Cause                                                                                                                |
| ------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `InvalidArgument`   | The name after the prefix is no topic, or the body of a `pub/` is no opaque body                                     |
| `PermissionDenied`  | The policy forbids the topic, or the connection has no standing because it dropped or the registry never admitted it |
| `Unavailable`       | The registry is draining, or the fabric of the backplane failed                                                      |
| `ResourceExhausted` | The connection holds its subscription limit, or the backplane holds its topic limit                                  |
| `Internal`          | The update frame of an authorized publish failed to build                                                            |

Both sides dispatch on the same prefixes. The TypeScript client reads them from the JSON that [`examples/wire_contract.rs`](../pubsub/tightbeam-pubsub/examples/wire_contract.rs) renders, so each value has one home:

- `topicMaxLen`: `Topic::MAX_LEN`, the longest topic name in UTF-8 octets.
- `prefixes`: the command prefix of each verb, keyed `subscribe`, `unsubscribe`, `publish`, and `end`.
- `samples`: sample topic names, each with the `TopicError` code that refuses it or `null`. The Rust and the TypeScript suites grade both validations against them.

`make -C pubsub client` renders that JSON into `pubsub/client/src/wire.generated.json` before it compiles the client.

The TypeScript client answers the same rows, one route each:

```ts
const manager = new SubscriptionManager(ClientPorts.split(client), {
	// Non-topic server pushes. Unmatched ids answer Unimplemented.
	fallback: async (update) => handleAppStream(update),
});

// Registers the topic route, then emits `sub/prices`.
const prices = await manager.subscribe("prices", { codec: engine.opaque });
for await (const { message, frame } of prices) {
	render(message, frame.order);
}

await manager.publish("prices", payload, { codec: engine.opaque }); // emits `pub/prices`
await manager.unsubscribe("prices"); // emits `unsub/prices`
```

## Testing

The `testing` feature holds the support for tests over loopback WebSocket links:

- `Loopback`, one cleartext WebSocket connection on loopback, through the real listener, dial, and `AcceptedLink::cleartext` of `tightbeam-ws`. The server end dials, so it runs on the clock of its `Dial`.
- `Dial`, the multiplexing settings of both ends, the clock of the server end, and the trace that both transports record on.
- `Peer`, one client of a registry over a `Loopback`. It sends commands, reads each update before its ack, and reads the GoAway of the server. A `Peer` from `connect` acks each update as it arrives, and one from `stalled` holds each ack until `grant` frees it. The open of a `Loopback` and each command of a `Peer` wait at most the patience of the kit on the system clock, and a lapse answers the transport failure `DeadlineExceeded`, or `FailedPrecondition` on a thread with no timer.
- `BackplaneConformance`, the clauses of the [backplane](#backplane) contract that the kit checks, as one check. It builds a fresh `Fabric` for each clause, under a topic limit, and answers the first `BackplaneBreach` that the driver commits. A publish that answers other than the `Refusal` that a clause places answers `BackplaneBreach::Answered`. A step that a clause waits for past the patience of the check on the system clock, such as a join, a publish, a drain, or a read, answers `BackplaneBreach::Lapsed`, which names the clause, the step, and the `Lapse` of the bound.

The unit tests of the crate and of its examples run over `Loopback`. `Local` passes `BackplaneConformance`, and so do two fabrics of the `RelayBackplane` of the demo server: a relay for each node, and one relay that every node shares, whose one worker carries every topic. Scenarios of `Local` race a publish against a held eviction, run a sweep beside a publish in flight, and unwind a delivery through a delivery policy that votes one member off and panics at the next. The integration tests run as tightbeam scenarios over `Peer` links, so each spec grades the audit trail of the registry under the `instrument` feature, and the GoAway that the transports of the run record. The scenarios of the peer that a connection registers under dial over a real handshake.

The example `pubsub_demo_server` is the server that the dockerized end-to-end suite drives:

- It forbids every subscribe and every publish under `forbidden/`, so the suite reads `PermissionDenied`.
- Its `poke` command pushes one `notice` stream back, which reaches the fallback of the manager.
- With `PUBSUB_PROCESSOR_ENDPOINT` set, it relays every publish through the `pubsub_processor_server` servlet, which uppercases the text of each JSON note and seals the rebuilt frame under the topic key.

## Sources

- MQTT 5.0, § 4.7 Topic Names and Topic Filters, and § 3.11 UNSUBACK: <https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html>
- RFC 6455, The WebSocket Protocol, § 5.5.1 Close, the analog of an orderly closure: <https://datatracker.ietf.org/doc/html/rfc6455#section-5.5.1>
- `google.rpc.Code`, the gRPC canonical status codes: <https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto>
