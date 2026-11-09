# The Topic Registry and Wire Convention

This page specifies `tightbeam-pubsub`, topic membership and publish fan-out over the tightbeam mux:

- topic names and their validation
- the registry, its options, and its publish calls
- the delivery policy of a full queue
- the subscribe and publish policies
- the command dispatcher and the serve of one connection
- the emitter of a link
- the drain of a registry
- the backplane and its contract
- the wire convention that the TypeScript client answers
- the `testing` feature

It drills down from the [tightbeam-pubsub README](../pubsub/tightbeam-pubsub/README.md) for engineers who build on the registry or review it. The README holds what each part is for and the standards it follows. The client half has its own page, [The Subscription Client](pubsub-client.md). Every Rust sample on this page compiles as a doctest of `tightbeam-pubsub`, and the TypeScript sample compiles as the case of [`pubsub/client/src/docs.test.ts`](../pubsub/client/src/docs.test.ts) that names its section.

## Contents

- [Topics](#topics)
- [Registry](#registry)
- [Delivery policy](#delivery-policy)
- [Access policies](#access-policies)
- [Connection serve](#connection-serve)
- [Emitter](#emitter)
- [Drain](#drain)
- [Backplane](#backplane)
- [Wire convention](#wire-convention)
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

The reserved prefixes are `SUB_PREFIX` (`sub/`), `UNSUB_PREFIX` (`unsub/`), `PUB_PREFIX` (`pub/`), and `END_PREFIX` (`end/`), so a topic is never mistaken for a command. `MAX_LEN` bounds the memory that one name holds, because the registry keeps each subscribed name and the backplane keeps a counter for each published name. A `Topic` clones cheaply, because its inner string sits behind an `Arc`.

## Registry

`TopicRegistry` owns membership and publishing. It builds every update frame itself, so no stamp depends on a caller:

- `publish(&topic, payload)` wraps the bytes in an update frame. It stamps the topic into `metadata.id` and a dense sequence for the topic into `metadata.order`.
- `publish_frame(&topic, &frame)` relays a full tightbeam frame with its bytes unchanged as the payload. The signatures, commitments, encryption, and compression that a publisher applied hold end to end, because the registry never reads the inner frame. The TypeScript client decodes such a payload with the `framed` codec of its engine.

`RegistryOptions` bounds what one connection holds. Each count is a `NonZeroUsize`:

| Field                              | Default                               | Bounds                                                                                                                                 |
| ---------------------------------- | ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `queue_capacity`                   | 32                                    | The updates queued for one subscription                                                                                                |
| `max_subscriptions_per_connection` | 64                                    | The live subscriptions of one connection. A repeat `sub/` of a held topic does not count again                                         |
| `connection_queue_bytes`           | `MAX_MUX_CONNECTION_REASSEMBLY_BYTES` | The payload octets queued or in flight across every subscription of one connection. An update that does not fit counts as a full queue |
| `emit_deadline`                    | 30 s                                  | How long one update may take to leave, on the clock of the link of the connection. An emit past it ends that subscription              |
| `delivery`                         | `DropOldest`                          | The [delivery policy](#delivery-policy) of a full queue                                                                                |
| `backplane`                        | `Local`                               | Sequencing and distribution ([Backplane](#backplane))                                                                                  |

A registration fails with a `RegisterError`, and a publish with a `PublishError`:

| Error                              | Cause                                                                             |
| ---------------------------------- | --------------------------------------------------------------------------------- |
| `RegisterError::UnknownConnection` | The connection id was never registered, or it already dropped                     |
| `RegisterError::Draining`          | The registry is quiescing, so it takes no new subscription                        |
| `RegisterError::LimitReached`      | The connection already holds `max_subscriptions_per_connection` subscriptions     |
| `PublishError::Draining`           | The registry is quiescing, or every node that answered drains                     |
| `PublishError::Build`              | The update frame failed to build                                                  |
| `PublishError::TopicLimit`         | The topic is new, and the backplane has no room for its counter                   |
| `PublishError::Unavailable`        | The distribution fabric of a multi-node backplane failed, with a `BackplaneFault` |

```rust
# use tightbeam::Frame;
# use tightbeam_pubsub::{Topic, TopicRegistry};
# fn publish(registry: &TopicRegistry, payload: &[u8], signed_frame: Frame) -> Result<(), Box<dyn std::error::Error>> {
let topic: Topic = "prices/spot".parse()?;

// Bytes: the registry wraps them in an update frame, stamping the topic
// into `metadata.id` and a dense per-topic sequence into `metadata.order`.
registry.publish(&topic, payload)?;

// Frame in frame: a full tightbeam frame relays byte-for-byte as the
// payload. Publisher-applied signatures, commitments, encryption, and
// compression survive end to end (the TS client decodes with `engine.framed`),
// and the registry never reads the inner frame.
registry.publish_frame(&topic, &signed_frame)?;
# Ok(())
# }
```

## Delivery policy

The registry has no credit for each subscription, so a full queue, or a full byte budget of the connection, is the only backpressure signal. A `DeliveryPolicy` decides the fate of an update that does not fit. Its `on_full(registry, topic, dropped_so_far)` answers a `DeliveryVerdict`:

| Verdict      | Effect                                                             |
| ------------ | ------------------------------------------------------------------ |
| `DropOldest` | Drop the oldest queued update to make room for the new one         |
| `DropNew`    | Drop the new update and keep the queue as it is                    |
| `Disconnect` | Drop the whole connection of the subscriber, which cannot catch up |

- The `DropOldest` policy is the default, and it always answers `DropOldest`. It evicts one queued update, and when that frees too little of the byte budget, the new update drops as with `DropNew`. The registry counts each drop.
- A slow client never stalls the fan-out of a topic.
- Every drop is a gap at the gate of the client ([The Subscription Client](pubsub-client.md#ordering-and-gaps)).
- The registry asks with no registry lock held, and lends a `RegistryView` for the reads that a verdict weighs. The backplane may still hold its own lock, as `Local` does while it delivers, so a policy MUST NOT publish, quiesce, or make any other call that reaches the backplane.

## Access policies

A `SubscribePolicy` owns the `PermissionDenied` decision for a `sub/` command, and a `PublishPolicy` owns it for a `pub/` command. Each exposes `authorize(registry, session, &Topic)` and answers an `AccessVerdict`, `Allow` or `Forbid`, and `Forbid` answers `PermissionDenied`.

- `session` names the peer that the handshake of the connection proved. A mutual-auth peer carries its validated certificate, through `SessionContext::peer_certificate`, and an anonymous peer carries none.
- Every policy callback borrows a `RegistryView` for its reads, and no policy holds the registry.
- `AllowAll` implements both traits and allows every subscription and every publish.
- `PubsubCommands::new(registry, policy)` takes the subscribe policy. Client publish is off until `with_publish(policy)` installs a publish policy. Without one, a `pub/` frame falls through to the application like any other stream.

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
// through to the application like any other stream.
let commands = PubsubCommands::new(registry, DenySecrets).with_publish(AllowAll);
```

## Connection serve

`PubsubCommands` answers the wire commands inside a serve handler, and every other stream falls through to the routes of the application. `PubsubCommands::serve(link, routes)` runs the whole ceremony of one connection over a `tightbeam_ws::serve::AcceptedLink` ([The WebSocket Transport](ws.md#accepted-links)): the mux, the drivers, the keepalive, the transport gate, the registration, the dispatch, and the cleanup.

- `AcceptedLink::accepted` takes a transport whose server handshake completed. It keeps the transport gate, the peer that the handshake proved, and the in-band rekey context of a metered session. The connection registers under that peer.
- A link whose writer clock cannot race a wait on the runtime fails with `LinkError::ClockCannotRace`, because its emit deadlines and its keepalive could not run.
- Any other link that must outlive the read deadline of a quiet session runs `MuxHandle::keep_alive`.
- `routes` is an `AppRoutes` handler: every `async fn(ConnectionContext, Arc<Frame>) -> ResponsePackage`, and every closure of that shape. `Unrouted` serves a command-only connection, so every stream that no command claims answers `Unimplemented`.
- `ConnectionContext` names the served connection: its registry id (`connection`), its emitter (`emitter`), and the peer its handshake proved (`session`).
- Under the `instrument` feature, each served connection records its audit trail on the trace of the transport that its link was accepted on (`ServedMux::trace`), beside the gate verdict of each call. The trail records decisions alone, never one event per update, so a publish to many subscribers leaves the gate verdicts and the handshakes in a bounded trace. A build of tightbeam without its `testing` feature keeps the label of each event and drops its value, so the label carries what the event names, and the value repeats it for the spec of a scenario. The events live in `tightbeam_pubsub::events`:

| Event                 | Recorded when                                                                                       | Label                                               | Value                                           |
| --------------------- | --------------------------------------------------------------------------------------------------- | --------------------------------------------------- | ----------------------------------------------- |
| `CONNECTION_ADMITTED` | The registry admits the connection                                                                  | The number of its `ConnectionId`                    | The same number                                 |
| `CONNECTION_LEFT`     | The connection leaves, because its serve ended or it was expelled                                   | The number of its `ConnectionId`                    | The count of subscriptions it held              |
| `CONNECTION_EXPELLED` | The delivery policy votes the connection off, ahead of its `CONNECTION_LEFT`                        | The name of its GoAway reason, `enhance-your-calm` | The same name                                   |
| `COMMAND_REFUSED`     | A wire command takes no effect                                                                      | The command and the status, such as `sub PermissionDenied` | The status it answers                    |
| `UPDATE_DROPPED`      | The delivery policy drops an update of a full queue, or the peer or the session budget refuses one | The topic                                           | The count of drops of the subscription so far   |

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
#     ResponsePackage::new(TransitStatus::NotFound, None)
# }
# async fn serve<T>(registry: TopicRegistry, policy: impl SubscribePolicy + 'static, mut transport: T) -> Result<(), Box<dyn std::error::Error>>
# where
#     T: MuxAcceptor,
#     T::EnvelopeReader: Send,
#     T::EnvelopeWriter: Send,
# {
# transport.negotiate_mux().await?;
let commands = PubsubCommands::new(registry, policy).with_publish(AllowAll);

// Drivers, keepalive, gate, registration, command dispatch, cleanup: one
// call. The application handler receives everything the commands leave
// alone.
let link = AcceptedLink::accepted(transport)?;
commands
	.serve(link, move |context, frame| application_routes(context, frame))
	.await?;
# Ok(())
# }
```

## Emitter

`Emitter` owns the `MuxHandle` of one link and sorts each failed `MuxHandle::emit_on_stream` once, by what the failure costs the link. The registry emits through it, and an application emits beside it through `ConnectionContext::emitter`.

`Emitter::until_settled(&frame)` emits until the emit settles, and it waits out a full stream cap. It answers one of three outcomes:

- `Settled::Answered(Option<Box<Frame>>)`: the peer accepted the frame, with the frame it answered, if any.
- `Settled::Refused(TransportError)`: only this frame is lost, because the peer answered with a refusal or the session budget cannot carry the frame until a renewal restores it. The link stays up.
- `LinkLost`: the error of an emit that counts as the end of the link.

## Drain

`TopicRegistry::quiesce` refuses new work and pushes `end/<topic>` to every subscriber. `TopicRegistry::flushed` then waits for those pushes to leave, before each connection shuts down. Each `end/<topic>` carries the last order that its topic committed (`Backplane::last_order`), so a quiesce burns no order and the other nodes on the backplane keep a dense sequence.

```rust
# use tightbeam::transport::envelopes::GoAwayReason;
# use tightbeam::transport::multiplex::MuxHandle;
# use tightbeam_pubsub::TopicRegistry;
# async fn drain(registry: &TopicRegistry, handle: &MuxHandle) -> Result<(), Box<dyn std::error::Error>> {
registry.quiesce()?; // push end/<topic> everywhere, refuse new work
registry.flushed().await; // wait for the pushes to leave
handle.shutdown_with(GoAwayReason::Shutdown).await?; // per connection
# Ok(())
# }
```

## Backplane

The registry owns local fan-out: the lanes, the queues, and the delivery policies. It delegates two decisions to its `Backplane`: who assigns the dense order of a topic, and how a publish reaches other nodes. `Local` answers both in process, and it is the default. A backplane reaches each registry through the `NodeSink` that it is attached, which holds no ownership of the registry, so a dropped registry leaves distribution on its own.

Every backplane meets this contract:

- Orders MUST be dense (`1, 2, 3, ...`) for each topic across every node, because the client gate reads a hole as message loss. Redis `INCR` and `XADD` qualify. A raw Postgres sequence does not, because a rollback leaves a hole, so a locked counter row serves instead.
- Deliveries for one topic MUST NOT run concurrently, because the registry relies on arrival order that matches stamp order. `Local` holds its lock across delivery, and a remote implementation gets the same from a single consumer task.
- Every attached sink that does not drain MUST observe every accepted update, the own updates of the publishing node included. A `DeliverError::Draining` refusal means that the sink is leaving, so the publish stands when another sink accepted. A `DeliverError::Build` refusal fails the publish.
- The order stamp burns when at least one sink accepted. A publish that every sink refuses leaves the counter as it was, so no subscriber sees a gap for an update that no node fanned out.
- The counter of a topic MAY leave only while no attached sink has a member of that topic (`UpdateSink::has_members`). The next publish then restarts the topic at 1, which every client reads as fresh.
- Every backplane answers a publish with the one `PublishError` set that the registry answers with. A multi-node backplane reports a fault of its fabric as `PublishError::Unavailable` with a `BackplaneFault`.
- `Backplane::vacated` is a required method. The registry reports through it each topic that loses its last local member, and a backplane that wraps `Local` passes the report on.
- An async fabric MAY return `Ok` after a durable enqueue when it documents at-most-once delivery. `Local` stamps, then delivers.

`Local` counts at most 65,536 topics, and `Local::with_max_topics` sets another limit. A publish to a new topic at the limit evicts the counter of a topic with no member on any attached sink, and that topic restarts at order 1:

1. The candidates are the new counters and the topics that `Backplane::vacated` reported. Each candidate costs one question for each sink.
2. When no candidate is free, a sweep asks about every counted topic, so a member that left with no report frees its counter too. A sweep runs once the refusals since the last sweep outnumber the counted topics.
3. When every counted topic has a member, the publish fails with `PublishError::TopicLimit`.

One shared `Local` spans the registries of one process. An implementation over Redis, Postgres, or NATS spans machines under the same contract, and it swaps in through `RegistryOptions` with no change to the wire format or the TypeScript client. Egress to other channels, such as web push, email, or SNS, attaches as another consumer of the same bus, beside the registry.

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

## Wire convention

The convention adds no wire protocol and no broker. A subscription is an ordinary command stream that the client initiates, and an update is a push that the server initiates. Any carrier of the tightbeam mux therefore carries it, WebSocket or raw TCP. A topic name travels in `Frame.metadata.id` as UTF-8 bytes, and each answer is a `TransitStatus` from the gRPC canonical registry.

| Direction        | Frame id        | Meaning                                                      | Answer                                                                                                 |
| ---------------- | --------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| Client to server | `sub/<topic>`   | Subscribe                                                    | `Ok`, or `PermissionDenied`, `Unavailable`, `ResourceExhausted`, or `InvalidArgument`                  |
| Client to server | `unsub/<topic>` | Unsubscribe. A repeat or unknown topic still answers `Ok`    | `Ok`, or `InvalidArgument` for a name that is no topic                                                 |
| Client to server | `pub/<topic>`   | Publish the body payload, once a publish policy is installed | `Ok`, or `PermissionDenied`, `Unavailable`, `ResourceExhausted`, `InvalidArgument`, or `Internal`      |
| Server to client | `<topic>`       | Update: the payload in the body, the sequence in `order`     | `Ok`, or `ResourceExhausted`, `Unimplemented`, or `Unknown`. The server counts each refusal as a drop  |
| Server to client | `end/<topic>`   | Completion, at a quiesce                                     | `Ok`, or the answer of the fallback, `Unimplemented` by default, for a topic with no live subscription |

A command meets each refusal for one cause:

| Answer              | Cause                                                                                                                |
| ------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `InvalidArgument`   | The name after the prefix is no topic, or the body of a `pub/` is no opaque body                                     |
| `PermissionDenied`  | The policy forbids the topic, or the connection has no standing because it dropped or the registry never admitted it |
| `Unavailable`       | The registry is draining, or the fabric of the backplane failed                                                      |
| `ResourceExhausted` | The connection holds its subscription limit, or the backplane holds its topic limit                                  |
| `Internal`          | The update frame of an authorized publish failed to build                                                            |

Both sides dispatch on the same prefixes. The TypeScript client reads them, with `Topic::MAX_LEN`, from the JSON that [`examples/wire_contract.rs`](../pubsub/tightbeam-pubsub/examples/wire_contract.rs) renders, so each value has one home. `make -C pubsub client` renders that JSON into `pubsub/client/src/wire.generated.json` before it compiles the client.

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

The `testing` feature holds the support for tests without sockets:

- `MemoryLink`, an in-memory link, with `mux_pair` for two multiplexed ends and `served` for a link that `PubsubCommands::serve` takes
- `OpaqueFrame`, the builder of the frames that a client sends
- `Topic::fixture`, the topic of a name that a test or an example knows is valid. It panics on a name that fails validation

The unit tests of the crate and of its examples run over `MemoryLink`. The integration tests run as tightbeam scenarios over WebSocket peers on loopback, so each spec grades the audit trail of the registry under the `instrument` feature, and the GOAWAY that the transports of the run record. The two scenarios that prove the link which `served` builds from its parts run over `MemoryLink`, and they record what they observe themselves, because a mux built from parts records on no trace.

The example `pubsub_demo_server` is the server that the dockerized end-to-end suite drives.

## Sources

- MQTT 5.0, § 4.7 Topic Names and Topic Filters, and § 3.11 UNSUBACK: <https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html>
- RFC 6455, The WebSocket Protocol, § 5.5.1 Close, the analog of an orderly closure: <https://datatracker.ietf.org/doc/html/rfc6455#section-5.5.1>
- `google.rpc.Code`, the gRPC canonical status codes: <https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto>
