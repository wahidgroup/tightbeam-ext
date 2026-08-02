# tightbeam-pubsub

Topic pub/sub extension for the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol.

This crate adds topic membership and publish fan-out on the existing tightbeam mux. Subscriptions are ordinary client-initiated command streams, and updates are server-initiated pushes. Any process that holds a `MuxHandle` can fan out. There is no new wire protocol and no broker, so the design stays carrier-agnostic (WebSocket or raw TCP mux alike).

## Surface

- `Topic` validates names as a `/`-separated hierarchy with exact match semantics. Command prefixes are reserved.
- `TopicRegistry` owns membership and publishing. The registry builds every update frame itself, so stamps never depend on callers. `RegistryOptions::max_subscriptions_per_connection` (default 64) caps live subscriptions per connection.
- `PubsubCommands` answers the wire commands inside an existing serve handler. Everything else falls through to the application's routes.
- `serve_connection` performs the per-connection ceremony in one call: drivers, registration, dispatch, and cleanup. `serve_connection_as` attaches an identity. `unrouted` serves command-only.
- `SubscribePolicy` and `PublishPolicy` expose `authorize(identity, &Topic)` and own the `PermissionDenied` decision. Default is `AllowAll`.
- `DeliveryPolicy` defines what a full subscriber queue does: `DropOldest` (default, counted), `DropNew`, or `Disconnect`. A slow client never stalls the topic fan-out.
- `Backplane` provides sequencing and cross-node distribution. `Local` (in-process, the default) covers one node. See [Scaling out](#scaling-out).

## Publish

```rust
let topic: Topic = "prices/spot".parse()?;

// Bytes: the registry wraps them in an update frame, stamping the topic
// into `metadata.id` and a dense per-topic sequence into `metadata.order`.
registry.publish(&topic, payload)?;

// Frame in frame: a full tightbeam frame relays byte-for-byte as the
// payload. Publisher-applied signatures, commitments, encryption, and
// compression survive end to end (the TS client decodes with `Framed`),
// and the registry never reads the inner frame.
registry.publish_frame(&topic, &signed_frame)?;
```

## Authorize

Identity is whatever the application attaches at connection registration. Mutual-auth certificates are the expected source.

```rust
struct DenySecrets;

impl SubscribePolicy for DenySecrets {
	fn authorize(&self, _identity: Option<&[u8]>, topic: &Topic) -> AccessVerdict {
		if topic.as_str().starts_with("secrets/") {
			return AccessVerdict::Forbid;
		}

		AccessVerdict::Allow
	}
}

// Client publish is opt-in. Without `with_publish`, `pub/` frames fall
// through to the application like any other stream.
let commands = PubsubCommands::new(registry, DenySecrets).with_publish(AllowAll);
```

## Drain

Quiesce refuses new work, pushes `end/<topic>` to every subscriber, then waits for those pushes to leave before connection shutdown.

```rust
registry.quiesce()?; // push end/<topic> everywhere, refuse new work
registry.flushed().await; // wait for the pushes to leave
handle.shutdown_with(GoAwayReason::Shutdown).await?; // per connection
```

## Scaling out

```rust
let backplane: Arc<dyn Backplane> = Arc::new(Local::default());

// Every node hands the same backplane to its registry: a publish on any
// node reaches subscribers on all of them with one dense stamp.
let registry = TopicRegistry::new(RegistryOptions {
	backplane: Arc::clone(&backplane),
	..RegistryOptions::default()
});
```

Sharing one `Local` spans registries in one process. An implementation over Redis/Postgres/NATS spans machines under the same contract: orders stay dense per topic and deliveries never run concurrently for one topic. Egress to other channels (web push, email, SNS) attaches as additional consumers of the same bus, beside the registry rather than through it.

## Wire convention

Topic names travel in `Frame.metadata.id` as UTF-8 bytes. Refusals use tightbeam's gRPC-canonical `TransitStatus`.

| Direction         | Frame id        | Meaning                                      | Answer                                                          |
| ----------------- | --------------- | -------------------------------------------- | --------------------------------------------------------------- |
| client to server  | `sub/<topic>`   | subscribe                                    | `Ok`, or `PermissionDenied` / `Unavailable` / `ResourceExhausted` / `InvalidArgument` |
| client to server  | `unsub/<topic>` | unsubscribe (idempotent)                     | `Ok`                                                            |
| client to server  | `pub/<topic>`   | publish the body payload (opt-in)            | `Ok`, or `PermissionDenied` / `Unavailable` / `InvalidArgument` |
| server to client  | `<topic>`       | update: payload in body, sequence in `order` | `Ok`, or `ResourceExhausted` / `Unimplemented` (drop-and-count) |
| server to client  | `end/<topic>`   | completion (quiesce)                         | `Ok`                                                            |

Both sides dispatch on the same prefixes. The Rust server, per accepted connection:

```rust
let commands = PubsubCommands::new(registry, policy).with_publish(AllowAll);

// Drivers, registration, command dispatch, cleanup: one call. The
// application handler receives everything the commands leave alone.
serve_connection(mux, commands, move |context, frame| {
	application_routes(context, frame)
})
.await?;
```

The TypeScript client answers the same rows, one route each:

```ts
const manager = new SubscriptionManager(client, {
	// Non-topic server pushes. Unmatched ids answer Unimplemented.
	fallback: async (update) => handleAppStream(update),
});

// Registers the topic route, then emits `sub/prices`.
const prices = await manager.subscribe("prices", { codec: Opaque });
for await (const { message, frame } of prices) {
	render(message, frame.order);
}

await manager.publish("prices", payload, Opaque); // emits `pub/prices`
await manager.unsubscribe("prices"); // emits `unsub/prices`
```

## Features

- `testing` - in-memory mux fixtures (`memory_mux_pair`) and command-frame helpers for integration tests without sockets.

## Sources

- MQTT 5.0 § 4.7, Topic names and filters:
  <https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html>

## Related

The TypeScript counterpart is `@wahidgroup/tightbeam-pubsub-client` ([client](../client)), which consumes these conventions over `@wahidgroup/tightbeam-ws-client`. A runnable server is [examples/pubsub_demo_server.rs](examples/pubsub_demo_server.rs), the same binary the dockerized e2e suite drives. See the [repository README](../../README.md) for development and release workflows.

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
