# tightbeam-pubsub

Topic pub/sub extension for the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol.

## Status

This project is under active development. Public APIs MAY change without notice. No security audit has been conducted. Use this software at your own risk.

## Abstract

This crate adds topic membership and publish fan-out to the tightbeam mux. A subscription is an ordinary command stream that the client opens, and an update is a push that the server initiates. The crate therefore adds no wire protocol and no broker, and any carrier of the mux carries it, WebSocket or raw TCP. Topic names follow the exact-match model of [MQTT 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html) § 4.7, with no wildcards.

## Install

```sh
cargo add tightbeam-pubsub
```

## Quick start

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
// compression survive end to end (the TS client decodes with `Framed`),
// and the registry never reads the inner frame.
registry.publish_frame(&topic, &signed_frame)?;
# Ok(())
# }
```

## Topics and delivery

`TopicRegistry` owns membership, stamps each update with a dense sequence for its topic, and bounds what each connection queues. A delivery policy decides what a full queue drops, so a slow client never stalls the fan-out. Implementation: [docs/pubsub.md](../../docs/pubsub.md#registry).

## Authorization

A subscribe policy and an optional publish policy decide each topic against the peer that the handshake proved. Client publish stays off until a publish policy is installed. Implementation: [docs/pubsub.md](../../docs/pubsub.md#access-policies).

## Serving connections

`PubsubCommands::serve` runs the whole life of one accepted connection, and it hands every stream that no command claims to the routes of the application. Implementation: [docs/pubsub.md](../../docs/pubsub.md#connection-serve).

## Drain

A quiesce completes every subscription before the connections shut down, and it keeps each sequence dense. Implementation: [docs/pubsub.md](../../docs/pubsub.md#drain).

## Scaling out

A backplane assigns the sequence of each topic and carries a publish to every node. The in-process `Local` backplane is the default, and an implementation over Redis, Postgres, or NATS meets the same contract. Implementation: [docs/pubsub.md](../../docs/pubsub.md#backplane).

## Wire convention

Topic names travel in the frame id behind the command prefixes `sub/`, `unsub/`, `pub/`, and `end/`, and every answer is a gRPC canonical status. Implementation: [docs/pubsub.md](../../docs/pubsub.md#wire-convention).

## Features

`testing` adds in-memory links and frame builders for integration tests without sockets. Implementation: [docs/pubsub.md](../../docs/pubsub.md#testing).

## Related

The TypeScript counterpart is `@wahidgroup/tightbeam-pubsub-client` ([client](../client)), which consumes these conventions over `@wahidgroup/tightbeam-ws-client`. A runnable server is [examples/pubsub_demo_server.rs](examples/pubsub_demo_server.rs), the same binary the dockerized e2e suite drives. See the [repository README](../../README.md) for development and release workflows.

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
