# tightbeam-pubsub

Topic pub/sub extension for the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol.

## Status

This project is under active development. Public APIs MAY change without notice. No security audit has been conducted. Use this software at your own risk.

## Abstract

This crate adds topic membership and publish fan-out to the tightbeam mux. A subscription is an ordinary command stream that the client opens, and an update is a push that the server initiates. The crate therefore adds no transport protocol and no broker, and any carrier of the mux carries it, WebSocket or raw TCP. Topic names follow the exact-match model of [MQTT 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html) § 4.7, with no wildcards.

## Install

```sh
cargo add tightbeam-pubsub
```

## Publishing

`TopicRegistry::publish` wraps a payload in an update frame, and `publish_frame` relays a whole tightbeam frame as the payload, so the signatures and the seal of its publisher hold end to end. Implementation: [docs/pubsub.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub.md#registry).

## Topics and delivery

`TopicRegistry` owns membership, stamps each update with a dense sequence for its topic, and bounds what each connection queues. A [delivery policy](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub.md#delivery-policy) decides what a full queue drops. Implementation: [docs/pubsub.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub.md#registry).

## Authorization

A subscribe policy and an optional publish policy decide each topic against the peer that the handshake proved. Client publish stays off until a publish policy is installed. Implementation: [docs/pubsub.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub.md#access-policies).

## Serving connections

`PubsubCommands::serve` runs the whole life of one accepted connection, and it hands every unary stream that no command claims to the routes of the application. Implementation: [docs/pubsub.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub.md#connection-serve).

## Drain

A drain completes every subscription, waits for each completion to leave, and then dismisses every connection with a GoAway. It keeps each sequence dense. Implementation: [docs/pubsub.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub.md#drain).

## Scaling out

A backplane assigns the sequence of each topic and carries a publish to every node. The in-process `Local` backplane is the default, and an implementation over Redis, Postgres, or NATS meets the same contract. `testing::BackplaneConformance` checks the clauses of the contract that the implementation page names for it. Implementation: [docs/pubsub.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub.md#backplane).

## Command convention

Topic names travel in the frame id behind the command prefixes `sub/`, `unsub/`, `pub/`, and `end/`, and every answer is a gRPC canonical status. Implementation: [docs/pubsub.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub.md#command-convention).

## Features

`instrument` records the audit trail of each served connection: its admission, departure, and expulsion, its refused commands, and its dropped updates. Implementation: [docs/pubsub.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub.md#connection-serve).

`testing` adds loopback WebSocket links and peers for tests, and the backplane contract suite. Implementation: [docs/pubsub.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub.md#testing).

## Related

The TypeScript counterpart is `@wahidgroup/tightbeam-pubsub-client` ([client](https://github.com/wahidgroup/tightbeam-ext/tree/master/pubsub/client)), which consumes these conventions over `@wahidgroup/tightbeam-ws-client`. A runnable server is [examples/pubsub_demo_server.rs](https://github.com/wahidgroup/tightbeam-ext/blob/master/pubsub/tightbeam-pubsub/examples/pubsub_demo_server.rs), the same binary the dockerized e2e suite drives. See the [repository README](https://github.com/wahidgroup/tightbeam-ext/blob/master/README.md) for development and release workflows.

## License

Licensed under either of [MIT](https://github.com/wahidgroup/tightbeam-ext/blob/master/pubsub/tightbeam-pubsub/LICENSE-MIT) or [Apache-2.0](https://github.com/wahidgroup/tightbeam-ext/blob/master/pubsub/tightbeam-pubsub/LICENSE-APACHE) at your option.
