# tightbeam-pubsub-client

Topic subscriptions for the [tightbeam](https://crates.io/crates/tightbeam-rs) WebSocket client: typed subscribe/unsubscribe lifecycle with per-topic ordering and reconnect replay.

## Status

This project is under active development. Public APIs MAY change without notice. No security audit has been conducted. Use this software at your own risk.

## Abstract

This package is the client half of the `tightbeam-pubsub` extension. The Rust `TopicRegistry` pushes updates as server-initiated streams over the multiplexed connection of `@wahidgroup/tightbeam-ws-client`, and a `SubscriptionManager` turns those streams into typed subscriptions. The command convention has its own page, [The Topic Registry and Its Commands](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub.md#command-convention).

The quick-start sample compiles in [`src/docs.test.ts`](https://github.com/wahidgroup/tightbeam-ext/blob/master/pubsub/client/src/docs.test.ts), which reads it from this README.

## Install

```sh
npm install @wahidgroup/tightbeam-pubsub-client
```

The package is published to GitHub Packages. Point the `@wahidgroup` scope there in `.npmrc`:

```ini
@wahidgroup:registry=https://npm.pkg.github.com
```

## Quick start

```ts
import { Engine } from "@wahidgroup/tightbeam-ws-client";
import { ClientPorts, SubscriptionManager } from "@wahidgroup/tightbeam-pubsub-client";

const engine = await Engine.load();
const client = await engine.connectCleartext("ws://localhost:9110");
const ports = ClientPorts.split(client);
const manager = new SubscriptionManager(ports);

// Without an onUpdate handler, the subscription is async-iterable.
const prices = await manager.subscribe("prices", {
	codec: engine.opaque,
});
for await (const { message, frame } of prices) {
	render(message, frame.order);
}
// Iteration ends when the topic completes or unsubscribes. A break out of
// the loop unsubscribes the topic.
```

## Subscriptions

A subscription delivers each update as the decoded payload, through a `for await` loop or an `onUpdate` handler, and a slow consumer slows only its own delivery. Implementation: [docs/pubsub-client.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub-client.md#subscriptions).

## Payloads

A codec types each topic payload. A payload can also be a full tightbeam frame under an `Envelope`, so the signature and seal of the publisher hold end to end through the broker. Implementation: [docs/pubsub-client.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub-client.md#payload-shapes).

## Publish

`publish` sends a payload to a topic on a server that enables client publish. Implementation: [docs/pubsub-client.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub-client.md#publish).

## Ordering and gaps

A gate for each subscription checks the dense sequence of the registry, drops duplicates, and reports each gap. Implementation: [docs/pubsub-client.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub-client.md#ordering-and-gaps).

## Reconnect replay

The manager keeps the desired topic set across connections, and `reattach` replays it on a new client. Implementation: [docs/pubsub-client.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub-client.md#reconnect-replay).

## Non-topic streams

A fallback handler serves the server pushes that no subscription matches. Implementation: [docs/pubsub-client.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/pubsub-client.md#unmatched-pushes).

## License

Licensed under either of [MIT](https://github.com/wahidgroup/tightbeam-ext/blob/master/pubsub/client/LICENSE-MIT) or [Apache-2.0](https://github.com/wahidgroup/tightbeam-ext/blob/master/pubsub/client/LICENSE-APACHE) at your option.
