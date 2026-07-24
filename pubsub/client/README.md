# tightbeam-pubsub-client

Topic subscriptions for the [tightbeam](https://crates.io/crates/tightbeam-rs) WebSocket client: typed subscribe/unsubscribe lifecycle with per-topic ordering and reconnect replay.

## Status

> Warning: This project is under active development. Public APIs MAY change without notice.

**Security Disclaimer:** A SECURITY AUDIT HAS NOT BEEN CONDUCTED. USE AT YOUR OWN RISK.

## Abstract

This package is the client half of the `tightbeam-pubsub` extension. The server side (the Rust `TopicRegistry`) fans updates out as server-initiated streams over the multiplexed connection `@wahidgroup/tightbeam-ws-client` already provides. This package turns those streams into subscriptions:

- `SubscriptionManager` owns the client's serve handler (an exclusive claim: a later `client.serve` throws instead of silently unrouting updates). Updates dispatch by exact topic match, `end/<topic>` completes a subscription, and anything else goes to an optional fallback handler (or answers `Unimplemented`).
- Each subscription carries a `MessageCodec<T>` (or an `Envelope<T>` for layered frame-in-frame payloads), so updates arrive as the decoded `T` (not bytes), through an `onUpdate` handler or by async iteration.
- `publish(topic, message, codec)` emits the wire's `pub/<topic>` command, for servers that enable client publish.
- A `TopicGate` per subscription verifies the registry's dense per-topic `metadata.order` stamps: duplicates drop silently, and a gap (updates dropped under backpressure) fires `onGap` or, by default, re-emits the `sub/` command to resync.
- The manager tracks the desired topic set across connections: after a reconnect, `reattach(newClient)` re-installs the handler, resets the gates, and replays every subscription. `Subscription.state` says where each one stands (`live`, `pending`, `ended`).

The wire convention (`sub/`, `unsub/`, `pub/`, `end/` ids, gRPC-status answers) is documented beside its Rust `match` in the [tightbeam-pubsub README](../tightbeam-pubsub/README.md).

## Install

```sh
npm install @wahidgroup/tightbeam-pubsub-client
```

The package is published to GitHub Packages. Point the `@wahidgroup` scope there in `.npmrc`:

```ini
@wahidgroup:registry=https://npm.pkg.github.com
```

## Subscribe

```ts
import { Opaque, TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";
import { SubscriptionManager } from "@wahidgroup/tightbeam-pubsub-client";

const client = await TightbeamWsClient.connectCleartext("ws://localhost:9110");
const manager = new SubscriptionManager(client);

// Without an onUpdate handler, the subscription is async-iterable.
const prices = await manager.subscribe("prices", { codec: Opaque });
for await (const { message, frame } of prices) {
	render(message, frame.order);
}
// Iteration ends when the topic completes or unsubscribes.
```

Handler style fits event-driven consumers (a DOM renderer, a store dispatch):

```ts
const prices = await manager.subscribe("prices", {
	codec: Opaque,
	onUpdate: (payload, update, topic) => {
		render(topic, payload, update.order);
	},
	onEnd: (topic) => {
		console.log(`${topic} completed`);
	},
});

// Later: emits `unsub/prices` and stops local dispatch.
await prices.unsubscribe();
```

`subscribe` registers the dispatch entry before the `sub/` command leaves, so an update racing the acknowledgment still routes. It resolves on the server's `Ok` and rejects with the transport error on a refusal (`PermissionDenied` for a forbidden topic, `Unavailable` while draining), removing the entry.

Both styles apply backpressure: the manager acknowledges each update stream only after `onUpdate` settles (or the iterating consumer takes the item), so a slow consumer slows that subscriber's delivery lane, not the process.

## Publish

```ts
await manager.publish("prices", encoded, Opaque); // emits `pub/prices`
```

The server opts in by installing a `PublishPolicy` on its `PubsubCommands` (`with_publish`). Without one, the command falls through to the server's application routes and typically rejects `Unimplemented`. A policy refusal rejects with `PermissionDenied`.

## Frames as payloads

A topic payload is opaque bytes, so it can be a full tightbeam frame. Publish and subscribe with the ws client's `Framed` codec: the registry stamps only its wrapper (`id` = topic, `order` = dense sequence) and relays the inner frame byte-for-byte. Everything the publisher applied survives end to end (signature, commitment, encrypted or compressed body, priority, lifetime, `previousFrame` chain), so subscribers verify the publisher, not the broker.

```ts
import type { MessageCodec } from "@wahidgroup/tightbeam-ws-client";
import {
	Framed,
	MessagePriority,
	frame,
	wrapped,
} from "@wahidgroup/tightbeam-ws-client";

interface Order {
	symbol: string;
	quantity: number;
}

// Any MessageCodec<T> types the inner body (the ws client's "Typed
// messages" section); this one lifts JSON. asOrder runtime-validates.
const Orders: MessageCodec<Order> = wrapped({
	encode: (order) => new TextEncoder().encode(JSON.stringify(order)),
	decode: (payload) => asOrder(JSON.parse(new TextDecoder().decode(payload))),
});

// Publisher: a typed body inside a signed frame.
const inner = await frame()
	.withMessage(Orders, { symbol: "BTC", quantity: 42 })
	.withId("order-42")
	.withOrder(7)
	.withPriority(MessagePriority.Expedited)
	.withLifetime(60)
	.withSigner(signingKey)
	.build();
await manager.publish("orders", inner, Framed);

// Subscriber: the whole Frame surface is live on each update.
const orders = await manager.subscribe("orders", { codec: Framed });
for await (const { message: received, frame: wrapper } of orders) {
	received.verify(publisherKey); // end-to-end publisher authenticity

	// The publisher's metadata, distinct from the wrapper's stamps.
	if (received.priority === MessagePriority.Expedited) {
		expedite(received.id, received.lifetime);
	}

	apply(received.message(Orders), wrapper.order); // Order
}
```

The rest of the unwrap toolset applies unchanged. A sealed inner body decrypts with any `BodyDecryptor` (typed by the same codec), and a carried commitment checks against its disclosed salt:

```ts
const order = await received.decryptMessage(new Aes256Gcm(topicKey), Orders);
const verdict = await received.messageCommitmentVerdict(salt); // "verified"
```

The server side publishes the same shape with `TopicRegistry::publish_frame`. An encrypted inner body (`withEncryptor`) makes the topic confidential: the registry relays what it cannot read.

## Envelopes end to end

Applying those layers by hand on every publish and every update gets repetitive. The ws client's `envelope(codec)` declares them once, and the manager accepts it wherever it accepts a codec: `publish` builds the inner frame under the declared layers, and each update unwraps (verifies, opens, inflates, decodes) under the same declaration before your handler runs. Enforcement is strict: an update missing a declared signature or seal rejects instead of degrading, so the broker (or another publisher) cannot downgrade the topic by omission.

```ts
import { Aes256Gcm, envelope } from "@wahidgroup/tightbeam-ws-client";

const notes = envelope(Notes) // the Orders-style typed codec above
	.signed(publisherKey)
	.sealed(Aes256Gcm.fromKey(topicKey));

// Publisher: one call builds the signed, sealed inner frame.
await manager.publish("notes", { author: "board", text: "hello" }, notes);

// Subscriber: `note` arrives verified, opened, and decoded.
await manager.subscribe("notes", {
	envelope: notes,
	onUpdate: (note, wrapper) => {
		render(note, wrapper.order);
	},
});
```

The envelope's `authenticated` and `confidential` getters report the declared (and therefore enforced) properties, so a UI badges them without probing frames. Subscribers without the signing key compose their half with `verified(publisherKey)`, and an ECIES topic splits the same way (`sealed(EciesEncryptor...)` to publish, `sealed(EciesDecryptor...)` to receive). See the [ws client's Envelopes section](../../ws/client/README.md#envelopes) for the full contract.

## Ordering and gaps

The registry stamps each topic's updates 1, 2, 3, ... in `metadata.order`. The per-subscription gate classifies every arrival:

- stale (duplicate or reorder): dropped silently.
- gap (the server's delivery policy dropped updates for this subscriber): `onGap(topic, expected, received)` runs first, then the update that revealed the gap is still delivered. Without an `onGap`, the manager re-emits `sub/` so a replay-capable server can resync.

```ts
await manager.subscribe("ticks", {
	codec: Opaque,
	onUpdate: (payload) => apply(payload),
	onGap: (topic, expected, received) => {
		refetchSnapshot(topic, expected, received);
	},
});
```

## Reconnect replay

The ws client has no auto-reconnect: reconnection is an application loop. The manager keeps the desired topic set through it:

```ts
let client = await connect();
let manager = new SubscriptionManager(client);
await manager.subscribe("prices", { codec: Opaque, onUpdate: render });

// The connection drops and the app decides to reconnect.
client.close();

client = await connect();
await manager.reattach(client);
// `sub/prices` replayed, gate re-baselined, updates flowing again.
```

While disconnected, `subscribe` and `unsubscribe` still settle: a `ConnectionClosed` rejection counts as "await reattach", never as a topic-level failure. `Subscription.state` distinguishes the cases: `live` once the server acknowledged, `pending` while parked for a reattach, `ended` after unsubscribe or completion. The state tracks command acknowledgments, not link health. Watch `client.closed` for the connection itself.

## Non-topic streams

The server can push streams beside topic updates. Pass a fallback at construction. Topic ids never reach it:

```ts
const manager = new SubscriptionManager(client, {
	fallback: async (update) => handleAppStream(update),
});
```

Without a fallback, unmatched server pushes answer `Unimplemented`.

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
