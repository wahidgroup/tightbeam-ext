# The Subscription Client

This page specifies `@wahidgroup/tightbeam-pubsub-client`, the client half of the `tightbeam-pubsub` extension:

- the manager, the ports it splits a client into, and its serve claim
- topic names and the command frames built from them
- subscriptions, their two delivery styles, and their errors
- the payload shapes of a topic
- client publish
- the ordering gate and gap handling
- the command lane of each topic
- reconnect replay and the state of a subscription
- the pushes that no subscription matches

It drills down from the [tightbeam-pubsub-client README](../pubsub/client/README.md) for engineers who build on the client or review it. The README holds what each part is for and the standards it follows. The server half and the wire convention have their own page, [The Topic Registry and Wire Convention](pubsub.md). Every sample on this page compiles as the case of [`pubsub/client/src/docs.test.ts`](../pubsub/client/src/docs.test.ts) that names its section.

## Contents

- [Manager](#manager)
- [Topics](#topics)
- [Subscriptions](#subscriptions)
- [Payload shapes](#payload-shapes)
- [Publish](#publish)
- [Ordering and gaps](#ordering-and-gaps)
- [Command lanes](#command-lanes)
- [Reconnect replay](#reconnect-replay)
- [Unmatched pushes](#unmatched-pushes)
- [Sources](#sources)

## Manager

The server side, the Rust `TopicRegistry`, fans updates out as server-initiated streams over the multiplexed connection that `@wahidgroup/tightbeam-ws-client` provides. A `SubscriptionManager` turns those streams into subscriptions.

- `new SubscriptionManager(ClientPorts.split(client), options?)` takes the client split once into the `CommandPort` that sends commands and the `ServePort` that serves pushes. The ports read the `Engine` that dialed the client, which builds each command frame and decodes each payload. The manager reaches the command port only through the `CommandLane` of each topic ([Command lanes](#command-lanes)).
- The manager owns the serve handler of the client, and its claim is exclusive. A later `serve`, `serveStreaming`, or `serveDuplex` call throws a `TightbeamTransportError` whose `code` is `ServeDispatchClaimed`, so no update goes unrouted in silence. A manager built over a client that already serves a shared handler throws the same error with the `code` `ServeDispatchShared`. Each `code` is a member of the closed `TransportErrorCode` union of the ws client.
- A client stays open until `await client.close()`, the close of the peer, or a GoAway, and the manager routes its pushes until the manager is disposed. `await manager[Symbol.asyncDispose]()`, or the end of an `await using` scope, ends every subscription, sends `unsub/` for each, and detaches the serve handler of the manager, which then answers every push `Unimplemented`. The disposal waits for the commands still in flight, then drops every command that a lost connection deferred and frees what each one holds. An emit has no deadline of its own, so a disposal over a stalled connection resolves once the client closes: the close settles every pending emit with `ConnectionClosed`. The disposed manager stays ended. Close the client to end the connection itself.
- `ManagerOptions.fallback` serves the pushes that no subscription matches ([Unmatched pushes](#unmatched-pushes)).

## Topics

`Topic.parse(name)` applies the rules of the server ([The Topic Registry](pubsub.md#topics)). A name MUST be non-empty, fit in the octet limit of the Rust `Topic::MAX_LEN` (256 UTF-8 octets), and start outside the reserved prefixes. Otherwise it throws a `TopicError` whose `code` is `Empty`, `TooLong`, or `ReservedPrefix`. `subscribe`, `publish`, and `unsubscribe` take a `Topic` or a name, and parse a name first.

The limit and the command prefixes come from the Rust `Topic`. The `wire_contract` example renders them into `src/wire.generated.json`, which `make -C pubsub client` writes before it compiles the package. `Topic.subscribe`, `Topic.unsubscribe`, and `Topic.publish` build each `Command`, and `Command.parse` reads the id of an `end/<topic>` push.

## Subscriptions

`subscribe(topic, options)` registers the dispatch entry before the `sub/` command leaves, so an update that races the acknowledgment still routes. It resolves on the `Ok` of the server. It rejects with the transport error of a refusal, such as `PermissionDenied` for a forbidden topic or `Unavailable` while the server drains, and it removes the entry.

The options choose one of two delivery styles:

| Style    | Type                       | Delivery                                                                                                                           |
| -------- | -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Iterator | `IteratingSubscription<T>` | Without an `onUpdate` handler. One `for await` loop takes each update, and a `break` out of it unsubscribes the topic              |
| Handler  | `HandlerSubscription`      | `onUpdate(payload, update, topic)` runs for each update. The type holds no iterator, so the compiler refuses a `for await` over it |

The iteration ends when the topic completes or unsubscribes. `onEnd(topic)` observes a completion. `unsubscribe()` emits `unsub/<topic>` and stops the local dispatch. Once a subscription has ended, the call returns at once and leaves a newer subscription to the same topic live.

The manager refuses a call with a `SubscriptionError`:

- `AlreadySubscribed`: a second `subscribe` to a topic with a live subscription.
- `AlreadyIterating`: a second iterator over one `IteratingSubscription`.
- `Disposed`: a `subscribe`, a `publish`, or a `reattach` after the manager is disposed. A refused `reattach` installs no handler.
- `DeferralFull`: a command that a lost connection would defer past `MAX_DEFERRED`, 256 commands that one manager keeps across all its topics.

Both styles apply backpressure. The manager acknowledges each update stream only after `onUpdate` settles, or after the iterating consumer takes the item. A slow consumer therefore slows the delivery lane of its subscriber, and not the process.

```ts
const prices = await manager.subscribe("prices", {
  codec: engine.opaque,
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

## Payload shapes

Each subscription and each publish names its payload shape, and updates arrive as the decoded `T`:

- `{ codec }` takes a `MessageCodec<T>`.
- `{ envelope }` takes an `Envelope<T>` for a layered payload, frame in frame.

`PayloadShape` is the one owner of how each shape builds and decodes a frame. `PayloadShape.of(source, engine, use)` decides the shape once: the kind, and for a codec whether the shape decodes the updates of a subscription or builds the commands of a publish.

### Frames as payloads

A topic payload is opaque bytes, so it can be a full tightbeam frame. A publisher and a subscriber that both name the `framed` codec of the engine relay the inner frame with its bytes unchanged. The registry stamps only its wrapper, with the topic as `id` and the dense sequence as `order`. Everything that the publisher applied holds end to end: the signature, the commitment, an encrypted or compressed body, the priority, the lifetime, and the `previousFrame` chain. A subscriber therefore verifies the publisher, and not the broker.

```ts
import type { MessageCodec } from "@wahidgroup/tightbeam-ws-client";

interface Order {
  symbol: string;
  quantity: number;
}

// Any MessageCodec<T> types the inner body (the ws client's "Typed
// messages" section). This one lifts JSON, and asOrder runtime-validates.
const Orders: MessageCodec<Order> = engine.wrapping({
  encode: (order) => new TextEncoder().encode(JSON.stringify(order)),
  decode: (payload) => asOrder(JSON.parse(new TextDecoder().decode(payload))),
});

// Publisher: a typed body inside a signed frame.
const inner = await engine
  .frameBuilder()
  .withMessage(Orders, { symbol: "BTC", quantity: 42 })
  .withId("order-42")
  .withOrder(7)
  .withPriority(engine.MessagePriority.Expedited)
  .withLifetime(60)
  .withSigner(signingKey)
  .build();
await manager.publish("orders", inner, { codec: engine.framed });

// Subscriber: the whole Frame surface is live on each update.
const orders = await manager.subscribe("orders", { codec: engine.framed });
for await (const { message: received, frame: wrapper } of orders) {
  received.verify(publisherKey); // end-to-end publisher authenticity

  // The publisher's metadata, distinct from the wrapper's stamps.
  if (received.priority === engine.MessagePriority.Expedited) {
    expedite(received.id, received.lifetime);
  }

  apply(received.message(Orders), wrapper.order); // Order
}
```

The rest of the unwrap calls of the ws client apply unchanged. A sealed inner body opens with any `BodyDecryptor`, typed by the same codec, and a carried commitment checks against its disclosed salt:

```ts
const order = await received.open(Orders, {
  opener: engine.aes256Gcm({ key: topicKey, keyId: topicKeyId }),
});
const verdict = await received.messageCommitmentVerdict(engine.salt(salt)); // "verified"
```

The server publishes the same shape with `TopicRegistry::publish_frame`. An encrypted inner body (`withEncryptor`) makes the topic confidential, because the registry relays what it cannot read.

### Envelopes end to end

`engine.envelope(codec)` of the ws client declares the layers once ([The WebSocket Client](ws-client.md#envelopes)), and the manager accepts `{ envelope }` wherever it accepts `{ codec }`:

- `publish` builds the inner frame under the declared layers.
- Each update unwraps under the same declaration, verify, open, inflate, and decode, before the handler runs.
- An update that lacks a declared signature or seal rejects and never degrades, so the broker or another publisher cannot downgrade the topic by omission.
- The `authenticated` and `confidential` getters of the envelope report the declared properties, which `unwrap` enforces, so a UI shows them as badges with no probe of each frame.
- A subscriber without the signing key composes its half with `verified(publisherKey)`. An HPKE topic splits the same way, `sealed(engine.hpkeEncryptor(...))` to publish and `sealed(engine.hpkeDecryptor(...))` to receive.

```ts
const notes = engine
  .envelope(Notes) // the Orders-style typed codec above
  .signed(publisherKey)
  .sealed(engine.aes256Gcm({ key: topicKey, keyId: topicKeyId }));

// Publisher: one call builds the signed, sealed inner frame.
await manager.publish(
  "notes",
  { author: "board", text: "hello" },
  { envelope: notes },
);

// Subscriber: `note` arrives verified, opened, and decoded.
await manager.subscribe("notes", {
  envelope: notes,
  onUpdate: (note, wrapper) => {
    render(note, wrapper.order);
  },
});
```

## Publish

`publish(topic, message, { codec })` emits the `pub/<topic>` command of the wire, for a server that enables client publish. It takes the same payload shapes as `subscribe`.

The server opts in when it installs a `PublishPolicy` on its `PubsubCommands` (`with_publish`). Without one, the command falls through to the application routes of the server, which typically answer `Unimplemented`. A policy refusal rejects with `PermissionDenied`.

```ts
await manager.publish("prices", encoded, { codec: engine.opaque }); // emits `pub/prices`
```

## Ordering and gaps

The registry stamps the updates of each topic 1, 2, 3, and onward in `metadata.order`. A `TopicGate` for each subscription classifies every arrival with a `GateVerdict`:

| Verdict | Arrival                                                                                    | Effect                                                                                                 |
| ------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| `fresh` | The first update, or the next dense order                                                  | The update is delivered                                                                                |
| `stale` | An order at or behind the baseline, such as a duplicate or a reorder                       | The update drops with no report                                                                        |
| `gap`   | An order ahead by more than one, because the delivery policy of the server dropped updates | `onGap(topic, expected, received)` runs first, and the update that revealed the gap is still delivered |

- The baseline moves only after a delivery settles, so a failed decode or handler leaves its order unclaimed, and a later update reports the loss as a `gap`.
- When `onGap` throws, the update is still delivered, and the failure of the observer surfaces only after the delivery settles.
- Without an `onGap`, the manager emits `sub/` again, so a server that can replay resyncs.

```ts
await manager.subscribe("ticks", {
  codec: engine.opaque,
  onUpdate: (payload) => apply(payload),
  onGap: (topic, expected, received) => {
    refetchSnapshot(topic, expected, received);
  },
});
```

## Command lanes

The commands for one topic leave in the order that the manager issued them, through the one `CommandLane` of the topic:

- An `unsubscribe` called while its `sub/` is still pending sends `unsub/` once that `sub/` settles.
- A later `subscribe` to the same topic follows the `unsub/`.

## Reconnect replay

The ws client does not reconnect on its own, so reconnection is a loop of the application. The manager keeps the desired topic set across connections. `reattach(ClientPorts.split(newClient))` installs the handler again, resets the gates, and replays every subscription.

While the client is disconnected, `subscribe`, `unsubscribe`, and `publish` still settle. The lane of the topic defers each command that a `ConnectionClosed` rejection refuses, up to `MAX_DEFERRED`, 256 commands that one manager keeps across all its topics, so an outage holds bounded memory however many topics it spans. Each deferred command holds one slot of that budget until a replay or a drop returns it. A command past the budget rejects with `DeferralFull`. `reattach` replays the deferred commands of each topic before any later command of that topic, and a subscription that was live sends its `sub/` again first.

The `state` of a subscription tracks command acknowledgments, and not link health:

| State      | The subscription                                                                                                                           |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `pending`  | Its `sub/` awaits its turn or its answer                                                                                                   |
| `live`     | The server acknowledged its `sub/`. It stays `live` through a lost link until `reattach` replays it                                        |
| `deferred` | Its `sub/` waits for the replay of `reattach`: the link lost a pending `sub/`, or `reattach` lapsed a live subscription and reset its gate |
| `ended`    | It unsubscribed, the server refused it, or the server completed it                                                                         |

Watch `client.closed` for the connection itself.

```ts
let client = await connect();
const manager = new SubscriptionManager(ClientPorts.split(client));
await manager.subscribe("prices", { codec: engine.opaque, onUpdate: render });

// The connection drops and the app decides to reconnect.
await client.close();

client = await connect();
await manager.reattach(ClientPorts.split(client));
// `sub/prices` replayed, gate re-baselined, updates flowing again.
```

## Unmatched pushes

The server can push streams beside topic updates. The `fallback` of the manager receives every push whose id matches no live subscription, and without a fallback such a push answers `Unimplemented`. Topic ids can reach the fallback too: an update that arrives after its `unsubscribe`, and an `end/<topic>` for a topic with no live subscription.

```ts
const manager = new SubscriptionManager(ClientPorts.split(client), {
  fallback: async (update) => handleAppStream(update),
});
```

The client answers each update stream on the wire as [the wire convention](pubsub.md#wire-convention) states. A decode, an `onUpdate`, an `onGap`, or a resync that throws answers `Unknown`, and the server counts it as a drop.

## Sources

- MQTT 5.0, § 4.7 Topic Names and Topic Filters: <https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html>
- `google.rpc.Code`, the gRPC canonical status codes: <https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto>
