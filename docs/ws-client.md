# The WebSocket Client

This page specifies `@wahidgroup/tightbeam-ws-client`, the TypeScript client of the tightbeam WebSocket transport:

- the package, its bundles, and the names it shares with `tightbeam-rs`
- the engine, its load, and the values it parses
- the connectors, their options, and their faults
- the `Frame` a call resolves with
- client and server streams, progressive bodies, and routing
- cluster work submission
- cancellation, the connection lifecycle, and reconnection
- the transport errors and the keepalive
- the frame builder, typed messages, and caller-supplied cryptography
- compression, verification, and decryption
- envelopes and detached commitments

It drills down from the [tightbeam-ws-client README](../ws/client/README.md) for engineers who build on the client or review it. The README holds what each part is for and the standards it follows. The wasm engine under the client has its own page, [The Browser Engine](ws-wasm.md). Every sample on this page compiles in [`ws/client/src/docs.test.ts`](../ws/client/src/docs.test.ts), which reads it from this page.

## Contents

- [Package](#package)
- [Engine](#engine)
- [Connectors](#connectors)
- [Frame](#frame)
- [Streams](#streams)
- [Cluster work submission](#cluster-work-submission)
- [Cancellation](#cancellation)
- [Connection lifecycle](#connection-lifecycle)
- [Transport errors](#transport-errors)
- [Keepalive](#keepalive)
- [Frame builder](#frame-builder)
- [Typed messages](#typed-messages)
- [Custom cryptography](#custom-cryptography)
- [Compression](#compression)
- [Verification and decryption](#verification-and-decryption)
- [Envelopes](#envelopes)
- [Detached commitments](#detached-commitments)
- [Sources](#sources)

## Package

The frame codec, the ASN.1 DER engine, is the Rust implementation of tightbeam, compiled from `tightbeam-ws-wasm` with `wasm-pack`. The TypeScript layer adds the builder, the typed message envelope, validation, and connection handling.

Two wasm bundles ship in the package, a `web` build and a `nodejs` build, and each has its own engine loader. The `#engine` entry of the package `imports` map selects the loader of the `nodejs` build under the `node` condition and the loader of the `web` build otherwise. The `#wasm` entry names the types of the glue alone. ESM gives a relative import no module-private visibility, so the lint of the client holds the glue to the loaders, as [The Browser Engine](ws-wasm.md#build) states. Its `no-restricted-imports` rule refuses a static value import of the glue in every module, and its `no-restricted-syntax` rule refuses a dynamic import outside `src/engine/**`. Node 24 and later supply a global `WebSocket`, so Node needs no shim.

The client keeps this surface of `tightbeam-rs` under the same names:

| Part      | Shared surface                                                                                                                                                                                |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Builder   | `withSigner`, `withEncryptor`, `withMessageHasher`, and the version floor rules of `GatedField::since`                                                                                        |
| `Frame`   | `verify`, `frameIntegrityVerdict`, `messageCommitmentVerdict`, and the enums `Version` and `MessagePriority` with the same ordinals, which `engine.Version` and `engine.MessagePriority` hold |
| Transport | Multiplexed bidirectional streams, HPKE sessions, GoAway reasons, and the gRPC status codes of a refusal                                                                                      |

`assertVersion` belongs to the client alone. `tightbeam-rs` takes the version when the builder starts, through `FrameBuilder::from(Version)` or `compose!`, and the engine refuses another version as the structure assembles.

The package checks:

- `tsconfig.build.json` names no Node types, so a Node import or a Node global in the sources fails to compile, and `dist/` holds no Node code.
- `tsconfig.build.json` sets `stripInternal`, and each static that takes the parts of an engine is `@internal`, so the declarations leave those statics out. The `PARTS` brand of `EngineParts` keeps each such static behind the `Engine`: the key of the brand is local to `engine.ts`, so only an `Engine` builds the parts.
- `npm run smoke` loads every export that `package.json` names under a resolve hook that refuses each module of `wasm/` and `wasm-node/`, so an export that loads the glue as it imports fails the smoke. `Engine.load` is the one call that loads the glue.
- `npm run pack:check` asserts that the pack holds what `package.json` names. Every packed path sits under a `files` entry or is `package.json`, every `files` entry appears in the pack, and every packed output under the `outDir` of the build compiles from a source that `tsconfig.build.json` includes.

## Engine

`Engine.load(input?)` loads the wasm engine and resolves with an `Engine`, the proof that the module loaded. Every parse and constructor that calls into the module synchronously is a method of the `Engine`, and only `load` makes one, so the type checker refuses a call that needs the module before it loaded. The loader of the build imports the glue inside `load`, so the binary loads at `load` alone and an import of the package stays free of it.

```ts
import { Engine } from "@wahidgroup/tightbeam-ws-client";

// Node, or a page that serves the binary beside the glue:
const engine = await Engine.load();

// A custom host, a CSP-restricted page, or a worker with a compiled module:
const hosted = await Engine.load(wasmUrl);
const inWorker = await Engine.load(compiledModule);
```

The load rules:

- The `web` build starts the binary from `input`: a URL, a `Response`, the bytes, or a compiled `WebAssembly.Module`. Without `input`, it fetches the binary that sits beside its glue.
- The `nodejs` build reads its binary beside its glue as it loads, so it ignores `input`.
- Each loader starts its glue once per realm, and `Engine.load` builds one engine over it, both through one `Once`. Every later load therefore resolves the same `Engine` and leaves its `input` unread, and a failed load leaves the next call to load again.
- A failed load rejects with a `TightbeamTransportError` whose `code` is `EngineUnavailable`, and the failure of the platform or the glue is its `cause`. The browser e2e runs that failure and its retry, because only the web loader reads an input that can fail.
- A failed load leaves no engine, so its rejection takes the test that [Transport errors](#transport-errors) names for a caller with no engine.

The engine parses each value it owns once, in Rust, and hands back a handle, so the TypeScript layer keeps the proof and runs no second parser:

| Method                                                                      | Answers                                                                     | Refusal                             |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ----------------------------------- |
| `oid(dotted)`                                                               | An `Oid`, with `toString()` and `equals(other)`                             | `InvalidOid`                        |
| `salt(bytes)`                                                               | A `CommitmentSalt`: empty for a plain digest, or at least 16 octets         | `InvalidSaltLength`                 |
| `digestInfo(algorithmOid, digest)`                                          | A `DigestInfo`, which judges a recomputed digest in constant time           | `EmptyDigest`                       |
| `zstd(maxOutput?)`                                                          | A `ZstdView` of the engine zstd ([Compression](#compression))               | `InvalidMaxOutput`                  |
| `frame(der)`                                                                | A `Frame` ([Frame](#frame))                                                 | `SerializationError`, `EmptyDigest` |
| `frameBuilder(bytes)`, `messageBuilder(codec, message)`                     | A `FrameBuilder` ([Frame builder](#frame-builder))                          | None                                |
| `signingKey`, `verifyingKey`, `aes256Gcm`, `hpkeEncryptor`, `hpkeDecryptor` | The profile key classes ([Custom cryptography](#custom-cryptography))       | The engine code of the key rule     |
| `wrapping(inner)`, `opaque`, `framed`                                       | The codecs over the profile opaque body ([Typed messages](#typed-messages)) | None                                |
| `envelope(codec)`, `opening(salt, bodyDer)`                                 | [Envelopes](#envelopes) and [Detached commitments](#detached-commitments)   | `CommitmentSpent` for a spent salt  |
| `connect`, `connectMutual`, `connectCleartext`                              | A `TightbeamWsClient` ([Connectors](#connectors))                           | The option and identity faults      |

`engine.profile` holds the object identifiers of the tightbeam profile, read from the constants of `tightbeam-rs`, and `engine.sha3_256` is the profile hasher.

The handle rules:

- A method that receives an `Oid` or a `DigestInfo` borrows it for the call, and a holder that keeps one past the call keeps a copy of its own. `withContentOid`, `withPreviousHash`, `withMessageHasher`, `withWitnessHasher`, `withCompressor`, `engine.messageBuilder`, an envelope, and a pub/sub publish each copy the `Oid` or the `DigestInfo` they keep, so a free of the caller's handle leaves the holder its own. `withMessageHasher` and `engine.opening` take the salt of the `CommitmentSalt` they receive and leave the caller an empty shell ([Frame builder](#frame-builder), [Detached commitments](#detached-commitments)). A pub/sub subscription only decodes, so it holds the caller's codec and reads no handle of it. A `HeldCodec` holds the copy of its content type until its holder disposes it, and a later read of its `contentOid` refuses with `CodecReleased`.
- The realm owns `engine.profile`, `engine.sha3_256`, and one zstd handle, and lends each one as a view (`ProfileView`, `OidView`, `ZstdView`) with no `free` and no `[Symbol.dispose]`, so no caller can release a handle that every later build of the realm reads. `engine.zstd(maxOutput)` parses the ceiling once into a handle bound to it, and the `ZstdView` holds that handle, which the glue reclaims with the view.
- A frame keeps the wasm `DigestInfo` and `Oid` handles of the digests and the identifiers it decoded, and lends them as views too. `clone()` answers a handle the caller owns.

## Connectors

Every connection is a multiplexed tightbeam session, so one socket carries concurrent, bidirectional streams. Each connector is a method of the `Engine`, and it resolves once the session is ready, so a failed dial rejects the connect call and not the first emit. The rejection is `InvalidUrl` when the runtime refuses the url, `ConnectionClosed` when the socket of `connectCleartext` closes before it opens, `PeerClosedBeforeHandshake` when the socket of `connect` or `connectMutual` closes before the handshake completes, `InvalidCertificate` when the trust store refuses the pinned server certificate, such as one outside its validity on the host clock, or the code of the `tightbeam-rs` variant that refuses the handshake or the client identity, such as `Signer`.

| Connector                                | Session                                             | Stream caps                                                                                                                      |
| ---------------------------------------- | --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `connectCleartext(url, options?)`        | No handshake, no confidentiality, no integrity      | `streams` (default `DEFAULT_STREAM_CAP`) caps both directions. Both endpoints MUST configure the same value                      |
| `connect(url, serverCertDer, options?)`  | HPKE, with the server pinned by its DER certificate | `maxPeerStreams` (default `DEFAULT_STREAM_CAP`) caps server-initiated streams. The advertisement of the server caps client emits |
| `connectMutual(url, identity, options?)` | HPKE with mutual authentication                     | As `connect`                                                                                                                     |

The HPKE handshake also negotiates stream multiplexing (`transport-multiplex` of tightbeam, in the style of HTTP/2). A connection to a server that offers no multiplexing rejects with `InvalidState`.

```ts
// Server-authenticated:
const secure = await engine.connect(url, serverCertDer);

// Mutually authenticated (32-byte secp256k1 signing key):
const mutual = await engine.connectMutual(url, {
  serverCertDer,
  clientCertDer,
  clientKey: clientSigningKey,
});
```

### Identity faults

`connectMutual` takes the identity as named fields, so each certificate names its role at the call. It reads and parses the identity before any dial, so the caller may reuse its buffers at once. A malformed identity rejects with a `TightbeamTransportError`:

| Code                                            | Cause                                                                                                       |
| ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `InvalidBytes`                                  | A certificate is not a `Uint8Array`, or the raw scalar is a `Uint8Array` over a detached buffer             |
| `InvalidClientKey`                              | The key is neither a `Uint8Array` nor an object                                                             |
| `InvalidSigningKey`                             | The raw scalar is not 32 octets, or names no key                                                            |
| `InvalidCallback`, `InvalidOid`, `InvalidBytes` | A `TransportSigner` lacks `signPrehash`, names no OID, or holds a `publicKeyDer` that is not a `Uint8Array` |
| `InvalidCertificate`                            | A certificate is no DER certificate, named on `path`, as `connect` refuses its `serverCertDer`              |

The engine parses the options of every connector once, and its faults belong to the same family, a `TightbeamTransportError` that `engine.isTransportError` recognizes:

| Code                         | Cause                                                                                                      |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `InvalidConnectOptions`      | The options are not an object                                                                              |
| `InvalidSignal`              | The `signal` of the options, or of a call, is no `AbortSignal`                                             |
| `InvalidText`                | The url of a dial is not a string                                                                          |
| `InvalidCallback`            | `approveReceipt` is not a function                                                                         |
| `InvalidStreamCap`           | The cap is no whole number from 1 to 2^32-1, so zero, a fraction, a negative number, and `NaN` are refused |
| `SessionOfferRequiresMutual` | A connector other than `connectMutual` receives a session knob                                             |
| `InvalidBudgets`             | A budget in `budgets` is no whole, non-negative number                                                     |
| `InvalidBytes`               | `authorization` is not a `Uint8Array`                                                                      |
| `InvalidAuthorization`       | `authorization` does not fit an `OCTET STRING`                                                             |

### External signers

A certificate key in an external key store, such as WebAuthn, a wallet, or a KMS bridge, signs through a `TransportSigner` in place of the raw scalar. The handshake hands the signer the transcript prehash, so the private key stays outside wasm. The contract names no algorithm: the signer signs the prehash directly, with no second hash, and returns the signature encoding that the session profile verifies. Under the default-profile build that encoding is a secp256k1 signature as a DER `ECDSA-Sig-Value` (RFC 3279 § 2.2.3). A custom-profile build expects the encoding of its own profile ([The Browser Engine](ws-wasm.md#session-profiles)).

```ts
import type { TransportSigner } from "@wahidgroup/tightbeam-ws-client";

const signer: TransportSigner = {
  algorithmOid: "2.16.840.1.101.3.4.3.10", // ecdsa-with-SHA3-256
  publicKeyDer: spkiFromKeyStore,
  signPrehash: (prehash) => keyStore.signDigest(prehash),
};

const external = await engine.connectMutual(url, {
  serverCertDer,
  clientCertDer,
  clientKey: signer,
});
```

The engine parses the dotted `algorithmOid` of the signer once, as the dial begins.

The session profile is a compile-time choice, as for a native `tightbeam-rs` transport, and the default build runs HPKE over secp256k1, AES-256-GCM records, and SHA3-256 certificates. A deployment on another provider rebuilds the wasm layer against its own `CryptoProvider`. Frame-level cryptography stays caller-supplied under any profile.

### Session budgets

A metered session requests credits for each direction and settles the invoices of the server through `approveReceipt`. `budgets`, `authorization`, and `approveReceipt` belong to `MutualConnectOptions`, so `connect` and `connectCleartext` refuse them, and a JavaScript caller that passes them anyway is refused.

```ts
const metered = await engine.connectMutual(
  url,
  { serverCertDer, clientCertDer, clientKey: clientSigningKey },
  {
    budgets: { clientToServer: 4096, serverToClient: 4096 },
    approveReceipt: ({ receiptDer, challenge }) => {
      // Pay the invoice in `challenge`, or return undefined to refuse.
      return paymentFor(challenge);
    },
  },
);

metered.usableSendBudget; // epoch usable credits, or undefined when unmetered
metered.sessionReceiptDer; // dual-signed receipt DER, rotates on renewal
```

The client has no getter for a live remaining balance. A reconnect policy MUST treat the peer GoAway reasons `"budget-exhausted"` and `"settlement-failed"` as drain signals, with a backoff or a new authorization, and not as a protocol fault.

## Frame

`emit` resolves with the response `Frame`, or with `undefined` when the peer answers without a body. `engine.frame(der)` parses the bytes once, so a malformed frame throws `SerializationError` at construction. The one decode answers the fields and the preimages, so every getter reads decoded state. The engine decides the layer of the body at the parse: cleartext, compressed, or sealed. A `Frame` exposes:

- the typed body through `open(codec, { opener, inflator })`, the one decode of a body, which refuses a layer it holds no capability for with `OpaqueBody` and names the missing `opener` or `inflator` on `layer`. A capability that the frame needs no use of goes unused, so a cleartext frame opens under any options
- the carried body octets through `bodyDer`, and the raw frame through `toDer()`
- the metadata `version`, `id`, and `order`, and the V2+ and V3+ fields `priority`, `lifetime`, `previousFrame`, and `matrix` when present
- the security markers `signed`, `messageIntegrity`, `frameIntegrity`, and `confidential`, with their carried infos `signatureInfo`, `messageIntegrityInfo`, `frameIntegrityInfo`, and `confidentialityInfo`. A carried digest is an engine `DigestInfo`, every carried algorithm is an `Oid`, and the confidentiality info names the content type that its envelope authenticates as `contentOid`
- the methods of [Verification and decryption](#verification-and-decryption)

## Streams

Every `emit` opens its own stream, so concurrent emits interleave on the connection and each response correlates by stream ID. `serve` answers the streams that the server initiates.

```ts
const mux = await engine.connect(url, serverCertDer);

// Answer server-initiated streams. Callable repeatedly (the latest
// handler serves streams dispatched after the call), and handlers for
// distinct streams run concurrently.
mux.serve(async (request) => {
  const reply = await engine
    .frameBuilder(handle(await request.open(engine.opaque)))
    .withId("reply")
    .withOrder(1)
    .build();
  return reply; // or undefined/null for a bodiless acceptance
});

// Concurrent client-initiated streams over the one connection.
const [first, second] = await Promise.all([
  mux.emit(builtFirst),
  mux.emit(builtSecond),
]);

await mux.shutdown(); // GoAway, drain in-flight streams, stop
await mux.close();
```

The serve rules:

- A later `serve*` call in the same mode swaps the handler for the streams that dispatch after it, and a stream in flight finishes on the handler it started on. Handlers for distinct streams run concurrently.
- A handler of `serve`, `serveStreaming`, or `serveDuplex` refuses a stream by throwing `StreamRefusal` with the gRPC status code of its choice, as in `throw new StreamRefusal("NotFound", "no such order")`. `StreamRefusal.settlement` decides the status of every throw, so any other throw or rejection answers `Unknown`, a rethrown `TransportError` and a bare status name among them.
- A duplex handler resolves with a `TransitRefusal`, a status other than `Ok`, or with `undefined` for `Ok`.
- A server-initiated stream that arrives before `serve()` waits in a bounded queue, sized to the cap granted to the server. The handler serves the queue in order once it registers, so registration has no race.
- `serve`, `serveStreaming`, and `serveDuplex` each take `{ claim: "exclusive" }`, which claims dispatch, and `"shared"` is the default claim. Every later `serve*` call then throws a `TightbeamTransportError` whose `code` is `ServeDispatchClaimed`, so no stream reroutes in silence. An exclusive claim over a running shared handler throws `ServeDispatchShared`, and a claim that is neither label throws `InvalidServeClaim`. The pubsub `SubscriptionManager` claims its client this way, and application routes compose through its `fallback` option.
- `serve`, `serveStreaming`, and `serveDuplex` exclude one another on one client. The first call consumes the responder, and a later call in another mode throws a `TightbeamTransportError` whose `code` is `ServeModeConflict`.
- `maxConcurrentStreams` reports the negotiated local cap. After `shutdown`, a new emit rejects while the streams in flight drain.
- `emit` and `submitWork` take the slot of their stream before they return, so `hasPendingStreams` reads `true` at once after the call.
- The engine declares the handler of each `serve*` call and the `StreamRoute` a progressive handler reads, so the client and the engine share one declaration of each.

### Progressive bodies

Unary `emit` and `serve` stay the default. Progressive body I/O runs on the same Open, Data, and `last` records:

| Call                      | Direction                                                                        |
| ------------------------- | -------------------------------------------------------------------------------- |
| `openStream()`            | Push request chunks, then `close()` or `closeWith(chunk)` for a `Frame` response |
| `openDuplex()`            | Push request chunks, and consume `body` as an async iterable of reply chunks     |
| `serveStreaming(handler)` | Serve a progressive request body that the peer initiates                         |
| `serveDuplex(handler)`    | Serve a progressive duplex body that the peer initiates                          |

A push reaches the socket at once, so a duplex conversation that pushes and then awaits the next reply chunk makes progress. `closeWith(chunk)` flags that chunk `last` in one record, one record fewer than a push and a close.

The calls on one push half, the request half of a stream or the reply half of a served duplex stream, run in the order they were made, so a close waits for the pushes before it, and a push that waits holds a copy of its chunk. Each stream owns its wasm handle and releases it on every exit. A close consumes the handle, and the end of an `await using` scope cancels a stream that no close reached. After a close or a disposal, a push or a second close refuses with `StreamClosed`. A disposal of a request half also ends a push in flight with `StreamClosed`, even one that waits on the credit of the peer, and a push in flight on a reply half finishes.

The request half and the reply `body` of a duplex stream end apart: a close ends the request half, the body reads until the `last` chunk of the peer, and a `break` out of the body cancels the stream. A disposal of the body also cancels an opened stream, and a read that still waits ends at once with no chunk. A `serveStreaming` or `serveDuplex` handler receives a body and a reply half that the client frees once the handler settles.

A body frees its handle on the `last` chunk of the peer, on a failed read, on a `break` or a `return` of a `for await` loop, and as an `await using` scope ends, and each of these discards the chunks still to come. A body is single-use: every loop over it shares one generator, so overlapping loops queue their reads, and a `break` in any loop ends the body for every loop.

```ts
await using stream = client.openStream();
await stream.push(frameDer.subarray(0, mid));
const response = await stream.closeWith(frameDer.subarray(mid));

await using duplex = client.openDuplex();
await duplex.push(chunkA);
const first = await duplex.body[Symbol.asyncIterator]().next();
await duplex.closeWith(chunkB);
for await (const chunk of duplex.body) {
  handle(chunk);
}
```

### Routing

An application that serves more than one kind of stream demultiplexes by frame id. A `Router` binds each id prefix to a `Route`, a decoder and a handler typed by it, so the type checker holds the two to one message type. The longest matching prefix wins. For an id that no prefix matches, `dispatch` rejects with an `UnroutedTopicError`, which answers the stream with an `Unimplemented` status.

- `Route.of(codec, handler)` decodes a cleartext body.
- `Route.sealed(envelope, handler)` unwraps the frame under an [envelope](#envelopes) first, so a route that declares a signature refuses an unsigned or forged frame before its body decodes.

```ts
import { Route, Router } from "@wahidgroup/tightbeam-ws-client";

const chat = engine.envelope(ChatCodec).signed({ verifier: publisherKey });

const routes = new Router({
  "tick/": Route.of(TickCodec, (tick) => {
    store.applyTick(tick); // tick: Tick, inferred from the codec
    return undefined; // bodiless ack
  }),
  "chat/": Route.sealed(chat, async (message, request) => {
    store.appendChat(message); // the signature verified before decode
    return buildReceipt(request); // response frame
  }),
});

mux.serve((request) => routes.dispatch(request));
```

A server matches on the frame id prefix in its own stream handler before it decodes. The router only routes, so subscription semantics, ordering, and replay stay with the application.

## Cluster work submission

`submitWork(target, frame, options?)` routes a signed work frame through a tightbeam cluster gateway to the servlet type that the URN `target` names. It resolves with the complete response frame of the servlet. The gateway relays the request frame and the response frame with their bytes unchanged, so each side verifies the end-to-end signature of the other ([The WebSocket Transport](ws.md#cluster-work-plane)).

```ts
const work = await engine
  .frameBuilder(payload)
  .withId("job-42")
  .withOrder(1)
  .withSigner(signingKey)
  .build();

const served = await mux.submitWork("urn:tightbeam::servlet:work-probe", work);
await served.verify(signingKey.verifyingKey());
```

A gateway refusal rejects with `code === "WorkRefused"`, and a check of that code narrows the error to the member whose `status` carries the name of the transit status from the gRPC canonical registry, such as `"Unavailable"` for an unserved servlet type. An `AbortSignal` in the options cancels the submission as it cancels `emit`.

```ts
try {
  await mux.submitWork(target, work, { signal });
} catch (error) {
  if (engine.isTransportError(error) && error.code === "WorkRefused") {
    handleRefusal(error);
  }
}
```

## Cancellation

`emit` takes an `AbortSignal`. The abort cancels the stream: it frees the slot of the cap, tells the peer with a best-effort `MuxCancel`, and rejects the emit with the abort reason of the signal. A timeout is a signal.

```ts
const response = await mux.emit(built, {
  signal: AbortSignal.timeout(5_000),
});
```

The connectors take a signal the same way. The abort cancels the dial and the handshake, closes the socket, and rejects with the abort reason of the signal.

```ts
const mux = await engine.connect(url, serverCertDer, {
  signal: AbortSignal.timeout(5_000),
});
```

## Connection lifecycle

Every client exposes `closed`, a promise that resolves with the `{ code, reason, wasClean }` of the close frame on every close path, and a `readyState` getter with the WebSocket constants.

```ts
async function watchClose(client: TightbeamWsClient): Promise<void> {
  const info = await client.closed;
  if (!info.wasClean) {
    scheduleReconnect(info.code);
  }
}

void watchClose(client);
```

### Close and drain

- `close()` closes the socket, releases the wasm resources of the client, and resolves once the socket has closed. It is idempotent, and it is safe with emits in flight.
- `shutdown()` drains the session gracefully with a GoAway. Call it before `close()`.
- `shutdownWith(reason)` drains and advertises why. The reason is a label, `"shutdown"`, `"protocol-error"`, `"enhance-your-calm"`, `"budget-exhausted"`, or `"settlement-failed"`, or a numeric code that the application defines and that the peer reads back through its own GoAway surface.
- After `close()`, an async operation rejects with `ConnectionClosed`, and a synchronous one throws it: `serve`, `serveStreaming`, `serveDuplex`, `openStream`, `openStreamTo`, `openDuplex`, and `openDuplexTo`. `closed`, `readyState`, and the GoAway getters stay readable for a reconnect policy.

### Lifetime

A client lives until `close()`, the close of the peer, or a GoAway. Garbage collection is a backstop for a client that the application leaked. A client declared with `await using` closes as its scope ends.

A `using` or `await using` declaration needs `Symbol.dispose` and `Symbol.asyncDispose` at runtime, which Node 24 and current browsers define. The client frees each handle it borrows for one call through `using` on its own paths, so it needs `Symbol.dispose` at runtime too.

```ts
await using client = await engine.connectCleartext(url);
client.serve((request) => routes.dispatch(request));
```

### GoAway

When the peer drains the session, the client records why. `goawayReason` reads the reason from the GoAway of the peer, and it reads `undefined` while the connection is live or after a local shutdown. `goawayCode` exposes the raw numeric code of a reason that the application defines, which `goawayReason` labels `"application"`.

### Reconnection

Reconnection belongs to the application. The client supplies the inputs of the policy, `closed`, `goawayReason`, and `wasClean`, and only the application knows what state to replay. The loop branches on the reason, backs off, and registers `serve` again on each connection.

```ts
async function connectLoop(
  handle: (client: TightbeamWsClient) => void,
): Promise<void> {
  let delay = 500;

  for (;;) {
    let client: TightbeamWsClient;
    try {
      client = await engine.connect(url, serverCertDer, {
        signal: AbortSignal.timeout(5_000),
      });
    } catch {
      await sleep((delay = Math.min(delay * 2, 30_000)));
      continue;
    }

    delay = 500;

    /*
     * serve is per connection: re-register handlers here.
     */
    handle(client);

    const info = await client.closed;

    /*
     * Free the dead connection's wasm resources. The GoAway getters
     * stay readable from the close snapshot.
     */
    await client.close();

    switch (client.goawayReason) {
      case "shutdown":
        break; // orderly drain (rotation, redeploy): go right back
      case "enhance-your-calm":
        await sleep((delay = Math.min(delay * 2, 30_000)));
        break; // the server asked for calm
      case "protocol-error":
        report(info);
        return; // a bug, not a transient fault
      default:
        await sleep(delay); // no GoAway: connection loss
    }
  }
}
```

## Transport errors

A transport failure rejects as a `TransportError`, an `Error` named `TightbeamTransportError` that carries a stable `code`. `TransportError` is a union with one member per family of its code, so a check of `code` narrows to the member that carries the detail of that code. `engine.isTransportError` narrows an unknown value once it checks the name brand, the code, and the detail, so it answers `false` for a forged error with an unknown code or a missing detail. A lost connection narrows through `engine.isTransportError`, and its `code` is `ConnectionClosed`. Before an engine exists, the one test is `error instanceof ClientTransportError && error.code === "EngineUnavailable"`, because a failed `Engine.load` is the one rejection that reaches a caller with no engine. `engine.isTransportError` tests every other case.

Each code has one declaration in one of four families:

| Family          | Declared in                                                                 | The code names                                                                                                     |
| --------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `RefusalCode`   | `fault.rs` of the engine, generated into the declarations of the wasm build | A value the engine refuses, such as `InvalidBytes`, `InvalidMatrixDimension`, or `CommitmentSpent`                 |
| `TransportCode` | `fault.rs` of the engine, generated the same way                            | An engine or transport error of `tightbeam-rs`, by its variant, such as `ConnectionClosed` or `SerializationError` |
| `TransitCode`   | `fault.rs` of the engine, generated the same way                            | A peer refusal, by its gRPC canonical status other than `Ok`, such as `Unavailable`                                |
| `ClientCode`    | `errors.ts` of the client                                                   | A failure the client decides itself, such as `KeyReleased`, `EngineUnavailable`, or `EnvelopeUnsigned`             |

Two codes carry a detail:

- `WorkRefused`, a refused work submission, carries its `TransitCode` on `status`.
- `OpaqueBody`, a body that a read cannot reverse, carries the capability it lacks on `layer`: `opener` or `inflator`.

A refusal of one field names it on `path`, such as `matrix.n`. `ClientTransportError` has a private constructor, and one named static builds each code it decides. `ClientTransportError.opaqueBody` builds the refusal of a body read under the `OpaqueBody` code of the engine, so a body refuses with one code on every read.

```ts
try {
  await mux.emit(built);
} catch (error) {
  if (engine.isTransportError(error) && error.code === "Draining") {
    // GoAway received on a live connection: reconnect before emitting again.
  }
}
```

A local condition carries its variant name. A peer refusal carries a gRPC canonical status name, with the retry contract that the name defines:

| Code                                                      | Source | Meaning                                                               |
| --------------------------------------------------------- | ------ | --------------------------------------------------------------------- |
| `ConnectionClosed`                                        | Local  | The connection is gone, which outranks `Draining` after `shutdown()`  |
| `Draining`                                                | Local  | Either side sent a GoAway, or the stream IDs ran out. Reconnect first |
| `StreamsExhausted`                                        | Local  | The local stream cap is full. Retry after a response frees a slot     |
| `OpaqueBody`                                              | Local  | A body read lacks the `opener` or `inflator` named on `layer`         |
| `ResourceExhausted`                                       | Peer   | The peer is at capacity. Retry with backoff                           |
| `Unavailable`                                             | Peer   | The peer is draining. Retry with backoff                              |
| `Unimplemented`                                           | Peer   | Nothing serves the topic. Do not retry                                |
| `Unknown`                                                 | Peer   | A peer handler failed without a classification                        |
| `DeadlineExceeded`, `Unauthenticated`, `PermissionDenied` | Peer   | A gate policy refused the stream                                      |

`waitForStreamSlot()` waits for admission in place of a blind retry of `StreamsExhausted`. It resolves once a new stream would be admitted. It rejects with `Draining` or `ConnectionClosed` once no stream will ever be admitted again, and with the abort reason of its `{ signal }` option when the caller gives up first. Like `hasStreamHeadroom`, it is advisory: a concurrent emit can take the slot between the wake and the use, so the caller keeps its rejection handling.

```ts
await mux.waitForStreamSlot({ signal: AbortSignal.timeout(5_000) });
const response = await mux.emit(built);
```

## Keepalive

A native tightbeam server runs each read under its operation timeout, 30 seconds by default (`DEFAULT_OPERATION_TIMEOUT`), and ends a session that sends nothing for that long. The client pings its peer every 10 seconds, a third of that timeout (`KEEPALIVE_PROBES_PER_DEADLINE`), so an idle session stays open with no application code.

`ping()` is the same liveness probe at the protocol level, the analog of RFC 9113 § 6.7, for an application that measures the link itself. It resolves when the peer acknowledges. It allocates no stream, and no application handler runs on the peer. Browsers answer the pings of the WebSocket protocol on their own, and this probe covers the application level, where silence otherwise looks the same as idleness.

```ts
await mux.ping({ signal: AbortSignal.timeout(5_000) });
```

## Frame builder

A builder begins with its body: `engine.frameBuilder(bytes)` for raw bytes under the profile opaque wrapper, or `engine.messageBuilder(codec, message)` for a typed message. Every `with*` call returns a new immutable builder, and `build()` exists once `withId` named the frame, as `tightbeam-rs` refuses a frame with no id. `build()` resolves with the assembled `Frame`. Capability objects select the algorithms.

```ts
const signingKey = engine.signingKey(rawScalar);

const built = await engine
  .frameBuilder(body)
  .withId("doc-42")
  .withOrder(1n)
  .withPriority(engine.MessagePriority.LowLatency) // V2+
  .withLifetime(60) // V2+
  .withPreviousHash(engine.digestInfo(engine.oid(digestOid), digest)) // V2+
  .withMatrix(2, new Uint8Array([0, 1, 1, 0])) // V3+
  .withMessageHasher(engine.sha3_256, engine.salt(salt)) // V1+: body commitment, hidden by a salt of 16+ octets
  .withWitnessHasher(engine.sha3_256) // V1+: frame integrity
  .withEncryptor(engine.aes256Gcm({ key, keyId })) // V1+: body encryption
  .withSigner(signingKey) // V1+: secp256k1 signature
  .assertVersion(engine.Version.V3) // fail the build unless it lands on V3
  .build();
```

The build rules:

- The wasm engine decides the version floor from every requested field, as `GatedField::since` does in `tightbeam-rs`, or it honors a pin from `withVersion(engine.Version.V2)`. A pin below the floor rejects with an error whose `code` is `UnsupportedField`. `assertVersion` rejects another version with `VersionMismatch`. The engine decides both as the structure assembles, before any hasher, encryptor, or signatory acts.
- A value with a rule parses once, in the engine, before it reaches the builder: `engine.oid`, `engine.salt`, and `engine.digestInfo` throw a `TightbeamTransportError` at the call. A `Hasher` and a `BodyCompressor` name their algorithm by such an `Oid`.
- The engine parses the order, the lifetime, the version, and the priority as the build installs them. The order and the lifetime take a whole number or a `bigint` from 0 to 2^64-1. A value outside the range, or one of another type, rejects the build with `InvalidOrder`, `InvalidLifetime`, `InvalidVersion`, or `InvalidPriority`.
- `withMessageHasher(hasher, salt?)` and `withWitnessHasher(hasher)` take any `Hasher`. The profile hasher is `engine.sha3_256`. Without a salt, the message commitment is a plain digest of the body.
- `withContentOid(oid)` and `withPreviousHash(parent)` hold a copy of the handle they receive, and the builder copies the content type a codec declares, so a free of the caller's handle leaves the build its own. Every handle a build makes, such as the digest of each integrity step, frees within the build.
- `withMessageHasher` takes its salt after it copies the algorithm of the hasher, so a refused hasher leaves the salt with the caller. A call that takes the salt leaves the caller an empty shell that frees as any handle does, and a disposal of that shell leaves the builder its salt. A salt commits one frame, so a committed builder, and every builder made from it, builds once. A second build, or a second take of the same shell, rejects with `CommitmentSpent`.
- A build holds its salt from its start, so a concurrent build rejects with `CommitmentSpent` before its signer prompts. A build that a layer refuses gives the salt back to a retry.
- `withEncryptor` takes any `BodyEncryptor`, and the frame has one body-encryption slot. The profile offers a symmetric cipher, `engine.aes256Gcm({ key, keyId })`, which every holder of the shared key opens under one `keyId`. It also offers an asymmetric encryptor to a recipient, `engine.hpkeEncryptor(recipientPublicKey)`, which the recipient secret opens. The encryptor seals the body as the content type that the builder or the codec names, and as `id-data` without one.
- A field the engine refuses rejects with the engine code and the field on `path`, such as `InvalidMatrixDimension` at `matrix.n`. An untyped caller that builds without an id meets `BuildError`.
- The builder runs its steps in this order: the message commitment, the compression, the encryption, the frame integrity, and the signature.

## Typed messages

The protocol treats the frame body as opaque DER, and what the body encodes is a contract between the peers. A `MessageCodec<T>` pairs a TypeScript type with that contract: `encode` produces the body DER, and `decode` parses and validates it at runtime. Each call site therefore reads a typed payload, and the encoded frame stays free of any schema.

`engine.wrapping(inner)` lifts a byte-level serialization, such as JSON, CBOR, or protobuf, into a codec by wrapping it in the profile opaque body:

```ts
import type { MessageCodec } from "@wahidgroup/tightbeam-ws-client";

interface ChatMessage {
  author: string;
  text: string;
}

const Chat: MessageCodec<ChatMessage> = engine.wrapping({
  encode: (message) => new TextEncoder().encode(JSON.stringify(message)),
  decode: (payload) => {
    const parsed = JSON.parse(new TextDecoder().decode(payload));
    // Runtime validation is the codec's responsibility.
    if (
      typeof parsed?.author !== "string" ||
      typeof parsed?.text !== "string"
    ) {
      throw new Error("not a ChatMessage");
    }
    return parsed;
  },
});

const built = await engine
  .messageBuilder(Chat, { author: "ada", text: "hello" })
  .withId("chat-1")
  .build();

const reply = await client.emit(built);
const message = await reply?.open(Chat); // ChatMessage
```

- A peer can expect one ASN.1 `Message` schema, such as a Rust `der::Sequence`. Its codec is a `MessageCodec` that the application implements with an ASN.1 library, or one that `tightbeam-asn-emit` generates ([The ASN.1 Codec Bridge](asn.md)). The builder installs the DER that the codec emits.
- `engine.frameBuilder(bytes)` is shorthand for `engine.messageBuilder(engine.opaque, bytes)`, raw bytes in the opaque wrapper.
- The optional `contentOid` of a codec is an `Oid`, and it goes into the confidentiality info when the body is sealed.
- `engine.framed` is the codec of a frame in a frame: a message that is itself a full tightbeam frame, carried with its bytes unchanged inside the body of another frame. Pub/sub topics use it to relay a frame that a publisher signed or sealed through the registry, so frame-level security holds end to end through the broker.

## Custom cryptography

Each digest and compression capability pairs the operation with the `Oid` that the frame records, so implementations from any library or language interchange. A cipher names its algorithm in the envelope it writes. A signer signs the profile signature, which the engine fixes, so a signer names no OID and only signs the prehash it receives. The profile ships wasm-backed implementations of SHA3-256, secp256k1 ECDSA, AES-256-GCM, HPKE, and zstd, and every other algorithm plugs in through the same interfaces.

| Interface                        | Contract                                                                                                                                 |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `Hasher`                         | `algorithmOid`, an `Oid`, and `digest(data)`                                                                                             |
| `FrameVerifier`                  | `verifyFrame(frame)`, which throws or rejects when the signature does not verify, so an asynchronous verifier such as WebCrypto plugs in |
| `Signatory`                      | `signerId()`, the subject key identifier of its certificate, and `signPrehash(prehash)`                                                  |
| `BodyEncryptor`                  | `encrypt(bodyDer, contentOid)`, which seals the body DER or its compressed octets, and resolves with `{ envelopeDer, ciphertext }`       |
| `BodyDecryptor`                  | `decrypt(sealed)`, which receives the carried pieces and resolves with the octets that were sealed                                       |
| `BodyCompressor`, `BodyInflator` | [Compression](#compression)                                                                                                              |

Each operation of these interfaces, of `MessageCodec` and `PayloadCodec`, and of `TransportSigner` that takes an input is a readonly function property. Under `strictFunctionTypes`, which `strict` sets, the type checker therefore refuses an implementation whose parameter admits less than the operation declares. A throw or a rejection from an operation fails the call that reached it, such as the build, `Frame.open`, or the dial.

The `envelopeDer` of an encrypted body is a DER CMS `AuthEnvelopedData` (RFC 5083) with its content detached, and it names the content-encryption algorithm. A profile decryptor reads the algorithm and the key from the envelope, and the engine rejects an envelope that the key refuses, such as one that names another key or whose tag fails, with a `TightbeamTransportError`. `engine.profile` lends the profile identifiers as views.

```ts
import type { Hasher, Signatory } from "@wahidgroup/tightbeam-ws-client";
import { sha3_512 } from "@noble/hashes/sha3.js";

// Any digest: implement Hasher with the OID peers should recompute under.
const sha3_512Hasher: Hasher = {
  algorithmOid: engine.oid("2.16.840.1.101.3.4.2.10"),
  digest: async (data) => sha3_512(data),
};

// Any signer of the profile signature: the builder hands the implementation the digest of the frame's CMS signed
// attributes and attaches the returned DER signature, so an external signer's private key stays outside wasm memory
// (wallets, passkeys, HSMs, remote KMS).
const walletSigner: Signatory = {
  signerId: () => walletKeyId, // subject key identifier of its certificate
  signPrehash: async (prehash) => wallet.signDigest(prehash),
};

const built = await engine
  .frameBuilder(body)
  .withId("wallet-1")
  .withWitnessHasher(sha3_512Hasher)
  .withSigner(walletSigner)
  .build();
```

The profile key classes, `Secp256k1SigningKey`, `Secp256k1VerifyingKey`, `Aes256Gcm`, `HpkeEncryptor`, and `HpkeDecryptor`, come from `engine.signingKey`, `engine.verifyingKey`, `engine.aes256Gcm`, `engine.hpkeEncryptor`, and `engine.hpkeDecryptor`. Each one owns a wasm handle and releases it through `[Symbol.dispose]`, so a `using` declaration frees the key as its scope ends:

- A release wipes the wasm copy of a secret at once, or when a decryption already in flight settles.
- The release is idempotent, and every later call on the key refuses with `KeyReleased`. A method that answers a promise, such as `encrypt`, `decrypt`, or `signPrehash`, rejects with it, so each one fails on one channel.
- A signing key derives its verifying key once and lends that one key from `verifyingKey()` as a `VerifyingKeyView`. The view has no release of its own, and the signing key frees it with itself.

## Compression

A `BodyCompressor` shrinks the body DER and names its algorithm once, as its `algorithmOid`, and a `BodyInflator` reverses it in the shape of the `Inflator` of `tightbeam-rs`: its `algorithmOid`, `admitsParameters(parametersDer?)`, and `decompress(data)`. `Frame.open` checks that the inflator reverses the algorithm of the frame and admits its parameters before it decrypts anything. The builder compresses after the message commitment, which covers the uncompressed body, and before the encryption, so peers encrypt the compressed bytes. That order is the order of `tightbeam-rs`.

`engine.zstd(maxOutput?)` lends the profile compression of the realm at that ceiling: one zstd frame under `engine.profile.zstd`, compatible in its encoded form with the `ZstdCompression` of `tightbeam-rs`. The engine runs it in Rust, so the browser admits what a native peer admits ([The Browser Engine](ws-wasm.md#compression)):

- no parameters, or a compression level that libzstd accepts
- one frame and no octet after it: a zstd frame, or a skippable frame that inflates to no octets. A trailing skippable frame or a seek table rejects
- a decompressed size within the output cap, 16 MiB by default as in `tightbeam-rs`, which `maxOutput` tunes. The output stays within the cap
- a declared window within the same cap, rounded up to a power of two as `tightbeam-rs` rounds it

```ts
const zstd = engine.zstd();

const built = await engine
  .frameBuilder(body)
  .withId("packed-1")
  .withCompressor(zstd)
  .build();

// Cleartext + compressed: name the inflator.
const message = await received.open(engine.opaque, { inflator: zstd });

// Compressed then sealed: name both capabilities.
const opened = await sealed.open(engine.opaque, {
  opener: cipher,
  inflator: zstd,
});
```

A refusal carries one code on every path:

- `zstd.decompress(data)`, which `Frame.open` calls, throws a `TightbeamTransportError` whose `code` names the refusal: `WindowTooLarge`, `OutputLimitExceeded`, `Truncated`, `TrailingBytes`, `Stalled`, or `Malformed`.
- An inflator that names another algorithm than the compactness info, or refuses its parameters, rejects with `CompactnessRefused` at `compactness` before any decryption.
- `engine.zstd(maxOutput)` throws `InvalidMaxOutput` for a cap that is no whole, non-negative number.

Any other algorithm works through the same interfaces. The platform-native `CompressionStream` gives a zlib alternative with no dependency (`engine.profile.zlib`, RFC 3274):

```ts
import type {
  BodyCompressor,
  BodyInflator,
  CompressedBody,
} from "@wahidgroup/tightbeam-ws-client";

async function pump(
  transform: ReadableWritablePair<Uint8Array, BufferSource>,
  bytes: Uint8Array,
): Promise<Uint8Array> {
  const source = new Blob([bytes.slice()]).stream().pipeThrough(transform);
  return new Uint8Array(await new Response(source).arrayBuffer());
}

const zlibOid = engine.profile.zlib;
const zlib: BodyCompressor & BodyInflator = {
  algorithmOid: zlibOid,
  compress: async (bodyDer) => ({
    data: await pump(new CompressionStream("deflate"), bodyDer),
  }),
  admitsParameters: (parametersDer) => parametersDer === undefined,
  decompress: (data) => pump(new DecompressionStream("deflate"), data),
};

const built = await engine
  .frameBuilder(body)
  .withId("zlib-1")
  .withCompressor(zlib)
  .build();
```

A compressor names its algorithm once, as `algorithmOid`, as an inflator does. `withCompressor` copies that `Oid`, so one compressor serves every build, and the compressor keeps its own handle.

A compressed frame reports `compressed: true` and carries `compactnessInfo`, `{ algorithmOid, parametersDer?, contentOid }`, with each algorithm an `OidView` that the frame owns. A read without an inflator rejects with `OpaqueBody`, which names `inflator` on `layer`. An inflator SHOULD cap its output size, because a body from the peer can be a decompression bomb (CWE-409).

## Verification and decryption

The `Frame` carries its own verification. A verdict is an `IntegrityVerdict` of `tightbeam-rs` by its label, one of `"verified"`, `"absent"`, `"algorithm-mismatch"`, and `"mismatch"`, and the engine `DigestInfo` that the frame carries judges every one but `"absent"`. The verdict methods recompute under any `Hasher`, and the profile SHA3-256 is the default. An external verifier checks `signatureInfo.signature`, a DER `ECDSA-Sig-Value`, over `signaturePrehash()` with its own library.

```ts
await response.verify(signingKey.verifyingKey()); // the profile scheme rejects an invalid signature
await response.frameIntegrityVerdict(); // "verified" | "absent" | ...
await response.frameIntegrityVerdict(sha3_512Hasher); // under your own hasher
await response.messageCommitmentVerdict(engine.salt(salt)); // checks the body commitment

// Open an encrypted body with the matching cipher or recipient secret,
// decoding the plaintext under any codec (engine.opaque for raw bytes):
await response.open(engine.opaque, {
  opener: engine.aes256Gcm({ key, keyId }),
});
await response.open(Chat, {
  opener: engine.hpkeDecryptor(recipientSecretKey),
});

// Raw surfaces for external verification:
response.tbs(); // to-be-signed bytes
response.signaturePrehash(); // digest the signature verifies over
response.witnessInput(); // frame-integrity preimage
response.signatureInfo; // { algorithmOid, digestAlgorithmOid, signature }
```

## Envelopes

The calls above work on one frame. A conversation applies the same layers to every frame in both directions, and `engine.envelope(codec)` declares them once:

- `frame(message)` begins a builder with the layers applied.
- `unwrap(frame)` reverses the layers in protocol order, verify, open, inflate, and decode, and it enforces them. A received frame that lacks a declared signature or seal rejects with `EnvelopeUnsigned` or `EnvelopeCleartext`, so a peer cannot downgrade the conversation by omission.

```ts
const topic = engine.aes256Gcm({ key: topicKey, keyId: topicKeyId });
const notes = engine
  .envelope(Notes) // any MessageCodec<T>
  .signed({ signer: signingKey, verifier: signingKey.verifyingKey() })
  .sealed({ sealer: topic, opener: topic })
  .compressed({ compressor: engine.zstd(), inflator: engine.zstd() });

// Sender: the layers are already applied, the metadata stays yours.
const sent = await notes.frame(note).withId("note-1").withOrder(1n).build();

// Receiver: a Note, or a rejection.
const received = await notes.unwrap(relayed);
```

An envelope is immutable, and every frame of the conversation reuses it. Each declaration names the halves that the party holds, each in a field of its own name:

- `signed({ signer, verifier })`: `frame()` signs with `signer`, and `unwrap` requires a signature that verifies under `verifier`. A wallet, a passkey, or an HSM that cannot verify names `signer` alone, and a party without the signing key names `verifier` alone.
- `sealed({ sealer, opener })` takes a `BodyEncryptor` and a `BodyDecryptor`, and `Aes256Gcm` is both. An HPKE pair splits: the publisher declares `sealed({ sealer: engine.hpkeEncryptor(recipientPublic) })`, and the recipient declares `sealed({ opener: engine.hpkeDecryptor(recipientSecret) })`.
- `compressed({ compressor, inflator })` is a transport optimization and no security property, so an uncompressed received frame still unwraps.

The type `Envelope<T, Sends, Receives>` records whether every declared layer holds its send half and its receive half, so `frame()` exists only on an envelope that can sign and seal what it sends, and `unwrap()` only on one that can verify and open what it receives. The type checker therefore refuses a `frame()` call on a verify-only envelope. The published declarations key that record with a symbol, so the guarantee holds for every consumer of the package. An untyped caller meets `EnvelopeSender` or `EnvelopeReceiver` instead.

A one-sided party composes only its half:

```ts
// A subscriber that verifies and opens, and holds no half that signs or sends.
const readOnly = engine
  .envelope(Notes)
  .signed({ verifier: publisherKey })
  .sealed({ opener: engine.hpkeDecryptor(recipientSecret) });
```

The `authenticated` and `confidential` getters report the declarations. `unwrap` enforces them, so they hold for every unwrapped frame, and a UI shows them as badges with no probe of each frame. The pubsub manager accepts an envelope wherever it accepts a codec, and it publishes frame in frame so the layers hold end to end through the broker ([The Subscription Client](pubsub-client.md#payload-shapes)).

## Detached commitments

A commitment can also live outside a frame, as `tightbeam::crypto::commitment::Opening` does in Rust. A prover publishes a hiding digest now and discloses the opening `(salt, body)` later, and any holder of the digest verifies the disclosure. The preimage is the one that the message commitment of a frame uses, so a detached commitment and one that a frame carries interchange:

- An empty salt binds the body, under the preimage `mode || body`.
- A salt of at least 16 octets binds and hides the body, under the preimage `mode || len(salt) || salt || body`.

A plain digest of the body binds it alone, because a brute force over candidate bodies recovers a low-entropy body from its published digest. A secret salt hides the body until the opening `(salt, body)` is disclosed.

The mode octet is `0x00` for an empty salt and `0x01` for a hiding salt, and `len(salt)` is an 8-octet big-endian length. The mode octet keeps a commitment under an empty salt apart from the plain digest of the body, so neither verifies as the other.

```ts
// Prover: publish `commitment`, keep the salt and the body secret until disclosure.
const secret = crypto.getRandomValues(new Uint8Array(32)); // a high-entropy salt hides the body
using proving = engine.opening(engine.salt(secret), bodyDer);
const commitment = await proving.commit(engine.sha3_256);

// Verifier: reassemble the disclosed salt and body, and check in constant time.
using disclosed = engine.opening(engine.salt(secret), bodyDer);
const verified = await disclosed.verify(engine.sha3_256, commitment);
```

`verify` resolves with `false` on an algorithm mismatch or a digest mismatch. `commitment` is an engine `DigestInfo`, the one owner that judges a recomputed digest against a carried one. An opening copies the body before it takes its salt, so a refused copy leaves the salt with the caller. An opening that takes the salt leaves the caller an empty shell, and it frees the salt as its `using` scope ends. The salt is a `CommitmentSalt` handle and the body is DER octets, so the type checker refuses a call that swaps them. Any `Hasher` works on both sides.

## Sources

- RFC 6455, The WebSocket Protocol: <https://datatracker.ietf.org/doc/html/rfc6455>
- RFC 9113, HTTP/2, § 6.7 PING: <https://datatracker.ietf.org/doc/html/rfc9113#section-6.7>
- RFC 3279, Algorithms and Identifiers for the Internet X.509 PKI, § 2.2.3 ECDSA signatures: <https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3>
- RFC 5083, CMS Authenticated-Enveloped-Data Content Type: <https://datatracker.ietf.org/doc/html/rfc5083>
- RFC 9180, Hybrid Public Key Encryption: <https://datatracker.ietf.org/doc/html/rfc9180>
- RFC 9629, Using Key Encapsulation Mechanism (KEM) Algorithms in the Cryptographic Message Syntax (CMS): <https://datatracker.ietf.org/doc/html/rfc9629>
- RFC 3274, Compressed Data Content Type for CMS: <https://datatracker.ietf.org/doc/html/rfc3274>
- RFC 8878, Zstandard Compression and the application/zstd Media Type: <https://datatracker.ietf.org/doc/html/rfc8878>
- CWE-409, Improper Handling of Highly Compressed Data: <https://cwe.mitre.org/data/definitions/409.html>
- `google.rpc.Code`, the gRPC canonical status codes: <https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto>
