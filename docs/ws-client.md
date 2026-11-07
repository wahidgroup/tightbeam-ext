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

It drills down from the [tightbeam-ws-client README](../ws/client/README.md) for engineers who build on the client or review it. The README holds what each part is for and the standards it follows. The wasm engine under the client has its own page, [The Browser Engine](ws-wasm.md). Every sample on this page compiles as the case of [`ws/client/src/docs.test.ts`](../ws/client/src/docs.test.ts) that names its section.

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

Two wasm bundles ship in the package, a `web` build and a `nodejs` build, and each has its own engine loader. The `#engine` entry of the package `imports` map selects the loader of the `nodejs` build under the `node` condition and the loader of the `web` build otherwise. The `#wasm` entry names the types of the glue alone, so the loaders are the one way to the glue as a value. Node 24 and later supply a global `WebSocket`, so Node needs no shim.

The client keeps this surface of `tightbeam-rs` under the same names:

| Part      | Shared surface                                                                                                                                                                                |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Builder   | `withSigner`, `withEncryptor`, `withMessageHasher`, and the version floor rules of `GatedField::since`                                                                                        |
| `Frame`   | `verify`, `frameIntegrityVerdict`, `messageCommitmentVerdict`, and the enums `Version` and `MessagePriority` with the same ordinals, which `engine.Version` and `engine.MessagePriority` hold |
| Transport | Multiplexed bidirectional streams, HPKE sessions, GoAway reasons, and the gRPC status codes of a refusal                                                                                      |

`assertVersion` belongs to the client alone. `tightbeam-rs` takes the version when the builder starts, through `FrameBuilder::from(Version)` or `compose!`.

## Engine

`TightbeamWsClient.init(input?)` loads the wasm engine and resolves with an `Engine`, the proof that the module loaded. Every parse and constructor that calls into the module synchronously is a method of the `Engine`, and only `init` makes one, so a call that needs the module before it loaded does not type-check. The loader of the build imports the glue inside `init`, so the binary loads at `init` alone and an import of the package stays free of it.

```ts
import { TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";

// Node, or a page that serves the binary beside the glue:
const engine = await TightbeamWsClient.init();

// A custom host, a CSP-restricted page, or a worker with a compiled module:
const hosted = await TightbeamWsClient.init(wasmUrl);
const inWorker = await TightbeamWsClient.init(compiledModule);
```

The load rules:

- The `web` build starts the binary from `input`: a URL, a `Response`, the bytes, or a compiled `WebAssembly.Module`. Without `input`, it fetches the binary that sits beside its glue.
- The `nodejs` build reads its binary beside its glue as it loads, so it ignores `input`.
- A failed load rejects with a `TightbeamTransportError` whose `code` is `EngineUnavailable`, and the failure of the platform or the glue is its `cause`.

The engine parses each value it owns once, in Rust, and hands back a handle, so the TypeScript layer keeps the proof and runs no second parser:

| Method                                                                      | Answers                                                                     | Refusal                            |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ---------------------------------- |
| `oid(dotted)`                                                               | An `Oid`, with `toString()` and `equals(other)`                             | `InvalidOid`                       |
| `salt(bytes)`                                                               | A `CommitmentSalt`: empty for a plain digest, or at least 16 octets         | `InvalidSaltLength`                |
| `digestInfo(algorithmOid, digest)`                                          | A `DigestInfo`, which judges a recomputed digest in constant time           | `EmptyDigest`                      |
| `zstd(maxOutput?)`                                                          | A `ZstdView` of the engine zstd ([Compression](#compression))               | `InvalidMaxOutput`                 |
| `frame(der)`                                                                | A `Frame` ([Frame](#frame))                                                 | `SerializationError`               |
| `frameBuilder(message?)`                                                    | A `FrameBuilder` ([Frame builder](#frame-builder))                          | None                               |
| `signingKey`, `verifyingKey`, `aes256Gcm`, `hpkeEncryptor`, `hpkeDecryptor` | The profile key classes ([Custom cryptography](#custom-cryptography))       | The engine code of the key rule    |
| `wrapping(inner)`, `opaque`, `framed`                                       | The codecs over the profile opaque body ([Typed messages](#typed-messages)) | None                               |
| `envelope(codec)`, `opening(salt, bodyDer)`                                 | [Envelopes](#envelopes) and [Detached commitments](#detached-commitments)   | `CommitmentSpent` for a spent salt |
| `connect`, `connectMutual`, `connectCleartext`                              | A `TightbeamWsClient` ([Connectors](#connectors))                           | The option and identity faults     |

`engine.profile` holds the object identifiers of the tightbeam profile, read from the constants of `tightbeam-rs`, and `engine.sha3_256` is the profile hasher.

The handle rules:

- A method that receives a handle borrows it for the call, and a holder that keeps one past the call keeps a copy of its own. `withContentOid`, `withPreviousHash`, `withMessageHasher`, `withWitnessHasher`, `withCompressor`, an envelope, and a pub/sub publish each copy the `Oid` they keep, so a free of the caller's handle leaves the holder its own. A pub/sub subscription only decodes, so it holds the caller's codec and reads no handle of it. A `HeldCodec` holds the copy of its content type until its holder disposes it, and a later read of its `contentOid` refuses with `CodecReleased`.
- The realm owns `engine.profile`, `engine.sha3_256`, and one zstd handle, and lends each one as a view (`ProfileView`, `OidView`, `ZstdView`) with no `free` and no `[Symbol.dispose]`, so no caller can release a handle that every later build of the realm reads. The glue builds the zstd handle with no ceiling, and a `ZstdView` passes the ceiling the engine parsed once to each inflate, so a ceiling leaves no state behind.
- A frame owns the digests and the identifiers it decoded, and lends them as views too. `clone()` answers a handle the caller owns.

## Connectors

Every connection is a multiplexed tightbeam session, so one socket carries concurrent, bidirectional streams. Each connector is a method of the `Engine`, and it resolves once the session is ready, so a failed dial rejects the connect call and not the first emit.

| Connector                                | Session                                             | Stream caps                                                                                                   |
| ---------------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `connectCleartext(url, options?)`        | No handshake, no confidentiality, no integrity      | `streams` (default 8) caps both directions. Both endpoints MUST configure the same value                      |
| `connect(url, serverCertDer, options?)`  | HPKE, with the server pinned by its DER certificate | `maxPeerStreams` (default 8) caps server-initiated streams. The advertisement of the server caps client emits |
| `connectMutual(url, identity, options?)` | HPKE with mutual authentication                     | As `connect`                                                                                                  |

The HPKE handshake also negotiates stream multiplexing (`transport-multiplex` of tightbeam, in the style of HTTP/2). A connection to a server that offers no multiplexing rejects.

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

`connectMutual` takes the identity as named fields, so the server and client certificates cannot trade places. It reads the identity before the call returns, so the caller may reuse its buffers at once. A malformed identity rejects with a `TightbeamTransportError`:

| Code                                          | Cause                                                                                                       |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `InvalidBytes`                                | A certificate is not a `Uint8Array`                                                                         |
| `InvalidClientKey`                            | The key is neither a `Uint8Array` nor an object                                                             |
| `InvalidSigningKey`                           | The raw scalar is not 32 octets, or names no key                                                            |
| `InvalidSigner`, `InvalidOid`, `InvalidBytes` | A `TransportSigner` lacks `signPrehash`, names no OID, or holds a `publicKeyDer` that is not a `Uint8Array` |
| `InvalidCertificate`                          | The client certificate is no DER certificate                                                                |

The engine parses the options of every connector once, and its faults belong to the same family, a `TightbeamTransportError` that `engine.isTransportError` recognizes:

| Code                         | Cause                                                                                                      |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `InvalidConnectOptions`      | The options are not an object, or their `signal` is no `AbortSignal`                                       |
| `InvalidStreamCap`           | The cap is no whole number from 1 to 2^32-1, so zero, a fraction, a negative number, and `NaN` are refused |
| `SessionOfferRequiresMutual` | A connector other than `connectMutual` receives a session knob                                             |

### External signers

A certificate key in an external key store, such as WebAuthn, a wallet, or a KMS bridge, signs through a `TransportSigner` in place of the raw scalar. The handshake hands the signer the transcript prehash, so the private key never crosses into wasm. The contract names no algorithm: the signer signs the prehash directly, with no second hash, and returns the signature encoding that the session profile verifies. Under the default-profile build that encoding is a secp256k1 signature as a DER `ECDSA-Sig-Value` (RFC 3279 § 2.2.3). A custom-profile build expects the encoding of its own profile ([The Browser Engine](ws-wasm.md#session-profiles)).

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

`emit` resolves with the response `Frame`, or with `undefined` when the peer answers without a body. `engine.frame(der)` parses the bytes once, so a malformed frame throws `SerializationError` at construction and every getter reads decoded state. A `Frame` exposes:

- the typed body through `message(codec)`, or through `open(codec, { opener, inflator })` for a sealed or compressed body
- the raw body DER through `bodyDer`, and the raw frame through `toDer()`
- the metadata `version`, `id`, and `order`, and the V2+ and V3+ fields `priority`, `lifetime`, `previousFrame`, and `matrix` when present
- the security markers `signed`, `messageIntegrity`, `frameIntegrity`, and `confidential`, with their carried infos `signatureInfo`, `messageIntegrityInfo`, `frameIntegrityInfo`, and `confidentialityInfo`. A carried digest is an engine `DigestInfo`, and every carried algorithm is an `Oid`
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
    .frameBuilder(handle(request.message(engine.opaque)))
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

- A handler of `serve`, `serveStreaming`, or `serveDuplex` refuses a stream by throwing `StreamRefusal` with the gRPC status code of its choice, as in `throw new StreamRefusal("NotFound", "no such order")`. Any other throw or rejection answers `Unknown`.
- A server-initiated stream that arrives before `serve()` waits in a bounded queue, sized to the cap granted to the server. The handler serves the queue in order once it registers, so registration has no race.
- `serve`, `serveStreaming`, and `serveDuplex` each take `{ claim: "exclusive" }`, which claims dispatch, and `"shared"` is the default claim. Every later `serve*` call then throws a `TightbeamTransportError` whose `code` is `ServeDispatchClaimed`, so no stream reroutes in silence. An exclusive claim over a running shared handler throws `ServeDispatchShared`, and a claim that is neither label throws `InvalidServeClaim`. The pubsub `SubscriptionManager` claims its client this way, and application routes compose through its `fallback` option.
- `serve`, `serveStreaming`, and `serveDuplex` exclude one another on one client. The first call consumes the responder, and a later call in another mode throws a `TightbeamTransportError` whose `code` is `ServeModeConflict`.
- `maxConcurrentStreams` reports the negotiated local cap. After `shutdown`, a new emit rejects while the streams in flight drain.

### Progressive bodies

Unary `emit` and `serve` stay the default. Progressive body I/O runs on the same Open, Data, and `last` records:

| Call                      | Direction                                                                        |
| ------------------------- | -------------------------------------------------------------------------------- |
| `openStream()`            | Push request chunks, then `close()` or `closeWith(chunk)` for a `Frame` response |
| `openDuplex()`            | Push request chunks, and consume `body` as an async iterable of reply chunks     |
| `serveStreaming(handler)` | Serve a progressive request body that the peer initiates                         |
| `serveDuplex(handler)`    | Serve a progressive duplex body that the peer initiates                          |

A push reaches the wire at once, so a duplex conversation that pushes and then awaits the next reply chunk makes progress. `closeWith(chunk)` flags that chunk `last` in one record, one record fewer than a push and a close.

Each stream owns its wasm handle and releases it on every exit. A close consumes the handle, and the end of an `await using` scope cancels a stream that no close reached. After a close or a disposal, a push or a second close refuses with `StreamClosed`. The request half and the reply `body` of a duplex stream end apart: a close ends the request half, the body reads until the `last` chunk of the peer, and a `break` out of the body cancels the stream. A disposal of the body also cancels an opened stream, and a read that still waits ends at once with no chunk. A `serveStreaming` or `serveDuplex` handler receives a body and a reply half that the client frees once the handler settles.

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

An application that serves more than one kind of stream demultiplexes by frame id. A `Router` binds each id prefix to a `Route`, a decoder and a handler typed by it, so the two cannot disagree at compile time. The longest matching prefix wins. For an id that no prefix matches, `dispatch` rejects with an `UnroutedTopicError`, which answers the stream with an `Unimplemented` status.

- `Route.of(codec, handler)` decodes a cleartext body.
- `Route.sealed(envelope, handler)` unwraps the frame under an [envelope](#envelopes) first, so a route that declares a signature refuses an unsigned or forged frame before its body decodes.

```ts
import { Route, Router } from "@wahidgroup/tightbeam-ws-client";

const chat = engine.envelope(ChatCodec).verified(publisherKey);

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
served.verify(signingKey.verifyingKey());
```

A gateway refusal rejects with `code === "WorkRefused"`, and its `status` property carries the name of the transit status from the gRPC canonical registry, such as `"Unavailable"` for an unserved servlet type. An `AbortSignal` in the options cancels the submission as it cancels `emit`.

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

A client lives until `close()`, the close of the peer, or a GoAway. Garbage collection is a backstop for a client that the application leaked. A client declared with `await using` closes as its scope ends. A `using` or `await using` declaration needs `Symbol.dispose` and `Symbol.asyncDispose` at runtime, which Node 24 and current browsers define. On an older runtime, call `close()` instead. The client declares no `using` on its own paths, so it runs there too.

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

A transport failure rejects as a `TransportError`, an `Error` named `TightbeamTransportError` that carries a stable `code`. `engine.isTransportError` narrows it once it checks the name brand and that the engine or the client declares its code, so a forged error with an unknown code does not narrow. `ClientTransportError.isConnectionClosed` recognizes a lost connection.

The type of `code` is the closed union `TransportErrorCode`, and each code has one declaration in one of four families:

| Family          | Declared in                                                                 | The code names                                                                                                     |
| --------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `RefusalCode`   | `fault.rs` of the engine, generated into the declarations of the wasm build | A value the engine refuses, such as `InvalidBytes`, `InvalidMatrixDimension`, or `CommitmentSpent`                 |
| `TransportCode` | `fault.rs` of the engine, generated the same way                            | An engine or transport error of `tightbeam-rs`, by its variant, such as `ConnectionClosed` or `SerializationError` |
| `TransitCode`   | `fault.rs` of the engine, generated the same way                            | A peer refusal, by its gRPC canonical status, such as `Unavailable`                                                |
| `ClientCode`    | `errors.ts` of the client                                                   | A failure the client decides itself: `KeyReleased`, `OpeningReleased`, `CodecReleased`, `EngineUnavailable`        |

A refusal of one field names it on `path`, such as `matrix.n`, and a refused work submission carries its `TransitCode` on `status`. `ClientTransportError` has a private constructor, and one named static builds each code it decides.

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
| `ConnectionClosed`                                        | Local  | The connection is gone                                                |
| `Draining`                                                | Local  | A GoAway arrived on a live connection. Reconnect before the next emit |
| `StreamsExhausted`                                        | Local  | The local stream cap is full. Retry after a response frees a slot     |
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

A native tightbeam server runs each read under its operation timeout, 30 seconds by default, and ends a session that sends nothing for that long. The client pings its peer every 10 seconds, a third of that timeout, so an idle session stays open with no application code.

`ping()` is the same liveness probe at the protocol level, the analog of RFC 9113 § 6.7, for an application that measures the link itself. It resolves when the peer acknowledges. It allocates no stream, and no application handler runs on the peer. Browsers answer the pings of the WebSocket protocol on their own, and this probe covers the application level, where silence otherwise looks the same as idleness.

```ts
await mux.ping({ signal: AbortSignal.timeout(5_000) });
```

## Frame builder

Every `with*` call returns a new immutable builder. `build()` validates the spec and resolves with the assembled `Frame`. Capability objects select the algorithms.

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
  .withMessageHasher(engine.sha3_256) // V1+: body commitment
  .withCommitment(engine.salt(salt)) // hide the commitment behind a salt of 16+ octets
  .withWitnessHasher(engine.sha3_256) // V1+: frame integrity
  .withEncryptor(engine.aes256Gcm({ key, keyId })) // V1+: body encryption
  .withSigner(signingKey) // V1+: secp256k1 signature
  .assertVersion(engine.Version.V3) // fail the build unless it lands on V3
  .build();
```

The build rules:

- The wasm engine decides the version floor from every requested field, as `GatedField::since` does in `tightbeam-rs`, or it honors a pin from `withVersion(engine.Version.V2)`. A pin below the floor rejects with an error whose `code` is `UnsupportedField`. `assertVersion` fails the build when the built frame carries another version.
- A value with a rule parses once, in the engine, before it reaches the builder: `engine.oid`, `engine.salt`, and `engine.digestInfo` throw a `TightbeamTransportError` at the call. A `Hasher` and a `BodyCompressor` name their algorithm by such an `Oid`.
- The engine parses the order, the lifetime, the version, and the priority as the build installs them. The order and the lifetime take a whole number or a `bigint` from 0 to 2^64-1. A value outside the range, or one of another type, rejects the build with `InvalidOrder`, `InvalidLifetime`, `InvalidVersion`, or `InvalidPriority`.
- `withMessageHasher` and `withWitnessHasher` take any `Hasher`. The profile hasher is `engine.sha3_256`. Without `withCommitment`, the message commitment is a plain digest of the body.
- `withContentOid(oid)` and `withPreviousHash(parent)` hold a copy of the handle they receive, and the builder copies the content type a codec declares, so a free of the caller's handle leaves the build its own. Every handle a build makes, such as the digest of each integrity step, frees within the build.
- `withCommitment(salt)` takes the salt, so the caller keeps an empty shell that frees as any handle does, and a disposal of that shell leaves the builder its salt. A salt commits one frame, so a committed builder, and every builder made from it, builds once. A second build, or a second `withCommitment` of the same shell, rejects with `CommitmentSpent`.
- `withEncryptor` takes any `BodyEncryptor`, and the frame has one body-encryption slot. The profile offers a symmetric cipher, `engine.aes256Gcm({ key, keyId })`, which every holder of the shared key opens under one `keyId`. It also offers an asymmetric encryptor to a recipient, `engine.hpkeEncryptor(recipientPublicKey)`, which the recipient secret opens. The encryptor seals the body as the content type that the builder or the codec names, and as `id-data` without one.
- A structurally invalid spec rejects with a `ValidationError` that carries an issue for each field. A field the engine refuses rejects with the engine code and the field on `path`, such as `InvalidMatrixDimension` at `matrix.n`.
- The builder runs its steps in this order: the message commitment, the compression, the encryption, the frame integrity, and the signature.

## Typed messages

The protocol treats the frame body as opaque DER, and what the body encodes is a contract between the peers. A `MessageCodec<T>` pairs a TypeScript type with that contract: `encode` produces the body DER, and `decode` parses and validates it at runtime. Each call site therefore reads a typed payload, and the wire stays free of any schema.

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
  .frameBuilder()
  .withMessage(Chat, { author: "ada", text: "hello" })
  .build();

const reply = await client.emit(built);
const message = reply?.message(Chat); // ChatMessage
```

- A peer can expect one ASN.1 `Message` schema, such as a Rust `der::Sequence`. Its codec is a `MessageCodec` that the application implements with an ASN.1 library, or one that `tightbeam-asn-emit` generates ([The ASN.1 Codec Bridge](asn.md)). The builder installs the DER that the codec emits.
- `engine.frameBuilder(bytes)` and `withMessage(bytes)` are shorthand for the profile codec `engine.opaque`, raw bytes in the opaque wrapper.
- The optional `contentOid` of a codec is an `Oid`, and it goes into the confidentiality info when the body is sealed.
- `engine.framed` is the codec of a frame in a frame: a message that is itself a full tightbeam frame, carried with its bytes unchanged inside the body of another frame. Pub/sub topics use it to relay a frame that a publisher signed or sealed through the registry, so frame-level security holds end to end through the broker.

## Custom cryptography

Each digest and compression capability pairs the operation with the `Oid` that the frame records, so implementations from any library or language interchange. A cipher names its algorithm in the envelope it writes. A signer signs the profile signature, which the engine fixes, so a signer names no OID and only signs the prehash it receives. The profile ships wasm-backed implementations of SHA3-256, secp256k1 ECDSA, AES-256-GCM, HPKE, and zstd, and every other algorithm plugs in through the same interfaces.

| Interface                        | Contract                                                                                      |
| -------------------------------- | --------------------------------------------------------------------------------------------- |
| `Hasher`                         | `algorithmOid`, an `Oid`, and `digest(data)`                                                  |
| `Signatory`                      | `signerId()`, the subject key identifier of its certificate, and `signPrehash(prehash)`       |
| `BodyEncryptor`                  | `encrypt(bodyDer, contentOid)`, which resolves with `{ envelopeDer, ciphertext }`             |
| `BodyDecryptor`                  | `decrypt(sealed)`, which receives the carried pieces and resolves with the plaintext body DER |
| `BodyCompressor`, `BodyInflator` | [Compression](#compression)                                                                   |

The `envelopeDer` of an encrypted body is a DER CMS `AuthEnvelopedData` (RFC 5083) with its content detached, and it names the content-encryption algorithm. A profile decryptor reads the algorithm and the key from the envelope, and the engine refuses an envelope that the key does not open. `engine.profile` lends the profile identifiers as views.

```ts
import type { Hasher, Signatory } from "@wahidgroup/tightbeam-ws-client";
import { sha3_512 } from "@noble/hashes/sha3.js";

// Any digest: implement Hasher with the OID peers should recompute under.
const sha3_512Hasher: Hasher = {
  algorithmOid: engine.oid("2.16.840.1.101.3.4.2.10"),
  digest: async (data) => sha3_512(data),
};

// Any signer of the profile signature: the builder hands the implementation
// the digest of the frame's CMS signed attributes and attaches the returned
// DER signature, so an external signer's private key never enters wasm memory
// (wallets, passkeys, HSMs, remote KMS).
const walletSigner: Signatory = {
  signerId: () => walletKeyId, // subject key identifier of its certificate
  signPrehash: async (prehash) => wallet.signDigest(prehash),
};

const built = await engine
  .frameBuilder(body)
  .withWitnessHasher(sha3_512Hasher)
  .withSigner(walletSigner)
  .build();
```

The profile key classes, `Secp256k1SigningKey`, `Secp256k1VerifyingKey`, `Aes256Gcm`, `HpkeEncryptor`, and `HpkeDecryptor`, come from `engine.signingKey`, `engine.verifyingKey`, `engine.aes256Gcm`, `engine.hpkeEncryptor`, and `engine.hpkeDecryptor`. Each one owns a wasm handle and release it through `[Symbol.dispose]`, so a `using` declaration frees the key as its scope ends. A release wipes the wasm copy of a secret at once, or when a decryption already in flight settles. A later release does nothing, and every later call on the key refuses with `KeyReleased`. A signing key derives its verifying key once, lends that one key from `verifyingKey()` and `verifier` as a `VerifyingKeyView`, and frees it with itself. The view has no release of its own.

## Compression

A `BodyCompressor` shrinks the body DER and names its algorithm once, as its `algorithmOid`, and a `BodyInflator` reverses it in the shape of the `Inflator` of `tightbeam-rs`: its `algorithmOid`, `admitsParameters(parametersDer?)`, and `decompress(data)`. `Frame.open` checks that the inflator reverses the algorithm of the frame and admits its parameters before it decrypts anything. The builder compresses after the message commitment, which covers the uncompressed body, and before the encryption, so peers encrypt the compressed bytes. That order is the order of `tightbeam-rs`.

`engine.zstd(maxOutput?)` lends the profile compression of the realm at that ceiling: one zstd frame under `engine.profile.zstd`, wire-compatible with the `ZstdCompression` of `tightbeam-rs`. The engine runs it in Rust, so the browser admits what a native peer admits ([The Browser Engine](ws-wasm.md#compression)):

- no parameters, or a compression level that libzstd accepts
- one frame and no octet after it: a zstd frame, or a skippable frame that inflates to no octets. A trailing skippable frame or a seek table rejects
- a decompressed size within the output cap, 16 MiB by default as in `tightbeam-rs`, which `maxOutput` tunes. The output never grows past the cap
- a declared window within the same cap, rounded up to a power of two as `tightbeam-rs` rounds it

```ts
const zstd = engine.zstd();

const built = await engine.frameBuilder(body).withCompressor(zstd).build();

// Cleartext + compressed: the engine inflates on the path a native peer takes.
const message = await received.inflateMessage(zstd, engine.opaque);

// Compressed then sealed: name both capabilities.
const opened = await sealed.open(engine.opaque, {
  opener: cipher,
  inflator: zstd,
});
```

A refusal carries the code of the path that refused:

- `zstd.decompress(data)`, which `Frame.open` calls, throws a `TightbeamTransportError` whose `code` names the refusal: `WindowTooLarge`, `OutputLimitExceeded`, `Truncated`, `TrailingBytes`, `Stalled`, or `Malformed`.
- `frame.inflateMessage(zstd, codec)` inflates on the frame inflate path of `tightbeam-rs`, where a refusal carries the code `CompressionError`. A compactness info that names another algorithm, or parameters that the engine refuses, rejects with `UnexpectedAlgorithm` or `InvalidMetadata`.
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

const built = await engine.frameBuilder(body).withCompressor(zlib).build();
```

A compressor names its algorithm once, as `algorithmOid`, as an inflator does. `withCompressor` copies that `Oid`, so one compressor serves every build, and the compressor keeps its own handle.

A compressed frame reports `compressed: true` and carries `compactnessInfo`, `{ algorithmOid, parametersDer?, contentOid }`, with each algorithm an `OidView` that the frame owns. A read without an inflator rejects with a `ValidationError`. An inflator SHOULD cap its output size, because a body from the wire can be a decompression bomb.

## Verification and decryption

The `Frame` carries its own verification. A verdict is one of `"verified"`, `"absent"`, `"algorithm-mismatch"`, and `"mismatch"`, and the engine `DigestInfo` that the frame carries judges every one but `"absent"`. The verdict methods recompute under any `Hasher`, and the profile SHA3-256 is the default. An external verifier checks `signatureInfo.signature`, a DER `ECDSA-Sig-Value`, over `signaturePrehash()` with its own library.

```ts
response.verify(signingKey.verifyingKey()); // profile scheme: throws when invalid
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
- `unwrap(frame)` reverses the layers in protocol order, verify, open, inflate, and decode, and it enforces them. A received frame that lacks a declared signature or seal rejects with a `ValidationError`, so a peer cannot downgrade the conversation by omission.

```ts
const notes = engine
  .envelope(Notes) // any MessageCodec<T>
  .signed(signingKey)
  .sealed(engine.aes256Gcm({ key: topicKey, keyId: topicKeyId }))
  .compressed(engine.zstd());

// Sender: the layers are already applied, the metadata stays yours.
const sent = await notes.frame(note).withId("note-1").withOrder(1n).build();

// Receiver: a Note, or a rejection.
const received = await notes.unwrap(relayed);
```

An envelope is immutable, and every frame of the conversation reuses it. Each declaration takes the halves that the capability implements:

- `signed(signatory)` signs on build. A signatory that exposes a `verifier` declares both directions. A profile `Secp256k1SigningKey` derives its own, and an external `Signatory` may carry one. A signatory without a `verifier`, such as a wallet, a passkey, or an HSM, needs `verified(key)` beside it before `unwrap` can check the signature.
- `verified(key)` is the read-only half for a party without the signing key. `unwrap` requires a signature that verifies under `key`, and `frame()` refuses to build, because a verify-only envelope MUST NOT send unsigned frames.
- `sealed(keys)` takes a `BodyEncryptor`, a `BodyDecryptor`, or both at once, and `Aes256Gcm` is both. An HPKE pair splits: the publisher declares `sealed(engine.hpkeEncryptor(recipientPublic))`, and the recipient declares `sealed(engine.hpkeDecryptor(recipientSecret))`.
- `compressed(compression)` is a transport optimization and no security property, so an uncompressed received frame still unwraps.

A one-sided party composes only its half:

```ts
// A subscriber that verifies and opens, but never signs or sends.
const readOnly = engine
  .envelope(Notes)
  .verified(publisherKey)
  .sealed(engine.hpkeDecryptor(recipientSecret));
```

The `authenticated` and `confidential` getters report the declarations. `unwrap` enforces them, so they hold for every unwrapped frame, and a UI shows them as badges with no probe of each frame. The pubsub manager accepts an envelope wherever it accepts a codec, and it publishes frame in frame so the layers hold end to end through the broker ([The Subscription Client](pubsub-client.md#payload-shapes)).

## Detached commitments

A commitment can also live outside a frame, as `tightbeam::crypto::commitment::Opening` does in Rust. A prover publishes a hiding digest now and discloses the opening `(salt, body)` later, and any holder of the digest verifies the disclosure. The preimage is the one that the message commitment of a frame uses, so a detached commitment and one that a frame carries interchange:

- An empty salt binds the body, under the preimage `mode || body`.
- A salt of at least 16 octets binds and hides the body, under the preimage `mode || len(salt) || salt || body`.

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

`verify` resolves with `false` on an algorithm mismatch or a digest mismatch. `commitment` is an engine `DigestInfo`, the one owner that judges a recomputed digest against a carried one. An opening takes its salt, so the caller keeps an empty shell, and the opening frees the salt as its `using` scope ends. A salt is a `CommitmentSalt` and never raw bytes, so the salt and the body cannot trade places. Any `Hasher` works on both sides.

## Sources

- RFC 6455, The WebSocket Protocol: <https://datatracker.ietf.org/doc/html/rfc6455>
- RFC 9113, HTTP/2, § 6.7 PING: <https://datatracker.ietf.org/doc/html/rfc9113#section-6.7>
- RFC 3279, Algorithms and Identifiers for the Internet X.509 PKI, § 2.2.3 ECDSA signatures: <https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3>
- RFC 5083, CMS Authenticated-Enveloped-Data Content Type: <https://datatracker.ietf.org/doc/html/rfc5083>
- RFC 3274, Compressed Data Content Type for CMS: <https://datatracker.ietf.org/doc/html/rfc3274>
- RFC 8878, Zstandard Compression and the application/zstd Media Type: <https://datatracker.ietf.org/doc/html/rfc8878>
- `google.rpc.Code`, the gRPC canonical status codes: <https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto>
