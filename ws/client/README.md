# tightbeam-ws-client

TypeScript/WebAssembly client for the [tightbeam](https://crates.io/crates/tightbeam-rs) WebSocket transport: build tightbeam frames in the browser or Node and exchange them over multiplexed sessions.

## Status

> Warning: This project is under active development. Public APIs MAY change without notice.

**Security Disclaimer:** A SECURITY AUDIT HAS NOT BEEN CONDUCTED. USE AT YOUR OWN RISK.

## Abstract

This package is tightbeam in TypeScript. The frame codec (the ASN.1 DER engine) is the Rust implementation itself, compiled from [`tightbeam-ws-wasm`](../tightbeam-ws-wasm) with `wasm-pack`. The TypeScript layer adds the builder, the typed message envelope, validation, and connection handling. The tightbeam-rs surface carries over under the same names:

- The builder: `withSigner`, `withEncryptor`, `withMessageHasher`, the version floor rules, `assertVersion`.
- The `Frame`: `verify`, `frameIntegrityVerdict`, `messageCommitmentVerdict`, `decryptMessage`, and the same enums with the same ordinals (`Version`, `MessagePriority`).
- The transport: multiplexed bidirectional streams, ECIES sessions, GoAway semantics, gRPC status codes on refusals.

Cryptography is caller-supplied. Every security operation goes through a capability interface (`Hasher`, `BodyEncryptor`, `BodyDecryptor`, `Signatory`, `BodyCompressor`, `BodyInflator`) identified by the dotted algorithm OID it writes into the frame. The tightbeam profile (SHA3-256, secp256k1 ECDSA, AES-256-GCM, ECIES, zstd) is included as wasm-backed implementations. Any other hash, cipher, signer, or compressor plugs in through the same interfaces.

Two wasm bundles ship in the package, a `web` build and a `nodejs` build, selected automatically through the package `imports` map. Node ≥ 24 uses its global `WebSocket`, no shim required.

## Table of Contents

- [Install](#install)
- [Cleartext round-trip](#cleartext-round-trip)
- [Encrypted sessions (ECIES)](#encrypted-sessions-ecies)
- [Session budgets (mutual auth only)](#session-budgets-mutual-auth-only)
- [Two-way streams](#two-way-streams)
- [Progressive body streaming](#progressive-body-streaming)
- [Cancellation and timeouts](#cancellation-and-timeouts)
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
- [License](#license)

## Install

```sh
npm install @wahidgroup/tightbeam-ws-client
```

The package is published to GitHub Packages. Point the `@wahidgroup` scope there in `.npmrc`:

```ini
@wahidgroup:registry=https://npm.pkg.github.com
```

## Cleartext round-trip

Every connection is a multiplexed tightbeam session: one socket carries concurrent, bidirectional streams. Cleartext sessions have no handshake to negotiate over, so the stream cap is symmetric and both endpoints MUST configure the same value (the `streams` option, default 8). Cleartext carries no confidentiality or integrity protection. Like the encrypted connectors, `connectCleartext` resolves once the session is ready: a failed dial rejects the connect call, not the first emit.

```ts
import {
	Opaque,
	TightbeamWsClient,
	frame,
} from "@wahidgroup/tightbeam-ws-client";

const client = await TightbeamWsClient.connectCleartext("ws://localhost:9101");

const built = await frame(new TextEncoder().encode("hello"))
	.withId("greeting")
	.withOrder(Math.floor(Date.now() / 1000))
	.build();

const response = await client.emit(built);
console.log(response?.message(Opaque), response?.order, response?.signed);

client.close();
```

`emit` resolves with the response `Frame`, or `undefined` when the peer answers without a body. A `Frame` exposes:

- the typed body via `message(codec)`, the raw body DER via `bodyDer`, the raw frame via `toDer()`
- metadata: `version`, `id`, `order`, plus the V2+/V3+ fields `priority`, `lifetime`, `previousFrame`, `matrix` when present
- the security markers (`signed`, `messageIntegrity`, `frameIntegrity`, `confidential`) with their carried infos (`signatureInfo`, `messageIntegrityInfo`, `frameIntegrityInfo`, `confidentialityInfo`)
- the methods under [Verification and decryption](#verification-and-decryption)

## Encrypted sessions (ECIES)

The server is authenticated by pinning its DER certificate. The ECIES handshake also negotiates stream multiplexing (HTTP/2-style, tightbeam's `transport-multiplex`): the `maxPeerStreams` option caps concurrent server-initiated streams (default 8), the server's advertisement caps this client's concurrent emits, and connecting to a server that does not offer multiplexing rejects.

```ts
import { TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";

// Server-authenticated:
const secure = await TightbeamWsClient.connect(url, serverCertDer);

// Mutually authenticated (32-byte secp256k1 signing key):
const mutual = await TightbeamWsClient.connectMutual(
	url,
	serverCertDer,
	clientCertDer,
	clientSigningKey,
);
```

When the certificate key lives in an external key store (WebAuthn, a wallet, a KMS bridge), pass a `TransportSigner` instead of the raw scalar. The handshake hands it the transcript prehash to sign, so the private key never crosses into wasm. The contract is algorithm-agnostic: the signer signs the prehash directly (no rehash) and returns whatever signature encoding the session profile verifies. Under the default-profile build that is a secp256k1 signature as 64-byte `r || s`. A custom-profile build expects its own profile's encoding (see the [`tightbeam-ws-wasm` README](../tightbeam-ws-wasm/README.md)).

```ts
import type { TransportSigner } from "@wahidgroup/tightbeam-ws-client";

const signer: TransportSigner = {
	algorithmOid: "2.16.840.1.101.3.4.3.10", // ecdsa-with-SHA3-256
	publicKeyDer: spkiFromKeyStore,
	signPrehash: (prehash) => keyStore.signDigest(prehash),
};

const external = await TightbeamWsClient.connectMutual(
	url,
	serverCertDer,
	clientCertDer,
	signer,
);
```

The session profile (secp256k1 ECIES, AES-256-GCM records, SHA3-256 certificates) is a compile-time choice, the same as for a native tightbeam-rs transport. A deployment on a different provider rebuilds the wasm layer against its own `CryptoProvider` (see the [`tightbeam-ws-wasm` README](../tightbeam-ws-wasm/README.md)). Frame-level cryptography stays caller-supplied regardless.

### Session budgets (mutual auth only)

Metered sessions request per-direction credits and settle server invoices through `approveReceipt`. Budgets, `authorization`, and `approveReceipt` are rejected on `connect` / `connectCleartext`.

```ts
const metered = await TightbeamWsClient.connectMutual(
	url,
	serverCertDer,
	clientCertDer,
	clientSigningKey,
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

There is no live remaining-balance getter. Reconnect policies MUST treat peer GoAway reasons `"BudgetExhausted"` and `"SettlementFailed"` like other drain signals (backoff / re-auth), not as a protocol bug.

## Two-way streams

Every `emit` opens its own stream: concurrent emits interleave on the connection and responses correlate by stream ID. `serve` answers streams the _server_ initiates.

```ts
import {
	Opaque,
	TightbeamWsClient,
	frame,
} from "@wahidgroup/tightbeam-ws-client";

const mux = await TightbeamWsClient.connect(url, serverCertDer);

// Answer server-initiated streams. Callable repeatedly (the latest
// handler serves streams dispatched after the call), and handlers for
// distinct streams run concurrently.
mux.serve(async (request) => {
	const reply = await frame(handle(request.message(Opaque)))
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
mux.close();
```

A `serve` handler refuses a stream by throwing `StreamRefusal` with the gRPC status code of its choice (`throw new StreamRefusal("NotFound", "no such order")`). Any other throwing or rejecting handler answers `Unknown`. `maxConcurrentStreams` reports the negotiated local cap. After `shutdown`, new emits reject while in-flight streams drain.

Registering the handler is not racy: server-initiated streams that arrive before `serve()` is called are parked in a bounded queue (the cap granted to the server) and served in order once the handler registers.

`serve(handler, { exclusive: true })` claims dispatch: every later `serve` call throws instead of silently rerouting streams. The pubsub `SubscriptionManager` claims its client this way. Application routes compose through its `fallback` option.

### Progressive body streaming

Unary `emit` / `serve` stay the default. Progressive body I/O uses the same Open/Data/`last` wire:

- `openStream()`: push request chunks, then `close()` / `closeWith(chunk)` for a Frame response
- `openDuplex()`: push request chunks; consume `body` as an async iterable of reply chunks
- `serveStreaming(handler)` / `serveDuplex(handler)`: peer-initiated progressive bodies

Pushes reach the wire eagerly, so a duplex chunk-for-chunk conversation (push, then await the next reply chunk) is sound. `closeWith(chunk)` flags that chunk `last` in one record (one fewer than push-then-close). Dropping a stream without `close` / `closeWith` cancels it.

```ts
const stream = client.openStream();
await stream.push(frameDer.subarray(0, mid));
const response = await stream.closeWith(frameDer.subarray(mid));

const duplex = client.openDuplex();
await duplex.push(chunkA);
const first = await duplex.body[Symbol.asyncIterator]().next();
await duplex.closeWith(chunkB);
for await (const chunk of duplex.body) {
	handle(chunk);
}
```

`serve`, `serveStreaming`, and `serveDuplex` are mutually exclusive on one client: the first call consumes the responder.

### Routing server-initiated streams

Applications that serve more than one kind of stream demultiplex by frame id. The `router` makes that pairing checkable: each `route` binds an id prefix to a codec and a handler typed by that codec, so the two cannot disagree at compile time. The longest matching prefix wins. An unmatched id throws `UnroutedTopicError`, answering the stream with an `Unimplemented` status.

```ts
import { route, router } from "@wahidgroup/tightbeam-ws-client";

mux.serve(
	router({
		"tick/": route(TickCodec, (tick) => {
			store.applyTick(tick); // tick: Tick, inferred from the codec
			return undefined; // bodiless ack
		}),
		"chat/": route(ChatCodec, async (message, request) => {
			store.appendChat(message);
			return buildReceipt(request); // response frame
		}),
	}),
);
```

The server matches on the frame id prefix before decoding in its own stream handler. The router only routes: subscription semantics, ordering, and replay stay with the application.

## Cancellation and timeouts

`emit` takes an `AbortSignal`. Aborting cancels the stream (the cap slot is freed and a best-effort `MuxCancel` tells the peer) and rejects the emit with the signal's abort reason. A timeout is a signal:

```ts
const response = await mux.emit(built, {
	signal: AbortSignal.timeout(5_000),
});
```

The connectors take a signal the same way. Aborting cancels the dial and handshake, closes the socket, and rejects with the signal's abort reason.

```ts
const mux = await TightbeamWsClient.connect(url, serverCertDer, {
	signal: AbortSignal.timeout(5_000),
});
```

## Connection lifecycle

Every client exposes `closed`, a promise resolving with the close frame's `{ code, reason, wasClean }` on every close path, plus a `readyState` getter with the WebSocket constants. Reconnect logic starts here:

```ts
void client.closed.then((info) => {
	if (!info.wasClean) {
		scheduleReconnect(info.code);
	}
});
```

`close()` closes the socket and releases the client's wasm resources (idempotent, safe with emits in flight). Call `shutdown()` first for a graceful GoAway drain, or `shutdownWith(reason)` to advertise why: a label (`"Shutdown"`, `"ProtocolError"`, `"EnhanceYourCalm"`, `"BudgetExhausted"`, `"SettlementFailed"`) or an application-defined numeric code the peer reads back through its own GoAway surface. After `close()`, operations reject with `ConnectionClosed`, while `closed`, `readyState`, and the GoAway getters stay readable for reconnect policies.

When the peer drains the session, the client records why. `goawayReason` reads the reason from the peer's GoAway (`undefined` while the connection is live or after a local shutdown), and reconnect policies branch on it. `goawayCode` exposes the raw numeric code for application-defined reasons, which `goawayReason` labels `"Application"`.

Reconnection belongs to the application: the client supplies the policy inputs (`closed`, `goawayReason`, `wasClean`) and only the application knows what state to replay. The complete pattern: branch on the reason, back off, re-register `serve`.

```ts
async function connectLoop(
	handle: (client: TightbeamWsClient) => void,
): Promise<void> {
	let delay = 500;

	for (;;) {
		let client: TightbeamWsClient;
		try {
			client = await TightbeamWsClient.connect(url, serverCertDer, {
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
		client.close();

		switch (client.goawayReason) {
			case "Shutdown":
				break; // orderly drain (rotation, redeploy): go right back
			case "EnhanceYourCalm":
				await sleep((delay = Math.min(delay * 2, 30_000)));
				break; // the server asked for calm
			case "ProtocolError":
				report(info);
				return; // a bug, not a transient fault
			default:
				await sleep(delay); // no GoAway: connection loss
		}
	}
}
```

## Transport errors

Transport failures reject as `Error` objects carrying a stable machine-readable `code` (the tightbeam-rs error variant name). Narrow them with `isTransportError`:

```ts
import { isTransportError } from "@wahidgroup/tightbeam-ws-client";

try {
	await mux.emit(built);
} catch (error) {
	if (isTransportError(error) && error.code === "Draining") {
		// GoAway received: reconnect before emitting again.
	}
}
```

Local conditions carry their variant name: `ConnectionClosed`, `Draining`, and `StreamsExhausted` (local stream cap full, retry after a response frees a slot). Peer refusals carry gRPC canonical status names, with the retry contract each name defines:

- `ResourceExhausted`: peer at capacity, retry with backoff
- `Unavailable`: peer draining, retry with backoff
- `Unimplemented`: nothing serves the topic, do not retry
- `Unknown`: unclassified peer handler failure
- `DeadlineExceeded`, `Unauthenticated`, `PermissionDenied`: gate policy rejections

Instead of retrying `StreamsExhausted` blind, wait for admission. `waitForStreamSlot()` resolves once a new stream would be admitted, rejects with `Draining` once no stream ever will be again, and takes the same `{ signal }` option as `emit` for callers that give up first. It is advisory like `hasStreamHeadroom`: a concurrent emit can take the slot between wake and use, so the rejection handling stays.

```ts
await mux.waitForStreamSlot({ signal: AbortSignal.timeout(5_000) });
const response = await mux.emit(built);
```

## Keepalive

Multiplexed sessions have a protocol-level liveness probe (RFC 9113 § 6.7 analog). `ping()` resolves when the peer acknowledges. No stream is allocated and no application handler runs on the peer, so a periodic ping doubles as an idle keepalive for browsers, whose sockets cannot send WebSocket protocol pings from JavaScript:

```ts
const interval = setInterval(() => {
	void mux.ping({ signal: AbortSignal.timeout(5_000) }).catch(() => {
		clearInterval(interval);
		// Draining, ConnectionClosed, or deadline: reconnect via the
		// closed promise.
	});
}, 30_000);
```

Browsers answer WebSocket protocol pings automatically. This probe covers the application level, where silence is otherwise indistinguishable from idleness.

### Sources

- RFC 9113 § 6.7, PING frame:
  <https://datatracker.ietf.org/doc/html/rfc9113#section-6.7>

## Frame builder

Every `with*` returns a new immutable builder. `build()` validates the spec and resolves with the assembled `Frame`. Algorithms are selected with capability objects:

```ts
import {
	Aes256Gcm,
	EciesEncryptor,
	MessagePriority,
	Secp256k1SigningKey,
	Sha3_256,
	Version,
	frame,
} from "@wahidgroup/tightbeam-ws-client";

const signingKey = Secp256k1SigningKey.fromBytes(rawScalar);

const built = await frame(body)
	.withId("doc-42")
	.withOrder(1n)
	.withPriority(MessagePriority.LowLatency) // V2+
	.withLifetime(60) // V2+
	.withPreviousHash({ algorithmOid, digest }) // V2+
	.withMatrix(2, new Uint8Array([0, 1, 1, 0])) // V3+
	.withMessageHasher(new Sha3_256(), salt) // V2+: body commitment
	.withWitnessHasher(new Sha3_256()) // V2+: frame integrity
	.withEncryptor(Aes256Gcm.fromKey(key)) // V1+: body encryption
	.withSigner(signingKey) // V1+: secp256k1 signature
	.assertVersion(Version.V2) // fail the build unless it lands on V2
	.build();
```

- The version floor is derived from the requested fields, or pinned with `withVersion(Version.V2)`. `assertVersion` fails the build when the effective version differs from the assertion.
- `withMessageHasher` / `withWitnessHasher` take any `Hasher`. The profile hasher is `Sha3_256`.
- `withEncryptor` takes any `BodyEncryptor`: the profile symmetric cipher (`Aes256Gcm.fromKey(k)`, opened with the shared key), the profile asymmetric encryptor to a recipient (`EciesEncryptor.fromBytes(recipientPublicKey)`, opened with the recipient secret), or your own scheme. The frame has a single body-encryption slot.
- Structurally invalid specs reject with a `ValidationError` carrying per-field issues.

## Typed messages

The protocol treats the frame body as opaque DER: what it encodes is your contract with the peer. A `MessageCodec<T>` pairs a TypeScript type with that contract. `encode` produces the body DER, `decode` parses and runtime-validates it, so payloads are typed at every call site while the wire stays schema-agnostic.

For payloads without an ASN.1 schema, `wrapped(inner)` lifts any byte-level serialization (JSON, CBOR, protobuf) into a codec by wrapping it in the profile opaque body:

```ts
import type { MessageCodec } from "@wahidgroup/tightbeam-ws-client";
import { frame, wrapped } from "@wahidgroup/tightbeam-ws-client";

interface ChatMessage {
	author: string;
	text: string;
}

const Chat: MessageCodec<ChatMessage> = wrapped({
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

const built = await frame()
	.withMessage(Chat, { author: "ada", text: "hello" })
	.build();

const reply = await client.emit(built);
const message = reply?.message(Chat); // ChatMessage
```

To interoperate with a peer expecting a specific ASN.1 `Message` schema (e.g. a Rust `der::Sequence`), implement `MessageCodec` directly with the ASN.1 library of your choice. The DER it emits is installed in the frame. `frame(bytes)` / `withMessage(bytes)` are sugar for the profile `Opaque` codec (raw bytes in the opaque wrapper), and a codec's optional `contentOid` is recorded in the confidentiality info when the body is sealed.

`Framed` is the frame-in-frame codec: messages that are themselves full tightbeam frames, carried byte-for-byte inside another frame's body. Pub/sub topics use it to relay publisher-signed (or sealed) frames through the registry untouched, so frame-level security survives the broker end to end.

## Custom cryptography

Each capability interface pairs the operation with the dotted OID recorded in the frame, so implementations are interchangeable across libraries and languages:

```ts
import type { Hasher, Signatory } from "@wahidgroup/tightbeam-ws-client";
import { sha3_512 } from "@noble/hashes/sha3.js";

// Any digest: implement Hasher with the OID peers should recompute under.
const sha3_512Hasher: Hasher = {
	algorithmOid: "2.16.840.1.101.3.4.2.10",
	digest: async (data) => sha3_512(data),
};

// Any signer: the builder hands the implementation the to-be-signed bytes
// and attaches the returned signature, so an external signer's private key
// never enters wasm memory (wallets, passkeys, HSMs, remote KMS).
const walletSigner: Signatory = {
	signatureAlgorithmOid: "2.16.840.1.101.3.4.3.10",
	digestAlgorithmOid: "2.16.840.1.101.3.4.2.8",
	signerId: () => walletKeyId, // subject-key-identifier octets
	sign: async (tbs) => wallet.sign(tbs),
};

const built = await frame(body)
	.withWitnessHasher(sha3_512Hasher)
	.withSigner(walletSigner)
	.build();
```

`BodyEncryptor` / `BodyDecryptor` follow the same shape: `encrypt(bodyDer)` resolves with `{ algorithmOid, parametersDer, ciphertext }`, and `decrypt(sealed)` receives the carried pieces and resolves with the plaintext body DER. The `PROFILE_OIDS` constant exports the profile identifiers.

## Compression

Compression is a capability too: a `BodyCompressor` shrinks the body DER and names its algorithm by OID, a `BodyInflator` reverses it. The builder compresses after the message commitment (the commitment is over the uncompressed body) and before encryption (peers encrypt the compressed bytes), matching tightbeam-rs.

The profile compression is included: `ZstdCompression` (zstd in the seekable format, `PROFILE_OIDS.zstd`) is wire-compatible with tightbeam-rs `ZstdCompression` and backed by a lazily loaded wasm build of libzstd. Clients that never compress never load it. Its decompression output is capped (16 MiB by default, matching tightbeam-rs, tunable with `new ZstdCompression(maxOutput)`), and the cap is enforced against the stream's declared size before anything is allocated.

```ts
import {
	Opaque,
	ZstdCompression,
	frame,
} from "@wahidgroup/tightbeam-ws-client";

const zstd = new ZstdCompression();

const built = await frame(body).withCompressor(zstd).build();

// Cleartext + compressed: inflate and decode in one step.
const message = await received.inflateMessage(zstd, Opaque);

// Compressed then sealed: pass the inflator to decryptMessage.
const opened = await sealed.decryptMessage(cipher, Opaque, zstd);
```

Any other algorithm works through the same interfaces. The platform-native `CompressionStream` gives a dependency-free zlib alternative (`PROFILE_OIDS.zlib`, RFC 3274):

```ts
import type {
	BodyCompressor,
	BodyInflator,
	CompressedBody,
} from "@wahidgroup/tightbeam-ws-client";
import { Opaque, PROFILE_OIDS, frame } from "@wahidgroup/tightbeam-ws-client";

async function pump(
	transform: ReadableWritablePair<Uint8Array, BufferSource>,
	bytes: Uint8Array,
): Promise<Uint8Array> {
	const source = new Blob([bytes]).stream().pipeThrough(transform);
	return new Uint8Array(await new Response(source).arrayBuffer());
}

const zlib: BodyCompressor & BodyInflator = {
	compress: async (bodyDer) => ({
		algorithmOid: PROFILE_OIDS.zlib,
		data: await pump(new CompressionStream("deflate"), bodyDer),
	}),
	decompress: (compressed) =>
		pump(new DecompressionStream("deflate"), compressed.data),
};

const built = await frame(body).withCompressor(zlib).build();
```

A compressed frame reports `compressed: true` and carries `compactnessInfo` (`{ algorithmOid, parametersDer?, contentOid? }`). Reading it without an inflator rejects with a `ValidationError`. Inflators SHOULD cap their output size: a wire-supplied body can be a decompression bomb.

## Verification and decryption

Verification is on the `Frame` itself. Verdicts are `"verified" | "absent" | "algorithm-mismatch" | "mismatch"`. The verdict methods recompute under any `Hasher` (profile SHA3-256 by default). For frames signed under non-profile schemes, verify `signatureInfo.signature` over `tbs()` with your own library.

```ts
import { Aes256Gcm, EciesDecryptor } from "@wahidgroup/tightbeam-ws-client";

response.verify(signingKey.verifyingKey()); // profile scheme: throws when invalid
await response.frameIntegrityVerdict(); // "verified" | "absent" | ...
await response.frameIntegrityVerdict(sha3_512Hasher); // under your own hasher
await response.messageCommitmentVerdict(salt); // checks the body commitment

// Open an encrypted body with the matching cipher or recipient secret,
// decoding the plaintext under any codec (Opaque for raw bytes):
await response.decryptMessage(Aes256Gcm.fromKey(key), Opaque);
await response.decryptMessage(
	EciesDecryptor.fromBytes(recipientSecretKey),
	Chat,
);

// Raw surfaces for external verification:
response.tbs(); // to-be-signed bytes
response.witnessInput(); // frame-integrity preimage
response.signatureInfo; // { algorithmOid, digestAlgorithmOid, signature }
```

## Envelopes

The calls above are per-frame tools. A conversation applies the same layers to every frame, in both directions: `envelope(codec)` declares them once. `frame(message)` begins a builder with the layers applied. `unwrap(frame)` reverses them in protocol order (verify, open, inflate, decode) and enforces them: a received frame missing a declared signature or seal rejects with a `ValidationError`, so a peer cannot downgrade the conversation by omission.

```ts
import {
	Aes256Gcm,
	ZstdCompression,
	envelope,
} from "@wahidgroup/tightbeam-ws-client";

const notes = envelope(Notes) // any MessageCodec<T>
	.signed(signingKey)
	.sealed(Aes256Gcm.fromKey(topicKey))
	.compressed(new ZstdCompression());

// Sender: the layers are already applied, the metadata stays yours.
const sent = await notes.frame(note).withId("note-1").withOrder(1n).build();

// Receiver: a Note, or a rejection.
const received = await notes.unwrap(relayed);
```

Envelopes are immutable and reusable across every frame of the conversation. Each declaration takes whichever halves the capability implements:

- `signed(signatory)` signs on build. A profile `Secp256k1SigningKey` derives its own verifying key for unwrap. Any other `Signatory` (wallet, passkey, HSM) needs `verified(key)` alongside it before `unwrap` can check the signature.
- `verified(key)` is the read-only half for parties without the signing key: `unwrap` requires a signature verifying under `key`, and `frame()` refuses to build (a verify-only envelope MUST NOT silently send unsigned frames).
- `sealed(keys)` takes a `BodyEncryptor`, a `BodyDecryptor`, or both at once. `Aes256Gcm` is both. An ECIES pair splits: the publisher declares `sealed(EciesEncryptor.fromBytes(recipientPublic))`, the recipient `sealed(EciesDecryptor.fromBytes(recipientSecret))`.
- `compressed(compression)` is a transport optimization, not a security property: an uncompressed received frame still unwraps.

One-sided parties compose only their half:

```ts
// A subscriber that verifies and opens, but never signs or sends.
const readOnly = envelope(Notes)
	.verified(publisherKey)
	.sealed(EciesDecryptor.fromBytes(recipientSecret));
```

The `authenticated` and `confidential` getters report the declarations. Because `unwrap` enforces them, they are proven properties of every unwrapped frame: a UI badges them instead of probing frames. The pubsub manager accepts an envelope wherever it accepts a codec ([`@wahidgroup/tightbeam-pubsub-client`](../../pubsub/client)), publishing frame-in-frame so the layers survive the broker end to end.

## Detached commitments

A commitment can also live outside a frame (`tightbeam::crypto::commitment::Opening`): publish a hiding digest now, disclose the opening `(salt, body)` later, and any holder of the digest verifies the disclosure. The preimage is the same length-framed `salt || body` the in-frame message commitment uses, so a detached commitment and a frame-carried one are interchangeable.

```ts
import { Opening, Sha3_256 } from "@wahidgroup/tightbeam-ws-client";

// Prover: publish `commitment`, keep `opening` secret until disclosure.
const { commitment, opening } = await Opening.prove(
	new Sha3_256(),
	bodyDer,
	crypto.getRandomValues(new Uint8Array(32)), // high-entropy salt hides the body
);

// Verifier: reassemble the disclosed parts and check in constant time.
const disclosed = Opening.fromParts(opening.salt, opening.bodyDer);
const verified = await disclosed.verify(new Sha3_256(), commitment);
```

`verify` resolves with `false` on an algorithm mismatch or a digest mismatch. An empty salt reproduces the plain body digest (binding, not hiding). Any `Hasher` works on both sides.

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
