# tightbeam-ws-client

TypeScript/WebAssembly client for the [tightbeam](https://crates.io/crates/tightbeam-rs) WebSocket transport: build tightbeam frames in the browser or Node and exchange them over multiplexed sessions.

## Status

This project is under active development. Public APIs MAY change without notice. No security audit has been conducted. Use this software at your own risk.

## Abstract

This package is tightbeam in TypeScript. Its frame codec is the Rust implementation of tightbeam, compiled to wasm, and the TypeScript layer adds the builder, typed messages, validation, and connection handling under the names of `tightbeam-rs`. Cryptography is caller-supplied through capability interfaces, and the package includes the tightbeam profile: SHA3-256, secp256k1 ECDSA, AES-256-GCM, HPKE, and zstd.

The quick-start sample compiles in [`src/docs.test.ts`](https://github.com/wahidgroup/tightbeam-ext/blob/master/ws/client/src/docs.test.ts), which reads it from this README.

## Install

```sh
npm install @wahidgroup/tightbeam-ws-client
```

The package is published to GitHub Packages. Point the `@wahidgroup` scope there in `.npmrc`:

```ini
@wahidgroup:registry=https://npm.pkg.github.com
```

## Quick start

```ts
import { Engine } from "@wahidgroup/tightbeam-ws-client";

const engine = await Engine.load();
const client = await engine.connectCleartext("ws://localhost:9101");

const built = await engine
	.frameBuilder(new TextEncoder().encode("hello"))
	.withId("greeting")
	.withOrder(Math.floor(Date.now() / 1000))
	.build();

const response = await client.emit(built);
const message = await response?.open(engine.opaque);
console.log(message, response?.order, response?.signed);

await client.close();
```

A cleartext session carries no confidentiality or integrity protection. Use `engine.connect` or `engine.connectMutual` for an encrypted one.

## Engine

`Engine.load` loads the wasm engine and resolves with the `Engine`, the owner of every parse and constructor that calls into the module. The binary loads at `load` alone, and [Transport errors](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/ws-client.md#transport-errors) names the test of a failed load. Implementation: [docs/ws-client.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/ws-client.md#engine).

## Sessions

Every connection is a multiplexed tightbeam session. `connect` pins the server by its certificate under an HPKE handshake, `connectMutual` adds client authentication, and a mutual session MAY run under metered budgets. Implementation: [docs/ws-client.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/ws-client.md#connectors).

## Streams

Each `emit` opens its own stream, `serve` answers the streams that the server initiates, and progressive bodies stream in chunks. A `Router` pairs each frame id prefix with a typed handler. Implementation: [docs/ws-client.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/ws-client.md#streams).

## Cluster work

`submitWork` sends a signed work frame through a tightbeam cluster gateway to a servlet. The gateway relays both frames with their bytes unchanged, so their signatures verify end to end. Implementation: [docs/ws-client.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/ws-client.md#cluster-work-submission).

## Connection lifecycle

Calls take an `AbortSignal`, the client reports why a connection closed or drained, and reconnection is a loop that the application owns. Failures reject with a stable `code` ([Transport errors](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/ws-client.md#transport-errors)). Implementation: [docs/ws-client.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/ws-client.md#connection-lifecycle).

## Frames

`FrameBuilder` begins with a body and builds once it holds an id. It assembles a frame with its version, metadata, commitment, encryption, compression, and signature, and a `Frame` verifies itself and opens through one decoder, `open`. Each algorithm is a capability object, so any library can supply it. Implementation: [docs/ws-client.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/ws-client.md#frame-builder).

## Envelopes

An `Envelope` declares the signature, seal, and compression of a conversation once, each with the halves the party holds, so `frame` and `unwrap` exist only for the directions those halves run. It refuses a received frame that lacks a declared layer. Implementation: [docs/ws-client.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/ws-client.md#envelopes).

## Detached commitments

`Opening` commits to a body now and discloses it later, under the preimage of the frame message commitment. Implementation: [docs/ws-client.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/ws-client.md#detached-commitments).

## Related

The host transport is [tightbeam-ws](https://github.com/wahidgroup/tightbeam-ext/tree/master/ws/tightbeam-ws), and the wasm engine is [tightbeam-ws-wasm](https://github.com/wahidgroup/tightbeam-ext/tree/master/ws/tightbeam-ws-wasm). Topic subscriptions on top of this client live in [`@wahidgroup/tightbeam-pubsub-client`](https://github.com/wahidgroup/tightbeam-ext/tree/master/pubsub/client). See the [repository README](https://github.com/wahidgroup/tightbeam-ext/blob/master/README.md) for development and release workflows.

## License

Licensed under either of [MIT](https://github.com/wahidgroup/tightbeam-ext/blob/master/ws/client/LICENSE-MIT) or [Apache-2.0](https://github.com/wahidgroup/tightbeam-ext/blob/master/ws/client/LICENSE-APACHE) at your option.
