# tightbeam-ws-client

TypeScript/WebAssembly client for the [tightbeam](https://crates.io/crates/tightbeam-rs) WebSocket transport: build tightbeam frames in the browser or Node and exchange them over multiplexed sessions.

## Status

This project is under active development. Public APIs MAY change without notice. No security audit has been conducted. Use this software at your own risk.

## Abstract

This package is tightbeam in TypeScript. Its frame codec is the Rust implementation of tightbeam, compiled to wasm, and the TypeScript layer adds the builder, typed messages, validation, and connection handling under the names of `tightbeam-rs`. Cryptography is caller-supplied through capability interfaces, and the package includes the tightbeam profile: SHA3-256, secp256k1 ECDSA, AES-256-GCM, HPKE, and zstd.

The quick-start sample compiles as the `quick start` case of [`src/readme.test.ts`](src/readme.test.ts).

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
import { TightbeamWsClient } from "@wahidgroup/tightbeam-ws-client";

const engine = await TightbeamWsClient.init();
const client = await engine.connectCleartext("ws://localhost:9101");

const built = await engine
	.frameBuilder(new TextEncoder().encode("hello"))
	.withId("greeting")
	.withOrder(Math.floor(Date.now() / 1000))
	.build();

const response = await client.emit(built);
const message = response?.message(engine.opaque);
console.log(message, response?.order, response?.signed);

await client.close();
```

A cleartext session carries no confidentiality or integrity protection. Use `engine.connect` or `engine.connectMutual` for an encrypted one.

## Engine

`TightbeamWsClient.init` loads the wasm engine and resolves with the `Engine`, the owner of every parse and constructor that calls into the module. The binary loads at `init` alone, and a failed load rejects with `EngineUnavailable`. Implementation: [docs/ws-client.md](../../docs/ws-client.md#engine).

## Sessions

Every connection is a multiplexed tightbeam session. `connect` pins the server by its certificate under an HPKE handshake, `connectMutual` adds client authentication, and a mutual session MAY run under metered budgets. Implementation: [docs/ws-client.md](../../docs/ws-client.md#connectors).

## Streams

Each `emit` opens its own stream, `serve` answers the streams that the server initiates, and progressive bodies stream in chunks. A `Router` pairs each frame id prefix with a typed handler. Implementation: [docs/ws-client.md](../../docs/ws-client.md#streams).

## Cluster work

`submitWork` sends a signed work frame through a tightbeam cluster gateway to a servlet. The gateway relays both frames with their bytes unchanged, so their signatures verify end to end. Implementation: [docs/ws-client.md](../../docs/ws-client.md#cluster-work-submission).

## Connection lifecycle

Calls take an `AbortSignal`, the client reports why a connection closed or drained, and reconnection is a loop that the application owns. Failures reject with a stable `code` from `tightbeam-rs`. Implementation: [docs/ws-client.md](../../docs/ws-client.md#connection-lifecycle).

## Frames

`FrameBuilder` assembles a frame with its version, metadata, commitment, encryption, compression, and signature, and a `Frame` verifies and opens itself. Each algorithm is a capability object, so any library can supply it. Implementation: [docs/ws-client.md](../../docs/ws-client.md#frame-builder).

## Envelopes

An `Envelope` declares the signature, seal, and compression of a conversation once, and it refuses a received frame that lacks a declared layer. Implementation: [docs/ws-client.md](../../docs/ws-client.md#envelopes).

## Detached commitments

`Opening` commits to a body now and discloses it later, under the preimage of the frame message commitment. Implementation: [docs/ws-client.md](../../docs/ws-client.md#detached-commitments).

## Related

The host transport is [tightbeam-ws](../tightbeam-ws), and the wasm engine is [tightbeam-ws-wasm](../tightbeam-ws-wasm). Topic subscriptions on top of this client live in [`@wahidgroup/tightbeam-pubsub-client`](../../pubsub/client). See the [repository README](../../README.md) for development and release workflows.

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
