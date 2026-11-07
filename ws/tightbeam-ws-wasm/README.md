# tightbeam-ws-wasm

WebAssembly WebSocket client for the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol.

## Status

This project is under active development. Public APIs MAY change without notice. No security audit has been conducted. Use this software at your own risk.

## Abstract

This crate is the browser counterpart of [tightbeam-ws](../tightbeam-ws). It runs the tightbeam transport over a browser WebSocket under the same envelope rules, and it exposes the frame composer of tightbeam to JavaScript through `wasm-bindgen`. It never reaches crates.io: it ships inside the npm package `@wahidgroup/tightbeam-ws-client` ([client](../client)).

## Build

```sh
make client   # wasm-pack build + TS workspace build
```

The build writes a browser bundle and a Node bundle, and each has a loader of its own, which imports the bundle as `TightbeamWsClient.init` runs. Implementation: [docs/ws-wasm.md](../../docs/ws-wasm.md#build).

## Parse once

Each JavaScript value that the engine owns parses once, in Rust, into a handle such as `Oid` or `DigestInfo`, and every binding refuses a value it cannot read with a code in place of a coercion. Implementation: [docs/ws-wasm.md](../../docs/ws-wasm.md#parse-once).

## Compression

The engine zstd runs on the pure-Rust `ruzstd` under the clauses of the zstd of `tightbeam-rs`, so the browser admits the compressed bodies a native peer admits, with no C compiler in the build. Implementation: [docs/ws-wasm.md](../../docs/ws-wasm.md#compression).

## Session profiles

The session profile is a compile-time `CryptoProvider` choice, as with a native tightbeam transport, and the shipped binding runs the default profile. A deployment on another provider builds its own wasm crate against this one. Implementation: [docs/ws-wasm.md](../../docs/ws-wasm.md#session-profiles).

## Tests

`wasm-pack test --node` runs the engine and its browser stream, `cargo test` checks the engine zstd against the zstd of `tightbeam-rs` on the host, and the Playwright suite runs the compiled client against a dockerized `tightbeam-ws` server. Implementation: [docs/ws-wasm.md](../../docs/ws-wasm.md#tests).

## Related

The host transport lives in [tightbeam-ws](../tightbeam-ws). This crate ships inside the npm package `@wahidgroup/tightbeam-ws-client` ([client](../client)). See the [repository README](../../README.md) for development and release workflows.

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
