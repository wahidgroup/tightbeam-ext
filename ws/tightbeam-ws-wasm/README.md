# tightbeam-ws-wasm

WebAssembly WebSocket client for the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol.

## Status

> Warning: This project is under active development. Public APIs MAY change without notice.

**Security Disclaimer:** A SECURITY AUDIT HAS NOT BEEN CONDUCTED. USE AT YOUR OWN RISK.

## Abstract

The wasm32 counterpart to [tightbeam-ws](../tightbeam-ws): a `gloo-net` WebSocket stream implementing the same tightbeam transport traits, plus `wasm-bindgen` frame-composer bindings for JavaScript callers.

Not published to crates.io. It is compiled with `wasm-pack` and shipped inside the npm package `@wahidgroup/tightbeam-ws-client` ([client](../client)):

```sh
make client   # wasm-pack build + TS workspace build
```

The Playwright suite under [tests/](../tests) exercises the compiled client end to end against a dockerized `tightbeam-ws` echo server (`make test`).

## Custom transport profiles

The session profile (curve, AEAD, digests, certificate policy) is a compile-time `CryptoProvider` choice, exactly as with a native tightbeam-rs transport. The shipped `MuxWsClient` binding instantiates the tightbeam default profile. Frame-level cryptography stays caller-supplied at runtime in the TypeScript layer regardless.

A deployment on a different provider builds its own wasm crate against this one (it compiles as an `rlib`) and reuses the transport layer with its own `#[wasm_bindgen]` bindings:

1. For mutual authentication, adapt a JavaScript `TransportSigner` with `JsSigningKeyProvider::identity::<P>(signer, cert_der)`. Its signatures MUST verify under `P`.
2. Call `build_transport_with::<P>(socket, trust_store, identity)` on an opened `gloo` WebSocket, with the identity from step 1 or `None`. The trust store MUST validate under `P`, as `profile_trust_store` does for the default profile.
3. For multiplexed traffic, offer mux with `with_mux_offer`.
4. Run `perform_client_handshake` on the transport.
5. Call `emit` for single-flight traffic, or `split_mux(transport)` for multiplexed traffic. `split_mux` accepts the default provider only.

## Related

The host transport lives in [tightbeam-ws](../tightbeam-ws). This crate ships inside the npm package `@wahidgroup/tightbeam-ws-client` ([client](../client)). See the [repository README](../../README.md) for development and release workflows.

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
