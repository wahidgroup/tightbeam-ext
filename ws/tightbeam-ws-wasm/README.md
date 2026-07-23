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

- `build_transport_with::<P>(socket, trust_store, credentials)` assembles the encrypted transport for any provider over an opened `gloo` WebSocket. The caller supplies a matching `Arc<dyn CertificateTrust>` (see `profile_trust_store` for the default-profile construction).
- Mutual authentication is provider-generic too: `ClientCredentials::<P>::from_signer(cert_der, signer)` adapts an external JavaScript `TransportSigner` (WebAuthn, wallet, KMS bridge), so only OIDs and signature bytes cross the boundary. The signer's output must verify under `P`'s signature algorithm.
- Drive the handshake on the returned transport (`perform_client_handshake`), where the concrete provider satisfies tightbeam's handshake bounds.
- Single-flight traffic: call `emit` directly. Multiplexed traffic: offer mux before the handshake (`with_mux_config`), then `split_mux(transport)` yields the stream handle and responder with the driver tasks already running.

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
