# tightbeam-ws-wasm

Browser (WebAssembly) WebSocket client for the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol.

The wasm32 counterpart to [tightbeam-ws](../tightbeam-ws): a `gloo-net` WebSocket stream implementing the same tightbeam transport traits, plus `wasm-bindgen` frame-composer bindings for JavaScript callers.

Not published to crates.io. It is compiled with `wasm-pack` and shipped inside the npm package `@wahidgroup/tightbeam-ws-client` ([client](../client)):

```sh
make client   # wasm-pack build + TS workspace build
```

The Playwright suite under [tests/](../tests) exercises the compiled client end to end against a dockerized `tightbeam-ws` echo server (`make test`).

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
