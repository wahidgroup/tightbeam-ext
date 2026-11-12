# tightbeam-wire

The envelope rules that every message-oriented socket transport of the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol shares.

## Status

This project is under active development. Public APIs MAY change without notice. No security audit has been conducted. Use this software at your own risk.

## Abstract

A message socket, such as a WebSocket, delimits each message itself, so a tightbeam envelope travels as one transport message and the stream needs no framing of its own. A socket kind classifies its own messages and errors, and this crate turns its two halves into one tightbeam stream that reads, writes, splits, and fails by the same rules as every other kind.

## Install

```sh
cargo add tightbeam-wire
```

The crate names no socket, so a browser transport depends on it as a native one does. A `wasm32` build needs the `wasm` feature of `tightbeam-rs` in the crate that links it, which selects the random source of the browser.

## Socket kinds

A kind implements `WireStream` and `WireSink` over the halves of its socket, and `WireDuplex` joins the two into a stream that implements `AsyncProtocolStream` and `SplittableStream`. Implementation: [docs/wire.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/wire.md#socket-kinds).

## Faults

`WireFault` names each class of socket failure, and each class maps to one transport error of tightbeam. Implementation: [docs/wire.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/wire.md#faults).

## Related

The native WebSocket kind is [tightbeam-ws](https://github.com/wahidgroup/tightbeam-ext/tree/master/ws/tightbeam-ws), the browser kind is the engine [tightbeam-ws-wasm](https://github.com/wahidgroup/tightbeam-ext/tree/master/ws/tightbeam-ws-wasm), and the gRPC kind is [tightbeam-grpc](https://github.com/wahidgroup/tightbeam-ext/tree/master/grpc/tightbeam-grpc). See the [repository README](https://github.com/wahidgroup/tightbeam-ext/blob/master/README.md) for development and release workflows.

## License

Licensed under either of [MIT](https://github.com/wahidgroup/tightbeam-ext/blob/master/wire/tightbeam-wire/LICENSE-MIT) or [Apache-2.0](https://github.com/wahidgroup/tightbeam-ext/blob/master/wire/tightbeam-wire/LICENSE-APACHE) at your option.
