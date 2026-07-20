# tightbeam-ws

WebSocket transport for the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol.

tightbeam frames are DER-encoded and streamed over raw TCP by `tightbeam::transport::tcp`. This crate carries the same DER envelopes as WebSocket binary frames ([RFC 6455](https://www.rfc-editor.org/rfc/rfc6455)), one envelope per message, so browsers and other WebSocket clients can speak tightbeam.

## Surface

- `protocol::WsListener` implements tightbeam's `Protocol`, `EncryptedProtocol`, and `AsyncListenerTrait`.
- `io::WsStream` / `io::WsTransport` implement `AsyncProtocolStream` over `tokio-tungstenite`.
- Cleartext and ECIES-encrypted round-trips, reusing tightbeam's transport-agnostic handshake unchanged.

## Features

- `testing` - test-support module with X.509 identity fixtures for encrypted end-to-end tests and examples (`gen_certs`, `echo_server_secure`).

## Limitations

- Cleartext `ws://` only; `wss://` (TLS) is not implemented yet. Transport privacy is provided by tightbeam's ECIES handshake on top of the cleartext socket.

## Related

The browser counterpart lives in [tightbeam-ws-wasm](../tightbeam-ws-wasm), packaged for npm as `@wahidgroup/tightbeam-ws-client` ([client](../client)). See the [repository README](../../README.md) for development and release workflows.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
