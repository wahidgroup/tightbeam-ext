# tightbeam-ws

WebSocket transport for the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol.

tightbeam frames are DER-encoded and streamed over raw TCP by `tightbeam::transport::tcp`. This crate carries the same DER envelopes as WebSocket binary frames, one envelope per message, so browsers and other WebSocket clients can speak tightbeam.

## Surface

This crate exposes WebSocket framing for tightbeam transports. Authentication and confidentiality come from tightbeam's ECIES application-layer handshake above the socket, not from TLS on the listener itself.

- `protocol::WsListener` implements tightbeam's `Protocol`, `EncryptedProtocol`, and `AsyncListenerTrait`.
- `io::WsStream` and `io::WsTransport` implement `AsyncProtocolStream` over `tokio-tungstenite`.
- Cleartext and ECIES-encrypted round-trips reuse tightbeam's transport-agnostic handshake unchanged.

## Features

- `testing` - test-support module with X.509 identity fixtures and the shared multiplexed echo behavior for encrypted end-to-end tests and examples (`gen_certs`, `echo_server_mux`, `echo_server_mux_clear`).

## Limitations

- The listener has no native TLS acceptor: it binds `ws://` only. This does not gate security or `wss://` deployments. Authentication and confidentiality come from tightbeam's ECIES handshake above the socket. Browsers on `https://` pages connect over `wss://` by terminating TLS in front (reverse proxy, load balancer) and forwarding `ws://` to this crate.

## Sources

- RFC 6455, The WebSocket Protocol:
  <https://datatracker.ietf.org/doc/html/rfc6455>

## Related

The browser counterpart lives in [tightbeam-ws-wasm](../tightbeam-ws-wasm), packaged for npm as `@wahidgroup/tightbeam-ws-client` ([client](../client)). See the [repository README](../../README.md) for development and release workflows.

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
