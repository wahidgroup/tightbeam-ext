# tightbeam-ws

WebSocket transport for the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol.

tightbeam frames are DER-encoded and streamed over raw TCP by `tightbeam::transport::tcp`. This crate carries the same DER envelopes as WebSocket binary frames, one envelope per message, so browsers and other WebSocket clients can speak tightbeam.

## Surface

This crate exposes WebSocket framing for tightbeam transports. Authentication and confidentiality come from tightbeam's ECIES application-layer handshake above the socket, not from TLS on the listener itself.

- `protocol::WsListener` implements tightbeam's `Protocol`, `EncryptedProtocol`, and `AsyncListenerTrait`.
- `io::WsStream` and `io::WsTransport` implement `AsyncProtocolStream` over `tokio-tungstenite`.
- Cleartext and ECIES-encrypted round-trips reuse tightbeam's transport-agnostic handshake unchanged.

## Cluster work plane

tightbeam's `colony` feature routes signed work frames through a cluster gateway to hive-registered servlets. The upstream `SubmitWork` blanket implementation already covers `GenericClient<WsListener>`, so no code in this crate changes for it. `tests/work_plane.rs` proves the round trip and a typed `WorkRefused` refusal over a real gateway, hive, and servlet topology on the ws transport:

```rust
let served = client.submit_work_to(servlet_urn, &signed_work_frame).await?;
```

The gateway forwards the caller's signed frame to the servlet byte-for-byte, and the servlet's complete signed response frame returns the same way. Enable `colony` on `tightbeam-rs` in your own manifest to use it.

## Features

- `testing` - test-support module with X.509 identity fixtures and the shared multiplexed echo behavior for encrypted end-to-end tests and examples (`gen_certs`, `echo_server_mux`, `echo_server_mux_clear`, `work_gateway_server`).

## Limitations

- The listener has no native TLS acceptor: it binds `ws://` only. This does not gate security or `wss://` deployments. Authentication and confidentiality come from tightbeam's ECIES handshake above the socket. Browsers on `https://` pages connect over `wss://` by terminating TLS in front (reverse proxy, load balancer) and forwarding `ws://` to this crate.

## Sources

- RFC 6455, The WebSocket Protocol:
  <https://datatracker.ietf.org/doc/html/rfc6455>

## Related

The browser counterpart lives in [tightbeam-ws-wasm](../tightbeam-ws-wasm), packaged for npm as `@wahidgroup/tightbeam-ws-client` ([client](../client)). See the [repository README](../../README.md) for development and release workflows.

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
