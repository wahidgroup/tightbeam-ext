# tightbeam-ws

WebSocket transport for the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol.

## Status

This project is under active development. Public APIs MAY change without notice. No security audit has been conducted. Use this software at your own risk.

## Abstract

tightbeam streams DER-encoded envelopes over raw TCP. This crate carries the same envelopes as WebSocket binary messages ([RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455)), one envelope per message, so browsers and other WebSocket clients speak tightbeam. It plugs into the transport traits of tightbeam, so the handshake, the policies, multiplexing, and pooling of tightbeam run over it unchanged.

## Install

```sh
cargo add tightbeam-ws
```

## Quick start

```rust
use tightbeam::{server, Frame};
use tightbeam_ws::protocol::WsListener;

# async fn serve() -> Result<(), Box<dyn std::error::Error>> {
let listener: WsListener = WsListener::bind_cleartext("127.0.0.1:9101").await?;
let server_handle = server! {
	protocol WsListener: listener,
	handle: |message: Frame| async move {
		Ok(Some(message))
	}
};
# server_handle.abort();
# Ok(())
# }
```

The listener serves in the clear here, and `bind_cleartext` says so: its connections are plaintext, unprotected, and unauthenticated (CWE-319). An encrypted listener binds with its certificate, and each connection runs the tightbeam handshake.

## Transport

`WsListener` is a tightbeam protocol: it binds, accepts, and dials WebSocket connections, and its stream holds every read and write to the envelope rules of [tightbeam-wire](https://github.com/wahidgroup/tightbeam-ext/tree/master/wire/tightbeam-wire). The browser engine shares those rules. Implementation: [docs/ws.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/ws.md#listener).

## Security

Authentication and confidentiality come from the tightbeam handshake above the socket, so the listener binds `ws://` and leaves TLS to a terminator in front of it. A listener that serves no anonymous peer requires mutual authentication. Implementation: [docs/ws.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/ws.md#limitations).

## Push-capable servers

The `serve` feature owns one accepted multiplexed connection and lends its service the handle that server-initiated streams leave on. `tightbeam-pubsub` serves through it. Implementation: [docs/ws.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/ws.md#accepted-links).

## Cluster edge

A tightbeam cluster gateway binds a WebSocket edge that admits signed work frames from browsers, and the colony runs on WebSocket too. Implementation: [docs/ws.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/ws.md#cluster-work-plane).

## Features

`socket`, on by default, holds the listener and the dial. `serve`, `instrument`, `testing`, and `colony` select the other parts. Implementation: [docs/ws.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/ws.md#features).

## Related

The browser engine is [tightbeam-ws-wasm](https://github.com/wahidgroup/tightbeam-ext/tree/master/ws/tightbeam-ws-wasm), packaged for npm as `@wahidgroup/tightbeam-ws-client` ([client](https://github.com/wahidgroup/tightbeam-ext/tree/master/ws/client)). See the [repository README](https://github.com/wahidgroup/tightbeam-ext/blob/master/README.md) for development and release workflows.

## License

Licensed under either of [MIT](https://github.com/wahidgroup/tightbeam-ext/blob/master/ws/tightbeam-ws/LICENSE-MIT) or [Apache-2.0](https://github.com/wahidgroup/tightbeam-ext/blob/master/ws/tightbeam-ws/LICENSE-APACHE) at your option.
