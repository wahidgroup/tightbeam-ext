# tightbeam-ext

Official extensions for the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol.

## Status

This project is under active development. Public APIs MAY change without notice. No security audit has been conducted. Use this software at your own risk.

## Abstract

This repository holds the parts of tightbeam that sit beyond the core crate: the envelope rules that its message socket transports share, a gRPC transport, a WebSocket transport, a browser client, topic pub/sub, and an ASN.1 bridge to TypeScript. Each extension lives in its own directory with its crates, its npm packages, and its end-to-end tests. The [documentation index](docs/README.md) lists the page that specifies each part.

## Extensions

### [wire/](wire): Envelope rules of message sockets

- [tightbeam-wire](wire/tightbeam-wire): the rules that every message-oriented socket transport shares, one envelope per transport message. Published to crates.io.

### [grpc/](grpc): gRPC transport

- [tightbeam-grpc](grpc/tightbeam-grpc): the gRPC edge of a colony, for native clients behind gRPC hops and for stock gRPC clients and servers. Published to crates.io.

### [ws/](ws): WebSocket transport

- [tightbeam-ws](ws/tightbeam-ws): the native transport, which carries tightbeam envelopes as WebSocket binary messages ([RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455)). Published to crates.io.
- [tightbeam-ws-client](ws/client): `@wahidgroup/tightbeam-ws-client`, the TypeScript and wasm client for browsers and Node. It builds and verifies tightbeam frames and runs encrypted, multiplexed sessions.
- [tightbeam-ws-wasm](ws/tightbeam-ws-wasm): the wasm engine that the client ships.

### [pubsub/](pubsub): Topic pub/sub

- [tightbeam-pubsub](pubsub/tightbeam-pubsub): the server-side topic registry over the tightbeam mux, which carries each subscription as a command stream of the mux.
- [tightbeam-pubsub-client](pubsub/client): `@wahidgroup/tightbeam-pubsub-client`, typed topic subscriptions over the ws client.

### [asn/](asn): ASN.1 bridge to TypeScript

- [tightbeam-asn](asn/tightbeam-asn): `#[derive(AsnCodec)]` on `der` types, and the `tightbeam-asn-emit` binary that writes TypeScript `MessageCodec` modules.

## Development

```sh
make setup       # toolchains + npm workspaces + Playwright (idempotent)
make lint        # every lint check that make help lists
make lint fix=1  # apply lint/format fixes
make test        # cargo tests + TS units + dockerized e2e
make build       # cargo build --release
make audit       # cargo audit + npm audit
make ci          # full CI pipeline
```

A project name after a target scopes it, as in `make test ws`, and `make help` prints every target. Each extension releases on its own with `make release`. Implementation: [docs/development.md](docs/development.md).

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
