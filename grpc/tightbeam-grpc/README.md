# tightbeam-grpc

gRPC transport for the [tightbeam](https://crates.io/crates/tightbeam-rs) messaging protocol.

## Status

This project is under active development. Public APIs MAY change without notice. No security audit has been conducted. Use this software at your own risk.

## Abstract

tightbeam streams DER-encoded envelopes over raw TCP. This crate carries the same envelopes as the messages of one bidirectional gRPC call over HTTP/2, the tunnel, so native tightbeam clients reach a server through gRPC hops: sidecar meshes, L4 load balancers, and HTTP/2 proxies that route by `:authority`, in h2c or over TLS 1.3. It plugs into the transport traits of tightbeam, so the handshake, the policies, multiplexing, and pooling of tightbeam run over it unchanged, and a cluster gateway takes it as its edge.

## Install

```sh
cargo add tightbeam-grpc
```

## Quick start

```rust
use tightbeam::{server, Frame};
use tightbeam_grpc::protocol::GrpcListener;

# async fn serve() -> Result<(), Box<dyn std::error::Error>> {
let listener: GrpcListener = GrpcListener::bind_cleartext("127.0.0.1:9120").await?;
let server_handle = server! {
	protocol GrpcListener: listener,
	handle: |message: Frame| async move { Ok(Some(message)) }
};
# server_handle.abort();
# Ok(())
# }
```

The listener serves in the clear here, and `bind_cleartext` says so: its tunnels are plaintext, unprotected, and unauthenticated (CWE-319). An encrypted listener binds with its certificate, and each tunnel runs the tightbeam handshake.

## Transport

`GrpcListener` is a tightbeam protocol: it binds, accepts, and dials tunnels, and its stream holds every read and write to the envelope rules of [tightbeam-wire](https://github.com/wahidgroup/tightbeam-ext/tree/master/wire/tightbeam-wire). Each connection holds a slot and a deadline while no caller holds its tunnel. Implementation: [docs/grpc.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/grpc.md#listener).

The edge profile of a listener is a type that provisions each bind and each dial of a deployment: h2c by default, or TLS 1.3 from the certificates of the deployment. A deployment whose material comes at run time stages it through `staged_profile!`. Implementation: [docs/grpc.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/grpc.md#edge-profile).

## Audit trail

The `instrument` feature records each call and each connection that an edge refuses before any session exists, each PROXY header that it reads or refuses, and each call of its coupler, on the one trace that the profile's `Edge::with_trace` attaches. Implementation: [docs/grpc.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/grpc.md#tunnel-call).

## Security

Authentication and confidentiality come from the tightbeam handshake inside the tunnel. TLS under the edge profile protects the hop to the listener, and replaces nothing inside the tunnel. Implementation: [docs/grpc.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/grpc.md#limitations).

## Cluster edge

A tightbeam cluster gateway binds a gRPC edge that admits signed work frames from native clients, and stream opens once its `EdgePlane` admits them, while the colony runs on the WebSocket protocol of `tightbeam-ws`. Implementation: [docs/grpc.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/grpc.md#cluster-work-plane).

## Coupled edge

The `couple` feature connects stock gRPC systems to a colony:

- Stock gRPC clients call colony servlets on the edge port, in unary calls and streams, under mutual TLS, a chain that a pinned proxy forwards, or a JWT-SVID.
- Browser pages call in gRPC-Web, and reflection lists the routed services.
- A backend adapter servlet calls stock gRPC servers, in unary calls and streams.

How to: [docs/grpc-interop.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/grpc-interop.md). Reference: [docs/grpc.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/grpc.md#coupled-edge).

## Proxy hops

A hop between client and server speaks HTTP/2 under the profile of the server, routes by `:authority`, sets no route timeout, and retires idle upstream connections before the server closes them, because a tunnel lives as long as its session. Implementation: [docs/grpc.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/grpc.md#hop-requirements).

## Related

The WebSocket transport is [tightbeam-ws](https://github.com/wahidgroup/tightbeam-ext/tree/master/ws/tightbeam-ws), which carries the same envelope rules to browsers. See the [repository README](https://github.com/wahidgroup/tightbeam-ext/blob/master/README.md) for development and release workflows.

## License

Licensed under either of [MIT](https://github.com/wahidgroup/tightbeam-ext/blob/master/grpc/tightbeam-grpc/LICENSE-MIT) or [Apache-2.0](https://github.com/wahidgroup/tightbeam-ext/blob/master/grpc/tightbeam-grpc/LICENSE-APACHE) at your option.
