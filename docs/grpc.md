# The gRPC Transport

This page specifies the types of `tightbeam-grpc` that carry tightbeam envelopes over a gRPC call:

- the listener, its edge profile, its connection slots, and the dial
- the tunnel call and the calls it refuses
- the stream, and how it runs the envelope rules over gRPC
- the cluster work plane at the gRPC edge
- the coupled edge, which serves stock gRPC callers beside the tunnel
- the backend adapter, which carries colony work to a stock gRPC server
- the requirements of a proxy hop between client and server
- the limits a deployment plans around

It drills down from the [tightbeam-grpc README](../grpc/tightbeam-grpc/README.md) for engineers who build on the transport, run it behind a proxy, or review it. The envelope rules that every message socket shares have their own page, [The Envelope Wire Rules](wire.md).

## Contents

- [Listener](#listener)
- [Edge profile](#edge-profile)
- [Connection slots](#connection-slots)
- [Tunnel call](#tunnel-call)
- [Stream and envelope rules](#stream-and-envelope-rules)
- [Cluster work plane](#cluster-work-plane)
- [Coupled edge](#coupled-edge)
- [Backend adapter](#backend-adapter)
- [Hop requirements](#hop-requirements)
- [Limitations](#limitations)
- [Sources](#sources)

## Listener

`protocol::GrpcListener<P, C>` is the tightbeam listener over gRPC. `P` is the `CryptoProvider` of the session, and `DefaultCryptoProvider` is the default. `C` is the [edge profile](#edge-profile) of the deployment, and `edge::H2c` is the default, so `GrpcListener` names the h2c listener. It implements these traits of `tightbeam::transport`:

| Trait                  | What the listener supplies                                                                             |
| ---------------------- | ------------------------------------------------------------------------------------------------------ |
| `Protocol`             | `bind_cleartext`, `connect`, `connect_within`, and `create_transport`. The stream is `io::GrpcStream`  |
| `EncryptedProtocol`    | `bind_with(addr, TransportEncryptionConfig)`, with `SendCipher` and `RecvCipher` as the record ciphers |
| `AsyncListenerTrait`   | `accept`, which yields the transport and the `GrpcAddr` of its peer                                    |
| `PersistentConnection` | `is_connected`, so `ConnectionPool` and the colony stack reuse one tunnel across leases                |

Every accepted transport builds from the one `EndpointConfig` that the listener holds, so the provisioning and the ceilings of the listener reach each tunnel. The inherent `GrpcListener::bind_cleartext(addr)` binds a listener that runs no tightbeam handshake, and its accepted transports carry no end-to-end confidentiality, integrity, or peer authentication (CWE-319). An encrypted listener binds through `EncryptedProtocol::bind_with`, and each tunnel then runs the tightbeam handshake unchanged. Authentication and confidentiality come from that handshake inside the tunnel, under either profile. TLS under the profile protects the hop to the listener, and replaces nothing inside the tunnel.

The server speaks HTTP/2 and no HTTP/1.1: with prior knowledge (h2c) under `H2c`, and over TLS 1.3 under a TLS profile. It serves on a task of its own, so a tunnel call queues whether or not a caller waits in `accept`. `accept` passes over a tunnel whose call ended before a caller took it, and returns these errors:

- `TransportError::IoError` -- the TCP accept failed, and the server backs off before the next one.
- `TransportError::ConnectionClosed` -- the server task stopped.

The drop of the listener stops the server: the socket closes, every connection with no tunnel closes, and every tunnel that no caller took ends. A tunnel that a caller took lives on with its transport.

`protocol::GrpcAddr` is a host and a port. A dial sends it as the `:authority` of the call, so a proxy that routes by host reaches the server behind it, and a bind resolves the host and binds the first address that binds. The host is an IPv6 address in brackets, an IPv4 address, or a name of letters, digits, hyphens, and dots, which compares without case. `"127.0.0.1:0"`, `"[::1]:7443"`, and `"gateway.internal:7443"` parse. `"gateway.internal"`, `":80"`, `"*:1"`, and `"user@host:1"` refuse with `TransportError::InvalidAddress`.

```rust
use tightbeam::transport::Protocol;
use tightbeam_grpc::protocol::{GrpcAddr, GrpcListener};

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), tightbeam::transport::TransportError> {
let bind: GrpcAddr = "127.0.0.1:0".parse()?;
let (listener, bound) = <GrpcListener as Protocol>::bind_cleartext(bind).await?;
assert_eq!(bound, GrpcAddr::from(listener.local_addr()));
# Ok(())
# }
```

## Edge profile

tightbeam binds the edge of a gateway through `EncryptedProtocol::bind_with(addr, TransportEncryptionConfig)`, and a client dials through `Protocol::connect(addr)`. Neither call carries a value for the deployment, so the listener names its deployment as the type `C`, and `C` implements `edge::EdgeProfile`:

| Method                | Called                                      | Returns                                                      |
| --------------------- | ------------------------------------------- | ------------------------------------------------------------ |
| `EdgeProfile::edge()` | Once for each bind, before the socket binds | `Edge::H2c`, or `Edge::Tls(EdgeTls)` for TLS 1.3             |
| `EdgeProfile::dial()` | Once for each dial, before it connects      | `Dial::H2c`, or `Dial::Tls(DialTls)`, which trusts its roots |

A profile reads its material from its own sources, such as a file or a secret mount. A profile that cannot read it fails the bind or the dial with an `edge::EdgeError`, which the transport error of the bind or the dial carries as its source, and a bind that fails this way binds no socket. A dial calls `dial()` each time, so a profile that reads files caches what it read.

- `edge::EdgeTls::from_pem(chain, key)` reads a PEM certificate chain, the certificate of the edge first, and its PEM private key. `EdgeTls::new` takes the same material as DER.
- `edge::DialTls::from_pem(roots)` reads the PEM roots that the certificate of the edge must chain to. A dial names the host of its `GrpcAddr` as the server it verifies, so the certificate of the edge carries that DNS name or IP address as a subject alternative name.
- Both ends admit TLS 1.3 alone, under the ring provider of rustls, and offer ALPN `h2` alone. The listener terminates TLS itself, so tonic runs no TLS of its own.

A gateway declares a TLS edge with its profile, and a client dials with the same type:

```rust
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam_grpc::edge::{Dial, DialTls, Edge, EdgeError, EdgeProfile, EdgeTls};
use tightbeam_grpc::protocol::GrpcListener;

/// The edge of the orders gateway, under the certificates that its pod mounts.
struct Orders;

impl EdgeProfile for Orders {
    fn edge() -> Result<Edge, EdgeError> {
        Ok(Edge::Tls(EdgeTls::from_pem("/run/edge/tls.crt", "/run/edge/tls.key")?))
    }

    fn dial() -> Result<Dial, EdgeError> {
        Ok(Dial::Tls(DialTls::from_pem("/run/edge/ca.crt")?))
    }
}

/// The listener that `cluster! { ..., edge: OrdersEdge }` binds, and that a client dials.
type OrdersEdge = GrpcListener<DefaultCryptoProvider, Orders>;
```

Under the `testing` feature, `testing::TlsAuthority` mints a P-256 root and the loopback certificates it issues, and `staged_profile!` declares a profile whose material a scenario stages at run time. `tests/tls.rs` runs the shared round trips and a colony work submission over a TLS edge, and a dial that trusts another root and an h2c dial to a TLS edge, which reach no tunnel.

## Connection slots

Every byte before a tunnel call parses comes from a peer that no handshake has proved, so the server holds each connection under a slot and a deadline while no caller holds its tunnel:

- The server holds at most `DEFAULT_MAX_SERVER_CONNECTIONS` (1024) slots. A slot covers a connection from TCP accept until a caller of `accept` takes its tunnel, so a full server leaves new connections in the listen backlog (CWE-770).
- A connection that opens no call within the `handshake_timeout` of the endpoint closes and returns its slot (CWE-400).
- On a TLS edge, each connection runs its TLS handshake on a task of its own, under its slot, and within that same deadline. A handshake that fails or passes the deadline closes the connection and returns its slot before the HTTP/2 server sees the connection, and a slow handshake holds back no other connection.
- A tunnel that no caller takes within the `handshake_timeout` of its call closes its connection, so a silent call holds its slot no longer than a silent connection does.
- A call that ends before a caller takes its tunnel, because tonic refused it or its peer reset it, returns the connection to the slot and the deadline it waited under before the call. A later call on the connection takes the place of a call that a caller never took, and its expiry, so one connection never holds two slots and never renews its deadline by replacing calls.
- A connection carries one tunnel at a time, because the server advertises `SETTINGS_MAX_CONCURRENT_STREAMS` of 1.
- A proxy pools its upstream connections, so it may send the next tunnel over a connection whose tunnel a caller took. The end of that call waits the connection again under a free slot and a fresh deadline. With no free slot, the connection drains: it holds no slot until the same deadline, a call on it takes a slot if one has freed by then, and a call refuses with status 14 (`UNAVAILABLE`) while none is free.
- A connection that waits again goes before the accept of a new connection, so it takes the slot that the accept loop holds for the next TCP connection.

## Tunnel call

A tunnel is one bidirectional gRPC call on `protocol::TUNNEL_PATH`, `/tightbeam.v1.Transport/Connect`, under `application/grpc`, which tonic writes on both ends. Each message of the call is the DER of one envelope, unwrapped, so no reader needs a service descriptor. An encrypted tunnel opens with the tightbeam handshake. The server parses the head of each call once and refuses every call the tunnel cannot carry:

| The call                                                                              | Refused with                                                 | By                                  |
| ------------------------------------------------------------------------------------- | ------------------------------------------------------------ | ----------------------------------- |
| A method other than `POST`                                                            | HTTP 405, with `Allow: POST`                                 | the tunnel                          |
| A content type other than `application/grpc`, alone, with `+`, or with `;` parameters | HTTP 415                                                     | the tunnel                          |
| A path that the edge serves no call on                                                | status 12, `UNIMPLEMENTED`                                   | the tunnel                          |
| A connection with no free slot, or a queue full of tunnels that ended                 | status 14, `UNAVAILABLE`                                     | the tunnel                          |
| A `grpc-encoding` other than `identity`                                               | status 12, `UNIMPLEMENTED`                                   | tonic, which accepts no encoding    |
| A compressed message with no encoding                                                 | status 13, `INTERNAL`, once the accepted transport reads it  | tonic decoder                       |
| A message past the envelope ceiling                                                   | status 11, `OUT_OF_RANGE`, once the accepted transport reads | tonic decoder, at the declared size |

The content type compares without case (RFC 9110 section 8.3.1). The envelope ceiling is `TransportLimits::max_envelope` of the endpoint, in both directions of the call, on the server and on the dial. tonic refuses a message by its declared size before it sizes a buffer for it. The server ends a tunnel it ends itself with status 0, because tightbeam frames carry every refusal of the session.

Under the `instrument` feature, `GrpcListener::with_trace(trace)` attaches the audit trail of the listener. Each refusal by the tunnel records on it as `events::TUNNEL_REFUSED`, before the server answers it, with the name of the refusal as its label and its value: `method`, `media-type`, `path`, `busy`, or `unconnected`. tonic refuses an encoding inside the call that the tunnel admitted, with no refusal of the tunnel, so that refusal records nothing. The server runs from the bind on, so a call that it refuses before the attach records nothing either. The refusals of a message that an accepted transport reads record on the trace of that transport as tightbeam's `TRANSPORT_ENVELOPE_REFUSED`, once `server!` attaches it through `with_trace`.

## Stream and envelope rules

`io::GrpcStream` holds the `tightbeam_wire::WireDuplex` of its two halves, `io::GrpcReadHalf` and `io::GrpcWriteHalf`. It implements `AsyncProtocolStream`, and it splits into exclusive halves (`SplittableStream`) so a multiplexed connection reads and writes at once. `io::GrpcTransport<P>` names `TcpTransport<GrpcStream, P>`, the tightbeam transport over that stream. A stream comes only from a dial or an accept of `GrpcListener`, and each one sets the message ceiling of both directions to the envelope ceiling of its endpoint.

A dial opens one HTTP/2 connection to the authority, makes the one tunnel call on it, and owns the connection for the life of the stream. It makes no other call on that connection, so a lost connection ends the tunnel instead of reconnecting under the session. The dial sends no `grpc-timeout`, and the server sets no call timeout, because upstream `Deadlined` bounds every read and write.

The halves are the gRPC kind of the envelope rules ([The Envelope Wire Rules](wire.md)):

- Every message of the call is one envelope, so no message skips.
- A write sends one envelope as one message. The channel to the call holds one envelope, and tonic batches the envelopes it takes from it up to its yield threshold of 32 KiB before HTTP/2 flow control applies.
- The read half classifies each end of the call once, and every later read returns the same end.
- An accepted tunnel answers the status that failed its inbound messages, so the peer reads the status of its own fault.

| The end of the call                                           | `Wire`             | `TransportError`                |
| ------------------------------------------------------------- | ------------------ | ------------------------------- |
| The end of the message stream                                 | `Closed`           | `ConnectionClosed`              |
| `CANCELLED`, `UNAVAILABLE`, `DEADLINE_EXCEEDED`               | `Closed`           | `ConnectionClosed`              |
| `OUT_OF_RANGE`                                                | `Failed(Oversize)` | `OperationFailed(SizeExceeded)` |
| An I/O error in the source chain, alone or in an HTTP/2 error | `Failed(Io)`       | `IoError`                       |
| Every other status                                            | `Failed(Invalid)`  | `InvalidMessage`                |

tonic reads a request that its client cancelled as the end of the message stream, so the server side of a tunnel reads that end as `Closed`. A failed dial classifies its error the same way.

## Cluster work plane

The `colony` feature of tightbeam routes signed work frames through a cluster gateway to the servlets that hives register. The gRPC transport is a native client edge of a colony, and the colony interior keeps its TCP protocol:

- A gateway declares the edge with `cluster! { ..., protocol: TokioListener, edge: GrpcListener }` and sets `ClusterConfig::edge_bind_addr`.
- The gateway binds a second accept plane on gRPC that admits `Work` frames only. It refuses each control frame, such as a hive registration, with `PermissionDenied`.
- The upstream `SubmitWork` blanket implementation covers `GenericClient<GrpcListener>` and `PooledClient<GrpcListener>`, so an edge client submits through `submit_work_to`.
- The gateway forwards the signed frame of the caller to the servlet with its bytes unchanged, and the complete signed response frame of the servlet returns the same way.

An application enables `colony` on `tightbeam-rs` in its own manifest to use the edge. `tests/work_plane.rs` runs the round trip, a typed `WorkRefused` refusal, the refused registration, and a pooled edge connection that serves two leases, and each spec grades the registration, the routes, and the refusals that the gateway records. In the docker stack, `tests/hop.rs` runs the round trip, the refusal, three tunnels in a row, and a tunnel that outlives the default route timeout of Envoy, all through Envoy. Its spec counts the dials and the handshakes of the pool, so the late exchange of the last case proves that one session outlived the timeout. The hop scenarios compile under the `e2e` feature alone, which the grpc e2e lane enables.

```rust
# mod submit {
# use tightbeam::colony::SubmitWork;
# use tightbeam::transport::GenericClient;
# use tightbeam::urn::Urn;
# use tightbeam::{Frame, TightBeamError};
# use tightbeam_grpc::protocol::GrpcListener;
# async fn submit(
#     client: &mut GenericClient<GrpcListener>,
#     servlet_urn: Urn<'static>,
#     signed_work_frame: Frame,
# ) -> Result<Frame, TightBeamError> {
let served = client.submit_work_to(servlet_urn, &signed_work_frame).await?;
# Ok(served)
# }
# }
```

## Coupled edge

Under the `couple` feature, a profile whose bind returns `Edge::Coupled(EdgeTls, Coupler)` serves stock gRPC callers on the edge port of a gateway, beside the tunnel. A stock caller is any gRPC client, in any language, that presents a TLS client certificate: it calls a routed unary method, a hive servlet serves the call, and the caller reads an answer whose signature the coupler verified. A native tunnel client presents no client certificate, and connects to the same port as before.

The edge serves each call by its path:

| The path                                            | The call                                                      |
| --------------------------------------------------- | ------------------------------------------------------------- |
| `TUNNEL_PATH`                                       | The tunnel of a native client                                 |
| `HEALTH_CHECK_PATH`, `/grpc.health.v1.Health/Check` | `SERVING` while the loopback session of the coupler is open   |
| A method of the `Routes` of the coupler             | The coupled call                                              |
| Any other path                                      | status 12, `UNIMPLEMENTED`, after the caller is authenticated |

A tunnel edge answers the health check with `SERVING` while it listens. The first call of a connection fixes its kind: a coupled call on a connection that carries a tunnel, and a tunnel call on a connection that carries coupled calls, refuse with status 14.

### Caller identity

The edge verifies the TLS client chain of each connection under `couple::CallerTrust`, and the leaf names one `couple::Principal`: its SPIFFE ID when it carries one `spiffe://` URI as a subject alternative name, and its subject otherwise. A leaf with two SPIFFE IDs names none. A call proves one `couple::Assurance`:

| Assurance | The call carries                                                                                                                        |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `Vouched` | A verified TLS client chain                                                                                                             |
| `Signed`  | A `couple::CallClaim` under the binary metadata key `tightbeam-claim-bin`, which `couple::ClaimSigner` signs under a tightbeam identity |

A claim signer is a tightbeam identity whose certificate path verifies under the claim store of `CallerTrust` and names the same principal as the TLS leaf. The claim covers the method, the SHA-256 of the encoded request, and the SHA-256 of the TLS leaf, so it moves to no other caller, body, or connection identity. A call that carries a claim that does not verify refuses, and never downgrades to `Vouched`. The replay window of the coupler, 60 seconds unless `Coupler::with_replay_window` sets one, spends each claim once.

### The saga of a coupled call

Each step refuses before the coupler sends anything to the colony, except the last two:

| Step | The coupler                                                                                              | Refuses with                                    |
| ---- | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| 1    | reads the caller of the connection, then the route of the method, its `grpc-timeout`, and its claim      | 16 `UNAUTHENTICATED`, 12, 3 `INVALID_ARGUMENT`  |
| 2    | opens the call on the lane of its connection                                                             | 14 `UNAVAILABLE`                                |
| 3    | verifies the claim                                                                                       | 16                                              |
| 4    | checks that `couple::Grants` grant the method to the principal, and that the route accepts the assurance | 7 `PERMISSION_DENIED`                           |
| 5    | signs a `couple::CoupledCall` under the signer of its `couple::Voucher`, held to the envelope ceiling    | 8 `RESOURCE_EXHAUSTED`, 13 `INTERNAL`           |
| 6    | finds the loopback session open                                                                          | 14                                              |
| 7    | spends the claim                                                                                         | 16                                              |
| 8    | sends the work through the loopback session, within the deadline of the call                             | 4 `DEADLINE_EXCEEDED`, the status of the colony |
| 9    | verifies that the answer answers the request and that the signer that the route pins signed it           | 13                                              |

The loopback session is one tightbeam session from the coupler into the accept queue of its own listener, under the handshake identity of the voucher. The gateway accepts it as any edge connection, so each coupled call passes the handshake, the gates, and the work admission of the edge. The session pins the certificate that the listener presents, and it multiplexes when the gateway sets `pool_config.mux_offer`, and carries one call at a time otherwise. The coupler never sends a call twice, so a servlet that answers after the deadline of its caller keeps its effect.

### Serve a coupled call

A servlet serves a coupled call through `couple::AdmittedCall::admit`, under its `couple::AdmissionTrust`: the vouchers whose signature names a principal, the direct callers that sign their own calls, and the claim store that verifies the claim a vouched call forwards. The admission decides the principal and the assurance from the signer of the frame, and the servlet answers with `AdmittedCall::reply`, signed under the identity that the route of the method pins.

```rust
# mod serve {
# use tightbeam::crypto::sign::SigningIdentity;
# use tightbeam::{Frame, TightBeamError};
# use tightbeam_grpc::couple::{AdmissionTrust, AdmittedCall, Code};
# async fn serve(frame: &Frame, trust: &AdmissionTrust, signer: &SigningIdentity) -> Result<Option<Frame>, TightBeamError> {
let admitted = AdmittedCall::admit(frame, trust)?;
let body = admitted.body().to_vec();
admitted.reply(Code::Ok, body, signer).await
# }
# }
```

Under the `instrument` feature, `Coupler::with_trace` attaches the audit trail of the coupler: `events::COUPLED_CALL_ADMITTED` with the method as its label and the assurance as its value, `events::COUPLED_CALL_REFUSED` with the name of the refusal, and `events::COUPLED_CALL_ANSWERED` with the method and the status code of the answer. The listener of a coupled edge records its tunnel refusals on the same trace.

`tests/coupler.rs` runs a stock tonic client with its own TLS through a colony: the vouched and the signed round trips, each refusal of the table, an answer under an unpinned signer, a servlet that trusts another voucher or claim store, eight calls at once on one connection, both lane kinds, and a mutual edge that trusts the voucher, beside one that refuses it and reads `NOT_SERVING`. In the docker stack, `tests/stock.rs` runs grpcurl, a Go client, against the coupled gateway of the stack with a client certificate and a protobuf `Order` of `grpc/docker/proto/orders.proto`, and reads the same `Order` back.

### Run a coupled gateway

A profile reads the TLS material of the edge, the roots of its callers, and the identities of its voucher from its own sources, and the gateway binds its edge under it. `examples/grpc_coupled_gateway_server.rs` is the coupled gateway of the docker stack, and `examples/gen_coupled_certs.rs` writes the material it reads:

1. The edge presents `edge.crt` with `edge.key` through `EdgeTls::from_pem`.
2. The coupler trusts its callers under `root.pem`, and their claims under `claims.pem`, through `CallerTrust::from_pem`.
3. `Routes::unary` routes `/orders.v1.Orders/Get` to the orders servlet as `Vouched`, and `Grants::grant` grants it to `spiffe://acme/grpcurl`.
4. The gateway binds the edge with `cluster! { ..., edge: GrpcListener<DefaultCryptoProvider, Profile> }`, and the hive registers with it.

The loopback session of the coupler presents the handshake identity of its voucher. A gateway whose accept planes authenticate their clients under `ClusterTlsConfig::client_authentication` trusts that identity, or the session never opens and the edge reads `NOT_SERVING`.

## Backend adapter

Under the `couple` feature, `couple::Backend` is the configuration of a servlet that relays each coupled call it admits to one stock gRPC server. A tightbeam client reaches the server through the colony, in its own name with `CoupledCall::direct`, or as a stock caller of a coupled edge whose coupler vouches for it. The adapter reads the call through the same `AdmittedCall::admit`, so a direct call and a vouched call name their principal the same way.

| Step | The adapter                                                                                                                          | Refuses with                                         |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- |
| 1    | admits the call under its `AdmissionTrust`                                                                                           | `WorkRefused(Unauthenticated)`, no reply             |
| 2    | checks that its `Routes<()>` route the method, that its `Grants` grant it to the principal, and that the route accepts the assurance | a signed reply of 12 or 7                            |
| 3    | calls the server through its `couple::BackendChannel`, within `Backend::with_timeout`                                                | a signed reply of the status of the server, 14, or 4 |
| 4    | signs the reply under its identity                                                                                                   | 13                                                   |

The call of the server is the one step that cannot be undone, and every step that can refuse runs before it. The channel presents the TLS client certificate of the adapter through `DialTls::with_identity`, and each call carries the principal in the binary metadata `Backend::PRINCIPAL_KEY`, `tightbeam-principal-bin`, as the UTF-8 of its SPIFFE ID or its subject, and the claim that a signed call forwards in `tightbeam-claim-bin`. A server that trusts the adapter decides on the principal, and a server that verifies claims checks the caller end to end.

### Call a stock gRPC backend

```rust
# mod relay {
# use tightbeam::{Frame, TightBeamError};
# use tightbeam_grpc::couple::Backend;
# async fn relay(backend: &Backend, frame: &Frame) -> Result<Option<Frame>, TightBeamError> {
let reply = backend.relay(frame).await?;
# Ok(reply)
# }
# }
```

A servlet declares `servlet! { pub LedgerAdapter<CoupledCall, EnvConfig = Backend>, ... }` and answers each frame with `ctx.env_config().relay(&frame)`. Under the `instrument` feature, `Backend::with_trace` records `events::BACKEND_CALL_RELAYED` with the method and the status code of the server, and `events::BACKEND_CALL_REFUSED` with `unrouted` or `denied`. `tests/adapter.rs` runs a stock tonic server that authenticates its clients: a direct call, a call from a stock caller through the coupled edge and the adapter to the server, a principal with no grant, an untrusted signer, and a backend whose assurance floor is above the one of the coupled route.

## Hop requirements

A tunnel lives as long as its session, so every hop between the client and the server MUST carry it unchanged:

- The hop speaks HTTP/2 to the server under the profile of the server: h2c with prior knowledge under `H2c`, and TLS 1.3 with ALPN `h2` under a TLS profile. A hop that terminates TLS from the client opens TLS again to a TLS edge, and a hop that passes TCP through leaves the TLS of the client to reach the edge.
- The hop routes by `:authority` or by `TUNNEL_PATH`, or passes TCP through unchanged, as an L4 load balancer does.
- The hop opens at most one stream at a time on each upstream connection. The server admits one, and HTTP/2 refuses a second that the hop sends before the SETTINGS of the server reach it.
- The hop sets no route timeout. Envoy's default route timeout of 15 seconds ends every tunnel at 15 seconds.
- The stream idle timeout of the hop sits above the operation timeout of the session, 30 seconds by default. A multiplexed session probes at a third of it, and a session with no keepalive stays silent up to the whole of it.
- The idle timeout of the upstream connections of the hop sits below the `handshake_timeout` of the server, 10 seconds by default. The server closes a connection that carries no tunnel at that timeout, with no GOAWAY, so the hop retires the connection first and never sends a tunnel down one the server is closing.
- The hop streams each message as it arrives, and buffers no whole request or response.

`grpc/docker/envoy.yaml` is the Envoy configuration of the docker stack, and it meets each requirement: `codec_type: HTTP2`, a virtual host for the authority of the client, `timeout: 0s` on the route, `stream_idle_timeout: 300s`, and an upstream cluster with `http2_protocol_options` of one concurrent stream and an `idle_timeout` of 5 seconds.

## Limitations

- A TLS edge presents one certificate chain, whatever server name the client sends, and admits TLS 1.3 alone.
- A coupled route and a backend route are unary, because the edge of a gateway admits unary work alone. A stock method that streams cannot be routed.
- Only a Rust caller signs a claim through `ClaimSigner` today. A claim is a DER frame with a CMS signature under secp256k1, which another language can build to the same form.
- The replay window lives in the process of one gateway, so a claim can be spent once on each replica of a gateway.
- The address that `accept` yields is the address of the TCP peer, which is the hop when a hop sits in front of the server.
- A cluster gateway binds its edge listener through `EncryptedProtocol::bind_with`, which takes no trace, and tightbeam keeps the trace of an `EndpointConfig` private, so the edge of a gateway records no tunnel refusal unless it is coupled, whose coupler carries its trace.
- The read cap of each phase applies to a whole message, as [The Envelope Wire Rules](wire.md#limitations) states, so a peer before its handshake can send one message up to the envelope ceiling.

## Sources

- gRPC over HTTP2, `grpc/grpc` `doc/PROTOCOL-HTTP2.md`: <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md>
- gRPC compression, `grpc/grpc` `doc/compression.md`: <https://github.com/grpc/grpc/blob/master/doc/compression.md>
- RFC 9113, HTTP/2, June 2022, sections 3.2, 3.3, and 8.1: <https://www.rfc-editor.org/rfc/rfc9113>
- RFC 8446, TLS 1.3, August 2018: <https://www.rfc-editor.org/rfc/rfc8446>
- RFC 7301, TLS Application-Layer Protocol Negotiation, July 2014: <https://www.rfc-editor.org/rfc/rfc7301>
- RFC 9110, HTTP Semantics, June 2022, sections 8.3.1, 15.5.6, and 15.5.16: <https://www.rfc-editor.org/rfc/rfc9110>
- Envoy, `RouteAction.timeout`, `HttpConnectionManager.stream_idle_timeout`, and `HttpProtocolOptions.idle_timeout`: <https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto>
- gRPC health checking, `grpc/grpc` `doc/health-checking.md`: <https://github.com/grpc/grpc/blob/master/doc/health-checking.md>
- SPIFFE ID, `spiffe/spiffe` `standards/SPIFFE-ID.md`: <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md>
- CWE-294, Authentication Bypass by Capture-replay: <https://cwe.mitre.org/data/definitions/294.html>
- CWE-319, Cleartext Transmission of Sensitive Information: <https://cwe.mitre.org/data/definitions/319.html>
- CWE-400, Uncontrolled Resource Consumption: <https://cwe.mitre.org/data/definitions/400.html>
- CWE-770, Allocation of Resources Without Limits or Throttling: <https://cwe.mitre.org/data/definitions/770.html>
