# The gRPC Transport

Reference for `tightbeam-grpc`, from its [README](../grpc/tightbeam-grpc/README.md). Tasks: [Connect gRPC Systems to a Colony](grpc-interop.md). Envelope rules: [The Envelope Wire Rules](wire.md).

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

`protocol::GrpcListener<P, C>`. `P` is the `CryptoProvider`, `DefaultCryptoProvider` by default. `C` is the [edge profile](#edge-profile), `edge::H2c` by default.

| Trait                  | Supplies                                                          |
| ---------------------- | ----------------------------------------------------------------- |
| `Protocol`             | `bind_cleartext`, `connect`, `connect_within`, `create_transport` |
| `EncryptedProtocol`    | `bind_with(addr, TransportEncryptionConfig)`                      |
| `AsyncListenerTrait`   | `accept`: the transport and the peer `GrpcAddr`                   |
| `PersistentConnection` | `is_connected`, so `ConnectionPool` reuses a tunnel               |

- `bind_cleartext` runs no tightbeam handshake: no authentication, no confidentiality (CWE-319).
- `bind_with` runs the tightbeam handshake inside each tunnel. Profile TLS protects only the hop.
- HTTP/2 only: h2c under `H2c`, TLS 1.3 under a TLS profile.
- `accept` skips a tunnel whose call already ended.
- `accept` fails with `IoError` when a TCP accept fails, and with `ConnectionClosed` once the server stops.
- Dropping the listener ends every tunnel not yet accepted. An accepted tunnel lives on.

`protocol::GrpcAddr` is `host:port`, sent as `:authority`. The host is a bracketed IPv6 address, an IPv4 address, or a DNS name, compared without case.

| Parses                                               | Refuses with `InvalidAddress`                   |
| ---------------------------------------------------- | ----------------------------------------------- |
| `127.0.0.1:0`, `[::1]:7443`, `gateway.internal:7443` | `gateway.internal`, `:80`, `*:1`, `user@host:1` |

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

`bind_with` and `connect` carry no deployment value, so the deployment is the type `C: edge::EdgeProfile`.

| Method                | Called                         | Returns                                      |
| --------------------- | ------------------------------ | -------------------------------------------- |
| `EdgeProfile::edge()` | Once per bind, before it binds | `Edge::H2c`, `Edge::Tls`, or `Edge::Coupled` |
| `EdgeProfile::dial()` | Once per dial                  | `Dial::H2c` or `Dial::Tls`                   |

- A profile reads its own files. A failure is an `edge::EdgeError`, and binds no socket.
- `EdgeTls::from_pem(chain, key)` loads the edge certificate. `DialTls::from_pem(roots)` loads the dial roots.
- The edge certificate names the host that a dial verifies.
- TLS 1.3 and ALPN `h2` only, under rustls with ring.

```rust
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam_grpc::edge::{Dial, DialTls, Edge, EdgeError, EdgeProfile, EdgeTls};
use tightbeam_grpc::protocol::GrpcListener;

struct Orders;

impl EdgeProfile for Orders {
    fn edge() -> Result<Edge, EdgeError> {
        Ok(Edge::Tls(EdgeTls::from_pem("/run/edge/tls.crt", "/run/edge/tls.key")?))
    }

    fn dial() -> Result<Dial, EdgeError> {
        Ok(Dial::Tls(DialTls::from_pem("/run/edge/ca.crt")?))
    }
}

/// `cluster! { ..., edge: OrdersEdge }` binds it, and a client dials it.
type OrdersEdge = GrpcListener<DefaultCryptoProvider, Orders>;
```

Tests: `tests/tls.rs`. The `testing` feature adds `testing::TlsAuthority` and `staged_profile!`.

## Connection slots

Each connection is bounded before any handshake proves its peer:

| Bound                                        | Effect                                                                  |
| -------------------------------------------- | ----------------------------------------------------------------------- |
| 1024 slots, `DEFAULT_MAX_SERVER_CONNECTIONS` | A connection holds a slot until its tunnel is accepted (CWE-770)        |
| `handshake_timeout`                          | A connection with no call, or a tunnel nobody accepts, closes (CWE-400) |
| TLS handshake                                | Runs on its own task, under the slot and the same deadline              |
| One stream per connection                    | `SETTINGS_MAX_CONCURRENT_STREAMS` is 1 on a tunnel edge                 |

- A call that ends before its tunnel is accepted returns the connection to its old slot and deadline.
- A replacing call keeps the old expiry, so no connection renews its deadline.
- After an accepted tunnel ends, the connection waits under a free slot. With none free, its calls refuse with 14.
- A waiting connection gets a slot before a new TCP accept.

## Tunnel call

One bidirectional call on `TUNNEL_PATH`, `/tightbeam.v1.Transport/Connect`, under `application/grpc`. Each message is the DER of one envelope.

| The call                              | Refused with                        | By         |
| ------------------------------------- | ----------------------------------- | ---------- |
| Not `POST`                            | HTTP 405, `Allow: POST`             | the tunnel |
| Not `application/grpc` or a subtype   | HTTP 415                            | the tunnel |
| A path the edge does not serve        | 12 `UNIMPLEMENTED`                  | the tunnel |
| No free slot, or a full queue         | 14 `UNAVAILABLE`                    | the tunnel |
| `grpc-encoding` other than `identity` | 12                                  | tonic      |
| A compressed message with no encoding | 13 `INTERNAL`, on read              | tonic      |
| A message past the envelope ceiling   | 11 `OUT_OF_RANGE`, by declared size | tonic      |

- The content type compares without case (RFC 9110 section 8.3.1).
- The ceiling is `TransportLimits::max_envelope`, in both directions.
- The server ends its own tunnels with 0. tightbeam frames carry session refusals.

Under `instrument`, `GrpcListener::with_trace(trace)` records each tunnel refusal as `events::TUNNEL_REFUSED`: `method`, `media-type`, `path`, `busy`, or `unconnected`.

- tonic's refusals, and calls before the attach, record nothing.
- A refused message records on its transport trace as `TRANSPORT_ENVELOPE_REFUSED`.

## Stream and envelope rules

- `io::GrpcStream` is the `WireDuplex` of `GrpcReadHalf` and `GrpcWriteHalf`. It splits for a mux connection.
- `io::GrpcTransport<P>` is `TcpTransport<GrpcStream, P>`.
- A dial owns one HTTP/2 connection and its one call. A lost connection ends the tunnel.
- No `grpc-timeout`: tightbeam's `Deadlined` bounds every read and write.
- One message is one envelope. tonic batches writes up to 32 KiB.
- The read half classifies the end of the call once.
- An accepted tunnel answers the status that failed its inbound messages.

| The end of the call                             | `Wire`             | `TransportError`                |
| ----------------------------------------------- | ------------------ | ------------------------------- |
| The end of the message stream, or a cancel      | `Closed`           | `ConnectionClosed`              |
| `CANCELLED`, `UNAVAILABLE`, `DEADLINE_EXCEEDED` | `Closed`           | `ConnectionClosed`              |
| `OUT_OF_RANGE`                                  | `Failed(Oversize)` | `OperationFailed(SizeExceeded)` |
| An I/O error in the source chain                | `Failed(Io)`       | `IoError`                       |
| Any other status                                | `Failed(Invalid)`  | `InvalidMessage`                |

A failed dial classifies its error the same way.

## Cluster work plane

- Declare `cluster! { ..., protocol: TokioListener, edge: GrpcListener }`, and set `ClusterConfig::edge_bind_addr`.
- Enable `colony` on `tightbeam-rs`.
- The edge admits `Work` alone. A control frame refuses with `PermissionDenied`.
- `GenericClient<GrpcListener>` and `PooledClient<GrpcListener>` submit through `submit_work_to`.
- Signed frames pass the gateway unchanged, both ways.

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

Tests: `tests/work_plane.rs`, and `tests/hop.rs` through Envoy in the docker stack.

## Coupled edge

Under `couple`, `Edge::Coupled(EdgeTls, Coupler)` serves stock gRPC callers beside the tunnel, on one port.

- A stock caller is any gRPC client with a TLS client certificate. It calls a routed unary method.
- A native tunnel client needs no client certificate.
- The first call fixes the kind of a connection. A call of the other kind refuses with 14.

| Path                             | Served by                                    |
| -------------------------------- | -------------------------------------------- |
| `TUNNEL_PATH`                    | The tunnel                                   |
| `/grpc.health.v1.Health/Check`   | `SERVING` while the loopback session is open |
| A method of the coupler `Routes` | The coupler                                  |
| Anything else                    | 12, after the caller is authenticated        |

### Caller identity

- The edge verifies the client certificate under `couple::CallerTrust`.
- The certificate names one `couple::Principal`: its single `spiffe://` URI, or else its subject.

| Assurance | The call carries                                                |
| --------- | --------------------------------------------------------------- |
| `Vouched` | A verified client certificate                                   |
| `Signed`  | Also a `CallClaim` in `tightbeam-claim-bin`, from `ClaimSigner` |

- A claim signer is a tightbeam identity for the same principal, under the claim store of `CallerTrust`.
- A claim covers the method, the body hash, and the TLS certificate hash.
- A bad claim refuses with 16. It never downgrades to `Vouched`.
- The replay window spends each claim once: 60 s, or `Coupler::with_replay_window`.
- A call that times out before it holds the session keeps its claim.

### Steps of a coupled call

| Step | The coupler                                                | Refuses with        |
| ---- | ---------------------------------------------------------- | ------------------- |
| 1    | reads the caller, the route, `grpc-timeout`, and the claim | 16, 12, 3           |
| 2    | opens the call on its lane                                 | 14                  |
| 3    | verifies the claim                                         | 16                  |
| 4    | checks the grant and the assurance floor                   | 7                   |
| 5    | signs a `CoupledCall` under its `Voucher`                  | 8, 13               |
| 6    | finds the loopback session open                            | 14                  |
| 7    | holds the session within the deadline                      | 4                   |
| 8    | spends the claim                                           | 16                  |
| 9    | sends the work                                             | 4, or colony status |
| 10   | checks the answer id and its pinned signer                 | 13                  |

- The coupler never sends a call twice.
- A spent claim is forgotten only when the frame provably never left.
- The loopback session runs into the coupler's own listener, so the gateway admits it like any edge client.
- The session multiplexes when the gateway sets `pool_config.mux_offer`, and runs one call at a time otherwise.

### `AdmittedCall`

- `admit(frame, trust)` takes the principal and the assurance from the signer of the frame.
- `AdmissionTrust` holds the vouchers, the direct callers, and the claim store, from `CallerTrust::claim_store`.
- `reply(code, body, signer)` signs under the identity that the route pins.

### Events and tests

- Under `instrument`, `Coupler::with_trace` records `COUPLED_CALL_ADMITTED`, `_REFUSED`, and `_ANSWERED`.
- A mutual edge that refuses the voucher handshake identity reads `NOT_SERVING`.
- Tests: `tests/coupler.rs`, and `tests/stock.rs` in the docker stack.

## Backend adapter

`couple::Backend` configures a servlet that relays each coupled call to one stock gRPC server.

| Step | The adapter                                      | Refuses with                     |
| ---- | ------------------------------------------------ | -------------------------------- |
| 1    | admits the call                                  | `WorkRefused`, no reply          |
| 2    | checks the route, the grant, and the floor       | a signed 12 or 7                 |
| 3    | calls the server, within `Backend::with_timeout` | a signed server status, 14, or 4 |
| 4    | signs the reply                                  | 13                               |

- The adapter presents its client certificate, from `DialTls::with_identity`.
- Each call carries the principal in `tightbeam-principal-bin`, and any claim in `tightbeam-claim-bin`.
- A tightbeam client calls it with `CoupledCall::direct`.
- Under `instrument`, `Backend::with_trace` records `BACKEND_CALL_RELAYED` and `BACKEND_CALL_REFUSED`.
- Tests: `tests/adapter.rs`.

## Hop requirements

A hop MUST carry a tunnel unchanged for the life of its session:

- Speak HTTP/2 to the server under its profile: h2c, or TLS 1.3 with ALPN `h2`.
- Route by `:authority` or `TUNNEL_PATH`, or pass TCP through.
- Open at most one stream per upstream connection.
- Set no route timeout. Envoy's default of 15 s ends every tunnel.
- Keep the stream idle timeout above the session operation timeout, 30 s by default.
- Keep the upstream idle timeout below the server `handshake_timeout`, 10 s by default.
- Stream messages. Buffer nothing whole.

`grpc/docker/envoy.yaml` meets each one: `codec_type: HTTP2`, route `timeout: 0s`, `stream_idle_timeout: 300s`, one upstream stream, and upstream `idle_timeout: 5s`.

## Limitations

- A TLS edge presents one certificate chain, and admits TLS 1.3 alone.
- Coupled and backend routes are unary. The gateway edge refuses streams.
- Only Rust has a `ClaimSigner`. Other languages get `Vouched`.
- The replay window is per gateway process, so a claim can be spent once per replica.
- `accept` yields the TCP peer, which is the hop when one sits in front.
- A gateway edge records no tunnel refusals, unless it is coupled.
- Before its handshake, a peer can send one message up to the envelope ceiling ([The Envelope Wire Rules](wire.md#limitations)).

## Sources

- gRPC over HTTP2, `grpc/grpc` `doc/PROTOCOL-HTTP2.md`: <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md>
- gRPC compression, `grpc/grpc` `doc/compression.md`: <https://github.com/grpc/grpc/blob/master/doc/compression.md>
- gRPC health checking, `grpc/grpc` `doc/health-checking.md`: <https://github.com/grpc/grpc/blob/master/doc/health-checking.md>
- RFC 9113, HTTP/2, June 2022, sections 3.2, 3.3, and 8.1: <https://www.rfc-editor.org/rfc/rfc9113>
- RFC 8446, TLS 1.3, August 2018: <https://www.rfc-editor.org/rfc/rfc8446>
- RFC 7301, TLS ALPN, July 2014: <https://www.rfc-editor.org/rfc/rfc7301>
- RFC 9110, HTTP Semantics, June 2022, sections 8.3.1, 15.5.6, and 15.5.16: <https://www.rfc-editor.org/rfc/rfc9110>
- Envoy, `RouteAction.timeout`, `HttpConnectionManager.stream_idle_timeout`, and `HttpProtocolOptions.idle_timeout`: <https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto>
- SPIFFE ID, `spiffe/spiffe` `standards/SPIFFE-ID.md`: <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md>
- CWE-294, Authentication Bypass by Capture-replay: <https://cwe.mitre.org/data/definitions/294.html>
- CWE-319, Cleartext Transmission of Sensitive Information: <https://cwe.mitre.org/data/definitions/319.html>
- CWE-400, Uncontrolled Resource Consumption: <https://cwe.mitre.org/data/definitions/400.html>
- CWE-770, Allocation of Resources Without Limits or Throttling: <https://cwe.mitre.org/data/definitions/770.html>
