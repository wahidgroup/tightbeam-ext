# The gRPC Transport

Reference for `tightbeam-grpc`, from its [README](../grpc/tightbeam-grpc/README.md). Tasks: [Connect gRPC Systems to a Colony](grpc-interop.md). Envelope rules: [The Envelope Rules of Message Sockets](wire.md).

## Contents

- [Listener](#listener)
- [Edge profile](#edge-profile)
- [Connection slots](#connection-slots)
- [Tunnel call](#tunnel-call)
- [Stream and envelope rules](#stream-and-envelope-rules)
- [Cluster work plane](#cluster-work-plane)
- [Coupled edge](#coupled-edge)
- [Backend adapter](#backend-adapter)
- [Claim encoding](#claim-encoding)
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

| Method                | Called                         | Returns                                             |
| --------------------- | ------------------------------ | --------------------------------------------------- |
| `EdgeProfile::edge()` | Once per bind, before it binds | `Edge::h2c()`, `Edge::tls(..)`, `Edge::coupled(..)` |
| `EdgeProfile::dial()` | Once per dial                  | `Dial::H2c` or `Dial::Tls`                          |

- A profile reads its own files. A failure is an `edge::EdgeError`. A coupler that refuses its configuration fails with `couple::CoupleError`, which converts to `EdgeError::Couple`.
- A bind builds its TLS acceptor, its client verifier, and the pin of its coupler before it binds its socket, so a refused profile binds no socket. A coupled edge bound in the clear fails with `MissingEncryption`, and a refused certificate with `InvalidCertificate`.
- `staged_profile! { Orders }` declares a profile whose material its process stages at run time, through `Orders::stage(edge, dial)`, before its gateway binds. Its cell is static, so it holds one deployment per process, and each deployment of one process declares a type.
- Under `instrument`, `Edge::with_trace(trace)` is the one trace of each bind of the edge, from its first connection on: the refusals of the edge, its PROXY headers, and the calls of its coupler. A gateway binds its edge with no trace of its own.
- `Edge::with_clock(clock)` runs every timer of each bind on a tightbeam `Clock`, in place of `SystemClock`: the deadline of each connection and of its PROXY header and TLS handshake, the pause after a failed accept, and each deadline of each tunnel transport. On a coupled edge it also runs the deadline of each call, the call limit of each watch, and the transport, the probes, and the backoff of the loopback session.
- On a coupled edge, the same clock gives the time that the coupler judges the freshness of each claim and the expiry of each bearer token at.
- A clock that gives a wait no timer, `Lapse::NoTimer`, refuses that wait: a connection as `no-timer`, a health watch with 13, and a coupled call with 13, or with 4 when the wait is its send or the push of the head of its stream.
- `EdgeTls::from_pem(EdgeTlsFiles { chain, key })` loads the edge certificate. `DialTls::from_pem(roots)` loads the dial roots.
- The edge certificate names the host that a dial verifies.
- TLS 1.3 and ALPN `h2` only, under rustls with ring.

```rust
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam_grpc::edge::{Dial, DialTls, Edge, EdgeError, EdgeProfile, EdgeTls, EdgeTlsFiles};
use tightbeam_grpc::protocol::GrpcListener;

struct Orders;

impl EdgeProfile for Orders {
	fn edge() -> Result<Edge, EdgeError> {
		let files = EdgeTlsFiles { chain: "/run/edge/tls.crt", key: "/run/edge/tls.key" };
		Ok(Edge::tls(EdgeTls::from_pem(files)?))
	}

	fn dial() -> Result<Dial, EdgeError> {
		Ok(Dial::Tls(DialTls::from_pem("/run/edge/ca.crt")?))
	}
}

/// `cluster! { ..., edge: OrdersEdge }` binds it, and a client dials it.
type OrdersEdge = GrpcListener<DefaultCryptoProvider, Orders>;
```

Tests: `tests/tls.rs` and `tests/edge.rs`. The `testing` feature adds:

- `testing::TlsAuthority`, which creates a TLS PKI at run time.
- `testing::CoupledStack`, the coupled edge of the e2e stack: its routes, its callers, and its files. `write(lifetime, claims)` stages the whole set beside its directory, and a rename publishes it, so the directory holds every file from the moment it exists.
- Under `couple`, `testing::StreamParts` and `testing::PartFrames`, the parts of a coupled stream as any peer writes and reads them, under keys that the peer picks. `StreamParts::open` takes the `testing::StreamSigners` of the head and of the later parts, and gives the `testing::OpenedStream` of the framed head and those parts.

### PROXY protocol

- `Edge::with_proxy_protocol(ProxyHops::new(["10.0.0.0/8"])?)` reads a PROXY protocol v2 header from each connection of those hops.
- The source address of the header becomes the peer that `accept` yields.
- A `LOCAL` header, such as a health check of the hop, keeps the hop as the peer.
- A connection of a hop with no header, or a malformed one, closes.
- The edge reads a header from the addresses of its hops alone, so only a hop names another client.
- The header is read before TLS, under the slot and the deadline of the connection.
- Under `instrument`, `Edge::with_trace(trace)` records each header that the edge reads as `events::PROXY_HEADER_READ`, labeled `client` or `local`, with the peer it takes as its value.
- It records each header that it refuses as `events::PROXY_HEADER_REFUSED`: `malformed` for no header or a malformed one, and `ended` for a connection that ends within its header.

## Connection slots

Each connection is bounded before any handshake proves its peer:

| Bound                                        | Effect                                                                  |
| -------------------------------------------- | ----------------------------------------------------------------------- |
| `DEFAULT_MAX_SERVER_CONNECTIONS` slots       | A connection holds a slot until its tunnel is accepted (CWE-770)        |
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
| No connection of the server           | 13 `INTERNAL`                       | the tunnel |
| A lane or a queue with no room        | 14 `UNAVAILABLE`                    | the tunnel |
| `grpc-encoding` other than `identity` | 12                                  | tonic      |
| A compressed message with no encoding | 13 `INTERNAL`, on read              | tonic      |
| A message past the envelope ceiling   | 11 `OUT_OF_RANGE`, by declared size | tonic      |

- The content type compares without case (RFC 9110 section 8.3.1).
- The ceiling is `TransportLimits::max_envelope`, in both directions.
- The server ends its own tunnels with 0. tightbeam frames carry session refusals.

Under `instrument`, the trace of the profile records each of these refusals, which the edge makes before any session exists, as `events::EDGE_REFUSED`, by its kind:

| Label                                                                            | The edge refused                                                  |
| -------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `method`, `media-type`, `path`, `unconnected`                                    | a call, as the table above names it                               |
| `queue-full`                                                                     | a tunnel call, when the queue of tunnels for `accept` has no room |
| `no-slot`, `other-kind`, `tunnel-held`, `closed`                                 | a tunnel call that the lane of its connection refuses             |
| `tls`                                                                            | a connection whose TLS handshake failed                           |
| `late`                                                                           | a connection that passed neither its PROXY header nor TLS in time |
| `no-timer`                                                                       | a connection whose wait the clock of the edge gave no timer       |

- tonic's refusals record no `EDGE_REFUSED`.
- A PROXY header that the edge refuses records `events::PROXY_HEADER_REFUSED` alone, as [PROXY protocol](#proxy-protocol) states.
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

- Declare `cluster! { ..., protocol: WsListener, edge: GrpcListener }` with `tightbeam_ws::protocol::WsListener`, and set `ClusterConfig::edge` to an `EdgePlane`.
- Enable `colony` on `tightbeam-rs`, and add `tightbeam-ws` with its `colony` feature for `WsListener`.
- The edge admits `Work`. A control frame refuses with `PermissionDenied`.
- `EdgePlane::with_streams` also admits stream and duplex opens to servlets. A coupler with stream routes needs it.
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
# 	client: &mut GenericClient<GrpcListener>,
# 	servlet_urn: Urn<'static>,
# 	signed_work_frame: Frame,
# ) -> Result<Frame, TightBeamError> {
let served = client.submit_work_to(servlet_urn, &signed_work_frame).await?;
# Ok(served)
# }
# }
```

Tests: `tests/work_plane.rs`, and `tests/hop.rs` through Envoy in the docker stack.

## Coupled edge

Under `couple`, `Edge::coupled(EdgeTls, Coupler)` serves stock gRPC callers beside the tunnel, on one port.

- A stock caller is any gRPC client that the edge identifies. It calls a routed method.
- A native tunnel client needs no client certificate.
- The first call fixes the kind of a connection. A call of the other kind refuses with 14, which the trail records as `other-kind`.

| Path                                                  | Served by                                        |
| ----------------------------------------------------- | ------------------------------------------------ |
| `TUNNEL_PATH`                                         | The tunnel                                       |
| `/grpc.health.v1.Health/Check` and `Watch`            | [Health](#health), on every edge                 |
| `/grpc.reflection.v1.ServerReflection/` and `v1alpha` | [Reflection](#reflection), when it is configured |
| A method of the coupler `Routes`                      | The coupler                                      |
| Anything else                                         | 12, after the caller is authenticated            |

- A method is a `couple::MethodPath`: `/`, a service name, `/`, and a method name, each of visible ASCII with no `/`, no `?`, and no `#`.
- `Routes`, `Grants::grant`, and `CoupledCall::direct` take a `MethodPath` or text that parses as one, and refuse other text with `CoupleError::Method`.
- `Routes` also refuses `TUNNEL_PATH`, a health or reflection method, or a repeat, with `CoupleError::Method`.
- The routes and the grants of a coupler or a backend decide each call once: a route for the method and its carriage, a grant of the principal, and the assurance floor of the route.

### Caller identity

`couple::CallerTrust` names the caller of each call:

| The call proves                                                               | Principal                                 | Assurance without a claim |
| ----------------------------------------------------------------------------- | ----------------------------------------- | ------------------------- |
| A client certificate under the TLS roots and CRLs                             | Its single SPIFFE ID, or else its subject | `Vouched`                 |
| A chain in `x-forwarded-client-cert`, from `with_forwarding_proxy(principal)` | The forwarded leaf, as above              | `Vouched`                 |
| A JWT-SVID in `authorization: Bearer`, under `with_bearer(BearerTrust)`       | Its `sub`                                 | `Bearer`                  |

- A subject principal is the subject as `Principal::subject` parses its RFC 4514 string, so a PrintableString subject and a UTF8String subject of the same text are one principal.
- A principal SPIFFE ID names a workload: `spiffe://`, a trust domain of lowercase letters, digits, `.`, `-`, and `_`, and a path of one or more segments. Each segment is letters, digits, `.`, `-`, and `_`, and is neither `.` nor `..`.
- A certificate with two SPIFFE IDs, or with a `spiffe://` URI off that grammar, such as `spiffe://acme`, names no principal, and its call refuses with 16. The TLS path, the bearer path, and each servlet read a principal by this one rule.
- A connection of the forwarding proxy names its caller by the last XFCC element, the one the proxy appended, or else by a bearer token. The edge verifies the forwarded chain under its own roots and CRLs.
- A client chain may pass through intermediate authorities to a TLS root. A caller presents them after its leaf, and a proxy forwards them in `Chain`.
- The XFCC field follows the Envoy grammar strictly. Two fields, an unknown or repeated key, or a value that is neither a token nor one whole quoted string refuses the call with 16.
- `Cert` holds one certificate. A `Chain` beside a `Cert` starts with it.
- Set the proxy to replace the field, Envoy `SANITIZE_SET`, so each field that reaches the edge is one that the proxy set.
- Any other connection with a client certificate names its own caller, whatever its headers say.
- A connection with none names its caller by a bearer token.
- `BearerTrust::from_jwks(trust_domain, audience, jwks)` pins the ES256 keys of the bundle of one trust domain by `kid`. A trust domain off its grammar refuses with `CoupleError::Principal`.
- A token MUST carry `alg` `ES256`, a known `kid`, the audience in `aud`, an `exp`, and the SPIFFE ID of a workload of the trust domain in `sub`. `with_leeway` widens `exp` and `nbf`, by `BearerTrust::DEFAULT_LEEWAY` unless it is set.
- `exp` and an `nbf` are NumericDates: JSON numbers of seconds since the epoch, which may hold a fraction. A token whose `exp` or `nbf` is any other value refuses with 16.
- `authorization` and `x-forwarded-client-cert` name the caller to the edge alone. `with_forwarded_metadata` and `CoupledCall::with_metadata` refuse them.
- A call that proves no caller refuses with 16.

`CallerTrust::with_crls(crls)` checks each client chain, direct or forwarded, against the CRL of each issuer:

| The chain holds                                  | A direct caller fails its handshake with | A forwarded chain refuses its call with |
| ------------------------------------------------ | ---------------------------------------- | --------------------------------------- |
| A certificate that the CRL of its issuer revokes | `certificate_revoked`                    | 16                                      |
| A certificate whose issuer has no CRL in `crls`  | `unknown_ca`                             | 16                                      |
| A certificate under a CRL past its `nextUpdate`  | `unknown_ca`                             | 16                                      |

| Assurance | The call carries                                                     |
| --------- | -------------------------------------------------------------------- |
| `Bearer`  | A verified bearer token, which anyone who holds it can present       |
| `Vouched` | A verified client chain, its own or one that a pinned proxy forwards |
| `Signed`  | Also a `CallClaim` in `tightbeam-claim-bin`, bound to that chain     |

- A route that requires `Vouched` refuses a `Bearer` call with 7.
- A claim signer is a tightbeam identity for the same principal, under the claim store of `CallerTrust`.
- A claim covers the method, the body hash, and the TLS certificate hash, so a bearer caller holds no claim. The [claim encoding](#claim-encoding) specifies it.
- A bad claim refuses with 16, and the call stays refused at any lower assurance.
- The coupler spends each claim once in its claim ledger, within the replay window: `Coupler::DEFAULT_REPLAY_WINDOW`, or `Coupler::with_replay_window`, which takes a window of at most one day.

### Claim ledger

- A `couple::ClaimLedger` driver holds the spent claims. The coupler holds `MemoryLedger`, of its process alone, unless `Coupler::with_claim_ledger(Arc<dyn ClaimLedger>)` sets another.
- A clone of a coupler shares its ledger, and each bind of a clone starts its own replay window and loopback session.
- Replicas of an edge that share one ledger spend a claim once between them.
- A `ClaimSpend` carries the `ClaimKey` that names the claim, the `SignerDigest` of its signer, its expiry, and a `HolderId` of its own. The coupler builds a spend only from a verified claim, and `testing::LedgerConformance` builds its own.
- The key of a spend is the SHA-256 of the signer and the order of the claim, because one signer issues one claim at one order.
- The coupler checks the freshness of a claim on its own clock, so a key lives until its claim leaves the window.
- `ClaimLedger::spend(spend, now)` takes that clock, so a driver judges each expiry at `now` and reads no clock of its own.

| A driver MUST                                       | Because                                       |
| --------------------------------------------------- | --------------------------------------------- |
| Take a key and test it in one atomic operation      | Of racing spends of one key, exactly one wins |
| Answer `false` for a key that a live spend holds    | A replay on any replica refuses with 16       |
| Answer `false` for a spend past its expiry at `now` | A stale claim is no fresh spend               |
| Take each key on its own, by key and not by signer  | Two claims of one signer both serve           |
| Free a key at `ClaimSpend::expires`                 | The store holds one window of spends alone    |
| Free a key on `forget` only for its `holder`        | A forget frees the spend that made it alone   |
| Answer `LedgerError` when the store fails           | A failed spend refuses the call with 14       |

- A driver MAY refuse a fresh key of a signer that holds `REPLAY_GUARD_CAPACITY` live spends or more, as `MemoryLedger` does, the bound of `tightbeam::colony::hive::gates`. The coupler reads that refusal as a replay.
- A failed forget keeps the claim spent, and the call answers its own fault.
- `testing::LedgerConformance::new(ledger).check()` checks the first six rows of the table against a driver, on a tokio runtime of two workers or more, and refuses any other runtime with `LedgerBreach::Runtime`. A driver runs it in its own tests.
- The crate ships no driver of a shared store.
- A call keeps its claim when it times out before it holds a live session, or finds the session dead.

### Steps of a coupled call

| Step | The coupler                                                           | Refuses with  |
| ---- | --------------------------------------------------------------------- | ------------- |
| 1    | reads the caller, the route, the grant, `grpc-timeout`, and the claim | 16, 12, 7, 3  |
| 2    | opens the call on its lane                                            | 14            |
| 3    | reads the body, and verifies the claim                                | 16            |
| 4    | checks the assurance floor                                            | 7             |
| 5    | finds the loopback session open                                       | 14            |
| 6    | holds a live session, with a free stream on a multiplexed one         | 14            |
| 7    | signs a `CoupledCall` under its `Voucher`                             | 8, 13         |
| 8    | spends the claim                                                      | 16, 14        |
| 9    | sends the work, and waits again for a stream that another call took   | colony status |
| 10   | checks the answer id and its pinned signer                            | 13            |

- The deadline of the call bounds steps 2 to 10, and refuses with 4 once it passes.
- From step 8, the spend and the send of step 9 each hold the deadline themselves, so a call answers 4 only after it forgets or keeps the claim.
- A forget holds the call limit once more, from its own start. A forget that the ledger does not answer within it keeps the claim spent, so a call ends within its deadline and one more call limit.
- A ledger that answers the spend at the deadline or later may have taken the claim, so the coupler forgets the spend before it answers 4. The caller may retry the claim.
- The trail records one end of each call: its answer, its refusal, `refused` when tonic refuses its request before the coupler reads it, or `cancelled` when its caller ends it first.
- `Coupler::with_call_limits(CallLimits)` sets the deadline of each call, the coupled connections, and the calls on each one, from the defaults that `CallLimits` documents.
- `with_call_limits` refuses limits of fewer than 2 streams on a coupler with a stream route, with `CoupleError::Streams`.
- `CallLimits::with_timeout` takes a deadline of at most one day.
- The coupler sends each call at most once.
- A send that fails before the frame leaves the session, as tightbeam proves with `TransportError::is_connection_error`, forgets the spent claim, so the caller may retry it. A gateway that refuses the work before its handler runs is such a send.
- A send whose deadline passes while it waits again for a stream forgets its claim too, because the session refused its frame for want of a stream.
- Every other failed send keeps the claim spent, because the frame may have reached the servlet. A status that the gateway answers after its handler ran, such as `RESOURCE_EXHAUSTED`, is one.
- A call that its caller ends from step 8 on keeps any claim that its ledger took.
- The loopback session runs into the coupler's own listener, so the gateway admits it like any edge client.
- The session multiplexes when the gateway sets `pool_config.mux_offer`, and runs one call at a time otherwise.
- A single session that a call left mid-exchange reopens before it carries another call.

### Streams

| Route                   | Requests | Answers |
| ----------------------- | -------- | ------- |
| `Routes::unary`         | 1        | 1       |
| `Routes::client_stream` | many     | 1       |
| `Routes::server_stream` | 1        | many    |
| `Routes::bidi_stream`   | many     | many    |

- A stream needs a multiplexed loopback session. A single session refuses it with 14.
- Open streams take at most half the streams of the loopback session, so a coupler with a stream route needs 2 streams or more. Past that half, a stream refuses with 8.
- Steps 1 to 4 run as for a unary call. The stream then takes a relay permit before step 5 finds the loopback session open, and at step 6 it opens a duplex stream to the servlet. Steps 7 and 8 sign and spend as for a unary call, and step 9 pushes the head: the `CoupledCall` with an empty body and its stream terms. A push of the head that passes the deadline keeps the claim spent, because the head may have reached the servlet whole.
- The stream terms fix the shape of the method and the ceiling of each part, the envelope ceiling of the edge. Both ends keep to them.
- Every part, the head first, is a signed frame behind a 4-byte big-endian length, within the envelope ceiling of the edge. Each later part carries the call id, in order from 1.
- The voucher signs each request part. The coupler verifies each answer part under the pinned signer, at the next order.
- The last answer part carries the status. Once the coupler reads it, the coupler ends the requests and reads the stream to its end within the deadline. A failure of the stream after that part, or a deadline that passes before the stream ends, leaves the status to it. A request that meets a stream that the servlet ended leaves the status to the answer.
- A claim on a stream covers its method and its certificate, over an empty body.
- A count of messages that the route does not take refuses with 12, as gRPC answers a cardinality violation, at either end. A part past the part ceiling refuses with 8, at either end.
- An end part on the request side refuses with 3, because the requests end by a close.
- The coupler counts the answers of the servlet itself, so a servlet outside the stream library that breaks the shape refuses as `answer-shape`.
- The relay of a stream runs on a task of its own. The deadline of the call ends it, however slowly either side reads, and the drop of the response ends it at once, as `cancelled`.
- The relay frees the slot and the relay permit of its stream before it records the end.

### Health

| Edge           | `Check` and `Watch` read                                                        |
| -------------- | ------------------------------------------------------------------------------- |
| A tunnel edge  | `SERVING` while it listens                                                      |
| A coupled edge | `SERVING` once the loopback session outlives a probe, `Coupler::LIVENESS_PROBE` |

- `Check` refuses a named service with 5. `Watch` reads `SERVICE_UNKNOWN` for one, and holds.
- `Watch` answers the status at once, then each change.
- A watch of a caller that the edge identifies, and that a grant names, holds its connection, and ends with 0 at the call limit of the coupler. The caller watches again.
- The call limit covers the read of the request of the watch too.
- Any other watch ends with the deadline of its connection.
- A session that the gateway refuses after its handshake reads `NOT_SERVING`.
- A session that fails to open, or ends, opens again after `Coupler::SESSION_BACKOFF`.

### gRPC-Web

- `Coupler::with_grpc_web(["https://shop.example"])` serves gRPC-Web, binary and text, to the pages of those origins.
- The edge answers the CORS preflight of each origin with 204, and lets the page read `grpc-status`, `grpc-message`, and `grpc-status-details-bin`.
- A preflight or a call from another origin reads 403. A gRPC-Web call with no `origin` is served.
- `with_grpc_web` serializes each origin as RFC 6454 does: the scheme and the host in lowercase, and no default port.
- `with_grpc_web` refuses, with `CoupleError::Origin`, an origin with no scheme or a scheme other than `http` or `https`, with a path, a query, a fragment, a user, or a `*`, with no host, with a port that is no number up to 65535, or with an authority that does not parse as a URI authority, such as a host with a space, a `%`, or a byte outside ASCII.
- A page presents no client certificate, so its calls usually prove `Bearer`.
- A server stream answers each message in order, then its status in the trailer frame.

### Reflection

- `Coupler::with_reflection(descriptors)` serves `grpc.reflection.v1` and `v1alpha` from an encoded `FileDescriptorSet`.
- It serves the routed methods alone. Every unrouted service and method leaves the descriptor set, and so does every file that no routed service needs.
- A caller that the edge does not identify reads 16.
- Descriptors that do not decode refuse with `CoupleError::Reflection`.

### Metadata, deadline, details, compression

- `Coupler::with_forwarded_metadata(keys)` forwards every value of those request headers, such as `traceparent`, to the servlet.
- It refuses with `CoupleError::Metadata` a key outside `a-z0-9-_.`, under `grpc-`, a key that the edge stamps, `tightbeam-principal-bin` or `tightbeam-claim-bin`, a connection header such as `te` or `host`, a credential header, or a repeat. A value that does not decode refuses the call with 3.
- Each `CoupledCall` carries what remains of its deadline, in milliseconds, counted after the call holds the session.
- The coupled edge accepts and sends gzip.
- tonic refuses a request message past the envelope ceiling with 11, and one that decompresses past it with 8. The caller of a unary call or a stream reads that code, and the trail records the call as `refused`.

### `AdmittedCall` and `AdmittedStream`

- `AdmittedCall::admit(frame, trust)` takes the principal and the assurance from the signer of a direct call, or from the origin that a voucher signs. A frame that does not admit refuses with `WorkRefused(Unauthenticated)`, and the head of a stream with `WorkRefused(InvalidArgument)`.
- `AdmissionTrust::new()` trusts no sender. `with_vouchers`, `with_direct_callers`, and `with_claim_signers` each admit one kind, and a call of a kind that no setter names refuses.
- Pass `CallerTrust::claim_store` to `with_claim_signers`, so the servlet checks claims under the same store as the edge.
- `with_part_ceiling` bounds the parts of a stream, `DEFAULT_MAX_ENCRYPTED_ENVELOPE` by default.
- `origin()` of an `AdmittedCall` or an `AdmittedStream` reads its `Origin`: `principal()`, `assurance()`, `method()`, `metadata()`, each `Metadata` entry by its key and its value, and `remaining()`, the time left to its deadline.
- `Origin::stamp(metadata)` writes the identity of the call onto the metadata of a call that an adapter makes for it: each forwarded entry, the principal in `Origin::PRINCIPAL_KEY`, `tightbeam-principal-bin`, and any claim in `tightbeam-claim-bin`.
- `reply(body, signer)` answers status 0, and `fail(status, signer)` any other status, under the identity that the route pins. `fail` carries the status details to `grpc-status-details-bin`.
- `AdmittedStream::admit(body, reply, trust, signer)` admits the head of a stream in a duplex arm, and binds the signer of every answer part. Each later request part must verify under the signer of the head.
- `split()` gives an `AdmittedStreamParts` of the `Origin`, the `StreamRequests`, and the `StreamAnswers`, so each direction runs on its own.
- `StreamRequests::next()` reads a request. `StreamAnswers::send(body)`, `finish(requests)`, and `end(requests, status)` answer. `end` with status 0 is `finish`.
- `end` takes the `StreamRequests` back, and holds the stream until the caller ends its requests, dropping each request that comes, so a gateway relays the last answer part before the stream ends.
- A head or a part that does not admit ends the stream with the status that the `# Errors` of `AdmittedStream::admit` and `StreamRequests::next` give for it: 16, 3, 12, 8, or 14.
- `AdmittedStream::admit` refuses a head with no stream terms with 3.

### Events and tests

- Under `instrument`, the trace of the profile records `COUPLED_CALL_OPENED` when a head opens a call on its lane, then `COUPLED_CALL_ADMITTED`, `_REFUSED`, and `_ANSWERED`. A call that its lane refuses reads the label of the lane: `no-permit`, `calls-exhausted`, `other-kind`, or `closed`.
- It records `COUPLED_SESSION_OPENED` when the loopback session opens, after it reads the deadline of its first probe.
- It records each spend of a claim as `COUPLED_CLAIM_SPENT`, and each forget as `COUPLED_CLAIM_FORGOTTEN`: `unsent` after a send whose frame stayed in the session, `deadline` after a ledger that answered past the deadline, and `no-timer` after a ledger whose wait the clock gave no timer.
- A mutual edge that refuses the voucher handshake identity reads as [Health](#health) states for a refused session.
- A gateway whose `EdgePlane` refuses streams answers a stream with 7.
- Tests: `tests/coupler.rs`, `tests/compensation.rs`, and `tests/stock.rs` in the docker stack.

## Backend adapter

`couple::Backend` configures a servlet that relays each coupled call and stream to one stock gRPC server.

| Step | The adapter                                        | Refuses with                     |
| ---- | -------------------------------------------------- | -------------------------------- |
| 1    | admits the call                                    | `WorkRefused`, no reply          |
| 2    | checks the route, the grant, and the floor         | a signed 12 or 7                 |
| 3    | connects and calls, within `Backend::with_timeout` | a signed server status, 14, or 4 |
| 4    | signs the reply                                    | 13                               |

- The adapter presents its client certificate, from `DialTls::with_identity`.
- Each call carries the principal in `tightbeam-principal-bin`, any claim in `tightbeam-claim-bin`, and the metadata of the coupled call.
- The deadline is the sooner of `Backend::with_timeout` and the deadline of the coupled call.
- The details of a server status reach the caller.
- The adapter accepts gzip answers.
- A tightbeam client calls it with `CoupledCall::direct(method, body)`. `with_timeout(duration)` sets its deadline. `with_metadata(key, value)` adds an entry, and refuses as `with_forwarded_metadata` does.
- `CoupledReply` reads `code()`, `message()`, `body()`, and `details()`, the encoded `google.rpc.Status`. `into_result()` gives the body for status 0, and the status otherwise.
- `Backend::relay_stream(body, reply)` serves a stream route in the `duplex:` arm. Each request goes on as it arrives, and each answer comes back signed.
- A unary route reached as a stream, a stream of another shape, or a stream route reached as a unary call, refuses with a signed 12.
- A request part that does not admit cancels the call of the server, and records `BACKEND_CALL_REFUSED` as `part`.
- An answer of the server that the adapter cannot send ends the stream with its own status, which the caller reads: 12 past the count of the method, and 8 past the part ceiling. It records `part` too.
- An answer part takes its order once its push lands. A push that the timeout of the adapter cuts ends the stream with 4 and no part after it, and records `part`.
- `Backend::with_clock(clock)` runs the timeout of each call, and the deadline that each admitted call carries, on a tightbeam `Clock`, in place of `SystemClock`. A call whose wait that clock gives no timer ends with 13.
- Under `instrument`, `Backend::with_trace` records `BACKEND_CALL_RELAYED` and `BACKEND_CALL_REFUSED`.
- Tests: `tests/adapter.rs`.

## Claim encoding

A signer in any language builds a claim from these types and the tightbeam `Frame` of the [tightbeam README, section 5](https://github.com/wahidgroup/tightbeam/blob/master/README.md#5-asn1-formal-specification):

```asn1
ClaimBody ::= SEQUENCE {
    method      UTF8String,    -- the gRPC path, such as "/orders.v1.Orders/Place"
    bodyDigest  OCTET STRING,  -- SHA-256 of the encoded request message
    leafDigest  OCTET STRING   -- SHA-256 of the DER of the TLS client certificate of the caller
}

ClaimEnvelope ::= SEQUENCE {
    frame    OCTET STRING,            -- DER of the Frame that carries the ClaimBody
    signer   Certificate,             -- the claim identity, admitted for signing
    issuers  SEQUENCE OF Certificate  -- the issuers above the signer
}
```

- The `Frame` is `V1`. Its `order` is the time in milliseconds, strictly increasing for one signer. Its `id` is that order as 8 big-endian bytes.
- Its `nonrepudiation` is a CMS `SignerInfo` under the claim identity, over the coverage of README section 5.7.5.
- The claim identity names the principal of the caller, and chains to the claim store of `CallerTrust`.
- The caller sends the DER of the `ClaimEnvelope` in `tightbeam-claim-bin`.
- A stream claims an empty body.

## Hop requirements

A hop MUST carry a tunnel unchanged for the life of its session:

- Speak HTTP/2 to the server under its profile: h2c, or TLS 1.3 with ALPN `h2`.
- Route by `:authority` or `TUNNEL_PATH`, or pass TCP through.
- Open at most one stream per upstream connection.
- Set no route timeout. Envoy's default of 15 s ends every tunnel.
- Keep the stream idle timeout above the session `TransportLimits::operation_timeout`.
- Keep the upstream idle timeout below the server `TransportLimits::handshake_timeout`.
- Stream messages. Buffer nothing whole.

`grpc/docker/envoy.yaml` meets each one: `codec_type: HTTP2`, route `timeout: 0s`, `stream_idle_timeout: 300s`, one upstream stream, and upstream `idle_timeout: 5s`.

## Limitations

- A TLS edge presents one certificate chain, and admits TLS 1.3 alone.
- The ALPN of an edge offers `h2` alone, so gRPC-Web runs on HTTP/2.
- A claim on a stream covers no message of the stream.
- Bearer tokens are ES256 alone, under pinned keys. The edge fetches no key set.
- TLS roots, CRLs, and bearer keys load when the edge binds. A rolling restart of the replicas replaces them.
- `EncryptedProtocol::bind_with` and `cluster!` take no value of a deployment, so a profile is a type. A profile whose material comes at run time stages it in the static cell of `staged_profile!`, one deployment per type.
- The PROXY protocol is version 2 alone.
- Before its handshake, a peer can send one message up to the envelope ceiling ([The Envelope Rules of Message Sockets](wire.md#limitations)).
- A link on tightbeam's `TokioListener` that carries a stream of more than one record (16 KiB each by default) can lose part of a record. tightbeam-rs 0.19.0 drops a frame read that has taken part of a record when a stream body reports progress, so the next read starts inside the record. The link then refuses an envelope (`transport/envelope-refused`) and closes (`connection/closed`, `invalid-message`), and each stream on it ends with 13.
- The hive plane of a colony therefore runs on `WsListener`, which holds a partial message in its socket buffer across a dropped read. Test: `tests/adapter.rs` `a_flooded_answer_reaches_a_direct_caller_whole`.

## Sources

- tightbeam-rs 0.19.0, the mux reader and the frame read: `src/transport/multiplex/router/reader.rs` lines 702 to 727, and `src/transport/protocols.rs` lines 455 to 468.
- gRPC over HTTP2, `grpc/grpc` `doc/PROTOCOL-HTTP2.md`: <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md>
- gRPC compression, `grpc/grpc` `doc/compression.md`: <https://github.com/grpc/grpc/blob/master/doc/compression.md>
- gRPC health checking, `grpc/grpc` `doc/health-checking.md`: <https://github.com/grpc/grpc/blob/master/doc/health-checking.md>
- RFC 9113, HTTP/2, June 2022, sections 3.2, 3.3, and 8.1: <https://www.rfc-editor.org/rfc/rfc9113>
- RFC 8446, TLS 1.3, August 2018: <https://www.rfc-editor.org/rfc/rfc8446>
- RFC 7301, TLS ALPN, July 2014: <https://www.rfc-editor.org/rfc/rfc7301>
- RFC 9110, HTTP Semantics, June 2022, sections 8.3.1, 15.5.6, and 15.5.16: <https://www.rfc-editor.org/rfc/rfc9110>
- Envoy, `RouteAction.timeout`, `HttpConnectionManager.stream_idle_timeout`, and `HttpProtocolOptions.idle_timeout`: <https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto>
- gRPC error handling, richer error model: <https://grpc.io/docs/guides/error/>
- SPIFFE ID, `spiffe/spiffe` `standards/SPIFFE-ID.md`: <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md>
- JWT-SVID, `spiffe/spiffe` `standards/JWT-SVID.md`: <https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md>
- RFC 7519, JWT, May 2015: <https://www.rfc-editor.org/rfc/rfc7519>
- RFC 7518, JWA, May 2015, section 3.4: <https://www.rfc-editor.org/rfc/rfc7518>
- RFC 7517, JWK, May 2015: <https://www.rfc-editor.org/rfc/rfc7517>
- RFC 6750, Bearer Token Usage, October 2012: <https://www.rfc-editor.org/rfc/rfc6750>
- Envoy, `x-forwarded-client-cert`: <https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert>
- RFC 5280, X.509 PKI Certificate and CRL Profile, May 2008, sections 5 and 6.3: <https://www.rfc-editor.org/rfc/rfc5280>
- The PROXY protocol, HAProxy `doc/proxy-protocol.txt`: <https://www.haproxy.org/download/3.0/doc/proxy-protocol.txt>
- gRPC-Web, `grpc/grpc` `doc/PROTOCOL-WEB.md`: <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md>
- Fetch Standard, CORS protocol: <https://fetch.spec.whatwg.org/#http-cors-protocol>
- gRPC Server Reflection, `grpc/grpc` `doc/server-reflection.md`: <https://github.com/grpc/grpc/blob/master/doc/server-reflection.md>
- RFC 5652, CMS, September 2009, section 5.3: <https://www.rfc-editor.org/rfc/rfc5652#section-5.3>
- CWE-294, Authentication Bypass by Capture-replay: <https://cwe.mitre.org/data/definitions/294.html>
- CWE-319, Cleartext Transmission of Sensitive Information: <https://cwe.mitre.org/data/definitions/319.html>
- CWE-400, Uncontrolled Resource Consumption: <https://cwe.mitre.org/data/definitions/400.html>
- CWE-770, Allocation of Resources Without Limits or Throttling: <https://cwe.mitre.org/data/definitions/770.html>
