# The WebSocket Transport

This page specifies the types of `tightbeam-ws` that carry tightbeam envelopes over WebSocket:

- the listener, its upgrade slots, and the dial
- the stream and the envelope rules of `wire`
- the accepted multiplexed link of `serve`
- the cargo features
- the cluster work plane at the WebSocket edge
- the limits a deployment plans around

It drills down from the [tightbeam-ws README](../ws/tightbeam-ws/README.md) for engineers who build on the transport or review it. The README holds what each part is for and the standards it follows. The browser side has its own pages, [The Browser Engine](ws-wasm.md) and [The WebSocket Client](ws-client.md).

## Contents

- [Listener](#listener)
- [Stream and envelope rules](#stream-and-envelope-rules)
- [Multiplexed sessions](#multiplexed-sessions)
- [Accepted links](#accepted-links)
- [Features](#features)
- [Cluster work plane](#cluster-work-plane)
- [Limitations](#limitations)
- [Sources](#sources)

## Listener

`protocol::WsListener<P>` is the tightbeam listener over WebSocket. `P` is the `CryptoProvider` of the session, and `DefaultCryptoProvider` is the default. It implements these traits of `tightbeam::transport`:

| Trait                  | What the listener supplies                                                                                     |
| ---------------------- | -------------------------------------------------------------------------------------------------------------- |
| `Protocol`             | `bind_cleartext`, `connect`, `connect_within`, and `create_transport`. The stream is `io::WsStream`           |
| `EncryptedProtocol`    | `bind_with(addr, TransportEncryptionConfig)`, with `SendCipher` and `RecvCipher` as the record ciphers         |
| `AsyncListenerTrait`   | `accept`, which yields the transport and its `TightBeamSocketAddr`                                             |
| `PersistentConnection` | `is_connected`, so `ConnectionPool` and the colony stack reuse one WebSocket connection across leases          |

Every accepted transport builds from the one `EndpointConfig` that the listener holds, so the provisioning and the ceilings of the listener reach each connection. The inherent `WsListener::bind_cleartext(addr)` binds a listener in the clear, and its accepted transports carry no confidentiality, integrity, or peer authentication (CWE-319). An encrypted listener binds through `EncryptedProtocol::bind_with`, and each connection then runs the tightbeam handshake unchanged. Authentication and confidentiality come from that handshake above the socket, and the listener runs no TLS.

The listener accepts on a task of its own, so a socket upgrades whether or not a caller waits in `accept`. The task ends when the listener drops. The upgrade plane holds each socket under these rules:

- Each HTTP upgrade runs on a task of its own, under the `handshake_timeout` of the endpoint.
- The plane holds at most `DEFAULT_MAX_SERVER_CONNECTIONS` (1024) sockets, from TCP accept until a caller takes the socket, so a full accept loop stops new upgrades (CWE-770).
- A stalled upgrade returns its slot at the deadline (CWE-400), and a failed upgrade returns it at once. Neither reaches a caller.
- `accept` yields finished upgrades only, so its errors are the listener's own: `TransportError::IoError` when the TCP accept fails, and `TransportError::ConnectionClosed` when the accept task stopped.

A dial opens `ws://<addr>/`. `connect_within(addr, limits)` sizes the socket ceiling to the larger envelope ceiling of `limits`, and the transport narrows each read to the ceiling of its phase.

```rust
use tightbeam_ws::protocol::WsListener;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> tightbeam_ws::Result<()> {
let listener: WsListener = WsListener::bind_cleartext("127.0.0.1:0").await?;
assert!(listener.local_addr()?.ip().is_loopback());
# Ok(())
# }
```

## Stream and envelope rules

`io::WsStream<S>` is the `wire::WireDuplex` of the two native halves, `io::WsReadHalf` and `io::WsWriteHalf`, over a `tokio-tungstenite` WebSocket. It implements `AsyncProtocolStream`, and it splits into exclusive halves (`SplittableStream`) so a multiplexed connection reads and writes at once. `io::WsTransport<S, P>` names `TcpTransport<WsStream<S>, P>`, the tightbeam transport over that stream.

The `wire` module holds the envelope rules that every socket kind shares, the native one and the browser one:

- A tightbeam envelope travels as one binary WebSocket message.
- A read skips a text or control message, refuses an envelope past its cap, and ends at a close or at the end of the message stream.
- A write sends one binary message per envelope.
- A stream reads as dead after its first failure (`Liveness`).

A socket kind implements two traits: `WireStream` classifies each received message as a `Wire` value, and `WireSink` sends each envelope. `EnvelopeReader` admits one envelope from a `WireStream`. Each socket failure maps to one transport error:

| `WireFault` | Cause                                                                          | `TransportError`                   |
| ----------- | ------------------------------------------------------------------------------ | ---------------------------------- |
| `Closed`    | The connection closed before the operation finished                            | `ConnectionClosed`                 |
| `Io`        | The byte stream under the socket failed                                        | `IoError`                          |
| `Oversize`  | A message passed the frame ceiling of the socket, or the cap of a read         | `OperationFailed(SizeExceeded)`    |
| `Invalid`   | The socket broke the WebSocket protocol, lost its connection, or refused a send | `InvalidMessage`                   |

```rust
use tightbeam::transport::{TransportError, TransportFailure};
use tightbeam_ws::wire::WireFault;

let error = TransportError::from(WireFault::Oversize);
assert!(matches!(error, TransportError::OperationFailed(TransportFailure::SizeExceeded)));
```

Cleartext and HPKE-encrypted round trips run the transport-agnostic handshake of tightbeam unchanged. `tests/round_trip.rs` drives both: the `server!` and `client!` macros over a cleartext listener, and the HPKE handshake over `bind_with`.

## Multiplexed sessions

Each read of a multiplexed session runs under the operation timeout of its endpoint, 30 seconds by default (`DEFAULT_OPERATION_TIMEOUT`). A session that must outlive a silence runs `MuxHandle::keep_alive`, which probes its peer at a third of that timeout (`KEEPALIVE_PROBES_PER_DEADLINE`).

## Accepted links

The `serve` module owns one accepted multiplexed connection: its transport gate, its tasks, and the `MuxHandle` that a push-capable service emits on. Upstream `MuxAcceptor::serve` lends its service no handle, so a server that pushes streams of its own serves through this module in three steps:

1. `AcceptedLink::accepted(transport)` consumes a transport whose server handshake completed. It keeps the multiplexing settings, the in-band rekey context of a metered session, the peer of `MuxAcceptor::session_context`, the transport gate, and the writer clock. A cleartext endpoint runs no handshake, so `AcceptedLink::cleartext(transport, settings)` takes the `MuxSettings` that both ends agreed on.
2. `AcceptedLink::spawn` spawns the mux drivers and a keepalive into the `ServedMux` that owns them. The drop of the `ServedMux` ends all three.
3. `ServedMux::serve(dispatch, expulsion)` runs the responder until the connection ends, and every call passes the gate first.

A server that pushes nothing serves through upstream `MuxAcceptor::serve`, which also keeps the gate spans of the audit trail. A call served through this module records no gate verdict in the audit trail, injects no trace fault, and labels no `HANDLER_FAILED`, because upstream does all three through crate-private traits. Each call evaluates the gate against the session that the handshake proved, and a renewal of a metered session keeps that peer.

A link refuses a transport with a `LinkError`:

- `NotMultiplexed`: the handshake negotiated no multiplexing.
- `Encrypted`: `cleartext` met an endpoint provisioned for encryption.
- `ClockCannotRace(Timing)`: the writer clock cannot race a wait on the calling thread (`RacingClock`), so no emit deadline and no keepalive could run on it.
- `Transport(TransportError)`: the transport refused to detach its rekey context or to split.

```rust
use tightbeam::transport::error::TransportError;
use tightbeam_ws::serve::LinkError;

let refused = LinkError::from(TransportError::InvalidState);
assert_eq!(refused.to_string(), "the transport refused the split: Invalid state");
```

`tightbeam-pubsub` serves each connection through an `AcceptedLink` ([The Topic Registry](pubsub.md#connection-serve)).

## Features

| Feature            | Enables                                                                                                                                  |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `socket` (default) | The `tokio-tungstenite` listener, dial, and stream of `protocol` and `io`. It turns on `wire`                                            |
| `wire`             | The envelope rules of `wire`. They build on the tightbeam transport alone, so the browser engine depends on this crate with `wire` only  |
| `serve`            | The accepted link of `serve`. It names no socket, so `tightbeam-pubsub` depends on `serve` alone                                         |
| `link-parts`       | `serve`, and `AcceptedLink::from_parts`, a link from the parts of an in-memory test link. The parts name any gate and any session        |
| `testing`          | `socket` and `serve`, and the test-support module: X.509 identity fixtures and the shared multiplexed echo behavior                     |
| `colony`           | `testing`, and the upstream `colony` runtime with the gateway, hive, and servlet configs that one identity derives                      |

Only test support enables `link-parts`. The examples `gen_certs`, `echo_server_mux`, and `echo_server_mux_clear` require `testing`, and `work_gateway_server` requires `colony`.

## Cluster work plane

The `colony` feature of tightbeam routes signed work frames through a cluster gateway to the servlets that hives register. The WebSocket transport is the browser edge of a colony, and the colony interior keeps its TCP protocol:

- A gateway declares the edge with `cluster! { ..., protocol: TokioListener, edge: WsListener }` and sets `ClusterConfig::edge_bind_addr`.
- The gateway binds a second accept plane on WebSocket that admits `Work` frames only. It refuses each control frame, such as a registration, an advertisement, or gossip, with `PermissionDenied`.
- The upstream `SubmitWork` blanket implementation covers `GenericClient<WsListener>`, so an edge client submits through `submit_work_to`.
- The gateway forwards the signed frame of the caller to the servlet with its bytes unchanged, and the complete signed response frame of the servlet returns the same way.

An application enables `colony` on `tightbeam-rs` in its own manifest to use the edge. `tests/work_plane.rs` runs the round trip and a typed `WorkRefused` refusal from a WebSocket edge client through a TCP gateway, hive, and servlet.

```rust
# #[cfg(feature = "colony")]
# mod submit {
# use tightbeam::colony::SubmitWork;
# use tightbeam::transport::GenericClient;
# use tightbeam::urn::Urn;
# use tightbeam::{Frame, TightBeamError};
# use tightbeam_ws::protocol::WsListener;
# async fn submit(
#     client: &mut GenericClient<WsListener>,
#     servlet_urn: Urn<'static>,
#     signed_work_frame: Frame,
# ) -> Result<Frame, TightBeamError> {
let served = client.submit_work_to(servlet_urn, &signed_work_frame).await?;
# Ok(served)
# }
# }
```

## Limitations

- The listener has no TLS acceptor, so it binds `ws://` only. A page served over `https://` connects over `wss://` to a TLS terminator in front, such as a reverse proxy or a load balancer, which forwards `ws://` to the listener. Authentication and confidentiality still come from the tightbeam handshake above the socket.
- Before its handshake finishes, a peer can send one WebSocket message up to the established ceiling, `TransportLimits::max_envelope` (256 KiB by default). The socket ceiling is fixed at accept, so the 16 KiB handshake ceiling refuses an oversized handshake message only after the read.
- The listener does not check the `Origin` header. Any web page can open a WebSocket to a listener that the browser reaches, loopback included, and it connects as an anonymous peer because the protocol carries no ambient credential. A listener that MUST NOT serve anonymous peers requires mutual authentication.

## Sources

- RFC 6455, The WebSocket Protocol, December 2011, § 5.5.1 Close and § 5.6 Data Frames: <https://datatracker.ietf.org/doc/html/rfc6455>
- CWE-319, Cleartext Transmission of Sensitive Information: <https://cwe.mitre.org/data/definitions/319.html>
- CWE-400, Uncontrolled Resource Consumption: <https://cwe.mitre.org/data/definitions/400.html>
- CWE-770, Allocation of Resources Without Limits or Throttling: <https://cwe.mitre.org/data/definitions/770.html>
