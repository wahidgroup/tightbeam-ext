# The WebSocket Transport

This page specifies the types of `tightbeam-ws` that carry tightbeam envelopes over WebSocket:

- the listener, its upgrade slots, and the dial
- the stream, and how it runs the envelope rules over WebSocket
- the accepted multiplexed link of `serve`
- the cargo features
- the cluster work plane at the WebSocket edge
- the demo servers of the e2e stack, and the test support they share
- the limits a deployment plans around

It drills down from the [tightbeam-ws README](../ws/tightbeam-ws/README.md) for engineers who build on the transport or review it. The README holds what each part is for and the standards it follows. The browser side has its own pages, [The Browser Engine](ws-wasm.md) and [The WebSocket Client](ws-client.md).

## Contents

- [Listener](#listener)
- [Stream and envelope rules](#stream-and-envelope-rules)
- [Multiplexed sessions](#multiplexed-sessions)
- [Accepted links](#accepted-links)
- [Features](#features)
- [Cluster work plane](#cluster-work-plane)
- [Demo servers](#demo-servers)
- [Test support](#test-support)
- [Limitations](#limitations)
- [Sources](#sources)

## Listener

`protocol::WsListener<P>` is the tightbeam listener over WebSocket. `P` is the `CryptoProvider` of the session, and `DefaultCryptoProvider` is the default. It implements these traits of `tightbeam::transport`:

| Trait                  | What the listener supplies                                                                             |
| ---------------------- | ------------------------------------------------------------------------------------------------------ |
| `Protocol`             | `bind_cleartext`, `connect`, `connect_within`, and `create_transport`. The stream is `io::WsStream`    |
| `EncryptedProtocol`    | `bind_with(addr, TransportEncryptionConfig)`, with `SendCipher` and `RecvCipher` as the record ciphers |
| `AsyncListenerTrait`   | `accept`, which yields the transport and its `TightBeamSocketAddr`                                     |
| `PersistentConnection` | `is_connected`, so `ConnectionPool` and the colony stack reuse one WebSocket connection across leases  |

Every accepted transport builds from the one `EndpointConfig` that the listener holds, so the provisioning, the ceilings, and the clock of the listener reach each connection. The inherent `WsListener::bind(addr, config, clock)` binds a listener over any `EndpointConfig` and replaces its clock with `clock` (`EndpointConfig::with_clock`), so the upgrade plane and every transport run on that one clock. The inherent `WsListener::bind_cleartext(addr)` binds a listener in the clear, and its accepted transports carry no confidentiality, integrity, or peer authentication (CWE-319). An encrypted listener binds through `EncryptedProtocol::bind_with`, and each connection then runs the tightbeam handshake unchanged. Authentication and confidentiality come from that handshake above the socket, and the listener runs no TLS. `bind_cleartext` and `bind_with` bind on the clocks of the operating system.

The listener accepts on a task of its own, so a socket upgrades whether or not a caller waits in `accept`. The task ends when the listener drops. The upgrade plane holds each socket under these rules:

- Each HTTP upgrade runs on a task of its own, under the `handshake_timeout` of the endpoint, which runs from the TCP accept on the clock of the listener.
- The plane holds at most `DEFAULT_MAX_SERVER_CONNECTIONS` sockets, from TCP accept until a caller takes the socket, so a full accept loop stops new upgrades (CWE-770).
- A stalled upgrade returns its slot at the deadline (CWE-400), and a failed upgrade returns it at once. Neither reaches a caller.
- A failed TCP accept, such as a descriptor shortage, returns its slot and waits out `DEFAULT_ACCEPT_RETRY_DELAY` on the clock of the listener before the next accept, as the upstream accept plane absorbs one. It reaches no caller either.
- `accept` yields finished upgrades only, so its one error is `TransportError::ConnectionClosed`. It comes only once the accept task is gone, and only the drop of the listener ends that task.

A dial opens `ws://<addr>/`. `connect_within(addr, limits)` sizes the socket ceiling to the larger envelope ceiling of `limits`, and the transport narrows each read to the ceiling of its phase.

```rust
use tightbeam_ws::protocol::WsListener;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> tightbeam_ws::Result<()> {
let listener: WsListener = WsListener::bind_cleartext("127.0.0.1:0").await?;
assert!(listener.local_addr().ip().is_loopback());
# Ok(())
# }
```

## Stream and envelope rules

`io::WsStream<S>` holds the `tightbeam_wire::WireDuplex` of the two native halves, `io::WsReadHalf` and `io::WsWriteHalf`, over a `tokio-tungstenite` WebSocket. It implements `AsyncProtocolStream`, and it splits into exclusive halves (`SplittableStream`) so a multiplexed connection reads and writes at once. `io::WsTransport<S, P>` names `TcpTransport<WsStream<S>, P>`, the tightbeam transport over that stream. A stream comes only from a dial or an accept of `WsListener`, and each one opens its socket under the envelope ceiling of its endpoint.

The halves are the native socket kind of the envelope rules that `tightbeam-wire` holds for every message-oriented socket ([The Envelope Rules of Message Sockets](wire.md)). Over WebSocket the rules read as follows:

- A tightbeam envelope travels as one binary WebSocket message.
- A text message skips. So do ping, pong, and raw frames, because tungstenite answers each ping itself.
- A close frame, or the end of the message stream, ends a read.
- Tungstenite refuses a message past the envelope ceiling of the endpoint by its declared length, before it sizes a buffer, and the stream reads that refusal as `WireFault::Oversize`.
- A close, the end of the stream with no close, a send after the close, and a use after the end are `WireFault::Closed`. A failed byte stream, such as a write to a peer that left with no close, is `WireFault::Io`. Every other tungstenite error is a break of the protocol, `WireFault::Invalid`.

An HPKE round trip runs the handshake of tightbeam unchanged, and a cleartext one runs none. `tests/round_trip.rs` drives the `server!` and `client!` macros over a cleartext listener, and `tests/encrypted_fixtures.rs` drives the HPKE handshake over `bind_with`. Each spec counts one accepted connection, one admitted request, and no refused request, and the encrypted spec also counts one handshake at each end.

## Multiplexed sessions

Each read of a multiplexed session runs under the operation timeout of its endpoint, `DEFAULT_OPERATION_TIMEOUT` by default, on the clock of the endpoint. A session that must outlive a silence probes its peer `KEEPALIVE_PROBES_PER_DEADLINE` times per timeout. A dialed session runs `MuxHandle::keep_alive`, and an accepted link runs the keepalive that `AcceptedLink::spawn` starts.

## Accepted links

The `serve` module owns one accepted multiplexed connection: its transport gate, its tasks, and the `MuxHandle` that a push-capable service emits on. Upstream `MuxAcceptor::serve` lends its service no handle, so a server that pushes streams of its own serves through this module in three steps:

1. `AcceptedLink::accepted(transport)` consumes a transport whose server handshake completed. It keeps the multiplexing settings, the in-band rekey context of a metered session, the peer of `MuxAcceptor::session_context`, the transport gate, and the writer clock. A cleartext endpoint runs no handshake, so `AcceptedLink::cleartext(transport, settings)` takes the `MuxSettings` that both ends agreed on.
2. `AcceptedLink::spawn` spawns the mux drivers and a keepalive into the `ServedMux` that owns them. The keepalive probes the peer through `MuxHandle::ping` `KEEPALIVE_PROBES_PER_DEADLINE` times per read deadline, on the writer clock. The drop of the `ServedMux` ends all three.
3. `ServedMux::serve_dispatch(dispatch, expulsion)` runs the responder with a `MuxDispatch`, which answers each call with a status of its own, until the connection ends. Every call passes the gate first.

Under the `testing` feature, `ServedMux::serve(service, expulsion)` runs a `MuxService` in place of a dispatch, so the suites grade the served plane against upstream `MuxAcceptor::serve`. A call of `serve` reaches the method of its kind with a `CallContext` of the session that the handshake proved and the route of its stream. A handler that fails with an error of its own answers the status of the failure as upstream answers it: a carried status, `Unknown` for a carried `Unavailable`, and `Internal` for a failure that carries none. A kind that the service leaves out answers `Unimplemented`.

Under the `instrument` feature, a served link records on the trace that its mux records on, which is the trace of the transport that the link was accepted on:

- `GATE_ACCEPT` with `Ok`, or `GATE_REJECT` with the status that the refused call answers, as the label and the value, as upstream records them.
- `HANDLER_FAILED` with the status that a failed handler of `serve` answers, under the `testing` feature, as upstream records it.
- `serve::KEEPALIVE_ANSWERED` once for each probe of the keepalive that the peer answered. The link runs its own keepalive over `MuxHandle::ping`, so a scenario moves its clock on this record.

`ServedMux::trace` lends that trace to the service, so `tightbeam-pubsub` records the decisions of its registry beside the verdicts. `tests/serve.rs` grades both planes against each other for every gate verdict and every handler outcome. Its read deadline scenarios, which [Test support](#test-support) lists, run on a listener bound on a `ManualClock`.

The published tightbeam API leaves four parts of the upstream pipeline out of reach, so a served connection differs from an upstream one in each:

- A gate evaluates the receipt of the handshake, not the receipt of the latest renewal. `SessionContext` keeps its fields private, and only crate-private code builds one with a live receipt. A renewal keeps the peer, so a gate that reads the peer decides alike.
- A verdict carries no peer key as its evidence. The one public emit that carries a value carries no payload, and a verdict keeps its status as the value that a spec grades.
- A call records no `POLICY_EVAL`, `HANDLER_ENTER`, or `HANDLER_EXIT`, so a trace fault stops a call only at its verdict or at the record of a failed handler. The trace keeps the switch of those events private.
- Envelopes that the responder queued before it ended drop when the connection ends, because the writer stops at once. That includes the `EnhanceYourCalm` GoAway of a cancel-budget refusal. Upstream closes the handle and then finishes the drivers, so its writer sends the queue first, and both `MuxHandle::close` and `MuxDrivers::finish` are crate-private.

A link refuses a transport with a `LinkError`:

- `NotMultiplexed`: the handshake negotiated no multiplexing.
- `Encrypted`: `cleartext` met an endpoint provisioned for encryption.
- `ClockCannotRace(Timing)`: the writer clock cannot race a wait on the calling thread (`RacingClock`), so no emit deadline and no keepalive could run on it. The check is an early refusal. A timer of the clock reads the timing again at each bound, on the thread that polls it.
- `Transport(TransportError)`: the transport refused to detach its rekey context or to split.

```rust
# #[cfg(feature = "serve")]
# fn main() {
use tightbeam::transport::error::TransportError;
use tightbeam_ws::serve::LinkError;

let refused = LinkError::from(TransportError::InvalidState);
assert_eq!(refused.to_string(), "the transport refused the split: Invalid state");
# }
# #[cfg(not(feature = "serve"))]
# fn main() {}
```

`tightbeam-pubsub` serves each connection through an `AcceptedLink` ([The Topic Registry](pubsub.md#connection-serve)).

## Features

| Feature            | Enables                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `socket` (default) | The `tokio-tungstenite` listener, dial, and stream of `protocol` and `io`, over the envelope rules of `tightbeam-wire`                                                                                                                                                                                                                                                                                                                                                         |
| `serve`            | The accepted link of `serve`. It names no socket, so `tightbeam-pubsub` depends on `serve` alone                                                                                                                                                                                                                                                                                                                                                                               |
| `instrument`       | The audit trail of a served link: the gate verdict of each call and each answered probe of the keepalive, on the trace of the transport that the link was accepted on, and `ServedMux::trace`                                                                                                                                                                                                                                                                                  |
| `testing`          | `socket`, `serve`, `instrument`, and the `testing` feature of `tightbeam-rs`, with the test-support module: X.509 identity fixtures, the demo security kinds and the `PeerIdentity` that a kind decides, the shared multiplexed echo behavior, the echo suites (`EchoService`, `PoolEchoes`) that every transport of the repository runs against itself, the `ReadOutcome` that a scenario records for the read of a dial, and `specs`, the specs that grade the shared suites |
| `colony`           | `testing`, and the upstream `colony` runtime with the gateway, hive, and servlet configs that one identity derives, and the work probe that every edge transport shares: `WorkPlane`, `WorkStack`, `WorkClient`, `WorkBody`, `WorkProbe` and the `work_probe!` macro that declares a probe over one colony protocol, `WorkProbeServlet` and `WorkProbeHive` over the WebSocket colony, and `WorkGateway`, the gateway of the WebSocket edge, over an optional `der`            |

The examples `gen_certs`, `echo_server_mux`, and `echo_server_mux_clear` require `testing`, and `work_gateway_server` requires `colony`.

## Cluster work plane

The `colony` feature of tightbeam routes signed work frames through a cluster gateway to the servlets that hives register. The WebSocket transport is the browser edge of a colony, and the colony interior runs on `WsListener` too:

- A gateway declares the edge with `cluster! { ..., protocol: WsListener, edge: WsListener }` and sets `ClusterConfig::edge` to `EdgePlane::new(addr)`.
- The gateway binds a second accept plane on WebSocket that admits `Work` frames only. It refuses each control frame, such as a registration, an advertisement, or gossip, with `PermissionDenied`.
- The upstream `SubmitWork` blanket implementation covers `GenericClient<WsListener>`, so an edge client submits through `submit_work_to`.
- The gateway forwards the signed frame of the caller to the servlet with its bytes unchanged, and the complete signed response frame of the servlet returns the same way.

An application enables `colony` on `tightbeam-rs` in its own manifest to use the edge. The `colony` feature of this crate holds the work plane that the edge transports of the repository share. Every colony process presents one `Identity`, and the gateway, the hive, and the servlet derive their configuration from it:

- `WorkPlane` holds that identity and the work identity, and starts each part on its own, as a scenario does. `WorkPlane::hive::<S>` starts a hive of the probe `S`.
- `work_probe!` declares a probe servlet and its hive over one colony protocol, with `WorkProbe` on the servlet. This crate declares `WorkProbeServlet` and `WorkProbeHive` over `WsListener`, and `tightbeam-grpc` declares its probe over `TokioListener`.
- `WorkStack<G, S>` starts the gateway `G` of any edge protocol, with a hive of the probe `S` over the colony of `G`.
- `WorkGateway` is the gateway of the WebSocket edge.
- `WorkClient::submit` submits one signed probe frame through the edge of any work gateway, at the address that `WorkClient::edge_of` reads.
- Each probe that `work_probe!` declares answers `pong:<payload-hex>:<valid>`, where `valid` says whether the end-to-end signature verified on the bytes that the servlet received.

`tests/work_plane.rs` runs the round trip and a typed `WorkRefused` refusal from a WebSocket edge client through a gateway, hive, and servlet on the WebSocket colony.

```rust
# #[cfg(feature = "colony")]
# mod submit {
# use tightbeam::colony::SubmitWork;
# use tightbeam::transport::GenericClient;
# use tightbeam::urn::Urn;
# use tightbeam::{Frame, TightBeamError};
# use tightbeam_ws::protocol::WsListener;
# async fn submit(
# 	client: &mut GenericClient<WsListener>,
# 	servlet_urn: Urn<'static>,
# 	signed_work_frame: Frame,
# ) -> Result<Frame, TightBeamError> {
let served = client.submit_work_to(servlet_urn, &signed_work_frame).await?;
# Ok(served)
# }
# }
```

## Demo servers

The e2e stack runs the examples of this crate in one image (`ws/docker/echo-server/Dockerfile`), and `ws/docker-compose.yml` names one service per server. Each server reads its demo facts from the environment that `ws/scripts/stack-env.sh` writes.

| Example                 | Serves                                                                                   | Environment                                                                             |
| ----------------------- | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `echo_server_mux`       | An encrypted multiplexed echo, under the `Security` kind that `DemoConfig` reads         | `ECHO_WS_PORT`, `TBWS_SERVER_CERT`, `TBWS_ECHO_BODY`, and the variables of `DemoConfig` |
| `echo_server_mux_clear` | A cleartext multiplexed echo, under the stream cap that both ends configure              | `ECHO_WS_PORT`, `TBWS_ECHO_BODY`, and `MUX_STREAMS`                                     |
| `work_gateway_server`   | A cluster gateway, a hive, and the work probe in one process, with its edge on WebSocket | `ECHO_WS_PORT`, `TBWS_SERVER_CERT`, `TBWS_WORK_CERT`, and `TBWS_WORK_SERVLET`           |
| `gen_certs`             | No connection. It writes the server and the client identity before the stack starts      | `CERT_DIR`                                                                              |

- A certificate variable names the DER file of an identity, and its raw 32-byte signing key sits beside it.
- `DemoConfig` decides the `Security` of every connection: server-auth, mutual-auth when `TBWS_CLIENT_CERT` names a client certificate to pin, and the session-budget paywall on top of mutual auth when `TBWS_PAYWALL` is on.
- A cleartext endpoint runs no handshake, so both ends MUST configure the same stream cap, and the connection carries no confidentiality or integrity protection.
- The work gateway serves its probe under the servlet type that `TBWS_WORK_SERVLET` names (`WorkPlane::serving`), and the e2e suites submit their work to the same type.

`TBWS_ECHO_BODY` names the `EchoBody` of a server, and `streaming` is the default:

- `streaming` echoes unary frames and progressive bodies. The echo of a progressive body carries the route of its Open as the id `routed:<target>:<hops>`, with an empty target when the Open names none, so a client asserts `openStream` and `openStreamTo` without a colony.
- `unary` echoes reassembled frames alone.
- `duplex` echoes the chunks of each duplex stream.

In the `streaming` and `unary` bodies, a frame id selects a command in place of the echo, such as `call-me` (the server calls the client back and relays its reply) or `drain-calm` (the server drains with an `EnhanceYourCalm` GoAway). A peer refusal of a call-back keeps its status on the relayed answer.

The work gateway holds its process with a pending future, because its topology serves from tasks of its own. The image checks the liveness of each server by the LISTEN state of its port, because a probe that connects holds an accept slot until the handshake deadline.

## Test support

The `testing` feature holds the support that the demo servers, the scenarios, and the suites of the other transports share:

| Item                        | What it holds                                                                                                                                                                           |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Identity`, `IdentityFiles` | Self-signed X.509 identities, issued natively because a browser has no clock, and the certificate and key files that hold one                                                           |
| `Error`                     | The error of the test support, which wraps the error of the crate                                                                                                                       |
| `IdentityFilesError`        | The refusal of a name, a certificate path, or a key file of the identity files                                                                                                          |
| `EventWatch`                | A count of each event label of a trace, which wakes a waiting scenario party as the trace records the event, and fails the wait with `Error::Unrecorded` when its patience passes first |
| `DemoConfig`, `Security`    | The demo environment of the stack, and the kind that decides how a server authenticates and how a dial answers it                                                                       |
| `DemoPaywall`               | The demo session-budget paywall, which invoices each session and renewal                                                                                                                |
| `EchoService`, `PoolEchoes` | The shared echo that every transport of the repository runs against itself, and what one pooled connection echoed                                                                       |
| `ReadOutcome`               | How the read of a dial ended, which a scenario records because the emit path files no event for a read refused before the decode                                                        |
| `specs`                     | The specs that grade the shared suites, so a transport whose scenarios meet a spec behaves as the other transports do                                                                   |

`IdentityFiles::provision` writes both files of an identity into a sibling staging directory, removes the published certificate, and then renames the key and the certificate into place, in that order. The certificate therefore publishes the identity, and an interrupted write leaves no certificate without its key. The cert step of `ws/scripts/stack-env.sh` keeps both identities while both certificates are present.

The e2e package `ws/tests` holds the lanes that run against the stack:

- `fixtures.ts` holds the stack fact readers, the dial facts, the Node lane dials, and the note payload, and a page imports it as a Node lane does. The pubsub suites import it as `#ws-fixtures`.
- `util.ts` holds `base64ToBytes`, which the pages and the pubsub fixtures share. The pubsub suites import it as `#ws-util`.
- `app/main.ts` installs the round trips of the page as `window.tb`, and each takes one options object across the `page.evaluate` boundary.
- `app/engine.ts` loads the engine from a custom module input as `window.tbEngine`.

`tests/support/mod.rs` holds what the Rust suites share: `bounded`, the hang guard of a wait on a peer, and `Answers`, which opens one stream of each kind and reads how each ends.

| Suite                         | What it proves                                                                                                                     |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `tests/accept.rs`             | A stalled or failed upgrade ends beside a served client, a stall ends on the `bind` clock, and a dropped listener frees its port   |
| `tests/dial.rs`               | A dial refuses a frame past the ceiling of its endpoint by its declared length                                                     |
| `tests/demo_security.rs`      | Each `Security` kind dials a server of the same kind, and the spec grades the handshake and receipt of each end                    |
| `tests/echo_body.rs`          | Each echo body of the demo servers serves its own stream kinds alone                                                               |
| `tests/encrypted_fixtures.rs` | The HPKE handshake completes over `bind_with`, and a DER identity reloads as the echo server and the browser load it               |
| `tests/pooled_mux.rs`         | One pooled WebSocket connection carries every stream kind                                                                          |
| `tests/specs.rs`              | Each shared spec rejects a run that breaks the behavior it grades                                                                  |
| `tests/serve.rs`              | `ServedMux::serve` answers as upstream `MuxAcceptor::serve`, a served link outlives a silent client, and an upstream one ends      |
| `tests/watch.rs`              | A wait of `EventWatch` ends at the count that the trace records, and answers `Unrecorded` for a count that the trace never reaches |

## Limitations

- The listener has no TLS acceptor, so it binds `ws://` only. A page served over `https://` connects over `wss://` to a TLS terminator in front, such as a reverse proxy or a load balancer, which forwards `ws://` to the listener. Authentication and confidentiality still come from the tightbeam handshake above the socket.
- Before its handshake finishes, a peer can send one WebSocket message up to the established ceiling, `TransportLimits::max_envelope`. The socket ceiling is fixed at accept, so the handshake ceiling, `TransportLimits::handshake_wire`, refuses an oversized handshake message only after the read.
- A pool that closes an idle WebSocket closes it with no Close frame, because `TcpTransport` lends no handle on its stream and `PersistentConnection::try_close` is synchronous. The peer reads the end as a lost connection, `ConnectionClosed`.
- The listener accepts a WebSocket whatever its `Origin` header names. Any web page can open a WebSocket to a listener that the browser reaches, loopback included, and it connects as an anonymous peer because the protocol carries no ambient credential. A listener that MUST NOT serve anonymous peers requires mutual authentication.

## Sources

- RFC 6455, The WebSocket Protocol, December 2011, § 5.5.1 Close and § 5.6 Data Frames: <https://datatracker.ietf.org/doc/html/rfc6455>
- CWE-319, Cleartext Transmission of Sensitive Information: <https://cwe.mitre.org/data/definitions/319.html>
- CWE-400, Uncontrolled Resource Consumption: <https://cwe.mitre.org/data/definitions/400.html>
- CWE-770, Allocation of Resources Without Limits or Throttling: <https://cwe.mitre.org/data/definitions/770.html>
