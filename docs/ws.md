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

#### Binding

| Bind                                    | Endpoint             | Clock                                                                                             | Protection                                                            |
| --------------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `WsListener::bind(addr, config, clock)` | Any `EndpointConfig` | `clock`, through `EndpointConfig::with_clock`, so the upgrade plane and every transport run on it | As `config` provisions                                                |
| `WsListener::bind_cleartext(addr)`      | In the clear         | The clocks of the operating system                                                                | None: no confidentiality, integrity, or peer authentication (CWE-319) |
| `EncryptedProtocol::bind_with`          | Encrypted            | The clocks of the operating system                                                                | The tightbeam handshake, unchanged, on each connection                |

- Every accepted transport builds from the one `EndpointConfig` that the listener holds.
- The provisioning, the ceilings, and the clock of the listener therefore reach each connection.
- Authentication and confidentiality come from the tightbeam handshake above the socket. The listener runs no TLS.

#### Upgrade plane

- The listener accepts on a task of its own, so a socket upgrades whether or not a caller waits in `accept`.
- The task ends when the listener drops.

| The plane meets                                    | It                                                                                                                                                                                     |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| An HTTP upgrade                                    | Runs it on a task of its own, under the `handshake_timeout` of the endpoint, which runs from the TCP accept on the clock of the listener                                               |
| A socket, from TCP accept until a caller takes it  | Holds it in one of at most `DEFAULT_MAX_SERVER_CONNECTIONS` slots, so a full accept loop stops new upgrades (CWE-770)                                                                  |
| A stalled upgrade                                  | Returns its slot at the deadline (CWE-400). It reaches no caller                                                                                                                       |
| A failed upgrade                                   | Returns its slot at once. It reaches no caller                                                                                                                                         |
| A failed TCP accept, such as a descriptor shortage | Returns its slot and waits out `DEFAULT_ACCEPT_RETRY_DELAY` on the clock of the listener before the next accept, as the upstream accept plane absorbs one. It reaches no caller either |

- `accept` yields finished upgrades only, so its one error is `TransportError::ConnectionClosed`.
- That error comes only once the accept task is gone, and only the drop of the listener ends that task.

#### Dial

- A dial opens `ws://<addr>/`.
- `connect_within(addr, limits)` sizes the socket ceiling to the larger envelope ceiling of `limits`.
- The transport narrows each read to the ceiling of its phase.

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

#### The stream

- `io::WsStream<S>` holds the `tightbeam_wire::WireDuplex` of the two native halves, `io::WsReadHalf` and `io::WsWriteHalf`, over a `tokio-tungstenite` WebSocket.
- It implements `AsyncProtocolStream`.
- It splits into exclusive halves (`SplittableStream`), so a multiplexed connection reads and writes at once.
- `io::WsTransport<S, P>` names `TcpTransport<WsStream<S>, P>`, the tightbeam transport over that stream.
- A stream comes only from a dial or an accept of `WsListener`, and each one opens its socket under the envelope ceiling of its endpoint.

#### The envelope rules over WebSocket

The halves are the native socket kind of the envelope rules that `tightbeam-wire` holds for every message-oriented socket ([The Envelope Rules of Message Sockets](wire.md)). Over WebSocket the rules read as follows:

| On the socket                                                                                | The stream                                                                                           |
| -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| A tightbeam envelope                                                                         | Carries it as one binary WebSocket message                                                           |
| A text message                                                                               | Skips it                                                                                             |
| A ping, a pong, or a raw frame                                                               | Skips it, because tungstenite answers each ping itself                                               |
| A close frame, or the end of the message stream                                              | Ends a read                                                                                          |
| A message past the envelope ceiling of the endpoint                                          | Reads `WireFault::Oversize`. Tungstenite refuses it by its declared length, before it sizes a buffer |
| A close, the end of the stream with no close, a send after the close, or a use after the end | Reads `WireFault::Closed`                                                                            |
| A failed byte stream, such as a write to a peer that left with no close                      | Reads `WireFault::Io`                                                                                |
| Every other tungstenite error                                                                | Reads `WireFault::Invalid`, a break of the protocol                                                  |

#### Round trips

- An HPKE round trip runs the handshake of tightbeam unchanged, and a cleartext one runs none.
- `tests/round_trip.rs` drives the `server!` and `client!` macros over a cleartext listener.
- `tests/encrypted_fixtures.rs` drives the HPKE handshake over `bind_with`.
- Each spec counts one accepted connection, one admitted request, and no refused request.
- The encrypted spec also counts one handshake at each end.

## Multiplexed sessions

- Each read of a multiplexed session runs under the operation timeout of its endpoint, `DEFAULT_OPERATION_TIMEOUT` by default, on the clock of the endpoint.
- A session that must outlive a silence probes its peer `KEEPALIVE_PROBES_PER_DEADLINE` times per timeout.
- A dialed session runs `MuxHandle::keep_alive`.
- An accepted link runs the keepalive that `AcceptedLink::spawn` starts.

## Accepted links

The `serve` module owns one accepted multiplexed connection: its transport gate, its tasks, and the `MuxHandle` that a push-capable service emits on. Upstream `MuxAcceptor::serve` lends its service no handle, so a server that pushes streams of its own serves through this module in three steps.

#### Serving a link

| Step | Call                                             | Does                                                                                                                                                                                                                            |
| ---- | ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | `AcceptedLink::accepted(transport)`              | Consumes a transport whose server handshake completed. It keeps the multiplexing settings, the in-band rekey context of a metered session, the peer of `MuxAcceptor::session_context`, the transport gate, and the writer clock |
| 1    | `AcceptedLink::cleartext(transport, settings)`   | Takes the `MuxSettings` that both ends agreed on, because a cleartext endpoint runs no handshake                                                                                                                                |
| 2    | `AcceptedLink::spawn`                            | Spawns the mux drivers and a keepalive into the `ServedMux` that owns them                                                                                                                                                      |
| 3    | `ServedMux::serve_dispatch(dispatch, expulsion)` | Runs the responder with a `MuxDispatch`, which answers each call with a status of its own, until the connection ends                                                                                                            |

- The keepalive probes the peer through `MuxHandle::ping` `KEEPALIVE_PROBES_PER_DEADLINE` times per read deadline, on the writer clock.
- The drop of the `ServedMux` ends all three: the mux drivers and the keepalive.
- Every call passes the gate first.

#### Serving a `MuxService`

- Under the `testing` feature, `ServedMux::serve(service, expulsion)` runs a `MuxService` in place of a dispatch, so the suites grade the served plane against upstream `MuxAcceptor::serve`.
- A call of `serve` reaches the method of its kind with a `CallContext` of the session that the handshake proved and the route of its stream.
- A kind that the service leaves out answers `Unimplemented`.

A handler that fails with an error of its own answers the status of the failure as upstream answers it:

| The failure carries | The call answers |
| ------------------- | ---------------- |
| A status            | That status      |
| `Unavailable`       | `Unknown`        |
| No status           | `Internal`       |

#### Events

Under the `instrument` feature, a served link records on the trace that its mux records on, which is the trace of the transport that the link was accepted on:

| Event                       | Label and value                                                                                          |
| --------------------------- | -------------------------------------------------------------------------------------------------------- |
| `GATE_ACCEPT`               | `Ok`, as upstream records it                                                                             |
| `GATE_REJECT`               | The status that the refused call answers, as upstream records it                                         |
| `HANDLER_FAILED`            | The status that a failed handler of `serve` answers, under the `testing` feature, as upstream records it |
| `serve::KEEPALIVE_ANSWERED` | Once for each probe of the keepalive that the peer answered                                              |

- The link runs its own keepalive over `MuxHandle::ping`, so a scenario moves its clock on `KEEPALIVE_ANSWERED`.
- `ServedMux::trace` lends that trace to the service, so `tightbeam-pubsub` records the decisions of its registry beside the verdicts.
- `tests/serve.rs` grades both planes against each other for every gate verdict and every handler outcome.
- Its read deadline scenarios, which [Test support](#test-support) lists, run on a listener bound on a `ManualClock`.

#### Differences from upstream

The published tightbeam API leaves four parts of the upstream pipeline out of reach, so a served connection differs from an upstream one in each:

- A gate evaluates the receipt of the handshake, not the receipt of the latest renewal.
  - `SessionContext` keeps its fields private, and only crate-private code builds one with a live receipt.
  - A renewal keeps the peer, so a gate that reads the peer decides alike.
- A verdict carries no peer key as its evidence.
  - The one public emit that carries a value carries no payload.
  - A verdict keeps its status as the value that a spec grades.
- A call records no `POLICY_EVAL`, `HANDLER_ENTER`, or `HANDLER_EXIT`.
  - A trace fault therefore stops a call only at its verdict or at the record of a failed handler.
  - The trace keeps the switch of those events private.
- Envelopes that the responder queued before it ended drop when the connection ends, because the writer stops at once.
  - That includes the `EnhanceYourCalm` GoAway of a cancel-budget refusal.
  - Upstream closes the handle and then finishes the drivers, so its writer sends the queue first.
  - Both `MuxHandle::close` and `MuxDrivers::finish` are crate-private.

#### Refusals

A link refuses a transport with a `LinkError`:

| `LinkError`                 | The link refused                                                                                                                   |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `NotMultiplexed`            | A transport whose handshake negotiated no multiplexing                                                                             |
| `Encrypted`                 | An endpoint provisioned for encryption, met by `cleartext`                                                                         |
| `ClockCannotRace(Timing)`   | A writer clock that cannot race a wait on the calling thread (`RacingClock`), so no emit deadline and no keepalive could run on it |
| `Transport(TransportError)` | A transport that refused to detach its rekey context or to split                                                                   |

- The `ClockCannotRace` check is an early refusal.
- A timer of the clock reads the timing again at each bound, on the thread that polls it.

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

| Feature            | Enables                                                                                                                |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `socket` (default) | The `tokio-tungstenite` listener, dial, and stream of `protocol` and `io`, over the envelope rules of `tightbeam-wire` |
| `serve`            | The accepted link of `serve`. It names no socket, so `tightbeam-pubsub` depends on `serve` alone                       |
| `instrument`       | The audit trail of a served link, below                                                                                |
| `testing`          | `socket`, `serve`, `instrument`, the `testing` feature of `tightbeam-rs`, and the test-support module, below           |
| `colony`           | `testing`, the upstream `colony` runtime, and the colony parts below                                                   |

#### `instrument`

- The gate verdict of each call, on the trace of the transport that the link was accepted on.
- Each answered probe of the keepalive, on the same trace.
- `ServedMux::trace`.

#### `testing`

The test-support module holds:

- X.509 identity fixtures
- the demo security kinds, and the `PeerIdentity` that a kind decides
- the shared multiplexed echo behavior
- the echo suites (`EchoService`, `PoolEchoes`) that every transport of the repository runs against itself
- the `ReadOutcome` that a scenario records for the read of a dial
- `specs`, the specs that grade the shared suites

#### `colony`

- The gateway, hive, and servlet configs that one identity derives.
- The work probe that every edge transport shares: `WorkPlane`, `WorkStack`, `WorkClient`, `WorkBody`, `WorkProbe`, and the `work_probe!` macro that declares a probe over one colony protocol.
- `WorkProbeServlet` and `WorkProbeHive` over the WebSocket colony.
- `WorkGateway`, the gateway of the WebSocket edge, over an optional `der`.

#### Examples

- `gen_certs`, `echo_server_mux`, and `echo_server_mux_clear` require `testing`.
- `work_gateway_server` requires `colony`.

## Cluster work plane

The `colony` feature of tightbeam routes signed work frames through a cluster gateway to the servlets that hives register. The WebSocket transport is the browser edge of a colony, and the colony interior runs on `WsListener` too.

#### The edge

- A gateway declares the edge with `cluster! { ..., protocol: WsListener, edge: WsListener }` and sets `ClusterConfig::edge` to `EdgePlane::new(addr)`.
- The gateway binds a second accept plane on WebSocket that admits `Work` frames only.
- It refuses each control frame, such as a registration, an advertisement, or gossip, with `PermissionDenied`.
- The upstream `SubmitWork` blanket implementation covers `GenericClient<WsListener>`, so an edge client submits through `submit_work_to`.
- The gateway forwards the signed frame of the caller to the servlet with its bytes unchanged.
- The complete signed response frame of the servlet returns the same way.

#### The shared work plane

- An application enables `colony` on `tightbeam-rs` in its own manifest to use the edge.
- The `colony` feature of this crate holds the work plane that the edge transports of the repository share.
- Every colony process presents one `Identity`, and the gateway, the hive, and the servlet derive their configuration from it.

| Item                   | Does                                                                                                                 |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `WorkPlane`            | Holds that identity and the work identity, and starts each part on its own, as a scenario does                       |
| `WorkPlane::hive::<S>` | Starts a hive of the probe `S`                                                                                       |
| `work_probe!`          | Declares a probe servlet and its hive over one colony protocol, with `WorkProbe` on the servlet                      |
| `WorkStack<G, S>`      | Starts the gateway `G` of any edge protocol, with a hive of the probe `S` over the colony of `G`                     |
| `WorkGateway`          | Is the gateway of the WebSocket edge                                                                                 |
| `WorkClient::submit`   | Submits one signed probe frame through the edge of any work gateway, at the address that `WorkClient::edge_of` reads |

- This crate declares `WorkProbeServlet` and `WorkProbeHive` over `WsListener`, and `tightbeam-grpc` declares its probe over `TokioListener`.
- Each probe that `work_probe!` declares answers `pong:<payload-hex>:<valid>`.
- `valid` says whether the end-to-end signature verified on the bytes that the servlet received.
- `tests/work_plane.rs` runs the round trip and a typed `WorkRefused` refusal from a WebSocket edge client through a gateway, hive, and servlet on the WebSocket colony.

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

#### Identities and security

- A certificate variable names the DER file of an identity, and its raw 32-byte signing key sits beside it.
- `DemoConfig` decides the `Security` of every connection:
  - server-auth
  - mutual-auth, when `TBWS_CLIENT_CERT` names a client certificate to pin
  - the session-budget paywall on top of mutual auth, when `TBWS_PAYWALL` is on
- A cleartext endpoint runs no handshake, so both ends MUST configure the same stream cap.
- A cleartext connection carries no confidentiality or integrity protection.
- The work gateway serves its probe under the servlet type that `TBWS_WORK_SERVLET` names (`WorkPlane::serving`).
- The e2e suites submit their work to the same type.

#### Echo bodies

`TBWS_ECHO_BODY` names the `EchoBody` of a server, and `streaming` is the default:

| Body        | Echoes                              |
| ----------- | ----------------------------------- |
| `streaming` | Unary frames and progressive bodies |
| `unary`     | Reassembled frames alone            |
| `duplex`    | The chunks of each duplex stream    |

- The echo of a progressive body carries the route of its Open as the id `routed:<target>:<hops>`.
- The target is empty when the Open names none.
- A client therefore asserts `openStream` and `openStreamTo` without a colony.

In the `streaming` and `unary` bodies, a frame id selects a command in place of the echo. The commands include:

| Frame id     | The server                                 |
| ------------ | ------------------------------------------ |
| `call-me`    | Calls the client back and relays its reply |
| `drain-calm` | Drains with an `EnhanceYourCalm` GoAway    |

A peer refusal of a call-back keeps its status on the relayed answer.

#### Liveness

- The work gateway holds its process with a pending future, because its topology serves from tasks of its own.
- The image checks the liveness of each server by the LISTEN state of its port, because a probe that connects holds an accept slot until the handshake deadline.

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

#### Identity files

- `IdentityFiles::provision` writes both files of an identity into a sibling staging directory.
- It then removes the published certificate, and renames the key and then the certificate into place.
- The certificate therefore publishes the identity, and an interrupted write leaves no certificate without its key.
- The cert step of `ws/scripts/stack-env.sh` keeps both identities while both certificates are present.

#### The e2e package

The e2e package `ws/tests` holds the lanes that run against the stack:

| File            | Holds                                                                                                                                                                   |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fixtures.ts`   | The stack fact readers, the dial facts, the Node lane dials, and the note payload. A page imports it as a Node lane does. The pubsub suites import it as `#ws-fixtures` |
| `util.ts`       | `base64ToBytes`, which the pages and the pubsub fixtures share. The pubsub suites import it as `#ws-util`                                                               |
| `app/main.ts`   | The round trips of the page, installed as `window.tb`. Each takes one options object across the `page.evaluate` boundary                                                |
| `app/engine.ts` | The engine, loaded from a custom module input as `window.tbEngine`                                                                                                      |

#### The Rust suites

`tests/support/mod.rs` holds what the Rust suites share:

- `bounded`, the hang guard of a wait on a peer
- `Answers`, which opens one stream of each kind and reads how each ends

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

#### TLS

- The listener has no TLS acceptor, so it binds `ws://` only.
- A page served over `https://` connects over `wss://` to a TLS terminator in front, such as a reverse proxy or a load balancer, which forwards `ws://` to the listener.
- Authentication and confidentiality still come from the tightbeam handshake above the socket.

#### Ceilings

- Before its handshake finishes, a peer can send one WebSocket message up to the established ceiling, `TransportLimits::max_envelope`.
- The socket ceiling is fixed at accept, so the handshake ceiling, `TransportLimits::handshake_wire`, refuses an oversized handshake message only after the read.

#### Idle close

- A pool that closes an idle WebSocket closes it with no Close frame, because `TcpTransport` lends no handle on its stream and `PersistentConnection::try_close` is synchronous.
- The peer reads the end as a lost connection, `ConnectionClosed`.

#### Origin

- The listener accepts a WebSocket whatever its `Origin` header names.
- Any web page can open a WebSocket to a listener that the browser reaches, loopback included.
- It connects as an anonymous peer, because the protocol carries no ambient credential.
- A listener that MUST NOT serve anonymous peers requires mutual authentication.

## Sources

- RFC 6455, The WebSocket Protocol, December 2011, § 5.5.1 Close and § 5.6 Data Frames: <https://datatracker.ietf.org/doc/html/rfc6455>
- CWE-319, Cleartext Transmission of Sensitive Information: <https://cwe.mitre.org/data/definitions/319.html>
- CWE-400, Uncontrolled Resource Consumption: <https://cwe.mitre.org/data/definitions/400.html>
- CWE-770, Allocation of Resources Without Limits or Throttling: <https://cwe.mitre.org/data/definitions/770.html>
