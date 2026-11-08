# The Envelope Wire Rules

This page specifies `tightbeam-wire`, the envelope rules that every message-oriented socket transport of tightbeam shares:

- what a socket kind implements, and what each of its messages means
- how a read and a write run, and when a stream reads as dead
- how each socket failure maps to a transport error
- the socket kinds that run the rules, and where each one is tested
- the limits of the rules against the upstream read contract

It drills down from the [tightbeam-wire README](../wire/tightbeam-wire/README.md) for engineers who add a socket kind or review one. The WebSocket kinds have their own pages, [The WebSocket Transport](ws.md) and [The Browser Engine](ws-wasm.md).

## Contents

- [Socket kinds](#socket-kinds)
- [Reads and writes](#reads-and-writes)
- [Faults](#faults)
- [Kinds in this repository](#kinds-in-this-repository)
- [Limitations](#limitations)
- [Sources](#sources)

## Socket kinds

A tightbeam envelope travels as one transport message, so the transport delimits each envelope and the stream needs no framing of its own. Upstream tightbeam puts such a transport on `AsyncProtocolStream` directly, and a byte transport on `AsyncByteStream` with its framing, as the docs of `AsyncByteStream` state.

A socket kind implements two traits over the halves of its socket:

- `WireStream::next_wire` classifies each received message as a `Wire` value.
- `WireSink::send_envelope` sends one envelope as one message.

| `Wire`     | The message                                                     |
| ---------- | --------------------------------------------------------------- |
| `Envelope` | Carries one envelope                                            |
| `Skip`     | Lies outside the tightbeam wire format, such as text or control |
| `Closed`   | Is a close, or the message stream ended                         |
| `Failed`   | Is an error of the socket, as a `WireFault` class               |

A kind whose socket has a message ceiling refuses a message past it before it sizes a buffer for it, and reports `Failed(WireFault::Oversize)`. A reader sees only whole messages, so it cannot refuse one any earlier. A socket without a message ceiling delivers every message whole, and [Limitations](#limitations) states what that leaves open.

## Reads and writes

`WireDuplex::new(stream, sink)` joins the two halves of one socket into a tightbeam stream. It implements `AsyncProtocolStream`, and `SplittableStream::into_split` hands out `WireReader` and `WireWriter`, which run the same rules apart, so a multiplexed connection reads and writes at once.

- A read passes over every `Skip`, admits the first envelope within its cap, and refuses an envelope past the cap with `SizeExceeded`. It checks the cap on the whole message that the kind handed over. A cap of zero refuses with `InvalidLimits(ZeroCeiling)`.
- A read ends at `Closed` with `ConnectionClosed`, and at `Failed` with the transport error of its class.
- A write sends one message per envelope.
- The duplex reads as dead after the first read or write that failed, so a pool passes over a failed socket.

## Faults

| `WireFault` | Cause                                                                 | `TransportError`                |
| ----------- | --------------------------------------------------------------------- | ------------------------------- |
| `Closed`    | The connection closed before the operation finished                   | `ConnectionClosed`              |
| `Io`        | The byte stream under the socket failed                               | `IoError`                       |
| `Oversize`  | A message passed the ceiling of the socket, or the cap of a read      | `OperationFailed(SizeExceeded)` |
| `Invalid`   | The socket broke its protocol, lost its connection, or refused a send | `InvalidMessage`                |

Each kind maps the errors of its own socket library into these classes in a private item of its module, because the orphan rule keeps a `From` impl between two foreign types out of every kind's crate.

```rust
use tightbeam::transport::{TransportError, TransportFailure};
use tightbeam_wire::WireFault;

let error = TransportError::from(WireFault::Oversize);
assert!(matches!(error, TransportError::OperationFailed(TransportFailure::SizeExceeded)));
```

## Kinds in this repository

| Kind                            | Crate               | Socket                                      | Message ceiling                                          | Suite that runs the rules against a real peer                          |
| ------------------------------- | ------------------- | ------------------------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------------- |
| `WsReadHalf`, `WsWriteHalf`     | `tightbeam-ws`      | A `tokio-tungstenite` WebSocket             | `TransportLimits::max_envelope`, set at a dial or accept | The `io` unit tests, against a tungstenite peer over an in-memory pipe |
| `GlooReadHalf`, `GlooWriteHalf` | `tightbeam-ws-wasm` | A `gloo-net` WebSocket in a JavaScript host | None: the browser exposes no ceiling                     | `tests/gloo_stream.rs`, against the `ws` server of the ws workspace    |

`make test wire` runs the `io` unit tests of `tightbeam-ws` beside the documentation tests of this crate, so a scoped run proves the rules against a real peer. `make wasm wire` builds the browser engine, which links this crate for `wasm32`.

The crate names no socket and depends on tightbeam alone. A `wasm32` build of it needs a random source for the browser, which the `wasm` feature of `tightbeam-rs` selects, so the crate that links it for `wasm32` enables that feature, as `tightbeam-ws-wasm` does.

## Limitations

- Upstream `AsyncProtocolStream::read_frame` asks a stream to refuse a frame past the cap of a read before it sizes any buffer. A message socket hands over only whole messages, so the rules check the cap of a read on a whole message. A peer can make a socket buffer one message up to its message ceiling, which each native kind sets at the envelope ceiling of its endpoint, because only the transport knows the phase of a read and its smaller cap.
- A browser exposes no message ceiling, so the browser kind holds each message in full before the rules see it, whatever its size.

## Sources

- The Rust Reference, Implementations, Orphan rules: <https://doc.rust-lang.org/reference/items/implementations.html#orphan-rules>
- tightbeam-rs 0.18.0, `transport::AsyncProtocolStream` and `transport::AsyncByteStream`: <https://docs.rs/tightbeam-rs/0.18.0/tightbeam/transport/index.html>
