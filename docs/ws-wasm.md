# The Browser Engine

This page specifies `tightbeam-ws-wasm`, the WebAssembly engine of the WebSocket client:

- the build, the two bundles it ships in, and the loader of each one
- the modules of the crate and the target each one compiles for
- the parse-once rule of the boundary
- the engine compression
- the browser transport and its socket rules
- the session profile, and the steps of a build on another provider
- the suites that run the engine

It drills down from the [tightbeam-ws-wasm README](../ws/tightbeam-ws-wasm/README.md) for engineers who build on the engine or review it. The README holds what each part is for and the standards it follows. The TypeScript surface over the engine has its own page, [The WebSocket Client](ws-client.md).

## Contents

- [Build](#build)
- [Modules](#modules)
- [Parse once](#parse-once)
- [Codes](#codes)
- [Compression](#compression)
- [Browser transport](#browser-transport)
- [Session profiles](#session-profiles)
- [Tests](#tests)
- [Sources](#sources)

## Build

The crate has `publish = false`, and it builds as a `cdylib` for `wasm-pack` and as an `rlib`, so another wasm crate can link it. `make client` runs `wasm-pack` twice and then builds the TypeScript workspace:

| Bundle  | `wasm-pack` target | Output directory      | Loaded by                                                 |
| ------- | ------------------ | --------------------- | --------------------------------------------------------- |
| Browser | `web`              | `ws/client/wasm`      | `src/engine/web.ts`, the `default` condition of `#engine` |
| Node    | `nodejs`           | `ws/client/wasm-node` | `src/engine/node.ts`, the `node` condition of `#engine`   |

The npm package `@wahidgroup/tightbeam-ws-client` ships both bundles, and its `imports` map selects the loader of one, so the build condition decides the bundle at resolution:

- Each loader imports its own glue inside `load`, so a binary loads at `Engine.load` alone.
- Each loader starts its glue once per realm through one `Once`, and answers that start to every later call, because a second start in flight would swap the instance under live handles. A failed start clears the memo, so the next call starts again. `Engine.load` builds one engine per realm through the same `Once`.
- The web loader passes the input of `Engine.load` to the `init` of its glue. The Node loader ignores it, because the `nodejs` glue reads its binary beside itself.

`make test` skips `wasm-opt` to save build time, and `make ci` passes `wasm_opt=1`, so CI builds the release-sized wasm.

The lint of the client holds the glue to the loaders. The typescript-eslint `no-restricted-imports` rule refuses a static value import of `#wasm` or of a bundle in every module, with type imports allowed, and `no-restricted-syntax` refuses a dynamic import in `src/**` outside `src/engine/**`.

```sh
make client
```

## Modules

The engine depends on `tightbeam-wire`, which names no socket, so the browser stream runs the envelope rules of the native one ([The Envelope Rules of Message Sockets](wire.md)).

| Module      | Target         | Holds                                                                                                                              |
| ----------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `build`     | Every target   | Frame assembly and the structural security operations over opaque message bytes                                                    |
| `compress`  | Every target   | `ZstdCompression`, the engine zstd over `ruzstd`, and its refusals in `ZstdRefusal`                                                |
| `fault`     | Every target   | The code families, `BodyLayer`, the `Code` of one failure, and on `wasm32` the structured error `JsFault` and `Codes`              |
| `goaway`    | Every target   | The labels that JavaScript reads a GoAway reason by, and the parse of a reason it hands over                                       |
| `metadata`  | Every target   | The labels that JavaScript reads a protocol version and a message priority by, and their parse                                     |
| `approver`  | `wasm32` only  | `JsReceiptApprover`, and the reads of the session budgets and the authorization token                                              |
| `bindings`  | `wasm32` only  | The `wasm-bindgen` frame-composer bindings, and the handles `Oid`, `DigestInfo`, `CommitmentSalt`, and `ProfileOids`               |
| `clock`     | `wasm32` only  | `BrowserClock`, the host clock of a page or a Node process                                                                         |
| `dial`      | `wasm32` only  | `Dial`, which reads the kind of session, its certificates, and its options once, and the setup each kind runs                      |
| `mux`       | `wasm32` only  | `BrowserMux`, `SessionParts`, `MuxTasks`, and `MuxWsClient`, the multiplexed session that the client binds                         |
| `profile`   | `wasm32` only  | The profile keys and ciphers: `Secp256k1SigningKey`, `Secp256k1VerifyingKey`, `Aes256Gcm`, and the HPKE pair                       |
| `promise`   | `wasm32` only  | The one parse of each JavaScript kind a binding reads, and the promise boundary of the bindings                                    |
| `protocol`  | `wasm32` only  | `BrowserSocket<P>`, the tightbeam protocol over a socket that the page opened, and the session states `Pinned<P>` and `Session<P>` |
| `signer`    | `wasm32` only  | `JsSigningKeyProvider` and `TransportSigner`, a JavaScript signer for mutual authentication                                        |
| `socket`    | `wasm32` only  | `OpeningSocket` and `SocketMonitor`, the open and close events of a browser WebSocket                                              |
| `stream`    | `wasm32` only  | `GlooStream`, the `gloo-net` WebSocket stream, and `WsTransport`                                                                   |
| `streaming` | `wasm32` only  | The progressive request, reply, and duplex bodies, and the serve loop of each kind                                                 |
| `loopback`  | `wasm32` tests | A listening `ws` server, a hold on the socket it accepted, and two sessions over one socket, for the tests that need a peer        |

## Parse once

The engine parses every JavaScript value it owns once, in a Rust constructor, and the TypeScript layer keeps the handle that the parse returns. A binding parameter is one of three kinds:

- a handle class, such as `Oid`, `DigestInfo`, `CommitmentSalt`, or `ZstdCompression`, which only its parse builds and which a call borrows
- `JsBytes`, which admits a `Uint8Array` of any realm and refuses every other value with `InvalidBytes`, as it refuses a `Uint8Array` over a detached buffer
- a `JsValue` that one Rust parser reads, such as the options of a dial, a serve claim, an order, or a version

`promise` holds the one parse of each JavaScript kind that a binding reads: `JsBytes` for bytes, `Text::read` for a string, `WholeNumber` for a whole number or a `bigint`, `Signal::read` for an optional `AbortSignal`, and `Callback::read` for a function. `Text::read`, `Signal::read`, `Callback::read`, and `JsBytes::read_value` name the field they read on `path`, so a binding takes a `JsValue` with an `unchecked_param_type` and refuses a value of another kind with a code, where the glue would pass it through unchecked or throw an untyped `TypeError`.

The three kinds replace the coercing primitives of `wasm-bindgen`. A `u32`, a `u64`, a `bool`, or a numeric enum parameter converts any value it receives, so a fraction truncates, a negative number wraps, and an unknown enum value throws an untyped error from the glue. The parsers that replace them refuse with a code:

| Parameter                                                          | Parser                                                        | Refusal                                                                                                                |
| ------------------------------------------------------------------ | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| The options of `connect`, `connectMutual`, `connectCleartext`      | `Dial::parse`, which reads them once, each knob at its member | `InvalidConnectOptions`, `InvalidStreamCap`, `InvalidSignal`, `SessionOfferRequiresMutual`, and the codes of each knob |
| The url of a dial                                                  | `Text::read`                                                  | `InvalidText` at `url`                                                                                                 |
| The target of a routed stream or work                              | `StreamTarget::read`, which parses the URN once               | `InvalidStreamRoute` at `target`                                                                                       |
| The signal of `request`, `submitWork`, `ping`, `waitForStreamSlot` | `Signal::read`                                                | `InvalidSignal` at `signal`                                                                                            |
| The handler of `serve*`, `approveReceipt`, and `signPrehash`       | `Callback::read`                                              | `InvalidCallback` at the field                                                                                         |
| The certificates of `connect` and `connectMutual`                  | The one certificate parse of `dial`                           | `InvalidBytes`, `InvalidCertificate`                                                                                   |
| The order and the lifetime of a frame                              | `WholeNumber::u64_at`, a number or a `bigint`                 | `InvalidOrder`, `InvalidLifetime`                                                                                      |
| The version and the priority of a frame                            | `TryFrom<&JsValue>` for `VersionLabel` and `PriorityLabel`    | `InvalidVersion`, `InvalidPriority`                                                                                    |
| The claim of `serve`, `serveStreaming`, `serveDuplex`              | `ServeClaim::admit`, which answers the private `Claim`        | `InvalidServeClaim`                                                                                                    |
| The ceiling of `ZstdCompression.ceiling`                           | `WholeNumber::read`                                           | `InvalidMaxOutput`                                                                                                     |

The engine reads a handle only as a parameter of its own, because `wasm-bindgen` 0.2.126 moves a handle out of any object it reads the handle from. A call that names an algorithm therefore takes the `Oid` as a parameter, such as `FrameAssembly.withCompactness(algorithmOid, data, parametersDer)`. The integrity steps `withMessageIntegrity(algorithmOid, digest)` and `withWitness(algorithmOid, digest)` build the digest inside the step that consumes the assembly, so an empty digest refuses there and leaves no digest handle behind. The duck-typed `TransportSigner` names its algorithm as a dotted string, which the one Rust OID parser reads as the dial begins. `JsSigningKeyProvider::new` reads its `signPrehash` function once too, so each handshake calls the function that the dial admitted.

The engine holds the rules of a frame that tightbeam holds:

- `FrameAssembly.decode` admits each digest a frame carries once as a `NamedDigest` and keeps it, and refuses an empty digest with `EmptyDigest`. Each step that installs a digest keeps it too, so the summary reads the digests the assembly admitted.
- A composer without `withId` refuses at the build with `BuildError`, as tightbeam refuses a frame with no id.
- `FrameComposer.assertVersion` refuses at the build with `VersionMismatch`, before any security step of the caller runs.
- `DigestInfo.verdict` judges the algorithm first and the octets in constant time through `ConstantTimeDigest` of `tightbeam-rs`, and answers the label of its `IntegrityVerdict`.
- A dial parses its certificates once, so `BrowserSocket::trust_store` and `JsSigningKeyProvider::identity` take a parsed `Certificate`.

`CommitmentSalt.take()` borrows its handle mutably, moves the salt into a new handle, and leaves the old one an empty shell, which frees as any handle does. A take by value would make the glue zero the pointer of the caller, and a later `free()` of that object would throw an error with no code. An empty shell refuses `take`, `preimage`, and a commitment preimage with `CommitmentSpent`.

## Codes

A failure crosses the boundary as an `Error` named `TightbeamTransportError`. Its `code` is a variant of one of three string enums in `fault.rs`, or one of the two labels whose code carries a detail, `WorkRefused` and `OpaqueBody`. Each code has one declaration:

| Enum            | The code names                                                                                                 |
| --------------- | -------------------------------------------------------------------------------------------------------------- |
| `RefusalCode`   | A value the bindings refuse before an engine or a transport error exists, a `BuildRefusal`, or a `ZstdRefusal` |
| `TransportCode` | A variant of `TransportError` or `TightBeamError` of `tightbeam-rs`, or a local `TransportFailure`             |
| `TransitCode`   | A gRPC canonical status: the code of a peer refusal, and the status a stream handler answers with              |

- One macro, `code_enum!`, declares each enum from one list of variants, and the same list writes a TypeScript union into the declarations of the wasm build through a `typescript_custom_section`. The client imports the unions as types, so it copies no code by hand.
- The macro holds each label equal to the name of its variant with a const assertion, and writes the fault member of each family: `RefusalFault`, `TransportFault`, and `TransitFault`.
- The macro lists the labels of each family. One const assertion holds those lists and the labels `WorkRefused` and `OpaqueBody` pairwise disjoint, so `Code::read` reads each label as one family.
- `TransportCode` maps every upstream variant through one match, and the last arm names `Unrecognized`, because both upstream error types are `#[non_exhaustive]`.
- A `TransportFailure` names its code through one exhaustive match: a local failure names its `TransportCode`, and a peer refusal names the `TransitCode` of the status that `tightbeam-rs` pairs it with. A pin test holds each pair equal.
- `Code`, the code of one failure, carries the detail of its family. `Code::WorkRefused` holds the `TransitCode` of a refused work submission, which the error carries on `status`. `Code::OpaqueBody` holds the `BodyLayer` that a body read lacks, `opener` or `inflator`, which the error carries on `layer`. One match from `TightBeamError` builds both.
- `EngineFault` is the union of the fault members, one per `Code` family, so a TypeScript check of `code` narrows to the member that carries `status` or `layer`. `Codes.recognizes` reads a value back the way `JsFault` writes it, so a forged error with an unknown code or detail is no transport error.
- A refusal of one field names it on `path`, such as `matrix.n`, through `JsFault::at`, as the `FieldError` of `tightbeam-asn` names a path.
- `TransitCode::refusal` is the one decider of a refusal label: every label of `TransitCode` but `Ok`, which names no refusal. The macro writes the same rule as `TransitRefusal = Exclude<TransitCode, "Ok">`, the type a duplex handler resolves with.
- A served stream reads its settlement as a label alone, on the unary, streaming, and duplex serve paths alike. A label that `TransitCode::refusal` admits answers that status, and every other value answers `Unknown`. The client decides the label through `StreamRefusal.settlement`, so only a `StreamRefusal` picks the status of a stream.
- The labels of `TransitCode`, `GoAwayReason`, `Version`, and `MessagePriority` copy upstream names and ordinals as literals, because a `wasm-bindgen` enum takes literal discriminants. A pin test holds each label equal to its upstream value.

## Compression

`ZstdCompression` in the `compress` module is the profile zstd of the engine. It implements the `Inflator` and the `Compressor` of `tightbeam-rs` over `ruzstd` 0.9.1, a pure-Rust decoder and encoder, because the zstd of `tightbeam-rs` links libzstd through `zstd-sys`, which needs a C compiler for `wasm32-unknown-unknown`. The crate enables the `compress` feature of `tightbeam-rs`, which carries the traits and `CompressionError` without libzstd.

The engine copies the clauses of the `ZstdCompression` of `tightbeam-rs`:

- It admits one frame: a zstd frame, or a skippable frame that inflates to no octets. An octet after the frame is refused, so a trailing skippable frame or a seek table rejects.
- The output stays within the ceiling, 16 MiB by default. The window that a frame declares is held to the ceiling rounded up to a power of two, with the window log clamped to 10 through 30 on `wasm32`, a 32-bit target, and to 10 through 31 on the 64-bit host.
- It admits absent parameters, or a DER `INTEGER` level from -131072 to 22. The range is a fact copied from zstd 1.5.7, because `tightbeam-rs` reads it from libzstd at runtime.
- It enforces the content checksum, the reserved descriptor bit, and the declared content size, which `ruzstd` 0.9.1 leaves to its caller, and refuses a frame that breaks one as `Malformed`.
- A block that states a size, or carries literals or sequences, past its Block_Maximum_Size, the smaller of the window and 128 KiB (RFC 8878 section 3.1.1.2.4), is refused as `Malformed`, or as `Truncated` when it is an RLE block whose octet has not arrived, as libzstd does. The engine checks a compressed block's size and, once the block is in the input, its literals, and the RLE block whose octet is missing. `ruzstd` 0.9.1 checks a raw or RLE size and the sequence expansion of RUSTSEC-2026-0344. The literals left after the sequences bring a block to at most twice its maximum, which the output ceiling bounds.

The compressor writes at the `Fastest` level of `ruzstd`, records no parameters, and declares the 128 KiB window that `ruzstd` 0.9.1 always writes. A peer therefore admits engine-compressed bodies once its ceiling exceeds 64 KiB.

`ZstdCompression.ceiling(maxOutput)` parses a ceiling once and answers a handle bound to it, and `decompress` inflates within the ceiling of its own handle. `ZstdCompression.decompress` is the one inflate that JavaScript reaches, and `Frame.open` of the client inflates through it. A refusal carries the `RefusalCode` of its `ZstdRefusal` variant: `WindowTooLarge`, `OutputLimitExceeded`, `Truncated`, `TrailingBytes`, `Stalled`, or `Malformed`.

The engine also implements the `Inflator` of `tightbeam-rs` for the frame paths of the host interop tests. That trait returns the error type of `tightbeam-rs`, so the implementation wraps each refusal in `CompressionError::IO`, the one variant that exists without libzstd.

## Browser transport

`GlooStream` adapts a `gloo-net` WebSocket to `AsyncProtocolStream`, and it splits into exclusive halves (`SplittableStream`) so a multiplexed connection reads and writes at once. Each read and write runs the envelope rules of `tightbeam_wire`. A close event, a lost connection, and a refused send each meet no peer, so each is `WireFault::Closed` and reaches callers as `ConnectionClosed`. `BrowserSocket<P>` is the protocol of a socket the page opened, which it adopts in place of a dial:

- `Protocol::connect` and `Protocol::bind_cleartext` refuse with `TransportError::InvalidState`.
- `BrowserSocket::<P>::pinned(stream, trust_store, identity, mux)` adopts an opened socket into a `Pinned<P>`, the transport of a client that pins `trust_store` and offers `mux` for its handshake. It presents `identity` when a server demands mutual authentication. The dialer rule or the key-purpose check refuses the provisioning with a `TransportError`.
- `BrowserSocket::<DefaultCryptoProvider>::trust_store(server_cert)` builds one anchor that pins the parsed server certificate, validated under the secp256k1 certificate policy on the host clock. It fails with `TransportError::InvalidCertificate` when the store refuses the certificate.
- `Protocol` requires `connect` and `bind_cleartext` of every protocol, and `ClientBuilder::adopt` of `tightbeam-rs` takes a `Protocol`, so the adopt-only socket answers both with a refusal.

`BrowserClock::host`, the one constructor of the clock, reads the `setTimeout` of its host once. A host with a timer races each bound against its sleep, and a host with none answers `Timing::Absent`, so a bound refuses work that waits on it. `setTimeout` honours a delay up to 2^31-1 milliseconds, about 24.8 days, so a longer sleep arms the timer again for the rest, in steps of that bound.

Every session is multiplexed: the WebSocket profile of tightbeam negotiates stream multiplexing, so one connection carries concurrent, bidirectional streams. `BrowserMux::split` spawns the reader pump, the writer pump, and the keepalive on the browser executor. It returns the `SessionParts` of the session: the stream handle, the responder, and the `MuxTasks` set that owns the tasks. The tasks run until the set drops or the connection ends. The drop ends each task at its next poll, which fails every stream still pending on the session.

The bindings that open a stream:

- `request` and `submitWork` take an optional `AbortSignal`, which `Signal::read` parses, and they poll their call once before they return, so the stream holds its slot of the cap by the time the caller reads `hasPendingStreams`.
- A body half of a progressive stream is a `Slot` that one call leases at a time. The slot holds the abort of the call that holds the half, so a free of the handle ends the read in flight at once. A free before the peer's `last` discards the chunks still to come, and only a free of a duplex reply body cancels its stream, as the doc of `MuxStreamBody` says.
- The request half of a client stream is a `Slot` that only its handle holds, so a free of the handle ends the push in flight at once, even one that waits on the credit of the peer, and cancels the stream. The reply half of a served duplex stream shares its slot with its push, so that push finishes after a free, because tightbeam counts the records of a reply push as owed until they send or the stream ends.
- The handlers of `serve`, `serveStreaming`, and `serveDuplex` and the `StreamRoute` they read are declared once, in Rust, as TypeScript types of the build.

`JsSigningKeyProvider` adapts a JavaScript signer to the `SigningKeyProvider` of tightbeam, so mutual authentication needs no raw key bytes. The signer is duck-typed: an object with an `algorithmOid` string, a `publicKeyDer` `Uint8Array`, and a `signPrehash` method that resolves with a `Uint8Array`. `JsSigningKeyProvider::new` refuses any other shape.

## Session profiles

The session profile is a compile-time `CryptoProvider` choice, as with a native `tightbeam-rs` transport. It fixes the curve, the AEAD, the digests, and the certificate policy. The shipped `MuxWsClient` binding runs `BrowserSocket<DefaultCryptoProvider>`, the default profile of tightbeam. Frame-level cryptography stays caller-supplied at runtime in the TypeScript layer under any profile.

A deployment on another provider builds its own wasm crate against this one, which links as an `rlib`, and binds the transport layer with its own `#[wasm_bindgen]` items. The types hold the order of the steps:

1. For mutual authentication, adapt a JavaScript `TransportSigner` with `JsSigningKeyProvider::identity::<P>(signer, certificate)`, over the parsed client certificate. Its signatures MUST verify under `P`.
2. Call `BrowserSocket::<P>::pinned(socket, trust_store, identity, TransportOffer::mux(streams))` on an opened `gloo` WebSocket. It answers a `Pinned<P>`, which offers multiplexing for the handshake. The trust store MUST validate under `P`, as `BrowserSocket::trust_store` does for the default profile. `Pinned::approving` adds a receipt approver.
3. Call `Pinned::handshake`, which runs the client handshake and answers a `Session<P>`.
4. Call `BrowserMux::split` on the session. The split runs the pumps and the keepalive under any provider, until the `MuxTasks` of the `SessionParts` that it returns drops.

## Tests

| Suite                                          | Command                            | Runs                                                                                                                                                                                                                                                                                                          |
| ---------------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tests/wasm_runtime.rs`                        | `wasm-pack test --node`            | The two target-specific hazards of a handshake: the host clock through `OffsetDateTime::now_utc`, and the RNG through an HPKE seal of `build::HpkeSecp256k1Encryptor`                                                                                                                                         |
| `tests/gloo_stream.rs`                         | `wasm-pack test --node`            | The envelope rules of `tightbeam-wire` against `GlooStream`, over a real `gloo` WebSocket to a peer that the `ws` server of the ws workspace serves                                                                                                                                                           |
| `mod tests` of the `wasm32` modules            | `wasm-pack test --node`            | `approver`, `bindings`, `clock`, `compress`, `goaway`, `mux`, `profile`, `promise`, `signer`, `socket`, and `streaming`: the parse-once refusals, the JavaScript signer, the timer steps of the clock, and the stream halves. `loopback` serves a real peer for the serve, body, open, and freed-client cases |
| `mod tests` of the host modules                | `cargo test`                       | `build`, `compress`, `fault`, `goaway`, and `metadata`: the frame steps, the engine zstd against the zstd of `tightbeam-rs`, and the pins of each code and label                                                                                                                                              |
| Playwright and the node lane, under `ws/tests` | `make test` at the repository root | The compiled client end to end, against a dockerized `tightbeam-ws` echo server                                                                                                                                                                                                                               |

Each wait of a `wasm32` test on a peer runs under `settled` of `tests/support/patience.rs`, which fails the test once `PATIENCE` passes. The `loopback` module and `tests/gloo_stream.rs` both include that one file.

`make -C ws test` runs the `wasm-pack` suites, and the repository root `make test` adds the dockerized end-to-end lanes.

## Sources

- RFC 6455, The WebSocket Protocol, December 2011, § 4.2.2 the server handshake and § 5.2 the frame layout: <https://datatracker.ietf.org/doc/html/rfc6455>
- wasm-pack, the Rust and WebAssembly packaging tool: <https://rustwasm.github.io/docs/wasm-pack/>
- RFC 8878, Zstandard Compression and the `application/zstd` Media Type, February 2021, § 3.1.1 the frame layout and § 3.1.2 skippable frames: <https://datatracker.ietf.org/doc/html/rfc8878>
- CWE-409, Improper Handling of Highly Compressed Data: <https://cwe.mitre.org/data/definitions/409.html>
- CWE-770, Allocation of Resources Without Limits or Throttling: <https://cwe.mitre.org/data/definitions/770.html>
- RUSTSEC-2026-0344, 2026-10-11, a decompression bomb in `ruzstd` below 0.9.1, where one block's sequences expand without a Block_Maximum_Size bound: <https://rustsec.org/advisories/RUSTSEC-2026-0344>
