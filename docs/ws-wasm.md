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

The crate has `publish = false`, so it never reaches crates.io. It builds as a `cdylib` for `wasm-pack` and as an `rlib`, so another wasm crate can link it. `make client` runs `wasm-pack` twice and then builds the TypeScript workspace:

| Bundle  | `wasm-pack` target | Output directory      | Loaded by                                                 |
| ------- | ------------------ | --------------------- | --------------------------------------------------------- |
| Browser | `web`              | `ws/client/wasm`      | `src/engine/web.ts`, the `default` condition of `#engine` |
| Node    | `nodejs`           | `ws/client/wasm-node` | `src/engine/node.ts`, the `node` condition of `#engine`   |

The npm package `@wahidgroup/tightbeam-ws-client` ships both bundles, and its `imports` map selects the loader of one. Each loader imports its own glue inside `load`, so a binary loads at `TightbeamWsClient.init` alone, and the build condition decides the bundle at resolution. The web loader passes the input of `TightbeamWsClient.init` to the `init` of its glue, and the Node loader ignores it, because the `nodejs` glue reads its binary beside itself. `make test` skips `wasm-opt` to save build time, and `make ci` passes `wasm_opt=1`, so CI builds the release-sized wasm.

The lint of the client holds the glue to the loaders. The typescript-eslint `no-restricted-imports` rule refuses a static value import of `#wasm` or of a bundle in every module, with type imports allowed, and `no-restricted-syntax` refuses a dynamic import in `src/**` outside `src/engine/**`.

```sh
make client
```

## Modules

The engine depends on `tightbeam-ws` with default features off and `wire` on, so the browser stream runs the envelope rules of the native one ([The WebSocket Transport](ws.md#stream-and-envelope-rules)).

| Module      | Target        | Holds                                                                                                                |
| ----------- | ------------- | -------------------------------------------------------------------------------------------------------------------- |
| `build`     | Every target  | Frame assembly and the structural security operations over opaque message bytes                                      |
| `compress`  | Every target  | `ZstdCompression`, the engine zstd over `ruzstd`, and its refusals in `ZstdRefusal`                                  |
| `fault`     | Every target  | The code families `RefusalCode`, `TransportCode`, and `TransitCode`, and on `wasm32` the structured error `JsFault`  |
| `goaway`    | Every target  | The labels that JavaScript reads a GoAway reason by, and the parse of a reason it hands over                         |
| `metadata`  | Every target  | The labels that JavaScript reads a protocol version and a message priority by, and their parse                       |
| `bindings`  | `wasm32` only | The `wasm-bindgen` frame-composer bindings, and the handles `Oid`, `DigestInfo`, `CommitmentSalt`, and `ProfileOids` |
| `secure`    | `wasm32` only | The mutual identity and the dial options, each parsed once                                                           |
| `protocol`  | `wasm32` only | `BrowserSocket<P>`, the tightbeam protocol over a socket that the page opened                                        |
| `stream`    | `wasm32` only | `GlooStream`, the `gloo-net` WebSocket stream, and `WsTransport`                                                     |
| `mux`       | `wasm32` only | `BrowserMux`, `MuxTasks`, and `MuxWsClient`, the multiplexed session that the client binds                           |
| `signer`    | `wasm32` only | `JsSigningKeyProvider` and `TransportSigner`, a JavaScript signer for mutual authentication                          |
| `clock`     | `wasm32` only | The host clock of a page                                                                                             |
| `streaming` | `wasm32` only | The progressive request, reply, and duplex bodies                                                                    |

## Parse once

The engine parses every JavaScript value it owns once, in a Rust constructor, and the TypeScript layer keeps the handle that the parse returns. A binding parameter is one of three kinds:

- a handle class, such as `Oid`, `DigestInfo`, `CommitmentSalt`, or `ZstdCompression`, which only its parse builds and which a call borrows
- `JsBytes`, which admits a `Uint8Array` of any realm and refuses every other value with `InvalidBytes`
- a `JsValue` that one Rust parser reads, such as the options of a dial, a serve claim, an order, or a version

The three kinds replace the coercing primitives of `wasm-bindgen`. A `u32`, a `u64`, a `bool`, or a numeric enum parameter converts any value it receives, so a fraction truncates, a negative number wraps, and an unknown enum value throws an untyped error from the glue. The parsers that replace them refuse with a code:

| Parameter                                                     | Parser                                                     | Refusal                                                                   |
| ------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------- |
| The options of `connect`, `connectMutual`, `connectCleartext` | `DialOptions`, `MutualDialOptions`                         | `InvalidConnectOptions`, `InvalidStreamCap`, `SessionOfferRequiresMutual` |
| The order and the lifetime of a frame                         | `WholeNumber::u64_at`, a number or a `bigint`              | `InvalidOrder`, `InvalidLifetime`                                         |
| The version and the priority of a frame                       | `TryFrom<&JsValue>` for `VersionLabel` and `PriorityLabel` | `InvalidVersion`, `InvalidPriority`                                       |
| The claim of `serve`, `serveStreaming`, `serveDuplex`         | `TryFrom<&JsValue>` for `Claim`                            | `InvalidServeClaim`                                                       |
| The ceiling of `ZstdCompression.ceiling` and `decompress`     | `WholeNumber::read`                                        | `InvalidMaxOutput`                                                        |

The engine reads a handle only as a parameter of its own, because `wasm-bindgen` 0.2.126 moves a handle out of any object it reads the handle from. A call that names an algorithm therefore takes the `Oid` as a parameter, such as `FrameAssembly.withCompactness(algorithmOid, data, parametersDer)`. The integrity steps `withMessageIntegrity(algorithmOid, digest)` and `withWitness(algorithmOid, digest)` build the digest inside the step that consumes the assembly, so an empty digest refuses there and leaves no digest handle behind. The duck-typed `TransportSigner` names its algorithm as a dotted string, which the one Rust OID parser reads as the dial begins.

`CommitmentSalt.take()` borrows its handle mutably, moves the salt into a new handle, and leaves the old one an empty shell, which frees as any handle does. A take by value would make the glue zero the pointer of the caller, and a later `free()` of that object would throw an error with no code. An empty shell refuses `take`, `preimage`, and a commitment preimage with `CommitmentSpent`.

## Codes

A failure crosses the boundary as an `Error` named `TightbeamTransportError`. Its `code` is a variant of one of three string enums in `fault.rs`, and each code has one declaration:

| Enum            | The code names                                                                                                 |
| --------------- | -------------------------------------------------------------------------------------------------------------- |
| `RefusalCode`   | A value the bindings refuse before an engine or a transport error exists, a `BuildRefusal`, or a `ZstdRefusal` |
| `TransportCode` | A variant of `TransportError` or `TightBeamError` of `tightbeam-rs`, or a local `TransportFailure`             |
| `TransitCode`   | A gRPC canonical status: the code of a peer refusal, and the status a stream handler answers with              |

- One macro declares each enum from one list of variants, and the same list writes a TypeScript union into the declarations of the wasm build through a `typescript_custom_section`. The client imports the unions as types, so it copies no code by hand.
- `TransportCode` maps every upstream variant through one match, and the last arm names `Unrecognized`, because both upstream error types are `#[non_exhaustive]`. A peer refusal names the `TransitCode` of its status through the conversion of `tightbeam-rs`.
- Every label equals the name of its upstream variant, such as `OpaqueBody` for `TightBeamError::OpaqueBody`. The wasm class of the profile opaque body is `OpaqueCodec`, so no class shares a name with a code.
- A refusal of one field names it on `path`, such as `matrix.n`, through `JsFault::at`, as the `FieldError` of `tightbeam-asn` names a path. A refused work submission carries its `TransitCode` on `status`.
- `TransitCode::of_js` reads the status that a stream handler settles with, as a label or as the `code` of a rejection, on the unary, streaming, and duplex serve paths alike. `Ok` names no refusal, so it answers `Unknown`, as any other value does.
- The labels of `TransitCode`, `GoAwayReason`, `Version`, and `MessagePriority` copy upstream names and ordinals as literals, because a `wasm-bindgen` enum takes literal discriminants. A pin test holds each label equal to its upstream value.

## Compression

`ZstdCompression` in the `compress` module is the profile zstd of the engine. It implements the `Inflator` and the `Compressor` of `tightbeam-rs` over `ruzstd` 0.9.0, a pure-Rust decoder and encoder, because the zstd of `tightbeam-rs` links libzstd through `zstd-sys`, which needs a C compiler for `wasm32-unknown-unknown`. The crate enables the `compress` feature of `tightbeam-rs`, which carries the traits and `CompressionError` without libzstd.

The engine copies the clauses of the `ZstdCompression` of `tightbeam-rs`:

- It admits one frame: a zstd frame, or a skippable frame that inflates to no octets. An octet after the frame is refused, so a trailing skippable frame or a seek table rejects.
- The output never grows past the ceiling, 16 MiB by default. The window that a frame declares is held to the ceiling rounded up to a power of two, with the window log clamped to 10 through 30 on `wasm32`, a 32-bit target, and to 10 through 31 on the 64-bit host.
- It admits absent parameters, or a DER `INTEGER` level from -131072 to 22. The range is a fact copied from zstd 1.5.7, because `tightbeam-rs` reads it from libzstd at runtime.
- It enforces the content checksum, the reserved descriptor bit, and the declared content size, which `ruzstd` 0.9.0 leaves to its caller, and refuses a frame that breaks one as `Malformed`.

The compressor writes at the `Fastest` level of `ruzstd`, records no parameters, and declares the 128 KiB window that `ruzstd` 0.9.0 always writes. A peer therefore admits engine-compressed bodies once its ceiling exceeds 64 KiB.

A refusal carries the code of the path that refused it:

| Path                                                                         | Code                                                                                                                                             |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ZstdCompression.decompress`, a direct call                                  | The `RefusalCode` of the `ZstdRefusal` variant: `WindowTooLarge`, `OutputLimitExceeded`, `Truncated`, `TrailingBytes`, `Stalled`, or `Malformed` |
| `FrameAssembly.inflate`, the frame inflate path of `CleartextFrame::inflate` | `CompressionError`                                                                                                                               |

The frame inflate path returns the error type of `tightbeam-rs`, so the engine wraps each refusal in `CompressionError::IO`, the one variant that exists without libzstd, and the `ZstdRefusal` stays inside it.

## Browser transport

`GlooStream` adapts a `gloo-net` WebSocket to `AsyncProtocolStream`, and it splits into exclusive halves (`SplittableStream`) so a multiplexed connection reads and writes at once. Each read and write runs the envelope rules of `tightbeam_ws::wire`. `BrowserSocket<P>` is the protocol of a socket the page opened, so it adopts and never dials:

- `Protocol::connect` and `Protocol::bind_cleartext` refuse with `TransportError::InvalidState`.
- `BrowserSocket::<P>::pinned(stream, trust_store, identity)` adopts an opened socket into the transport of a client that pins `trust_store`. It presents `identity` when a server demands mutual authentication. The dialer rule or the key-purpose check refuses the provisioning with a `TransportError`.
- `BrowserSocket::<DefaultCryptoProvider>::trust_store(server_cert_der)` builds one anchor that pins the server certificate, validated under the secp256k1 certificate policy on the host clock. It fails with `TransportError::DerError` for bytes that are no DER certificate, and with `TransportError::InvalidCertificate` when the store refuses the certificate.

Every session is multiplexed: the WebSocket profile of tightbeam negotiates stream multiplexing, so one connection carries concurrent, bidirectional streams. `BrowserMux::split` spawns the reader pump, the writer pump, and the keepalive on the browser executor, and returns the `MuxTasks` set that owns them. The tasks run until the set drops or the connection ends. The drop ends each task at its next poll, which fails every stream still pending on the session.

`JsSigningKeyProvider` adapts a JavaScript signer to the `SigningKeyProvider` of tightbeam, so mutual authentication needs no raw key bytes. The signer is duck-typed: an object with an `algorithmOid` string, a `publicKeyDer` `Uint8Array`, and a `signPrehash` method that resolves with a `Uint8Array`. `JsSigningKeyProvider::new` refuses any other shape.

## Session profiles

The session profile is a compile-time `CryptoProvider` choice, as with a native `tightbeam-rs` transport. It fixes the curve, the AEAD, the digests, and the certificate policy. The shipped `MuxWsClient` binding runs `BrowserSocket<DefaultCryptoProvider>`, the default profile of tightbeam. Frame-level cryptography stays caller-supplied at runtime in the TypeScript layer under any profile.

A deployment on another provider builds its own wasm crate against this one, which links as an `rlib`, and binds the transport layer with its own `#[wasm_bindgen]` items:

1. For mutual authentication, adapt a JavaScript `TransportSigner` with `JsSigningKeyProvider::identity::<P>(signer, cert_der)`. Its signatures MUST verify under `P`.
2. Call `BrowserSocket::<P>::pinned(socket, trust_store, identity)` on an opened `gloo` WebSocket, with the identity of step 1 or `None`. The trust store MUST validate under `P`, as `BrowserSocket::trust_store` does for the default profile.
3. For multiplexed traffic, offer mux with `with_mux_offer`.
4. Run `perform_client_handshake` on the transport.
5. Call `emit` for single-flight traffic, or `BrowserMux::split` for multiplexed traffic. The split runs the pumps and the keepalive under any provider, until the `MuxTasks` set that it returns drops.

## Tests

| Suite                                                                                 | Command                            | Runs                                                                                                                                                                                         |
| ------------------------------------------------------------------------------------- | ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tests/wasm_runtime.rs`                                                               | `wasm-pack test --node`            | The two target-specific hazards of a handshake: the host clock through `OffsetDateTime::now_utc`, and the RNG through an HPKE seal of `build::HpkeSecp256k1Encryptor`                        |
| `tests/gloo_stream.rs`                                                                | `wasm-pack test --node`            | The envelope rules of `wire` against `GlooStream`, over a real `gloo` WebSocket to a peer that the `ws` server of the ws workspace serves                                                    |
| `mod tests` of `src/bindings.rs`, `src/mux.rs`, `src/profile.rs`, and `src/signer.rs` | `wasm-pack test --node`            | The bindings and their parse-once refusals, and the JavaScript signer                                                                                                                        |
| `mod tests` of `src/compress.rs`                                                      | `cargo test`                       | The engine zstd against the zstd of `tightbeam-rs` on the host: bodies that one side compresses inflate on the other, one case for each refusal test of `tightbeam-rs`, and each level bound |
| Playwright, under `ws/tests`                                                          | `make test` at the repository root | The compiled client end to end, against a dockerized `tightbeam-ws` echo server                                                                                                              |

`make -C ws test` runs the `wasm-pack` suites, and the repository root `make test` adds the dockerized end-to-end lanes.

## Sources

- RFC 6455, The WebSocket Protocol, December 2011, § 4.2.2 the server handshake and § 5.2 the frame layout: <https://datatracker.ietf.org/doc/html/rfc6455>
- wasm-pack, the Rust and WebAssembly packaging tool: <https://rustwasm.github.io/docs/wasm-pack/>
- RFC 8878, Zstandard Compression and the `application/zstd` Media Type, February 2021, § 3.1.1 the frame layout and § 3.1.2 skippable frames: <https://datatracker.ietf.org/doc/html/rfc8878>
- CWE-409, Improper Handling of Highly Compressed Data: <https://cwe.mitre.org/data/definitions/409.html>
