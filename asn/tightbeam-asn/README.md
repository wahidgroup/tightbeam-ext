# tightbeam-asn

`#[derive(AsnCodec)]` on [`der`](https://crates.io/crates/der) wire types, plus `tightbeam-asn-emit` to generate TypeScript `MessageCodec` modules for [tightbeam](https://crates.io/crates/tightbeam-rs).

## Status

This project is under active development. Public APIs MAY change without notice. No security audit has been conducted. Use this software at your own risk.

## Abstract

A Rust wire type that derives `AsnCodec` gains wasm exports that encode and decode it as DER ([ITU-T X.690](https://www.itu.int/rec/T-REC-X.690)) from a plain JavaScript value. `tightbeam-asn-emit` reads the `.d.ts` that `wasm-pack` writes and generates a typed `MessageCodec` for each wire type, so a TypeScript peer of the tightbeam WebSocket client sends the same message schema as a Rust peer.

The quick-start TypeScript sample compiles as the `README quick start compiles against the emitted module` case of [`emit.test.ts`](../tests/emit.test.ts).

## Install

```sh
cargo add tightbeam-asn
cargo install tightbeam-asn --features emit
```

## Quick start

After `wasm-pack`, scan the wasm `.d.ts` and write `codecs.ts`:

```sh
tightbeam-asn-emit \
	--from-dts path/to/package.d.ts \
	--out path/to/codecs.ts \
	--import '#your-asn-alias'
```

Then build the codecs from the wasm module once its init resolves:

```ts
import init, * as asn from "#your-asn-alias";
import { AsnCodecs } from "./codecs.js";

await init();
const codecs = new AsnCodecs(asn);
const bodyDer = codecs.Doc.encode({ title: "hello" });
```

## Derive

The derive covers Sequence structs, Enumerated enums, and Choice enums, and it refuses at compile time each shape in which DER would erase a `None`. Implementation: [docs/asn.md](../../docs/asn.md#derive).

## Field map

Each `der` field type maps to one TypeScript type, and the generated exports check every value against it. Implementation: [docs/asn.md](../../docs/asn.md#field-map).

## Emit

The emitter writes one `AsnCodecs` class with a `MessageCodec` for each wire type, typed so that `tsc` checks each codec. Implementation: [docs/asn.md](../../docs/asn.md#emit).

## Errors

A generated export throws a `TypeError` that names the field by its path, or the error of `der` for bytes that are not DER. Implementation: [docs/asn.md](../../docs/asn.md#errors).

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
