# tightbeam-asn

`#[derive(AsnCodec)]` on [`der`](https://crates.io/crates/der) DER types, plus `tightbeam-asn-emit` to generate TypeScript `MessageCodec` modules for [tightbeam](https://crates.io/crates/tightbeam-rs).

## Status

This project is under active development. Public APIs MAY change without notice. No security audit has been conducted. Use this software at your own risk.

## Abstract

A Rust DER type that derives `AsnCodec` gains wasm exports that encode and decode it as DER ([ITU-T X.690](https://www.itu.int/rec/T-REC-X.690)) from a plain JavaScript value. `tightbeam-asn-emit` reads the `.d.ts` that `wasm-pack` writes and generates a typed `MessageCodec` for each DER type, so a TypeScript peer of the tightbeam WebSocket client sends the same message schema as a Rust peer.

[docs/asn.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/asn.md#tests) names the suite that compiles the quick-start TypeScript sample.

## Install

```sh
cargo add tightbeam-asn
cargo install tightbeam-asn --features emit
```

## Quick start

After `wasm-pack build --target web`, scan the wasm `.d.ts` and write `codecs.ts`:

```sh
tightbeam-asn-emit \
	--from-dts path/to/package.d.ts \
	--out path/to/codecs.ts \
	--import '#your-asn-alias'
```

Then build the codecs from the wasm module and the output of its init:

```ts
import init, * as asn from "#your-asn-alias";
import { AsnCodecs } from "./codecs.js";

const codecs = new AsnCodecs(asn, await init());
const bodyDer = codecs.Doc.encode({ title: "hello" });
```

A `--target nodejs` build initializes on import, so its `AsnCodecs` takes the exports alone: `new AsnCodecs(asn)`.

## Derive

The derive covers Sequence structs, Enumerated enums, and Choice enums, and it refuses at compile time each shape in which DER would erase a `None`. Implementation: [docs/asn.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/asn.md#derive).

## Field map

Each `der` field type maps to one TypeScript type, and the generated exports check every value against it. Implementation: [docs/asn.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/asn.md#field-map).

## Emit

The emitter writes one `AsnCodecs` class with a `MessageCodec` for each DER type, typed so that `tsc` checks each codec. Implementation: [docs/asn.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/asn.md#emit).

## Errors

A generated export throws a `TypeError` that names the field by its path, or the error of `der` for bytes that are not DER. Implementation: [docs/asn.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/asn.md#errors).

## License

Licensed under either of [MIT](https://github.com/wahidgroup/tightbeam-ext/blob/master/asn/tightbeam-asn/LICENSE-MIT) or [Apache-2.0](https://github.com/wahidgroup/tightbeam-ext/blob/master/asn/tightbeam-asn/LICENSE-APACHE) at your option.
