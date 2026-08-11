# tightbeam-asn

Runtime and derive entry point for DER-backed TypeScript `MessageCodec`
bindings over [tightbeam](https://crates.io/crates/tightbeam-rs) wire types.

Consumers annotate existing `der` Sequence, `#[repr(u8)]` Enumerated, and
Choice types with `#[derive(AsnCodec)]`. With the `wasm` feature on
`wasm32`, the derive emits `encode{Name}` / `decode{Name}` exports that
convert plain JS values through RustCrypto `der` encode and decode, plus
TypeScript shape sections. Consumer MessageCodec façades are written by
the `tightbeam-asn-emit` binary shipped in this published package
(`--features emit`). It scans the wasm `.d.ts` for encode/decode pairs.
Per-type `ASN_CODEC_TS` fragments remain for engine fixtures only.

```sh
cargo run -p tightbeam-asn --features emit --bin tightbeam-asn-emit -- \
	--from-dts path/to/package.d.ts \
	--out path/to/codecs.ts \
	--import '#your-asn-alias' \
	--init-import './asnInit.js'
```

## Supported Sequence fields

AsnCodec covers der-owned Sequence field vocabulary with these JS shapes:

| Rust field                                                   | JS / TS                                                           |
| ------------------------------------------------------------ | ----------------------------------------------------------------- |
| `bool`                                                       | `boolean`                                                         |
| `u8`…`u32`, `i8`…`i32`                                       | `number` (range-checked)                                          |
| `u64`, `i64`                                                 | `bigint` (JS number rejected)                                     |
| `Null`                                                       | `null`                                                            |
| `String` / path ending `Utf8String`                          | `string`                                                          |
| `Ia5String`, `PrintableString`, `TeletexString`, `BmpString` | `string` (validated by der)                                       |
| `OctetString`                                                | `Uint8Array`                                                      |
| `BitString`                                                  | `{ unusedBits: number, bytes: Uint8Array }`                       |
| `ObjectIdentifier`                                           | dotted `string`                                                   |
| `Any`                                                        | `Uint8Array` (full DER encoding of the value)                     |
| `UtcTime`, `GeneralizedTime`                                 | RFC 3339 / ISO-8601 `string`                                      |
| nested `AsnCodec`                                            | object / enum / Choice tag                                        |
| `Option<T>`                                                  | omit key for `None`, accept absent/`null`/`undefined` (recursive) |
| `Vec<T>`, `SetOfVec<T>`                                      | `Array`                                                           |
| `SequenceOf<T, N>`, `SetOf<T, N>`                            | `Array` with length `N`                                           |

Enumerated values are numbers. Choice values use a single externally tagged
variant key. SET OF and SEQUENCE OF share the JS `Array` shape. Wire order
for SET OF is owned by der encode.

## Boundary

Completeness covers der-owned Sequence fields for annotation. Borrowed
`*Ref` types, `ContextSpecific` / `Application` / `Private` as Rust field
wrappers, arbitrary-precision `Int` / `Uint`, foreign CMS/`spki`/`x509-cert`
deriving, and product wasm packaging remain consumer concerns.

Wire codecs use the RustCrypto [`der`](https://crates.io/crates/der)
stack. Fallible work uses [`der::Error`].

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE)
at your option.
