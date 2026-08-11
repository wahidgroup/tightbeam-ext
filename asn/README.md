# asn

DER-backed ASN.1 codec bridge for TypeScript `MessageCodec` façades over
[tightbeam](https://crates.io/crates/tightbeam-rs) wire types.

## Contents

- **[tightbeam-asn](tightbeam-asn)** - published package: `AsnCodec` trait, JS
  helpers, derive entry, and the `tightbeam-asn-emit` binary that writes
  consumer MessageCodec TypeScript modules
- **[tightbeam-asn-derive](tightbeam-asn-derive)** - `#[derive(AsnCodec)]`

Annotate existing `der` `Sequence`, `#[repr(u8)]` `Enumerated`, and `Choice`
types with `#[derive(AsnCodec)]`. On `wasm32` with the `wasm` feature, the
derive emits `encode{Name}` / `decode{Name}` exports and TypeScript shape
sections. After `wasm-pack`, run the emit binary from the same published
package to generate consumer `codecs.ts` façades (`asCodec`, type aliases,
optional `encodeAsn` / `decodeAsn`).

## Supported Sequence fields

| Rust field                                                   | JS / TS                             |
| ------------------------------------------------------------ | ----------------------------------- |
| `bool`                                                       | `boolean`                           |
| `u8`…`u32`, `i8`…`i32`                                       | `number` (range-checked)            |
| `u64`, `i64`                                                 | `bigint`                            |
| `Null`                                                       | `null`                              |
| `String` / `Utf8String`                                      | `string`                            |
| `Ia5String`, `PrintableString`, `TeletexString`, `BmpString` | `string`                            |
| `OctetString`                                                | `Uint8Array`                        |
| `BitString`                                                  | `{ unusedBits, bytes }`             |
| `ObjectIdentifier`                                           | dotted `string`                     |
| `Any`                                                        | opaque DER `Uint8Array`             |
| `UtcTime`, `GeneralizedTime`                                 | RFC 3339 `string`                   |
| nested `AsnCodec`                                            | object / enum / Choice tag          |
| `Option<T>`                                                  | omit / nullish ↔ `None` (recursive) |
| `Vec<T>`, `SetOfVec<T>`                                      | `Array`                             |
| `SequenceOf<T, N>`, `SetOf<T, N>`                            | `Array` of length `N`               |

Enumerated values are numbers. Choice values are externally tagged
`{ VariantName: payload }`. Completeness covers der-owned Sequence fields.
Borrowed refs, context-specific field wrappers, `Int`/`Uint`, and product
wasm packaging stay with consumers.

Product schemas and private wasm link crates live in consumer repos. Consumers
invoke emit after wasm-pack through the same Cargo dependency they already use
for `tightbeam-asn` (path or crates.io). Example from a consumer workspace that
depends on this package:

```sh
cargo run -p tightbeam-asn --features emit --bin tightbeam-asn-emit -- \
	--from-dts apps/portal/src/lib/asn/wasm/apollyon_asn.d.ts \
	--out apps/portal/src/lib/codecs.ts \
	--import '#apollyon-asn' \
	--init-import './asnInit.js'
```

When `tightbeam-asn` is only a path/registry dependency (not a workspace
member), resolve its manifest from that dependency graph and pass
`--manifest-path`, or install the binary:

```sh
cargo install tightbeam-asn --features emit --bin tightbeam-asn-emit
```

Override with `TIGHTBEAM_ASN_EMIT` when a prebuilt path is preferred. Frame
typing uses `@wahidgroup/tightbeam-ws-client` `MessageCodec`.

## Development

```sh
make setup asn
make test asn
make lint asn
cargo test -p tightbeam-asn --features emit
```

## License

Licensed under either of [MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE)
at your option.
