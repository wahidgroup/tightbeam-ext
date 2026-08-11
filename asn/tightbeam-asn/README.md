# tightbeam-asn

`#[derive(AsnCodec)]` on [`der`](https://crates.io/crates/der) wire types, plus `tightbeam-asn-emit` to generate TypeScript `MessageCodec` modules for [tightbeam](https://crates.io/crates/tightbeam-rs).

## Emit

After `wasm-pack`, scan the wasm `.d.ts` and write `codecs.ts`:

```sh
tightbeam-asn-emit \
	--from-dts path/to/package.d.ts \
	--out path/to/codecs.ts \
	--import '#your-asn-alias' \
	--init-import './asnInit.js'
```

Set `TIGHTBEAM_ASN_EMIT` to a prebuilt binary. Frame types come from `@wahidgroup/tightbeam-ws-client`.

## Field map

| Rust field                                                   | JS / TS                                                           |
| ------------------------------------------------------------ | ----------------------------------------------------------------- |
| `bool`                                                       | `boolean`                                                         |
| `u8`…`u32`, `i8`…`i32`                                       | `number` (range-checked)                                          |
| `u64`, `i64`                                                 | `bigint`                                                          |
| `Null`                                                       | `null`                                                            |
| `String` / path ending `Utf8String`                          | `string`                                                          |
| `Ia5String`, `PrintableString`, `TeletexString`, `BmpString` | `string`                                                          |
| `OctetString`                                                | `Uint8Array`                                                      |
| `BitString`                                                  | `{ unusedBits: number, bytes: Uint8Array }`                       |
| `ObjectIdentifier`                                           | dotted `string`                                                   |
| `Any`                                                        | `Uint8Array` (full DER encoding)                                  |
| `UtcTime`, `GeneralizedTime`                                 | RFC 3339 `string`                                                 |
| nested `AsnCodec`                                            | object / enum / Choice tag                                        |
| `Option<T>`                                                  | omit / nullish for `None` (recursive)                             |
| `Vec<T>`, `SetOfVec<T>`                                      | `Array`                                                           |
| `SequenceOf<T, N>`, `SetOf<T, N>`                            | `Array` of length `N`                                             |

Enums map to numbers. Choices use one externally tagged variant key.

## Out of scope

Borrowed `*Ref` types, context-specific wrappers, `Int` / `Uint`, and product wasm packaging.

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
