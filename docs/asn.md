# The ASN.1 Codec Bridge

This page specifies the `asn` extension, which bridges `der` wire types of Rust to TypeScript `MessageCodec` modules:

- the three crates and what each one owns
- the `AsnCodec` derive and its expansion on each target
- the field map from Rust to TypeScript
- the shapes the derive refuses
- the rule for the TypeScript type names
- the `tightbeam-asn-emit` binary and the module it writes
- the errors of the generated exports
- the suites that run the bridge

It drills down from the [asn README](../asn/README.md) and the [tightbeam-asn README](../asn/tightbeam-asn/README.md) for engineers who build on the bridge or review it. The README holds what each part is for and the standards it follows. Every Rust sample on this page compiles as a doctest of `tightbeam-asn`.

## Contents

- [Crates](#crates)
- [Derive](#derive)
- [Field map](#field-map)
- [Refused shapes](#refused-shapes)
- [Type names](#type-names)
- [Emit](#emit)
- [Errors](#errors)
- [Tests](#tests)
- [Sources](#sources)

## Crates

| Crate                  | Owns                                                                                                                                                               |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `tightbeam-asn`        | The `AsnCodec` trait, the re-export of the derive and of `der`, `FieldError`, and, under the `emit` feature, the `emit` module and the `tightbeam-asn-emit` binary |
| `tightbeam-asn-derive` | The `#[derive(AsnCodec)]` proc macro. An application depends on `tightbeam-asn`, which re-exports it                                                               |
| `tightbeam-asn-names`  | `TypeName`, the TypeScript type-name rule that the derive and the emitter share                                                                                    |

`AsnCodec` is sealed to the derive. On `wasm32`, an implementor converts a JavaScript value with `from_js` and projects one with `to_js`, and both fail with a `FieldError`. Every other target gets the sealed trait alone, and `tightbeam-asn` builds as `no_std` there unless the `emit` feature is on.

## Derive

`#[derive(AsnCodec)]` implements the JavaScript conversion for three kinds of `der` wire type:

- a Sequence struct
- an Enumerated enum under `#[repr(u8)]`
- a Choice enum

On `wasm32`, the derive also emits the `encode{Name}` and `decode{Name}` exports of `wasm-bindgen`, typed by the TypeScript shape that the same expansion declares. The expansion names both `wasm-bindgen` and `der`, so a crate that derives `AsnCodec` on `wasm32` needs a direct dependency on each.

`#[asn_codec(js_name = "...")]` sets the basename of the wasm exports and the name of the declared type. Without it, the Rust name of the type serves. A field names its nested type by the Rust ident, so a renamed type answers to both names. The expansion declares a type alias from the Rust name to the `js_name`.

```rust
use tightbeam_asn::der::Sequence;
use tightbeam_asn::AsnCodec;

/// A document body, exported to TypeScript as `Doc`.
#[derive(Sequence, AsnCodec)]
#[asn_codec(js_name = "Doc")]
pub struct Document {
	pub title: String,
}

let document = Document { title: String::from("hello") };
assert_eq!(document.title, "hello");
```

## Field map

| Rust field                                                   | TypeScript                                      |
| ------------------------------------------------------------ | ----------------------------------------------- |
| `bool`                                                       | `boolean`                                       |
| `u8` to `u32`, `i8` to `i32`                                 | `number`, range-checked                         |
| `u64`, `i64`                                                 | `bigint`                                        |
| `Null`                                                       | `null`                                          |
| `String`                                                     | `string`                                        |
| `Ia5String`, `PrintableString`, `TeletexString`, `BmpString` | `string`                                        |
| `OctetString`                                                | `Uint8Array`                                    |
| `BitString`                                                  | `{ unusedBits: number, bytes: Uint8Array }`     |
| `ObjectIdentifier`                                           | A dotted `string`                               |
| `Any`                                                        | `Uint8Array`, the full DER encoding             |
| `UtcTime`                                                    | A `YYYY-MM-DDTHH:MM:SSZ` `string`, 1970 to 2049 |
| `GeneralizedTime`                                            | A `YYYY-MM-DDTHH:MM:SSZ` `string`, 1970 to 9999 |
| A nested `AsnCodec`                                          | An object, an enum, or a Choice tag             |
| `Option<T>` on a Sequence field                              | Omitted or nullish for `None`                   |
| `Vec<T>`, `SetOfVec<T>`                                      | `Array`                                         |
| `SequenceOf<T, N>`, `SetOf<T, N>`                            | An `Array` of at most `N` elements              |

An Enumerated enum maps to a number, typed as the union of its discriminants, which MUST be integer literals. A Choice maps to an object with one key, the tag of its variant.

## Refused shapes

`der` encodes `None` as zero bytes, so an absent value leaves no trace inside a collection, inside another `Option`, or inside a Choice. The derive therefore refuses at compile time:

- an `Option` inside a collection, inside another `Option`, or on a Choice variant
- `Option<Null>`, whose `Some(Null)` reads back as `None`
- a wire type with generic parameters
- a union

These `der` types stay out of scope: the borrowed `*Ref` types, the context-specific wrappers, `Int`, and `Uint`. Product wasm packaging is out of scope too.

## Type names

The derive and the emitter admit the same type names, through `tightbeam_asn_names::TypeName`. A `TypeName` is an ASCII TypeScript identifier that is no reserved word. The reserved set holds the reserved words of ECMA-262, the words that strict mode reserves, which a module always is, and the predefined type names of TypeScript.

- The derive refuses a `js_name`, or a Rust type name, that breaks the rule.
- The emitter refuses a codec export of the `.d.ts` whose name breaks it, with `EmitError::UnboundExport`.

## Emit

`tightbeam-asn-emit` scans the `.d.ts` that `wasm-pack` writes and writes the `MessageCodec` module of every `encode{Name}` and `decode{Name}` pair it finds. It requires the `emit` feature.

| Flag                          | Required | Value                                                                                |
| ----------------------------- | -------- | ------------------------------------------------------------------------------------ |
| `--from-dts <file.d.ts>`      | Yes      | The `.d.ts` of the wasm package                                                      |
| `--out <codecs.ts>`           | Yes      | The module to write                                                                  |
| `--import <spec>`             | Yes      | The import specifier of the wasm module, such as a package `imports` alias           |
| `--message-codec-from <spec>` | No       | The package of the `MessageCodec` type, `@wahidgroup/tightbeam-ws-client` by default |

A missing flag or value, or an unknown argument, fails the run. `--help` prints the usage. The emit itself fails with an `EmitError`:

- `Io`: a read or a write of the filesystem failed.
- `NoCodecPairs`: the `.d.ts` holds no `encode{Name}` and `decode{Name}` pair.
- `UnboundExport`: the `.d.ts` exports a codec function whose name holds no TypeScript type name.

The generated module imports the `MessageCodec` type alone from the package of `--message-codec-from`, and the wire types as a namespace of types from `--import`. It re-exports each wire type by name, and its one `AsnCodecs` class holds a `MessageCodec` for each wire type. The `encode{Name}` and `decode{Name}` exports carry the TypeScript shape of their wire type, so `tsc` checks each codec. An application builds `AsnCodecs` from the namespace of the wasm module once the init of that module resolves, so every codec calls an initialized module.

The binary runs the `emit` module, which a build script can call in its place. `CodecPairs` parses the text of a `.d.ts` into its sorted pairs. `EmitOptions::new(import)` reads `MessageCodec` from the default package, and `with_message_codec_from` names another. `EmitOptions::render` returns the module text, and `EmitOptions::emit(from_dts, out)` reads the `.d.ts`, writes the module, and creates the parent directory of `out`.

```rust
# #[cfg(feature = "emit")]
# fn main() -> Result<(), tightbeam_asn::emit::EmitError> {
use tightbeam_asn::emit::{CodecPairs, EmitOptions};

let dts = "export function encodeDoc(value: Doc): Uint8Array;\n\
           export function decodeDoc(bytes: Uint8Array): Doc;\n";
let pairs: CodecPairs = dts.parse()?;

let options = EmitOptions::new("#asn-wasm").with_message_codec_from("./message.js");
let module = pairs.render(&options);
assert!(module.contains("export class AsnCodecs {"));
# Ok(())
# }
# #[cfg(not(feature = "emit"))]
# fn main() {}
```

## Errors

The generated exports throw on failure:

- A value that does not fit its wire type throws a `TypeError` that names the field by its path, such as `records[1].subject: expected a string`. The path is empty when the failure is the value handed to the codec itself.
- Bytes that are not valid DER throw an `Error` from `der`.

The Rust conversion of a value fails with a `FieldError`, which carries the path, the expected shape, and the `der` cause when `der` refused the value.

## Tests

| Suite                        | Command                      | Runs                                                                                                                                                                                                                                                                             |
| ---------------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tests/marker.rs`            | `make test asn`              | The derive implements the marker off `wasm32`, where the expansion needs no `der` derive                                                                                                                                                                                         |
| `tests/fixtures_dx.rs`       | `make test asn`              | The Sequence, Enumerated, and Choice shapes of the fixture wire types                                                                                                                                                                                                            |
| `tests/emit.rs`              | `make test asn`              | The emitter over the fixture `.d.ts`, which exports no codec for an unpaired function                                                                                                                                                                                            |
| `tests/wasm_js_roundtrip.rs` | `make test asn`, on `wasm32` | The expansion of the derive: each fixture type round-trips through a JavaScript value                                                                                                                                                                                            |
| `asn/tests/emit.test.ts`     | `make test asn`              | The emitted module over the real build: the emitter reads the `.d.ts` of the `fixture_package` example, the codecs round-trip `Doc` and `StatusReport` through its exports, and the module compiles under `tsc` against the real `MessageCodec` and the real engine declarations |

`make test asn` builds the ws client and the `fixture_package` example before the TypeScript suite, so the suite reads the declarations and runs the exports that a real build writes.

The [tightbeam-asn README](../asn/tightbeam-asn/README.md) is the crate documentation of `tightbeam-asn`, so `cargo test` compiles its Rust examples, and this page compiles under the same test run.

## Sources

- ITU-T X.690, the ASN.1 encoding rules BER, CER, and DER: <https://www.itu.int/rec/T-REC-X.690>
- ECMA-262, 16th edition, June 2025, § 12.7.2 Keywords and Reserved Words: <https://tc39.es/ecma262/2025/>
- TypeScript 5.9.3, `checkTypeNameIsReserved` in `lib/typescript.js`: <https://github.com/microsoft/TypeScript>
