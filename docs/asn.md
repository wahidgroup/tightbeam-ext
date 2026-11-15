# The ASN.1 Codec Bridge

This page specifies the `asn` extension, which bridges `der` types of Rust to TypeScript `MessageCodec` modules. It covers:

- the three crates and what each one owns
- the `AsnCodec` derive and its expansion on each target
- the field map from Rust to TypeScript
- the shapes the derive refuses
- the rule for the TypeScript type names
- the `tightbeam-asn-emit` binary and the module it writes
- the errors of the generated exports
- the suites that run the bridge

It drills down from the [asn README](../asn/README.md) and the [tightbeam-asn README](../asn/tightbeam-asn/README.md), for engineers who build on the bridge or review it. The README holds what each part is for and the standards it follows.

Every Rust sample on this page compiles as a doctest of `tightbeam-asn`.

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

| Crate                         | Owns                                                                                                                       |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `tightbeam-asn`               | The `AsnCodec` trait, the `JsLeaf` contract of each `der` leaf, `FieldError`, and the re-export of the derive and of `der` |
| `tightbeam-asn`, under `emit` | The `emit` module and the `tightbeam-asn-emit` binary                                                                      |
| `tightbeam-asn-derive`        | The `#[derive(AsnCodec)]` proc macro. An application depends on `tightbeam-asn`, which re-exports it                       |
| `tightbeam-asn-names`         | `TypeName`, the TypeScript type-name rule, and `Export`, the names of the codec exports                                    |

The derive and the emitter share `tightbeam-asn-names`.

### The `AsnCodec` trait

- The derive is the only intended implementor of `AsnCodec`, by convention.
- The derive expands in the crate that derives, so that crate can name the `__private::Sealed` and `__private::JsLeaf` supertraits.
- A hand-written `impl` of all three traits therefore compiles.
- The derive writes the JavaScript conversion of a type once, in its `JsLeaf` implementation.

| Target             | `AsnCodec` provides                                                                                                                  |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| `wasm32`           | `from_js`, which converts a JavaScript value through that conversion, and `to_js`, which projects one. Both fail with a `FieldError` |
| Every other target | The trait without methods. `tightbeam-asn` builds as `no_std` there, unless the `emit` feature is on                                 |

## Derive

`#[derive(AsnCodec)]` implements the JavaScript conversion for three kinds of `der` type:

- a Sequence struct
- an Enumerated enum under `#[repr(u8)]`
- a Choice enum

### Expansion

| Target       | The expansion                                                                                                                  |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| Every target | Implements `JsLeaf` for the type, and declares the TypeScript shape of the type from the `JsLeaf` constants of its field types |
| `wasm32`     | Also emits the `encode{Name}` and `decode{Name}` exports of `wasm-bindgen`, typed by that TypeScript shape                     |

- A field of a type that implements no `JsLeaf` fails the build at that field.
- A Sequence field carries each non-empty line of its doc into the JSDoc of its property.
- Each `*/` in that doc is written as `*\/`.
- The `wasm32` expansion names both `wasm-bindgen` and `der`, so a crate that derives `AsnCodec` on `wasm32` needs a direct dependency on each.

### `js_name`

- `#[asn_codec(js_name = "...")]` sets the basename of the wasm exports and the name of the declared type.
- Without it, the Rust name of the type serves.
- A field declares a nested type by the `js_name` of that type.
- The derive reads every `asn_codec` attribute of the type. It refuses:
  - a key other than `js_name`
  - a second `js_name`
  - an `asn_codec` attribute on a field or a variant

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

- Each leaf type of `der` maps to one TypeScript type.
- Its `JsLeaf` implementation in `tightbeam-asn` converts it.
- Its constants hold its TypeScript type, and the JSDoc of a field without a doc of its own.
- One macro of `tightbeam-asn` writes the `JsLeaf` implementation of each leaf and the list of the leaves.
- A unit test of `tightbeam-asn` fails when this table and that list differ by a row.

| Rust leaf          | TypeScript                                  | JSDoc of an undocumented field                                                                |
| ------------------ | ------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `bool`             | `boolean`                                   | Carries a BOOLEAN Sequence field as a JavaScript boolean.                                     |
| `u8`               | `number`                                    | Carries an INTEGER field in the inclusive u8 range.                                           |
| `u16`              | `number`                                    | Carries an INTEGER field in the inclusive u16 range.                                          |
| `u32`              | `number`                                    | Carries an INTEGER field in the inclusive u32 range.                                          |
| `i8`               | `number`                                    | Carries an INTEGER field in the inclusive i8 range.                                           |
| `i16`              | `number`                                    | Carries an INTEGER field in the inclusive i16 range.                                          |
| `i32`              | `number`                                    | Carries an INTEGER field in the inclusive i32 range.                                          |
| `u64`              | `bigint`                                    | Carries an INTEGER field as a JavaScript bigint in the inclusive u64 range.                   |
| `i64`              | `bigint`                                    | Carries an INTEGER field as a JavaScript bigint in the inclusive i64 range.                   |
| `Null`             | `null`                                      | Carries a NULL Sequence field as JavaScript null.                                             |
| `String`           | `string`                                    | Carries a UTF-8 string Sequence field.                                                        |
| `Ia5String`        | `string`                                    | Carries an IA5String Sequence field validated by der.                                         |
| `PrintableString`  | `string`                                    | Carries a PrintableString Sequence field validated by der.                                    |
| `TeletexString`    | `string`                                    | Carries a TeletexString Sequence field validated by der.                                      |
| `BmpString`        | `string`                                    | Carries a BmpString Sequence field validated by der.                                          |
| `OctetString`      | `Uint8Array`                                | Carries an octet string Sequence field as Uint8Array.                                         |
| `BitString`        | `{ unusedBits: number; bytes: Uint8Array }` | Carries a BIT STRING Sequence field as unusedBits plus bytes.                                 |
| `ObjectIdentifier` | `string`                                    | Carries an OBJECT IDENTIFIER Sequence field as a dotted string.                               |
| `Any`              | `Uint8Array`                                | Carries an ANY Sequence field as opaque DER bytes.                                            |
| `UtcTime`          | `string`                                    | Carries a UTCTime Sequence field as a YYYY-MM-DDTHH:MM:SSZ string, from 1970 to 2049.         |
| `GeneralizedTime`  | `string`                                    | Carries a GeneralizedTime Sequence field as a YYYY-MM-DDTHH:MM:SSZ string, from 1970 to 9999. |

A field of any other type takes one of these shapes:

| Rust field                        | TypeScript                          |
| --------------------------------- | ----------------------------------- |
| A nested `AsnCodec`               | An object, an enum, or a Choice tag |
| `Option<T>` on a Sequence field   | Omitted or nullish for `None`       |
| `Vec<T>`, `SetOfVec<T>`           | `Array`                             |
| `SequenceOf<T, N>`, `SetOf<T, N>` | An `Array` of at most `N` elements  |

- An Enumerated enum maps to a number, typed as the union of its discriminants.
- A Choice maps to an object with one key, the tag of its variant.

## Refused shapes

`der` encodes `None` as zero bytes, so an absent value leaves no trace inside a collection, inside another `Option`, or inside a Choice.

### Refused by the derive, at compile time

| Of            | The derive refuses                                                                                                                        |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| A field type  | An `Option` inside a collection, inside another `Option`, or on a Choice variant                                                          |
| A field type  | A type that is no plain path, such as a tuple or `<T as Trait>::Assoc`                                                                    |
| A field type  | Generic arguments in a form other than `Option<T>`, `Vec<T>`, `SetOfVec<T>`, `SequenceOf<T, N>` and `SetOf<T, N>`, such as `Box<T>`       |
| A DER type    | Generic parameters                                                                                                                        |
| A DER type    | A union                                                                                                                                   |
| A struct      | No named fields, such as a tuple struct or a unit struct                                                                                  |
| An enum       | No variant                                                                                                                                |
| An enum       | Unit variants mixed with other variants                                                                                                   |
| A Choice      | A variant other than one unnamed field, such as `List(Body, Pad)` or `List { body: Body }`                                                |
| An Enumerated | No `#[repr(u8)]`                                                                                                                          |
| An Enumerated | A discriminant that is no integer literal, or that falls past `u8`                                                                        |
| A name        | A Sequence field or a Choice variant named `__proto__`, because a JavaScript object reads that key as its prototype and not as an own key |

### Refused by the build of the deriving crate

The build refuses the shapes that only the `JsLeaf` constants show:

- `Option<T>` of a `T` whose `JsLeaf::READS_AS_ABSENT` holds, such as `Option<Null>`, whose `Some(Null)` reads back as `None`
- a field of a type that implements no `JsLeaf`
- a Sequence field of a type `T` with no doc of its own, when the `JsLeaf::CONTRACT` of `T` holds `*/`, which would end the JSDoc of the field

### Samples that fail the build

`Option<Null>` fails the build:

```rust,compile_fail
use tightbeam_asn::der::asn1::Null;
use tightbeam_asn::der::Sequence;
use tightbeam_asn::AsnCodec;

#[derive(Sequence, AsnCodec)]
pub struct Gap {
	pub gap: Option<Null>,
}
```

A field of a type that implements no `JsLeaf` fails the build at that field:

```rust,compile_fail
use tightbeam_asn::der::Sequence;
use tightbeam_asn::AsnCodec;

#[derive(Sequence)]
pub struct Plain {
	pub title: String,
}

#[derive(Sequence, AsnCodec)]
pub struct Outer {
	pub plain: Plain,
}
```

A `JsLeaf::CONTRACT` that holds `*/` fails the build of a Sequence that holds an undocumented field of that type:

```rust,compile_fail
use tightbeam_asn::__private::JsLeaf;
use tightbeam_asn::der::Sequence;
use tightbeam_asn::AsnCodec;

#[derive(Sequence)]
pub struct Glob {
	pub pattern: String,
}

impl JsLeaf for Glob {
	const TS_TYPE: &'static str = "{ pattern: string }";
	const CONTRACT: &'static str = "Carries a glob such as docs*/README.md.";
}

#[derive(Sequence, AsnCodec)]
pub struct Search {
	pub glob: Glob,
}
```

A Sequence field named `__proto__` fails the build:

```rust,compile_fail
use tightbeam_asn::der::Sequence;
use tightbeam_asn::AsnCodec;

#[derive(Sequence, AsnCodec)]
pub struct Doc {
	pub __proto__: String,
}
```

### Out of scope

- These `der` types: the borrowed `*Ref` types, the context-specific wrappers, `Int`, and `Uint`.
- Product wasm packaging.

## Type names

The derive and the emitter admit the same type names, through `tightbeam_asn_names::TypeName`. A `TypeName` is an ASCII TypeScript identifier that is no reserved word.

### The reserved set

| Source      | Reserves                                                      |
| ----------- | ------------------------------------------------------------- |
| ECMA-262    | Its reserved words                                            |
| Strict mode | The words that strict mode reserves, which a module always is |
| TypeScript  | Its predefined type names                                     |
| TypeScript  | Its type operators, such as `readonly`                        |

A `TypeName` is also not:

- a name that the emitted module, or the `.d.ts` that it reads, declares or uses unqualified, such as `Pick`, `MessageCodec`, `InitOutput`, `Uint8Array`, or `constructor`
- `as`, which the `export type` line of the module cannot declare

### How each side applies the rule

- The derive refuses a `js_name` that breaks the rule.
- Without a `js_name`, the derive refuses a Rust type name that breaks it.
- The emitter binds an export of the `.d.ts` when its line is the declaration of an export of the derive, and its name after `encode` or `decode` keeps the rule.
- The emitter skips any other export, such as `decode64`, or an `encodeBase64(text: string): string` that is no codec.

### `Export`

- `tightbeam_asn_names::Export` names the `encode{Name}` and `decode{Name}` exports of a codec.
- `Export::declaration` writes the line that a `.d.ts` declares each one with: `encode{Name}(value: {Name}): Uint8Array` and `decode{Name}(bytes: Uint8Array): {Name}`.
- The derive names each export and its parameter through `Export::name` and `Export::parameter`.
- The emitter reads each declaration back through `Export::parse`, as a `CodecExport` of the export and its type name.

A type named `Pick`, which the emitted module uses, fails the build:

```rust,compile_fail
use tightbeam_asn::der::Sequence;
use tightbeam_asn::AsnCodec;

#[derive(Sequence, AsnCodec)]
pub struct Pick {
	pub title: String,
}
```

## Emit

- `tightbeam-asn-emit` scans the `.d.ts` that `wasm-pack` writes.
- It writes the `MessageCodec` module of every `encode{Name}` and `decode{Name}` pair it finds.
- It requires the `emit` feature.

### Flags

| Flag                          | Required | Value                                                                                |
| ----------------------------- | -------- | ------------------------------------------------------------------------------------ |
| `--from-dts <file.d.ts>`      | Yes      | The `.d.ts` of the wasm package                                                      |
| `--out <codecs.ts>`           | Yes      | The module to write                                                                  |
| `--import <spec>`             | Yes      | The import specifier of the wasm module, such as a package `imports` alias           |
| `--message-codec-from <spec>` | No       | The package of the `MessageCodec` type, `@wahidgroup/tightbeam-ws-client` by default |

- A missing flag or value, or an unknown argument, fails the run.
- `--help` prints the usage.

### Emit errors

The emit itself fails with an `EmitError`:

| Variant        | The emit failed because                                     |
| -------------- | ----------------------------------------------------------- |
| `Io`           | A read or a write of the filesystem failed                  |
| `NoCodecPairs` | The `.d.ts` holds no `encode{Name}` and `decode{Name}` pair |

### The generated module

- It imports the `MessageCodec` type alone, from the package of `--message-codec-from`.
- It imports the DER types as a namespace of types, from `--import`.
- It re-exports each DER type by name.
- Its one `AsnCodecs` class holds a `MessageCodec` for each DER type.
- Each specifier renders as a TypeScript string literal, with its quotes, backslashes, and line terminators escaped.
- The `encode{Name}` and `decode{Name}` exports carry the TypeScript shape of their DER type, so `tsc` checks each codec.

### The `AsnCodecs` constructor

The constructor takes the codec exports of the wasm module. `CodecPairs` reads from the `.d.ts` how the module initializes, and the constructor follows it:

| Build             | Initializes                                                         | The constructor takes                                                            |
| ----------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `--target web`    | Through `init` and `initSync`, the only returns of its `InitOutput` | The exports and that `InitOutput`, so `tsc` refuses codecs built before the init |
| `--target nodejs` | On import, and declares no `InitOutput`                             | The exports alone                                                                |

### The `emit` module

The binary runs the `emit` module, which a build script can call in its place.

| Item                                   | Does                                                                                              |
| -------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `CodecPairs`                           | Parses the text of a `.d.ts` into its sorted pairs, each a `TypeName`, and the init of its module |
| `CodecPairs::read(from_dts)`           | Reads the pairs of a `.d.ts` file                                                                 |
| `EmitOptions::new(import)`             | Reads `MessageCodec` from the default package                                                     |
| `EmitOptions::with_message_codec_from` | Names another package                                                                             |
| `CodecPairs::render(&options)`         | Returns the module text                                                                           |
| `pairs.write(&options, out)`           | Writes the module text, and creates the parent directory of `out`                                 |

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

| Failure                                | Throws                                                                                          |
| -------------------------------------- | ----------------------------------------------------------------------------------------------- |
| A value that does not fit its DER type | A `TypeError` that names the field by its path, such as `records[1].subject: expected a string` |
| Bytes that are not valid DER           | An `Error` from `der`                                                                           |

- The path is empty when the failure is the value handed to the codec itself.
- The Rust conversion of a value fails with a `FieldError`.
- A `FieldError` carries the path, the expected shape, and the `der` cause when `der` refused the value.

## Tests

| Suite                        | Command                      | Runs                                                                                  |
| ---------------------------- | ---------------------------- | ------------------------------------------------------------------------------------- |
| `tests/fixtures_dx.rs`       | `make test asn`              | The DER oracle                                                                        |
| `tests/emit.rs`              | `make test asn`              | The emitter over the fixture `.d.ts`                                                  |
| `tests/wasm_js_roundtrip.rs` | `make test asn`, on `wasm32` | The expansion of the derive: each fixture type round-trips through a JavaScript value |
| `asn/tests/emit.test.ts`     | `make test asn`              | The emitted modules over the real build                                               |

### The DER oracle

- The fixture DER types round-trip through DER under their `der` derives alone.
- A failed JS round trip therefore points at the expansion and not at a fixture.

### The emitter suite

`tests/emit.rs` checks that the emitter binds no codec for:

- an unpaired function
- an export that names no type
- a pair of another signature
- a pair of a name that the emitted module uses

### The TypeScript suite

- `tsc` checks `asn/tests/emit.test.ts` against the module of the web binding and of the nodejs binding of the `fixture_package` example.
- It also checks the suite against their `.d.ts`, and the published declarations of the ws client.
- The web codecs round-trip each fixture shape through the exports.
- The nodejs codecs round-trip a `Doc`.
- The suite compiles the TypeScript quick start of the [tightbeam-asn README](../asn/tightbeam-asn/README.md), which it reads from the README.

### `make test asn`

1. It builds the ws client.
2. It binds the `fixture_package` example for the web into `asn/tests/fixture/`, and for Node into `asn/tests/fixture/node/`.
3. It emits the module of the web binding to `asn/tests/codecs.ts`, and the module of the nodejs binding beside that binding.
4. It type-checks the TypeScript suite, then runs it.

The suite therefore reads the declarations and runs the exports that a real build writes.

### `cargo test`

- `cargo test` compiles each Rust example of this page as a doctest of `tightbeam-asn`.
- Each `compile_fail` sample passes only when its build fails.

## Sources

- ITU-T X.690, the ASN.1 encoding rules BER, CER, and DER: <https://www.itu.int/rec/T-REC-X.690>
- ECMA-262, 16th edition, June 2025, § 12.7.2 Keywords and Reserved Words: <https://tc39.es/ecma262/2025/>
- TypeScript 5.9.3, `checkTypeNameIsReserved` in `lib/typescript.js`: <https://github.com/microsoft/TypeScript>
