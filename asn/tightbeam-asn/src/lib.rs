//! DER-backed ASN.1 codec bridge for TypeScript `MessageCodec` façades.
//!
//! Annotate wire types with [`AsnCodec`]. On `wasm32` with the `wasm`
//! feature, the derive emits `encode{Name}` / `decode{Name}` exports that
//! convert plain JS values through RustCrypto `der` encode and decode.
//!
//! Consumer MessageCodec façades come from the `tightbeam-asn-emit` binary
//! shipped with the `emit` feature. Set `TIGHTBEAM_ASN_EMIT` to a prebuilt
//! path when preferred. Per-type `ASN_CODEC_TS` fragments remain for engine
//! fixtures only. Fallible work uses [`der::Error`].
//!
//! # Coverage
//!
//! AsnCodec maps der-owned Sequence field types to stable JS shapes:
//!
//! | Rust field | JS / TS |
//! |------------|---------|
//! | `bool` | `boolean` |
//! | `u8`…`u32`, `i8`…`i32` | `number` (range-checked) |
//! | `u64`, `i64` | `bigint` |
//! | `Null` | `null` |
//! | `String` / `Utf8String` | `string` |
//! | `Ia5String`, `PrintableString`, `TeletexString`, `BmpString` | `string` (der-validated) |
//! | `OctetString` | `Uint8Array` |
//! | `BitString` | `{ unusedBits, bytes }` |
//! | `ObjectIdentifier` | dotted `string` |
//! | `Any` | `Uint8Array` (full DER encoding) |
//! | `UtcTime`, `GeneralizedTime` | RFC 3339 `string` |
//! | nested `AsnCodec` | object / enum / Choice tag |
//! | `Option<T>` | omit / nullish ↔ `None` (recursive) |
//! | `Vec<T>`, `SetOfVec<T>` | `Array` |
//! | `SequenceOf<T, N>`, `SetOf<T, N>` | `Array` of length `N` |
//!
//! Enumerated `#[repr(u8)]` values are JS numbers. Choice enums use
//! externally tagged `{ VariantName: payload }` objects.
//!
//! Completeness means covering the der-owned Sequence field vocabulary.
//! Borrowed `*Ref` types, `ContextSpecific` / `Application` / `Private`
//! field wrappers, and arbitrary-precision `Int` / `Uint` stay outside
//! this mapping. Wire tags remain on `der` derives.
//!
//! # Sources
//!
//! - [X.690](https://www.itu.int/rec/T-REC-X.690) BER/CER/DER
//! - RustCrypto [`der`](https://docs.rs/der) crate

#![cfg_attr(not(any(feature = "wasm", feature = "emit")), no_std)]

extern crate alloc;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub mod js;

#[cfg(feature = "emit")]
pub mod emit;

pub use der::{Error, Result};
pub use tightbeam_asn_derive::AsnCodec;

/// Re-export of the RustCrypto `der` crate used for wire encode and decode.
pub use der;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
use wasm_bindgen::JsValue;

/// Codec endpoint for a `der` wire type.
///
/// On `wasm32` with the `wasm` feature, implementors provide JS value
/// conversion used by the generated `encode` / `decode` exports.
pub trait AsnCodec: Sized {
	/// Build `Self` from a plain JavaScript value.
	#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
	fn from_js(value: &JsValue) -> Result<Self>;

	/// Project `Self` into a plain JavaScript value.
	#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
	fn to_js(&self) -> Result<JsValue>;
}
