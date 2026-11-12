#![doc = include_str!("../README.md")]
#![cfg_attr(not(any(target_arch = "wasm32", feature = "emit")), no_std)]

extern crate alloc;

// Each Rust sample of docs/asn.md compiles as a doctest of this crate.
#[cfg(doctest)]
#[doc = include_str!("../../../docs/asn.md")]
mod docs_asn {}

mod error;
#[cfg(target_arch = "wasm32")]
mod js;
mod leaf;

#[cfg(feature = "emit")]
pub mod emit;

pub use error::FieldError;
pub use tightbeam_asn_derive::AsnCodec;

/// The RustCrypto `der` crate, which encodes and decodes each DER type.
pub use der;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

/// The items that the `#[derive(AsnCodec)]` expansion names in the deriving
/// crate.
#[doc(hidden)]
pub mod __private {
	#[cfg(target_arch = "wasm32")]
	pub use crate::js::{ChoiceEntry, JsField, JsList, JsObject, JsRecord, WireError};
	pub use crate::leaf::{JsLeaf, TsSection};

	/// The supertrait that reserves [`AsnCodec`](crate::AsnCodec) for the
	/// derive, by convention.
	pub trait Sealed {}
}

/// A `der` type with codec exports for TypeScript, which the derive implements:
/// [docs/asn.md][crates].
///
/// [crates]: https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/asn.md#crates
pub trait AsnCodec: __private::Sealed + __private::JsLeaf {
	/// Build `Self` from a plain JavaScript value.
	///
	/// # Errors
	///
	/// - The [`FieldError`] of a `value`, or a field inside it, that does not fit its DER type.
	#[cfg(target_arch = "wasm32")]
	fn from_js(value: &JsValue) -> Result<Self, FieldError> {
		<Self as __private::JsLeaf>::read(value)
	}

	/// Project `Self` into a plain JavaScript value.
	///
	/// # Errors
	///
	/// - The [`FieldError`] of a DER projection or an object write that failed.
	#[cfg(target_arch = "wasm32")]
	fn to_js(&self) -> Result<JsValue, FieldError> {
		<Self as __private::JsLeaf>::project(self)
	}
}
