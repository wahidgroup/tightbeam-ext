#![doc = include_str!("../README.md")]
#![cfg_attr(not(any(target_arch = "wasm32", feature = "emit")), no_std)]

extern crate alloc;

// This module compiles every Rust example of the page under `docs/` that
// specifies this crate as a doctest, so a renamed item fails the build
// instead of leaving the page stale.
#[cfg(doctest)]
#[doc = include_str!("../../../docs/asn.md")]
mod docs_asn {}

mod error;
#[cfg(target_arch = "wasm32")]
mod js;

#[cfg(feature = "emit")]
pub mod emit;

pub use error::FieldError;
pub use tightbeam_asn_derive::AsnCodec;

/// Re-export of the RustCrypto `der` crate used for wire encode and decode.
pub use der;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

/// Support for the `#[derive(AsnCodec)]` expansion, reserved for the derive.
#[doc(hidden)]
pub mod __private {
	#[cfg(target_arch = "wasm32")]
	pub use crate::js::{JsField, JsList, JsObject, JsProjection, JsRecord, WireError};

	/// Seals [`AsnCodec`](crate::AsnCodec) to the derive.
	pub trait Sealed {}

	/// Fails to compile unless `T` carries the derive.
	pub const fn assert_codec<T: crate::AsnCodec>() {}
}

/// Codec endpoint for a `der` wire type. Implement it with the derive.
///
/// On `wasm32`, implementors provide the JS value conversion that the
/// generated `encode` / `decode` exports use.
pub trait AsnCodec: __private::Sealed + Sized {
	/// Build `Self` from a plain JavaScript value.
	///
	/// # Errors
	///
	/// - [`FieldError`] -- `value`, or a field inside it, does not fit its wire type.
	#[cfg(target_arch = "wasm32")]
	fn from_js(value: &JsValue) -> Result<Self, FieldError>;

	/// Project `Self` into a plain JavaScript value.
	///
	/// # Errors
	///
	/// - [`FieldError`] -- a DER projection or an object write failed.
	#[cfg(target_arch = "wasm32")]
	fn to_js(&self) -> Result<JsValue, FieldError>;
}
