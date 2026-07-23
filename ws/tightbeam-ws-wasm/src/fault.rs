//! Structured JavaScript errors for the wasm bindings.
//! Compiled only for `wasm32` targets.
//!
//! Failures cross the boundary as JavaScript `Error` objects named
//! `TightbeamTransportError` and carrying a machine-readable `code` alongside
//! the human-readable message. Codes are the Rust enum variant names, extracted
//! mechanically from the `Debug` representation, so new upstream variants
//! surface without a hand-maintained mapping.

use core::fmt::{Debug, Display};

use js_sys::{Error as JsError, Reflect};
use wasm_bindgen::JsValue;

use tightbeam::transport::TransportError;

/// The `name` carried by every structured transport error.
pub const TRANSPORT_ERROR_NAME: &str = "TightbeamTransportError";

/// Surface any displayable error to JavaScript as a string `JsValue`.
pub(crate) fn to_js<E: Display>(error: E) -> JsValue {
	JsValue::from_str(&error.to_string())
}

/// Surface a [`TransportError`] as a structured JavaScript error.
///
/// The `code` is the variant name, except operation failures, which
/// collapse to their `TransportFailure` name: the inner failure is the
/// signal callers branch on.
pub(crate) fn transport_to_js(error: TransportError) -> JsValue {
	match &error {
		TransportError::OperationFailed(failure) => coded(&format!("{failure:?}"), &error),
		TransportError::MessageNotSent(_, failure) => coded(&format!("{failure:?}"), &error),
		other => debug_coded(other),
	}
}

/// Surface an error as a structured JavaScript error whose `code` is the
/// variant name of its `Debug` representation.
pub(crate) fn debug_coded<E: Debug + Display>(error: &E) -> JsValue {
	let debug = format!("{error:?}");
	let code = variant_name(&debug);
	coded(code, error)
}

/// Build the structured JavaScript `Error` carrying `code`.
fn coded<E: Display>(code: &str, error: &E) -> JsValue {
	let js_error = JsError::new(&error.to_string());
	js_error.set_name(TRANSPORT_ERROR_NAME);

	// `Reflect::set` on a freshly built `Error` object cannot fail.
	let _ = Reflect::set(&js_error, &JsValue::from_str("code"), &JsValue::from_str(code));
	js_error.into()
}

/// The variant name of a `Debug` representation: everything before the
/// first payload or field delimiter.
fn variant_name(debug: &str) -> &str {
	let end = debug.find(['(', '{', ' ']).unwrap_or(debug.len());
	debug[..end].trim_end()
}
