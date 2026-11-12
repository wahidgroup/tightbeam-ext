//! The JavaScript objects and arrays that the `AsnCodec` expansion reads and
//! writes.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ops::RangeInclusive;
use core::str::FromStr;

use der::DateTime;
use js_sys::{Array, Object, Reflect, TypeError, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};

use crate::FieldError;

/// A JavaScript value that the `AsnCodec` expansion reads an object, a
/// Choice entry, or an array from.
#[derive(Clone, Copy)]
pub struct JsField<'a>(&'a JsValue);

impl<'a> From<&'a JsValue> for JsField<'a> {
	fn from(value: &'a JsValue) -> Self {
		Self(value)
	}
}

impl<'a> JsField<'a> {
	/// Interpret a JavaScript value as an object, whatever its prototype.
	///
	/// # Errors
	///
	/// - The [`FieldError`] of a value that is no object.
	pub fn object(self) -> Result<JsObject<'a>, FieldError> {
		if self.0.is_object() {
			return Ok(JsObject(self.0.unchecked_ref()));
		}

		Err(FieldError::new("an object"))
	}

	/// The entry of an externally tagged Choice object.
	///
	/// # Errors
	///
	/// - The [`FieldError`] of a value that is no object with one own key.
	/// - The [`FieldError`] of an entry whose read throws.
	pub fn single_entry(self) -> Result<ChoiceEntry, FieldError> {
		const EXPECTED: &str = "an object with one variant key";

		let object = self.object().map_err(|_| FieldError::new(EXPECTED))?;
		let keys = Object::keys(object.0);
		if keys.length() != 1 {
			return Err(FieldError::new(EXPECTED));
		}

		let variant = keys.get(0).as_string().ok_or_else(|| FieldError::new(EXPECTED))?;
		let value = object.get(&variant)?;
		Ok(ChoiceEntry { variant, value })
	}

	/// Interpret a JavaScript value as an `Array`.
	///
	/// # Errors
	///
	/// - The [`FieldError`] of a value that is no `Array`.
	pub fn array(self) -> Result<Array, FieldError> {
		self.0.dyn_ref::<Array>().cloned().ok_or_else(|| FieldError::new("an Array"))
	}

	pub(crate) fn string(self) -> Result<String, FieldError> {
		self.0.as_string().ok_or_else(|| FieldError::new("a string"))
	}

	pub(crate) fn octets(self) -> Result<Vec<u8>, FieldError> {
		let array = self.0.dyn_ref::<Uint8Array>().ok_or_else(|| FieldError::new("a Uint8Array"))?;
		Ok(array.to_vec())
	}

	pub(crate) fn date_time(self, expected: &'static str) -> Result<DateTime, FieldError> {
		let text = self.string().map_err(|_| FieldError::new(expected))?;
		DateTime::from_str(&text).map_err(|cause| FieldError::refused(expected, cause))
	}

	pub(crate) fn integer(self, range: RangeInclusive<f64>, expected: &'static str) -> Result<f64, FieldError> {
		let number = self.0.as_f64().ok_or_else(|| FieldError::new(expected))?;
		if !number.is_finite() || number.fract() != 0.0 || !range.contains(&number) {
			return Err(FieldError::new(expected));
		}

		Ok(number)
	}
}

/// The one own key of an externally tagged Choice object, and the value under
/// it.
pub struct ChoiceEntry {
	/// The key, which names the variant.
	pub variant: String,
	/// The value of the variant.
	pub value: JsValue,
}

/// An object that the expansion reads its fields from.
#[derive(Clone, Copy)]
pub struct JsObject<'a>(&'a Object);

impl JsObject<'_> {
	/// Read the own property `key`. A key outside the own keys of the object
	/// reads as `undefined`, which every conversion refuses except an absent
	/// OPTIONAL.
	///
	/// # Errors
	///
	/// - The [`FieldError`] of an own property whose read throws.
	pub fn get(self, key: &str) -> Result<JsValue, FieldError> {
		let key_value = JsValue::from_str(key);
		if !Object::has_own(self.0, &key_value) {
			return Ok(JsValue::UNDEFINED);
		}

		Reflect::get(self.0, &key_value).map_err(|_| FieldError::new("a readable object").within(key))
	}
}

/// A plain object that the expansion writes its fields onto.
pub struct JsRecord(JsValue);

impl Default for JsRecord {
	/// An empty plain object.
	fn default() -> Self {
		Self(JsValue::from(Object::new()))
	}
}

impl JsRecord {
	/// Write `value` to the property `key`.
	///
	/// # Errors
	///
	/// - The [`FieldError`] of a write that throws.
	pub fn set(&self, key: &str, value: &JsValue) -> Result<(), FieldError> {
		let written = Reflect::set(&self.0, &JsValue::from_str(key), value);
		written.map(|_| ()).map_err(|_| FieldError::new("a writable object"))
	}
}

impl From<JsRecord> for JsValue {
	fn from(record: JsRecord) -> Self {
		record.0
	}
}

/// An `Array` that the expansion pushes the items of a collection onto.
pub struct JsList(Array);

impl Default for JsList {
	/// An empty `Array`.
	fn default() -> Self {
		Self(Array::new())
	}
}

impl JsList {
	/// Append `item` after the items pushed before it, so the `Array` keeps the
	/// order of the collection.
	pub fn push(&self, item: &JsValue) {
		self.0.push(item);
	}
}

impl From<JsList> for JsValue {
	fn from(list: JsList) -> Self {
		JsValue::from(list.0)
	}
}

impl From<FieldError> for JsValue {
	/// A shape failure as a JavaScript `TypeError`.
	fn from(error: FieldError) -> Self {
		TypeError::new(&error.to_string()).into()
	}
}

/// A DER failure, as the JavaScript `Error` the expansion throws.
pub struct WireError(pub der::Error);

impl From<WireError> for JsValue {
	fn from(error: WireError) -> Self {
		js_sys::Error::new(&error.0.to_string()).into()
	}
}
