//! JavaScript value conversions behind the `AsnCodec` expansion.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str::FromStr;

use der::asn1::{
	Any, BitString, BmpString, GeneralizedTime, Ia5String, Null, ObjectIdentifier, OctetString, PrintableString,
	TeletexString, UtcTime,
};
use der::{DateTime, Decode, Encode};
use js_sys::{Array, BigInt, Object, Reflect, TypeError, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};

use crate::FieldError;

/// A JavaScript value that the `AsnCodec` expansion reads one field from.
#[derive(Clone, Copy)]
pub struct JsField<'a>(&'a JsValue);

impl<'a> From<&'a JsValue> for JsField<'a> {
	fn from(value: &'a JsValue) -> Self {
		Self(value)
	}
}

impl<'a> JsField<'a> {
	/// Interpret a JavaScript value as an object, whatever its prototype.
	pub fn object(self) -> Result<JsObject<'a>, FieldError> {
		if self.0.is_object() {
			return Ok(JsObject(self.0.unchecked_ref()));
		}

		Err(FieldError::new("an object"))
	}

	/// The single own key and value of an externally tagged Choice object.
	pub fn single_entry(self) -> Result<(String, JsValue), FieldError> {
		const EXPECTED: &str = "an object with one variant key";

		let object = self.object().map_err(|_| FieldError::new(EXPECTED))?;
		let keys = Object::keys(object.0);
		if keys.length() != 1 {
			return Err(FieldError::new(EXPECTED));
		}

		let key = keys.get(0).as_string().ok_or_else(|| FieldError::new(EXPECTED))?;
		let entry = object.get(&key)?;
		Ok((key, entry))
	}

	/// Interpret a JavaScript value as a UTF-8 string.
	pub fn string(self) -> Result<String, FieldError> {
		self.0.as_string().ok_or_else(|| FieldError::new("a string"))
	}

	/// Interpret a JavaScript value as a BOOLEAN.
	pub fn bool(self) -> Result<bool, FieldError> {
		self.0.as_bool().ok_or_else(|| FieldError::new("a boolean"))
	}

	/// Interpret JavaScript `null` as ASN.1 NULL.
	pub fn null(self) -> Result<Null, FieldError> {
		if self.0.is_null() {
			return Ok(Null);
		}

		Err(FieldError::new("null"))
	}

	/// Interpret a JavaScript number as a `u8` INTEGER.
	pub fn u8(self) -> Result<u8, FieldError> {
		let number = self.integer(0.0, f64::from(u8::MAX), "an integer in the u8 range")?;
		Ok(number as u8)
	}

	/// Interpret a JavaScript number as a `u16` INTEGER.
	pub fn u16(self) -> Result<u16, FieldError> {
		let number = self.integer(0.0, f64::from(u16::MAX), "an integer in the u16 range")?;
		Ok(number as u16)
	}

	/// Interpret a JavaScript number as a `u32` INTEGER.
	pub fn u32(self) -> Result<u32, FieldError> {
		let number = self.integer(0.0, f64::from(u32::MAX), "an integer in the u32 range")?;
		Ok(number as u32)
	}

	/// Interpret a JavaScript number as an `i8` INTEGER.
	pub fn i8(self) -> Result<i8, FieldError> {
		let number = self.integer(f64::from(i8::MIN), f64::from(i8::MAX), "an integer in the i8 range")?;
		Ok(number as i8)
	}

	/// Interpret a JavaScript number as an `i16` INTEGER.
	pub fn i16(self) -> Result<i16, FieldError> {
		let number = self.integer(f64::from(i16::MIN), f64::from(i16::MAX), "an integer in the i16 range")?;
		Ok(number as i16)
	}

	/// Interpret a JavaScript number as an `i32` INTEGER.
	pub fn i32(self) -> Result<i32, FieldError> {
		let number = self.integer(f64::from(i32::MIN), f64::from(i32::MAX), "an integer in the i32 range")?;
		Ok(number as i32)
	}

	/// Interpret a JavaScript bigint as a `u64` INTEGER. A JS number is
	/// refused.
	pub fn u64(self) -> Result<u64, FieldError> {
		const EXPECTED: &str = "a bigint in the u64 range";

		let bigint = self.bigint(EXPECTED)?;
		u64::try_from(bigint).map_err(|_| FieldError::new(EXPECTED))
	}

	/// Interpret a JavaScript bigint as an `i64` INTEGER. A JS number is
	/// refused.
	pub fn i64(self) -> Result<i64, FieldError> {
		const EXPECTED: &str = "a bigint in the i64 range";

		let bigint = self.bigint(EXPECTED)?;
		i64::try_from(bigint).map_err(|_| FieldError::new(EXPECTED))
	}

	/// Interpret a `Uint8Array` as an OCTET STRING.
	pub fn octet_string(self) -> Result<OctetString, FieldError> {
		const EXPECTED: &str = "a Uint8Array within the der length limit";

		let octets = self.octets()?;
		OctetString::new(octets).map_err(|cause| FieldError::refused(EXPECTED, cause))
	}

	/// Interpret `{ unusedBits, bytes }` as a BIT STRING.
	pub fn bitstring(self) -> Result<BitString, FieldError> {
		let object = self.object()?;

		let unused_bits = object.get("unusedBits")?;
		let unused_bits = JsField(&unused_bits).u8().map_err(|error| error.within("unusedBits"))?;
		let bytes = object.get("bytes")?;
		let bytes = JsField(&bytes).octets().map_err(|error| error.within("bytes"))?;
		BitString::new(unused_bits, bytes).map_err(|cause| FieldError::refused("a BIT STRING", cause))
	}

	/// Interpret a dotted string as an OBJECT IDENTIFIER.
	pub fn oid(self) -> Result<ObjectIdentifier, FieldError> {
		const EXPECTED: &str = "a dotted OBJECT IDENTIFIER";

		let text = self.string().map_err(|_| FieldError::new(EXPECTED))?;
		ObjectIdentifier::new(&text).map_err(|cause| FieldError::refused(EXPECTED, cause.into()))
	}

	/// Interpret opaque DER bytes as an ANY self.0.
	pub fn any(self) -> Result<Any, FieldError> {
		const EXPECTED: &str = "a Uint8Array holding one DER value";

		let bytes = self.octets().map_err(|_| FieldError::new(EXPECTED))?;
		Any::from_der(&bytes).map_err(|cause| FieldError::refused(EXPECTED, cause))
	}

	/// Interpret a `YYYY-MM-DDTHH:MM:SSZ` string as UTCTime.
	pub fn utc_time(self) -> Result<UtcTime, FieldError> {
		const EXPECTED: &str = "a YYYY-MM-DDTHH:MM:SSZ time from 1970 to 2049";

		let datetime = self.date_time(EXPECTED)?;
		UtcTime::from_date_time(datetime).map_err(|cause| FieldError::refused(EXPECTED, cause))
	}

	/// Interpret a `YYYY-MM-DDTHH:MM:SSZ` string as GeneralizedTime.
	pub fn generalized_time(self) -> Result<GeneralizedTime, FieldError> {
		let datetime = self.date_time("a YYYY-MM-DDTHH:MM:SSZ time from 1970 to 9999")?;
		Ok(GeneralizedTime::from_date_time(datetime))
	}

	/// Interpret a string as IA5String through the der constructor.
	pub fn ia5_string(self) -> Result<Ia5String, FieldError> {
		const EXPECTED: &str = "an IA5String";

		let text = self.string().map_err(|_| FieldError::new(EXPECTED))?;
		Ia5String::new(&text).map_err(|cause| FieldError::refused(EXPECTED, cause))
	}

	/// Interpret a string as PrintableString through the der constructor.
	pub fn printable_string(self) -> Result<PrintableString, FieldError> {
		const EXPECTED: &str = "a PrintableString";

		let text = self.string().map_err(|_| FieldError::new(EXPECTED))?;
		PrintableString::new(&text).map_err(|cause| FieldError::refused(EXPECTED, cause))
	}

	/// Interpret a string as TeletexString through the der constructor.
	pub fn teletex_string(self) -> Result<TeletexString, FieldError> {
		const EXPECTED: &str = "a TeletexString";

		let text = self.string().map_err(|_| FieldError::new(EXPECTED))?;
		TeletexString::new(&text).map_err(|cause| FieldError::refused(EXPECTED, cause))
	}

	/// Interpret a string as BmpString through the der constructor.
	pub fn bmp_string(self) -> Result<BmpString, FieldError> {
		const EXPECTED: &str = "a BmpString";

		let text = self.string().map_err(|_| FieldError::new(EXPECTED))?;
		BmpString::from_utf8(&text).map_err(|cause| FieldError::refused(EXPECTED, cause))
	}

	/// Interpret a JavaScript value as an `Array`.
	pub fn array(self) -> Result<Array, FieldError> {
		self.0.dyn_ref::<Array>().cloned().ok_or_else(|| FieldError::new("an Array"))
	}

	fn octets(self) -> Result<Vec<u8>, FieldError> {
		let array = self.0.dyn_ref::<Uint8Array>().ok_or_else(|| FieldError::new("a Uint8Array"))?;
		Ok(array.to_vec())
	}

	fn date_time(self, expected: &'static str) -> Result<DateTime, FieldError> {
		let text = self.string().map_err(|_| FieldError::new(expected))?;
		DateTime::from_str(&text).map_err(|cause| FieldError::refused(expected, cause))
	}

	fn bigint(self, expected: &'static str) -> Result<BigInt, FieldError> {
		if !self.0.is_bigint() {
			return Err(FieldError::new(expected));
		}

		self.0.clone().dyn_into::<BigInt>().map_err(|_| FieldError::new(expected))
	}

	fn integer(self, min: f64, max: f64, expected: &'static str) -> Result<f64, FieldError> {
		let number = self.0.as_f64().ok_or_else(|| FieldError::new(expected))?;
		if !number.is_finite() || number.fract() != 0.0 || number < min || number > max {
			return Err(FieldError::new(expected));
		}

		Ok(number)
	}
}

/// An object that the expansion reads its fields from.
#[derive(Clone, Copy)]
pub struct JsObject<'a>(&'a Object);

impl JsObject<'_> {
	/// Read the property `key`. A missing key reads as `undefined`, which every
	/// conversion refuses except an absent OPTIONAL.
	pub fn get(self, key: &str) -> Result<JsValue, FieldError> {
		Reflect::get(self.0, &JsValue::from_str(key)).map_err(|_| FieldError::new("a readable object").within(key))
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
	/// Write the property `key`.
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
	/// Push one item.
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

/// A Rust value that the expansion projects onto a JavaScript value.
pub trait JsProjection {
	/// This value as JavaScript.
	///
	/// # Errors
	///
	/// - [`FieldError`]: the value does not project, as an ANY that fails to
	///   encode.
	fn project(&self) -> Result<JsValue, FieldError>;
}

/// Projects each integer type of at most 32 bits as a JavaScript number.
macro_rules! project_number {
	($($number:ty),*) => {
		$(
			impl JsProjection for $number {
				fn project(&self) -> Result<JsValue, FieldError> {
					Ok(JsValue::from(f64::from(*self)))
				}
			}
		)*
	};
}

project_number!(u8, u16, u32, i8, i16, i32);

impl JsProjection for bool {
	fn project(&self) -> Result<JsValue, FieldError> {
		Ok(JsValue::from(*self))
	}
}

impl JsProjection for u64 {
	/// A `u64` as a JavaScript bigint.
	fn project(&self) -> Result<JsValue, FieldError> {
		Ok(JsValue::from(BigInt::from(*self)))
	}
}

impl JsProjection for i64 {
	/// An `i64` as a JavaScript bigint.
	fn project(&self) -> Result<JsValue, FieldError> {
		Ok(JsValue::from(BigInt::from(*self)))
	}
}

impl JsProjection for OctetString {
	/// An OCTET STRING as a `Uint8Array`.
	fn project(&self) -> Result<JsValue, FieldError> {
		Ok(JsValue::from(Uint8Array::from(self.as_bytes())))
	}
}

impl JsProjection for BitString {
	/// A BIT STRING as `{ unusedBits, bytes }`.
	fn project(&self) -> Result<JsValue, FieldError> {
		let record = JsRecord::default();
		let unused_bits = self.unused_bits().project()?;
		let bytes = JsValue::from(Uint8Array::from(self.raw_bytes()));
		record.set("unusedBits", &unused_bits)?;
		record.set("bytes", &bytes)?;

		Ok(record.into())
	}
}

impl JsProjection for ObjectIdentifier {
	/// An OBJECT IDENTIFIER as a dotted string.
	fn project(&self) -> Result<JsValue, FieldError> {
		Ok(JsValue::from_str(&self.to_string()))
	}
}

impl JsProjection for Any {
	/// An ANY value as its full DER encoding.
	fn project(&self) -> Result<JsValue, FieldError> {
		let encoded = self.to_der()?;
		Ok(JsValue::from(Uint8Array::from(encoded.as_slice())))
	}
}

impl JsProjection for UtcTime {
	/// UTCTime as a `YYYY-MM-DDTHH:MM:SSZ` string.
	fn project(&self) -> Result<JsValue, FieldError> {
		Ok(JsValue::from_str(&self.to_date_time().to_string()))
	}
}

impl JsProjection for GeneralizedTime {
	/// GeneralizedTime as a `YYYY-MM-DDTHH:MM:SSZ` string.
	fn project(&self) -> Result<JsValue, FieldError> {
		Ok(JsValue::from_str(&self.to_date_time().to_string()))
	}
}

impl JsProjection for Ia5String {
	fn project(&self) -> Result<JsValue, FieldError> {
		Ok(JsValue::from_str(self.as_str()))
	}
}

impl JsProjection for PrintableString {
	fn project(&self) -> Result<JsValue, FieldError> {
		Ok(JsValue::from_str(self.as_str()))
	}
}

impl JsProjection for TeletexString {
	fn project(&self) -> Result<JsValue, FieldError> {
		Ok(JsValue::from_str(self.as_str()))
	}
}

impl JsProjection for BmpString {
	fn project(&self) -> Result<JsValue, FieldError> {
		Ok(JsValue::from_str(&self.to_string()))
	}
}
