//! JavaScript value helpers for `AsnCodec` wasm expansions.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::str::FromStr;

use der::asn1::{
	Any, BitString, BmpString, GeneralizedTime, Ia5String, Null, ObjectIdentifier, PrintableString, TeletexString,
	UtcTime,
};
use der::{DateTime, Decode, Encode, Error, ErrorKind, Result};
use js_sys::{Array, BigInt, Object, Reflect, Uint8Array};
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

/// Read a UTF-8 string field from a plain object.
pub fn string_field(value: &JsValue, name: impl AsRef<str>) -> Result<String> {
	as_string(&object_field(value, name)?)
}

/// Read an octet field from a plain object as a `Uint8Array`.
pub fn octet_field(value: &JsValue, name: impl AsRef<str>) -> Result<Vec<u8>> {
	as_octets(&object_field(value, name)?)
}

/// Read a nested value field for another `AsnCodec` type.
pub fn object_field(value: &JsValue, name: impl AsRef<str>) -> Result<JsValue> {
	let field = Reflect::get(value, &JsValue::from_str(name.as_ref())).map_err(|_| Error::from(ErrorKind::Failed))?;
	if field.is_undefined() || field.is_null() {
		return Err(Error::from(ErrorKind::Failed));
	}

	Ok(field)
}

/// Read an OPTIONAL field. Missing, `null`, and `undefined` map to `None`.
pub fn optional_field(value: &JsValue, name: impl AsRef<str>) -> Result<Option<JsValue>> {
	let field = Reflect::get(value, &JsValue::from_str(name.as_ref())).map_err(|_| Error::from(ErrorKind::Failed))?;
	if field.is_undefined() || field.is_null() {
		return Ok(None);
	}

	Ok(Some(field))
}

/// Read a SEQUENCE OF / SET OF field as a JavaScript `Array`.
pub fn array_field(value: &JsValue, name: impl AsRef<str>) -> Result<Array> {
	as_array(&object_field(value, name)?)
}

/// Read a finite JavaScript number field from a plain object.
pub fn number_field(value: &JsValue, name: impl AsRef<str>) -> Result<f64> {
	as_number(&object_field(value, name)?)
}

/// Read a `u8` INTEGER field from a plain object.
pub fn u8_field(value: &JsValue, name: impl AsRef<str>) -> Result<u8> {
	as_u8(&object_field(value, name)?)
}

/// Read a `bool` BOOLEAN field from a plain object.
pub fn bool_field(value: &JsValue, name: impl AsRef<str>) -> Result<bool> {
	as_bool(&object_field(value, name)?)
}

/// Read a NULL field that must be JS `null`.
pub fn null_field(value: &JsValue, name: impl AsRef<str>) -> Result<Null> {
	let field = Reflect::get(value, &JsValue::from_str(name.as_ref())).map_err(|_| Error::from(ErrorKind::Failed))?;
	as_null(&field)
}

/// Read a range-checked signed or unsigned INTEGER number field.
pub fn i8_field(value: &JsValue, name: impl AsRef<str>) -> Result<i8> {
	as_i8(&object_field(value, name)?)
}

/// Read a range-checked `u16` INTEGER field.
pub fn u16_field(value: &JsValue, name: impl AsRef<str>) -> Result<u16> {
	as_u16(&object_field(value, name)?)
}

/// Read a range-checked `i16` INTEGER field.
pub fn i16_field(value: &JsValue, name: impl AsRef<str>) -> Result<i16> {
	as_i16(&object_field(value, name)?)
}

/// Read a range-checked `u32` INTEGER field.
pub fn u32_field(value: &JsValue, name: impl AsRef<str>) -> Result<u32> {
	as_u32(&object_field(value, name)?)
}

/// Read a range-checked `i32` INTEGER field.
pub fn i32_field(value: &JsValue, name: impl AsRef<str>) -> Result<i32> {
	as_i32(&object_field(value, name)?)
}

/// Read a `u64` INTEGER field that must be a JS bigint.
pub fn u64_field(value: &JsValue, name: impl AsRef<str>) -> Result<u64> {
	as_u64(&object_field(value, name)?)
}

/// Read an `i64` INTEGER field that must be a JS bigint.
pub fn i64_field(value: &JsValue, name: impl AsRef<str>) -> Result<i64> {
	as_i64(&object_field(value, name)?)
}

/// Read an OBJECT IDENTIFIER field as a dotted string.
pub fn oid_field(value: &JsValue, name: impl AsRef<str>) -> Result<ObjectIdentifier> {
	as_oid(&object_field(value, name)?)
}

/// Read an ANY field as opaque DER bytes.
pub fn any_field(value: &JsValue, name: impl AsRef<str>) -> Result<Any> {
	as_any(&object_field(value, name)?)
}

/// Read a BIT STRING field as `{ unusedBits, bytes }`.
pub fn bitstring_field(value: &JsValue, name: impl AsRef<str>) -> Result<BitString> {
	as_bitstring(&object_field(value, name)?)
}

/// Read a UTCTime field as an RFC 3339 string.
pub fn utc_time_field(value: &JsValue, name: impl AsRef<str>) -> Result<UtcTime> {
	as_utc_time(&object_field(value, name)?)
}

/// Read a GeneralizedTime field as an RFC 3339 string.
pub fn generalized_time_field(value: &JsValue, name: impl AsRef<str>) -> Result<GeneralizedTime> {
	as_generalized_time(&object_field(value, name)?)
}

/// Read an IA5String field validated by the der constructor.
pub fn ia5_string_field(value: &JsValue, name: impl AsRef<str>) -> Result<Ia5String> {
	as_ia5_string(&object_field(value, name)?)
}

/// Read a PrintableString field validated by the der constructor.
pub fn printable_string_field(value: &JsValue, name: impl AsRef<str>) -> Result<PrintableString> {
	as_printable_string(&object_field(value, name)?)
}

/// Read a TeletexString field validated by the der constructor.
pub fn teletex_string_field(value: &JsValue, name: impl AsRef<str>) -> Result<TeletexString> {
	as_teletex_string(&object_field(value, name)?)
}

/// Read a BmpString field validated by the der constructor.
pub fn bmp_string_field(value: &JsValue, name: impl AsRef<str>) -> Result<BmpString> {
	as_bmp_string(&object_field(value, name)?)
}

/// Interpret a JavaScript value as a UTF-8 string.
pub fn as_string(value: &JsValue) -> Result<String> {
	value.as_string().ok_or_else(|| Error::from(ErrorKind::Failed))
}

/// Interpret a JavaScript value as octet bytes from a `Uint8Array`.
pub fn as_octets(value: &JsValue) -> Result<Vec<u8>> {
	let array = value.dyn_ref::<Uint8Array>().ok_or_else(|| Error::from(ErrorKind::Failed))?;
	Ok(array.to_vec())
}

/// Interpret a JavaScript value as a finite number.
pub fn as_number(value: &JsValue) -> Result<f64> {
	value.as_f64().ok_or_else(|| Error::from(ErrorKind::Failed))
}

/// Interpret a JavaScript value as a `u8` discriminant or INTEGER.
pub fn as_u8(value: &JsValue) -> Result<u8> {
	f64_as_unsigned(as_number(value)?, u8::MAX as f64).map(|n| n as u8)
}

/// Interpret a JavaScript value as a BOOLEAN.
pub fn as_bool(value: &JsValue) -> Result<bool> {
	value.as_bool().ok_or_else(|| Error::from(ErrorKind::Failed))
}

/// Interpret a JavaScript `null` as ASN.1 NULL.
pub fn as_null(value: &JsValue) -> Result<Null> {
	if value.is_null() {
		return Ok(Null);
	}
	Err(Error::from(ErrorKind::Failed))
}

/// Interpret a JavaScript number as an `i8` INTEGER.
pub fn as_i8(value: &JsValue) -> Result<i8> {
	f64_as_signed(as_number(value)?, i8::MIN as f64, i8::MAX as f64).map(|n| n as i8)
}

/// Interpret a JavaScript number as a `u16` INTEGER.
pub fn as_u16(value: &JsValue) -> Result<u16> {
	f64_as_unsigned(as_number(value)?, u16::MAX as f64).map(|n| n as u16)
}

/// Interpret a JavaScript number as an `i16` INTEGER.
pub fn as_i16(value: &JsValue) -> Result<i16> {
	f64_as_signed(as_number(value)?, i16::MIN as f64, i16::MAX as f64).map(|n| n as i16)
}

/// Interpret a JavaScript number as a `u32` INTEGER.
pub fn as_u32(value: &JsValue) -> Result<u32> {
	f64_as_unsigned(as_number(value)?, u32::MAX as f64).map(|n| n as u32)
}

/// Interpret a JavaScript number as an `i32` INTEGER.
pub fn as_i32(value: &JsValue) -> Result<i32> {
	f64_as_signed(as_number(value)?, i32::MIN as f64, i32::MAX as f64).map(|n| n as i32)
}

/// Interpret a JavaScript bigint as a `u64` INTEGER. JS numbers are rejected.
pub fn as_u64(value: &JsValue) -> Result<u64> {
	let bigint = as_bigint(value)?;
	u64::try_from(bigint).map_err(|_| Error::from(ErrorKind::Failed))
}

/// Interpret a JavaScript bigint as an `i64` INTEGER. JS numbers are rejected.
pub fn as_i64(value: &JsValue) -> Result<i64> {
	let bigint = as_bigint(value)?;
	i64::try_from(bigint).map_err(|_| Error::from(ErrorKind::Failed))
}

/// Interpret a dotted string as an OBJECT IDENTIFIER.
pub fn as_oid(value: &JsValue) -> Result<ObjectIdentifier> {
	let text = as_string(value)?;
	ObjectIdentifier::new(&text).map_err(Error::from)
}

/// Interpret opaque DER bytes as an ANY value.
pub fn as_any(value: &JsValue) -> Result<Any> {
	let bytes = as_octets(value)?;
	Any::from_der(&bytes)
}

/// Interpret `{ unusedBits, bytes }` as a BIT STRING.
pub fn as_bitstring(value: &JsValue) -> Result<BitString> {
	let unused_bits = u8_field(value, "unusedBits")?;
	let bytes = octet_field(value, "bytes")?;
	BitString::new(unused_bits, bytes)
}

/// Interpret an RFC 3339 string as UTCTime.
pub fn as_utc_time(value: &JsValue) -> Result<UtcTime> {
	let text = as_string(value)?;
	let datetime = DateTime::from_str(&text)?;
	UtcTime::from_date_time(datetime)
}

/// Interpret an RFC 3339 string as GeneralizedTime.
pub fn as_generalized_time(value: &JsValue) -> Result<GeneralizedTime> {
	let text = as_string(value)?;
	let datetime = DateTime::from_str(&text)?;
	Ok(GeneralizedTime::from_date_time(datetime))
}

/// Interpret a string as IA5String through the der constructor.
pub fn as_ia5_string(value: &JsValue) -> Result<Ia5String> {
	Ia5String::new(&as_string(value)?)
}

/// Interpret a string as PrintableString through the der constructor.
pub fn as_printable_string(value: &JsValue) -> Result<PrintableString> {
	PrintableString::new(&as_string(value)?)
}

/// Interpret a string as TeletexString through the der constructor.
pub fn as_teletex_string(value: &JsValue) -> Result<TeletexString> {
	TeletexString::new(&as_string(value)?)
}

/// Interpret a string as BmpString through the der constructor.
pub fn as_bmp_string(value: &JsValue) -> Result<BmpString> {
	BmpString::from_utf8(&as_string(value)?)
}

/// Interpret a JavaScript value as an `Array`.
pub fn as_array(value: &JsValue) -> Result<Array> {
	value.dyn_ref::<Array>().cloned().ok_or_else(|| Error::from(ErrorKind::Failed))
}

/// Interpret a JavaScript value as an `Array` with an exact length.
pub fn as_array_len(value: &JsValue, expected: usize) -> Result<Array> {
	let array = as_array(value)?;
	if (array.length() as usize) != expected {
		return Err(Error::from(ErrorKind::Failed));
	}
	Ok(array)
}

/// Project a `u8` as a JavaScript number.
pub fn from_u8(value: u8) -> JsValue {
	JsValue::from(f64::from(value))
}

/// Project a bool as a JavaScript boolean.
pub fn from_bool(value: bool) -> JsValue {
	JsValue::from(value)
}

/// Project ASN.1 NULL as JavaScript `null`.
pub fn from_null(_value: Null) -> JsValue {
	JsValue::NULL
}

/// Project a `u16` as a JavaScript number.
pub fn from_u16(value: u16) -> JsValue {
	JsValue::from(f64::from(value))
}

/// Project an `i8` as a JavaScript number.
pub fn from_i8(value: i8) -> JsValue {
	JsValue::from(f64::from(value))
}

/// Project an `i16` as a JavaScript number.
pub fn from_i16(value: i16) -> JsValue {
	JsValue::from(f64::from(value))
}

/// Project a `u32` as a JavaScript number.
pub fn from_u32(value: u32) -> JsValue {
	JsValue::from(f64::from(value))
}

/// Project an `i32` as a JavaScript number.
pub fn from_i32(value: i32) -> JsValue {
	JsValue::from(f64::from(value))
}

/// Project a `u64` as a JavaScript bigint.
pub fn from_u64(value: u64) -> JsValue {
	JsValue::from(BigInt::from(value))
}

/// Project an `i64` as a JavaScript bigint.
pub fn from_i64(value: i64) -> JsValue {
	JsValue::from(BigInt::from(value))
}

/// Project an OBJECT IDENTIFIER as a dotted string.
pub fn from_oid(value: &ObjectIdentifier) -> JsValue {
	JsValue::from_str(&value.to_string())
}

/// Project an ANY value as its full DER encoding.
pub fn from_any(value: &Any) -> Result<JsValue> {
	Ok(from_octets(value.to_der()?))
}

/// Project a BIT STRING as `{ unusedBits, bytes }`.
pub fn from_bitstring(value: &BitString) -> Result<JsValue> {
	let object = object()?;
	set_u8(&object, "unusedBits", value.unused_bits())?;
	set_octets(&object, "bytes", value.raw_bytes())?;
	Ok(object)
}

/// Project UTCTime as an RFC 3339 string.
pub fn from_utc_time(value: &UtcTime) -> JsValue {
	JsValue::from_str(&value.to_date_time().to_string())
}

/// Project GeneralizedTime as an RFC 3339 string.
pub fn from_generalized_time(value: &GeneralizedTime) -> JsValue {
	JsValue::from_str(&value.to_date_time().to_string())
}

/// Project an IA5String as a JS string.
pub fn from_ia5_string(value: &Ia5String) -> JsValue {
	JsValue::from_str(value.as_str())
}

/// Project a PrintableString as a JS string.
pub fn from_printable_string(value: &PrintableString) -> JsValue {
	JsValue::from_str(value.as_str())
}

/// Project a TeletexString as a JS string.
pub fn from_teletex_string(value: &TeletexString) -> JsValue {
	JsValue::from_str(value.as_str())
}

/// Project a BmpString as a JS string.
pub fn from_bmp_string(value: &BmpString) -> JsValue {
	JsValue::from_str(&value.to_string())
}

/// Project octet bytes as a `Uint8Array` JavaScript value.
pub fn from_octets(value: impl AsRef<[u8]>) -> JsValue {
	JsValue::from(Uint8Array::from(value.as_ref()))
}

/// Empty JavaScript `Array` used when projecting SEQUENCE OF / SET OF fields.
pub fn array() -> Array {
	Array::new()
}

/// Single own enumerable string key and value for Choice tag objects.
pub fn single_entry(value: &JsValue) -> Result<(String, JsValue)> {
	let object = value.dyn_ref::<Object>().ok_or_else(|| Error::from(ErrorKind::Failed))?;
	let keys = Object::keys(object);
	if keys.length() != 1 {
		return Err(Error::from(ErrorKind::Failed));
	}

	let key_value = keys.get(0);
	let key = key_value.as_string().ok_or_else(|| Error::from(ErrorKind::Failed))?;
	let entry = Reflect::get(value, &key_value).map_err(|_| Error::from(ErrorKind::Failed))?;
	if entry.is_undefined() || entry.is_null() {
		return Err(Error::from(ErrorKind::Failed));
	}

	Ok((key, entry))
}

/// Empty plain object used when projecting Sequence and Choice values.
pub fn object() -> Result<JsValue> {
	Ok(JsValue::from(Object::new()))
}

/// Set a UTF-8 string field on a plain object.
pub fn set_string(object: &JsValue, name: impl AsRef<str>, value: impl AsRef<str>) -> Result<()> {
	Reflect::set(object, &JsValue::from_str(name.as_ref()), &JsValue::from_str(value.as_ref()))
		.map_err(|_| Error::from(ErrorKind::Failed))?;
	Ok(())
}

/// Set an octet field on a plain object as a `Uint8Array`.
pub fn set_octets(object: &JsValue, name: impl AsRef<str>, value: impl AsRef<[u8]>) -> Result<()> {
	Reflect::set(object, &JsValue::from_str(name.as_ref()), &from_octets(value))
		.map_err(|_| Error::from(ErrorKind::Failed))?;
	Ok(())
}

/// Set a nested value field from another `AsnCodec` value.
pub fn set_object(object: &JsValue, name: impl AsRef<str>, value: &JsValue) -> Result<()> {
	Reflect::set(object, &JsValue::from_str(name.as_ref()), value).map_err(|_| Error::from(ErrorKind::Failed))?;
	Ok(())
}

/// Set a SEQUENCE OF / SET OF field from a JavaScript `Array`.
pub fn set_array(object: &JsValue, name: impl AsRef<str>, value: &Array) -> Result<()> {
	Reflect::set(object, &JsValue::from_str(name.as_ref()), value).map_err(|_| Error::from(ErrorKind::Failed))?;
	Ok(())
}

/// Set a JavaScript number field on a plain object.
pub fn set_number(object: &JsValue, name: impl AsRef<str>, value: f64) -> Result<()> {
	Reflect::set(object, &JsValue::from_str(name.as_ref()), &JsValue::from(value))
		.map_err(|_| Error::from(ErrorKind::Failed))?;
	Ok(())
}

/// Set a `u8` INTEGER field on a plain object.
pub fn set_u8(object: &JsValue, name: impl AsRef<str>, value: u8) -> Result<()> {
	set_number(object, name, f64::from(value))
}

/// Set a BOOLEAN field on a plain object.
pub fn set_bool(object: &JsValue, name: impl AsRef<str>, value: bool) -> Result<()> {
	Reflect::set(object, &JsValue::from_str(name.as_ref()), &from_bool(value))
		.map_err(|_| Error::from(ErrorKind::Failed))?;
	Ok(())
}

/// Set a NULL field on a plain object as JS `null`.
pub fn set_null(object: &JsValue, name: impl AsRef<str>, value: Null) -> Result<()> {
	Reflect::set(object, &JsValue::from_str(name.as_ref()), &from_null(value))
		.map_err(|_| Error::from(ErrorKind::Failed))?;
	Ok(())
}

/// Set an `i8` INTEGER field on a plain object.
pub fn set_i8(object: &JsValue, name: impl AsRef<str>, value: i8) -> Result<()> {
	set_number(object, name, f64::from(value))
}

/// Set a `u16` INTEGER field on a plain object.
pub fn set_u16(object: &JsValue, name: impl AsRef<str>, value: u16) -> Result<()> {
	set_number(object, name, f64::from(value))
}

/// Set an `i16` INTEGER field on a plain object.
pub fn set_i16(object: &JsValue, name: impl AsRef<str>, value: i16) -> Result<()> {
	set_number(object, name, f64::from(value))
}

/// Set a `u32` INTEGER field on a plain object.
pub fn set_u32(object: &JsValue, name: impl AsRef<str>, value: u32) -> Result<()> {
	set_number(object, name, f64::from(value))
}

/// Set an `i32` INTEGER field on a plain object.
pub fn set_i32(object: &JsValue, name: impl AsRef<str>, value: i32) -> Result<()> {
	set_number(object, name, f64::from(value))
}

/// Set a `u64` INTEGER field on a plain object as a bigint.
pub fn set_u64(object: &JsValue, name: impl AsRef<str>, value: u64) -> Result<()> {
	Reflect::set(object, &JsValue::from_str(name.as_ref()), &from_u64(value))
		.map_err(|_| Error::from(ErrorKind::Failed))?;
	Ok(())
}

/// Set an `i64` INTEGER field on a plain object as a bigint.
pub fn set_i64(object: &JsValue, name: impl AsRef<str>, value: i64) -> Result<()> {
	Reflect::set(object, &JsValue::from_str(name.as_ref()), &from_i64(value))
		.map_err(|_| Error::from(ErrorKind::Failed))?;
	Ok(())
}

/// Set an OBJECT IDENTIFIER field from its dotted string form.
pub fn set_oid(object: &JsValue, name: impl AsRef<str>, value: &ObjectIdentifier) -> Result<()> {
	set_string(object, name, value.to_string())
}

/// Set an ANY field from its full DER encoding.
pub fn set_any(object: &JsValue, name: impl AsRef<str>, value: &Any) -> Result<()> {
	let encoded = from_any(value)?;
	set_object(object, name, &encoded)
}

/// Set a BIT STRING field as `{ unusedBits, bytes }`.
pub fn set_bitstring(object: &JsValue, name: impl AsRef<str>, value: &BitString) -> Result<()> {
	let encoded = from_bitstring(value)?;
	set_object(object, name, &encoded)
}

/// Set a UTCTime field from its RFC 3339 string form.
pub fn set_utc_time(object: &JsValue, name: impl AsRef<str>, value: &UtcTime) -> Result<()> {
	set_string(object, name, value.to_date_time().to_string())
}

/// Set a GeneralizedTime field from its RFC 3339 string form.
pub fn set_generalized_time(object: &JsValue, name: impl AsRef<str>, value: &GeneralizedTime) -> Result<()> {
	set_string(object, name, value.to_date_time().to_string())
}

/// Set an IA5String field.
pub fn set_ia5_string(object: &JsValue, name: impl AsRef<str>, value: &Ia5String) -> Result<()> {
	set_string(object, name, value.as_str())
}

/// Set a PrintableString field.
pub fn set_printable_string(object: &JsValue, name: impl AsRef<str>, value: &PrintableString) -> Result<()> {
	set_string(object, name, value.as_str())
}

/// Set a TeletexString field.
pub fn set_teletex_string(object: &JsValue, name: impl AsRef<str>, value: &TeletexString) -> Result<()> {
	set_string(object, name, value.as_str())
}

/// Set a BmpString field.
pub fn set_bmp_string(object: &JsValue, name: impl AsRef<str>, value: &BmpString) -> Result<()> {
	set_string(object, name, value.to_string())
}

/// Convert a `der::Error` into a JavaScript exception value.
pub fn to_js_error(error: Error) -> JsValue {
	JsValue::from_str(&alloc::format!("{error}"))
}

fn as_bigint(value: &JsValue) -> Result<BigInt> {
	if !value.is_bigint() {
		return Err(Error::from(ErrorKind::Failed));
	}

	value.clone().dyn_into::<BigInt>().map_err(|_| Error::from(ErrorKind::Failed))
}

fn f64_as_unsigned(number: f64, max: f64) -> Result<f64> {
	if !number.is_finite() {
		return Err(Error::from(ErrorKind::Failed));
	}
	if number.fract() != 0.0 {
		return Err(Error::from(ErrorKind::Failed));
	}
	if number < 0.0 || number > max {
		return Err(Error::from(ErrorKind::Failed));
	}

	Ok(number)
}

fn f64_as_signed(number: f64, min: f64, max: f64) -> Result<f64> {
	if !number.is_finite() {
		return Err(Error::from(ErrorKind::Failed));
	}
	if number.fract() != 0.0 {
		return Err(Error::from(ErrorKind::Failed));
	}
	if number < min || number > max {
		return Err(Error::from(ErrorKind::Failed));
	}

	Ok(number)
}
