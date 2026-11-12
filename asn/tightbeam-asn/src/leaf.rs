//! The JavaScript contract of each field type of a DER type:
//! [docs/asn.md][field-map].
//!
//! [field-map]: https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/asn.md#field-map

use der::asn1::{
	Any, BitString, BmpString, GeneralizedTime, Ia5String, Null, ObjectIdentifier, OctetString, PrintableString,
	TeletexString, UtcTime,
};
#[cfg(target_arch = "wasm32")]
use {
	crate::js::{JsField, JsRecord},
	crate::FieldError,
	alloc::string::ToString,
	der::{Decode, Encode},
	js_sys::{BigInt, Uint8Array},
	wasm_bindgen::JsValue,
};

/// A type that a field of a DER type holds: a `der` leaf, or an `AsnCodec`.
///
/// The derive declares the TypeScript type of each field from these constants,
/// and on `wasm32` it converts each field through these methods. Each
/// implementation holds two laws:
///
/// - `value.project()` yields a JavaScript value of the type that `TS_TYPE` names.
/// - `read(&value.project()?)` returns `Ok(value)`.
#[diagnostic::on_unimplemented(
	message = "`{Self}` is no field type of an AsnCodec DER type",
	label = "a field takes a der leaf, or a type that derives AsnCodec",
	note = "the field map of docs/asn.md lists each der leaf"
)]
pub trait JsLeaf: Sized {
	/// The TypeScript type of a value.
	const TS_TYPE: &'static str;

	/// The JSDoc of a field of this type that carries no doc of its own. Such a
	/// field fails the build of the deriving crate when the text holds `*/`,
	/// which would end the JSDoc block.
	const CONTRACT: &'static str;

	/// Whether JavaScript reads a present value back as an absent OPTIONAL.
	const READS_AS_ABSENT: bool = false;

	/// Build the value from a JavaScript value.
	///
	/// # Errors
	///
	/// - The [`FieldError`] of a `value` that does not fit the type.
	#[cfg(target_arch = "wasm32")]
	fn read(value: &JsValue) -> Result<Self, FieldError>;

	/// Project the value onto a JavaScript value.
	///
	/// # Errors
	///
	/// - The [`FieldError`] of a value that does not project, such as an ANY
	///   that fails to encode.
	#[cfg(target_arch = "wasm32")]
	fn project(&self) -> Result<JsValue, FieldError>;
}

/// Implements [`JsLeaf`] for each `der` leaf from the items of its impl, and
/// lists the leaves for the field-map test of `docs/asn.md`.
macro_rules! js_leaves {
	($($leaf:ty { $($items:tt)* })*) => {
		$(
			impl JsLeaf for $leaf {
				$($items)*
			}
		)*

		/// The field-map row of each leaf of [`js_leaves`].
		#[cfg(test)]
		fn leaves() -> alloc::vec::Vec<[alloc::string::String; 3]> {
			alloc::vec![$(tests::row::<$leaf>()),*]
		}
	};
}

/// The [`JsLeaf`] items of an integer type of at most 32 bits, as a
/// JavaScript number in the range of the type.
macro_rules! js_number {
	($number:ty) => {
		const TS_TYPE: &'static str = "number";
		const CONTRACT: &'static str =
			concat!("Carries an INTEGER field in the inclusive ", stringify!($number), " range.");

		#[cfg(target_arch = "wasm32")]
		fn read(value: &JsValue) -> Result<Self, FieldError> {
			let range = f64::from(<$number>::MIN)..=f64::from(<$number>::MAX);
			let expected = concat!("an integer in the ", stringify!($number), " range");
			let number = JsField::from(value).integer(range, expected)?;
			Ok(number as $number)
		}

		#[cfg(target_arch = "wasm32")]
		fn project(&self) -> Result<JsValue, FieldError> {
			Ok(JsValue::from(f64::from(*self)))
		}
	};
}

/// The [`JsLeaf`] items of a 64-bit integer type, as a JavaScript bigint in
/// the range of the type. A JavaScript number is refused.
macro_rules! js_bigint {
	($number:ty) => {
		const TS_TYPE: &'static str = "bigint";
		const CONTRACT: &'static str = concat!(
			"Carries an INTEGER field as a JavaScript bigint in the inclusive ",
			stringify!($number),
			" range."
		);

		#[cfg(target_arch = "wasm32")]
		fn read(value: &JsValue) -> Result<Self, FieldError> {
			let expected = concat!("a bigint in the ", stringify!($number), " range");
			<$number>::try_from(value.clone()).map_err(|_| FieldError::new(expected))
		}

		#[cfg(target_arch = "wasm32")]
		fn project(&self) -> Result<JsValue, FieldError> {
			Ok(JsValue::from(BigInt::from(*self)))
		}
	};
}

/// The [`JsLeaf`] items of a restricted string type that `der` builds with
/// `new`, as a JavaScript string that the constructor checks. The literal
/// names the ASN.1 type with its article.
macro_rules! js_restricted_string {
	($string:ty, $named:literal) => {
		const TS_TYPE: &'static str = "string";
		const CONTRACT: &'static str = concat!("Carries ", $named, " Sequence field validated by der.");

		#[cfg(target_arch = "wasm32")]
		fn read(value: &JsValue) -> Result<Self, FieldError> {
			let text = JsField::from(value).string().map_err(|_| FieldError::new($named))?;
			<$string>::new(&text).map_err(|cause| FieldError::refused($named, cause))
		}

		#[cfg(target_arch = "wasm32")]
		fn project(&self) -> Result<JsValue, FieldError> {
			Ok(JsValue::from_str(self.as_str()))
		}
	};
}

js_leaves! {
	u8 { js_number!(u8); }
	u16 { js_number!(u16); }
	u32 { js_number!(u32); }
	i8 { js_number!(i8); }
	i16 { js_number!(i16); }
	i32 { js_number!(i32); }

	u64 { js_bigint!(u64); }
	i64 { js_bigint!(i64); }

	Ia5String { js_restricted_string!(Ia5String, "an IA5String"); }
	PrintableString { js_restricted_string!(PrintableString, "a PrintableString"); }
	TeletexString { js_restricted_string!(TeletexString, "a TeletexString"); }

	bool {
		const TS_TYPE: &'static str = "boolean";
		const CONTRACT: &'static str = "Carries a BOOLEAN Sequence field as a JavaScript boolean.";

		#[cfg(target_arch = "wasm32")]
		fn read(value: &JsValue) -> Result<Self, FieldError> {
			value.as_bool().ok_or_else(|| FieldError::new("a boolean"))
		}

		#[cfg(target_arch = "wasm32")]
		fn project(&self) -> Result<JsValue, FieldError> {
			Ok(JsValue::from(*self))
		}
	}

	Null {
		const TS_TYPE: &'static str = "null";
		const CONTRACT: &'static str = "Carries a NULL Sequence field as JavaScript null.";

		/// JavaScript `null` is both NULL and an absent OPTIONAL.
		const READS_AS_ABSENT: bool = true;

		#[cfg(target_arch = "wasm32")]
		fn read(value: &JsValue) -> Result<Self, FieldError> {
			if value.is_null() {
				return Ok(Null);
			}

			Err(FieldError::new("null"))
		}

		#[cfg(target_arch = "wasm32")]
		fn project(&self) -> Result<JsValue, FieldError> {
			Ok(JsValue::NULL)
		}
	}

	alloc::string::String {
		const TS_TYPE: &'static str = "string";
		const CONTRACT: &'static str = "Carries a UTF-8 string Sequence field.";

		#[cfg(target_arch = "wasm32")]
		fn read(value: &JsValue) -> Result<Self, FieldError> {
			JsField::from(value).string()
		}

		#[cfg(target_arch = "wasm32")]
		fn project(&self) -> Result<JsValue, FieldError> {
			Ok(JsValue::from_str(self))
		}
	}

	BmpString {
		const TS_TYPE: &'static str = "string";
		const CONTRACT: &'static str = "Carries a BmpString Sequence field validated by der.";

		#[cfg(target_arch = "wasm32")]
		fn read(value: &JsValue) -> Result<Self, FieldError> {
			const EXPECTED: &str = "a BmpString";

			let text = JsField::from(value).string().map_err(|_| FieldError::new(EXPECTED))?;
			BmpString::from_utf8(&text).map_err(|cause| FieldError::refused(EXPECTED, cause))
		}

		#[cfg(target_arch = "wasm32")]
		fn project(&self) -> Result<JsValue, FieldError> {
			Ok(JsValue::from_str(&self.to_string()))
		}
	}

	OctetString {
		const TS_TYPE: &'static str = "Uint8Array";
		const CONTRACT: &'static str = "Carries an octet string Sequence field as Uint8Array.";

		#[cfg(target_arch = "wasm32")]
		fn read(value: &JsValue) -> Result<Self, FieldError> {
			const EXPECTED: &str = "a Uint8Array within the der length limit";

			let octets = JsField::from(value).octets()?;
			OctetString::new(octets).map_err(|cause| FieldError::refused(EXPECTED, cause))
		}

		#[cfg(target_arch = "wasm32")]
		fn project(&self) -> Result<JsValue, FieldError> {
			Ok(JsValue::from(Uint8Array::from(self.as_bytes())))
		}
	}

	BitString {
		const TS_TYPE: &'static str = "{ unusedBits: number; bytes: Uint8Array }";
		const CONTRACT: &'static str = "Carries a BIT STRING Sequence field as unusedBits plus bytes.";

		#[cfg(target_arch = "wasm32")]
		fn read(value: &JsValue) -> Result<Self, FieldError> {
			let object = JsField::from(value).object()?;

			let unused_bits = object.get("unusedBits")?;
			let unused_bits = u8::read(&unused_bits).map_err(|error| error.within("unusedBits"))?;
			let bytes = object.get("bytes")?;
			let bytes = JsField::from(&bytes).octets().map_err(|error| error.within("bytes"))?;
			BitString::new(unused_bits, bytes).map_err(|cause| FieldError::refused("a BIT STRING", cause))
		}

		#[cfg(target_arch = "wasm32")]
		fn project(&self) -> Result<JsValue, FieldError> {
			let record = JsRecord::default();
			let unused_bits = self.unused_bits().project()?;
			let bytes = JsValue::from(Uint8Array::from(self.raw_bytes()));
			record.set("unusedBits", &unused_bits)?;
			record.set("bytes", &bytes)?;

			Ok(record.into())
		}
	}

	ObjectIdentifier {
		const TS_TYPE: &'static str = "string";
		const CONTRACT: &'static str = "Carries an OBJECT IDENTIFIER Sequence field as a dotted string.";

		#[cfg(target_arch = "wasm32")]
		fn read(value: &JsValue) -> Result<Self, FieldError> {
			const EXPECTED: &str = "a dotted OBJECT IDENTIFIER";

			let text = JsField::from(value).string().map_err(|_| FieldError::new(EXPECTED))?;
			ObjectIdentifier::new(&text).map_err(|cause| FieldError::refused(EXPECTED, cause.into()))
		}

		#[cfg(target_arch = "wasm32")]
		fn project(&self) -> Result<JsValue, FieldError> {
			Ok(JsValue::from_str(&self.to_string()))
		}
	}

	Any {
		const TS_TYPE: &'static str = "Uint8Array";
		const CONTRACT: &'static str = "Carries an ANY Sequence field as opaque DER bytes.";

		#[cfg(target_arch = "wasm32")]
		fn read(value: &JsValue) -> Result<Self, FieldError> {
			const EXPECTED: &str = "a Uint8Array holding one DER value";

			let bytes = JsField::from(value).octets().map_err(|_| FieldError::new(EXPECTED))?;
			Any::from_der(&bytes).map_err(|cause| FieldError::refused(EXPECTED, cause))
		}

		#[cfg(target_arch = "wasm32")]
		fn project(&self) -> Result<JsValue, FieldError> {
			let encoded = self.to_der()?;
			Ok(JsValue::from(Uint8Array::from(encoded.as_slice())))
		}
	}

	UtcTime {
		const TS_TYPE: &'static str = "string";
		const CONTRACT: &'static str =
			"Carries a UTCTime Sequence field as a YYYY-MM-DDTHH:MM:SSZ string, from 1970 to 2049.";

		#[cfg(target_arch = "wasm32")]
		fn read(value: &JsValue) -> Result<Self, FieldError> {
			const EXPECTED: &str = "a YYYY-MM-DDTHH:MM:SSZ time from 1970 to 2049";

			let datetime = JsField::from(value).date_time(EXPECTED)?;
			UtcTime::from_date_time(datetime).map_err(|cause| FieldError::refused(EXPECTED, cause))
		}

		#[cfg(target_arch = "wasm32")]
		fn project(&self) -> Result<JsValue, FieldError> {
			Ok(JsValue::from_str(&self.to_date_time().to_string()))
		}
	}

	GeneralizedTime {
		const TS_TYPE: &'static str = "string";
		const CONTRACT: &'static str =
			"Carries a GeneralizedTime Sequence field as a YYYY-MM-DDTHH:MM:SSZ string, from 1970 to 9999.";

		#[cfg(target_arch = "wasm32")]
		fn read(value: &JsValue) -> Result<Self, FieldError> {
			let datetime = JsField::from(value).date_time("a YYYY-MM-DDTHH:MM:SSZ time from 1970 to 9999")?;
			Ok(GeneralizedTime::from_date_time(datetime))
		}

		#[cfg(target_arch = "wasm32")]
		fn project(&self) -> Result<JsValue, FieldError> {
			Ok(JsValue::from_str(&self.to_date_time().to_string()))
		}
	}
}

/// The text of a TypeScript declaration, joined at compile time from its parts.
pub struct TsSection;

impl TsSection {
	/// The length of `parts` joined.
	#[must_use]
	pub const fn len(parts: &[&str]) -> usize {
		let mut len = 0;
		let mut index = 0;
		while index < parts.len() {
			len += parts[index].len();
			index += 1;
		}

		len
	}

	/// The bytes of `parts` joined, `N` long. The expansion of
	/// [`__ts_section`](crate::__ts_section) sets `N` to the
	/// [`TsSection::len`] of `parts`.
	#[must_use]
	pub const fn join<const N: usize>(parts: &[&str]) -> [u8; N] {
		let mut bytes = [0; N];
		let mut at = 0;
		let mut index = 0;
		while index < parts.len() {
			let part = parts[index].as_bytes();
			let mut offset = 0;
			while offset < part.len() {
				bytes[at] = part[offset];
				at += 1;
				offset += 1;
			}
			index += 1;
		}

		bytes
	}

	/// `text` as one line of a JSDoc block.
	///
	/// # Panics
	///
	/// Panics when `text` holds `*/`, which would end the block.
	#[must_use]
	pub const fn doc_line(text: &'static str) -> &'static str {
		let bytes = text.as_bytes();
		let mut index = 1;
		while index < bytes.len() {
			if bytes[index - 1] == b'*' && bytes[index] == b'/' {
				panic!("a JsLeaf CONTRACT holds */, which would end the JSDoc block of its field");
			}

			index += 1;
		}

		text
	}
}

/// The `&'static str` of the TypeScript declaration that joins the parts of
/// the `&[&str]` expression `$parts`, which the build evaluates.
///
/// The expansion sizes the join by the parts, so the bytes hold whole `str`
/// parts, and the conversion to text holds for every input.
#[doc(hidden)]
#[macro_export]
macro_rules! __ts_section {
	($parts:expr) => {{
		const PARTS: &[&str] = $parts;
		const LEN: usize = $crate::__private::TsSection::len(PARTS);
		const BYTES: [u8; LEN] = $crate::__private::TsSection::join::<LEN>(PARTS);
		const TEXT: &str = match ::core::str::from_utf8(&BYTES) {
			::core::result::Result::Ok(text) => text,
			::core::result::Result::Err(_) => ::core::panic!("the joined parts of a TypeScript declaration are UTF-8"),
		};

		TEXT
	}};
}

#[cfg(test)]
mod tests {
	use alloc::borrow::ToOwned;
	use alloc::format;
	use alloc::string::String;
	use alloc::vec::Vec;

	use super::*;

	/// The field-map row of `T`: its Rust name, its TypeScript type, and its
	/// JSDoc.
	pub(super) fn row<T: JsLeaf>() -> [String; 3] {
		let path = core::any::type_name::<T>();
		let rust = path.rsplit("::").next().unwrap_or(path);
		[format!("`{rust}`"), format!("`{}`", T::TS_TYPE), T::CONTRACT.to_owned()]
	}

	/// Each row of the field map of `docs/asn.md`: the table under its
	/// `Rust leaf` header.
	fn field_map() -> Vec<[String; 3]> {
		let page = include_str!("../../../docs/asn.md");
		let table = page.lines().skip_while(|line| !line.starts_with("| Rust leaf"));
		let body = table.skip(2).take_while(|line| line.starts_with('|'));
		let mut rows: Vec<[String; 3]> = body
			.map(|line| {
				let mut cells = line.split('|').skip(1).map(|cell| cell.trim().to_owned());
				[0; 3].map(|_| cells.next().unwrap_or_default())
			})
			.collect();
		rows.sort();
		rows
	}

	#[test]
	fn the_field_map_of_the_docs_holds_each_leaf_and_no_other_row() {
		let mut rows = leaves();
		rows.sort();
		assert_eq!(field_map(), rows);
	}
}
