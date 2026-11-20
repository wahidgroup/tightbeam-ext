//! The crate and type that own a table: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#tables).

use core::fmt;

/// The longest crate name or type name of an owner, in bytes.
const MAX_PART: usize = 64;

/// The refusal of a name with no `::`.
const UNWRITTEN_REFUSAL: &str = "an owner is written `crate::Type`";

/// The refusal of a crate part of no byte, or of more than 64.
const CRATE_LENGTH_REFUSAL: &str = "the crate of an owner holds 1 to 64 bytes";

/// The refusal of a type part of no byte, or of more than 64.
const TYPE_LENGTH_REFUSAL: &str = "the type of an owner holds 1 to 64 bytes";

/// The refusal of a crate part with a byte outside its grammar.
const CRATE_BYTE_REFUSAL: &str = "the crate of an owner holds ASCII letters, digits, hyphens, and underscores alone";

/// The refusal of a type part that starts with no letter or underscore.
const TYPE_FIRST_REFUSAL: &str = "the type of an owner starts with an ASCII letter or an underscore";

/// The refusal of the type part `_`, which is no identifier.
const UNDERSCORE_REFUSAL: &str = "the type of an owner is an identifier, and `_` is none";

/// The refusal of a type part with a byte outside its grammar.
const TYPE_BYTE_REFUSAL: &str = "the type of an owner holds ASCII letters, digits, and underscores alone";

/// The crate and type that own a table, written `crate::Type`.
///
/// The crate part holds 1 to 64 ASCII letters, digits, hyphens, and
/// underscores. The type part is an ASCII Rust identifier of 1 to 64 bytes.
///
/// # Examples
///
/// ```
/// use tightbeam_store::Owner;
///
/// const OWNER: Owner = Owner::from_static("colony::HiveLeaf");
/// assert_eq!(OWNER.as_str(), "colony::HiveLeaf");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Owner(&'static str);

impl Owner {
	/// The owner `name`, written `crate::Type`.
	///
	/// # Panics
	///
	/// - `name` is no `crate::Type`. In a `const` item, the panic is a compile
	///   error.
	pub const fn from_static(name: &'static str) -> Self {
		let bytes = name.as_bytes();
		let split = Self::separator(bytes);
		let type_start = split + 2;
		let type_len = bytes.len() - type_start;
		if split == 0 || split > MAX_PART {
			panic!("{}", CRATE_LENGTH_REFUSAL);
		}
		if type_len == 0 || type_len > MAX_PART {
			panic!("{}", TYPE_LENGTH_REFUSAL);
		}

		let mut index = 0;
		while index < split {
			let byte = bytes[index];
			let admitted = byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_';
			if !admitted {
				panic!("{}", CRATE_BYTE_REFUSAL);
			}

			index += 1;
		}

		let first = bytes[type_start];
		if !(first.is_ascii_alphabetic() || first == b'_') {
			panic!("{}", TYPE_FIRST_REFUSAL);
		}
		if first == b'_' && type_len == 1 {
			panic!("{}", UNDERSCORE_REFUSAL);
		}

		let mut index = type_start;
		while index < bytes.len() {
			let byte = bytes[index];
			if !(byte.is_ascii_alphanumeric() || byte == b'_') {
				panic!("{}", TYPE_BYTE_REFUSAL);
			}

			index += 1;
		}

		Self(name)
	}

	/// The owner, written `crate::Type`.
	pub const fn as_str(&self) -> &'static str {
		self.0
	}

	/// The index of the first `::` of `bytes`. Neither part admits a colon, so
	/// the grammar of each part refuses a second one.
	///
	/// # Panics
	///
	/// - `bytes` holds no `::`.
	const fn separator(bytes: &[u8]) -> usize {
		let mut index = 0;
		while index + 1 < bytes.len() {
			if bytes[index] == b':' && bytes[index + 1] == b':' {
				return index;
			}

			index += 1;
		}

		panic!("{}", UNWRITTEN_REFUSAL)
	}
}

impl fmt::Display for Owner {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.0)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_support::panic_message;

	tightbeam::tb_cases! {
		fn a_crate_and_type_is_an_owner(name: &'static str) {
			assert_eq!(Owner::from_static(name).as_str(), name);
		}
		cases {
			plain => "colony::HiveLeaf",
			hyphenated_crate => "tightbeam-store::Leaf",
			underscored_crate => "my_crate::Leaf",
			underscore_type => "colony::_Leaf2",
			one_byte_parts => "c::L",
			longest_crate => "a234567890123456789012345678901234567890123456789012345678901234::L",
			longest_type => "c::A234567890123456789012345678901234567890123456789012345678901234",
		}
	}

	#[test]
	fn an_owner_displays_as_written() {
		assert_eq!(Owner::from_static("colony::HiveLeaf").to_string(), "colony::HiveLeaf");
	}

	tightbeam::tb_cases! {
		fn a_name_outside_the_grammar_panics((name, message): (&'static str, &'static str)) {
			assert_eq!(panic_message(|| Owner::from_static(name)).as_deref(), Some(message));
		}
		cases {
			empty => ("", UNWRITTEN_REFUSAL),
			no_separator => ("colony", UNWRITTEN_REFUSAL),
			single_colon => ("colony:Leaf", UNWRITTEN_REFUSAL),
			/// A lone colon at the end leaves no byte after it to read.
			lone_trailing_colon => ("colony:", UNWRITTEN_REFUSAL),
			empty_crate => ("::Leaf", CRATE_LENGTH_REFUSAL),
			long_crate => ("a2345678901234567890123456789012345678901234567890123456789012345::Leaf", CRATE_LENGTH_REFUSAL),
			empty_type => ("colony::", TYPE_LENGTH_REFUSAL),
			long_type => ("colony::A2345678901234567890123456789012345678901234567890123456789012345", TYPE_LENGTH_REFUSAL),
			space_in_crate => ("my colony::Leaf", CRATE_BYTE_REFUSAL),
			/// The crate loop reads the byte before the separator too.
			bad_last_crate_byte => ("colony!::Leaf", CRATE_BYTE_REFUSAL),
			leading_digit_type => ("colony::9Leaf", TYPE_FIRST_REFUSAL),
			underscore_alone => ("colony::_", UNDERSCORE_REFUSAL),
			two_separators => ("colony::hive::Leaf", TYPE_BYTE_REFUSAL),
			hyphen_in_type => ("colony::Hive-Leaf", TYPE_BYTE_REFUSAL),
			trailing_colon => ("colony::Leaf:", TYPE_BYTE_REFUSAL),
			non_ascii_type => ("colony::Leaf\u{e9}", TYPE_BYTE_REFUSAL),
		}
	}
}
