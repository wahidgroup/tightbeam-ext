//! The crate and type that own a table: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#tables).

use core::fmt;

/// The longest crate name or type name of an owner, in bytes.
const MAX_PART: usize = 64;

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
			panic!("the crate of an owner holds 1 to 64 bytes");
		}
		if type_len == 0 || type_len > MAX_PART {
			panic!("the type of an owner holds 1 to 64 bytes");
		}

		let mut index = 0;
		while index < split {
			let byte = bytes[index];
			let admitted = byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_';
			if !admitted {
				panic!("the crate of an owner holds ASCII letters, digits, hyphens, and underscores alone");
			}

			index += 1;
		}

		let first = bytes[type_start];
		if !(first.is_ascii_alphabetic() || first == b'_') {
			panic!("the type of an owner starts with an ASCII letter or an underscore");
		}
		if first == b'_' && type_len == 1 {
			panic!("the type of an owner is an identifier, and `_` is none");
		}

		let mut index = type_start;
		while index < bytes.len() {
			let byte = bytes[index];
			if !(byte.is_ascii_alphanumeric() || byte == b'_') {
				panic!("the type of an owner holds ASCII letters, digits, and underscores alone");
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

		panic!("an owner is written `crate::Type`")
	}
}

impl fmt::Display for Owner {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.0)
	}
}

#[cfg(test)]
mod tests {
	use std::panic;

	use super::*;

	tightbeam::tb_cases! {
		fn a_crate_and_type_is_an_owner(name: &'static str) {
			assert_eq!(Owner::from_static(name).as_str(), name);
		}
		cases {
			plain => "colony::HiveLeaf",
			hyphenated_crate => "tightbeam-store::Leaf",
			underscore_type => "colony::_Leaf2",
			one_byte_parts => "c::L",
			longest_crate => "a234567890123456789012345678901234567890123456789012345678901234::L",
			longest_type => "c::A234567890123456789012345678901234567890123456789012345678901234",
		}
	}

	#[test]
	fn a_name_with_no_separator_is_refused_as_unwritten() {
		let refusal = panic::catch_unwind(|| Owner::from_static("colony:")).err();
		let message = refusal.as_ref().and_then(|payload| payload.downcast_ref::<&str>());
		assert_eq!(message, Some(&"an owner is written `crate::Type`"));
	}

	#[test]
	fn an_owner_displays_as_written() {
		assert_eq!(Owner::from_static("colony::HiveLeaf").to_string(), "colony::HiveLeaf");
	}

	tightbeam::tb_cases! {
		fn a_name_outside_the_grammar_panics(name: &'static str) {
			assert!(panic::catch_unwind(|| Owner::from_static(name)).is_err());
		}
		cases {
			empty => "",
			no_separator => "colony",
			single_colon => "colony:Leaf",
			two_separators => "colony::hive::Leaf",
			empty_crate => "::Leaf",
			empty_type => "colony::",
			leading_digit_type => "colony::9Leaf",
			hyphen_in_type => "colony::Hive-Leaf",
			space_in_crate => "my colony::Leaf",
			long_crate => "a2345678901234567890123456789012345678901234567890123456789012345::Leaf",
			long_type => "colony::A2345678901234567890123456789012345678901234567890123456789012345",
			trailing_colon => "colony::Leaf:",
			underscore_alone => "colony::_",
			non_ascii_type => "colony::Leaf\u{e9}",
		}
	}
}
