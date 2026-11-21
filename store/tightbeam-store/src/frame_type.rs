//! The name of the table of one `Storable` type: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#tables).

use core::fmt;

use tightbeam::urn::Urn;

use crate::error::StoreError;
use crate::row_id::RowId;
use crate::urn_spec::StoreUrn;

/// The longest frame type, in bytes.
pub(crate) const MAX_LEN: usize = 63;

/// The prefix that names the tables of this crate.
const RESERVED: &[u8] = b"tightbeam-";

/// The refusal of a name of no byte, or of more than 63.
const LENGTH_REFUSAL: &str = "a frame type holds 1 to 63 bytes";

/// The refusal of a name that starts with no lowercase letter.
const FIRST_REFUSAL: &str = "a frame type starts with a lowercase ASCII letter";

/// The refusal of a name with a byte outside the grammar.
const BYTE_REFUSAL: &str = "a frame type holds lowercase ASCII letters, digits, and hyphens alone";

/// The refusal of a name with the reserved prefix.
const PREFIX_REFUSAL: &str = "the tightbeam- prefix of a frame type is reserved";

/// The name of the table that one [`Storable`](crate::Storable) type fills.
///
/// A frame type holds 1 to 63 lowercase ASCII letters, digits, and hyphens,
/// and starts with a letter. The `tightbeam-` prefix is reserved.
///
/// # Examples
///
/// ```
/// use tightbeam_store::FrameType;
///
/// const LEAF: FrameType = FrameType::from_static("colony-leaf");
/// assert_eq!(LEAF.as_str(), "colony-leaf");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameType(&'static str);

impl FrameType {
	/// The frame type `name`.
	///
	/// # Panics
	///
	/// - `name` breaks the grammar of a frame type. In a `const` item, the
	///   panic is a compile error.
	pub const fn from_static(name: &'static str) -> Self {
		let bytes = name.as_bytes();
		if bytes.is_empty() || bytes.len() > MAX_LEN {
			panic!("{}", LENGTH_REFUSAL);
		}
		if !bytes[0].is_ascii_lowercase() {
			panic!("{}", FIRST_REFUSAL);
		}

		let mut index = 0;
		while index < bytes.len() {
			if !Self::admits(bytes[index]) {
				panic!("{}", BYTE_REFUSAL);
			}

			index += 1;
		}

		if Self::starts_with(bytes, RESERVED) {
			panic!("{}", PREFIX_REFUSAL);
		}

		Self(name)
	}

	/// Whether a frame type takes `byte`: a lowercase ASCII letter, a digit,
	/// or a hyphen.
	pub(crate) const fn admits(byte: u8) -> bool {
		byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
	}

	/// The name of the table.
	pub const fn as_str(&self) -> &'static str {
		self.0
	}

	/// Whether `self` and `other` name one table, in a `const` context.
	pub(crate) const fn same_as(&self, other: &Self) -> bool {
		let left = self.0.as_bytes();
		let right = other.0.as_bytes();
		left.len() == right.len() && Self::starts_with(left, right)
	}

	/// The row of this table that `urn` names.
	///
	/// # Errors
	///
	/// The errors answer in this order, so a URN with two faults always gets
	/// the first:
	///
	/// - [`StoreError::Urn`] -- `urn` is no store URN.
	/// - [`StoreError::UrnRowId`] -- the row id part of `urn` is no lowercase hex of 1 to 512 bytes.
	/// - [`StoreError::NonCanonicalUrn`] -- `urn` spells a store URN another way.
	/// - [`StoreError::ForeignTable`] -- `urn` names a row of another table.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam_store::{FrameType, RowId, RowKey, StoreError};
	///
	/// const LEAF: FrameType = FrameType::from_static("colony-leaf");
	///
	/// let key = RowKey::new(LEAF, RowId::from(*b"leaf-42"))?;
	/// assert_eq!(LEAF.row_id_of(key.urn())?, *key.row_id());
	/// # Ok::<(), StoreError>(())
	/// ```
	pub fn row_id_of(&self, urn: &Urn<'_>) -> Result<RowId, StoreError> {
		let parsed = StoreUrn::read(urn)?;
		if parsed.frame_type() != self.0 {
			let found = parsed.frame_type().to_owned();
			return Err(StoreError::ForeignTable { expected: *self, found });
		}

		Ok(parsed.into_row_id())
	}

	/// Whether `bytes` starts with `prefix`, in a `const` context.
	const fn starts_with(bytes: &[u8], prefix: &[u8]) -> bool {
		if bytes.len() < prefix.len() {
			return false;
		}

		let mut index = 0;
		while index < prefix.len() {
			if bytes[index] != prefix[index] {
				return false;
			}

			index += 1;
		}

		true
	}
}

impl AsRef<str> for FrameType {
	fn as_ref(&self) -> &str {
		self.0
	}
}

impl fmt::Display for FrameType {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.0)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_support::panic_message;

	tightbeam::tb_cases! {
		fn a_valid_name_is_a_frame_type(name: &'static str) {
			assert_eq!(FrameType::from_static(name).as_str(), name);
		}
		cases {
			one_letter => "a",
			hyphenated => "colony-leaf",
			digits_after_the_first_letter => "v2-block-9",
			trailing_hyphen => "leaf-",
			longest => "a23456789012345678901234567890123456789012345678901234567890123",
			reserved_word_without_the_prefix => "tightbeam",
		}
	}

	tightbeam::tb_cases! {
		fn a_name_outside_the_grammar_panics((name, message): (&'static str, &'static str)) {
			assert_eq!(panic_message(|| FrameType::from_static(name)).as_deref(), Some(message));
		}
		cases {
			empty => ("", LENGTH_REFUSAL),
			too_long => ("a234567890123456789012345678901234567890123456789012345678901234", LENGTH_REFUSAL),
			uppercase => ("Colony-leaf", FIRST_REFUSAL),
			leading_digit => ("9leaf", FIRST_REFUSAL),
			leading_hyphen => ("-leaf", FIRST_REFUSAL),
			uppercase_inside => ("colony-Leaf", BYTE_REFUSAL),
			dot => ("colony.leaf", BYTE_REFUSAL),
			underscore => ("colony_leaf", BYTE_REFUSAL),
			non_ascii => ("leaf\u{e9}", BYTE_REFUSAL),
			/// The loop reads the last byte too.
			bad_last_byte => ("leaf.", BYTE_REFUSAL),
			reserved_prefix => ("tightbeam-claims", PREFIX_REFUSAL),
			reserved_prefix_alone => ("tightbeam-", PREFIX_REFUSAL),
		}
	}

	#[test]
	fn a_frame_type_reads_and_displays_as_its_name() {
		let leaf = FrameType::from_static("colony-leaf");
		assert_eq!((leaf.as_ref(), leaf.to_string().as_str()), ("colony-leaf", "colony-leaf"));
	}

	tightbeam::tb_cases! {
		fn same_as_compares_names((left, right, same): (&'static str, &'static str, bool)) {
			assert_eq!(FrameType::from_static(left).same_as(&FrameType::from_static(right)), same);
		}
		cases {
			equal => ("colony-leaf", "colony-leaf", true),
			prefix => ("colony", "colony-leaf", false),
			longer => ("colony-leaf", "colony", false),
			other => ("colony-leaf", "colony-seed", false),
		}
	}
}
