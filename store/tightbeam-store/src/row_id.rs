//! The key of a row within its table: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#row-ids).

use tightbeam::der::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Tag, Writer};

use crate::error::StoreError;

/// The longest row id, in bytes.
pub(crate) const MAX_LEN: usize = 512;

/// The lowercase hex digits of a row id in a URN.
const HEX: &[u8; 16] = b"0123456789abcdef";

/// The key of a row within its table: 1 to 512 bytes.
///
/// A message field of this type encodes as a DER OCTET STRING, and a decode
/// refuses one outside the bounds.
///
/// # Examples
///
/// ```
/// use tightbeam_store::{RowId, StoreError};
///
/// let id = RowId::try_from(b"leaf-42".as_slice())?;
/// assert_eq!(id, RowId::from(*b"leaf-42"));
/// assert!(RowId::try_from(Vec::new()).is_err());
/// # Ok::<(), StoreError>(())
/// ```
///
/// `From<[u8; N]>` checks `N` when the crate builds. One and 512 bytes build:
///
/// ```
/// # use tightbeam_store::RowId;
/// let shortest = RowId::from([0u8; 1]);
/// let longest = RowId::from([0u8; 512]);
/// ```
///
/// No bytes do not:
///
/// ```compile_fail
/// # use tightbeam_store::RowId;
/// let shortest = RowId::from([0u8; 0]);
/// let longest = RowId::from([0u8; 512]);
/// ```
///
/// Nor do 513:
///
/// ```compile_fail
/// # use tightbeam_store::RowId;
/// let shortest = RowId::from([0u8; 1]);
/// let longest = RowId::from([0u8; 513]);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RowId(Vec<u8>);

impl RowId {
	/// The row id that `text` spells in lowercase hex, two digits per byte.
	pub(crate) fn from_hex(text: &str) -> Option<Self> {
		let digits = text.as_bytes();
		if !digits.len().is_multiple_of(2) {
			return None;
		}

		let mut bytes = Vec::with_capacity(digits.len() / 2);
		for pair in digits.chunks_exact(2) {
			let high = Self::nibble(pair[0])?;
			let low = Self::nibble(pair[1])?;
			bytes.push((high << 4) + low);
		}

		Self::try_from(bytes).ok()
	}

	/// The lowercase hex of this row id, two digits per byte.
	pub(crate) fn to_hex(&self) -> String {
		let mut text = String::with_capacity(self.0.len() * 2);
		for byte in &self.0 {
			text.push(char::from(HEX[usize::from(byte >> 4)]));
			text.push(char::from(HEX[usize::from(byte & 0x0f)]));
		}

		text
	}

	/// Whether a row id holds `len` bytes: 1 to 512.
	const fn fits(len: usize) -> bool {
		0 < len && len <= MAX_LEN
	}

	/// The value of the lowercase hex digit `digit`.
	fn nibble(digit: u8) -> Option<u8> {
		match digit {
			b'0'..=b'9' => Some(digit - b'0'),
			b'a'..=b'f' => Some(digit - b'a' + 10),
			_ => None,
		}
	}
}

impl TryFrom<Vec<u8>> for RowId {
	type Error = StoreError;

	/// The row id `bytes`.
	///
	/// # Errors
	///
	/// - [`StoreError::RowIdLength`] -- `bytes` holds 0 bytes, or more than 512.
	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		if !Self::fits(bytes.len()) {
			return Err(StoreError::RowIdLength(bytes.len()));
		}

		Ok(Self(bytes))
	}
}

impl TryFrom<&[u8]> for RowId {
	type Error = StoreError;

	/// The row id of a copy of `bytes`.
	///
	/// # Errors
	///
	/// - [`StoreError::RowIdLength`] -- `bytes` holds 0 bytes, or more than 512.
	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		Self::try_from(bytes.to_vec())
	}
}

impl<const N: usize> From<[u8; N]> for RowId {
	/// The row id `bytes`, whose length the compiler checks: a length outside
	/// 1 to 512 fails the build.
	fn from(bytes: [u8; N]) -> Self {
		const { assert!(Self::fits(N), "a row id holds 1 to 512 bytes") };
		Self(bytes.to_vec())
	}
}

impl AsRef<[u8]> for RowId {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl AsRef<RowId> for RowId {
	fn as_ref(&self) -> &RowId {
		self
	}
}

impl FixedTag for RowId {
	const TAG: Tag = Tag::OctetString;
}

impl EncodeValue for RowId {
	fn value_len(&self) -> tightbeam::der::Result<Length> {
		Length::try_from(self.0.len())
	}

	fn encode_value(&self, writer: &mut impl Writer) -> tightbeam::der::Result<()> {
		writer.write(&self.0)
	}
}

impl<'a> DecodeValue<'a> for RowId {
	/// The row id of the content of one OCTET STRING. The length of the
	/// header is checked before the read, since the read allocates it.
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> tightbeam::der::Result<Self> {
		let len = usize::try_from(header.length)?;
		if !Self::fits(len) {
			return Err(Self::TAG.value_error());
		}

		let bytes = reader.read_vec(header.length)?;
		Ok(Self(bytes))
	}
}

#[cfg(test)]
mod tests {
	use tightbeam::der::{Decode, Encode};

	use super::*;

	tightbeam::tb_cases! {
		fn a_length_in_bounds_is_a_row_id(len: usize) {
			let bytes = vec![7u8; len];
			let from_slice = RowId::try_from(bytes.as_slice()).map(|id| id.0);
			let from_vec = RowId::try_from(bytes.clone()).map(|id| id.0);
			assert_eq!((from_slice.ok(), from_vec.ok()), (Some(bytes.clone()), Some(bytes)));
		}
		cases {
			one_byte => 1,
			longest => 512,
		}
	}

	tightbeam::tb_cases! {
		fn a_length_out_of_bounds_is_refused(len: usize) {
			let bytes = vec![7u8; len];
			let from_slice = RowId::try_from(bytes.as_slice());
			let from_vec = RowId::try_from(bytes);
			assert!(matches!(from_slice, Err(StoreError::RowIdLength(found)) if found == len));
			assert!(matches!(from_vec, Err(StoreError::RowIdLength(found)) if found == len));
		}
		cases {
			empty => 0,
			one_past_the_longest => 513,
		}
	}

	#[test]
	fn a_fixed_array_is_a_row_id() {
		let id = RowId::from(*b"ab");
		assert_eq!(AsRef::<[u8]>::as_ref(&id), b"ab");
	}

	tightbeam::tb_cases! {
		fn hex_round_trips(bytes: &'static [u8]) -> Result<(), StoreError> {
			let id = RowId::try_from(bytes)?;
			assert_eq!(RowId::from_hex(&id.to_hex()), Some(id));
			Ok(())
		}
		cases {
			ascii => b"leaf-42",
			every_nibble => &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
			zero_and_high => &[0x00, 0xff],
		}
	}

	#[test]
	fn hex_is_lowercase_and_two_digits_per_byte() -> Result<(), StoreError> {
		let id = RowId::try_from([0x0a, 0xb0].as_slice())?;
		assert_eq!(id.to_hex(), "0ab0");
		Ok(())
	}

	tightbeam::tb_cases! {
		fn hex_outside_the_form_is_refused(text: &'static str) {
			assert_eq!(RowId::from_hex(text), None);
		}
		cases {
			empty => "",
			odd_length => "abc",
			uppercase => "0A",
			non_hex => "zz",
			prefixed => "0x00",
			too_long => "00".repeat(513).leak(),
		}
	}

	tightbeam::tb_cases! {
		fn der_is_an_octet_string((bytes, encoded): (Vec<u8>, Vec<u8>)) -> Result<(), tightbeam::der::Error> {
			let id = RowId::try_from(bytes).map_err(|_| Tag::OctetString.value_error())?;
			assert_eq!(id.to_der()?, encoded);
			assert_eq!(RowId::from_der(&encoded)?, id);
			Ok(())
		}
		cases {
			one_byte => (vec![0x61], vec![0x04, 0x01, 0x61]),
			two_bytes => (b"ab".to_vec(), vec![0x04, 0x02, 0x61, 0x62]),
			longest => (vec![0xab; 512], [&[0x04, 0x82, 0x02, 0x00][..], &[0xab; 512]].concat()),
		}
	}

	tightbeam::tb_cases! {
		fn der_refuses_an_octet_string_out_of_bounds(encoded: Vec<u8>) {
			let refused = RowId::from_der(&encoded).err().map(|error| error.kind());
			assert_eq!(refused, Some(Tag::OctetString.value_error().kind()));
		}
		cases {
			empty => vec![0x04, 0x00],
			one_past_the_longest => [&[0x04, 0x82, 0x02, 0x01][..], &[1u8; 513]].concat(),
			/// A header of 0x0fff_ffff bytes and no content: the bound refuses
			/// it before the read allocates the length.
			longest_header_without_content => vec![0x04, 0x84, 0x0f, 0xff, 0xff, 0xff],
		}
	}
}
