//! The errors of the store.

use tightbeam::urn::UrnValidationError;
use tightbeam::{Errorizable, TightBeamError};

use crate::frame_type::FrameType;
use crate::schema::Field;

/// A refusal or a failure of the store.
#[derive(Debug, Errorizable)]
#[non_exhaustive]
pub enum StoreError {
	/// A row id holds 0 bytes, or more than 512.
	#[error("a row id holds {0} bytes, outside 1 to 512")]
	RowIdLength(usize),

	/// A sort key of the KV port holds 0 bytes, or more than 621.
	#[error("a sort key holds {0} bytes, outside 1 to 621")]
	SortKeyLength(usize),

	/// A URN is no store URN, such as one of another NID or with no row id part.
	#[error("the URN names no store row: {0}")]
	#[from]
	Urn(UrnValidationError),

	/// A store URN in another spelling: an NID not in lowercase, or an r-,
	/// q-, or f-component.
	#[error("the URN spells a store URN another way: its NID is not lowercase, or it holds an r-, q-, or f-component")]
	NonCanonicalUrn,

	/// The row id part of a store URN is no lowercase hex of 1 to 512 bytes.
	#[error("the row id of the URN is no lowercase hex of 1 to 512 bytes")]
	UrnRowId,

	/// A store URN names a row of another table.
	#[error("the URN names a row of table {found}, not {expected}")]
	ForeignTable {
		/// The table the caller asked for.
		expected: FrameType,
		/// The table the URN names.
		found: String,
	},

	/// A frame carries a value of more than 100 bytes in a field that holds at
	/// most 100.
	#[error("the frame carries a {field} value of {length} bytes, past 100")]
	FieldLength {
		/// The field of the value.
		field: Field,
		/// The length of the value, in bytes.
		length: usize,
	},

	/// A frame carries more values in a field than it holds.
	#[error("the frame carries more than 32 values of {field}")]
	FieldCount {
		/// The field of the values.
		field: Field,
	},

	/// A frame does not encode, or its metadata does not project.
	#[error("the frame does not project: {0}")]
	Frame(TightBeamError),
}
