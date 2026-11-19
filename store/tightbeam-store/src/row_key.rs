//! The identity of one row, and its URN: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#urns).

use tightbeam::urn::Urn;

use crate::error::StoreError;
use crate::frame_type::FrameType;
use crate::row_id::RowId;
use crate::urn_spec::StoreUrn;

/// The identity of one row: its table and its row id, with the URN they name.
///
/// The URN is `urn:tightbeam:store:{frame_type}:{row_id}`, with the row id in
/// lowercase hex. One row id in two tables names two rows, with two URNs.
///
/// # Examples
///
/// ```
/// use tightbeam_store::{FrameType, RowId, RowKey, StoreError};
///
/// const LEAF: FrameType = FrameType::from_static("colony-leaf");
///
/// let key = RowKey::new(LEAF, RowId::from(*b"leaf-42"))?;
/// assert_eq!(key.urn().to_string(), "urn:tightbeam:store:colony-leaf:6c6561662d3432");
/// # Ok::<(), StoreError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RowKey {
	frame_type: FrameType,
	row_id: RowId,
	urn: Urn<'static>,
}

impl RowKey {
	/// The key of the row `row_id` of the table `frame_type`.
	///
	/// # Errors
	///
	/// - [`StoreError::Urn`] -- tightbeam refuses the URN of the key. The
	///   grammar of a frame type and the hex of a row id meet the store URN
	///   spec, so this answers only a defect of that spec.
	pub fn new(frame_type: FrameType, row_id: RowId) -> Result<Self, StoreError> {
		let urn = StoreUrn::build(frame_type, &row_id)?;
		Ok(Self { frame_type, row_id, urn })
	}

	/// The table of the row.
	pub fn frame_type(&self) -> FrameType {
		self.frame_type
	}

	/// The id of the row within its table.
	pub fn row_id(&self) -> &RowId {
		&self.row_id
	}

	/// The URN of the row.
	pub fn urn(&self) -> &Urn<'static> {
		&self.urn
	}
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;

	use super::*;

	const LEAF: FrameType = FrameType::from_static("colony-leaf");
	const SEED: FrameType = FrameType::from_static("colony-seed");

	#[test]
	fn a_key_names_its_canonical_urn() -> Result<(), StoreError> {
		let key = RowKey::new(LEAF, RowId::from([0x00, 0xab]))?;
		assert_eq!(key.urn().to_string(), "urn:tightbeam:store:colony-leaf:00ab");
		Ok(())
	}

	#[test]
	fn a_urn_resolves_to_its_row_id() -> Result<(), StoreError> {
		let key = RowKey::new(LEAF, RowId::from(*b"leaf-42"))?;
		assert_eq!(LEAF.row_id_of(key.urn())?, *key.row_id());
		Ok(())
	}

	#[test]
	fn one_row_id_in_two_tables_names_two_urns() -> Result<(), StoreError> {
		let id = RowId::from(*b"42");
		let leaf = RowKey::new(LEAF, id.clone())?;
		let seed = RowKey::new(SEED, id)?;
		assert_ne!(leaf.urn(), seed.urn());
		Ok(())
	}

	#[test]
	fn a_urn_of_another_table_is_refused() -> Result<(), StoreError> {
		let key = RowKey::new(SEED, RowId::from(*b"42"))?;
		let refused = LEAF.row_id_of(key.urn());
		assert!(
			matches!(refused, Err(StoreError::ForeignTable { expected, found }) if expected == LEAF && found == "colony-seed")
		);
		Ok(())
	}

	tightbeam::tb_cases! {
		fn a_urn_outside_the_store_spec_is_refused(text: &'static str) -> Result<(), StoreError> {
			let urn = Urn::from_str(text)?;
			assert!(matches!(LEAF.row_id_of(&urn), Err(StoreError::Urn(_))));
			Ok(())
		}
		cases {
			other_nid => "urn:other:store:colony-leaf:00ab",
			other_category => "urn:tightbeam:instrumentation:colony-leaf:00ab",
			table_outside_the_pattern => "urn:tightbeam:store:colony.leaf:00ab",
			no_row_id_part => "urn:tightbeam:store:colony-leaf",
		}
	}

	tightbeam::tb_cases! {
		fn a_store_urn_spelled_another_way_is_refused(text: &'static str) -> Result<(), StoreError> {
			let urn = Urn::from_str(text)?;
			assert!(matches!(LEAF.row_id_of(&urn), Err(StoreError::NonCanonicalUrn)));
			Ok(())
		}
		cases {
			uppercase_nid => "urn:TIGHTBEAM:store:colony-leaf:00ab",
			mixed_case_nid => "urn:TightBeam:store:colony-leaf:00ab",
			q_component => "urn:tightbeam:store:colony-leaf:00ab?=q",
			r_component => "urn:tightbeam:store:colony-leaf:00ab?+r",
			f_component => "urn:tightbeam:store:colony-leaf:00ab#frag",
			empty_f_component => "urn:tightbeam:store:colony-leaf:00ab#",
		}
	}

	tightbeam::tb_cases! {
		fn a_row_id_outside_lowercase_hex_is_refused(text: &'static str) -> Result<(), StoreError> {
			let urn = Urn::from_str(text)?;
			assert!(matches!(LEAF.row_id_of(&urn), Err(StoreError::UrnRowId)));
			Ok(())
		}
		cases {
			empty => "urn:tightbeam:store:colony-leaf:",
			uppercase => "urn:tightbeam:store:colony-leaf:00AB",
			odd_length => "urn:tightbeam:store:colony-leaf:0ab",
			non_hex_letter => "urn:tightbeam:store:colony-leaf:0g",
			dot => "urn:tightbeam:store:colony-leaf:00.b",
			percent_encoded => "urn:tightbeam:store:colony-leaf:00%61b",
			extra_segment => "urn:tightbeam:store:colony-leaf:00ab:ff",
			non_hex_with_an_uppercase_nid => "urn:TIGHTBEAM:store:colony-leaf:0g",
			dot_with_an_uppercase_nid => "urn:TIGHTBEAM:store:colony-leaf:00.b",
			empty_with_an_uppercase_nid => "urn:TIGHTBEAM:store:colony-leaf:",
			non_hex_with_a_q_component => "urn:tightbeam:store:colony-leaf:0g?=q",
			dot_with_a_q_component => "urn:tightbeam:store:colony-leaf:00.b?=q",
		}
	}

	#[test]
	fn a_bad_row_id_answers_before_the_table_compare() -> Result<(), StoreError> {
		let urn = Urn::from_str("urn:tightbeam:store:colony-seed:0g")?;
		assert!(matches!(LEAF.row_id_of(&urn), Err(StoreError::UrnRowId)));
		Ok(())
	}

	#[test]
	fn a_spelling_fault_answers_before_the_table_compare() -> Result<(), StoreError> {
		let urn = Urn::from_str("urn:TIGHTBEAM:store:colony-seed:00ab")?;
		assert!(matches!(LEAF.row_id_of(&urn), Err(StoreError::NonCanonicalUrn)));
		Ok(())
	}

	#[test]
	fn a_table_spelled_another_way_names_another_table() -> Result<(), StoreError> {
		let urn = Urn::from_str("urn:tightbeam:store:Colony-leaf:00ab")?;
		assert!(matches!(LEAF.row_id_of(&urn), Err(StoreError::ForeignTable { .. })));
		Ok(())
	}
}
