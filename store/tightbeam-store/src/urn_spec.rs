//! The URN of a store row, `urn:tightbeam:store:{frame_type}:{row_id}`.

use std::borrow::Cow;

use tightbeam::urn::builders::spec::Pattern;
use tightbeam::urn::{Urn, UrnBuilder, UrnComponents, UrnSpec, UrnValidationError};

use crate::error::StoreError;
use crate::frame_type::FrameType;
use crate::row_id::RowId;

/// The component key of the category, which every store URN fixes to `store`.
const CATEGORY: &str = "category";

/// The component key of the table.
const FRAME_TYPE: &str = "frame_type";

/// The component key of the row id, in lowercase hex.
const ROW_ID: &str = "row_id";

tightbeam::urn_spec! {
	/// The spec of a store URN. `FrameType` and `RowId` hold the canonical
	/// form of each part, which the patterns admit.
	pub(crate) StoreUrnSpec,
	nid: "tightbeam",
	nss_structure {
		category: { value: "store", sep: ":" },
		frame_type: { pattern: Pattern::AlphaNumericHyphen, sep: ":" },
		row_id: { pattern: Pattern::AlphaNumeric }
	},
	nss_format: "{}:{}:{}"
}

/// The table and the row id that one store URN names. The table stays text,
/// since `FrameType` alone decides whether it names one of its own.
pub(crate) struct StoreUrn {
	frame_type: String,
	row_id: RowId,
}

impl StoreUrn {
	/// The URN of the row `row_id` of the table `frame_type`.
	///
	/// # Errors
	///
	/// - [`StoreError::Urn`] -- the spec refuses the parts.
	pub(crate) fn build(frame_type: FrameType, row_id: &RowId) -> Result<Urn<'static>, StoreError> {
		let builder = UrnBuilder::from(StoreUrnSpec)
			.set(CATEGORY, "store")
			.set(FRAME_TYPE, frame_type.as_str())
			.set(ROW_ID, row_id.to_hex());

		let urn = builder.build()?;
		Ok(urn.into_owned())
	}

	/// The parts of `urn`, read through the spec. A store URN has one
	/// spelling: the NID in lowercase, and no r-, q-, or f-component.
	///
	/// # Errors
	///
	/// The errors answer in this order, so a URN with two faults always gets
	/// the first:
	///
	/// - [`StoreError::Urn`] -- `urn` is no store URN.
	/// - [`StoreError::UrnRowId`] -- the row id part is no lowercase hex of 1 to 512 bytes.
	/// - [`StoreError::NonCanonicalUrn`] -- `urn` spells a store URN another way.
	pub(crate) fn read(urn: &Urn<'_>) -> Result<Self, StoreError> {
		urn.verify::<StoreUrnSpec>().map_err(Self::refusal)?;

		let components = StoreUrnSpec::components(urn.nss()).map_err(Self::refusal)?;
		let frame_type = Self::component(&components, FRAME_TYPE)?;
		let hex = Self::component(&components, ROW_ID)?;
		let row_id = RowId::from_hex(&hex).ok_or(StoreError::UrnRowId)?;

		let has_components = urn.r_component().is_some() || urn.q_component().is_some() || urn.f_component().is_some();
		if urn.nid() != StoreUrnSpec::NID || has_components {
			return Err(StoreError::NonCanonicalUrn);
		}

		Ok(Self { frame_type, row_id })
	}

	/// The table this URN names.
	pub(crate) fn frame_type(&self) -> &str {
		&self.frame_type
	}

	/// The row id this URN names.
	pub(crate) fn into_row_id(self) -> RowId {
		self.row_id
	}

	/// The value of the component `key` of `components`.
	///
	/// # Errors
	///
	/// - The [`StoreError`] of [`StoreUrn::refusal`] for a missing `key`.
	fn component<'a>(components: &impl UrnComponents<'a>, key: &'static str) -> Result<String, StoreError> {
		let value = components.get_component(key).map(Cow::to_string);
		value.ok_or_else(|| Self::refusal(UrnValidationError::RequiredFieldMissing(key)))
	}

	/// The store error of the spec refusal `error`: a refusal of the row id
	/// part is [`StoreError::UrnRowId`], and any other is [`StoreError::Urn`].
	fn refusal(error: UrnValidationError) -> StoreError {
		match error {
			UrnValidationError::InvalidFormat { field: ROW_ID, .. } => StoreError::UrnRowId,
			other => StoreError::Urn(other),
		}
	}
}
