//! A tightbeam message that the store keeps: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#declare-a-type).

use tightbeam::Message;

use crate::frame_type::FrameType;
use crate::owner::Owner;
use crate::row_id::RowId;

/// A tightbeam message that the store keeps, one row per value, in the table
/// [`Storable::FRAME_TYPE`].
///
/// `#[derive(Storable)]` writes the impl: `#[storable(frame_type = "...")]`
/// on the type names the table, and `#[storable(id)]` marks the one
/// [`RowId`] field.
///
/// # Examples
///
/// ```
/// use der::Sequence;
/// use tightbeam::Beamable;
/// use tightbeam_store::{FrameType, RowId, Storable};
///
/// #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// #[storable(frame_type = "colony-leaf")]
/// pub struct HiveLeaf {
/// 	#[storable(id)]
/// 	pub id: RowId,
/// 	pub colony: String,
/// }
///
/// let leaf = HiveLeaf { id: RowId::from(*b"leaf-42"), colony: String::from("north") };
/// assert_eq!(HiveLeaf::FRAME_TYPE, FrameType::from_static("colony-leaf"));
/// assert_eq!(HiveLeaf::OWNER.as_str(), "tightbeam-store::HiveLeaf");
/// assert_eq!(leaf.row_id(), leaf.id);
/// ```
///
/// The derive checks the frame type even when nothing reads it. A frame type
/// in the grammar compiles:
///
/// ```
/// # use der::Sequence;
/// # use tightbeam::Beamable;
/// # use tightbeam_store::{RowId, Storable};
/// #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// #[storable(frame_type = "colony-claims")]
/// pub struct Claims {
/// 	#[storable(id)]
/// 	pub id: RowId,
/// }
/// ```
///
/// The reserved prefix does not:
///
/// ```compile_fail
/// # use der::Sequence;
/// # use tightbeam::Beamable;
/// # use tightbeam_store::{RowId, Storable};
/// #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// #[storable(frame_type = "tightbeam-claims")]
/// pub struct Claims {
/// 	#[storable(id)]
/// 	pub id: RowId,
/// }
/// ```
///
/// The derive checks the owner too. A type name of 64 bytes compiles:
///
/// ```
/// # use der::Sequence;
/// # use tightbeam::Beamable;
/// # use tightbeam_store::{RowId, Storable};
/// #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// #[storable(frame_type = "colony-leaf")]
/// pub struct L234567890234567890234567890234567890234567890234567890234567890 {
/// 	#[storable(id)]
/// 	pub id: RowId,
/// }
/// ```
///
/// A type name of 65 bytes does not:
///
/// ```compile_fail
/// # use der::Sequence;
/// # use tightbeam::Beamable;
/// # use tightbeam_store::{RowId, Storable};
/// #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// #[storable(frame_type = "colony-leaf")]
/// pub struct L2345678902345678902345678902345678902345678902345678902345678905 {
/// 	#[storable(id)]
/// 	pub id: RowId,
/// }
/// ```
///
/// The id field is a `RowId`:
///
/// ```
/// # use der::Sequence;
/// # use tightbeam::Beamable;
/// # use tightbeam_store::{RowId, Storable};
/// #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// #[storable(frame_type = "colony-leaf")]
/// pub struct HiveLeaf {
/// 	#[storable(id)]
/// 	pub id: RowId,
/// }
/// ```
///
/// A field of another type does not compile as the id:
///
/// ```compile_fail
/// # use der::Sequence;
/// # use tightbeam::Beamable;
/// # use tightbeam_store::{RowId, Storable};
/// #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// #[storable(frame_type = "colony-leaf")]
/// pub struct HiveLeaf {
/// 	#[storable(id)]
/// 	pub id: u64,
/// }
/// ```
pub trait Storable: Message {
	/// The table of this type.
	const FRAME_TYPE: FrameType;

	/// The crate and type that own the table.
	const OWNER: Owner;

	/// The key of this value within its table.
	fn row_id(&self) -> RowId;
}
