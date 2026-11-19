//! The tables one store holds: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#catalogs).

use crate::frame_type::FrameType;
use crate::owner::Owner;
use crate::storable::Storable;

/// The types one store holds.
///
/// `#[derive(Catalog)]` with `#[catalog(TypeA, TypeB)]` writes this impl and
/// one [`Holds`] impl per type. Two types that claim one table fail to compile.
///
/// # Examples
///
/// ```
/// use der::Sequence;
/// use tightbeam::Beamable;
/// use tightbeam_store::{Catalog, FrameType, RowId, Storable};
///
/// #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// #[storable(frame_type = "colony-leaf")]
/// pub struct HiveLeaf {
/// 	#[storable(id)]
/// 	pub id: RowId,
/// }
///
/// #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// #[storable(frame_type = "colony-seed")]
/// pub struct HiveSeed {
/// 	#[storable(id)]
/// 	pub id: RowId,
/// }
///
/// #[derive(Catalog)]
/// #[catalog(HiveLeaf, HiveSeed)]
/// pub struct Colony;
///
/// assert!(Colony::TABLES.holds(FrameType::from_static("colony-seed")));
/// assert!(!Colony::TABLES.holds(FrameType::from_static("colony-bark")));
/// ```
///
/// A derived catalog checks its tables even when nothing reads them. Two
/// types on two tables compile:
///
/// ```
/// # use der::Sequence;
/// # use tightbeam::Beamable;
/// # use tightbeam_store::{Catalog, RowId, Storable};
/// #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// #[storable(frame_type = "colony-leaf")]
/// pub struct HiveLeaf {
/// 	#[storable(id)]
/// 	pub id: RowId,
/// }
/// #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// #[storable(frame_type = "colony-seed")]
/// pub struct OtherLeaf {
/// 	#[storable(id)]
/// 	pub id: RowId,
/// }
/// #[derive(Catalog)]
/// #[catalog(HiveLeaf, OtherLeaf)]
/// pub struct Colony;
/// ```
///
/// The same two types on one table do not:
///
/// ```compile_fail
/// # use der::Sequence;
/// # use tightbeam::Beamable;
/// # use tightbeam_store::{Catalog, RowId, Storable};
/// #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// #[storable(frame_type = "colony-leaf")]
/// pub struct HiveLeaf {
/// 	#[storable(id)]
/// 	pub id: RowId,
/// }
/// #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// #[storable(frame_type = "colony-leaf")]
/// pub struct OtherLeaf {
/// 	#[storable(id)]
/// 	pub id: RowId,
/// }
/// #[derive(Catalog)]
/// #[catalog(HiveLeaf, OtherLeaf)]
/// pub struct Colony;
/// ```
pub trait Catalog {
	/// The tables of the types this catalog lists.
	const TABLES: Tables;
}

/// A catalog that lists the type `T`.
///
/// The derive implements it for each listed type alone. A listed type meets
/// the bound:
///
/// ```
/// # use der::Sequence;
/// # use tightbeam::Beamable;
/// # use tightbeam_store::{Catalog, Holds, RowId, Storable};
/// # #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// # #[storable(frame_type = "chain-block")]
/// # pub struct Block {
/// # 	#[storable(id)]
/// # 	pub id: RowId,
/// # }
/// # #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// # #[storable(frame_type = "chain-tx")]
/// # pub struct Tx {
/// # 	#[storable(id)]
/// # 	pub id: RowId,
/// # }
/// # #[derive(Catalog)]
/// # #[catalog(Block)]
/// # pub struct Ledger;
/// fn needs<C: Holds<T>, T: Storable>() {}
///
/// needs::<Ledger, Block>();
/// ```
///
/// A type the catalog does not list does not:
///
/// ```compile_fail
/// # use der::Sequence;
/// # use tightbeam::Beamable;
/// # use tightbeam_store::{Catalog, Holds, RowId, Storable};
/// # #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// # #[storable(frame_type = "chain-block")]
/// # pub struct Block {
/// # 	#[storable(id)]
/// # 	pub id: RowId,
/// # }
/// # #[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
/// # #[storable(frame_type = "chain-tx")]
/// # pub struct Tx {
/// # 	#[storable(id)]
/// # 	pub id: RowId,
/// # }
/// # #[derive(Catalog)]
/// # #[catalog(Block)]
/// # pub struct Ledger;
/// fn needs<C: Holds<T>, T: Storable>() {}
///
/// needs::<Ledger, Tx>();
/// ```
pub trait Holds<T: Storable>: Catalog {}

/// The tables of one catalog, each with its owner, no two alike.
#[derive(Clone, Copy, Debug)]
pub struct Tables {
	entries: &'static [(FrameType, Owner)],
}

impl Tables {
	/// The tables `entries`.
	///
	/// # Panics
	///
	/// - Two entries name one table. In a `const` item, the panic is a compile
	///   error.
	pub const fn new(entries: &'static [(FrameType, Owner)]) -> Self {
		let mut outer = 0;
		while outer < entries.len() {
			let mut inner = outer + 1;
			while inner < entries.len() {
				if entries[outer].0.same_as(&entries[inner].0) {
					panic!("two types of one catalog claim one table");
				}

				inner += 1;
			}

			outer += 1;
		}

		Self { entries }
	}

	/// Whether these tables include `frame_type`.
	pub const fn holds(&self, frame_type: FrameType) -> bool {
		let mut index = 0;
		while index < self.entries.len() {
			if self.entries[index].0.same_as(&frame_type) {
				return true;
			}

			index += 1;
		}

		false
	}
}

#[cfg(test)]
mod tests {
	use std::panic;

	use super::*;

	const LEAF: FrameType = FrameType::from_static("colony-leaf");
	const SEED: FrameType = FrameType::from_static("colony-seed");
	const OWNER: Owner = Owner::from_static("colony::Leaf");

	#[test]
	fn tables_hold_what_they_list() {
		const TABLES: Tables = Tables::new(&[(LEAF, OWNER), (SEED, OWNER)]);
		assert!(TABLES.holds(LEAF));
		assert!(TABLES.holds(SEED));
		assert!(!TABLES.holds(FrameType::from_static("colony-bark")));
	}

	const BARK: FrameType = FrameType::from_static("colony-bark");

	tightbeam::tb_cases! {
		fn two_entries_on_one_table_panic(entries: &'static [(FrameType, Owner)]) {
			assert!(panic::catch_unwind(|| Tables::new(entries)).is_err());
		}
		cases {
			first_and_second => &[(LEAF, OWNER), (LEAF, OWNER), (BARK, OWNER)],
			first_and_third => &[(LEAF, OWNER), (SEED, OWNER), (LEAF, OWNER)],
			second_and_third => &[(LEAF, OWNER), (SEED, OWNER), (SEED, OWNER)],
		}
	}
}
