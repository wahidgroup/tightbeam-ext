//! What `#[derive(Storable)]` and `#[derive(Catalog)]` expand to, as a crate
//! that uses them sees it.

use der::Sequence;
use tightbeam::testing::SetupEnv;
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn, Beamable};
use tightbeam_store::{Catalog, FrameType, Holds, Owner, RowId, Storable};

/// A leaf whose id follows a documented field.
#[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
#[storable(frame_type = "colony-leaf")]
struct Leaf {
	/// The colony of the leaf.
	colony: String,
	/// The key of the leaf.
	#[storable(id)]
	key: RowId,
}

/// A seed whose type name is raw.
#[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
#[storable(frame_type = "colony-seed")]
struct r#Seed {
	#[storable(id)]
	id: RowId,
}

/// A bark whose impl is written by hand.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
struct Bark {
	id: RowId,
}

impl Storable for Bark {
	const FRAME_TYPE: FrameType = FrameType::from_static("colony-bark");
	const OWNER: Owner = Owner::from_static("colony::Bark");

	fn row_id(&self) -> RowId {
		self.id.clone()
	}
}

/// A catalog of two derived types and one written by hand.
#[derive(Catalog)]
#[catalog(Leaf, Seed, Bark)]
struct Colony;

/// Whether `C` holds the table of `T`, which the `Holds` bound admits.
fn holds<C: Holds<T>, T: Storable>() -> bool {
	C::TABLES.holds(T::FRAME_TYPE)
}

/// Whether a type's row id is the value of its id field.
const ID_FIELD: Urn<'static> = urn!("test", "event:store-derive/id-field");

/// Whether a type names the table and the owner it declares.
const TABLE_AND_OWNER: Urn<'static> = urn!("test", "event:store-derive/table-and-owner");

/// Whether a catalog holds a type it lists.
const HELD: Urn<'static> = urn!("test", "event:store-derive/held");

tb_assert_spec! {
	pub DerivedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(ID_FIELD, exactly!(3), equals!(true)),
			(TABLE_AND_OWNER, exactly!(3), equals!(true)),
			(HELD, exactly!(3), equals!(true))
		]
	}
}

// A derived type reads its marked field after a documented one, records a
// raw type name without its prefix, and a derived catalog holds every type it
// lists, derived or written by hand.
tb_scenario! {
	name: derived_types_and_catalogs_answer_what_they_declare,
	spec: DerivedSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			let ids = [
				(Leaf { colony: String::from("north"), key: RowId::from(*b"leaf") }.row_id(), RowId::from(*b"leaf")),
				(Seed { id: RowId::from(*b"seed") }.row_id(), RowId::from(*b"seed")),
				(Bark { id: RowId::from(*b"bark") }.row_id(), RowId::from(*b"bark")),
			];
			for (row_id, expected) in ids {
				trace.event_with(ID_FIELD, &[], row_id == expected)?;
			}

			let declared = [
				((Leaf::FRAME_TYPE, Leaf::OWNER), ("colony-leaf", "tightbeam-store::Leaf")),
				((Seed::FRAME_TYPE, Seed::OWNER), ("colony-seed", "tightbeam-store::Seed")),
				((Bark::FRAME_TYPE, Bark::OWNER), ("colony-bark", "colony::Bark")),
			];
			for ((frame_type, owner), written) in declared {
				trace.event_with(TABLE_AND_OWNER, &[], (frame_type.as_str(), owner.as_str()) == written)?;
			}

			for held in [holds::<Colony, Leaf>(), holds::<Colony, Seed>(), holds::<Colony, Bark>()] {
				trace.event_with(HELD, &[], held)?;
			}

			Ok(())
		}
	}
}
