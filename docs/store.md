# The Frame Store

`tightbeam-store` keeps tightbeam messages as rows, one table per message type. This page specifies how a type declares its table and its row id, how a catalog lists the types of one store, and the URN of each row.

## Contents

- [Declare a type](#declare-a-type)
- [Tables](#tables)
- [Catalogs](#catalogs)
- [Row ids](#row-ids)
- [URNs](#urns)

## Declare a type

A tightbeam `Message` derives `Storable`:

| Attribute                         | On         | Sets                                      |
| --------------------------------- | ---------- | ----------------------------------------- |
| `#[storable(frame_type = "...")]` | the struct | `Storable::FRAME_TYPE`, the table         |
| `#[storable(id)]`                 | one field  | `Storable::row_id`, a clone of that field |

- The id field is a `RowId`.
- `Storable::OWNER` is the crate name and the type name, `crate::Type`. A raw name such as `r#Leaf` records `Leaf`.
- A type name that is no ASCII identifier of at most 64 bytes fails to compile, through the grammar of `Owner`.
- The derive refuses a generic struct, an enum, a tuple struct, a second `frame_type`, and no `id` field or two.
- A hand-written impl of `Storable` stays legal.

```rust
use der::Sequence;
use tightbeam::Beamable;
use tightbeam_store::{RowId, Storable};

#[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
#[storable(frame_type = "chain-block")]
pub struct Block {
	#[storable(id)]
	pub id: RowId,
	pub height: u64,
}

assert_eq!(Block::FRAME_TYPE.as_str(), "chain-block");
assert_eq!(Block::OWNER.as_str(), "tightbeam-store::Block");
```

## Tables

A `FrameType` names one table:

- 1 to 63 bytes of lowercase ASCII letters, digits, and hyphens, starting with a letter.
- The `tightbeam-` prefix is reserved for the tables of the crate.
- `FrameType::from_static` checks the grammar. In a `const` item, a name that breaks it is a compile error.

An `Owner` names the crate and the type that own a table, written `crate::Type`:

- The crate part holds 1 to 64 ASCII letters, digits, hyphens, and underscores.
- The type part is an ASCII Rust identifier of 1 to 64 bytes.

## Catalogs

A `Catalog` lists the `Storable` types of one store. `#[derive(Catalog)]` on a unit struct writes it:

```rust
use der::Sequence;
use tightbeam::Beamable;
use tightbeam_store::{Catalog, Holds, RowId, Storable};

#[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
#[storable(frame_type = "chain-block")]
pub struct Block {
	#[storable(id)]
	pub id: RowId,
}

#[derive(Beamable, Sequence, Storable, Clone, Debug, PartialEq)]
#[storable(frame_type = "chain-tx")]
pub struct Tx {
	#[storable(id)]
	pub id: RowId,
}

#[derive(Catalog)]
#[catalog(Block)]
pub struct Ledger;

#[derive(Catalog)]
#[catalog(Tx)]
pub struct Mempool;

fn holds<C: Holds<T>, T: Storable>() -> bool {
	C::TABLES.holds(T::FRAME_TYPE)
}

assert!(holds::<Ledger, Block>());
assert!(holds::<Mempool, Tx>());
```

| Mistake                                         | Result                                |
| ----------------------------------------------- | ------------------------------------- |
| Two listed types claim one table                | A compile error from `Tables::new`    |
| One type listed twice                           | A refusal of the derive               |
| A type the catalog does not list, under `Holds` | A compile error: the bound is not met |

- `Tables::new` is the one constructor of `Catalog::TABLES`, so a hand-written catalog runs the same check.
- The derive also evaluates its tables in a `const _`, so `cargo check` reports a derived catalog's clash. A hand-written catalog reports it at `cargo build`, once a store uses it.

## Row ids

A `RowId` keys a row within its table:

- 1 to 512 bytes.
- `TryFrom<&[u8]>` and `TryFrom<Vec<u8>>` refuse a length outside the bounds with `StoreError::RowIdLength`.
- `From<[u8; N]>` checks `N` at compile time.
- As a message field, it encodes as a DER OCTET STRING, and a decode refuses a length outside the bounds.

## URNs

A `RowKey` pairs a table with a row id and builds the URN of the row:

```text
urn:tightbeam:store:{frame_type}:{row_id}
```

- The row id is lowercase hex, two digits per byte.
- One row id in two tables names two rows, with two URNs.
- `FrameType::row_id_of` reads a URN back into the row id of that table.

`row_id_of` checks in this order, so a URN with two faults gets the answer of the first:

| Check | Refuses                                                                             | With                          |
| ----- | ----------------------------------------------------------------------------------- | ----------------------------- |
| 1     | A URN of another NID or category, or with no row id part                            | `StoreError::Urn`             |
| 2     | A row id part that is no lowercase hex of 1 to 512 bytes                            | `StoreError::UrnRowId`        |
| 3     | A store URN spelled another way: an NID not in lowercase, an r-, q-, or f-component | `StoreError::NonCanonicalUrn` |
| 4     | A URN of another table                                                              | `StoreError::ForeignTable`    |

- A store URN has one spelling, so its text and its DER name one row.

```rust
use tightbeam_store::{FrameType, RowId, RowKey, StoreError};

const BLOCK: FrameType = FrameType::from_static("chain-block");
const TX: FrameType = FrameType::from_static("chain-tx");

let key = RowKey::new(BLOCK, RowId::from(*b"42"))?;
assert_eq!(key.urn().to_string(), "urn:tightbeam:store:chain-block:3432");
assert_eq!(BLOCK.row_id_of(key.urn())?, RowId::from(*b"42"));
assert!(matches!(TX.row_id_of(key.urn()), Err(StoreError::ForeignTable { .. })));
# Ok::<(), StoreError>(())
```
