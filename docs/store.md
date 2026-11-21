# The Frame Store

`tightbeam-store` keeps tightbeam messages as rows, one table per message type. This page specifies how a type declares its table and its row id, how a catalog lists the types of one store, the URN of each row, the metadata a driver indexes, and the two ports through which a backend joins the store.

## Contents

- [Declare a type](#declare-a-type)
- [Tables](#tables)
- [Catalogs](#catalogs)
- [Row ids](#row-ids)
- [URNs](#urns)
- [The metadata schema](#the-metadata-schema)
- [The native port](#the-native-port)
- [The native contract](#the-native-contract)
- [The KV port](#the-kv-port)
- [The KV contract](#the-kv-contract)
- [MemoryKv](#memorykv)
- [Indexed](#indexed)
- [Write a native driver](#write-a-native-driver)
- [Write a KV driver](#write-a-kv-driver)
- [Check a driver](#check-a-driver)

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
- The derive also evaluates its tables in a `const _`, so `cargo check` reports a derived catalog's clash. A hand-written catalog reports it at `cargo build`, once code reads its `TABLES`.

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

- `row_id_of` accepts one spelling of each row, the one `RowKey` writes, so the text and the DER of an accepted URN name one row. The `urn:` scheme is the exception: tightbeam reads it in any case, as RFC 8141 sets.

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

## The metadata schema

`Schema::CURRENT` names the fields of every row. The core derives each row's `Projection` from its frame alone.

| Field        | Kind    | Per row | Role      | From                                                                 |
| ------------ | ------- | ------- | --------- | -------------------------------------------------------------------- |
| `row_id`     | bytes   | 1       | key       | `metadata.id`                                                        |
| `order`      | u64     | 1       | attribute | `metadata.order`                                                     |
| `version`    | ordinal | 1       | attribute | the frame version                                                    |
| `digest`     | bytes   | 1       | identity  | the SHA3-256 `DigestInfo` DER of the stored frame                    |
| `previous`   | bytes   | 0..1    | reference | the `DigestInfo` DER of `metadata.previous_frame`                    |
| `commitment` | bytes   | 0..1    | attribute | the `DigestInfo` DER of `metadata.integrity`                         |
| `signer`     | bytes   | 0..1    | principal | the SHA3-256 of the signer identifier DER                            |
| `recipient`  | bytes   | 0..32   | principal | the SHA3-256 of each `RecipientKey` of the seal, once each, in order |
| `priority`   | ordinal | 0..1    | attribute | `metadata.priority`                                                  |
| `lifetime`   | u64     | 0..1    | attribute | `metadata.lifetime`, as its writer means it                          |
| `protection` | ordinal | 0..5    | attribute | each `Protection` the frame carries                                  |

- A `RecipientKey` is the key identifier of a `kekri` recipient, and the recipient identifier DER of a `ktri`, a KEM `ori`, and each `kari` recipient. A `pwri` recipient has none. `RecipientKey::principal` is its `recipient` value.
- `u64` values compare unsigned, bytes unsigned lexicographic, and ordinals by declaration order: tightbeam's `Version` and `MessagePriority`, and `Protection` (`signed` 0, `sealed` 1, `compressed` 2, `message_integrity` 3, `frame_integrity` 4).
- `FieldValue::kind` names the kind of a value, and `FieldValue::from(Protection)` is the value of a protection.
- A bytes value other than `row_id` holds at most 100 bytes. A frame with a longer `previous` or `commitment`, or a seal of more than 32 recipients, does not project.
- `version()` hashes the field table, the protections in order, and the revision of how each value is derived, so a change of any changes it. `index_hints()` lists the access paths the store keeps cheap.
- Every field is cleartext metadata, so a sealed frame is indexed with no key.
- Every field is a claim of the frame. The store verifies no signature, seal, commitment, or chain link, so a caller that trusts `signer` or `protection` verifies the frame itself.

## The native port

A backend with its own model and indexes joins the store through `Driver`, which provisions tables and opens transactions, and `DriverTxn`, which reads and writes rows inside one.

- The core builds every `Row`: its `RowKey`, its frame DER, and its `Projection`. A driver stores the bytes as they are and indexes the projection.
- The core prepares the tables of a store before its first transaction touches them.
- `prepare(schema, tables)` provisions `tables` and records `schema.version()`. It answers `Ready` again for the same or other tables of that schema, and `Foreign` for a backend that holds another schema version. The loser of a race to provision answers `DriverError::Aborted`.
- `DriverTxn` keeps the rules of `OrderedKvTxn` over rows: each call hands the transaction back, a `DriverError` ends it, and the commit refuses a transaction whose relied-on rows moved.
- The backend issues a `Revision` at each write, own writes included, and two revisions of one row are equal only when the frame bytes are.
- The key of a `Conflicted` answer is one of the keys this transaction wrote or confirmed, or `None`.
- A backend of signed integers stores a `u64` order-preserving, such as with its top bit flipped. A backend whose binary order differs, as BSON compares length first, stores bytes in an order-preserving form.

| Call                     | Answers                                                                                         |
| ------------------------ | ----------------------------------------------------------------------------------------------- |
| `get(keys)`              | The frame DER and revision of each key, in the order of the keys, and `None` for an absent row  |
| `insert(row)`            | `Inserted`, or `Occupied` when the key holds a row                                              |
| `swap(row, expected)`    | `Swapped`, or `Stale` when the key holds another revision or none                               |
| `remove(key, expected)`  | `Removed`, or `Stale` when the guard meets another revision. An unguarded remove always removes |
| `confirm(key, expected)` | `Held`, or `Changed`. A `Held` answer holds until the commit                                    |
| `commit()`               | `Committed`, or `Conflicted` with the key when the backend names it                             |
| `rollback()`             | Nothing. Every write is discarded, as on a drop                                                 |

## The native contract

Each row is a clause of `testing::DriverConformance`. Each clause runs on a fresh backend, prepared for the tables of the check. The clauses on rows run the KV clauses of the same meaning, without their scans, over V2 frames whose body is the KV value and which carry an order, a priority, a lifetime, a previous frame, a message commitment, and a frame integrity digest. A get must answer the exact frame written.

| A driver MUST                                                                                                                                                                              | Clause            | KV clause              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------- | ---------------------- |
| Answer `Ready` to two prepares of the tables and one of fewer, and `Foreign` to a schema version it does not hold                                                                          | `prepares`        | none                   |
| Hide an open insert, swap, and remove of either kind from other transactions until the commit starts                                                                                       | `isolates`        | `isolates`             |
| Show a transaction its own inserts, swaps, and removes of either kind, in each table                                                                                                       | `reads_own`       | `reads_own`            |
| Make every write of a commit visible together, or none                                                                                                                                     | `commits_atomic`  | `commits_atomic`       |
| Discard every write on `rollback` and on drop, and leave each row free for the next transaction                                                                                            | `discards`        | `discards`             |
| Answer `Occupied` and keep the row when `insert` meets a present key, and commit an insert after an own remove                                                                             | `inserts_once`    | `inserts_once`         |
| Commit at most one of concurrent inserts of one row                                                                                                                                        | `races_insert`    | `races_insert`         |
| Answer `Stale` when `swap` or a guarded `remove` meets another revision or an absent row, and guard with the revision of an own write                                                      | `guards_revision` | `guards_revision`      |
| Commit at most one of concurrent swaps and guarded removes from one revision                                                                                                               | `races_swap`      | `races_swap`           |
| Answer `Changed` for a moved row, and fail the commit when a confirmed row changes, vanishes, appears, or comes back                                                                       | `confirms_reads`  | `confirms_reads`       |
| Answer `Removed` for an unguarded `remove` of an absent row                                                                                                                                | `removes_absent`  | `removes_absent`       |
| Give two frames of one row two revisions, also after a remove and an insert, and when only the metadata differs                                                                            | `revises`         | `revises`              |
| Return the exact frame bytes written, of bodies that are empty, hold NUL bytes, or hold 64 KiB                                                                                             | `preserves`       | `preserves`            |
| Keep each table to its own rows, also beside a remove, a swap, and a confirm of another table, and when a table name starts another or a name and a row id join to the text of another row | `separates_types` | `separates_partitions` |
| Answer a batch `get` in the order of its keys, one row or `None` per key                                                                                                                   | `gets_batch`      | `gets_batch`           |
| Accept row ids of any bytes, NUL and 0xFF included, of 1 to 512 bytes, in tables of 1 to 63 bytes                                                                                          | `accepts_keys`    | `accepts_keys`         |
| Answer `Occupied`, `Stale`, or `Changed` at a call only for a competing commit that the read view holds                                                                                    | `conflicts_early` | `conflicts_early`      |
| Answer `DriverError::Aborted`, never `Failed`, when a conflict ends a transaction in any race of the check                                                                                 | `aborts_typed`    | `aborts_typed`         |

- Isolation floor: read committed, atomic commit, insert only if absent, compare and swap, and read confirmation. A driver MAY promise more.

## The KV port

An ordered key-value backend joins the store through `OrderedKv`, which opens transactions, and `OrderedKvTxn`, which reads and writes inside one.

- The core builds every `Key`, `KvValue`, and `KeyRange`. A driver reads them and answers.
- A key is a `Partition` and a sort key. A partition holds 1 to 80 bytes of lowercase ASCII letters, digits, hyphens, and slashes, starting with a letter. A sort key holds 1 to 621 bytes.
- A range sits inside one partition. Its lower bound sits at or below its upper bound, and equal bounds include both ends, so an ordered map takes the bounds as they are. The core answers a range that admits no key itself.
- A scan reads one partition in unsigned byte order of its sort keys. `KeyRange::contains` says whether a key falls inside a range.
- The backend issues a `Revision` at each write, own writes included. The core reads no meaning in its bytes, and hands it back to guard a swap, a remove, or a confirm.
- `scope` answers which processes reach the values: `Scope::Process` or `Scope::Shared`. Whether the values last is a separate promise of each driver.

Each call takes the transaction and hands it back with its answer, as a `TxnFuture`. A `DriverError` hands nothing back, so it ends the transaction.

| Call                            | Answers                                                                                         |
| ------------------------------- | ----------------------------------------------------------------------------------------------- |
| `get(keys)`                     | The value of each key, in the order of the keys, and `None` for an absent key                   |
| `insert(key, value)`            | `Inserted`, or `Occupied` when the key holds a value                                            |
| `swap(key, expected, value)`    | `Swapped`, or `Stale` when the key holds another revision or none                               |
| `remove(key, expected)`         | `Removed`, or `Stale` when the guard meets another revision. An unguarded remove always removes |
| `scan(range, direction, limit)` | At most `limit` entries of the range, along `direction`                                         |
| `confirm(key, expected)`        | `Held`, or `Changed`. A `Held` answer holds until the commit                                    |
| `commit()`                      | `Committed`, or `Conflicted` with the key when the backend names it                             |
| `rollback()`                    | Nothing. Every write is discarded, as on a drop                                                 |

- A read sees the committed state and the writes of its transaction. A call on a key the transaction wrote answers from that write.
- The commit MUST NOT answer `Committed` when a competing commit moved a key that a call relied on: the absence an insert found, the revision a swap or a guarded remove matched, or the state a confirm held. A call on a key the transaction wrote relies on nothing in committed state.
- A commit that loses answers `Conflicted`, or `DriverError::Aborted` when the backend ends the transaction itself, so the work may run again.
- `DriverError::Failed` from a commit means that the outcome is unknown.

## The KV contract

Each row is a clause of `testing::KvConformance`. Each clause runs on a fresh backend.

| A KV driver MUST                                                                                                                                                        | Clause                 |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| Hide an open insert, swap, and remove of either kind from the gets and scans of other transactions until the commit starts                                              | `isolates`             |
| Show a transaction its own inserts, swaps, and removes in `get`, and in scans each way, between bounds, under a limit, in each partition                                | `reads_own`            |
| Make every write of a commit visible together, or none                                                                                                                  | `commits_atomic`       |
| Discard every write on `rollback` and on drop, and leave each key free for the next transaction                                                                         | `discards`             |
| Answer `Occupied` and keep the value when `insert` meets a present key, and commit an insert after an own remove                                                        | `inserts_once`         |
| Commit at most one of concurrent inserts of one key                                                                                                                     | `races_insert`         |
| Answer `Stale` when `swap` or a guarded `remove` meets another revision or an absent key, and guard with the revision of an own write                                   | `guards_revision`      |
| Commit at most one of concurrent swaps and guarded removes from one revision                                                                                            | `races_swap`           |
| Answer `Changed` for a moved key, and fail the commit when a held key changes, vanishes, appears, or comes back                                                         | `confirms_reads`       |
| Answer `Removed` for an unguarded `remove` of an absent key                                                                                                             | `removes_absent`       |
| Give two values of one key with other bytes two revisions, also after a remove and an insert                                                                            | `revises`              |
| Return the exact bytes written, including empty values, NUL bytes, and 64 KiB values                                                                                    | `preserves`            |
| Keep each partition to its own entries, also beside writes of another partition, when one name starts another, or a name and a sort key join to the text of another key | `separates_partitions` |
| Scan in unsigned byte order, both ways, inside the range bounds, and at most `limit` entries                                                                            | `scans_ordered`        |
| Answer a batch `get` in the order of its keys                                                                                                                           | `gets_batch`           |
| Accept partitions of 1 to 80 bytes with slashes, and sort keys of any bytes, NUL and 0xFF included, of 1 to 621 bytes                                                   | `accepts_keys`         |
| Answer `Occupied`, `Stale`, or `Changed` at a call only for a competing commit that the read view holds                                                                 | `conflicts_early`      |
| Answer `DriverError::Aborted`, never `Failed`, when a conflict ends a transaction in any race of the check                                                              | `aborts_typed`         |

- Isolation floor: read committed, atomic commit, insert only if absent, compare and swap, and read confirmation. A driver MAY promise more.
- A driver MAY refuse a transaction past its documented size with `DriverError::Failed`. The suite stays under 64 writes per transaction.

## MemoryKv

`MemoryKv` is the ordered key-value backend of one process.

- A transaction is optimistic. Each read sees the committed state and the writes of the transaction, and a commit answers `Conflicted` when a key that the transaction relied on moved in committed state.
- A transaction writes at most 10 000 keys. A write of one more key answers `DriverError::Failed`, which ends the transaction.
- This process alone reaches the values, and they end with it, so its scope is `Scope::Process`.

## Indexed

`Indexed<K>` answers the native port over any `OrderedKv`. `MemoryDriver` is `Indexed<MemoryKv>`, the backend of local work and of tests.

- The rows of a table are the partition named by its frame type, keyed by row id, each value the frame DER.
- `prepare` writes one layout record: the layout version, the schema version, and the shard count. A backend whose record differs answers `Foreign`, and the tables need no provisioning. Of two prepares that race on an empty backend, the loser answers `DriverError::Aborted`.
- A get of the backend that answers another count of values than keys fails with `DriverError::Failed`.
- The scope is the scope of the backend.

## Write a native driver

A native driver implements `Driver` and `DriverTxn`, under the bounds and the boxed futures of a KV driver. It stores `Row::bytes` as they are, indexes `Row::projection`, and answers a get with the bytes and their `Revision` as a `Stored`. This driver forwards each call to a `MemoryDriver`, and reads the projection as an index of its own would:

```rust
use tightbeam_store::testing::{DriverBreach, DriverConformance};
use tightbeam_store::{
	CommitOutcome, ConfirmOutcome, Driver, DriverFuture, DriverTxn, Field, FieldKind, FieldValue, FrameType,
	InsertOutcome, MemoryDriver, Prepared, RemoveOutcome, Revision, Row, RowKey, RowTxnFuture, Schema, Scope,
	Stored, SwapOutcome,
};

struct Forwarding(MemoryDriver);

struct ForwardingTxn(Box<dyn DriverTxn>);

impl Driver for Forwarding {
	fn prepare<'a>(&'a self, schema: &'a Schema, tables: &'a [FrameType]) -> DriverFuture<'a, Prepared> {
		// A relational driver creates one column per field of `schema.fields()`
		// and one index per entry of `schema.index_hints()`.
		self.0.prepare(schema, tables)
	}

	fn begin(&self) -> DriverFuture<'_, Box<dyn DriverTxn>> {
		Box::pin(async move {
			let inner = self.0.begin().await?;
			Ok(Box::new(ForwardingTxn(inner)) as Box<dyn DriverTxn>)
		})
	}

	fn scope(&self) -> Scope {
		self.0.scope()
	}
}

impl DriverTxn for ForwardingTxn {
	fn insert<'a>(self: Box<Self>, row: &'a Row) -> RowTxnFuture<'a, InsertOutcome> {
		// Each value has the kind of its field, so a column takes it as is.
		for (field, value) in row.projection().iter() {
			assert_eq!(value.kind(), field.kind());
		}

		let order = row.projection().values(Field::Order);
		assert!(matches!(order, [FieldValue::U64(_)]));
		assert_eq!(Field::Order.kind(), FieldKind::U64);

		Box::pin(async move {
			let (inner, inserted) = self.0.insert(row).await?;
			Ok((Box::new(Self(inner)) as Box<dyn DriverTxn>, inserted))
		})
	}
#
# 	fn get<'a>(self: Box<Self>, keys: &'a [RowKey]) -> RowTxnFuture<'a, Vec<Option<Stored>>> {
# 		Box::pin(async move {
# 			let (inner, read) = self.0.get(keys).await?;
# 			Ok((Box::new(Self(inner)) as Box<dyn DriverTxn>, read))
# 		})
# 	}
#
# 	fn swap<'a>(self: Box<Self>, row: &'a Row, expected: &'a Revision) -> RowTxnFuture<'a, SwapOutcome> {
# 		Box::pin(async move {
# 			let (inner, swapped) = self.0.swap(row, expected).await?;
# 			Ok((Box::new(Self(inner)) as Box<dyn DriverTxn>, swapped))
# 		})
# 	}
#
# 	fn remove<'a>(self: Box<Self>, key: &'a RowKey, expected: Option<&'a Revision>) -> RowTxnFuture<'a, RemoveOutcome> {
# 		Box::pin(async move {
# 			let (inner, removed) = self.0.remove(key, expected).await?;
# 			Ok((Box::new(Self(inner)) as Box<dyn DriverTxn>, removed))
# 		})
# 	}
#
# 	fn confirm<'a>(self: Box<Self>, key: &'a RowKey, expected: Option<&'a Revision>) -> RowTxnFuture<'a, ConfirmOutcome> {
# 		Box::pin(async move {
# 			let (inner, confirmed) = self.0.confirm(key, expected).await?;
# 			Ok((Box::new(Self(inner)) as Box<dyn DriverTxn>, confirmed))
# 		})
# 	}

	// `get`, `swap`, `remove`, and `confirm` take the same shape.

	fn commit(self: Box<Self>) -> DriverFuture<'static, CommitOutcome<RowKey>> {
		self.0.commit()
	}

	fn rollback(self: Box<Self>) -> DriverFuture<'static, ()> {
		self.0.rollback()
	}
}

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), DriverBreach> {
DriverConformance::new(|| async { Ok(Forwarding(MemoryDriver::default())) }).check().await
# }
```

## Write a KV driver

A driver implements both traits. `OrderedKv` is `Send` and `Sync`, and `OrderedKvTxn` is `Send`, except on wasm32: the bounds are `MaybeSend` and `MaybeSync`. Each call returns a boxed future, built with `Box::pin(async move { .. })`, and a call of a transaction hands the transaction back with its answer. This driver forwards each call to a `MemoryKv`:

```rust
use core::num::NonZeroU32;

use tightbeam_store::testing::{KvBreach, KvConformance};
use tightbeam_store::{
	CommitOutcome, ConfirmOutcome, Direction, DriverFuture, Entry, InsertOutcome, Key, KeyRange, KvValue, MemoryKv,
	OrderedKv, OrderedKvTxn, RemoveOutcome, Revision, Scope, Stored, SwapOutcome, TxnFuture,
};

struct Forwarding(MemoryKv);

struct ForwardingTxn(Box<dyn OrderedKvTxn>);

impl OrderedKv for Forwarding {
	fn begin(&self) -> DriverFuture<'_, Box<dyn OrderedKvTxn>> {
		Box::pin(async move {
			let inner = self.0.begin().await?;
			Ok(Box::new(ForwardingTxn(inner)) as Box<dyn OrderedKvTxn>)
		})
	}

	fn scope(&self) -> Scope {
		self.0.scope()
	}
}

impl OrderedKvTxn for ForwardingTxn {
	fn get<'a>(self: Box<Self>, keys: &'a [Key]) -> TxnFuture<'a, Vec<Option<Stored>>> {
		Box::pin(async move {
			let (inner, read) = self.0.get(keys).await?;
			Ok((Box::new(Self(inner)) as Box<dyn OrderedKvTxn>, read))
		})
	}
#
# 	fn insert<'a>(self: Box<Self>, key: &'a Key, value: &'a KvValue) -> TxnFuture<'a, InsertOutcome> {
# 		Box::pin(async move {
# 			let (inner, inserted) = self.0.insert(key, value).await?;
# 			Ok((Box::new(Self(inner)) as Box<dyn OrderedKvTxn>, inserted))
# 		})
# 	}
#
# 	fn swap<'a>(self: Box<Self>, key: &'a Key, expected: &'a Revision, value: &'a KvValue) -> TxnFuture<'a, SwapOutcome> {
# 		Box::pin(async move {
# 			let (inner, swapped) = self.0.swap(key, expected, value).await?;
# 			Ok((Box::new(Self(inner)) as Box<dyn OrderedKvTxn>, swapped))
# 		})
# 	}
#
# 	fn remove<'a>(self: Box<Self>, key: &'a Key, expected: Option<&'a Revision>) -> TxnFuture<'a, RemoveOutcome> {
# 		Box::pin(async move {
# 			let (inner, removed) = self.0.remove(key, expected).await?;
# 			Ok((Box::new(Self(inner)) as Box<dyn OrderedKvTxn>, removed))
# 		})
# 	}
#
# 	fn scan<'a>(self: Box<Self>, range: &'a KeyRange, direction: Direction, limit: NonZeroU32) -> TxnFuture<'a, Vec<Entry>> {
# 		Box::pin(async move {
# 			let (inner, entries) = self.0.scan(range, direction, limit).await?;
# 			Ok((Box::new(Self(inner)) as Box<dyn OrderedKvTxn>, entries))
# 		})
# 	}
#
# 	fn confirm<'a>(self: Box<Self>, key: &'a Key, expected: Option<&'a Revision>) -> TxnFuture<'a, ConfirmOutcome> {
# 		Box::pin(async move {
# 			let (inner, checked) = self.0.confirm(key, expected).await?;
# 			Ok((Box::new(Self(inner)) as Box<dyn OrderedKvTxn>, checked))
# 		})
# 	}

	// `insert`, `swap`, `remove`, `scan`, and `confirm` take the same shape.

	fn commit(self: Box<Self>) -> DriverFuture<'static, CommitOutcome<Key>> {
		self.0.commit()
	}

	fn rollback(self: Box<Self>) -> DriverFuture<'static, ()> {
		self.0.rollback()
	}
}

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), KvBreach> {
KvConformance::new(|| async { Ok(Forwarding(MemoryKv::default())) }).check().await
# }
```

`MemoryKv` is a full driver to read beside it, in `memory.rs`.

## Check a driver

A driver runs its contract in its own tests, through the `testing` feature:

```toml
[dev-dependencies]
tightbeam-store = { version = "0.1", features = ["testing"] }
```

```rust
use tightbeam_store::testing::{KvBreach, KvClause, KvConformance};
use tightbeam_store::MemoryKv;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), KvBreach> {
let conformance = KvConformance::new(|| async { Ok(MemoryKv::default()) });
conformance.clause(KvClause::ScansOrdered).await?;
conformance.check().await
# }
```

`DriverConformance` checks a native driver the same way:

```rust
use tightbeam_store::testing::{DriverBreach, DriverClause, DriverConformance};
use tightbeam_store::MemoryDriver;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), DriverBreach> {
let conformance = DriverConformance::new(|| async { Ok(MemoryDriver::default()) });
conformance.clause(DriverClause::Prepares).await?;
conformance.check().await
# }
```

- The factory builds one empty backend per clause, or answers the `DriverError` of a backend it cannot build.
- `check` runs each clause of `KvClause::ALL` or `DriverClause::ALL` and answers the first breach. `clause` runs one alone, so each clause can be a test of its own.
- The check runs on a tokio runtime with its timer. Each step waits at most five seconds, or the span of `with_patience`, and a step that waits longer breaks its clause with `Breach::Lapsed`.
- Racing transactions share one task and signal each other. A racer waits for its rival while the rival answers calls, and reads a rival silent for a tenth of the patience as blocked, so a backend that blocks a write or a read behind an open transaction meets every clause. A single call slower than that tenth reads as blocked too.
- A breach names its clause, the step with its inputs, the answer, and what the clause places. A `DriverError::Failed` inside any race breaks `aborts_typed`.
