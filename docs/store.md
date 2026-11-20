# The Frame Store

`tightbeam-store` keeps tightbeam messages as rows, one table per message type. This page specifies how a type declares its table and its row id, how a catalog lists the types of one store, the URN of each row, and the port through which an ordered key-value backend joins the store.

## Contents

- [Declare a type](#declare-a-type)
- [Tables](#tables)
- [Catalogs](#catalogs)
- [Row ids](#row-ids)
- [URNs](#urns)
- [The KV port](#the-kv-port)
- [The KV contract](#the-kv-contract)
- [MemoryKv](#memorykv)
- [Write a KV driver](#write-a-kv-driver)
- [Check a KV driver](#check-a-kv-driver)

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

## The KV port

An ordered key-value backend joins the store through `OrderedKv`, which opens transactions, and `OrderedKvTxn`, which reads and writes inside one.

- The core builds every `Key`, `KvValue`, and `KeyRange`. A driver reads them and answers.
- A key is a `Partition` and a sort key. A partition holds 1 to 80 bytes of lowercase ASCII letters, digits, hyphens, and slashes, starting with a letter. A sort key holds 1 to 621 bytes.
- A range sits inside one partition. Its lower bound sits at or below its upper bound, and equal bounds include both ends, so an ordered map takes the bounds as they are. The core answers a range that admits no key itself.
- A scan reads one partition in unsigned byte order of its sort keys. `KeyRange::contains` says whether a key falls inside a range.
- The backend issues a `Revision` at each write, own writes included. The core reads no meaning in its bytes, and hands it back to guard a swap, a remove, or a check.
- `scope` answers which processes reach the values: `Scope::Process` or `Scope::Shared`. Whether the values last is a separate promise of each driver.

Each call takes the transaction and hands it back with its answer, as a `TxnFuture`. A `DriverError` hands nothing back, so it ends the transaction.

| Call                            | Answers                                                                                         |
| ------------------------------- | ----------------------------------------------------------------------------------------------- |
| `get(keys)`                     | The value of each key, in the order of the keys, and `None` for an absent key                   |
| `insert(key, value)`            | `Inserted`, or `Occupied` when the key holds a value                                            |
| `swap(key, expected, value)`    | `Swapped`, or `Stale` when the key holds another revision or none                               |
| `remove(key, expected)`         | `Removed`, or `Stale` when the guard meets another revision. An unguarded remove always removes |
| `scan(range, direction, limit)` | At most `limit` entries of the range, along `direction`                                         |
| `check(key, expected)`          | `Held`, or `Changed`. A `Held` answer holds until the commit                                    |
| `commit()`                      | `Committed`, or `Conflicted` with the key when the backend names it                             |
| `rollback()`                    | Nothing. Every write is discarded, as on a drop                                                 |

- A read sees the committed state and the writes of its transaction. A call on a key the transaction wrote answers from that write.
- The commit MUST NOT answer `Committed` when a competing commit moved a key that a call relied on: the absence an insert found, the revision a swap or a guarded remove matched, or the state a check held. A call on a key the transaction wrote relies on nothing in committed state.
- A commit that loses answers `Conflicted`, or `DriverError::Aborted` when the backend ends the transaction itself, so the work may run again.
- `DriverError::Failed` from a commit means that the outcome is unknown.

## The KV contract

Each row is a clause of `testing::KvConformance`. Each clause runs on a fresh backend.

| A KV driver MUST                                                                                                                         | Clause                 |
| ---------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| Hide an open insert, swap, and remove of either kind from the gets and scans of other transactions until the commit starts               | `isolates`             |
| Show a transaction its own inserts, swaps, and removes in `get`, and in scans each way, between bounds, under a limit, in each partition | `reads_own`            |
| Make every write of a commit visible together, or none                                                                                   | `commits_atomic`       |
| Discard every write on `rollback` and on drop, and leave each key free for the next transaction                                          | `discards`             |
| Answer `Occupied` and keep the value when `insert` meets a present key, and commit an insert after an own remove                         | `inserts_once`         |
| Commit at most one of concurrent inserts of one key                                                                                      | `races_insert`         |
| Answer `Stale` when `swap` or a guarded `remove` meets another revision or an absent key, and guard with the revision of an own write    | `guards_revision`      |
| Commit at most one of concurrent swaps and guarded removes from one revision                                                             | `races_swap`           |
| Answer `Changed` for a moved key, and fail the commit when a held key changes, vanishes, appears, or comes back                          | `checks_reads`         |
| Answer `Removed` for an unguarded `remove` of an absent key                                                                              | `removes_absent`       |
| Give two values of one key with other bytes two revisions, also after a remove and an insert                                             | `revises`              |
| Return the exact bytes written, including empty values, NUL bytes, and 64 KiB values                                                     | `preserves`            |
| Keep each partition to its own entries, also when one name starts another or a name and a sort key join to the text of another key       | `separates_partitions` |
| Scan in unsigned byte order, both ways, inside the range bounds, and at most `limit` entries                                             | `scans_ordered`        |
| Answer a batch `get` in the order of its keys                                                                                            | `gets_batch`           |
| Accept partitions of 1 to 80 bytes with slashes, and sort keys of 1 to 621 bytes                                                         | `accepts_keys`         |
| Answer `Occupied`, `Stale`, or `Changed` at a call only for a competing commit that the read view holds                                  | `conflicts_early`      |
| Answer `DriverError::Aborted`, never `Failed`, when a conflict ends a transaction in any race of the check                               | `aborts_typed`         |

- Isolation floor: read committed, atomic commit, insert only if absent, compare and swap, and read confirmation. A driver MAY promise more.
- A driver MAY refuse a transaction past its documented size with `DriverError::Failed`. The suite stays under 64 writes per transaction.

## MemoryKv

`MemoryKv` is the ordered key-value backend of one process.

- A transaction is optimistic. Each read sees the committed state and the writes of the transaction, and a commit answers `Conflicted` when a key that the transaction relied on moved in committed state.
- A transaction writes at most 10 000 keys. A write of one more key answers `DriverError::Failed`, which ends the transaction.
- This process alone reaches the values, and they end with it, so its scope is `Scope::Process`.

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
# 	fn check<'a>(self: Box<Self>, key: &'a Key, expected: Option<&'a Revision>) -> TxnFuture<'a, ConfirmOutcome> {
# 		Box::pin(async move {
# 			let (inner, checked) = self.0.check(key, expected).await?;
# 			Ok((Box::new(Self(inner)) as Box<dyn OrderedKvTxn>, checked))
# 		})
# 	}

	// `insert`, `swap`, `remove`, `scan`, and `check` take the same shape.

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

## Check a KV driver

A KV driver runs the contract in its own tests, through the `testing` feature:

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

- The factory builds one empty backend per clause, or answers the `DriverError` of a backend it cannot build.
- `check` runs each clause of `KvClause::ALL` and answers the first breach. `clause` runs one alone, so each clause can be a test of its own.
- The check runs on a tokio runtime with its timer. Each step waits at most five seconds, or the span of `with_patience`, and a step that waits longer breaks its clause with `KvBreach::Lapsed`.
- Racing transactions share one task and signal each other. A racer waits for its rival while the rival answers calls, and reads a rival silent for a tenth of the patience as blocked, so a backend that blocks a write or a read behind an open transaction meets every clause. A single call slower than that tenth reads as blocked too.
- A breach names its clause, the step with its inputs, the answer, and what the clause places. A `DriverError::Failed` inside any race breaks `aborts_typed`.
