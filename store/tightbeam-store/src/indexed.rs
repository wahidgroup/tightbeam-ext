//! The native port over an ordered key-value backend: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#indexed).

use core::slice;

use tightbeam::Errorizable;

use crate::driver::{
	CommitOutcome, ConfirmOutcome, Driver, DriverError, DriverFuture, DriverTxn, InsertOutcome, Prepared,
	RemoveOutcome, Revision, Row, RowTxnFuture, SwapOutcome,
};
use crate::frame_type::FrameType;
use crate::kv::{Key, KvValue, OrderedKv, OrderedKvTxn, Partition, Stored};
use crate::row_key::RowKey;
use crate::schema::Schema;
use crate::scope::Scope;

/// The version of the layout of this release.
const LAYOUT_VERSION: u8 = 1;

/// The partitions that each index spreads over.
const SHARDS: u32 = 1;

/// The key of the layout record, in a partition that the reserved prefix
/// keeps from every application table.
const LAYOUT: Key = Key::from_static(Partition::from_static("tightbeam-layout"), b"record");

/// The native port over the ordered key-value backend `K`.
///
/// - The rows of a table are the partition of its frame type, by row id. Each
///   value is the frame DER.
/// - `prepare` keeps one layout record, and answers `Foreign` for a backend
///   whose record names another layout or schema version.
/// - A get of the backend that answers another count of values than keys
///   fails with [`DriverError::Failed`].
///
/// # Examples
///
/// ```
/// use tightbeam_store::{Driver, Indexed, MemoryKv, Scope};
///
/// let driver = Indexed::from(MemoryKv::default());
/// assert_eq!(driver.scope(), Scope::Process);
/// ```
#[derive(Debug, Default)]
pub struct Indexed<K> {
	kv: K,
}

impl<K: OrderedKv> From<K> for Indexed<K> {
	fn from(kv: K) -> Self {
		Self { kv }
	}
}

impl<K: OrderedKv> Indexed<K> {
	/// The layout record of this release for `schema`: the layout version,
	/// the schema version, and the shard count.
	fn record(schema: &Schema) -> KvValue {
		let mut record = vec![LAYOUT_VERSION];
		record.extend(schema.version().to_be_bytes());
		record.extend(SHARDS.to_be_bytes());
		KvValue::new(record)
	}
}

impl<K: OrderedKv> Driver for Indexed<K> {
	fn prepare<'a>(&'a self, schema: &'a Schema, _tables: &'a [FrameType]) -> DriverFuture<'a, Prepared> {
		Box::pin(async move {
			let record = Self::record(schema);
			let txn = self.kv.begin().await?;
			let (txn, held) = IndexedTxn::read(txn, slice::from_ref(&LAYOUT)).await?;
			if let Some(held) = held.into_iter().flatten().next() {
				txn.rollback().await?;
				if held.bytes() == record.as_bytes() {
					return Ok(Prepared::Ready);
				}

				let foreign =
					IndexedError::Foreign { held: held.bytes().to_vec(), written: record.as_bytes().to_vec() };
				return Ok(Prepared::foreign(foreign));
			}

			let (txn, inserted) = txn.insert(&LAYOUT, &record).await?;
			if inserted == InsertOutcome::Occupied {
				txn.rollback().await?;
				return Err(DriverError::aborted(IndexedError::Raced));
			}

			match txn.commit().await? {
				CommitOutcome::Committed => Ok(Prepared::Ready),
				CommitOutcome::Conflicted(_) => Err(DriverError::aborted(IndexedError::Raced)),
			}
		})
	}

	fn begin(&self) -> DriverFuture<'_, Box<dyn DriverTxn>> {
		Box::pin(async move {
			let kv = self.kv.begin().await?;
			Ok(IndexedTxn::boxed(kv))
		})
	}

	fn scope(&self) -> Scope {
		self.kv.scope()
	}
}

/// The answers of a backend that [`Indexed`] refuses, each the source of a
/// [`DriverError`] or of [`Prepared::Foreign`].
#[derive(Debug, Errorizable)]
pub(crate) enum IndexedError {
	/// A get answered another count of values than it took keys.
	#[error("a get of {asked} keys answered {answered} values")]
	Batch {
		/// The keys of the get.
		asked: usize,
		/// The values it answered.
		answered: usize,
	},

	/// The backend holds another layout record than this release writes.
	#[error("the backend holds the layout record {held:02x?}, where this release writes {written:02x?}")]
	Foreign {
		/// The record of the backend.
		held: Vec<u8>,
		/// The record of this release.
		written: Vec<u8>,
	},

	/// Another prepare wrote the layout record first.
	#[error("another prepare wrote the layout record first")]
	Raced,
}

/// One transaction of an [`Indexed`] backend.
struct IndexedTxn {
	kv: Box<dyn OrderedKvTxn>,
}

impl IndexedTxn {
	/// The transaction `kv`, for the next call.
	fn boxed(kv: Box<dyn OrderedKvTxn>) -> Box<dyn DriverTxn> {
		Box::new(Self { kv })
	}

	/// The values of `keys` in `kv`, one for each key.
	///
	/// # Errors
	///
	/// - The [`DriverError`] of the get, or [`DriverError::Failed`] for another count of values.
	async fn read(
		kv: Box<dyn OrderedKvTxn>,
		keys: &[Key],
	) -> Result<(Box<dyn OrderedKvTxn>, Vec<Option<Stored>>), DriverError> {
		let (kv, values) = kv.get(keys).await?;
		if values.len() != keys.len() {
			return Err(DriverError::failed(IndexedError::Batch {
				asked: keys.len(),
				answered: values.len(),
			}));
		}

		Ok((kv, values))
	}
}

impl DriverTxn for IndexedTxn {
	fn get<'a>(self: Box<Self>, keys: &'a [RowKey]) -> RowTxnFuture<'a, Vec<Option<Stored>>> {
		Box::pin(async move {
			let kv_keys: Vec<Key> = keys.iter().map(Key::row).collect();
			let (kv, values) = Self::read(self.kv, &kv_keys).await?;
			Ok((Self::boxed(kv), values))
		})
	}

	fn insert<'a>(self: Box<Self>, row: &'a Row) -> RowTxnFuture<'a, InsertOutcome> {
		Box::pin(async move {
			let (key, value) = (Key::row(row.key()), KvValue::new(row.bytes()));
			let (kv, inserted) = self.kv.insert(&key, &value).await?;
			Ok((Self::boxed(kv), inserted))
		})
	}

	fn swap<'a>(self: Box<Self>, row: &'a Row, expected: &'a Revision) -> RowTxnFuture<'a, SwapOutcome> {
		Box::pin(async move {
			let (key, value) = (Key::row(row.key()), KvValue::new(row.bytes()));
			let (kv, swapped) = self.kv.swap(&key, expected, &value).await?;
			Ok((Self::boxed(kv), swapped))
		})
	}

	fn remove<'a>(self: Box<Self>, key: &'a RowKey, expected: Option<&'a Revision>) -> RowTxnFuture<'a, RemoveOutcome> {
		Box::pin(async move {
			let (kv, removed) = self.kv.remove(&Key::row(key), expected).await?;
			Ok((Self::boxed(kv), removed))
		})
	}

	fn confirm<'a>(
		self: Box<Self>,
		key: &'a RowKey,
		expected: Option<&'a Revision>,
	) -> RowTxnFuture<'a, ConfirmOutcome> {
		Box::pin(async move {
			let (kv, confirmed) = self.kv.confirm(&Key::row(key), expected).await?;
			Ok((Self::boxed(kv), confirmed))
		})
	}

	fn commit(self: Box<Self>) -> DriverFuture<'static, CommitOutcome<RowKey>> {
		Box::pin(async move {
			let committed = self.kv.commit().await?;
			Ok(committed.map_key(|key| key.row_key()))
		})
	}

	fn rollback(self: Box<Self>) -> DriverFuture<'static, ()> {
		self.kv.rollback()
	}
}

#[cfg(test)]
mod tests {
	use std::io;

	use tightbeam::builder::{FrameBuilder, TypeBuilder};
	use tightbeam::testing::{SetupEnv, TestMessage};
	use tightbeam::urn::Urn;
	use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn, Version};

	use super::*;
	use crate::memory::{MemoryDriver, MemoryKv};

	/// The table of the rows of the tests.
	const LEAVES: FrameType = FrameType::from_static("colony-leaf");

	/// The layout record of this release: layout 1, the schema version, and
	/// one shard.
	const RECORD: [u8; 13] = [1, 0xfa, 0xf0, 0x49, 0x0e, 0x50, 0xcc, 0xb4, 0x5e, 0, 0, 0, 1];

	// The layout record of this release is pinned byte for byte, since every
	// backend it wrote holds it.
	#[test]
	fn the_layout_record_is_pinned() {
		assert_eq!(Indexed::<MemoryKv>::record(&Schema::CURRENT).as_bytes(), RECORD);
	}

	/// The answers of two inserts of `row` in a fresh memory driver, in the
	/// order of their commits.
	async fn race_for(row: &Row) -> Result<[CommitOutcome<RowKey>; 2], DriverError> {
		let driver = MemoryDriver::default();
		let (first, _) = driver.begin().await?.insert(row).await?;
		let (second, _) = driver.begin().await?.insert(row).await?;
		Ok([first.commit().await?, second.commit().await?])
	}

	/// Whether the first of two inserts of one row committed.
	const WON: Urn<'static> = urn!("test", "event:store-indexed/won");

	/// Whether the commit that lost the race named the row it lost on.
	const NAMED: Urn<'static> = urn!("test", "event:store-indexed/named");

	tb_assert_spec! {
		pub ConflictSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(WON, exactly!(1), equals!(true)),
				(NAMED, exactly!(1), equals!(true))
			]
		}
	}

	// Of two inserts of one row, the commit that loses answers `Conflicted`
	// with the key of that row.
	tb_scenario! {
		name: a_lost_commit_names_its_row,
		spec: ConflictSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let message = TestMessage::sample(None);
				let frame = FrameBuilder::from(Version::V0).with_message(message).with_id("leaf").build()?;
				let row = Row::new(LEAVES, &frame).map_err(io::Error::other)?;
				let [won, lost] = race_for(&row).await.map_err(io::Error::other)?;
				trace.event_with(WON, &[], won == CommitOutcome::Committed)?;
				trace.event_with(NAMED, &[], lost == CommitOutcome::Conflicted(Some(row.key().clone())))?;
				Ok(())
			}
		}
	}

	/// The answer of a prepare of a memory driver whose layout record holds
	/// `held`.
	async fn prepared_over(held: &[u8]) -> Result<Prepared, DriverError> {
		let kv = MemoryKv::default();
		let (txn, _) = kv.begin().await?.insert(&LAYOUT, &KvValue::new(held)).await?;
		let _ = txn.commit().await?;
		Indexed::from(kv).prepare(&Schema::CURRENT, &[LEAVES]).await
	}

	/// Whether a prepare over a held layout record answered as its case says.
	const PREPARED: Urn<'static> = urn!("test", "event:store-indexed/prepared");

	tb_assert_spec! {
		pub HeldRecordSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(PREPARED, exactly!(1), equals!(true))
			]
		}
	}

	/// A scenario per held layout record: a prepare answers `Ready` over the
	/// record of this release, and `Foreign` over any other.
	macro_rules! prepared_over {
		($($name:ident => ($held:expr, $ready:expr)),+ $(,)?) => {
			$(
				tb_scenario! {
					name: $name,
					spec: HeldRecordSpec,
					environment Bare {
						exec: |SetupEnv { trace, .. }| async move {
							let prepared = prepared_over(&$held).await.map_err(io::Error::other)?;
							let answered = if $ready { matches!(prepared, Prepared::Ready) } else { matches!(prepared, Prepared::Foreign(_)) };
							trace.event_with(PREPARED, &[], answered)?;
							Ok(())
						}
					}
				}
			)+
		};
	}

	prepared_over! {
		the_own_record_prepares => (RECORD, true),
		another_layout_is_foreign => ([[2].as_slice(), &RECORD[1..]].concat(), false),
		another_schema_is_foreign => ([&RECORD[..1], &[0; 8], &RECORD[9..]].concat(), false),
		another_shard_count_is_foreign => ([&RECORD[..12], &[2]].concat(), false),
		a_short_record_is_foreign => ([1], false),
	}
}
