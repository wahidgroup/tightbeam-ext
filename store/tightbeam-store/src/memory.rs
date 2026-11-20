//! An ordered key-value backend in the memory of one process: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#memorykv).

use core::num::NonZeroU32;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use tightbeam::Errorizable;

use crate::driver::{
	CommitOutcome, ConfirmOutcome, DriverError, DriverFuture, InsertOutcome, RemoveOutcome, Revision, SwapOutcome,
};
use crate::kv::{Entry, Key, KeyRange, KvValue, OrderedKv, OrderedKvTxn, Partition, Stored, TxnFuture};
use crate::scope::Scope;
use crate::selection::Direction;

/// The most keys that one transaction of a [`MemoryKv`] writes.
const MAX_WRITES: usize = 10_000;

/// An ordered key-value backend in the memory of this process.
///
/// - A transaction is optimistic. Each read sees the committed state and the
///   writes of the transaction, and a commit answers `Conflicted` when a key
///   that the transaction relied on moved in committed state.
/// - A transaction writes at most 10 000 keys. A write of one more key
///   answers [`DriverError::Failed`], which ends the transaction.
/// - This process alone reaches the values, and they end with it, so the
///   scope is [`Scope::Process`].
///
/// # Examples
///
/// ```
/// use tightbeam_store::{MemoryKv, OrderedKv, Scope};
///
/// let kv = MemoryKv::default();
/// assert_eq!(kv.scope(), Scope::Process);
/// ```
#[derive(Debug, Default)]
pub struct MemoryKv {
	committed: Arc<Mutex<Committed>>,
}

impl OrderedKv for MemoryKv {
	fn begin(&self) -> DriverFuture<'_, Box<dyn OrderedKvTxn>> {
		let committed = Arc::clone(&self.committed);
		Box::pin(async move {
			let txn = MemoryTxn { committed, writes: BTreeMap::new(), written: 0, reads: BTreeMap::new() };
			Ok(Box::new(txn) as Box<dyn OrderedKvTxn>)
		})
	}

	fn scope(&self) -> Scope {
		Scope::Process
	}
}

/// The failures of a [`MemoryKv`], each the source of a [`DriverError::Failed`].
#[derive(Debug, Errorizable)]
enum MemoryKvError {
	/// A transaction wrote one key past the cap.
	#[error("a MemoryKv transaction writes at most {MAX_WRITES} keys")]
	Full,

	/// A panic while the committed state was locked left the lock poisoned.
	#[error("a panic left the committed state of a MemoryKv poisoned")]
	Poisoned,
}

/// The values of one partition, by sort key.
type Values = BTreeMap<Vec<u8>, Stored>;

/// The writes of a transaction in one partition, by sort key: a value, or a
/// removal for `None`.
type Writes = BTreeMap<Vec<u8>, Option<Stored>>;

/// The committed state of a [`MemoryKv`].
#[derive(Debug, Default)]
struct Committed {
	partitions: BTreeMap<Partition, Values>,
	/// The last revision this backend issued.
	issued: u64,
}

impl Committed {
	/// The committed state that `shared` holds, locked.
	///
	/// # Errors
	///
	/// - [`DriverError::Failed`] -- a panic left the lock poisoned.
	fn lock(shared: &Mutex<Self>) -> Result<MutexGuard<'_, Self>, DriverError> {
		shared.lock().map_err(|_| DriverError::failed(MemoryKvError::Poisoned))
	}

	/// The committed value of `key`.
	fn stored(&self, key: &Key) -> Option<&Stored> {
		self.partitions.get(&key.partition())?.get(key.sort())
	}

	/// A revision that no write of this backend carries yet.
	fn issue(&mut self) -> Revision {
		self.issued += 1;
		Revision::new(self.issued.to_be_bytes())
	}

	/// The first key of `reads` whose committed revision moved since the
	/// transaction read it.
	fn moved(&self, reads: &BTreeMap<Key, Option<Revision>>) -> Option<Key> {
		let moved = |(key, read): &(&Key, &Option<Revision>)| self.stored(key).map(Stored::revision) != read.as_ref();
		reads.iter().find(moved).map(|(key, _)| key.clone())
	}

	/// Apply each of `writes`: a value, or a removal for `None`.
	fn apply(&mut self, writes: BTreeMap<Partition, Writes>) {
		for (partition, writes) in writes {
			let values = self.partitions.entry(partition).or_default();
			for (sort, write) in writes {
				match write {
					Some(stored) => values.insert(sort, stored),
					None => values.remove(&sort),
				};
			}
		}
	}

	/// The first `count` committed entries of `range` along `direction`.
	fn entries(&self, range: &KeyRange, direction: Direction, count: usize) -> Vec<(&[u8], &Stored)> {
		let Some(values) = self.partitions.get(&range.partition()) else {
			return Vec::new();
		};

		let inside = values.range::<[u8], _>((range.lower(), range.upper()));
		let borrowed = inside.map(|(sort, stored)| (sort.as_slice(), stored));
		match direction {
			Direction::Ascending => borrowed.take(count).collect(),
			Direction::Descending => borrowed.rev().take(count).collect(),
		}
	}
}

/// One transaction of a [`MemoryKv`].
struct MemoryTxn {
	committed: Arc<Mutex<Committed>>,
	/// The writes of this transaction, by partition.
	writes: BTreeMap<Partition, Writes>,
	/// How many keys this transaction wrote.
	written: usize,
	/// The committed revision that each answer of this transaction relied
	/// on, or `None` for an absent key. The commit holds while each stands.
	reads: BTreeMap<Key, Option<Revision>>,
}

impl MemoryTxn {
	/// The write of this transaction at `key`: `Some(None)` for a removal,
	/// and `None` when this transaction did not write the key.
	fn own(&self, key: &Key) -> Option<&Option<Stored>> {
		self.writes.get(&key.partition())?.get(key.sort())
	}

	/// The revision `key` holds for this transaction: its own write, or the
	/// committed value.
	fn revision(&self, committed: &Committed, key: &Key) -> Option<Revision> {
		let current = match self.own(key) {
			Some(own) => own.as_ref(),
			None => committed.stored(key),
		};

		current.map(|stored| stored.revision().clone())
	}

	/// Rely on the committed revision `read` of `key` at the commit. A key
	/// this transaction wrote relies on nothing more, and a key it relied on
	/// before keeps its first reliance.
	fn rely(&mut self, key: &Key, read: Option<Revision>) {
		if self.own(key).is_none() {
			self.reads.entry(key.clone()).or_insert(read);
		}
	}

	/// Write `value` at `key` under a fresh revision, or remove it for `None`.
	///
	/// # Errors
	///
	/// - [`DriverError::Failed`] -- the write is of one more key than [`MAX_WRITES`].
	fn write(&mut self, committed: &mut Committed, key: &Key, value: Option<&KvValue>) -> Result<(), DriverError> {
		let more = self.own(key).is_none();
		if more && self.written >= MAX_WRITES {
			return Err(DriverError::failed(MemoryKvError::Full));
		}

		let stored = value.map(|value| Stored::new(value.as_bytes(), committed.issue()));
		let writes = self.writes.entry(key.partition()).or_default();
		writes.insert(key.sort().to_vec(), stored);
		if more {
			self.written += 1;
		}

		Ok(())
	}

	fn get_now(&self, keys: &[Key]) -> Result<Vec<Option<Stored>>, DriverError> {
		let committed = Committed::lock(&self.committed)?;
		let current = |key: &Key| match self.own(key) {
			Some(own) => own.clone(),
			None => committed.stored(key).cloned(),
		};

		Ok(keys.iter().map(current).collect())
	}

	fn insert_now(&mut self, key: &Key, value: &KvValue) -> Result<InsertOutcome, DriverError> {
		let shared = Arc::clone(&self.committed);
		let mut committed = Committed::lock(&shared)?;
		if self.revision(&committed, key).is_some() {
			return Ok(InsertOutcome::Occupied);
		}

		self.rely(key, None);
		self.write(&mut committed, key, Some(value))?;
		Ok(InsertOutcome::Inserted)
	}

	fn swap_now(&mut self, key: &Key, expected: &Revision, value: &KvValue) -> Result<SwapOutcome, DriverError> {
		let shared = Arc::clone(&self.committed);
		let mut committed = Committed::lock(&shared)?;
		let held = self.revision(&committed, key);
		if held.as_ref() != Some(expected) {
			return Ok(SwapOutcome::Stale);
		}

		self.rely(key, held);
		self.write(&mut committed, key, Some(value))?;
		Ok(SwapOutcome::Swapped)
	}

	fn remove_now(&mut self, key: &Key, expected: Option<&Revision>) -> Result<RemoveOutcome, DriverError> {
		let shared = Arc::clone(&self.committed);
		let mut committed = Committed::lock(&shared)?;
		let held = self.revision(&committed, key);
		let guarded = expected.is_some();
		if guarded && held.as_ref() != expected {
			return Ok(RemoveOutcome::Stale);
		}

		if guarded {
			self.rely(key, held);
		}

		self.write(&mut committed, key, None)?;
		Ok(RemoveOutcome::Removed)
	}

	/// The entries of `range` along `direction`, at most `limit`: the
	/// committed ones under the writes of this transaction.
	///
	/// The first `limit` entries need at most `limit` committed entries that
	/// stay, and one more for each removal of this transaction in the range.
	/// Only the entries returned are copied.
	fn scan_now(&self, range: &KeyRange, direction: Direction, limit: NonZeroU32) -> Result<Vec<Entry>, DriverError> {
		let limit = usize::try_from(limit.get()).unwrap_or(usize::MAX);
		let bounds = (range.lower(), range.upper());
		let own: Vec<(&[u8], Option<&Stored>)> = match self.writes.get(&range.partition()) {
			Some(writes) => writes
				.range::<[u8], _>(bounds)
				.map(|(sort, write)| (sort.as_slice(), write.as_ref()))
				.collect(),
			None => Vec::new(),
		};

		let committed = Committed::lock(&self.committed)?;
		let removals = own.iter().filter(|(_, write)| write.is_none()).count();
		let fetched = committed.entries(range, direction, limit.saturating_add(removals));
		let mut merged: BTreeMap<&[u8], &Stored> = fetched.into_iter().collect();
		for (sort, write) in own {
			match write {
				Some(stored) => merged.insert(sort, stored),
				None => merged.remove(sort),
			};
		}

		let entry = |(sort, stored): (&[u8], &Stored)| Entry::new(sort, stored.clone());
		let entries = match direction {
			Direction::Ascending => merged.into_iter().take(limit).map(entry).collect(),
			Direction::Descending => merged.into_iter().rev().take(limit).map(entry).collect(),
		};

		Ok(entries)
	}

	fn check_now(&mut self, key: &Key, expected: Option<&Revision>) -> Result<ConfirmOutcome, DriverError> {
		let shared = Arc::clone(&self.committed);
		let committed = Committed::lock(&shared)?;
		let held = self.revision(&committed, key);
		if held.as_ref() != expected {
			return Ok(ConfirmOutcome::Changed);
		}

		self.rely(key, held);
		Ok(ConfirmOutcome::Held)
	}

	fn commit_now(self) -> Result<CommitOutcome<Key>, DriverError> {
		let Self { committed: shared, writes, reads, .. } = self;
		let mut committed = Committed::lock(&shared)?;
		if let Some(key) = committed.moved(&reads) {
			return Ok(CommitOutcome::Conflicted(Some(key)));
		}

		committed.apply(writes);
		Ok(CommitOutcome::Committed)
	}
}

impl OrderedKvTxn for MemoryTxn {
	fn get<'a>(self: Box<Self>, keys: &'a [Key]) -> TxnFuture<'a, Vec<Option<Stored>>> {
		Box::pin(async move {
			let read = self.get_now(keys)?;
			Ok((self as Box<dyn OrderedKvTxn>, read))
		})
	}

	fn insert<'a>(mut self: Box<Self>, key: &'a Key, value: &'a KvValue) -> TxnFuture<'a, InsertOutcome> {
		Box::pin(async move {
			let inserted = self.insert_now(key, value)?;
			Ok((self as Box<dyn OrderedKvTxn>, inserted))
		})
	}

	fn swap<'a>(
		mut self: Box<Self>,
		key: &'a Key,
		expected: &'a Revision,
		value: &'a KvValue,
	) -> TxnFuture<'a, SwapOutcome> {
		Box::pin(async move {
			let swapped = self.swap_now(key, expected, value)?;
			Ok((self as Box<dyn OrderedKvTxn>, swapped))
		})
	}

	fn remove<'a>(mut self: Box<Self>, key: &'a Key, expected: Option<&'a Revision>) -> TxnFuture<'a, RemoveOutcome> {
		Box::pin(async move {
			let removed = self.remove_now(key, expected)?;
			Ok((self as Box<dyn OrderedKvTxn>, removed))
		})
	}

	fn scan<'a>(
		self: Box<Self>,
		range: &'a KeyRange,
		direction: Direction,
		limit: NonZeroU32,
	) -> TxnFuture<'a, Vec<Entry>> {
		Box::pin(async move {
			let entries = self.scan_now(range, direction, limit)?;
			Ok((self as Box<dyn OrderedKvTxn>, entries))
		})
	}

	fn check<'a>(mut self: Box<Self>, key: &'a Key, expected: Option<&'a Revision>) -> TxnFuture<'a, ConfirmOutcome> {
		Box::pin(async move {
			let checked = self.check_now(key, expected)?;
			Ok((self as Box<dyn OrderedKvTxn>, checked))
		})
	}

	fn commit(self: Box<Self>) -> DriverFuture<'static, CommitOutcome<Key>> {
		Box::pin(async move { self.commit_now() })
	}

	fn rollback(self: Box<Self>) -> DriverFuture<'static, ()> {
		Box::pin(async move {
			drop(self);
			Ok(())
		})
	}
}

#[cfg(test)]
mod tests {
	use core::slice;
	use std::io;
	use std::thread;

	use tightbeam::testing::SetupEnv;
	use tightbeam::urn::Urn;
	use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn};

	use super::*;

	/// The partition of the keys of these tests.
	const CAPPED: Partition = Partition::from_static("capped");

	/// The key of the write numbered `index`.
	fn key(index: usize) -> Result<Key, io::Error> {
		Key::new(CAPPED, index.to_be_bytes()).map_err(io::Error::other)
	}

	/// Whether the write of one key past the cap failed.
	const PAST_THE_CAP: Urn<'static> = urn!("test", "event:memory-kv/past-the-cap");

	/// Whether the transaction that failed committed none of its writes.
	const NONE_COMMITTED: Urn<'static> = urn!("test", "event:memory-kv/none-committed");

	tb_assert_spec! {
		pub CappedSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(PAST_THE_CAP, exactly!(1), equals!(true)),
				(NONE_COMMITTED, exactly!(1), equals!(true))
			]
		}
	}

	// A transaction that holds 10 000 written keys fails the write of one
	// more key. The failure ends it, so none of its writes commit.
	tb_scenario! {
		name: a_transaction_past_the_cap_fails_and_commits_nothing,
		spec: CappedSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let kv = MemoryKv::default();
				let filler = KvValue::new(b"filler".to_vec());
				let mut txn = kv.begin().await.map_err(io::Error::other)?;
				for index in 0..MAX_WRITES {
					let key = key(index)?;
					let (filled, inserted) = txn.insert(&key, &filler).await.map_err(io::Error::other)?;
					if inserted != InsertOutcome::Inserted {
						return Err(io::Error::other("a write under the cap did not take").into());
					}

					txn = filled;
				}

				let past = key(MAX_WRITES)?;
				let refused = txn.insert(&past, &filler).await;
				trace.event_with(PAST_THE_CAP, &[], matches!(refused, Err(DriverError::Failed(_))))?;

				let first = key(0)?;
				let reader = kv.begin().await.map_err(io::Error::other)?;
				let (_, read) = reader.get(slice::from_ref(&first)).await.map_err(io::Error::other)?;
				trace.event_with(NONE_COMMITTED, &[], read == [None])?;
				Ok(())
			}
		}
	}

	/// Whether a transaction on a poisoned lock failed its read.
	const POISONED: Urn<'static> = urn!("test", "event:memory-kv/poisoned");

	tb_assert_spec! {
		pub PoisonedSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(POISONED, exactly!(1), equals!(true))
			]
		}
	}

	// A panic while a thread holds the committed state poisons its lock, and
	// the next read of a transaction fails rather than read a state that a
	// write may have left half done.
	tb_scenario! {
		name: a_read_on_a_poisoned_lock_fails,
		spec: PoisonedSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let kv = MemoryKv::default();
				let shared = Arc::clone(&kv.committed);
				let panicked = thread::spawn(move || {
					let _held = shared.lock();
					panic!("a panic while the committed state is locked");
				})
				.join();

				let first = key(0)?;
				let txn = kv.begin().await.map_err(io::Error::other)?;
				let read = txn.get(slice::from_ref(&first)).await;
				trace.event_with(POISONED, &[], panicked.is_err() && matches!(read, Err(DriverError::Failed(_))))?;
				Ok(())
			}
		}
	}
}
