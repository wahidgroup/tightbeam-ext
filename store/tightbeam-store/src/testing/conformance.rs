//! The clauses of the KV contract that `docs/store.md` (The KV contract)
//! lists, which a KV driver checks in its tests against fresh backends of its
//! own.

use core::error::Error;
use core::fmt;
use core::future::Future;
use core::num::NonZeroU32;
use core::ops::Bound;
use core::slice;
use core::time::Duration;

use tightbeam::marker::{MaybeSend, MaybeSync};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio::{join, select};

use crate::driver::{CommitOutcome, ConfirmOutcome, DriverError, InsertOutcome, RemoveOutcome, Revision, SwapOutcome};
use crate::kv::{Entry, Key, KeyRange, KvValue, OrderedKv, OrderedKvTxn, Partition, Stored, TxnFuture};
use crate::selection::Direction;

/// How long one step of a clause waits before the check reads it as hung.
const PATIENCE: Duration = Duration::from_secs(5);

/// The share of the patience that a racer waits for its rival: a tenth.
const RIVAL_SHARE: u32 = 10;

/// The most entries that one scan of the check reads.
const ALL: NonZeroU32 = NonZeroU32::new(100).unwrap();

/// The limit of a scan that stops short.
const TWO: NonZeroU32 = NonZeroU32::new(2).unwrap();

/// The partition of most keys of the check.
const NORTH: Partition = Partition::from_static("conformance-north");

/// The partition beside [`NORTH`].
const SOUTH: Partition = Partition::from_static("conformance-south");

/// A partition whose name starts the names of [`NORTH`] and [`SOUTH`].
const PREFIX: Partition = Partition::from_static("conformance");

/// The shortest partition.
const SHORTEST: Partition = Partition::from_static("c");

/// The longest partition, with a slash.
const LONGEST: Partition =
	Partition::from_static("conformance/longest/partition-of-eighty-bytes-0123456789012345678901234567890123");

const _: () = assert!(LONGEST.as_bytes().len() == Partition::MAX_LEN);

/// The longest sort key.
static LONGEST_SORT: [u8; Key::MAX_SORT] = [0xab; Key::MAX_SORT];

/// The largest value of the clause of exact bytes, in bytes.
const LARGE_VALUE: usize = 65_536;

/// One clause of the KV contract, by the name that `docs/store.md` gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KvClause {
	/// A write stays hidden from other transactions until it commits.
	Isolates,
	/// A transaction reads its own writes.
	ReadsOwn,
	/// A commit makes every write visible, or none.
	CommitsAtomic,
	/// A rollback and a drop discard every write and free the keys.
	Discards,
	/// An insert of a present key answers `Occupied` and keeps the value.
	InsertsOnce,
	/// Of concurrent inserts of one key, at most one commits.
	RacesInsert,
	/// A swap or a guarded remove of another revision answers `Stale`.
	GuardsRevision,
	/// Of concurrent guarded writes from one revision, at most one commits.
	RacesSwap,
	/// A checked key that changes, appears, or vanishes fails the commit.
	ChecksReads,
	/// An unguarded remove of an absent key answers `Removed`.
	RemovesAbsent,
	/// Two values of one key with other bytes carry other revisions.
	Revises,
	/// A read returns the exact bytes written.
	Preserves,
	/// A partition holds only its own entries.
	SeparatesPartitions,
	/// A scan reads its range in unsigned byte order, at most its limit.
	ScansOrdered,
	/// A batch get answers in the order of its keys.
	GetsBatch,
	/// The backend takes partitions of 1 to 80 bytes and sort keys of 1 to
	/// 621 bytes.
	AcceptsKeys,
	/// A write answers `Occupied`, `Stale`, or `Changed` only for a competing
	/// commit the read view holds.
	ConflictsEarly,
	/// A conflict that ends a transaction answers `DriverError::Aborted`.
	AbortsTyped,
}

impl KvClause {
	/// Every clause, in the order of `docs/store.md`, which
	/// [`KvConformance::check`] runs.
	pub const ALL: [Self; 18] = [
		Self::Isolates,
		Self::ReadsOwn,
		Self::CommitsAtomic,
		Self::Discards,
		Self::InsertsOnce,
		Self::RacesInsert,
		Self::GuardsRevision,
		Self::RacesSwap,
		Self::ChecksReads,
		Self::RemovesAbsent,
		Self::Revises,
		Self::Preserves,
		Self::SeparatesPartitions,
		Self::ScansOrdered,
		Self::GetsBatch,
		Self::AcceptsKeys,
		Self::ConflictsEarly,
		Self::AbortsTyped,
	];

	/// The name of this clause in `docs/store.md`.
	pub const fn name(self) -> &'static str {
		match self {
			Self::Isolates => "isolates",
			Self::ReadsOwn => "reads_own",
			Self::CommitsAtomic => "commits_atomic",
			Self::Discards => "discards",
			Self::InsertsOnce => "inserts_once",
			Self::RacesInsert => "races_insert",
			Self::GuardsRevision => "guards_revision",
			Self::RacesSwap => "races_swap",
			Self::ChecksReads => "checks_reads",
			Self::RemovesAbsent => "removes_absent",
			Self::Revises => "revises",
			Self::Preserves => "preserves",
			Self::SeparatesPartitions => "separates_partitions",
			Self::ScansOrdered => "scans_ordered",
			Self::GetsBatch => "gets_batch",
			Self::AcceptsKeys => "accepts_keys",
			Self::ConflictsEarly => "conflicts_early",
			Self::AbortsTyped => "aborts_typed",
		}
	}
}

impl fmt::Display for KvClause {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.name())
	}
}

/// The clause of the KV contract that a driver breaks, and how.
pub enum KvBreach {
	/// At `step` of `clause`, the driver answered `answered` where the clause
	/// places `expected`.
	Answered {
		/// The clause that the answer breaks.
		clause: KvClause,
		/// The step of the clause, with its inputs.
		step: String,
		/// The answer of the driver.
		answered: String,
		/// What the clause places.
		expected: String,
	},
	/// At `step` of `clause`, the driver failed with `error`.
	Failed {
		/// The clause that the failure breaks.
		clause: KvClause,
		/// The step that failed, with its inputs.
		step: String,
		/// The failure of the driver.
		error: DriverError,
	},
	/// `step` of `clause` did not settle within the patience of the check.
	Lapsed {
		/// The clause that waited.
		clause: KvClause,
		/// The step that the clause waited for, with its inputs.
		step: String,
		/// How long the step waited.
		patience: Duration,
	},
}

impl KvBreach {
	/// The clause that the driver breaks.
	pub fn clause(&self) -> KvClause {
		match self {
			Self::Answered { clause, .. } | Self::Failed { clause, .. } | Self::Lapsed { clause, .. } => *clause,
		}
	}
}

impl fmt::Display for KvBreach {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Answered { clause, step, answered, expected } => {
				write!(
					f,
					"the driver breaks {clause}: {step} answered {answered}, where the clause places {expected}"
				)
			}
			Self::Failed { clause, step, error } => write!(f, "the driver breaks {clause}: {step} failed: {error}"),
			Self::Lapsed { clause, step, patience } => {
				write!(f, "the driver breaks {clause}: {step} did not settle within {patience:?}")
			}
		}
	}
}

/// The text of a breach, which a test that returns `Result<(), KvBreach>`
/// prints.
impl fmt::Debug for KvBreach {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}

impl Error for KvBreach {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Failed { error, .. } => Some(error),
			Self::Answered { .. } | Self::Lapsed { .. } => None,
		}
	}
}

/// The factory of the empty backends of a check, one per clause.
///
/// A closure that returns a future of `Result<impl OrderedKv, DriverError>`
/// is a factory.
pub trait FreshKv: MaybeSync {
	/// The backend under check.
	type Kv: OrderedKv;

	/// One more empty backend.
	///
	/// # Errors
	///
	/// - The [`DriverError`] of a backend that could not be built.
	fn fresh(&self) -> impl Future<Output = Result<Self::Kv, DriverError>> + MaybeSend;
}

impl<F, Fut, K> FreshKv for F
where
	F: Fn() -> Fut + MaybeSync,
	Fut: Future<Output = Result<K, DriverError>> + MaybeSend,
	K: OrderedKv,
{
	type Kv = K;

	fn fresh(&self) -> impl Future<Output = Result<K, DriverError>> + MaybeSend {
		self()
	}
}

/// The clauses of the KV contract that `docs/store.md` (The KV contract)
/// lists, as one check of one driver.
///
/// - Each clause runs on a fresh backend that `fresh` builds.
/// - Racing transactions share one task and signal each other. A racer waits
///   for its rival while the rival answers calls, and reads a rival silent for
///   a tenth of the patience as blocked, so a backend that blocks a write
///   behind an open transaction meets every clause. A single call slower than
///   that tenth reads as blocked too.
/// - The check runs on a tokio runtime with its timer, which bounds each step.
///
/// # Examples
///
/// ```
/// use tightbeam_store::testing::{KvBreach, KvConformance};
/// use tightbeam_store::MemoryKv;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), KvBreach> {
/// KvConformance::new(|| async { Ok(MemoryKv::default()) }).check().await
/// # }
/// ```
pub struct KvConformance<F> {
	fresh: F,
	/// How long one step of a clause waits.
	patience: Duration,
}

impl<F: FreshKv> KvConformance<F> {
	/// The check of the backends that `fresh` builds. Each step of a clause
	/// waits at most five seconds.
	pub fn new(fresh: F) -> Self {
		Self { fresh, patience: PATIENCE }
	}

	/// This check, with each step waiting at most `patience`.
	#[must_use]
	pub fn with_patience(self, patience: Duration) -> Self {
		Self { patience, ..self }
	}

	/// Check each clause of [`KvClause::ALL`], each on a fresh backend.
	///
	/// # Errors
	///
	/// - The [`KvBreach`] of the first clause that the driver breaks.
	pub async fn check(&self) -> Result<(), KvBreach> {
		for clause in KvClause::ALL {
			self.clause(clause).await?;
		}

		Ok(())
	}

	/// Check `clause` alone, on a fresh backend.
	///
	/// # Errors
	///
	/// - The [`KvBreach`] of the run. A `DriverError::Failed` inside a race
	///   breaks [`KvClause::AbortsTyped`], whichever clause raced.
	pub async fn clause(&self, clause: KvClause) -> Result<(), KvBreach> {
		let probe = self.probe(clause).await?;
		match clause {
			KvClause::Isolates => probe.isolates().await,
			KvClause::ReadsOwn => probe.reads_own().await,
			KvClause::CommitsAtomic => probe.commits_atomic().await,
			KvClause::Discards => probe.discards().await,
			KvClause::InsertsOnce => probe.inserts_once().await,
			KvClause::RacesInsert => probe.races_insert().await,
			KvClause::GuardsRevision => probe.guards_revision().await,
			KvClause::RacesSwap => probe.races_swap().await,
			KvClause::ChecksReads => probe.checks_reads().await,
			KvClause::RemovesAbsent => probe.removes_absent().await,
			KvClause::Revises => probe.revises().await,
			KvClause::Preserves => probe.preserves().await,
			KvClause::SeparatesPartitions => probe.separates_partitions().await,
			KvClause::ScansOrdered => probe.scans_ordered().await,
			KvClause::GetsBatch => probe.gets_batch().await,
			KvClause::AcceptsKeys => probe.accepts_keys().await,
			KvClause::ConflictsEarly => probe.conflicts_early().await,
			KvClause::AbortsTyped => probe.aborts_typed().await,
		}
	}

	/// The probe of `clause` on a fresh backend.
	///
	/// # Errors
	///
	/// - [`KvBreach::Lapsed`] or [`KvBreach::Failed`] -- the factory built no backend.
	async fn probe(&self, clause: KvClause) -> Result<Probe<F::Kv>, KvBreach> {
		let building = Probe { clause, patience: self.patience, kv: () };
		let kv = building.call("the build of a fresh backend", self.fresh.fresh()).await?;
		Ok(Probe { clause, patience: self.patience, kv })
	}
}

/// The bytes of a key or a value, as a breach prints them.
#[derive(PartialEq, Eq)]
struct Shown<'a>(&'a [u8]);

impl fmt::Debug for Shown<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "\"{}\"", self.0.escape_ascii())
	}
}

impl<'a> From<&'a Stored> for Shown<'a> {
	fn from(stored: &'a Stored) -> Self {
		Self(stored.bytes())
	}
}

impl<'a> From<&'a Entry> for (Shown<'a>, Shown<'a>) {
	fn from(entry: &'a Entry) -> Self {
		(Shown(entry.sort()), Shown(entry.stored().bytes()))
	}
}

/// One scan of the clause of ordered scans: its bounds, its direction, its
/// limit, and the indexes of the seeded sort keys it reads, in order.
type OrderedScan<'a> = (Bound<&'a [u8]>, Bound<&'a [u8]>, Direction, NonZeroU32, &'a [usize]);

/// One race of guarded writes from one revision: the sort key of its key, and
/// the value each racer leaves, or `None` for a remove.
type GuardedRace<'a> = (&'static [u8], Option<&'a [u8]>, Option<&'a [u8]>);

/// A signal between racing transactions, which carries the value it opens
/// with.
struct Gate<T> {
	sender: watch::Sender<Option<T>>,
}

impl<T: Clone> Gate<T> {
	/// A closed gate.
	fn new() -> Self {
		let (sender, _) = watch::channel(None);
		Self { sender }
	}

	/// Open this gate with `value`.
	fn open(&self, value: T) {
		self.sender.send_replace(Some(value));
	}

	/// Whether this gate is open.
	fn is_open(&self) -> bool {
		self.sender.borrow().is_some()
	}
}

/// One racing transaction, as its rival sees it: a beat at each answer of
/// the backend, and its end. A racer that is slow keeps beating, and one
/// that is blocked goes silent.
struct Lane {
	beats: watch::Sender<()>,
	ended: Gate<Raced>,
}

impl Lane {
	/// A lane with no beat and no end.
	fn new() -> Self {
		let (beats, _) = watch::channel(());
		Self { beats, ended: Gate::new() }
	}

	/// Mark one answer of the backend.
	fn beat(&self) {
		self.beats.send_replace(());
	}

	/// The value `gate` opens with, waiting while this lane beats, or `None`
	/// once the lane goes silent for `silence` with the gate closed.
	async fn waits<T: Clone>(&self, gate: &Gate<T>, silence: Duration) -> Option<T> {
		let mut opened = gate.sender.subscribe();
		let mut beats = self.beats.subscribe();
		loop {
			select! {
				value = opened.wait_for(Option::is_some) => return value.ok().and_then(|value| (*value).clone()),
				beat = timeout(silence, beats.changed()) => {
					if !matches!(beat, Ok(Ok(()))) {
						return None;
					}
				}
			}
		}
	}
}

/// The signals of a race of a check against a rival write.
struct CheckLanes {
	/// Opens once the check held.
	checked: Gate<()>,
	checker: Lane,
	rival: Lane,
}

impl CheckLanes {
	/// The signals of one race of a check.
	fn new() -> Self {
		Self { checked: Gate::new(), checker: Lane::new(), rival: Lane::new() }
	}
}

/// One write of a transaction, or a check, that has to take.
enum Write<'a> {
	/// An insert of the value at the key.
	Insert(&'a Key, KvValue),
	/// A swap of the key from the revision to the value.
	Swap(&'a Key, &'a Revision, KvValue),
	/// A remove of the key, guarded by the revision or unguarded.
	Remove(&'a Key, Option<&'a Revision>),
	/// A check that the key holds the revision, or is absent.
	Check(&'a Key, Option<&'a Revision>),
}

impl fmt::Display for Write<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Insert(key, value) => write!(f, "an insert of {:?} at {key}", Shown(value.as_bytes())),
			Self::Swap(key, _, value) => write!(f, "a swap to {:?} at {key}", Shown(value.as_bytes())),
			Self::Remove(key, Some(_)) => write!(f, "a guarded remove at {key}"),
			Self::Remove(key, None) => write!(f, "an unguarded remove at {key}"),
			Self::Check(key, Some(_)) => write!(f, "a check of a revision at {key}"),
			Self::Check(key, None) => write!(f, "a check of absence at {key}"),
		}
	}
}

impl Write<'_> {
	/// Run this write in `txn`: the transaction back, and `None` when the
	/// write took, or the answer that refused it.
	fn run<'t>(&'t self, txn: Box<dyn OrderedKvTxn>) -> TxnFuture<'t, Option<String>> {
		match self {
			Self::Insert(key, value) => {
				let answered = txn.insert(key, value);
				Box::pin(async move {
					let (txn, inserted) = answered.await?;
					Ok((txn, (inserted != InsertOutcome::Inserted).then(|| format!("{inserted:?}"))))
				})
			}
			Self::Swap(key, expected, value) => {
				let answered = txn.swap(key, expected, value);
				Box::pin(async move {
					let (txn, swapped) = answered.await?;
					Ok((txn, (swapped != SwapOutcome::Swapped).then(|| format!("{swapped:?}"))))
				})
			}
			Self::Remove(key, expected) => {
				let answered = txn.remove(key, *expected);
				Box::pin(async move {
					let (txn, removed) = answered.await?;
					Ok((txn, (removed != RemoveOutcome::Removed).then(|| format!("{removed:?}"))))
				})
			}
			Self::Check(key, expected) => {
				let answered = txn.check(key, *expected);
				Box::pin(async move {
					let (txn, checked) = answered.await?;
					Ok((txn, (checked != ConfirmOutcome::Held).then(|| format!("{checked:?}"))))
				})
			}
		}
	}
}

/// How one racing transaction ended.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Raced {
	/// Every write took, and the commit committed.
	Committed,
	/// The racer rolled back as its script says.
	RolledBack,
	/// A write did not take, with the answer, and the racer rolled back.
	Refused(String),
	/// The commit answered `Conflicted`.
	Conflicted,
	/// The backend aborted the transaction.
	Aborted,
}

/// One step of a racing transaction.
enum Step<'a> {
	/// A write, or a check, that has to take.
	Write(Write<'a>),
	/// Open the gate.
	Open(&'a Gate<()>),
	/// Wait for the gate while the lane of the rival beats.
	Wait(&'a Gate<()>, &'a Lane),
	/// Wait for the end of the rival while its lane beats.
	Rival(&'a Lane),
	/// Commit, which ends the racer.
	Commit,
	/// Roll back, which ends the racer.
	Rollback,
}

/// One clause of a check, on its fresh backend. It owns each step of the
/// clause and the patience of each wait.
struct Probe<K> {
	clause: KvClause,
	patience: Duration,
	kv: K,
}

impl<K> Probe<K> {
	/// The output of `future`, once it settles within the patience.
	///
	/// # Errors
	///
	/// - [`KvBreach::Lapsed`] -- `future` did not settle in time, at `step`.
	async fn within<T>(&self, step: &str, future: impl Future<Output = T>) -> Result<T, KvBreach> {
		let Self { clause, patience, .. } = *self;
		let bounded = timeout(patience, future).await;
		bounded.map_err(|_| KvBreach::Lapsed { clause, step: step.to_owned(), patience })
	}

	/// The answer of the port call `future` at `step`.
	///
	/// # Errors
	///
	/// - [`KvBreach::Lapsed`] -- the call did not settle in time.
	/// - [`KvBreach::Failed`] -- the call failed.
	async fn call<T>(&self, step: &str, future: impl Future<Output = Result<T, DriverError>>) -> Result<T, KvBreach> {
		let answered = self.within(step, future).await?;
		answered.map_err(|error| KvBreach::Failed { clause: self.clause, step: step.to_owned(), error })
	}

	/// The breach of the answer `answered` at `step`, where the clause places
	/// `expected`.
	fn refuse(&self, step: &str, answered: &impl fmt::Debug, expected: &impl fmt::Debug) -> KvBreach {
		let answered = format!("{answered:?}");
		let expected = format!("{expected:?}");
		KvBreach::Answered { clause: self.clause, step: step.to_owned(), answered, expected }
	}

	/// Expect `answered` at `step` to be `expected`.
	///
	/// # Errors
	///
	/// - [`KvBreach::Answered`] -- the driver answered anything else.
	fn expect<T: PartialEq + fmt::Debug>(&self, step: &str, answered: T, expected: T) -> Result<(), KvBreach> {
		if answered != expected {
			return Err(self.refuse(step, &answered, &expected));
		}

		Ok(())
	}

	/// How long a rival may go silent before a racer reads it as blocked.
	fn rival_wait(&self) -> Duration {
		self.patience / RIVAL_SHARE
	}

	/// The range of `partition` from `lower` to `upper`, which the check
	/// builds only from bounds that admit a key.
	///
	/// # Errors
	///
	/// - [`KvBreach::Answered`] -- the bounds admit no key, a defect of the check.
	fn range(&self, partition: Partition, lower: Bound<&[u8]>, upper: Bound<&[u8]>) -> Result<KeyRange, KvBreach> {
		let range = KeyRange::new(partition, lower.map(<[u8]>::to_vec), upper.map(<[u8]>::to_vec));
		range.ok_or_else(|| self.refuse("a range of the check", &(lower, upper), &"bounds that admit a key"))
	}

	/// The answer of the port call `future` at `step` of a race, or `None`
	/// when the backend aborted the transaction.
	///
	/// # Errors
	///
	/// - [`KvBreach::Lapsed`] -- the call did not settle in time.
	/// - [`KvBreach::Failed`] of [`KvClause::AbortsTyped`] -- the call failed with another error than an
	///   abort, which a conflict in a race never answers.
	async fn racing<T>(
		&self,
		step: &str,
		future: impl Future<Output = Result<T, DriverError>>,
	) -> Result<Option<T>, KvBreach> {
		match self.within(step, future).await? {
			Ok(answered) => Ok(Some(answered)),
			Err(DriverError::Aborted(_)) => Ok(None),
			Err(error) => {
				let step = format!("{step}, in a race of {}", self.clause);
				Err(KvBreach::Failed { clause: KvClause::AbortsTyped, step, error })
			}
		}
	}
}

impl<K: OrderedKv> Probe<K> {
	/// The transaction of the call `future` at `step`, once it answers
	/// `expected`.
	///
	/// # Errors
	///
	/// - The breach of the call, or [`KvBreach::Answered`] for another answer.
	async fn answers<T: PartialEq + fmt::Debug>(
		&self,
		step: &str,
		future: TxnFuture<'_, T>,
		expected: T,
	) -> Result<Box<dyn OrderedKvTxn>, KvBreach> {
		let (txn, answered) = self.call(step, future).await?;
		self.expect(step, answered, expected)?;
		Ok(txn)
	}

	/// The transaction of `writes` in `txn`, once each takes.
	///
	/// # Errors
	///
	/// - The breach of a write, or [`KvBreach::Answered`] for a write that did not take.
	async fn takes(
		&self,
		mut txn: Box<dyn OrderedKvTxn>,
		writes: &[Write<'_>],
	) -> Result<Box<dyn OrderedKvTxn>, KvBreach> {
		for write in writes {
			let step = write.to_string();
			let (back, refused) = self.call(&step, write.run(txn)).await?;
			self.expect(&step, refused, None)?;
			txn = back;
		}

		Ok(txn)
	}

	/// A transaction of the backend.
	///
	/// # Errors
	///
	/// - The breach of the begin.
	async fn begin(&self) -> Result<Box<dyn OrderedKvTxn>, KvBreach> {
		self.call("a begin", self.kv.begin()).await
	}

	/// Commit `txn`, expecting it to commit.
	///
	/// # Errors
	///
	/// - The breach of the commit, or [`KvBreach::Answered`] for a conflict.
	async fn commit(&self, step: &str, txn: Box<dyn OrderedKvTxn>) -> Result<(), KvBreach> {
		let committed = self.call(step, txn.commit()).await?;
		self.expect(step, committed, CommitOutcome::Committed)
	}

	/// Roll back `txn`.
	///
	/// # Errors
	///
	/// - The breach of the rollback.
	async fn rollback(&self, txn: Box<dyn OrderedKvTxn>) -> Result<(), KvBreach> {
		self.call("a rollback", txn.rollback()).await
	}

	/// Insert each of `seeds` in one transaction, and commit it.
	///
	/// # Errors
	///
	/// - The breach of a step, or [`KvBreach::Answered`] for an insert that did not take.
	async fn seed(&self, seeds: &[(&Key, &[u8])]) -> Result<(), KvBreach> {
		let writes: Vec<Write<'_>> = seeds
			.iter()
			.map(|(key, bytes)| Write::Insert(key, KvValue::new(*bytes)))
			.collect();
		let txn = self.begin().await?;
		let txn = self.takes(txn, &writes).await?;
		self.commit("the commit of the seeds", txn).await
	}

	/// The committed value of `key`, read alone in a transaction of its own,
	/// so only the clause of batch gets reads a batch.
	///
	/// # Errors
	///
	/// - The breach of a step.
	async fn read(&self, key: &Key) -> Result<Option<Stored>, KvBreach> {
		let txn = self.begin().await?;
		let step = format!("a get of the committed value at {key}");
		let (txn, read) = self.call(&step, txn.get(slice::from_ref(key))).await?;

		self.rollback(txn).await?;

		Ok(read.into_iter().next().flatten())
	}

	/// The committed revision of the present key `key`.
	///
	/// # Errors
	///
	/// - The breach of a step, or [`KvBreach::Answered`] for an absent key.
	async fn revision(&self, key: &Key) -> Result<Revision, KvBreach> {
		let read = self.read(key).await?;
		let revision = read.as_ref().map(|stored| stored.revision().clone());
		let step = format!("the read of the committed key at {key}");
		revision.ok_or_else(|| self.refuse(&step, &read, &"a value"))
	}

	/// Expect each committed key of `expected` to hold its bytes, or to be
	/// absent for `None`.
	///
	/// # Errors
	///
	/// - The breach of a step, or [`KvBreach::Answered`] at `step` for any other value.
	async fn holds(&self, step: &str, expected: &[(&Key, Option<&[u8]>)]) -> Result<(), KvBreach> {
		for (key, bytes) in expected {
			let read = self.read(key).await?;
			let step = format!("{step}, at {key}");
			self.expect(&step, read.as_ref().map(Shown::from), bytes.map(Shown))?;
		}

		Ok(())
	}

	/// The transaction of a get of `key` in `txn`, once it answers `expected`.
	///
	/// # Errors
	///
	/// - The breach of the get, or [`KvBreach::Answered`] for another value.
	async fn reads(
		&self,
		txn: Box<dyn OrderedKvTxn>,
		key: &Key,
		expected: Option<&[u8]>,
	) -> Result<Box<dyn OrderedKvTxn>, KvBreach> {
		let step = format!("a get at {key}");
		let (txn, read) = self.call(&step, txn.get(slice::from_ref(key))).await?;
		let answered = read.first().and_then(Option::as_ref).map(Shown::from);

		self.expect(&step, answered, expected.map(Shown))?;

		Ok(txn)
	}

	/// The transaction and the revision of the present key `key` in `txn`.
	///
	/// # Errors
	///
	/// - The breach of the get, or [`KvBreach::Answered`] for an absent key.
	async fn own_revision(
		&self,
		txn: Box<dyn OrderedKvTxn>,
		key: &Key,
	) -> Result<(Box<dyn OrderedKvTxn>, Revision), KvBreach> {
		let step = format!("a get of the own write at {key}");
		let (txn, read) = self.call(&step, txn.get(slice::from_ref(key))).await?;
		let revision = read.first().and_then(Option::as_ref).map(|stored| stored.revision().clone());
		let revision = revision.ok_or_else(|| self.refuse(&step, &read, &"a value"))?;
		Ok((txn, revision))
	}

	/// The transaction of a scan of `range` in `txn`, once it answers the
	/// sort keys and bytes `expected`.
	///
	/// # Errors
	///
	/// - The breach of the scan, or [`KvBreach::Answered`] for other entries.
	async fn scans(
		&self,
		txn: Box<dyn OrderedKvTxn>,
		range: &KeyRange,
		(direction, limit): (Direction, NonZeroU32),
		expected: &[(&[u8], &[u8])],
	) -> Result<Box<dyn OrderedKvTxn>, KvBreach> {
		let step = format!("a scan of {range}, {direction:?}, at most {limit}");
		let (txn, entries) = self.call(&step, txn.scan(range, direction, limit)).await?;
		let answered: Vec<(Shown<'_>, Shown<'_>)> = entries.iter().map(Into::into).collect();
		let expected: Vec<(Shown<'_>, Shown<'_>)> =
			expected.iter().map(|(sort, bytes)| (Shown(sort), Shown(bytes))).collect();

		self.expect(&step, answered, expected)?;

		Ok(txn)
	}

	/// Run `script` in one transaction on `lane`, then open each gate it
	/// opens and the end of `lane`, so a rival never waits on a racer that
	/// stopped early.
	///
	/// # Errors
	///
	/// - The breach of a step. An abort ends the racer.
	async fn race(&self, script: &[Step<'_>], lane: &Lane) -> Result<Raced, KvBreach> {
		let raced = self.run(script, lane).await;
		for step in script {
			if let Step::Open(gate) = step {
				gate.open(());
			}
		}

		if let Ok(raced) = &raced {
			lane.ended.open(raced.clone());
		}

		raced
	}

	/// Run `script` in one transaction, with a beat of `lane` at each answer.
	///
	/// # Errors
	///
	/// - The breach of a step. An abort ends the racer.
	async fn run(&self, script: &[Step<'_>], lane: &Lane) -> Result<Raced, KvBreach> {
		let mut txn = self.begin().await?;
		lane.beat();
		for step in script {
			txn = match step {
				Step::Write(write) => {
					let step = write.to_string();
					let answered = self.racing(&step, write.run(txn)).await?;
					lane.beat();
					let Some((txn, refused)) = answered else {
						return Ok(Raced::Aborted);
					};
					if let Some(answered) = refused {
						self.rollback(txn).await?;
						return Ok(Raced::Refused(format!("{step} answered {answered}")));
					}

					txn
				}
				Step::Open(gate) => {
					gate.open(());
					txn
				}
				Step::Wait(gate, rival) => {
					let _opened = rival.waits(gate, self.rival_wait()).await;
					txn
				}
				Step::Rival(rival) => {
					let _ended = rival.waits(&rival.ended, self.rival_wait()).await;
					txn
				}
				Step::Commit => {
					let committed = self.racing("the commit of a racer", txn.commit()).await?;
					lane.beat();
					let raced = match committed {
						Some(CommitOutcome::Committed) => Raced::Committed,
						Some(CommitOutcome::Conflicted(_)) => Raced::Conflicted,
						None => Raced::Aborted,
					};

					return Ok(raced);
				}
				Step::Rollback => {
					self.rollback(txn).await?;
					lane.beat();
					return Ok(Raced::RolledBack);
				}
			};
		}

		self.rollback(txn).await?;
		lane.beat();
		Ok(Raced::RolledBack)
	}

	/// Expect at most one of `raced` to have committed, and `key` to hold
	/// what the one that did left, or `before` when none did.
	///
	/// # Errors
	///
	/// - The breach of a read, or [`KvBreach::Answered`] at `step` for two commits or a value of
	///   another racer.
	async fn one_winner(
		&self,
		step: &str,
		raced: [(Raced, Option<&[u8]>); 2],
		key: &Key,
		before: Option<&[u8]>,
	) -> Result<(), KvBreach> {
		let read = self.read(key).await?;
		let held = read.as_ref().map(Stored::bytes);
		let winners: Vec<Option<&[u8]>> = raced
			.iter()
			.filter(|(raced, _)| *raced == Raced::Committed)
			.map(|(_, after)| *after)
			.collect();

		let left = match winners.as_slice() {
			[] => Some(before),
			[winner] => Some(*winner),
			_ => None,
		};
		if left != Some(held) {
			let answered = (&raced, held.map(Shown));
			return Err(self.refuse(step, &answered, &"at most one commit, whose write the key holds"));
		}

		Ok(())
	}

	/// Race a transaction that checks `key` at `expected` against `rival`,
	/// which waits for the check on `lanes` and then commits a write of the
	/// key. A checker that `rewrites` the key after the rival ends swaps it
	/// from the revision it reads then. Once the rival committed first, the
	/// checker does not commit.
	///
	/// # Errors
	///
	/// - The breach of a step, or [`KvBreach::Answered`] for a check that held past a competing
	///   commit, or a rival that did not take.
	async fn checked_against(
		&self,
		(key, expected): (&Key, Option<&Revision>),
		rival: &[Step<'_>],
		lanes: &CheckLanes,
		rewrites: bool,
	) -> Result<(), KvBreach> {
		let CheckLanes { checked, checker, rival: rival_lane } = lanes;
		let checking = async {
			let check = Write::Check(key, expected);
			let txn = self.begin().await?;

			checker.beat();

			let txn = self.takes(txn, slice::from_ref(&check)).await?;

			checker.beat();
			checked.open(());

			let rival = rival_lane.waits(&rival_lane.ended, self.rival_wait()).await;
			let txn = if rewrites {
				let (txn, current) = self.own_revision(txn, key).await?;

				checker.beat();

				let rewrite = Write::Swap(key, &current, KvValue::new(b"rewritten".as_slice()));
				self.takes(txn, slice::from_ref(&rewrite)).await?
			} else {
				txn
			};

			let committed = self.racing("the commit of a check", txn.commit()).await?;

			checker.beat();

			if rival == Some(Raced::Committed) && committed == Some(CommitOutcome::Committed) {
				let step = format!("the commit of {check} after a competing commit");
				return Err(self.refuse(&step, &committed, &"Conflicted, or an abort"));
			}

			Ok(())
		};

		let (checking, raced) = join!(checking, self.race(rival, rival_lane));
		checked.open(());
		checking?;

		let raced = raced?;
		if !rewrites && matches!(raced, Raced::Refused(_) | Raced::Conflicted | Raced::RolledBack) {
			return Err(self.refuse("the write that competes with a check", &raced, &"Committed, or an abort"));
		}

		Ok(())
	}

	/// Writes of each kind in an open transaction, which a transaction beside
	/// it reads as they were, in a get and in a scan, until the commit
	/// starts.
	async fn isolates(&self) -> Result<(), KvBreach> {
		let inserted = Key::from_static(NORTH, b"a-inserted");
		let swapped = Key::from_static(NORTH, b"b-swapped");
		let guarded = Key::from_static(NORTH, b"c-guarded");
		let unguarded = Key::from_static(NORTH, b"d-unguarded");

		self.seed(&[(&swapped, b"b0"), (&guarded, b"c0"), (&unguarded, b"d0")]).await?;

		let swapped_at = self.revision(&swapped).await?;
		let guarded_at = self.revision(&guarded).await?;

		let (wrote, read, committing) = (Gate::new(), Gate::new(), Gate::new());
		let (writer_lane, reader_lane) = (Lane::new(), Lane::new());
		let writer = [
			Step::Write(Write::Insert(&inserted, KvValue::new(b"open".as_slice()))),
			Step::Write(Write::Swap(&swapped, &swapped_at, KvValue::new(b"open".as_slice()))),
			Step::Write(Write::Remove(&guarded, Some(&guarded_at))),
			Step::Write(Write::Remove(&unguarded, None)),
			Step::Open(&wrote),
			Step::Wait(&read, &reader_lane),
			Step::Open(&committing),
			Step::Commit,
		];
		let before: [(&Key, Option<&[u8]>); 4] = [
			(&inserted, None),
			(&swapped, Some(b"b0")),
			(&guarded, Some(b"c0")),
			(&unguarded, Some(b"d0")),
		];

		let reading = async {
			let _wrote = writer_lane.waits(&wrote, self.rival_wait()).await;
			let mut txn = self.begin().await?;

			reader_lane.beat();

			for (key, held) in before {
				let step = format!("a get beside an open write at {key}");
				let (back, answered) = self.call(&step, txn.get(slice::from_ref(key))).await?;

				reader_lane.beat();

				let shown = answered.first().and_then(Option::as_ref).map(Shown::from);
				if shown != held.map(Shown) && !committing.is_open() {
					return Err(self.refuse(&step, &shown, &held.map(Shown)));
				}

				txn = back;
			}

			let north = KeyRange::whole(NORTH);
			let step = format!("a scan of {north} beside an open write");
			let (txn, entries) = self.call(&step, txn.scan(&north, Direction::Ascending, ALL)).await?;

			reader_lane.beat();

			let shown: Vec<(Shown<'_>, Shown<'_>)> = entries.iter().map(Into::into).collect();
			let present = before[1..]
				.iter()
				.filter_map(|(key, bytes)| Some((Shown(key.sort()), Shown((*bytes)?))));

			let held: Vec<(Shown<'_>, Shown<'_>)> = present.collect();
			if shown != held && !committing.is_open() {
				return Err(self.refuse(&step, &shown, &held));
			}

			self.rollback(txn).await?;
			read.open(());
			Ok(())
		};

		let (reading, raced) = join!(reading, self.race(&writer, &writer_lane));
		read.open(());
		reading?;

		self.expect("the commit of the open writes", raced?, Raced::Committed)?;

		let after: [(&Key, Option<&[u8]>); 4] = [
			(&inserted, Some(b"open")),
			(&swapped, Some(b"open")),
			(&guarded, None),
			(&unguarded, None),
		];

		self.holds("a read after the commit", &after).await
	}

	/// A transaction that reads its own inserts, swaps, and removes of both
	/// kinds, in a get and in scans of each direction, between bounds, under
	/// a limit, and in another partition.
	async fn reads_own(&self) -> Result<(), KvBreach> {
		let unguarded = Key::from_static(NORTH, b"a");
		let guarded = Key::from_static(NORTH, b"b");
		let kept = Key::from_static(NORTH, b"c");
		let swapped = Key::from_static(NORTH, b"d");
		let last = Key::from_static(NORTH, b"e");
		let inserted = Key::from_static(NORTH, b"f");
		let beside = Key::from_static(SOUTH, b"s");
		let south_inserted = Key::from_static(SOUTH, b"x");
		let seeds: [(&Key, &[u8]); 6] = [
			(&unguarded, b"a0"),
			(&guarded, b"b0"),
			(&kept, b"c0"),
			(&swapped, b"d0"),
			(&last, b"e0"),
			(&beside, b"s0"),
		];

		self.seed(&seeds).await?;

		let guarded_at = self.revision(&guarded).await?;
		let swapped_at = self.revision(&swapped).await?;
		let writes = [
			Write::Remove(&unguarded, None),
			Write::Remove(&guarded, Some(&guarded_at)),
			Write::Swap(&swapped, &swapped_at, KvValue::new(b"d-own".as_slice())),
			Write::Insert(&inserted, KvValue::new(b"f-own".as_slice())),
			Write::Insert(&south_inserted, KvValue::new(b"x-own".as_slice())),
		];

		let txn = self.begin().await?;
		let txn = self.takes(txn, &writes).await?;
		let txn = self.reads(txn, &unguarded, None).await?;
		let txn = self.reads(txn, &guarded, None).await?;
		let txn = self.reads(txn, &swapped, Some(b"d-own")).await?;
		let txn = self.reads(txn, &inserted, Some(b"f-own")).await?;

		// The first entry left after the own removes is committed alone, so a
		// scan of one reads past both removes to it.
		let north = KeyRange::whole(NORTH);
		let between = self.range(NORTH, Bound::Included(b"c"), Bound::Excluded(b"e"))?;
		let south = KeyRange::whole(SOUTH);
		let whole_north: [(&[u8], &[u8]); 4] = [(b"c", b"c0"), (b"d", b"d-own"), (b"e", b"e0"), (b"f", b"f-own")];
		let txn = self.scans(txn, &north, (Direction::Ascending, ALL), &whole_north).await?;
		let txn = self
			.scans(txn, &north, (Direction::Descending, TWO), &[(b"f", b"f-own"), (b"e", b"e0")])
			.await?;
		let txn = self
			.scans(txn, &north, (Direction::Ascending, NonZeroU32::MIN), &[(b"c", b"c0")])
			.await?;
		let txn = self
			.scans(txn, &between, (Direction::Ascending, ALL), &[(b"c", b"c0"), (b"d", b"d-own")])
			.await?;
		let txn = self
			.scans(txn, &south, (Direction::Ascending, ALL), &[(b"s", b"s0"), (b"x", b"x-own")])
			.await?;

		self.rollback(txn).await
	}

	/// A commit of two writes that shows both, and a commit that conflicts on
	/// its second write, which shows neither.
	async fn commits_atomic(&self) -> Result<(), KvBreach> {
		let in_north = Key::from_static(NORTH, b"all-north");
		let in_south = Key::from_static(SOUTH, b"all-south");
		let both = [
			Write::Insert(&in_north, KvValue::new(b"north".as_slice())),
			Write::Insert(&in_south, KvValue::new(b"south".as_slice())),
		];

		let txn = self.begin().await?;
		let txn = self.takes(txn, &both).await?;

		self.commit("the commit of two writes", txn).await?;
		self.holds(
			"a read after the commit",
			&[(&in_north, Some(b"north")), (&in_south, Some(b"south"))],
		)
		.await?;

		let inserted = Key::from_static(NORTH, b"a-insert");
		let contested = Key::from_static(NORTH, b"b-contested");

		self.seed(&[(&contested, b"seeded")]).await?;

		let seeded = self.revision(&contested).await?;

		let loser_wrote = Gate::new();
		let (loser_lane, winner_lane) = (Lane::new(), Lane::new());
		let loser = [
			Step::Write(Write::Insert(&inserted, KvValue::new(b"loser".as_slice()))),
			Step::Write(Write::Swap(&contested, &seeded, KvValue::new(b"loser".as_slice()))),
			Step::Open(&loser_wrote),
			Step::Rival(&winner_lane),
			Step::Commit,
		];
		let winner = [
			Step::Wait(&loser_wrote, &loser_lane),
			Step::Write(Write::Swap(&contested, &seeded, KvValue::new(b"winner".as_slice()))),
			Step::Commit,
		];

		let (lost, won) = join!(self.race(&loser, &loser_lane), self.race(&winner, &winner_lane));
		let raced = (lost?, won?);

		let insert_read = self.read(&inserted).await?;
		let swap_read = self.read(&contested).await?;
		let insert_shows = insert_read.is_some();
		let swap_shows = swap_read.as_ref().map(Stored::bytes) == Some(b"loser".as_slice());
		if insert_shows != swap_shows {
			let answered = (
				raced,
				insert_read.as_ref().map(Shown::from),
				swap_read.as_ref().map(Shown::from),
			);
			return Err(self.refuse(
				"a read after a commit that raced",
				&answered,
				&"both writes of a racer, or neither",
			));
		}

		Ok(())
	}

	/// A rollback, and a drop, of an insert, a swap, and removes of both
	/// kinds, which leave each key as it was and free for the next
	/// transaction.
	async fn discards(&self) -> Result<(), KvBreach> {
		let inserted = Key::from_static(NORTH, b"inserted");
		let swapped = Key::from_static(NORTH, b"swapped");
		let guarded = Key::from_static(NORTH, b"guarded");
		let unguarded = Key::from_static(NORTH, b"unguarded");

		self.seed(&[(&swapped, b"s0"), (&guarded, b"g0"), (&unguarded, b"u0")]).await?;

		let swapped_at = self.revision(&swapped).await?;
		let guarded_at = self.revision(&guarded).await?;
		let writes = [
			Write::Insert(&inserted, KvValue::new(b"written".as_slice())),
			Write::Swap(&swapped, &swapped_at, KvValue::new(b"written".as_slice())),
			Write::Remove(&guarded, Some(&guarded_at)),
			Write::Remove(&unguarded, None),
		];
		let before: [(&Key, Option<&[u8]>); 4] = [
			(&inserted, None),
			(&swapped, Some(b"s0")),
			(&guarded, Some(b"g0")),
			(&unguarded, Some(b"u0")),
		];

		let txn = self.begin().await?;
		let txn = self.takes(txn, &writes).await?;

		self.rollback(txn).await?;
		self.holds("a read after a rollback", &before).await?;

		let txn = self.begin().await?;
		let txn = self.takes(txn, &writes).await?;

		drop(txn);

		self.holds("a read after a drop", &before).await?;

		let txn = self.begin().await?;
		let txn = self.takes(txn, &writes).await?;

		self.commit("the commit after a rollback and a drop", txn).await?;

		let after: [(&Key, Option<&[u8]>); 4] = [
			(&inserted, Some(b"written")),
			(&swapped, Some(b"written")),
			(&guarded, None),
			(&unguarded, None),
		];
		self.holds("a read after the commit", &after).await
	}

	/// Inserts of a committed key and of an own key that answer `Occupied`
	/// and keep the value, and an insert after an own remove, which commits
	/// alone.
	async fn inserts_once(&self) -> Result<(), KvBreach> {
		let committed = Key::from_static(NORTH, b"committed");
		let own = Key::from_static(NORTH, b"own");
		let reinserted = Key::from_static(NORTH, b"reinserted");

		self.seed(&[(&committed, b"first"), (&reinserted, b"r0")]).await?;

		let first = KvValue::new(b"first".as_slice());
		let second = KvValue::new(b"second".as_slice());
		let txn = self.begin().await?;
		let step = "an insert at a committed key";
		let txn = self
			.answers(step, txn.insert(&committed, &second), InsertOutcome::Occupied)
			.await?;
		let txn = self
			.answers("an insert", txn.insert(&own, &first), InsertOutcome::Inserted)
			.await?;
		let txn = self
			.answers("an insert at an own key", txn.insert(&own, &second), InsertOutcome::Occupied)
			.await?;
		let txn = self.reads(txn, &committed, Some(b"first")).await?;

		self.commit("the commit of the inserts", txn).await?;
		self.holds(
			"a read after the commit",
			&[(&committed, Some(b"first")), (&own, Some(b"first"))],
		)
		.await?;

		let again = [
			Write::Remove(&reinserted, None),
			Write::Insert(&reinserted, KvValue::new(b"r1".as_slice())),
		];
		let txn = self.begin().await?;
		let txn = self.takes(txn, &again).await?;

		self.commit("the commit of an insert after an own remove", txn).await?;
		self.holds("a read after the reinsert", &[(&reinserted, Some(b"r1"))]).await
	}

	/// Two transactions that insert one key at once, of which at most one
	/// commits its value.
	async fn races_insert(&self) -> Result<(), KvBreach> {
		let key = Key::from_static(NORTH, b"raced");
		let (first_wrote, second_wrote) = (Gate::new(), Gate::new());
		let (first_lane, second_lane) = (Lane::new(), Lane::new());
		let first = [
			Step::Write(Write::Insert(&key, KvValue::new(b"first".as_slice()))),
			Step::Open(&first_wrote),
			Step::Wait(&second_wrote, &second_lane),
			Step::Commit,
		];
		let second = [
			Step::Write(Write::Insert(&key, KvValue::new(b"second".as_slice()))),
			Step::Open(&second_wrote),
			Step::Wait(&first_wrote, &first_lane),
			Step::Commit,
		];

		let (first, second) = join!(self.race(&first, &first_lane), self.race(&second, &second_lane));
		let raced = [(first?, Some(b"first".as_slice())), (second?, Some(b"second".as_slice()))];
		self.one_winner("two inserts of one key that raced", raced, &key, None).await
	}

	/// Swaps and guarded removes of stale revisions and of absent keys that
	/// answer `Stale` and leave the transaction usable, and own revisions that
	/// guard the next calls.
	async fn guards_revision(&self) -> Result<(), KvBreach> {
		let key = Key::from_static(NORTH, b"guarded");
		let absent = Key::from_static(NORTH, b"never-written");

		self.seed(&[(&key, b"v0")]).await?;

		let stale = self.revision(&key).await?;
		let txn = self.begin().await?;
		let txn = self
			.takes(txn, &[Write::Swap(&key, &stale, KvValue::new(b"v-1".as_slice()))])
			.await?;

		self.commit("the commit of a swap", txn).await?;

		let current = self.revision(&key).await?;
		let lost = KvValue::new(b"lost".as_slice());
		let txn = self.begin().await?;
		let txn = self
			.answers(
				"a swap from a stale revision",
				txn.swap(&key, &stale, &lost),
				SwapOutcome::Stale,
			)
			.await?;
		let step = "a remove of a stale revision";
		let txn = self.answers(step, txn.remove(&key, Some(&stale)), RemoveOutcome::Stale).await?;
		let txn = self
			.answers(
				"a swap at an absent key",
				txn.swap(&absent, &current, &lost),
				SwapOutcome::Stale,
			)
			.await?;
		let step = "a remove at an absent key";
		let txn = self
			.answers(step, txn.remove(&absent, Some(&current)), RemoveOutcome::Stale)
			.await?;
		let txn = self.reads(txn, &key, Some(b"v-1")).await?;
		let txn = self
			.takes(txn, &[Write::Swap(&key, &current, KvValue::new(b"v--2".as_slice()))])
			.await?;
		let (txn, own) = self.own_revision(txn, &key).await?;
		let step = "a remove of the replaced revision";
		let txn = self
			.answers(step, txn.remove(&key, Some(&current)), RemoveOutcome::Stale)
			.await?;
		let step = "a remove of the own revision";
		let txn = self.answers(step, txn.remove(&key, Some(&own)), RemoveOutcome::Removed).await?;

		self.commit("the commit of a remove", txn).await?;
		self.holds("a read after the remove", &[(&key, None)]).await
	}

	/// Guarded writes that race from one revision, swap against swap, remove
	/// against swap, and remove against remove, of which at most one
	/// commits.
	async fn races_swap(&self) -> Result<(), KvBreach> {
		let races: [GuardedRace<'_>; 3] = [
			(b"swap-swap", Some(b"first"), Some(b"second")),
			(b"remove-swap", None, Some(b"second")),
			(b"remove-remove", None, None),
		];
		for (sort, first_after, second_after) in races {
			let key = Key::from_static(NORTH, sort);
			self.seed(&[(&key, b"seeded")]).await?;
			let seeded = self.revision(&key).await?;
			let write = |after: Option<&[u8]>| match after {
				Some(bytes) => Write::Swap(&key, &seeded, KvValue::new(bytes)),
				None => Write::Remove(&key, Some(&seeded)),
			};

			let (first_wrote, second_wrote) = (Gate::new(), Gate::new());
			let (first_lane, second_lane) = (Lane::new(), Lane::new());
			let first = [
				Step::Write(write(first_after)),
				Step::Open(&first_wrote),
				Step::Wait(&second_wrote, &second_lane),
				Step::Commit,
			];
			let second = [
				Step::Write(write(second_after)),
				Step::Open(&second_wrote),
				Step::Wait(&first_wrote, &first_lane),
				Step::Commit,
			];
			let (first, second) = join!(self.race(&first, &first_lane), self.race(&second, &second_lane));
			let raced = [(first?, first_after), (second?, second_after)];
			let step = format!("two guarded writes from one revision at {key}");
			self.one_winner(&step, raced, &key, Some(b"seeded")).await?;
		}

		Ok(())
	}

	/// Checks that answer `Changed` for a key that moved before them, two
	/// checks of absence that cross, of which one fails, and checks whose
	/// commit fails once the key changes, vanishes, appears, or comes back.
	async fn checks_reads(&self) -> Result<(), KvBreach> {
		let moved = Key::from_static(NORTH, b"moved");
		let absent = Key::from_static(NORTH, b"never-written");

		self.seed(&[(&moved, b"c0")]).await?;

		let stale = self.revision(&moved).await?;
		let txn = self.begin().await?;
		let txn = self
			.takes(txn, &[Write::Swap(&moved, &stale, KvValue::new(b"c-1".as_slice()))])
			.await?;

		self.commit("the commit of a swap", txn).await?;

		let current = self.revision(&moved).await?;
		let checks = [
			("a check of a stale revision", &moved, Some(&stale), ConfirmOutcome::Changed),
			("a check of a present key as absent", &moved, None, ConfirmOutcome::Changed),
			(
				"a check of an absent key as present",
				&absent,
				Some(&current),
				ConfirmOutcome::Changed,
			),
			("a check of an absent key", &absent, None, ConfirmOutcome::Held),
			("a check of the current revision", &moved, Some(&current), ConfirmOutcome::Held),
		];
		let mut txn = self.begin().await?;
		for (step, key, expected, outcome) in checks {
			txn = self.answers(step, txn.check(key, expected), outcome).await?;
		}

		self.rollback(txn).await?;
		self.crossed_checks().await?;

		let changed = Key::from_static(NORTH, b"changed");
		let vanished = Key::from_static(NORTH, b"vanished");
		let appeared = Key::from_static(NORTH, b"appeared");
		let returned = Key::from_static(NORTH, b"returned");
		let rewritten = Key::from_static(NORTH, b"rewritten");
		let seeds: [(&Key, &[u8]); 4] =
			[(&changed, b"k0"), (&vanished, b"v0"), (&returned, b"r0"), (&rewritten, b"w0")];

		self.seed(&seeds).await?;

		let changed_at = self.revision(&changed).await?;
		let vanished_at = self.revision(&vanished).await?;
		let returned_at = self.revision(&returned).await?;
		let rewritten_at = self.revision(&rewritten).await?;

		let lanes = CheckLanes::new();
		let rival = [
			Step::Wait(&lanes.checked, &lanes.checker),
			Step::Write(Write::Swap(&changed, &changed_at, KvValue::new(b"k-1".as_slice()))),
			Step::Commit,
		];
		self.checked_against((&changed, Some(&changed_at)), &rival, &lanes, false)
			.await?;

		let lanes = CheckLanes::new();
		let rival = [
			Step::Wait(&lanes.checked, &lanes.checker),
			Step::Write(Write::Remove(&vanished, Some(&vanished_at))),
			Step::Commit,
		];
		self.checked_against((&vanished, Some(&vanished_at)), &rival, &lanes, false)
			.await?;

		let lanes = CheckLanes::new();
		let rival = [
			Step::Wait(&lanes.checked, &lanes.checker),
			Step::Write(Write::Insert(&appeared, KvValue::new(b"appeared".as_slice()))),
			Step::Commit,
		];
		self.checked_against((&appeared, None), &rival, &lanes, false).await?;

		let lanes = CheckLanes::new();
		let rival = [
			Step::Wait(&lanes.checked, &lanes.checker),
			Step::Write(Write::Remove(&returned, Some(&returned_at))),
			Step::Write(Write::Insert(&returned, KvValue::new(b"r-back".as_slice()))),
			Step::Commit,
		];
		self.checked_against((&returned, Some(&returned_at)), &rival, &lanes, false)
			.await?;

		let lanes = CheckLanes::new();
		let rival = [
			Step::Wait(&lanes.checked, &lanes.checker),
			Step::Write(Write::Swap(&rewritten, &rewritten_at, KvValue::new(b"w-1".as_slice()))),
			Step::Commit,
		];
		self.checked_against((&rewritten, Some(&rewritten_at)), &rival, &lanes, true)
			.await
	}

	/// Two transactions that each check one key absent and insert the other,
	/// the write skew that read confirmation refuses, of which at most one
	/// commits.
	async fn crossed_checks(&self) -> Result<(), KvBreach> {
		let left = Key::from_static(NORTH, b"skew-left");
		let right = Key::from_static(NORTH, b"skew-right");
		let (left_ready, right_ready) = (Gate::new(), Gate::new());
		let (left_lane, right_lane) = (Lane::new(), Lane::new());
		let lefty = [
			Step::Write(Write::Check(&right, None)),
			Step::Write(Write::Insert(&left, KvValue::new(b"left".as_slice()))),
			Step::Open(&left_ready),
			Step::Wait(&right_ready, &right_lane),
			Step::Commit,
		];
		let righty = [
			Step::Write(Write::Check(&left, None)),
			Step::Write(Write::Insert(&right, KvValue::new(b"right".as_slice()))),
			Step::Open(&right_ready),
			Step::Wait(&left_ready, &left_lane),
			Step::Commit,
		];

		let (lefty, righty) = join!(self.race(&lefty, &left_lane), self.race(&righty, &right_lane));
		let raced = [lefty?, righty?];
		if raced.iter().all(|raced| *raced == Raced::Committed) {
			return Err(self.refuse("two crossed checks of absence", &raced, &"at most one commit"));
		}

		Ok(())
	}

	/// An unguarded remove of a key no transaction wrote, which answers
	/// `Removed` and commits.
	async fn removes_absent(&self) -> Result<(), KvBreach> {
		let absent = Key::from_static(NORTH, b"never-written");
		let txn = self.begin().await?;
		let step = "an unguarded remove at an absent key";
		let txn = self.answers(step, txn.remove(&absent, None), RemoveOutcome::Removed).await?;
		self.commit("the commit of the remove", txn).await
	}

	/// Values of one key with other bytes of one length, committed, own, and
	/// after a remove and an insert, which carry other revisions.
	async fn revises(&self) -> Result<(), KvBreach> {
		let key = Key::from_static(NORTH, b"revised");
		let own_key = Key::from_static(NORTH, b"revised-own");
		let returned = Key::from_static(NORTH, b"returned");
		self.seed(&[(&key, b"left"), (&returned, b"left")]).await?;

		let before = self.revision(&key).await?;
		let txn = self.begin().await?;
		let txn = self
			.takes(txn, &[Write::Swap(&key, &before, KvValue::new(b"rite".as_slice()))])
			.await?;
		self.commit("the commit of a swap", txn).await?;
		let after = self.revision(&key).await?;
		if before == after {
			return Err(self.refuse("the revision of a committed swap", &after, &"another revision"));
		}

		let txn = self.begin().await?;
		let txn = self
			.takes(txn, &[Write::Insert(&own_key, KvValue::new(b"left".as_slice()))])
			.await?;
		let (txn, own_before) = self.own_revision(txn, &own_key).await?;
		let txn = self
			.takes(txn, &[Write::Swap(&own_key, &own_before, KvValue::new(b"rite".as_slice()))])
			.await?;
		let (txn, own_after) = self.own_revision(txn, &own_key).await?;
		if own_before == own_after {
			return Err(self.refuse("the revision of an own swap", &own_after, &"another revision"));
		}

		self.rollback(txn).await?;

		let gone = self.revision(&returned).await?;
		let txn = self.begin().await?;
		let txn = self.takes(txn, &[Write::Remove(&returned, Some(&gone))]).await?;
		self.commit("the commit of a remove", txn).await?;
		let txn = self.begin().await?;
		let txn = self
			.takes(txn, &[Write::Insert(&returned, KvValue::new(b"rite".as_slice()))])
			.await?;
		self.commit("the commit of a reinsert", txn).await?;
		let back = self.revision(&returned).await?;
		if back == gone {
			return Err(self.refuse("the revision of a key that came back", &back, &"another revision"));
		}

		let lost = KvValue::new(b"lost".as_slice());
		let txn = self.begin().await?;
		let step = "a swap from the revision before the remove";
		let txn = self
			.answers(step, txn.swap(&returned, &gone, &lost), SwapOutcome::Stale)
			.await?;
		self.rollback(txn).await
	}

	/// Values with NUL and 0xFF bytes, an empty one, and a large one, which
	/// a get and a scan return byte for byte.
	async fn preserves(&self) -> Result<(), KvBreach> {
		let every_byte: Vec<u8> = (0..=u8::MAX).collect();
		let large: Vec<u8> = (0..=u8::MAX).cycle().take(LARGE_VALUE).collect();
		let values: [&[u8]; 6] = [b"", &[0x00], &[0x00, 0x00], &[0xff, 0x00, 0xff, 0x00], &every_byte, &large];
		let sorts: [&'static [u8]; 6] = [b"p0", b"p1", b"p2", b"p3", b"p4", b"p5"];
		let keys = sorts.map(|sort| Key::from_static(NORTH, sort));
		let seeds: Vec<(&Key, &[u8])> = keys.iter().zip(values).collect();
		self.seed(&seeds).await?;

		let expected: Vec<(&Key, Option<&[u8]>)> = keys.iter().zip(values.map(Some)).collect();
		self.holds("a get of the values", &expected).await?;

		let entries: Vec<(&[u8], &[u8])> = sorts.into_iter().zip(values).collect();
		let txn = self.begin().await?;
		let txn = self
			.scans(txn, &KeyRange::whole(NORTH), (Direction::Ascending, ALL), &entries)
			.await?;
		self.rollback(txn).await
	}

	/// One sort key in two partitions, a partition whose name starts another,
	/// and two keys whose partition and sort key join to one text, each of
	/// which holds and scans as its own entry.
	async fn separates_partitions(&self) -> Result<(), KvBreach> {
		let in_north = Key::from_static(NORTH, b"shared");
		let in_south = Key::from_static(SOUTH, b"shared");
		let in_prefix = Key::from_static(PREFIX, b"short");
		let joined_after = Key::from_static(Partition::from_static("a"), b"bc");
		let joined_before = Key::from_static(Partition::from_static("ab"), b"c");
		let seeds: [(&Key, &[u8]); 5] = [
			(&in_north, b"north"),
			(&in_south, b"south"),
			(&in_prefix, b"prefix"),
			(&joined_after, b"a/bc"),
			(&joined_before, b"ab/c"),
		];
		self.seed(&seeds).await?;
		let held: Vec<(&Key, Option<&[u8]>)> = seeds.iter().map(|(key, bytes)| (*key, Some(*bytes))).collect();
		self.holds("a read of each partition", &held).await?;

		let mut txn = self.begin().await?;
		for (key, bytes) in seeds {
			let partition = KeyRange::whole(key.partition());
			txn = self
				.scans(txn, &partition, (Direction::Ascending, ALL), &[(key.sort(), bytes)])
				.await?;
		}

		self.rollback(txn).await
	}

	/// Scans over sort keys at the edges of unsigned byte order, each way,
	/// between bounds, under a limit, and both at once.
	async fn scans_ordered(&self) -> Result<(), KvBreach> {
		let sorts: [&'static [u8]; 7] = [&[0x00], &[0x00, 0x00], &[0x01], &[0x7f], &[0x80], &[0xff], &[0xff, 0x00]];
		let keys = sorts.map(|sort| Key::from_static(NORTH, sort));
		let beside = Key::from_static(SOUTH, &[0x50]);
		let mut seeds: Vec<(&Key, &[u8])> = keys.iter().zip(sorts).collect();
		seeds.push((&beside, b"beside"));
		self.seed(&seeds).await?;

		let one = NonZeroU32::MIN;
		let scans: [OrderedScan<'_>; 11] = [
			(
				Bound::Unbounded,
				Bound::Unbounded,
				Direction::Ascending,
				ALL,
				&[0, 1, 2, 3, 4, 5, 6],
			),
			(
				Bound::Unbounded,
				Bound::Unbounded,
				Direction::Descending,
				ALL,
				&[6, 5, 4, 3, 2, 1, 0],
			),
			(Bound::Unbounded, Bound::Unbounded, Direction::Ascending, TWO, &[0, 1]),
			(Bound::Unbounded, Bound::Unbounded, Direction::Descending, TWO, &[6, 5]),
			(
				Bound::Included(&[0x01]),
				Bound::Excluded(&[0xff]),
				Direction::Ascending,
				ALL,
				&[2, 3, 4],
			),
			(
				Bound::Excluded(&[0x00]),
				Bound::Included(&[0x80]),
				Direction::Descending,
				ALL,
				&[4, 3, 2, 1],
			),
			(
				Bound::Included(&[0x01]),
				Bound::Excluded(&[0xff]),
				Direction::Ascending,
				TWO,
				&[2, 3],
			),
			(
				Bound::Included(&[0x01]),
				Bound::Excluded(&[0xff]),
				Direction::Descending,
				TWO,
				&[4, 3],
			),
			(
				Bound::Included(&[0x80]),
				Bound::Included(&[0x80]),
				Direction::Ascending,
				ALL,
				&[4],
			),
			(Bound::Excluded(&[0x00]), Bound::Unbounded, Direction::Ascending, one, &[1]),
			(Bound::Unbounded, Bound::Excluded(&[0xff]), Direction::Descending, one, &[4]),
		];

		let mut txn = self.begin().await?;
		for (lower, upper, direction, limit, reads) in scans {
			let range = self.range(NORTH, lower, upper)?;
			let expected: Vec<(&[u8], &[u8])> = reads.iter().map(|index| (sorts[*index], sorts[*index])).collect();
			txn = self.scans(txn, &range, (direction, limit), &expected).await?;
		}

		self.rollback(txn).await
	}

	/// A batch get out of key order, with an absent key, which answers in
	/// the order of its keys.
	async fn gets_batch(&self) -> Result<(), KvBreach> {
		let first = Key::from_static(NORTH, b"a-first");
		let second = Key::from_static(NORTH, b"b-second");
		let absent = Key::from_static(NORTH, b"c-absent");
		self.seed(&[(&first, b"first"), (&second, b"second")]).await?;

		let txn = self.begin().await?;
		let keys = [second.clone(), absent.clone(), first.clone()];
		let step = "a batch get out of key order";
		let (txn, read) = self.call(step, txn.get(&keys)).await?;
		let answered: Vec<Option<Shown<'_>>> = read.iter().map(|stored| stored.as_ref().map(Shown::from)).collect();
		let expected = vec![Some(Shown(b"second")), None, Some(Shown(b"first"))];
		self.expect(step, answered, expected)?;
		self.rollback(txn).await
	}

	/// Keys at the bounds the core emits: partitions of 1 and 80 bytes, with
	/// a slash, and sort keys of 1 and 621 bytes.
	async fn accepts_keys(&self) -> Result<(), KvBreach> {
		let shortest = Key::from_static(SHORTEST, &[0x01]);
		let longest = Key::from_static(LONGEST, &LONGEST_SORT);
		self.seed(&[(&shortest, b"shortest"), (&longest, b"longest")]).await?;
		self.holds(
			"a get of the bounds",
			&[(&shortest, Some(b"shortest")), (&longest, Some(b"longest"))],
		)
		.await?;

		let shortest_entries: [(&[u8], &[u8]); 1] = [(&[0x01], b"shortest")];
		let longest_entries: [(&[u8], &[u8]); 1] = [(&LONGEST_SORT, b"longest")];
		let txn = self.begin().await?;
		let txn = self
			.scans(txn, &KeyRange::whole(SHORTEST), (Direction::Ascending, ALL), &shortest_entries)
			.await?;
		let txn = self
			.scans(txn, &KeyRange::whole(LONGEST), (Direction::Ascending, ALL), &longest_entries)
			.await?;
		self.rollback(txn).await
	}

	/// A swap, an insert, and a check beside an open write that rolls back,
	/// which take and commit as if the open write never ran.
	async fn conflicts_early(&self) -> Result<(), KvBreach> {
		let swapped = Key::from_static(NORTH, b"swapped");
		let inserted = Key::from_static(NORTH, b"inserted");
		let checked = Key::from_static(NORTH, b"checked");
		self.seed(&[(&swapped, b"seeded"), (&checked, b"seeded")]).await?;
		let swapped_at = self.revision(&swapped).await?;
		let checked_at = self.revision(&checked).await?;

		let open = || KvValue::new(b"open".as_slice());
		let beside = || KvValue::new(b"beside".as_slice());
		let competitions = [
			(
				Write::Swap(&swapped, &swapped_at, open()),
				Write::Swap(&swapped, &swapped_at, beside()),
			),
			(Write::Insert(&inserted, open()), Write::Insert(&inserted, beside())),
			(
				Write::Swap(&checked, &checked_at, open()),
				Write::Check(&checked, Some(&checked_at)),
			),
		];
		for (opening, besides) in competitions {
			let open_wrote = Gate::new();
			let (open_lane, beside_lane) = (Lane::new(), Lane::new());
			let step = format!("{besides} beside {opening} that rolls back");
			let opening = [
				Step::Write(opening),
				Step::Open(&open_wrote),
				Step::Rival(&beside_lane),
				Step::Rollback,
			];
			let besides = [Step::Wait(&open_wrote, &open_lane), Step::Write(besides), Step::Commit];
			let (open_raced, beside_raced) = join!(self.race(&opening, &open_lane), self.race(&besides, &beside_lane));
			self.expect("an open write that rolls back", open_raced?, Raced::RolledBack)?;
			let beside_raced = beside_raced?;
			if !matches!(beside_raced, Raced::Committed | Raced::Aborted) {
				return Err(self.refuse(&step, &beside_raced, &"Committed, or an abort"));
			}
		}

		Ok(())
	}

	/// Two transactions that swap two keys in crossed order, as a deadlock
	/// does, whose every failure is an abort and of which at most one
	/// commits.
	async fn aborts_typed(&self) -> Result<(), KvBreach> {
		let left = Key::from_static(NORTH, b"left");
		let right = Key::from_static(NORTH, b"right");
		self.seed(&[(&left, b"seeded"), (&right, b"seeded")]).await?;
		let left_at = self.revision(&left).await?;
		let right_at = self.revision(&right).await?;

		let (forward_first, backward_first) = (Gate::new(), Gate::new());
		let (forward_both, backward_both) = (Gate::new(), Gate::new());
		let (forward_lane, backward_lane) = (Lane::new(), Lane::new());
		let forward = [
			Step::Write(Write::Swap(&left, &left_at, KvValue::new(b"forward".as_slice()))),
			Step::Open(&forward_first),
			Step::Wait(&backward_first, &backward_lane),
			Step::Write(Write::Swap(&right, &right_at, KvValue::new(b"forward".as_slice()))),
			Step::Open(&forward_both),
			Step::Wait(&backward_both, &backward_lane),
			Step::Commit,
		];
		let backward = [
			Step::Write(Write::Swap(&right, &right_at, KvValue::new(b"backward".as_slice()))),
			Step::Open(&backward_first),
			Step::Wait(&forward_first, &forward_lane),
			Step::Write(Write::Swap(&left, &left_at, KvValue::new(b"backward".as_slice()))),
			Step::Open(&backward_both),
			Step::Wait(&forward_both, &forward_lane),
			Step::Commit,
		];

		let (forward, backward) = join!(self.race(&forward, &forward_lane), self.race(&backward, &backward_lane));
		let raced = [forward?, backward?];
		let left_read = self.read(&left).await?;
		let right_read = self.read(&right).await?;
		let committed = raced.iter().filter(|raced| **raced == Raced::Committed).count();
		let together = left_read.as_ref().map(Stored::bytes) == right_read.as_ref().map(Stored::bytes);
		if committed > 1 || !together {
			let answered = (raced, left_read.as_ref().map(Shown::from), right_read.as_ref().map(Shown::from));
			return Err(self.refuse("a read after crossed swaps", &answered, &"both swaps of at most one racer"));
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use core::future::pending;
	use std::collections::BTreeMap;
	use std::io;
	use std::sync::atomic::{AtomicU64, Ordering};
	use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};

	use tightbeam::testing::SetupEnv;
	use tightbeam::urn::Urn;
	use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn};
	use tokio::task::yield_now;
	use tokio::time::{pause, sleep};

	use super::*;
	use crate::driver::DriverFuture;
	use crate::memory::MemoryKv;
	use crate::scope::Scope;

	/// The longest sort key that a [`Fault::ShortKeys`] driver takes.
	const SHORT_SORT: usize = 512;

	/// No wait before a call.
	const NONE: Lag = Lag::Yields(0);

	/// The yields before each call of a driver with latency.
	const YIELDS: Lag = Lag::Yields(3);

	/// The wait before each call of a slow driver: three quarters of the rival
	/// wait of [`SLOW_PATIENCE`], so a rival of two calls outlasts that wait.
	const SLOW_CALL: Lag = Lag::Sleeps(Duration::from_millis(150));

	/// The patience of the scenarios of slow drivers, whose rival wait is
	/// 200 ms.
	const SLOW_PATIENCE: Duration = Duration::from_secs(2);

	/// How a faulty driver waits before each call, as a backend over a
	/// network does.
	#[derive(Clone, Copy, Debug)]
	enum Lag {
		/// Yield to the runtime this many times, which takes no time.
		Yields(usize),
		/// Sleep this long on the clock of the runtime.
		Sleeps(Duration),
	}

	impl Lag {
		/// Wait as this lag says.
		async fn wait(self) {
			match self {
				Self::Yields(count) => {
					for _ in 0..count {
						yield_now().await;
					}
				}
				Self::Sleeps(span) => sleep(span).await,
			}
		}
	}

	/// The one partition of a [`Fault::FlatKeys`] driver.
	const FLAT: Partition = Partition::from_static("flat");

	/// The one clause of the KV contract that each fault breaks.
	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
	enum Fault {
		/// A get and a scan show the open writes of other transactions.
		DirtyReads,
		/// A remove answers `Removed` and removes nothing.
		IgnoresRemoves,
		/// A get and a scan read the committed state alone.
		HidesOwn,
		/// A commit that conflicts keeps the writes before the conflict.
		PartialCommit,
		/// A rollback commits.
		KeepsRolledBack,
		/// An insert of a present key replaces its value.
		Overwrites,
		/// An insert relies on no absence, so racing inserts both commit.
		BlindInserts,
		/// A swap ignores the revision.
		IgnoresRevision,
		/// A swap relies on no revision, so racing swaps both commit.
		BlindSwaps,
		/// A check compares at the call and relies on nothing at the commit.
		ForgetsChecks,
		/// A check of a revision compares at the call and relies on nothing
		/// at the commit. A check of absence holds as it should.
		ForgetsRevisionChecks,
		/// A write of a key that another open transaction checked answers as
		/// refused.
		StaleBesideCheck,
		/// An unguarded remove of an absent key answers `Stale`.
		StaleOnAbsent,
		/// A revision is the length of the bytes.
		RevisesByLength,
		/// A write drops the trailing NUL bytes of its value.
		TrimsNul,
		/// Every key joins its partition and sort key in one partition, and a
		/// scan reads the partition name as a prefix.
		FlatKeys,
		/// A scan orders sort keys as signed bytes.
		SignedOrder,
		/// A batch get answers the present keys in key order, then the absent.
		SortsBatch,
		/// A sort key past 512 bytes fails.
		ShortKeys,
		/// A write beside the open write of another transaction answers as
		/// refused.
		EarlyStale,
		/// A commit that conflicts answers `DriverError::Failed`.
		ConflictAsFailed,
	}

	/// What the open transactions of one faulty backend hold, by the id of
	/// each transaction.
	#[derive(Default)]
	struct Open {
		/// Each key an open transaction wrote, with its open value, or `None`
		/// for a removal.
		writes: BTreeMap<Key, (u64, Option<KvValue>)>,
		/// Each key an open transaction checked.
		checks: BTreeMap<Key, u64>,
		/// The transaction that each waiting transaction waits on.
		waiting: BTreeMap<u64, u64>,
	}

	/// A [`MemoryKv`] whose transactions answer under one fault, or none,
	/// after a lag per call.
	struct Faulty {
		kv: Arc<MemoryKv>,
		fault: Option<Fault>,
		lag: Lag,
		/// Whether calls wait on the locks of other open transactions, as a
		/// backend of two-phase locking does: a read or a check waits on an
		/// open write, and a write waits on an open write or check.
		locks: bool,
		open: Arc<Mutex<Open>>,
		next: AtomicU64,
	}

	impl Faulty {
		/// An empty backend under `fault`, after `lag` per call.
		fn new(fault: Option<Fault>, lag: Lag) -> Self {
			let open = Arc::new(Mutex::new(Open::default()));
			Self {
				kv: Arc::new(MemoryKv::default()),
				fault,
				lag,
				locks: false,
				open,
				next: AtomicU64::new(0),
			}
		}

		/// This backend, whose calls wait on the locks of others and abort a
		/// transaction that would wait in a cycle.
		fn with_locks(self) -> Self {
			Self { locks: true, ..self }
		}
	}

	impl OrderedKv for Faulty {
		fn begin(&self) -> DriverFuture<'_, Box<dyn OrderedKvTxn>> {
			Box::pin(async move {
				let inner = self.kv.begin().await?;
				let id = self.next.fetch_add(1, Ordering::Relaxed);
				let ctx = Ctx {
					kv: Arc::clone(&self.kv),
					fault: self.fault,
					lag: self.lag,
					locks: self.locks,
					open: Arc::clone(&self.open),
					id,
					writes: Vec::new(),
				};
				Ok(Box::new(FaultyTxn { inner: Some(inner), ctx }) as Box<dyn OrderedKvTxn>)
			})
		}

		fn scope(&self) -> Scope {
			Scope::Process
		}
	}

	/// What a faulty transaction holds beside its inner transaction.
	struct Ctx {
		kv: Arc<MemoryKv>,
		fault: Option<Fault>,
		lag: Lag,
		locks: bool,
		open: Arc<Mutex<Open>>,
		id: u64,
		/// The writes of this transaction, in order: a value, or a removal.
		writes: Vec<(Key, Option<KvValue>)>,
	}

	impl Ctx {
		/// Whether this transaction runs under `fault`.
		fn is(&self, fault: Fault) -> bool {
			self.fault == Some(fault)
		}

		/// Wait out the lag of one call.
		async fn lag(&self) {
			self.lag.wait().await;
		}

		/// What the open transactions hold.
		fn open(&self) -> MutexGuard<'_, Open> {
			self.open.lock().unwrap_or_else(PoisonError::into_inner)
		}

		/// Record the open write of `key` by this transaction.
		fn hold(&mut self, key: &Key, value: Option<&KvValue>) {
			let id = self.id;
			let mut open = self.open();
			let held = open.writes.entry(key.clone()).or_insert((id, None));
			if held.0 == id {
				held.1 = value.cloned();
			}

			drop(open);
			self.writes.push((key.clone(), value.cloned()));
		}

		/// Record the held check of `key` by this transaction.
		fn hold_check(&self, key: &Key) {
			self.open().checks.entry(key.clone()).or_insert(self.id);
		}

		/// The open write of `key` by another transaction: `Some(None)` for a
		/// removal, and `None` when no other transaction wrote it.
		fn written_by_other(&self, key: &Key) -> Option<Option<KvValue>> {
			let open = self.open();
			let (holder, value) = open.writes.get(key)?;
			(*holder != self.id).then(|| value.clone())
		}

		/// Whether the fault refuses a write of `key` beside another open
		/// transaction.
		fn refuses_beside(&self, key: &Key) -> bool {
			let written = self.is(Fault::EarlyStale) && self.written_by_other(key).is_some();
			let checked = self.open().checks.get(key).is_some_and(|holder| *holder != self.id);
			written || (self.is(Fault::StaleBesideCheck) && checked)
		}

		/// The other open transaction whose write of one of `keys` a read
		/// waits on.
		fn read_blocker(&self, keys: &[Key]) -> Option<u64> {
			let open = self.open();
			let mut holders = keys.iter().filter_map(|key| open.writes.get(key).map(|(holder, _)| *holder));
			holders.find(|holder| *holder != self.id)
		}

		/// The other open transaction whose write or check of `key` a write
		/// waits on.
		fn write_blocker(&self, key: &Key) -> Option<u64> {
			let open = self.open();
			let written = open
				.writes
				.get(key)
				.map(|(holder, _)| *holder)
				.filter(|holder| *holder != self.id);
			let checked = open.checks.get(key).copied().filter(|holder| *holder != self.id);
			written.or(checked)
		}

		/// Whether `holder` waits, through the transactions it waits on, on
		/// this transaction.
		fn waits_on_me(&self, holder: u64) -> bool {
			let open = self.open();
			let mut current = holder;
			for _ in 0..=open.waiting.len() {
				match open.waiting.get(&current) {
					Some(next) if *next == self.id => return true,
					Some(next) => current = *next,
					None => return false,
				}
			}

			false
		}

		/// Wait, under locks, until `blocker` names no other transaction.
		///
		/// # Errors
		///
		/// - [`DriverError::Aborted`] -- the wait closes a cycle, a deadlock.
		async fn wait_on(&self, blocker: impl Fn(&Self) -> Option<u64>) -> Result<(), DriverError> {
			if !self.locks {
				return Ok(());
			}

			while let Some(holder) = blocker(self) {
				if self.waits_on_me(holder) {
					self.open().waiting.remove(&self.id);
					return Err(DriverError::aborted("the wait closes a cycle of locks"));
				}

				self.open().waiting.insert(self.id, holder);
				sleep(Duration::from_millis(1)).await;
			}

			self.open().waiting.remove(&self.id);
			Ok(())
		}

		/// The keys of `range` that other open transactions wrote.
		fn written_in(&self, range: &KeyRange) -> Vec<(Key, Option<KvValue>)> {
			let open = self.open();
			let others = open
				.writes
				.iter()
				.filter(|(key, (holder, _))| *holder != self.id && range.contains(key));
			others.map(|(key, (_, value))| (key.clone(), value.clone())).collect()
		}

		/// The revision an open value shows under [`Fault::DirtyReads`].
		fn dirty(value: &KvValue) -> Stored {
			Stored::new(value.as_bytes(), Revision::new(*b"open"))
		}

		/// Refuse a key past [`SHORT_SORT`] under [`Fault::ShortKeys`].
		fn admit(&self, key: &Key) -> Result<(), DriverError> {
			if self.is(Fault::ShortKeys) && key.sort().len() > SHORT_SORT {
				return Err(DriverError::failed("the sort key is past 512 bytes"));
			}

			Ok(())
		}

		/// The key that the fault writes for `key`.
		fn key(&self, key: &Key) -> Result<Key, DriverError> {
			if !self.is(Fault::FlatKeys) {
				return Ok(key.clone());
			}

			let joined = [key.partition().as_bytes(), key.sort()].concat();
			Key::new(FLAT, joined).map_err(DriverError::failed)
		}

		/// The range that the fault scans for `range`, or `None` for one that
		/// admits no key.
		fn range(&self, range: &KeyRange) -> Option<KeyRange> {
			if !self.is(Fault::FlatKeys) {
				return Some(range.clone());
			}

			let partition = range.partition();
			let prefix = partition.as_bytes();
			let joined = |bound: Bound<&[u8]>| bound.map(|bytes| [prefix, bytes].concat());
			let lower = match range.lower() {
				Bound::Unbounded => Bound::Included(prefix.to_vec()),
				bound => joined(bound),
			};
			let upper = match range.upper() {
				Bound::Unbounded => {
					let mut after = prefix.to_vec();
					if let Some(last) = after.last_mut() {
						*last += 1;
					}

					Bound::Excluded(after)
				}
				bound => joined(bound),
			};

			KeyRange::new(FLAT, lower, upper)
		}

		/// The value that the fault writes for `value`.
		fn value(&self, value: &KvValue) -> KvValue {
			let bytes = value.as_bytes();
			if !self.is(Fault::TrimsNul) {
				return value.clone();
			}

			let trailing = bytes.iter().rev().take_while(|byte| **byte == 0).count();
			KvValue::new(&bytes[..bytes.len() - trailing])
		}

		/// The value as the fault shows it.
		fn shown(&self, stored: Stored) -> Stored {
			if !self.is(Fault::RevisesByLength) {
				return stored;
			}

			let length = u64::try_from(stored.bytes().len()).unwrap_or(u64::MAX);
			Stored::new(stored.bytes(), Revision::new(length.to_be_bytes()))
		}
	}

	impl Drop for Ctx {
		fn drop(&mut self) {
			let id = self.id;
			let mut open = self.open();
			open.writes.retain(|_, (holder, _)| *holder != id);
			open.checks.retain(|_, holder| *holder != id);
			open.waiting.remove(&id);
		}
	}

	/// One transaction of a [`Faulty`] backend over one of its [`MemoryKv`].
	struct FaultyTxn {
		inner: Option<Box<dyn OrderedKvTxn>>,
		ctx: Ctx,
	}

	impl FaultyTxn {
		/// The inner transaction, taken for one call.
		fn take(&mut self) -> Result<Box<dyn OrderedKvTxn>, DriverError> {
			self.inner
				.take()
				.ok_or_else(|| DriverError::failed("the inner transaction ended"))
		}

		/// The answer of `call` on the inner transaction, which it hands back.
		async fn inner<T>(
			&mut self,
			call: impl FnOnce(Box<dyn OrderedKvTxn>) -> TxnFuture<'static, T>,
		) -> Result<T, DriverError> {
			self.ctx.lag().await;
			let (inner, answered) = call(self.take()?).await?;
			self.inner = Some(inner);
			Ok(answered)
		}

		/// The current value of `key` in the inner transaction.
		async fn current(&mut self, key: &Key) -> Result<Option<Stored>, DriverError> {
			let keys = vec![key.clone()];
			let read = self.inner(move |inner| Box::pin(async move { inner.get(&keys).await })).await?;
			Ok(read.into_iter().next().flatten())
		}

		/// The inner revision behind the shown revision `expected` of `key`,
		/// or `None` when `key` shows another.
		async fn actual(&mut self, key: &Key, expected: &Revision) -> Result<Option<Revision>, DriverError> {
			let current = self.current(key).await?;
			let shown = current.clone().map(|stored| self.ctx.shown(stored).revision().clone());
			if shown.as_ref() != Some(expected) {
				return Ok(None);
			}

			Ok(current.map(|stored| stored.revision().clone()))
		}

		/// An insert of `value` at `key` in the inner transaction.
		async fn insert_inner(&mut self, key: &Key, value: &KvValue) -> Result<InsertOutcome, DriverError> {
			let (key, value) = (key.clone(), value.clone());
			self.inner(move |inner| Box::pin(async move { inner.insert(&key, &value).await }))
				.await
		}

		/// A swap of `key` from `expected` to `value` in the inner transaction.
		async fn swap_inner(
			&mut self,
			key: &Key,
			expected: &Revision,
			value: &KvValue,
		) -> Result<SwapOutcome, DriverError> {
			let (key, expected, value) = (key.clone(), expected.clone(), value.clone());
			self.inner(move |inner| Box::pin(async move { inner.swap(&key, &expected, &value).await }))
				.await
		}

		/// A remove of `key` in the inner transaction.
		async fn remove_inner(&mut self, key: &Key, expected: Option<&Revision>) -> Result<RemoveOutcome, DriverError> {
			let (key, expected) = (key.clone(), expected.cloned());
			self.inner(move |inner| Box::pin(async move { inner.remove(&key, expected.as_ref()).await }))
				.await
		}

		/// A check of `key` in the inner transaction.
		async fn check_inner(&mut self, key: &Key, expected: Option<&Revision>) -> Result<ConfirmOutcome, DriverError> {
			let (key, expected) = (key.clone(), expected.cloned());
			self.inner(move |inner| Box::pin(async move { inner.check(&key, expected.as_ref()).await }))
				.await
		}

		/// A scan of `range` in the inner transaction.
		async fn scan_inner(
			&mut self,
			range: &KeyRange,
			direction: Direction,
			limit: NonZeroU32,
		) -> Result<Vec<Entry>, DriverError> {
			let range = range.clone();
			self.inner(move |inner| Box::pin(async move { inner.scan(&range, direction, limit).await }))
				.await
		}

		/// Write `value` at `key` relying on no revision: an unguarded remove,
		/// then an insert.
		async fn blind(&mut self, key: &Key, value: &KvValue) -> Result<(), DriverError> {
			let _removed = self.remove_inner(key, None).await?;
			let _inserted = self.insert_inner(key, value).await?;
			Ok(())
		}

		async fn insert_now(&mut self, key: &Key, value: &KvValue) -> Result<InsertOutcome, DriverError> {
			let key = self.ctx.key(key)?;
			let value = self.ctx.value(value);
			self.ctx.admit(&key)?;
			self.ctx.wait_on(|ctx| ctx.write_blocker(&key)).await?;
			if self.ctx.refuses_beside(&key) {
				return Ok(InsertOutcome::Occupied);
			}

			let inserted = match self.ctx.fault {
				Some(Fault::Overwrites) => {
					self.blind(&key, &value).await?;
					InsertOutcome::Inserted
				}
				Some(Fault::BlindInserts) => {
					if self.current(&key).await?.is_some() {
						return Ok(InsertOutcome::Occupied);
					}

					self.blind(&key, &value).await?;
					InsertOutcome::Inserted
				}
				_ => self.insert_inner(&key, &value).await?,
			};

			if inserted == InsertOutcome::Inserted {
				self.ctx.hold(&key, Some(&value));
			}

			Ok(inserted)
		}

		async fn swap_now(
			&mut self,
			key: &Key,
			expected: &Revision,
			value: &KvValue,
		) -> Result<SwapOutcome, DriverError> {
			let key = self.ctx.key(key)?;
			let value = self.ctx.value(value);
			self.ctx.admit(&key)?;
			self.ctx.wait_on(|ctx| ctx.write_blocker(&key)).await?;
			if self.ctx.refuses_beside(&key) {
				return Ok(SwapOutcome::Stale);
			}

			let swapped = match self.ctx.fault {
				Some(Fault::IgnoresRevision) => match self.current(&key).await? {
					Some(current) => self.swap_inner(&key, current.revision(), &value).await?,
					None => SwapOutcome::Stale,
				},
				Some(Fault::BlindSwaps) => {
					let current = self.current(&key).await?;
					if current.as_ref().map(Stored::revision) != Some(expected) {
						return Ok(SwapOutcome::Stale);
					}

					self.blind(&key, &value).await?;
					SwapOutcome::Swapped
				}
				Some(Fault::RevisesByLength) => match self.actual(&key, expected).await? {
					Some(actual) => self.swap_inner(&key, &actual, &value).await?,
					None => SwapOutcome::Stale,
				},
				_ => self.swap_inner(&key, expected, &value).await?,
			};

			if swapped == SwapOutcome::Swapped {
				self.ctx.hold(&key, Some(&value));
			}

			Ok(swapped)
		}

		async fn remove_now(&mut self, key: &Key, expected: Option<&Revision>) -> Result<RemoveOutcome, DriverError> {
			let key = self.ctx.key(key)?;
			self.ctx.admit(&key)?;
			self.ctx.wait_on(|ctx| ctx.write_blocker(&key)).await?;
			if self.ctx.refuses_beside(&key) {
				return Ok(RemoveOutcome::Stale);
			}

			let absent_refused = self.ctx.is(Fault::StaleOnAbsent) && expected.is_none();
			if absent_refused && self.current(&key).await?.is_none() {
				return Ok(RemoveOutcome::Stale);
			}

			let removed = match (self.ctx.fault, expected) {
				(Some(Fault::IgnoresRemoves), _) => return Ok(RemoveOutcome::Removed),
				(Some(Fault::RevisesByLength), Some(expected)) => match self.actual(&key, expected).await? {
					Some(actual) => self.remove_inner(&key, Some(&actual)).await?,
					None => RemoveOutcome::Stale,
				},
				_ => self.remove_inner(&key, expected).await?,
			};

			if removed == RemoveOutcome::Removed {
				self.ctx.hold(&key, None);
			}

			Ok(removed)
		}

		async fn get_now(&mut self, keys: &[Key]) -> Result<Vec<Option<Stored>>, DriverError> {
			let keys: Vec<Key> = keys.iter().map(|key| self.ctx.key(key)).collect::<Result<_, _>>()?;
			self.ctx.wait_on(|ctx| ctx.read_blocker(&keys)).await?;
			let read = if self.ctx.is(Fault::HidesOwn) {
				let side = self.ctx.kv.begin().await?;
				let (side, read) = side.get(&keys).await?;
				side.rollback().await?;
				read
			} else {
				let keys = keys.clone();
				self.inner(move |inner| Box::pin(async move { inner.get(&keys).await })).await?
			};

			let shown: Vec<Option<Stored>> = read
				.into_iter()
				.map(|stored| stored.map(|stored| self.ctx.shown(stored)))
				.collect();
			if self.ctx.is(Fault::DirtyReads) {
				let dirty = |(key, stored): (&Key, Option<Stored>)| match self.ctx.written_by_other(key) {
					Some(open) => open.as_ref().map(Ctx::dirty),
					None => stored,
				};

				return Ok(keys.iter().zip(shown).map(dirty).collect());
			}
			if !self.ctx.is(Fault::SortsBatch) {
				return Ok(shown);
			}

			let mut present: Vec<(Key, Stored)> = keys
				.into_iter()
				.zip(shown.iter().cloned())
				.filter_map(|(key, stored)| Some((key, stored?)))
				.collect();
			present.sort_by(|left, right| left.0.cmp(&right.0));
			let absent = shown.iter().filter(|stored| stored.is_none()).count();
			let sorted = present.into_iter().map(|(_, stored)| Some(stored));
			Ok(sorted.chain(core::iter::repeat_n(None, absent)).collect())
		}

		async fn scan_now(
			&mut self,
			range: &KeyRange,
			direction: Direction,
			limit: NonZeroU32,
		) -> Result<Vec<Entry>, DriverError> {
			let Some(scanned) = self.ctx.range(range) else {
				return Ok(Vec::new());
			};

			let written: Vec<Key> = self.ctx.written_in(range).into_iter().map(|(key, _)| key).collect();
			self.ctx.wait_on(|ctx| ctx.read_blocker(&written)).await?;
			let entries = match self.ctx.fault {
				Some(Fault::HidesOwn) => {
					let side = self.ctx.kv.begin().await?;
					let (side, entries) = side.scan(&scanned, direction, limit).await?;
					side.rollback().await?;
					entries
				}
				Some(Fault::SignedOrder) => {
					let mut entries = self.scan_inner(&scanned, Direction::Ascending, NonZeroU32::MAX).await?;
					let signed =
						|entry: &Entry| entry.sort().iter().map(|byte| byte.cast_signed()).collect::<Vec<i8>>();
					entries.sort_by_key(signed);
					if direction == Direction::Descending {
						entries.reverse();
					}

					entries.truncate(usize::try_from(limit.get()).unwrap_or(usize::MAX));
					entries
				}
				Some(Fault::DirtyReads) => {
					let entries = self.scan_inner(&scanned, Direction::Ascending, NonZeroU32::MAX).await?;
					let mut merged: BTreeMap<Vec<u8>, Stored> = entries
						.into_iter()
						.map(|entry| (entry.sort().to_vec(), entry.stored().clone()))
						.collect();
					for (key, open) in self.ctx.written_in(range) {
						match open {
							Some(value) => merged.insert(key.sort().to_vec(), Ctx::dirty(&value)),
							None => merged.remove(key.sort()),
						};
					}

					let limit = usize::try_from(limit.get()).unwrap_or(usize::MAX);
					let entry = |(sort, stored): (Vec<u8>, Stored)| Entry::new(sort, stored);
					match direction {
						Direction::Ascending => merged.into_iter().take(limit).map(entry).collect(),
						Direction::Descending => merged.into_iter().rev().take(limit).map(entry).collect(),
					}
				}
				_ => self.scan_inner(&scanned, direction, limit).await?,
			};

			let prefix = if self.ctx.is(Fault::FlatKeys) {
				range.partition().as_bytes().len()
			} else {
				0
			};
			let shown = |entry: Entry| {
				let sort = entry.sort().get(prefix..).unwrap_or_default();
				Entry::new(sort, self.ctx.shown(entry.stored().clone()))
			};

			Ok(entries.into_iter().map(shown).collect())
		}

		async fn check_now(&mut self, key: &Key, expected: Option<&Revision>) -> Result<ConfirmOutcome, DriverError> {
			let key = self.ctx.key(key)?;
			self.ctx.wait_on(|ctx| ctx.read_blocker(slice::from_ref(&key))).await?;
			let early = self.ctx.is(Fault::EarlyStale) && self.ctx.written_by_other(&key).is_some();
			if early {
				return Ok(ConfirmOutcome::Changed);
			}

			let checked = self.check_by_fault(&key, expected).await?;
			if checked == ConfirmOutcome::Held {
				self.ctx.hold_check(&key);
			}

			Ok(checked)
		}

		/// The answer of a check of `key` under the fault.
		async fn check_by_fault(
			&mut self,
			key: &Key,
			expected: Option<&Revision>,
		) -> Result<ConfirmOutcome, DriverError> {
			let key = key.clone();
			match (self.ctx.fault, expected) {
				(Some(Fault::ForgetsChecks), _) | (Some(Fault::ForgetsRevisionChecks), Some(_)) => {
					let current = self.current(&key).await?;
					let held = current.as_ref().map(Stored::revision) == expected;
					Ok(if held {
						ConfirmOutcome::Held
					} else {
						ConfirmOutcome::Changed
					})
				}
				(Some(Fault::RevisesByLength), Some(expected)) => match self.actual(&key, expected).await? {
					Some(actual) => self.check_inner(&key, Some(&actual)).await,
					None => Ok(ConfirmOutcome::Changed),
				},
				_ => self.check_inner(&key, expected).await,
			}
		}

		async fn commit_now(mut self) -> Result<CommitOutcome<Key>, DriverError> {
			self.ctx.lag().await;
			let inner = self.take()?;
			let committed = inner.commit().await?;
			match (&committed, self.ctx.fault) {
				(CommitOutcome::Conflicted(_), Some(Fault::ConflictAsFailed)) => {
					Err(DriverError::failed("the commit conflicts with another"))
				}
				(CommitOutcome::Conflicted(Some(conflict)), Some(Fault::PartialCommit)) => {
					let mut side = self.ctx.kv.begin().await?;
					for (key, value) in self.ctx.writes.iter().filter(|(key, _)| key < conflict) {
						side = side.remove(key, None).await?.0;
						if let Some(value) = value {
							side = side.insert(key, value).await?.0;
						}
					}

					let _kept = side.commit().await?;
					Ok(committed)
				}
				_ => Ok(committed),
			}
		}

		async fn rollback_now(mut self) -> Result<(), DriverError> {
			self.ctx.lag().await;
			let inner = self.take()?;
			if self.ctx.is(Fault::KeepsRolledBack) {
				return inner.commit().await.map(|_| ());
			}

			inner.rollback().await
		}
	}

	impl OrderedKvTxn for FaultyTxn {
		fn get<'a>(mut self: Box<Self>, keys: &'a [Key]) -> TxnFuture<'a, Vec<Option<Stored>>> {
			Box::pin(async move {
				let read = self.get_now(keys).await?;
				Ok((self as Box<dyn OrderedKvTxn>, read))
			})
		}

		fn insert<'a>(mut self: Box<Self>, key: &'a Key, value: &'a KvValue) -> TxnFuture<'a, InsertOutcome> {
			Box::pin(async move {
				let inserted = self.insert_now(key, value).await?;
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
				let swapped = self.swap_now(key, expected, value).await?;
				Ok((self as Box<dyn OrderedKvTxn>, swapped))
			})
		}

		fn remove<'a>(
			mut self: Box<Self>,
			key: &'a Key,
			expected: Option<&'a Revision>,
		) -> TxnFuture<'a, RemoveOutcome> {
			Box::pin(async move {
				let removed = self.remove_now(key, expected).await?;
				Ok((self as Box<dyn OrderedKvTxn>, removed))
			})
		}

		fn scan<'a>(
			mut self: Box<Self>,
			range: &'a KeyRange,
			direction: Direction,
			limit: NonZeroU32,
		) -> TxnFuture<'a, Vec<Entry>> {
			Box::pin(async move {
				let entries = self.scan_now(range, direction, limit).await?;
				Ok((self as Box<dyn OrderedKvTxn>, entries))
			})
		}

		fn check<'a>(
			mut self: Box<Self>,
			key: &'a Key,
			expected: Option<&'a Revision>,
		) -> TxnFuture<'a, ConfirmOutcome> {
			Box::pin(async move {
				let checked = self.check_now(key, expected).await?;
				Ok((self as Box<dyn OrderedKvTxn>, checked))
			})
		}

		fn commit(self: Box<Self>) -> DriverFuture<'static, CommitOutcome<Key>> {
			Box::pin((*self).commit_now())
		}

		fn rollback(self: Box<Self>) -> DriverFuture<'static, ()> {
			Box::pin((*self).rollback_now())
		}
	}

	/// Whether the check of a faulty driver answered the breach of the
	/// clause that its fault breaks.
	const REFUSED: Urn<'static> = urn!("test", "event:store-conformance/refused");

	tb_assert_spec! {
		pub FaultyDriverSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(REFUSED, exactly!(1), equals!(true))
			]
		}
	}

	/// Two scenarios per fault: the check of a driver under the fault breaks
	/// at the clause that the fault breaks, with no latency and with
	/// [`YIELDS`] per call.
	macro_rules! refused_by_its_clause {
		($($name:ident, $lagged:ident => ($fault:ident, $clause:ident)),+ $(,)?) => {
			$(
				refused_by_its_clause!(@one $name, NONE, $fault, $clause);
				refused_by_its_clause!(@one $lagged, YIELDS, $fault, $clause);
			)+
		};
		(@one $name:ident, $lag:expr, $fault:ident, $clause:ident) => {
			tb_scenario! {
				name: $name,
				spec: FaultyDriverSpec,
				environment Bare {
					exec: |SetupEnv { trace, .. }| async move {
						let fresh = || async { Ok(Faulty::new(Some(Fault::$fault), $lag)) };
						let checked = KvConformance::new(fresh).check().await;
						let breached = checked.as_ref().err().map(KvBreach::clause);
						trace.event_with(REFUSED, &[], breached == Some(KvClause::$clause))?;
						Ok(())
					}
				}
			}
		};
	}

	refused_by_its_clause! {
		dirty_reads_break_isolates, dirty_reads_with_latency_break_isolates => (DirtyReads, Isolates),
		ignored_removes_break_isolates, ignored_removes_with_latency_break_isolates => (IgnoresRemoves, Isolates),
		hidden_own_writes_break_reads_own, hidden_own_writes_with_latency_break_reads_own => (HidesOwn, ReadsOwn),
		a_partial_commit_breaks_commits_atomic, a_partial_commit_with_latency_breaks_commits_atomic
			=> (PartialCommit, CommitsAtomic),
		a_kept_rollback_breaks_discards, a_kept_rollback_with_latency_breaks_discards => (KeepsRolledBack, Discards),
		an_overwrite_breaks_inserts_once, an_overwrite_with_latency_breaks_inserts_once => (Overwrites, InsertsOnce),
		blind_inserts_break_races_insert, blind_inserts_with_latency_break_races_insert => (BlindInserts, RacesInsert),
		an_ignored_revision_breaks_guards_revision, an_ignored_revision_with_latency_breaks_guards_revision
			=> (IgnoresRevision, GuardsRevision),
		blind_swaps_break_races_swap, blind_swaps_with_latency_break_races_swap => (BlindSwaps, RacesSwap),
		forgotten_checks_break_checks_reads, forgotten_checks_with_latency_break_checks_reads
			=> (ForgetsChecks, ChecksReads),
		a_stale_beside_a_check_breaks_checks_reads, a_stale_beside_a_check_with_latency_breaks_checks_reads
			=> (StaleBesideCheck, ChecksReads),
		a_stale_absent_remove_breaks_removes_absent, a_stale_absent_remove_with_latency_breaks_removes_absent
			=> (StaleOnAbsent, RemovesAbsent),
		revisions_by_length_break_revises, revisions_by_length_with_latency_break_revises => (RevisesByLength, Revises),
		trimmed_nul_bytes_break_preserves, trimmed_nul_bytes_with_latency_break_preserves => (TrimsNul, Preserves),
		flat_keys_break_separates_partitions, flat_keys_with_latency_break_separates_partitions
			=> (FlatKeys, SeparatesPartitions),
		a_signed_order_breaks_scans_ordered, a_signed_order_with_latency_breaks_scans_ordered
			=> (SignedOrder, ScansOrdered),
		a_sorted_batch_breaks_gets_batch, a_sorted_batch_with_latency_breaks_gets_batch => (SortsBatch, GetsBatch),
		short_keys_break_accepts_keys, short_keys_with_latency_break_accepts_keys => (ShortKeys, AcceptsKeys),
		an_early_stale_breaks_conflicts_early, an_early_stale_with_latency_breaks_conflicts_early
			=> (EarlyStale, ConflictsEarly),
		a_conflict_as_failure_breaks_aborts_typed, a_conflict_as_failure_with_latency_breaks_aborts_typed
			=> (ConflictAsFailed, AbortsTyped),
	}

	/// Whether a driver with latency and no fault met the contract.
	const CONFORMS: Urn<'static> = urn!("test", "event:store-conformance/conforms");

	tb_assert_spec! {
		pub LaggedDriverSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CONFORMS, exactly!(1), equals!(true))
			]
		}
	}

	// A driver that yields before each call, as one over a network waits,
	// and breaks no clause meets the contract.
	tb_scenario! {
		name: a_driver_with_latency_meets_the_kv_contract,
		spec: LaggedDriverSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let checked = KvConformance::new(|| async { Ok(Faulty::new(None, YIELDS)) }).check().await;
				checked.map_err(io::Error::other)?;
				trace.event_with(CONFORMS, &[], true)?;
				Ok(())
			}
		}
	}

	/// Whether one clause ran alone answered as that clause does.
	const ALONE: Urn<'static> = urn!("test", "event:store-conformance/alone");

	tb_assert_spec! {
		pub ClauseAloneSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(ALONE, exactly!(2), equals!(true))
			]
		}
	}

	// A driver of signed order meets the clause of isolation run alone, and
	// breaks the clause of ordered scans run alone.
	tb_scenario! {
		name: a_clause_runs_alone,
		spec: ClauseAloneSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let conformance = KvConformance::new(|| async { Ok(Faulty::new(Some(Fault::SignedOrder), NONE)) });
				let isolated = conformance.clause(KvClause::Isolates).await;
				trace.event_with(ALONE, &[], isolated.is_ok())?;
				let ordered = conformance.clause(KvClause::ScansOrdered).await;
				let breached = ordered.as_ref().err().map(KvBreach::clause);
				trace.event_with(ALONE, &[], breached == Some(KvClause::ScansOrdered))?;
				Ok(())
			}
		}
	}

	/// Whether a check of a slow driver answered as the clauses place.
	const SLOW: Urn<'static> = urn!("test", "event:store-conformance/slow");

	tb_assert_spec! {
		pub SlowDriverSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(SLOW, exactly!(1), equals!(true))
			]
		}
	}

	// A driver whose every call takes three quarters of the rival wait meets
	// the contract: a racer waits out a rival that keeps answering. The clock
	// is paused, so the sleeps take no wall time.
	tb_scenario! {
		name: a_slow_driver_meets_the_kv_contract,
		spec: SlowDriverSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				pause();
				let fresh = || async { Ok(Faulty::new(None, SLOW_CALL)) };
				let checked = KvConformance::new(fresh).with_patience(SLOW_PATIENCE).check().await;
				checked.map_err(io::Error::other)?;
				trace.event_with(SLOW, &[], true)?;
				Ok(())
			}
		}
	}

	// A slow driver that forgets a check of a revision at the commit breaks
	// the clause of checks: the checker waits out its slow rival, so the
	// competing commit lands first. The clock is paused, so the sleeps take no
	// wall time.
	tb_scenario! {
		name: a_slow_driver_that_forgets_revision_checks_breaks_checks_reads,
		spec: SlowDriverSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				pause();
				let fresh = || async { Ok(Faulty::new(Some(Fault::ForgetsRevisionChecks), SLOW_CALL)) };
				let conformance = KvConformance::new(fresh).with_patience(SLOW_PATIENCE);
				let checked = conformance.clause(KvClause::ChecksReads).await;
				let breached = checked.as_ref().err().map(KvBreach::clause);
				trace.event_with(SLOW, &[], breached == Some(KvClause::ChecksReads))?;
				Ok(())
			}
		}
	}

	// A driver of two-phase locking meets the contract: its reads and checks
	// wait on open writes, its writes wait on open writes and checks, and a
	// wait that closes a cycle aborts. A read that answers once the commit of
	// the writer starts may show its writes, and a rival that waited out a
	// rewrite of its key answers `Stale`. The clock is paused, so the waits
	// take no wall time.
	tb_scenario! {
		name: a_driver_of_locks_meets_the_kv_contract,
		spec: SlowDriverSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				pause();
				let fresh = || async { Ok(Faulty::new(None, NONE).with_locks()) };
				KvConformance::new(fresh).check().await.map_err(io::Error::other)?;
				trace.event_with(SLOW, &[], true)?;
				Ok(())
			}
		}
	}

	/// Whether a clause broke at the step that alone catches its fault.
	const DECIDED: Urn<'static> = urn!("test", "event:store-conformance/decided");

	tb_assert_spec! {
		pub DecidingStepSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(DECIDED, exactly!(1), equals!(true))
			]
		}
	}

	// A driver that forgets checks lets two crossed checks of absence both
	// commit, the write skew that the clause of checks refuses first.
	tb_scenario! {
		name: forgotten_checks_let_crossed_checks_commit_together,
		spec: DecidingStepSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let fresh = || async { Ok(Faulty::new(Some(Fault::ForgetsChecks), NONE)) };
				let checked = KvConformance::new(fresh).clause(KvClause::ChecksReads).await;
				let decided = matches!(
					checked,
					Err(KvBreach::Answered { clause: KvClause::ChecksReads, ref step, .. })
						if step == "two crossed checks of absence"
				);
				trace.event_with(DECIDED, &[], decided)?;
				Ok(())
			}
		}
	}

	// A driver of blind swaps lets both swappers of crossed keys commit,
	// which the clause of aborts refuses when it runs alone.
	tb_scenario! {
		name: blind_swaps_let_crossed_swaps_commit_together,
		spec: DecidingStepSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let fresh = || async { Ok(Faulty::new(Some(Fault::BlindSwaps), NONE)) };
				let checked = KvConformance::new(fresh).clause(KvClause::AbortsTyped).await;
				let decided = matches!(
					checked,
					Err(KvBreach::Answered { clause: KvClause::AbortsTyped, ref step, .. })
						if step == "a read after crossed swaps"
				);
				trace.event_with(DECIDED, &[], decided)?;
				Ok(())
			}
		}
	}

	/// Whether the judge of a race answered as its rule says.
	const JUDGED: Urn<'static> = urn!("test", "event:store-conformance/judged");

	tb_assert_spec! {
		pub JudgeSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(JUDGED, exactly!(3), equals!(true))
			]
		}
	}

	// The judge of a race accepts no winner when the key holds what it held
	// before, and one winner when the key holds its write, and refuses two
	// winners.
	tb_scenario! {
		name: a_race_has_at_most_one_winner,
		spec: JudgeSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let probe = Probe { clause: KvClause::RacesSwap, patience: PATIENCE, kv: MemoryKv::default() };
				let key = Key::from_static(NORTH, b"judged");
				probe.seed(&[(&key, b"seeded")]).await.map_err(io::Error::other)?;
				let refused = Raced::Refused(String::from("a swap answered Stale"));
				let first: Option<&[u8]> = Some(b"first");
				let seeded: Option<&[u8]> = Some(b"seeded");
				let none = probe.one_winner("no winner", [(refused, first), (Raced::Conflicted, first)], &key, seeded).await;
				trace.event_with(JUDGED, &[], none.is_ok())?;
				let one = probe.one_winner("one winner", [(Raced::Committed, seeded), (Raced::Conflicted, first)], &key, None).await;
				trace.event_with(JUDGED, &[], one.is_ok())?;
				let two = probe.one_winner("two winners", [(Raced::Committed, seeded), (Raced::Committed, seeded)], &key, None).await;
				trace.event_with(JUDGED, &[], matches!(two, Err(KvBreach::Answered { clause: KvClause::RacesSwap, .. })))?;
				Ok(())
			}
		}
	}

	tightbeam::tb_cases! {
		fn every_clause_has_its_documented_name((clause, name): (KvClause, &'static str)) {
			assert_eq!((clause.name(), clause.to_string()), (name, name.to_owned()));
		}
		cases {
			isolates => (KvClause::Isolates, "isolates"),
			reads_own => (KvClause::ReadsOwn, "reads_own"),
			commits_atomic => (KvClause::CommitsAtomic, "commits_atomic"),
			discards => (KvClause::Discards, "discards"),
			inserts_once => (KvClause::InsertsOnce, "inserts_once"),
			races_insert => (KvClause::RacesInsert, "races_insert"),
			guards_revision => (KvClause::GuardsRevision, "guards_revision"),
			races_swap => (KvClause::RacesSwap, "races_swap"),
			checks_reads => (KvClause::ChecksReads, "checks_reads"),
			removes_absent => (KvClause::RemovesAbsent, "removes_absent"),
			revises => (KvClause::Revises, "revises"),
			preserves => (KvClause::Preserves, "preserves"),
			separates_partitions => (KvClause::SeparatesPartitions, "separates_partitions"),
			scans_ordered => (KvClause::ScansOrdered, "scans_ordered"),
			gets_batch => (KvClause::GetsBatch, "gets_batch"),
			accepts_keys => (KvClause::AcceptsKeys, "accepts_keys"),
			conflicts_early => (KvClause::ConflictsEarly, "conflicts_early"),
			aborts_typed => (KvClause::AbortsTyped, "aborts_typed"),
		}
	}

	#[test]
	fn every_clause_runs_in_the_documented_order() {
		let names: Vec<&str> = KvClause::ALL.iter().map(|clause| clause.name()).collect();
		let documented = [
			"isolates",
			"reads_own",
			"commits_atomic",
			"discards",
			"inserts_once",
			"races_insert",
			"guards_revision",
			"races_swap",
			"checks_reads",
			"removes_absent",
			"revises",
			"preserves",
			"separates_partitions",
			"scans_ordered",
			"gets_batch",
			"accepts_keys",
			"conflicts_early",
			"aborts_typed",
		];
		assert_eq!(names, documented);
	}

	tightbeam::tb_cases! {
		fn a_breach_prints_its_clause_step_and_answer((breach, text, has_source): (KvBreach, &'static str, bool)) {
			assert_eq!((breach.to_string(), format!("{breach:?}")), (text.to_owned(), text.to_owned()));
			assert_eq!(breach.source().is_some(), has_source);
		}
		cases {
			answered => (
				KvBreach::Answered {
					clause: KvClause::GetsBatch,
					step: String::from("a get"),
					answered: String::from("None"),
					expected: String::from("Some(\"a\")"),
				},
				"the driver breaks gets_batch: a get answered None, where the clause places Some(\"a\")",
				false,
			),
			failed => (
				KvBreach::Failed {
					clause: KvClause::AcceptsKeys,
					step: String::from("an insert"),
					error: DriverError::failed("too long"),
				},
				"the driver breaks accepts_keys: an insert failed: the backend failed: too long",
				true,
			),
			lapsed => (
				KvBreach::Lapsed { clause: KvClause::Isolates, step: String::from("a begin"), patience: Duration::from_millis(10) },
				"the driver breaks isolates: a begin did not settle within 10ms",
				false,
			),
		}
	}

	tightbeam::tb_cases! {
		fn a_write_prints_its_kind_and_key((write, text): (Write<'static>, &'static str)) {
			assert_eq!(write.to_string(), text);
		}
		cases {
			insert => (Write::Insert(&JUDGED_KEY, KvValue::new(*b"a\x00")), "an insert of \"a\\x00\" at conformance-north \"k\""),
			swap => (Write::Swap(&JUDGED_KEY, &JUDGED_REVISION, KvValue::new(*b"b")), "a swap to \"b\" at conformance-north \"k\""),
			guarded_remove => (Write::Remove(&JUDGED_KEY, Some(&JUDGED_REVISION)), "a guarded remove at conformance-north \"k\""),
			unguarded_remove => (Write::Remove(&JUDGED_KEY, None), "an unguarded remove at conformance-north \"k\""),
			check_of_a_revision => (Write::Check(&JUDGED_KEY, Some(&JUDGED_REVISION)), "a check of a revision at conformance-north \"k\""),
			check_of_absence => (Write::Check(&JUDGED_KEY, None), "a check of absence at conformance-north \"k\""),
		}
	}

	/// The key of the writes whose text the tests read.
	static JUDGED_KEY: Key = Key::from_static(NORTH, b"k");

	/// The revision of the writes whose text the tests read.
	static JUDGED_REVISION: LazyLock<Revision> = LazyLock::new(|| Revision::new(*b"r"));

	/// A backend whose begin never answers.
	struct Hanging;

	impl OrderedKv for Hanging {
		fn begin(&self) -> DriverFuture<'_, Box<dyn OrderedKvTxn>> {
			Box::pin(pending())
		}

		fn scope(&self) -> Scope {
			Scope::Process
		}
	}

	/// The patience of the scenarios of a driver that never answers.
	const SHORT: Duration = Duration::from_millis(10);

	/// Whether a check broke at the first clause with the breach of the step
	/// that never answered.
	const BROKE: Urn<'static> = urn!("test", "event:store-conformance/broke");

	tb_assert_spec! {
		pub HangingDriverSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(BROKE, exactly!(1), equals!(true))
			]
		}
	}

	// A factory that never builds a backend breaks the first clause with the
	// lapse of the build.
	tb_scenario! {
		name: a_factory_that_never_builds_breaks_the_check_with_a_lapse,
		spec: HangingDriverSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let checked = KvConformance::new(pending::<Result<MemoryKv, DriverError>>).with_patience(SHORT).check().await;
				let broke = matches!(
					checked,
					Err(KvBreach::Lapsed { clause: KvClause::Isolates, ref step, patience })
						if step == "the build of a fresh backend" && patience == SHORT
				);
				trace.event_with(BROKE, &[], broke)?;
				Ok(())
			}
		}
	}

	// A factory that fails breaks the first clause with its failure.
	tb_scenario! {
		name: a_factory_that_fails_breaks_the_check_with_its_failure,
		spec: HangingDriverSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let fresh = || async { Err::<MemoryKv, _>(DriverError::failed("no backend to reach")) };
				let checked = KvConformance::new(fresh).check().await;
				let broke = matches!(
					checked,
					Err(KvBreach::Failed { clause: KvClause::Isolates, ref step, .. }) if step == "the build of a fresh backend"
				);
				trace.event_with(BROKE, &[], broke)?;
				Ok(())
			}
		}
	}

	// A backend that never begins a transaction breaks the first clause with
	// the lapse of the begin.
	tb_scenario! {
		name: a_backend_that_never_begins_breaks_the_check_with_a_lapse,
		spec: HangingDriverSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let checked = KvConformance::new(|| async { Ok(Hanging) }).with_patience(SHORT).check().await;
				let broke = matches!(
					checked,
					Err(KvBreach::Lapsed { clause: KvClause::Isolates, ref step, patience })
						if step == "a begin" && patience == SHORT
				);
				trace.event_with(BROKE, &[], broke)?;
				Ok(())
			}
		}
	}
}
