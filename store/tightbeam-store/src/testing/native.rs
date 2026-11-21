//! The clauses of the native contract that `docs/store.md` (The native
//! contract) lists. The clauses on rows run the KV clauses of one name
//! through the native port.

use core::fmt;
use core::future::Future;
use core::num::NonZeroU32;
use core::slice;
use core::time::Duration;

use tightbeam::builder::{CheckDigestOid, FrameBuilder, TypeBuilder};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::profiles::TightbeamProfile;
use tightbeam::der::asn1::OctetString;
use tightbeam::der::{Decode, DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Tag, Writer};
use tightbeam::marker::{MaybeSend, MaybeSync};
use tightbeam::utils::digest;
use tightbeam::{Errorizable, Frame, Message, MessagePriority, Version};

use super::conformance::{Breach, KvClause, Probe, PATIENCE, TABLES};
use crate::driver::{
	CommitOutcome, ConfirmOutcome, Driver, DriverError, DriverFuture, DriverTxn, InsertOutcome, Prepared,
	RemoveOutcome, Revision, Row, SwapOutcome,
};
use crate::kv::{Entry, Key, KeyRange, KvValue, OrderedKv, OrderedKvTxn, Partition, Stored, TxnFuture};
use crate::row_key::RowKey;
use crate::schema::Schema;
use crate::scope::Scope;
use crate::selection::Direction;

/// The order of every frame of the check.
const ORDER: u64 = 1_700_000_000;

/// The lifetime of every frame of the check.
const LIFETIME: u64 = 3_600;

/// One clause of the native contract, by the name that `docs/store.md` gives
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DriverClause {
	/// A prepare answers `Ready` twice, and `Foreign` for a schema the
	/// backend does not hold.
	Prepares,
	/// A write stays hidden from other transactions until it commits.
	Isolates,
	/// A transaction reads its own writes.
	ReadsOwn,
	/// A commit makes every write visible, or none.
	CommitsAtomic,
	/// A rollback and a drop discard every write and free the rows.
	Discards,
	/// An insert of a present row answers `Occupied` and keeps the row.
	InsertsOnce,
	/// Of concurrent inserts of one row, at most one commits.
	RacesInsert,
	/// A swap or a guarded remove of another revision answers `Stale`.
	GuardsRevision,
	/// Of concurrent guarded writes from one revision, at most one commits.
	RacesSwap,
	/// A confirmed row that changes, appears, or vanishes fails the commit.
	ConfirmsReads,
	/// An unguarded remove of an absent row answers `Removed`.
	RemovesAbsent,
	/// Two frames of one row with other bytes carry other revisions, also
	/// when only their metadata differs.
	Revises,
	/// A read returns the exact frame bytes written.
	Preserves,
	/// A table holds only its own rows.
	SeparatesTypes,
	/// A batch get answers in the order of its keys.
	GetsBatch,
	/// The backend takes binary row ids of 1 to 512 bytes, and tables of 1
	/// to 63 bytes.
	AcceptsKeys,
	/// A write answers `Occupied`, `Stale`, or `Changed` only for a competing
	/// commit the read view holds.
	ConflictsEarly,
	/// A conflict that ends a transaction answers `DriverError::Aborted`.
	AbortsTyped,
}

impl DriverClause {
	/// Every clause, in the order of `docs/store.md`, which
	/// [`DriverConformance::check`] runs.
	pub const ALL: [Self; 18] = [
		Self::Prepares,
		Self::Isolates,
		Self::ReadsOwn,
		Self::CommitsAtomic,
		Self::Discards,
		Self::InsertsOnce,
		Self::RacesInsert,
		Self::GuardsRevision,
		Self::RacesSwap,
		Self::ConfirmsReads,
		Self::RemovesAbsent,
		Self::Revises,
		Self::Preserves,
		Self::SeparatesTypes,
		Self::GetsBatch,
		Self::AcceptsKeys,
		Self::ConflictsEarly,
		Self::AbortsTyped,
	];

	/// The name of this clause in `docs/store.md`.
	pub const fn name(self) -> &'static str {
		match self {
			Self::Prepares => "prepares",
			Self::Isolates => "isolates",
			Self::ReadsOwn => "reads_own",
			Self::CommitsAtomic => "commits_atomic",
			Self::Discards => "discards",
			Self::InsertsOnce => "inserts_once",
			Self::RacesInsert => "races_insert",
			Self::GuardsRevision => "guards_revision",
			Self::RacesSwap => "races_swap",
			Self::ConfirmsReads => "confirms_reads",
			Self::RemovesAbsent => "removes_absent",
			Self::Revises => "revises",
			Self::Preserves => "preserves",
			Self::SeparatesTypes => "separates_types",
			Self::GetsBatch => "gets_batch",
			Self::AcceptsKeys => "accepts_keys",
			Self::ConflictsEarly => "conflicts_early",
			Self::AbortsTyped => "aborts_typed",
		}
	}

	/// The KV clause that this clause runs through the native port, or `None`
	/// for a clause of the native port alone.
	const fn kv(self) -> Option<KvClause> {
		let clause = match self {
			Self::Prepares => return None,
			Self::Isolates => KvClause::Isolates,
			Self::ReadsOwn => KvClause::ReadsOwn,
			Self::CommitsAtomic => KvClause::CommitsAtomic,
			Self::Discards => KvClause::Discards,
			Self::InsertsOnce => KvClause::InsertsOnce,
			Self::RacesInsert => KvClause::RacesInsert,
			Self::GuardsRevision => KvClause::GuardsRevision,
			Self::RacesSwap => KvClause::RacesSwap,
			Self::ConfirmsReads => KvClause::ConfirmsReads,
			Self::RemovesAbsent => KvClause::RemovesAbsent,
			Self::Revises => KvClause::Revises,
			Self::Preserves => KvClause::Preserves,
			Self::SeparatesTypes => KvClause::SeparatesPartitions,
			Self::GetsBatch => KvClause::GetsBatch,
			Self::AcceptsKeys => KvClause::AcceptsKeys,
			Self::ConflictsEarly => KvClause::ConflictsEarly,
			Self::AbortsTyped => KvClause::AbortsTyped,
		};

		Some(clause)
	}
}

impl fmt::Display for DriverClause {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.name())
	}
}

/// The clause of the native contract that a driver breaks, and how.
pub type DriverBreach = Breach<DriverClause>;

/// The factory of the empty backends of a check, one per clause.
///
/// A closure that returns a future of `Result<impl Driver, DriverError>` is a
/// factory.
pub trait FreshDriver: MaybeSync {
	/// The backend under check.
	type Driver: Driver;

	/// One more empty backend.
	///
	/// # Errors
	///
	/// - The [`DriverError`] of a backend that could not be built.
	fn fresh(&self) -> impl Future<Output = Result<Self::Driver, DriverError>> + MaybeSend;
}

impl<F, Fut, D> FreshDriver for F
where
	F: Fn() -> Fut + MaybeSync,
	Fut: Future<Output = Result<D, DriverError>> + MaybeSend,
	D: Driver,
{
	type Driver = D;

	fn fresh(&self) -> impl Future<Output = Result<D, DriverError>> + MaybeSend {
		self()
	}
}

/// The clauses of the native contract that `docs/store.md` (The native
/// contract) lists, as one check of one driver.
///
/// - Each clause runs on a fresh backend that `fresh` builds, prepared for
///   the tables of the check.
/// - The clauses on rows run as the KV clauses of one name do, over frames
///   whose body is the value of the KV clause. The native port reads no
///   range, so they skip each scan.
///
/// # Examples
///
/// ```
/// use tightbeam_store::testing::{DriverBreach, DriverConformance};
/// use tightbeam_store::MemoryDriver;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), DriverBreach> {
/// DriverConformance::new(|| async { Ok(MemoryDriver::default()) }).check().await
/// # }
/// ```
pub struct DriverConformance<F> {
	fresh: F,
	/// How long one step of a clause waits.
	patience: Duration,
}

impl<F: FreshDriver> DriverConformance<F> {
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

	/// Check each clause of [`DriverClause::ALL`], each on a fresh backend.
	///
	/// # Errors
	///
	/// - The [`DriverBreach`] of the first clause that the driver breaks.
	pub async fn check(&self) -> Result<(), DriverBreach> {
		for clause in DriverClause::ALL {
			self.clause(clause).await?;
		}

		Ok(())
	}

	/// Check `clause` alone, on a fresh backend.
	///
	/// # Errors
	///
	/// - The [`DriverBreach`] of the run. A `DriverError::Failed` inside a race
	///   breaks [`DriverClause::AbortsTyped`], whichever clause raced.
	pub async fn clause(&self, clause: DriverClause) -> Result<(), DriverBreach> {
		let Some(kv) = clause.kv() else {
			return self.prepares().await;
		};

		if clause == DriverClause::Revises {
			self.revises_metadata().await?;
		}

		self.through_rows(clause, kv).await
	}

	/// Run the KV clause `kv` of the native clause `clause` through the native
	/// port of a fresh backend.
	///
	/// # Errors
	///
	/// - The breach of the run, charged to the native clause of the KV clause it breaks.
	async fn through_rows(&self, clause: DriverClause, kv: KvClause) -> Result<(), DriverBreach> {
		let checked = match self.probe(clause, kv).await {
			Ok(probe) => probe.clause(kv).await,
			Err(breach) => Err(breach),
		};

		checked.map_err(|breach| {
			let charged = DriverClause::ALL
				.into_iter()
				.find(|native| native.kv() == Some(breach.clause()));
			breach.charged(charged.unwrap_or(clause))
		})
	}

	/// The probe of the KV clause `clause` through the native port of a fresh
	/// backend, prepared for the tables of the check.
	///
	/// # Errors
	///
	/// - [`Breach::Lapsed`] or [`Breach::Failed`] -- the factory built no backend, or the prepare
	///   failed.
	/// - [`Breach::Answered`] -- the prepare answered `Foreign`.
	async fn probe(&self, native: DriverClause, clause: KvClause) -> Result<Probe<Rows<F::Driver>>, Breach<KvClause>> {
		let building = Probe::bare(clause, self.patience);
		let driver = self.prepared(&building).await?;
		Ok(Probe::rows(clause, native, self.patience, Rows { driver }))
	}

	/// A fresh backend, prepared for the tables of the check, with the steps
	/// of `probe`.
	///
	/// # Errors
	///
	/// - [`Breach::Lapsed`] or [`Breach::Failed`] -- the factory built no backend, or the prepare
	///   failed.
	/// - [`Breach::Answered`] -- the prepare answered `Foreign`.
	async fn prepared<C: Copy>(&self, probe: &Probe<(), C>) -> Result<F::Driver, Breach<C>> {
		let driver = probe.call("the build of a fresh backend", self.fresh.fresh()).await?;
		let step = "the prepare of the tables of the check";
		let prepared = probe.call(step, driver.prepare(&Schema::CURRENT, &TABLES)).await?;
		if let Prepared::Foreign(_) = prepared {
			return Err(probe.refuse(step, &prepared, &Prepared::Ready));
		}

		Ok(driver)
	}

	/// Two frames of one row with one body and other metadata, whose commits
	/// leave two revisions.
	async fn revises_metadata(&self) -> Result<(), DriverBreach> {
		let probe = Probe::bare(DriverClause::Revises, self.patience);
		let driver = self.prepared(&probe).await?;
		let key = Key::from_static(Partition::of(TABLES[0]), b"metadata");
		let value = KvValue::new(b"one body".as_slice());
		let (key, value) = (&key, &value);
		let framed = |priority| async move { RowsTxn::framed(key, value, priority) };
		let first = probe.call("the build of a frame", framed(MessagePriority::Standard)).await?;
		let second = probe.call("the build of a frame", framed(MessagePriority::Expedited)).await?;

		let txn = probe.call("a begin", driver.begin()).await?;
		let step = "an insert of a frame";
		let (txn, inserted) = probe.call(step, txn.insert(&first)).await?;
		if inserted != InsertOutcome::Inserted {
			return Err(probe.refuse(step, &inserted, &InsertOutcome::Inserted));
		}

		let before = Self::committed(&probe, &driver, txn, first.key()).await?;
		let txn = probe.call("a begin", driver.begin()).await?;
		let step = "a swap to a frame of other metadata";
		let (txn, swapped) = probe.call(step, txn.swap(&second, &before)).await?;
		if swapped != SwapOutcome::Swapped {
			return Err(probe.refuse(step, &swapped, &SwapOutcome::Swapped));
		}

		let after = Self::committed(&probe, &driver, txn, second.key()).await?;
		if before == after {
			return Err(probe.refuse("the revision of a frame of other metadata", &after, &"another revision"));
		}

		Ok(())
	}

	/// Commit `txn`, then the committed revision of the row at `key`.
	///
	/// # Errors
	///
	/// - The breach of a step, or [`Breach::Answered`] for a conflict or an absent row.
	async fn committed(
		probe: &Probe<(), DriverClause>,
		driver: &F::Driver,
		txn: Box<dyn DriverTxn>,
		key: &RowKey,
	) -> Result<Revision, DriverBreach> {
		let step = "the commit of a frame";
		let committed = probe.call(step, txn.commit()).await?;
		if committed != CommitOutcome::Committed {
			return Err(probe.refuse(step, &committed, &CommitOutcome::<RowKey>::Committed));
		}

		let txn = probe.call("a begin", driver.begin()).await?;
		let step = "a get of the committed frame";
		let (txn, read) = probe.call(step, txn.get(slice::from_ref(key))).await?;

		probe.call("a rollback", txn.rollback()).await?;

		let revision = read.into_iter().next().flatten().map(|stored| stored.revision().clone());
		revision.ok_or_else(|| probe.refuse(step, &"no row", &"a row"))
	}

	/// Two prepares of the tables of the check and one of fewer tables, each
	/// of the schema of this release, which answer `Ready`, and one of a
	/// schema that no release holds, which answers `Foreign`.
	async fn prepares(&self) -> Result<(), DriverBreach> {
		let probe = Probe::bare(DriverClause::Prepares, self.patience);
		let driver = probe.call("the build of a fresh backend", self.fresh.fresh()).await?;
		let steps = [
			("a prepare of the tables of the check", TABLES.as_slice()),
			("a second prepare of the tables", TABLES.as_slice()),
			("a prepare of one of the tables", &TABLES[..1]),
		];
		for (step, tables) in steps {
			let prepared = probe.call(step, driver.prepare(&Schema::CURRENT, tables)).await?;
			if !matches!(prepared, Prepared::Ready) {
				return Err(probe.refuse(step, &prepared, &Prepared::Ready));
			}
		}

		let step = "a prepare of a schema that no release holds";
		let prepared = probe.call(step, driver.prepare(&Schema::FOREIGN, &TABLES)).await?;
		if !matches!(prepared, Prepared::Foreign(_)) {
			return Err(probe.refuse(step, &prepared, &"Foreign"));
		}

		Ok(())
	}
}

/// The answers of a native driver that the rows of a KV clause cannot carry,
/// each the source of a [`DriverError::Failed`].
#[derive(Debug, Errorizable)]
enum RowsError {
	/// A key of a KV clause names no table.
	#[error("the partition {0} names no table")]
	Table(Partition),

	/// The native port reads no range.
	#[error("the native port reads no range")]
	Range,
}

/// The body of a frame of the check: the value of a KV clause.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Payload(OctetString);

impl FixedTag for Payload {
	const TAG: Tag = Tag::OctetString;
}

impl EncodeValue for Payload {
	fn value_len(&self) -> tightbeam::der::Result<Length> {
		self.0.value_len()
	}

	fn encode_value(&self, writer: &mut impl Writer) -> tightbeam::der::Result<()> {
		self.0.encode_value(writer)
	}
}

impl<'a> DecodeValue<'a> for Payload {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> tightbeam::der::Result<Self> {
		OctetString::decode_value(reader, header).map(Self)
	}
}

impl Message for Payload {
	type Profile = TightbeamProfile;
}

impl CheckDigestOid<Sha3_256> for Payload {}

/// A native driver as the KV port that the KV clauses drive: a partition is a
/// table, a sort key a row id, and a value the body of a frame.
pub(super) struct Rows<D> {
	driver: D,
}

impl<D: Driver> OrderedKv for Rows<D> {
	fn begin(&self) -> DriverFuture<'_, Box<dyn OrderedKvTxn>> {
		Box::pin(async move {
			let txn = self.driver.begin().await?;
			Ok(RowsTxn::boxed(txn))
		})
	}

	fn scope(&self) -> Scope {
		self.driver.scope()
	}
}

/// One transaction of a native driver, as the KV clauses drive it.
struct RowsTxn {
	txn: Box<dyn DriverTxn>,
}

impl RowsTxn {
	/// The transaction `txn`, for the next call.
	fn boxed(txn: Box<dyn DriverTxn>) -> Box<dyn OrderedKvTxn> {
		Box::new(Self { txn })
	}

	/// The row key of `key`.
	///
	/// # Errors
	///
	/// - [`DriverError::Failed`] -- `key` names no table of the check.
	fn row_key(key: &Key) -> Result<RowKey, DriverError> {
		key.row_key()
			.ok_or_else(|| DriverError::failed(RowsError::Table(key.partition())))
	}

	/// The row at `key` of the frame of the check whose body is `value`.
	///
	/// # Errors
	///
	/// - [`DriverError::Failed`] -- the row does not build.
	fn row(key: &Key, value: &KvValue) -> Result<Row, DriverError> {
		Self::framed(key, value, MessagePriority::Standard)
	}

	/// The row at `key` of a frame whose body is `value`, at `priority`. Each
	/// frame carries every field that needs no key: a fixed order, a priority,
	/// a lifetime, the previous frame, a message commitment, and a frame
	/// integrity digest.
	///
	/// # Errors
	///
	/// - [`DriverError::Failed`] -- the row does not build.
	fn framed(key: &Key, value: &KvValue, priority: MessagePriority) -> Result<Row, DriverError> {
		let table = Self::row_key(key)?.frame_type();
		let payload = Payload(OctetString::new(value.as_bytes()).map_err(DriverError::failed)?);
		let previous = digest::<Sha3_256>(value.as_bytes()).map_err(DriverError::failed)?;
		let builder = FrameBuilder::<Payload>::from(Version::V2)
			.with_id(key.sort())
			.with_order(ORDER)
			.with_message(payload)
			.with_priority(priority)
			.with_lifetime(LIFETIME)
			.with_previous_hash(previous)
			.with_message_hasher::<Sha3_256>(b"")
			.with_witness_hasher::<Sha3_256>();

		let frame = builder.build().map_err(DriverError::failed)?;
		Row::new(table, &frame).map_err(DriverError::failed)
	}

	/// The value of the KV clause that `stored` holds at `key`: the body of the
	/// frame, when the bytes are exactly the frame the check wrote for that
	/// body, or else the bytes as they are, which no value of the check
	/// matches.
	fn payload(key: Option<&Key>, stored: Stored) -> Stored {
		let frame = Frame::from_der(stored.bytes()).ok();
		let body = frame.and_then(|frame| Payload::from_der(frame.message()).ok());
		let value = body.map(|body| KvValue::new(body.0.into_bytes()));
		let written = key.zip(value).and_then(|(key, value)| {
			let row = Self::row(key, &value).ok()?;
			(row.bytes() == stored.bytes()).then_some(value)
		});

		match written {
			Some(value) => Stored::new(value.as_bytes(), stored.revision().clone()),
			None => stored,
		}
	}
}

impl OrderedKvTxn for RowsTxn {
	fn get<'a>(self: Box<Self>, keys: &'a [Key]) -> TxnFuture<'a, Vec<Option<Stored>>> {
		Box::pin(async move {
			let row_keys = keys.iter().map(Self::row_key).collect::<Result<Vec<_>, _>>()?;
			let (txn, rows) = self.txn.get(&row_keys).await?;
			let read = rows
				.into_iter()
				.enumerate()
				.map(|(index, row)| row.map(|stored| Self::payload(keys.get(index), stored)));
			Ok((Self::boxed(txn), read.collect()))
		})
	}

	fn insert<'a>(self: Box<Self>, key: &'a Key, value: &'a KvValue) -> TxnFuture<'a, InsertOutcome> {
		Box::pin(async move {
			let row = Self::row(key, value)?;
			let (txn, inserted) = self.txn.insert(&row).await?;
			Ok((Self::boxed(txn), inserted))
		})
	}

	fn swap<'a>(
		self: Box<Self>,
		key: &'a Key,
		expected: &'a Revision,
		value: &'a KvValue,
	) -> TxnFuture<'a, SwapOutcome> {
		Box::pin(async move {
			let row = Self::row(key, value)?;
			let (txn, swapped) = self.txn.swap(&row, expected).await?;
			Ok((Self::boxed(txn), swapped))
		})
	}

	fn remove<'a>(self: Box<Self>, key: &'a Key, expected: Option<&'a Revision>) -> TxnFuture<'a, RemoveOutcome> {
		Box::pin(async move {
			let row_key = Self::row_key(key)?;
			let (txn, removed) = self.txn.remove(&row_key, expected).await?;
			Ok((Self::boxed(txn), removed))
		})
	}

	fn scan<'a>(
		self: Box<Self>,
		_range: &'a KeyRange,
		_direction: Direction,
		_limit: NonZeroU32,
	) -> TxnFuture<'a, Vec<Entry>> {
		Box::pin(async { Err(DriverError::failed(RowsError::Range)) })
	}

	fn confirm<'a>(self: Box<Self>, key: &'a Key, expected: Option<&'a Revision>) -> TxnFuture<'a, ConfirmOutcome> {
		Box::pin(async move {
			let row_key = Self::row_key(key)?;
			let (txn, confirmed) = self.txn.confirm(&row_key, expected).await?;
			Ok((Self::boxed(txn), confirmed))
		})
	}

	fn commit(self: Box<Self>) -> DriverFuture<'static, CommitOutcome<Key>> {
		Box::pin(async move {
			let committed = self.txn.commit().await?;
			Ok(committed.map_key(|key| Some(Key::row(&key))))
		})
	}

	fn rollback(self: Box<Self>) -> DriverFuture<'static, ()> {
		self.txn.rollback()
	}
}
