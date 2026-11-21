//! The native port, and the vocabulary that both ports share: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#the-native-port).

use core::error::Error;
use core::fmt;

use tightbeam::marker::{MaybeSend, MaybeSendFuture, MaybeSync};

#[cfg(any(test, feature = "testing"))]
use tightbeam::Frame;

use crate::frame_type::FrameType;
use crate::kv::Stored;
use crate::row_key::RowKey;
use crate::schema::{Projection, Schema};
use crate::scope::Scope;

#[cfg(any(test, feature = "testing"))]
use crate::error::StoreError;
#[cfg(any(test, feature = "testing"))]
use crate::row_id::RowId;

/// The future of one call of a store port: a boxed future, `Send` off
/// wasm32, which a driver builds with `Box::pin(async move { .. })`.
pub type DriverFuture<'a, T> = MaybeSendFuture<'a, Result<T, DriverError>>;

/// The future of one call of an open [`DriverTxn`]: the transaction, handed
/// back for the next call, and the answer. A [`DriverError`] hands nothing
/// back, so no call follows it.
pub type RowTxnFuture<'a, T> = DriverFuture<'a, (Box<dyn DriverTxn>, T)>;

/// A backend of the store with its own physical model and indexes.
///
/// A driver MUST meet each clause of the native contract, which
/// `testing::DriverConformance` checks: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#the-native-contract).
pub trait Driver: MaybeSend + MaybeSync + 'static {
	/// Provision `tables` for rows of `schema`, and record its version.
	///
	/// - The core prepares the tables of a store before its first transaction
	///   touches them.
	/// - A later call for the same or other tables of `schema` answers `Ready`.
	/// - A backend that holds another schema version answers `Foreign`.
	/// - The loser of a race to provision answers [`DriverError::Aborted`].
	fn prepare<'a>(&'a self, schema: &'a Schema, tables: &'a [FrameType]) -> DriverFuture<'a, Prepared>;

	/// A new transaction, which sees every commit before it and none of the
	/// writes of other open transactions.
	fn begin(&self) -> DriverFuture<'_, Box<dyn DriverTxn>>;

	/// Where the rows of this backend are reachable from.
	fn scope(&self) -> Scope;
}

/// One transaction of a [`Driver`], with the rules of
/// [`OrderedKvTxn`](crate::OrderedKvTxn) over rows: each call hands the
/// transaction back, a [`DriverError`] ends it, and the commit refuses a
/// transaction whose relied-on rows moved.
pub trait DriverTxn: MaybeSend {
	/// The frame DER and revision of the row of each key of `keys`, in their
	/// order, and `None` for an absent row.
	fn get<'a>(self: Box<Self>, keys: &'a [RowKey]) -> RowTxnFuture<'a, Vec<Option<Stored>>>;

	/// Write `row` when its key is absent.
	fn insert<'a>(self: Box<Self>, row: &'a Row) -> RowTxnFuture<'a, InsertOutcome>;

	/// Write `row` when its key holds the revision `expected`. The compare and
	/// the write are one step.
	fn swap<'a>(self: Box<Self>, row: &'a Row, expected: &'a Revision) -> RowTxnFuture<'a, SwapOutcome>;

	/// Remove the row at `key`: when it holds the revision `expected`, or with
	/// no guard when `expected` is `None`. An unguarded remove of an absent row
	/// answers `Removed`.
	fn remove<'a>(self: Box<Self>, key: &'a RowKey, expected: Option<&'a Revision>) -> RowTxnFuture<'a, RemoveOutcome>;

	/// Confirm that `key` holds the revision `expected`, or is absent when
	/// `expected` is `None`. A `Held` answer holds until the commit.
	fn confirm<'a>(
		self: Box<Self>,
		key: &'a RowKey,
		expected: Option<&'a Revision>,
	) -> RowTxnFuture<'a, ConfirmOutcome>;

	/// Make every write of this transaction visible together, or none. The key
	/// of a conflict is one of the keys this transaction wrote or confirmed,
	/// or `None`.
	fn commit(self: Box<Self>) -> DriverFuture<'static, CommitOutcome<RowKey>>;

	/// Discard every write of this transaction. A drop discards them too.
	fn rollback(self: Box<Self>) -> DriverFuture<'static, ()>;
}

/// One row that the core writes: its key, its frame DER, and the projection
/// of that frame. Only the core builds one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
	key: RowKey,
	bytes: Vec<u8>,
	projection: Projection,
}

// The contract suite builds the rows of this release.
#[cfg(any(test, feature = "testing"))]
impl Row {
	/// The row of `frame` in `table`, at the row id `metadata.id`.
	///
	/// # Errors
	///
	/// - [`StoreError::RowIdLength`] -- `metadata.id` holds no byte, or more than 512.
	/// - The errors of [`RowKey::new`] and of the projection.
	pub(crate) fn new(table: FrameType, frame: &Frame) -> Result<Self, StoreError> {
		let row_id = RowId::try_from(frame.metadata().id())?;
		let key = RowKey::new(table, row_id)?;
		let (projection, bytes) = Projection::of(&key, frame)?;
		Ok(Self { key, bytes, projection })
	}
}

impl Row {
	/// The key of this row.
	pub fn key(&self) -> &RowKey {
		&self.key
	}

	/// The DER of the frame of this row, which a driver stores as it is.
	pub fn bytes(&self) -> &[u8] {
		&self.bytes
	}

	/// The metadata of the frame, which a driver indexes.
	pub fn projection(&self) -> &Projection {
		&self.projection
	}
}

/// The answer of a prepare.
#[must_use]
#[derive(Debug)]
pub enum Prepared {
	/// The backend holds the tables, for this schema.
	Ready,
	/// The backend holds another schema version or layout, so the store does
	/// not open it. The source says what it holds.
	Foreign(Box<dyn Error + Send + Sync>),
}

impl Prepared {
	/// The refusal of a backend that holds something else, with its reason
	/// `source`.
	pub fn foreign(source: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
		Self::Foreign(source.into())
	}
}

/// The version of one stored value, which the backend issues at each write.
///
/// The core reads no meaning in the bytes. It hands a revision back to guard
/// a write or to confirm a read. Two revisions of one key are equal only when
/// the bytes they version are equal.
///
/// # Examples
///
/// ```
/// use tightbeam_store::Revision;
///
/// let revision = Revision::new(7u64.to_be_bytes());
/// assert_eq!(revision.as_bytes(), [0, 0, 0, 0, 0, 0, 0, 7]);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Revision(Vec<u8>);

impl Revision {
	/// The revision `bytes`, such as a version column, an ETag, or a counter.
	pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
		Self(bytes.into())
	}

	/// The bytes of this revision.
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}
}

/// The answer of an insert.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertOutcome {
	/// The key was absent, and now holds the value.
	Inserted,
	/// The key holds a value, which the insert left in place.
	Occupied,
}

/// The answer of a guarded write.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapOutcome {
	/// The key held the expected revision, and now holds the new value.
	Swapped,
	/// The key held another revision, or none, so the write did not happen.
	Stale,
}

/// The answer of a remove.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoveOutcome {
	/// The key holds no value now.
	Removed,
	/// The key held another revision than the guard expected, or none, so
	/// the remove did not happen.
	Stale,
}

/// The answer of a read confirmation.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmOutcome {
	/// The key holds the expected revision, or is absent as expected. The
	/// commit fails if that changes before it.
	Held,
	/// The key holds another revision, or another presence, than expected.
	Changed,
}

/// The answer of a commit.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitOutcome<K> {
	/// Every write of the transaction is visible.
	Committed,
	/// A competing commit changed a key the transaction relied on, so no
	/// write of it is visible. The key is `None` when the backend does not
	/// name it.
	Conflicted(Option<K>),
}

impl<K> CommitOutcome<K> {
	/// This answer, with the key of a conflict as `named` names it, or `None`.
	pub(crate) fn map_key<L>(self, named: impl FnOnce(K) -> Option<L>) -> CommitOutcome<L> {
		match self {
			Self::Committed => CommitOutcome::Committed,
			Self::Conflicted(key) => CommitOutcome::Conflicted(key.and_then(named)),
		}
	}
}

/// A failure of a store port, which ends the transaction.
#[derive(Debug)]
pub enum DriverError {
	/// The backend ended the transaction over a conflict, such as a deadlock,
	/// a serialization failure, or a write conflict. Nothing committed, so
	/// the work may run again.
	Aborted(Box<dyn Error + Send + Sync>),
	/// The backend failed. From a commit, whether it committed is unknown.
	Failed(Box<dyn Error + Send + Sync>),
}

impl DriverError {
	/// The abort of a transaction over a conflict, with its cause `source`.
	pub fn aborted(source: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
		Self::Aborted(source.into())
	}

	/// The failure of a backend, with its cause `source`.
	pub fn failed(source: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
		Self::Failed(source.into())
	}
}

impl fmt::Display for DriverError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Aborted(source) => write!(f, "the backend aborted the transaction over a conflict: {source}"),
			Self::Failed(source) => write!(f, "the backend failed: {source}"),
		}
	}
}

impl Error for DriverError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Aborted(source) | Self::Failed(source) => Some(source.as_ref()),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	tightbeam::tb_cases! {
		fn a_driver_error_prints_its_kind_and_its_cause((error, text): (DriverError, &'static str)) {
			let cause = error.source().map(ToString::to_string);
			assert_eq!((error.to_string(), cause.as_deref()), (text.to_owned(), Some("the cause")));
		}
		cases {
			aborted => (DriverError::aborted("the cause"), "the backend aborted the transaction over a conflict: the cause"),
			failed => (DriverError::failed("the cause"), "the backend failed: the cause"),
		}
	}
}
