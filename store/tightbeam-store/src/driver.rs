//! The vocabulary that the ports of the store share: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#the-kv-port).

use core::error::Error;
use core::fmt;

use tightbeam::marker::MaybeSendFuture;

/// The future of one call of a store port: a boxed future, `Send` off
/// wasm32, which a driver builds with `Box::pin(async move { .. })`.
pub type DriverFuture<'a, T> = MaybeSendFuture<'a, Result<T, DriverError>>;

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
