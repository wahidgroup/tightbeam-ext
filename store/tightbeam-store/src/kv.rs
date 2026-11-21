//! The ordered key-value port: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#the-kv-port).

use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::num::NonZeroU32;
use core::ops::{Bound, RangeBounds};
use std::borrow::Cow;

use tightbeam::marker::{MaybeSend, MaybeSync};

use crate::driver::{CommitOutcome, ConfirmOutcome, DriverFuture, InsertOutcome, RemoveOutcome, Revision, SwapOutcome};
#[cfg(test)]
use crate::error::StoreError;
use crate::frame_type::{self, FrameType};
use crate::row_id::{self, RowId};
use crate::row_key::RowKey;
use crate::schema::MAX_BYTES;
use crate::scope::Scope;
use crate::selection::Direction;

/// The future of one call of an open transaction: the transaction, handed
/// back for the next call, and the answer. A [`DriverError`](crate::DriverError)
/// hands nothing back, so no call follows it.
pub type TxnFuture<'a, T> = DriverFuture<'a, (Box<dyn OrderedKvTxn>, T)>;

/// An ordered key-value backend of the store.
///
/// A driver MUST meet each clause of the KV contract, which
/// `testing::KvConformance` checks: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#the-kv-contract).
pub trait OrderedKv: MaybeSend + MaybeSync + 'static {
	/// A new transaction, which sees every commit before it and none of the
	/// writes of other open transactions.
	fn begin(&self) -> DriverFuture<'_, Box<dyn OrderedKvTxn>>;

	/// Where the values of this backend are reachable from.
	fn scope(&self) -> Scope;
}

/// One transaction of an [`OrderedKv`] backend.
///
/// - Each call takes the transaction and hands it back with its answer. A
///   [`DriverError`](crate::DriverError) ends the transaction.
/// - A read sees the committed state and the writes of this transaction. A
///   call on a key this transaction wrote answers from that write, and the
///   revision of that write guards the next calls of this transaction.
/// - The commit MUST NOT answer `Committed` when a competing commit moved a key
///   that a call relied on: the absence an insert found, the revision a swap
///   or a guarded remove matched, or the state a confirm held. A call on a key
///   this transaction wrote relies on nothing in committed state.
/// - A commit that loses answers `Conflicted`, or [`DriverError::Aborted`](crate::DriverError::Aborted)
///   when the backend ends the transaction itself.
pub trait OrderedKvTxn: MaybeSend {
	/// The value of each key of `keys`, in their order, and `None` for an
	/// absent key.
	fn get<'a>(self: Box<Self>, keys: &'a [Key]) -> TxnFuture<'a, Vec<Option<Stored>>>;

	/// Write `value` at `key` when the key is absent.
	fn insert<'a>(self: Box<Self>, key: &'a Key, value: &'a KvValue) -> TxnFuture<'a, InsertOutcome>;

	/// Write `value` at `key` when the key holds the revision `expected`.
	/// The compare and the write are one step.
	fn swap<'a>(
		self: Box<Self>,
		key: &'a Key,
		expected: &'a Revision,
		value: &'a KvValue,
	) -> TxnFuture<'a, SwapOutcome>;

	/// Remove the value at `key`: when it holds the revision `expected`, or
	/// with no guard when `expected` is `None`. An unguarded remove of an
	/// absent key answers `Removed`.
	fn remove<'a>(self: Box<Self>, key: &'a Key, expected: Option<&'a Revision>) -> TxnFuture<'a, RemoveOutcome>;

	/// The entries of `range`, in unsigned byte order of their sort keys
	/// along `direction`, and at most `limit` of them.
	fn scan<'a>(
		self: Box<Self>,
		range: &'a KeyRange,
		direction: Direction,
		limit: NonZeroU32,
	) -> TxnFuture<'a, Vec<Entry>>;

	/// Confirm that `key` holds the revision `expected`, or is absent when
	/// `expected` is `None`. A `Held` answer holds until the commit.
	fn confirm<'a>(self: Box<Self>, key: &'a Key, expected: Option<&'a Revision>) -> TxnFuture<'a, ConfirmOutcome>;

	/// Make every write of this transaction visible together, or none.
	fn commit(self: Box<Self>) -> DriverFuture<'static, CommitOutcome<Key>>;

	/// Discard every write of this transaction. A drop discards them too.
	fn rollback(self: Box<Self>) -> DriverFuture<'static, ()>;
}

/// One partition of the key space: 1 to 80 bytes of lowercase ASCII letters,
/// digits, hyphens, and slashes, starting with a letter.
///
/// Two partitions are equal when their names are, whatever table they name.
#[derive(Clone, Copy, Debug)]
pub struct Partition {
	name: &'static str,
	/// The table whose rows this partition holds, or `None` for a partition
	/// of no table.
	table: Option<FrameType>,
}

// A frame type is a partition: it starts with a lowercase letter, takes a
// subset of the bytes of a partition, and is no longer.
const _: () = assert!(frame_type::MAX_LEN <= Partition::MAX_LEN);

impl Partition {
	/// The bytes of this partition.
	pub const fn as_bytes(&self) -> &[u8] {
		self.name.as_bytes()
	}

	/// The longest partition, in bytes.
	pub(crate) const MAX_LEN: usize = 80;

	/// The refusal of a partition of no byte, or of more than 80.
	const LENGTH_REFUSAL: &str = "a partition holds 1 to 80 bytes";

	/// The refusal of a partition that starts with no lowercase letter.
	const FIRST_REFUSAL: &str = "a partition starts with a lowercase ASCII letter";

	/// The refusal of a partition with a byte outside the grammar.
	const BYTE_REFUSAL: &str = "a partition holds lowercase ASCII letters, digits, hyphens, and slashes alone";

	/// The partition `name`.
	///
	/// # Panics
	///
	/// - `name` breaks the grammar of a partition. In a `const` item, the panic
	///   is a compile error.
	pub(crate) const fn from_static(name: &'static str) -> Self {
		let bytes = name.as_bytes();
		if bytes.is_empty() || bytes.len() > Self::MAX_LEN {
			panic!("{}", Self::LENGTH_REFUSAL);
		}
		if !bytes[0].is_ascii_lowercase() {
			panic!("{}", Self::FIRST_REFUSAL);
		}

		let mut index = 0;
		while index < bytes.len() {
			let byte = bytes[index];
			if !FrameType::admits(byte) && byte != b'/' {
				panic!("{}", Self::BYTE_REFUSAL);
			}

			index += 1;
		}

		Self { name, table: None }
	}

	/// The partition of the rows of `table`.
	pub(crate) const fn of(table: FrameType) -> Self {
		Self { name: table.as_str(), table: Some(table) }
	}
}

impl PartialEq for Partition {
	fn eq(&self, other: &Self) -> bool {
		self.name == other.name
	}
}

impl Eq for Partition {}

impl PartialOrd for Partition {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl Ord for Partition {
	fn cmp(&self, other: &Self) -> Ordering {
		self.name.cmp(other.name)
	}
}

impl Hash for Partition {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.name.hash(state);
	}
}

impl fmt::Display for Partition {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.name)
	}
}

/// The key of one value: its partition and its sort key within it. A sort
/// key holds 1 to 621 bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
	partition: Partition,
	sort: Cow<'static, [u8]>,
}

impl Key {
	/// The partition of this key.
	pub fn partition(&self) -> Partition {
		self.partition
	}

	/// The sort key of this key within its partition.
	pub fn sort(&self) -> &[u8] {
		&self.sort
	}

	/// The longest sort key, in bytes: the longest index entry, of a length
	/// byte, a field value, an 8-byte order, and a row id.
	pub(crate) const MAX_SORT: usize = 1 + MAX_BYTES + 8 + row_id::MAX_LEN;

	/// The refusal of a sort key of no byte, or of more than 621.
	const SORT_LENGTH_REFUSAL: &str = "a sort key holds 1 to 621 bytes";

	/// The key `sort` within `partition`.
	///
	/// # Panics
	///
	/// - `sort` holds no byte, or more than 621. In a `const` item, the panic
	///   is a compile error.
	pub(crate) const fn from_static(partition: Partition, sort: &'static [u8]) -> Self {
		if sort.is_empty() || sort.len() > Self::MAX_SORT {
			panic!("{}", Self::SORT_LENGTH_REFUSAL);
		}

		Self { partition, sort: Cow::Borrowed(sort) }
	}

	/// The key of the row `key`, in the partition of its table. A row id is
	/// no longer than a sort key.
	pub(crate) fn row(key: &RowKey) -> Self {
		let sort: &[u8] = key.row_id().as_ref();
		let sort = Cow::Owned(sort.to_vec());
		Self { partition: Partition::of(key.frame_type()), sort }
	}

	/// The row key that [`Key::row`] built this key from, or `None` for a key
	/// of no table.
	pub(crate) fn row_key(&self) -> Option<RowKey> {
		let table = self.partition.table?;
		let row_id = RowId::try_from(self.sort()).ok()?;
		RowKey::new(table, row_id).ok()
	}

	/// The key `sort` within `partition`.
	///
	/// # Errors
	///
	/// - [`StoreError::SortKeyLength`] -- `sort` holds no byte, or more than 621.
	#[cfg(test)]
	pub(crate) fn new(partition: Partition, sort: impl Into<Vec<u8>>) -> Result<Self, StoreError> {
		let sort = sort.into();
		if sort.is_empty() || sort.len() > Self::MAX_SORT {
			return Err(StoreError::SortKeyLength(sort.len()));
		}

		Ok(Self { partition, sort: Cow::Owned(sort) })
	}
}

impl fmt::Display for Key {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{} \"{}\"", self.partition, self.sort.escape_ascii())
	}
}

/// The bytes of one value that the core writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvValue(Vec<u8>);

impl KvValue {
	/// The bytes of this value.
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}

	/// The value `bytes`.
	pub(crate) fn new(bytes: impl Into<Vec<u8>>) -> Self {
		Self(bytes.into())
	}
}

/// One value as the backend holds it: its bytes and their revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored {
	bytes: Vec<u8>,
	revision: Revision,
}

impl Stored {
	/// The value `bytes` at the revision `revision`.
	pub fn new(bytes: impl Into<Vec<u8>>, revision: Revision) -> Self {
		Self { bytes: bytes.into(), revision }
	}

	/// The bytes of this value.
	pub fn bytes(&self) -> &[u8] {
		&self.bytes
	}

	/// The revision of this value.
	pub fn revision(&self) -> &Revision {
		&self.revision
	}
}

/// One entry of a scan: its sort key and its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
	sort: Vec<u8>,
	stored: Stored,
}

impl Entry {
	/// The entry of `stored` at the sort key `sort`.
	pub fn new(sort: impl Into<Vec<u8>>, stored: Stored) -> Self {
		Self { sort: sort.into(), stored }
	}

	/// The sort key of this entry within its partition.
	pub fn sort(&self) -> &[u8] {
		&self.sort
	}

	/// The value of this entry.
	pub fn stored(&self) -> &Stored {
		&self.stored
	}
}

/// The sort keys of one partition between two bounds, which a scan reads.
///
/// The lower bound sits at or below the upper bound, and equal bounds include
/// both ends, so an ordered map takes the bounds as they are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRange {
	partition: Partition,
	lower: Bound<Vec<u8>>,
	upper: Bound<Vec<u8>>,
}

#[cfg(any(test, feature = "testing"))]
impl KeyRange {
	/// The sort keys of `partition` from `lower` to `upper`, or `None` when
	/// the bounds admit none: a lower bound above the upper one, or equal
	/// bounds that exclude an end. The core answers such a scan itself.
	pub(crate) fn new(partition: Partition, lower: Bound<Vec<u8>>, upper: Bound<Vec<u8>>) -> Option<Self> {
		let empty = match (&lower, &upper) {
			(Bound::Included(lower), Bound::Included(upper)) => lower > upper,
			(Bound::Included(lower) | Bound::Excluded(lower), Bound::Included(upper) | Bound::Excluded(upper)) => {
				lower >= upper
			}
			_ => false,
		};

		if empty {
			return None;
		}

		Some(Self { partition, lower, upper })
	}

	/// Every sort key of `partition`.
	pub(crate) fn whole(partition: Partition) -> Self {
		Self { partition, lower: Bound::Unbounded, upper: Bound::Unbounded }
	}
}

impl KeyRange {
	/// The partition of this range.
	pub fn partition(&self) -> Partition {
		self.partition
	}

	/// The lower bound of this range.
	pub fn lower(&self) -> Bound<&[u8]> {
		self.lower.as_ref().map(Vec::as_slice)
	}

	/// The upper bound of this range.
	pub fn upper(&self) -> Bound<&[u8]> {
		self.upper.as_ref().map(Vec::as_slice)
	}

	/// Whether `key` falls inside this range: in its partition, between its
	/// bounds.
	pub fn contains(&self, key: &Key) -> bool {
		let bounds = (self.lower(), self.upper());
		key.partition() == self.partition && RangeBounds::<[u8]>::contains(&bounds, key.sort())
	}

	/// Write `bound` as text, its bytes escaped.
	fn write_bound(f: &mut fmt::Formatter<'_>, bound: Bound<&[u8]>) -> fmt::Result {
		match bound {
			Bound::Included(bytes) => write!(f, "\"{}\" included", bytes.escape_ascii()),
			Bound::Excluded(bytes) => write!(f, "\"{}\" excluded", bytes.escape_ascii()),
			Bound::Unbounded => f.write_str("the end"),
		}
	}
}

impl fmt::Display for KeyRange {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{} from ", self.partition)?;
		Self::write_bound(f, self.lower())?;
		f.write_str(" to ")?;
		Self::write_bound(f, self.upper())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_support::panic_message;

	const NORTH: Partition = Partition::from_static("north");
	const SOUTH: Partition = Partition::from_static("south");

	tightbeam::tb_cases! {
		fn a_name_in_the_grammar_is_a_partition(name: &'static str) {
			assert_eq!(Partition::from_static(name).as_bytes(), name.as_bytes());
		}
		cases {
			one_letter => "a",
			slashed => "chain/block/order",
			digits_and_hyphens => "v2-block-9",
			longest => "a2345678901234567890123456789012345678901234567890123456789012345678901234567890",
		}
	}

	tightbeam::tb_cases! {
		fn a_name_outside_the_grammar_panics((name, message): (&'static str, &'static str)) {
			assert_eq!(panic_message(|| Partition::from_static(name)).as_deref(), Some(message));
		}
		cases {
			empty => ("", Partition::LENGTH_REFUSAL),
			too_long => ("a23456789012345678901234567890123456789012345678901234567890123456789012345678901", Partition::LENGTH_REFUSAL),
			leading_digit => ("9block", Partition::FIRST_REFUSAL),
			leading_slash => ("/block", Partition::FIRST_REFUSAL),
			uppercase => ("chain/Block", Partition::BYTE_REFUSAL),
			/// The loop reads the last byte too.
			bad_last_byte => ("block.", Partition::BYTE_REFUSAL),
		}
	}

	/// The hash of `partition`.
	fn hashed(partition: Partition) -> u64 {
		let mut hasher = std::hash::DefaultHasher::new();
		partition.hash(&mut hasher);
		hasher.finish()
	}

	// A partition equals, orders, and hashes by its name alone, whether it
	// names a table or not.
	#[test]
	fn a_partition_is_its_name() {
		const TABLE: FrameType = FrameType::from_static("north");

		let named = Partition::of(TABLE);
		assert_eq!(
			(named, named.cmp(&NORTH), hashed(named)),
			(NORTH, Ordering::Equal, hashed(NORTH))
		);
		assert_ne!(hashed(NORTH), hashed(SOUTH));
		assert!(NORTH < SOUTH);
	}

	// A key of a table turns back into the row key it was built from, and a
	// key of no table turns into none.
	#[test]
	fn a_row_key_round_trips_through_its_key() -> Result<(), StoreError> {
		let row = RowKey::new(FrameType::from_static("north"), RowId::from(*b"leaf"))?;
		assert_eq!(Key::row(&row).row_key(), Some(row));
		assert_eq!(Key::from_static(NORTH, b"leaf").row_key(), None);
		Ok(())
	}

	tightbeam::tb_cases! {
		fn a_sort_key_in_bounds_is_a_key(len: usize) -> Result<(), StoreError> {
			let key = Key::new(NORTH, vec![7u8; len])?;
			assert_eq!(key.sort().len(), len);
			Ok(())
		}
		cases {
			one_byte => 1,
			longest => 621,
		}
	}

	tightbeam::tb_cases! {
		fn a_sort_key_out_of_bounds_is_refused(len: usize) {
			let refused = Key::new(NORTH, vec![7u8; len]);
			assert!(matches!(refused, Err(StoreError::SortKeyLength(found)) if found == len));
		}
		cases {
			empty => 0,
			one_past_the_longest => 622,
		}
	}

	tightbeam::tb_cases! {
		fn a_static_sort_key_out_of_bounds_panics(sort: &'static [u8]) {
			assert_eq!(panic_message(|| Key::from_static(NORTH, sort)).as_deref(), Some(Key::SORT_LENGTH_REFUSAL));
		}
		cases {
			empty => b"",
			one_past_the_longest => &[7u8; 622],
		}
	}

	tightbeam::tb_cases! {
		fn bounds_that_admit_no_key_are_no_range((lower, upper): (Bound<Vec<u8>>, Bound<Vec<u8>>)) {
			assert_eq!(KeyRange::new(NORTH, lower, upper), None);
		}
		cases {
			inverted => (Bound::Included(vec![0x02]), Bound::Included(vec![0x01])),
			inverted_and_excluded => (Bound::Excluded(vec![0x02]), Bound::Excluded(vec![0x01])),
			equal_and_excluded => (Bound::Excluded(vec![0x01]), Bound::Excluded(vec![0x01])),
			equal_with_an_excluded_lower => (Bound::Excluded(vec![0x01]), Bound::Included(vec![0x01])),
			equal_with_an_excluded_upper => (Bound::Included(vec![0x01]), Bound::Excluded(vec![0x01])),
		}
	}

	tightbeam::tb_cases! {
		fn bounds_that_admit_a_key_are_a_range((lower, upper): (Bound<Vec<u8>>, Bound<Vec<u8>>)) {
			let range = KeyRange::new(NORTH, lower.clone(), upper.clone());
			let bounds = range.as_ref().map(|range| (range.lower().map(<[u8]>::to_vec), range.upper().map(<[u8]>::to_vec)));
			assert_eq!(bounds, Some((lower, upper)));
		}
		cases {
			one_key => (Bound::Included(vec![0x01]), Bound::Included(vec![0x01])),
			adjacent => (Bound::Excluded(vec![0x01]), Bound::Excluded(vec![0x01, 0x00])),
			open_above => (Bound::Excluded(vec![0x01]), Bound::Unbounded),
			open_below => (Bound::Unbounded, Bound::Excluded(vec![0x01])),
		}
	}

	tightbeam::tb_cases! {
		fn a_range_contains_the_keys_of_its_partition_between_its_bounds((key, inside): (Key, bool)) {
			let range = KeyRange::new(NORTH, Bound::Included(vec![0x10]), Bound::Excluded(vec![0x20]));
			assert_eq!(range.map(|range| range.contains(&key)), Some(inside));
		}
		cases {
			at_the_lower_bound => (Key::from_static(NORTH, &[0x10]), true),
			inside => (Key::from_static(NORTH, &[0x1f, 0xff]), true),
			at_the_upper_bound => (Key::from_static(NORTH, &[0x20]), false),
			below => (Key::from_static(NORTH, &[0x0f]), false),
			in_another_partition => (Key::from_static(SOUTH, &[0x10]), false),
		}
	}

	tightbeam::tb_cases! {
		fn a_range_displays_its_partition_and_bounds((lower, upper, text): (Bound<Vec<u8>>, Bound<Vec<u8>>, &'static str)) {
			let range = KeyRange::new(NORTH, lower, upper).map(|range| range.to_string());
			assert_eq!(range.as_deref(), Some(text));
		}
		cases {
			whole => (Bound::Unbounded, Bound::Unbounded, "north from the end to the end"),
			included_and_excluded => (
				Bound::Included(b"a".to_vec()),
				Bound::Excluded(b"z\x00".to_vec()),
				"north from \"a\" included to \"z\\x00\" excluded",
			),
		}
	}

	#[test]
	fn a_key_displays_its_partition_and_escaped_sort() {
		let key = Key::from_static(NORTH, b"leaf\x00");
		assert_eq!(key.to_string(), "north \"leaf\\x00\"");
	}
}
