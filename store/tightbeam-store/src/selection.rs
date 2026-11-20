//! The order of a read: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#the-kv-port).

/// The order a read walks its keys in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
	/// The smallest key first.
	Ascending,
	/// The largest key first.
	Descending,
}
