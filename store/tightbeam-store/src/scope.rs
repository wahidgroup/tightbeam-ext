//! Which processes reach the values of a backend: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#the-kv-port).

/// Which processes reach the values of a backend. Whether the values last
/// is a separate promise of each driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
	/// This process alone, such as a backend in its memory or a file it holds
	/// open.
	Process,
	/// Other processes too, such as through a database server.
	Shared,
}
