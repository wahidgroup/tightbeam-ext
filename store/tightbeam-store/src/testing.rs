//! The contract suites of the store ports, which a driver runs in its own
//! tests: [docs/store.md](https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#check-a-kv-driver).

mod conformance;

pub use self::conformance::{FreshKv, KvBreach, KvClause, KvConformance};
