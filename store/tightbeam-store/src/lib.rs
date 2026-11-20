#![doc = include_str!("../README.md")]

// Each Rust sample of docs/store.md compiles as a doctest of this crate.
#[cfg(doctest)]
#[doc = include_str!("../../../docs/store.md")]
mod docs_store {}

mod catalog;
mod driver;
mod error;
mod frame_type;
mod kv;
mod memory;
mod owner;
mod row_id;
mod row_key;
mod scope;
mod selection;
mod storable;
mod urn_spec;

#[cfg(test)]
mod test_support;
#[cfg(feature = "testing")]
pub mod testing;

pub use catalog::{Catalog, Holds, Tables};
pub use driver::{
	CommitOutcome, ConfirmOutcome, DriverError, DriverFuture, InsertOutcome, RemoveOutcome, Revision, SwapOutcome,
};
pub use error::StoreError;
pub use frame_type::FrameType;
pub use kv::{Entry, Key, KeyRange, KvValue, OrderedKv, OrderedKvTxn, Partition, Stored, TxnFuture};
pub use memory::MemoryKv;
pub use owner::Owner;
pub use row_id::RowId;
pub use row_key::RowKey;
pub use scope::Scope;
pub use selection::Direction;
pub use storable::Storable;
pub use tightbeam_store_derive::{Catalog, Storable};

#[doc(inline)]
pub use tightbeam::marker::{MaybeSend, MaybeSendFuture, MaybeSync};
