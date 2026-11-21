#![doc = include_str!("../README.md")]

// Each Rust sample of docs/store.md compiles as a doctest of this crate.
#[cfg(doctest)]
#[doc = include_str!("../../../docs/store.md")]
mod docs_store {}

mod catalog;
mod driver;
mod error;
mod frame_type;
mod indexed;
mod kv;
mod memory;
mod owner;
mod row_id;
mod row_key;
mod schema;
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
	CommitOutcome, ConfirmOutcome, Driver, DriverError, DriverFuture, DriverTxn, InsertOutcome, Prepared,
	RemoveOutcome, Revision, Row, RowTxnFuture, SwapOutcome,
};
pub use error::StoreError;
pub use frame_type::FrameType;
pub use indexed::Indexed;
pub use kv::{Entry, Key, KeyRange, KvValue, OrderedKv, OrderedKvTxn, Partition, Stored, TxnFuture};
pub use memory::{MemoryDriver, MemoryKv};
pub use owner::Owner;
pub use row_id::RowId;
pub use row_key::RowKey;
pub use schema::{Cardinality, Field, FieldKind, FieldValue, Projection, Protection, RecipientKey, Role, Schema};
pub use scope::Scope;
pub use selection::Direction;
pub use storable::Storable;
pub use tightbeam_store_derive::{Catalog, Storable};

#[doc(inline)]
pub use tightbeam::marker::{MaybeSend, MaybeSendFuture, MaybeSync};
