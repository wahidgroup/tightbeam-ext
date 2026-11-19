#![doc = include_str!("../README.md")]

// Each Rust sample of docs/store.md compiles as a doctest of this crate.
#[cfg(doctest)]
#[doc = include_str!("../../../docs/store.md")]
mod docs_store {}

mod catalog;
mod error;
mod frame_type;
mod owner;
mod row_id;
mod row_key;
mod storable;
mod urn_spec;

pub use catalog::{Catalog, Holds, Tables};
pub use error::StoreError;
pub use frame_type::FrameType;
pub use owner::Owner;
pub use row_id::RowId;
pub use row_key::RowKey;
pub use storable::Storable;
pub use tightbeam_store_derive::{Catalog, Storable};
