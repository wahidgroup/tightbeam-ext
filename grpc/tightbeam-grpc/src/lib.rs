#![doc = include_str!("../README.md")]

// This module compiles every Rust example of the page under `docs/` that
// specifies this crate as a doctest, so a renamed item fails the build
// instead of leaving the page stale.
#[cfg(doctest)]
#[doc = include_str!("../../../docs/grpc.md")]
mod docs_grpc {}

pub mod edge;
pub mod events;
pub mod io;
pub mod protocol;

#[cfg(feature = "couple")]
pub mod couple;
#[cfg(feature = "testing")]
pub mod testing;

mod health;
mod incoming;
mod service;
mod tunnel;

/// Re-export of the underlying messaging framework.
pub use tightbeam;
