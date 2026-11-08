#![doc = include_str!("../README.md")]

// This module compiles every Rust example of the page under `docs/` that
// specifies this crate as a doctest, so a renamed item fails the build
// instead of leaving the page stale.
#[cfg(doctest)]
#[doc = include_str!("../../../docs/ws.md")]
mod docs_ws {}

#[cfg(feature = "testing")]
pub mod testing;

#[cfg(feature = "socket")]
pub mod io;
#[cfg(feature = "socket")]
pub mod protocol;
#[cfg(feature = "serve")]
pub mod serve;

#[cfg(feature = "socket")]
mod acceptor;
#[cfg(feature = "socket")]
mod error;

#[cfg(feature = "socket")]
pub use error::{Error, Result};

/// Re-export of the underlying messaging framework.
pub use tightbeam;
