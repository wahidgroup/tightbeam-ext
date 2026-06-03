//! WebSocket transport for the [tightbeam](https://docs.rs/tightbeam-rs)
//! messaging protocol.

#[cfg(feature = "fixtures")]
pub mod fixtures;
pub mod io;
pub mod protocol;

mod error;

pub use error::{Error, Result};

/// Re-export of the underlying messaging framework.
pub use tightbeam;
