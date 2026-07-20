//! Test-support code for the encrypted WebSocket end-to-end stack.
//!
//! Compiled only under the `testing` feature.

mod fixtures;

pub use fixtures::{Identity, SIGNING_KEY_LEN};
