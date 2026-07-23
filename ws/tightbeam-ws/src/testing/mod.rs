//! Test-support code for the encrypted WebSocket end-to-end stack.
//!
//! Compiled only under the `testing` feature.

mod fixtures;
mod mux;

pub use fixtures::{Identity, SIGNING_KEY_LEN};
pub use mux::{echo_stream, env_u32, CALL_ME};
