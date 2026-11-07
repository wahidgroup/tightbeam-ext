//! Test-support code for the encrypted WebSocket end-to-end stack.
//!
//! Compiled only under the `testing` feature.

#[cfg(feature = "colony")]
mod colony;
mod demo;
mod env;
mod fixtures;
mod handshake;
mod mux;
mod paywall;

pub use demo::{DemoConfig, Security};
pub use env::{EnvError, EnvVar};
pub use fixtures::{Identity, IdentityFiles, SIGNING_KEY_LEN};
pub use handshake::Pinned;
pub use mux::{EchoBody, EchoCommand, UnknownBody};
pub use paywall::{DemoPaywall, FixedWallet, DEMO_INVOICE_REFUSAL, DEMO_WALLET_EMPTY};
