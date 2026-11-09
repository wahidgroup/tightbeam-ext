//! Test support for the WebSocket end-to-end stack, and the shared suites
//! that every transport of the repository runs against itself.
//!
//! Compiled only under the `testing` feature.

#[cfg(feature = "colony")]
mod colony;
mod demo;
mod echo;
mod env;
mod fixtures;
mod handshake;
mod mux;
mod outcome;
mod paywall;
pub mod specs;

#[cfg(feature = "colony")]
pub use colony::{WorkBody, WorkClient, WorkPlane, WorkProbeHive, WorkProbeServlet, WorkStack};
pub use demo::{DemoConfig, PeerIdentity, Security};
pub use echo::{EchoService, PoolEchoes};
pub use env::{EnvError, EnvVar};
pub use fixtures::{Identity, IdentityFiles, SIGNING_KEY_LEN};
pub use handshake::Pinned;
pub use mux::{EchoBody, EchoCommand, UnknownBody};
pub use outcome::ReadOutcome;
pub use paywall::{DemoPaywall, FixedWallet, DEMO_INVOICE_REFUSAL, DEMO_WALLET_EMPTY};
