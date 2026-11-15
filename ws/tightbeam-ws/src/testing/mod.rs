//! Test support for the e2e stack and the shared suites, as `docs/ws.md`
//! (Test support) states it.

mod demo;
mod echo;
mod env;
mod error;
mod fixtures;
mod handshake;
mod mux;
mod outcome;
mod paywall;
mod service;
pub mod specs;
mod watch;

#[cfg(feature = "colony")]
mod colony;

pub use demo::{DemoConfig, PeerIdentity, Security};
pub use echo::{EchoService, PoolEchoes};
pub use env::{EnvError, EnvVar};
pub use error::{Error, Result};
pub use fixtures::{Identity, IdentityFiles, IdentityFilesError, SIGNING_KEY_LEN};
pub use handshake::Pinned;
pub use mux::{EchoBody, UnknownBody};
pub use outcome::ReadOutcome;
pub use paywall::{DemoPaywall, DemoSettlement};
pub use watch::EventWatch;

#[cfg(feature = "colony")]
pub use colony::{WorkBody, WorkClient, WorkGateway, WorkPlane, WorkProbe, WorkProbeHive, WorkProbeServlet, WorkStack};
