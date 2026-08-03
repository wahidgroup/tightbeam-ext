//! HoneyBadgerMPC network adapter over the tightbeam messaging protocol.
//!
//! Implements the [`stoffelnet`] `Network` abstraction on a full mesh of
//! pairwise tightbeam links: mutually-authenticated ECIES sessions with
//! HTTP/2-style stream multiplexing, one TCP connection per party pair.
//!
//! # Topology
//!
//! Party `i` binds the listener named by its roster entry and dials every
//! party `j > i`, so exactly one link exists per pair. Certificates are
//! the identity anchor: the handshake proves possession of a roster
//! certificate's key, and every inbound frame is attributed to the party
//! that certificate belongs to. No identity claim travels inside frames.
//!
//! # Consumers
//!
//! MPC clients (input providers and output receivers) are not mesh
//! members. The roster authorizes them through
//! [`Roster::with_clients`]; a [`TightbeamClient`] then dials every
//! party, and the party-side `send_to_client` rides those same links
//! back. Client ids live outside the party id space, so one inbox
//! carries both kinds of traffic unambiguously.
//!
//! # Usage
//!
//! Build a [`Roster`] naming every party's id, listen address, and
//! certificate; wrap the local credentials in a [`LocalIdentity`]; then
//! [`TightbeamNetwork::establish`]. Hand the network (as `Arc`) to the
//! HoneyBadgerMPC engine and drive a message loop over
//! [`TightbeamNetwork::take_inbox`], feeding each `(sender, bytes)`
//! delivery into the engine's `process`.
//!
//! # Lanes
//!
//! Every frame names a lane: engine traffic feeds the MPC node, while
//! the control lane (program submission, digest exchange, reveal
//! shares) surfaces separately through `take_control_inbox` /
//! `send_control`, so layered protocols never sniff engine payloads.
//!
//! # Tracing
//!
//! Components record lifecycle events through an injected
//! [`TraceHandle`] (upstream tightbeam's collector under a shareable
//! wrapper): the mesh traces link lifecycle through
//! [`MeshConfig::trace`], and sessions trace their round transitions
//! through `PartySession::with_trace`. Verification runs check the
//! recorded stream against assertion specs and CSP process models, so
//! the specs bind to live execution rather than replayed transcripts.

mod client;
pub mod error;
mod frame;
mod mesh;
mod network;
mod roster;
mod trace;

#[cfg(feature = "session")]
pub mod session;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use client::TightbeamClient;
pub use error::{Error, Result, RosterError};
pub use frame::Lane;
pub use mesh::{Delivery, MeshConfig};
pub use network::TightbeamNetwork;
pub use roster::{ClientEntry, LocalIdentity, PartyEntry, Roster, TbNode};
pub use trace::{events, TraceEvent, TraceHandle};

#[cfg(feature = "session")]
pub use session::{ClientSession, PartySession, Round, SessionError};
