//! Browser (WebAssembly) WebSocket client for tightbeam.
//!
//! Multiplexed sessions only: the WebSocket profile of tightbeam always
//! negotiates stream multiplexing, so one connection carries concurrent,
//! bidirectional streams.

pub mod build;

#[cfg(target_arch = "wasm32")]
mod approver;
#[cfg(target_arch = "wasm32")]
mod bindings;
#[cfg(target_arch = "wasm32")]
mod fault;
#[cfg(target_arch = "wasm32")]
mod mux;
#[cfg(target_arch = "wasm32")]
mod promise;
#[cfg(target_arch = "wasm32")]
mod secure;
#[cfg(target_arch = "wasm32")]
mod signer;
#[cfg(target_arch = "wasm32")]
mod socket;
#[cfg(target_arch = "wasm32")]
pub mod stream;
#[cfg(target_arch = "wasm32")]
mod streaming;

#[cfg(target_arch = "wasm32")]
pub use mux::{split_mux, MuxWsClient};
#[cfg(target_arch = "wasm32")]
pub use secure::{build_transport_with, profile_trust_store, ClientCredentials};
#[cfg(target_arch = "wasm32")]
pub use signer::{JsSigningKeyProvider, TransportSigner};
#[cfg(target_arch = "wasm32")]
pub use stream::{GlooStream, WsTransport};
#[cfg(target_arch = "wasm32")]
pub use streaming::{MuxDuplexStream, MuxReplySink, MuxRequestStream, MuxStreamBody};
