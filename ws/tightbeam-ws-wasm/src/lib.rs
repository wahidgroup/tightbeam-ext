//! The WebAssembly engine of the tightbeam WebSocket client, which
//! `docs/ws-wasm.md` specifies.

pub mod build;
pub mod compress;
mod fault;
mod goaway;
mod metadata;

#[cfg(target_arch = "wasm32")]
mod approver;
#[cfg(target_arch = "wasm32")]
mod bindings;
#[cfg(target_arch = "wasm32")]
pub mod clock;
#[cfg(target_arch = "wasm32")]
mod dial;
#[cfg(all(test, target_arch = "wasm32"))]
mod loopback;
#[cfg(target_arch = "wasm32")]
mod mux;
#[cfg(target_arch = "wasm32")]
mod profile;
#[cfg(target_arch = "wasm32")]
mod promise;
#[cfg(target_arch = "wasm32")]
pub mod protocol;
#[cfg(target_arch = "wasm32")]
mod signer;
#[cfg(target_arch = "wasm32")]
mod socket;
#[cfg(target_arch = "wasm32")]
pub mod stream;
#[cfg(target_arch = "wasm32")]
mod streaming;

#[cfg(target_arch = "wasm32")]
pub use fault::JsFault;
#[cfg(target_arch = "wasm32")]
pub use mux::{BrowserMux, MuxTasks, MuxWsClient, SessionParts};
#[cfg(target_arch = "wasm32")]
pub use signer::{JsSigningKeyProvider, TransportSigner};
#[cfg(target_arch = "wasm32")]
pub use stream::{GlooStream, WsTransport};
#[cfg(target_arch = "wasm32")]
pub use streaming::{MuxDuplexStream, MuxReplySink, MuxRequestStream, MuxStreamBody};
