//! Browser (WebAssembly) WebSocket client for tightbeam.

pub mod build;
pub mod envelope;
mod error;

pub use error::{Error, Result};

#[cfg(target_arch = "wasm32")]
mod bindings;
#[cfg(target_arch = "wasm32")]
mod client;
#[cfg(target_arch = "wasm32")]
mod secure;
#[cfg(target_arch = "wasm32")]
pub mod stream;

#[cfg(target_arch = "wasm32")]
pub use client::WsClient;
#[cfg(target_arch = "wasm32")]
pub use secure::SecureWsClient;
#[cfg(target_arch = "wasm32")]
pub use stream::{GlooStream, WsTransport};
