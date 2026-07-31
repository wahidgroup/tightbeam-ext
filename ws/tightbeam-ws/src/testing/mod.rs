//! Test-support code for the encrypted WebSocket end-to-end stack.
//!
//! Compiled only under the `testing` feature.

mod fixtures;
mod handshake;
mod mux;
mod paywall;

pub use fixtures::{Identity, SIGNING_KEY_LEN};
pub use handshake::{pinned_trust, serve_handshake};
pub use mux::{echo_duplex, echo_stream, echo_streaming, env_u32, EchoFrames, CALL_ME};
pub use paywall::{
	budget_ceiling, paywall_enabled, DemoPaywall, FixedWallet, DEMO_BUDGET_CREDITS, DEMO_INVOICE, DEMO_INVOICE_REFUSAL,
	DEMO_PAYMENT, DEMO_WALLET_EMPTY,
};
