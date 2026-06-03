//! Error type for the browser WebSocket client.

use core::fmt;

/// Errors surfaced by the wasm client.
#[derive(Debug)]
pub enum Error {
	/// DER encode/decode failure on a tightbeam envelope or frame.
	Codec(tightbeam::der::Error),
	/// A decoded envelope was not the cleartext response the client expected.
	UnexpectedEnvelope,
	/// The peer closed the connection before a response arrived.
	ConnectionClosed,
	/// The underlying browser WebSocket reported an error.
	#[cfg(target_arch = "wasm32")]
	WebSocket(gloo_net::websocket::WebSocketError),
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Codec(error) => write!(f, "tightbeam DER codec error: {error}"),
			Self::UnexpectedEnvelope => f.write_str("expected a cleartext response envelope"),
			Self::ConnectionClosed => f.write_str("websocket closed before a response arrived"),
			#[cfg(target_arch = "wasm32")]
			Self::WebSocket(error) => write!(f, "websocket transport error: {error}"),
		}
	}
}

impl core::error::Error for Error {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			Self::Codec(error) => Some(error),
			#[cfg(target_arch = "wasm32")]
			Self::WebSocket(error) => Some(error),
			_ => None,
		}
	}
}

impl From<tightbeam::der::Error> for Error {
	fn from(error: tightbeam::der::Error) -> Self {
		Self::Codec(error)
	}
}

#[cfg(target_arch = "wasm32")]
impl From<gloo_net::websocket::WebSocketError> for Error {
	fn from(error: gloo_net::websocket::WebSocketError) -> Self {
		Self::WebSocket(error)
	}
}

/// Convenience result alias for the wasm client.
pub type Result<T> = core::result::Result<T, Error>;
