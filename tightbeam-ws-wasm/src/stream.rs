//! Browser WebSocket stream adapting `gloo-net` to tightbeam's
//! [`AsyncProtocolStream`]. Compiled only for `wasm32` targets.
//!
//! Each DER-encoded tightbeam envelope travels as a single WebSocket message.

use futures_util::{SinkExt, StreamExt};
use gloo_net::websocket::futures::WebSocket;
use gloo_net::websocket::{Message, WebSocketError};

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::transport::{AsyncProtocolStream, TcpTransport, TransportError};

/// A browser WebSocket carrying tightbeam frames, one DER envelope per message.
pub struct GlooStream {
	inner: WebSocket,
}

impl GlooStream {
	/// Drive tightbeam's transport-agnostic transport over this WebSocket.
	pub fn into_transport(self) -> WsTransport {
		TcpTransport::from(self)
	}
}

impl From<WebSocket> for GlooStream {
	fn from(inner: WebSocket) -> Self {
		Self { inner }
	}
}

/// tightbeam's transport-agnostic transport instantiated over a browser
/// WebSocket. Parameterised by the crypto provider `P` so encrypted clients
/// can utilize their own provider.
pub type WsTransport<P = DefaultCryptoProvider> = TcpTransport<GlooStream, P>;

/// Map a `gloo` WebSocket error onto the transport-agnostic [`TransportError`].
fn map_ws_error(error: WebSocketError) -> TransportError {
	match error {
		WebSocketError::ConnectionClose(_) => TransportError::ConnectionClosed,
		_ => TransportError::InvalidMessage,
	}
}

impl AsyncProtocolStream for GlooStream {
	type Error = TransportError;

	async fn read_frame(&mut self, max_len: Option<usize>) -> Result<Vec<u8>, Self::Error> {
		loop {
			match self.inner.next().await {
				None => return Err(TransportError::ConnectionClosed),
				Some(Err(error)) => return Err(map_ws_error(error)),
				Some(Ok(Message::Bytes(payload))) => {
					if let Some(max) = max_len {
						if payload.len() > max {
							return Err(TransportError::InvalidMessage);
						}
					}

					return Ok(payload);
				}

				Some(Ok(Message::Text(_))) => continue,
			}
		}
	}

	async fn write_frame(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		self.inner.send(Message::Bytes(buffer.to_vec())).await.map_err(map_ws_error)
	}

	fn is_alive(&self) -> bool {
		// `gloo` exposes no cheap, non-blocking liveness probe.
		// Closure surfaces on the next read as `ConnectionClosed`.
		true
	}
}
