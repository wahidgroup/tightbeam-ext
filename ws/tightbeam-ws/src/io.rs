//! WebSocket message I/O for tightbeam.
//!
//! [`WsStream`] adapts a `tokio-tungstenite` WebSocket to tightbeam's
//! transport-agnostic [`AsyncProtocolStream`] trait: each DER-encoded tightbeam
//! envelope is carried as a single WebSocket frame. Plugs into
//! tightbeam's generic transport yields [`WsTransport`].

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::{Bytes, Error as WsError, Message};
use tokio_tungstenite::WebSocketStream;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::transport::{AsyncProtocolStream, TcpTransport, TransportError};

/// A bidirectional WebSocket carrying tightbeam frames.
pub struct WsStream<S> {
	inner: WebSocketStream<S>,
}

impl<S> WsStream<S> {
	/// Wrap an already-upgraded WebSocket stream.
	pub fn new(inner: WebSocketStream<S>) -> Self {
		Self { inner }
	}
}

/// A tightbeam transport whose framing is provided by a WebSocket connection.
pub type WsTransport<S, P = DefaultCryptoProvider> = TcpTransport<WsStream<S>, P>;

/// Map a tungstenite error onto the transport-agnostic [`TransportError`].
pub(crate) fn map_ws_error(error: WsError) -> TransportError {
	match error {
		WsError::ConnectionClosed | WsError::AlreadyClosed => TransportError::ConnectionClosed,
		WsError::Io(io) => TransportError::IoError(io),
		_ => TransportError::InvalidMessage,
	}
}

impl<S> AsyncProtocolStream for WsStream<S>
where
	S: AsyncRead + AsyncWrite + Unpin + Send,
{
	type Error = TransportError;

	async fn read_frame(&mut self, max_len: Option<usize>) -> Result<Vec<u8>, Self::Error> {
		loop {
			match self.inner.next().await {
				None => return Err(TransportError::ConnectionClosed),
				Some(Err(error)) => return Err(map_ws_error(error)),
				Some(Ok(Message::Binary(payload))) => {
					if let Some(max) = max_len {
						if payload.len() > max {
							return Err(TransportError::InvalidMessage);
						}
					}

					return Ok(payload.into());
				}
				Some(Ok(Message::Close(_))) => return Err(TransportError::ConnectionClosed),
				// Text and control frames are not part of the tightbeam wire
				// format; skip them and await the next binary envelope.
				Some(Ok(_)) => continue,
			}
		}
	}

	async fn write_frame(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		let bytes = Bytes::copy_from_slice(buffer);
		let message = Message::Binary(bytes);

		self.inner.send(message).await.map_err(map_ws_error)
	}

	fn is_alive(&self) -> bool {
		// tungstenite exposes no cheap, non-blocking liveness probe
		true
	}
}
