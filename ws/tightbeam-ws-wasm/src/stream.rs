//! Browser WebSocket stream adapting `gloo-net` to tightbeam's
//! [`AsyncProtocolStream`]. Compiled only for `wasm32` targets.
//!
//! Each DER-encoded tightbeam envelope travels as a single WebSocket message.
//! [`GlooStream`] also splits into exclusive halves ([`SplittableStream`]) so
//! a multiplexed connection can read and write concurrently.

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use gloo_net::websocket::futures::WebSocket;
use gloo_net::websocket::{Message, WebSocketError};

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::transport::{
	AsyncProtocolStream, AsyncReadStream, AsyncWriteStream, SplittableStream, TcpTransport, TransportError,
};

/// A browser WebSocket carrying tightbeam frames, one DER envelope per message.
pub struct GlooStream {
	inner: WebSocket,
	/// Cleared when a read or write observes a closed peer.
	alive: bool,
}

impl GlooStream {
	/// Drive tightbeam's transport-agnostic transport over this WebSocket.
	pub fn into_transport(self) -> WsTransport {
		TcpTransport::from(self)
	}

	fn mark_dead_on_closed(&mut self, error: &TransportError) {
		if matches!(error, TransportError::ConnectionClosed) {
			self.alive = false;
		}
	}
}

impl From<WebSocket> for GlooStream {
	fn from(inner: WebSocket) -> Self {
		Self { inner, alive: true }
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

/// Await the next binary message, skipping interleaved text frames and
/// enforcing the caller's envelope size ceiling.
async fn read_binary_frame<S>(source: &mut S, max_len: Option<usize>) -> Result<Vec<u8>, TransportError>
where
	S: Stream<Item = Result<Message, WebSocketError>> + Unpin,
{
	loop {
		match source.next().await {
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

/// Send one DER envelope as a single binary WebSocket message.
async fn write_binary_frame<S>(sink: &mut S, buffer: &[u8]) -> Result<(), TransportError>
where
	S: Sink<Message, Error = WebSocketError> + Unpin,
{
	let message = Message::Bytes(buffer.to_vec());
	sink.send(message).await.map_err(map_ws_error)
}

impl AsyncProtocolStream for GlooStream {
	type Error = TransportError;

	async fn read_frame(&mut self, max_len: Option<usize>) -> Result<Vec<u8>, Self::Error> {
		match read_binary_frame(&mut self.inner, max_len).await {
			Ok(frame) => Ok(frame),
			Err(error) => {
				self.mark_dead_on_closed(&error);
				Err(error)
			}
		}
	}

	async fn write_frame(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		match write_binary_frame(&mut self.inner, buffer).await {
			Ok(()) => Ok(()),
			Err(error) => {
				self.mark_dead_on_closed(&error);
				Err(error)
			}
		}
	}

	fn is_alive(&self) -> bool {
		// gloo has no non-blocking probe. Track observed closure from
		// prior frame I/O so pooling can skip already-dead sockets.
		self.alive
	}
}

/// Exclusive read half of a split browser WebSocket.
pub struct GlooReadHalf {
	inner: SplitStream<WebSocket>,
}

impl AsyncReadStream for GlooReadHalf {
	type Error = TransportError;

	async fn read_frame(&mut self, max_len: Option<usize>) -> Result<Vec<u8>, Self::Error> {
		read_binary_frame(&mut self.inner, max_len).await
	}
}

/// Exclusive write half of a split browser WebSocket.
pub struct GlooWriteHalf {
	inner: SplitSink<WebSocket, Message>,
}

impl AsyncWriteStream for GlooWriteHalf {
	type Error = TransportError;

	async fn write_frame(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		write_binary_frame(&mut self.inner, buffer).await
	}
}

impl SplittableStream for GlooStream {
	type ReadHalf = GlooReadHalf;
	type WriteHalf = GlooWriteHalf;

	fn into_split(self) -> (Self::ReadHalf, Self::WriteHalf) {
		let (sink, stream) = self.inner.split();
		let read_half = GlooReadHalf { inner: stream };
		let write_half = GlooWriteHalf { inner: sink };

		(read_half, write_half)
	}
}
