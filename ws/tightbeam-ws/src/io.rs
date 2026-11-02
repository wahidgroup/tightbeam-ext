//! WebSocket message I/O for tightbeam.
//!
//! [`WsStream`] adapts a `tokio-tungstenite` WebSocket to tightbeam's
//! transport-agnostic [`AsyncProtocolStream`] trait: each DER-encoded tightbeam
//! envelope is carried as a single WebSocket frame. Plugs into
//! tightbeam's generic transport yields [`WsTransport`]. [`WsStream`] also
//! splits into exclusive halves ([`SplittableStream`]) so a multiplexed
//! connection can read and write concurrently.

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Bytes, Error as WsError, Message};
use tokio_tungstenite::WebSocketStream;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::transport::{
	AsyncProtocolStream, AsyncReadStream, AsyncWriteStream, SplittableStream, TcpTransport, TransportError,
	TransportFailure, TransportLimits,
};

/// A bidirectional WebSocket carrying tightbeam frames.
pub struct WsStream<S> {
	inner: WebSocketStream<S>,
	/// Cleared when a read or write observes a closed peer.
	alive: bool,
}

impl<S> WsStream<S> {
	/// Wrap an already-upgraded WebSocket stream.
	pub fn new(inner: WebSocketStream<S>) -> Self {
		Self { inner, alive: true }
	}

	/// A stream that met end of stream or any error reads as dead, as
	/// [`AsyncProtocolStream::is_alive`] requires.
	fn settle<T>(&mut self, outcome: Result<T, TransportError>) -> Result<T, TransportError> {
		if outcome.is_err() {
			self.alive = false;
		}

		outcome
	}
}

/// A tightbeam transport whose framing is provided by a WebSocket connection.
pub type WsTransport<S, P = DefaultCryptoProvider> = TcpTransport<WsStream<S>, P>;

/// The WebSocket configuration that holds a peer to the ceilings of `limits`.
///
/// Tungstenite refuses a frame by its declared length before it sizes a
/// buffer, which [`AsyncProtocolStream::read_frame`] requires of a stream.
/// The reader knows the wire mode only once it holds the bytes, so the socket
/// admits the larger ceiling, and each read narrows it to `cap`.
pub(crate) fn bounded_config(limits: &TransportLimits) -> WebSocketConfig {
	let ceiling = Some(limits.max_envelope());
	WebSocketConfig::default().max_message_size(ceiling).max_frame_size(ceiling)
}

/// Map a tungstenite error onto the transport-agnostic [`TransportError`].
pub(crate) fn map_ws_error(error: WsError) -> TransportError {
	match error {
		WsError::ConnectionClosed | WsError::AlreadyClosed => TransportError::ConnectionClosed,
		WsError::Io(io) => TransportError::IoError(io),
		WsError::Capacity(_) => TransportError::OperationFailed(TransportFailure::SizeExceeded),
		_ => TransportError::InvalidMessage,
	}
}

/// Await the next binary message, skipping text and control frames and
/// enforcing the caller's envelope size ceiling.
async fn read_binary_frame<S>(source: &mut S, cap: usize) -> Result<Vec<u8>, TransportError>
where
	S: Stream<Item = Result<Message, WsError>> + Unpin,
{
	loop {
		match source.next().await {
			None => return Err(TransportError::ConnectionClosed),
			Some(Err(error)) => return Err(map_ws_error(error)),
			Some(Ok(Message::Binary(payload))) => {
				if payload.len() > cap {
					return Err(TransportError::OperationFailed(TransportFailure::SizeExceeded));
				}

				return Ok(payload.into());
			}
			Some(Ok(Message::Close(_))) => return Err(TransportError::ConnectionClosed),
			// Text and control frames are not part of the tightbeam wire
			// format. Skip them and await the next binary envelope.
			Some(Ok(_)) => continue,
		}
	}
}

/// Send one DER envelope as a single binary WebSocket message.
async fn write_binary_frame<S>(sink: &mut S, buffer: &[u8]) -> Result<(), TransportError>
where
	S: Sink<Message, Error = WsError> + Unpin,
{
	let bytes = Bytes::copy_from_slice(buffer);
	let message = Message::Binary(bytes);

	sink.send(message).await.map_err(map_ws_error)
}

impl<S> AsyncProtocolStream for WsStream<S>
where
	S: AsyncRead + AsyncWrite + Unpin + Send,
{
	type Error = TransportError;

	async fn read_frame(&mut self, cap: usize) -> Result<Vec<u8>, Self::Error> {
		let outcome = read_binary_frame(&mut self.inner, cap).await;
		self.settle(outcome)
	}

	async fn write_frame(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		let outcome = write_binary_frame(&mut self.inner, buffer).await;
		self.settle(outcome)
	}

	fn is_alive(&self) -> bool {
		// Tungstenite has no non-blocking probe. Track observed closure
		// from prior frame I/O so pooling can skip already-dead sockets.
		self.alive
	}
}

/// Exclusive read half of a split WebSocket stream.
pub struct WsReadHalf<S> {
	inner: SplitStream<WebSocketStream<S>>,
}

impl<S> AsyncReadStream for WsReadHalf<S>
where
	S: AsyncRead + AsyncWrite + Unpin + Send,
{
	type Error = TransportError;

	async fn read_frame(&mut self, cap: usize) -> Result<Vec<u8>, Self::Error> {
		read_binary_frame(&mut self.inner, cap).await
	}
}

/// Exclusive write half of a split WebSocket stream.
pub struct WsWriteHalf<S> {
	inner: SplitSink<WebSocketStream<S>, Message>,
}

impl<S> AsyncWriteStream for WsWriteHalf<S>
where
	S: AsyncRead + AsyncWrite + Unpin + Send,
{
	type Error = TransportError;

	async fn write_frame(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		write_binary_frame(&mut self.inner, buffer).await
	}
}

impl<S> SplittableStream for WsStream<S>
where
	S: AsyncRead + AsyncWrite + Unpin + Send,
{
	type ReadHalf = WsReadHalf<S>;
	type WriteHalf = WsWriteHalf<S>;

	fn into_split(self) -> (Self::ReadHalf, Self::WriteHalf) {
		let (sink, stream) = self.inner.split();

		let read_half = WsReadHalf { inner: stream };
		let write_half = WsWriteHalf { inner: sink };
		(read_half, write_half)
	}
}
