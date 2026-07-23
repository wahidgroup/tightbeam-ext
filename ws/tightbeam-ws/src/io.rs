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
use tokio_tungstenite::tungstenite::{Bytes, Error as WsError, Message};
use tokio_tungstenite::WebSocketStream;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::transport::tcp::r#async::{AsyncReadStream, AsyncWriteStream, SplittableStream};
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

/// Await the next binary message, skipping text and control frames and
/// enforcing the caller's envelope size ceiling.
async fn read_binary_frame<S>(source: &mut S, max_len: Option<usize>) -> Result<Vec<u8>, TransportError>
where
	S: Stream<Item = Result<Message, WsError>> + Unpin,
{
	loop {
		match source.next().await {
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

	async fn read_frame(&mut self, max_len: Option<usize>) -> Result<Vec<u8>, Self::Error> {
		read_binary_frame(&mut self.inner, max_len).await
	}

	async fn write_frame(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		write_binary_frame(&mut self.inner, buffer).await
	}

	fn is_alive(&self) -> bool {
		// tungstenite exposes no cheap, non-blocking liveness probe
		true
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

	async fn read_frame(&mut self, max_len: Option<usize>) -> Result<Vec<u8>, Self::Error> {
		read_binary_frame(&mut self.inner, max_len).await
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
