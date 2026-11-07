//! WebSocket message I/O for tightbeam.
//!
//! [`WsStream`] adapts a `tokio-tungstenite` WebSocket to tightbeam's
//! transport-agnostic [`AsyncProtocolStream`] trait: each DER-encoded tightbeam
//! envelope is carried as a single WebSocket frame. Plugged into tightbeam's
//! generic transport, it yields [`WsTransport`]. [`WsStream`] also splits into
//! exclusive halves ([`SplittableStream`]) so a multiplexed connection can read
//! and write concurrently.
//!
//! [`WsReadHalf`] and [`WsWriteHalf`] are the native kinds of [`WireStream`]
//! and [`WireSink`], and [`WsStream`] is the [`WireDuplex`] of the two, so
//! every read and write runs the envelope rules of [`crate::wire`].
//!
//! [`AsyncProtocolStream`]: tightbeam::transport::AsyncProtocolStream
//! [`SplittableStream`]: tightbeam::transport::SplittableStream

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Bytes, Error as WsError, Message};
use tokio_tungstenite::WebSocketStream;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::transport::{TcpTransport, TransportLimits};

use crate::acceptor::WsInner;
use crate::wire::{Wire, WireDuplex, WireFault, WireSink, WireStream};

/// A bidirectional WebSocket carrying tightbeam frames, the [`WireDuplex`] of
/// the native halves.
///
/// # Examples
///
/// ```
/// use tightbeam::transport::SplittableStream;
/// use tightbeam_ws::io::WsStream;
/// use tightbeam_ws::protocol::WsListener;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let listener: WsListener = WsListener::bind_cleartext("127.0.0.1:0").await?;
/// let url = format!("ws://{}/", listener.local_addr()?);
/// let (websocket, _response) = tokio_tungstenite::connect_async(url).await?;
/// let (_read, _write) = WsStream::from(websocket).into_split();
/// # Ok(())
/// # }
/// ```
pub type WsStream<S> = WireDuplex<WsReadHalf<S>, WsWriteHalf<S>>;

/// The duplex over the two halves of an already-upgraded WebSocket stream.
impl<S: AsyncRead + AsyncWrite + Unpin> From<WebSocketStream<S>> for WsStream<S> {
	fn from(socket: WebSocketStream<S>) -> Self {
		let (sink, stream) = socket.split();

		let read = WsReadHalf { inner: stream };
		let write = WsWriteHalf { inner: sink };
		WireDuplex::new(read, write)
	}
}

impl WsStream<WsInner> {
	/// The WebSocket configuration that holds a peer to the ceilings of
	/// `limits`, at a dial and at an accept.
	///
	/// Tungstenite refuses a frame by its declared length before it sizes a
	/// buffer, which [`AsyncProtocolStream::read_frame`] requires of a stream.
	/// The reader knows the wire mode only once it holds the bytes, so the
	/// socket admits the larger ceiling, and each read narrows it to its cap.
	///
	/// [`AsyncProtocolStream::read_frame`]: tightbeam::transport::AsyncProtocolStream::read_frame
	pub(crate) fn socket_config(limits: &TransportLimits) -> WebSocketConfig {
		let ceiling = Some(limits.max_envelope());
		WebSocketConfig::default().max_message_size(ceiling).max_frame_size(ceiling)
	}
}

/// A tightbeam transport whose framing is provided by a WebSocket connection.
pub type WsTransport<S, P = DefaultCryptoProvider> = TcpTransport<WsStream<S>, P>;

/// The fault class of each tungstenite error:
///
/// - A closed connection, at a read or a write, is [`WireFault::Closed`].
/// - A failed byte stream is [`WireFault::Io`].
/// - A message past the socket configuration is [`WireFault::Oversize`].
/// - Every other error, such as a protocol violation, is [`WireFault::Invalid`].
impl From<WsError> for WireFault {
	fn from(error: WsError) -> Self {
		match error {
			WsError::ConnectionClosed | WsError::AlreadyClosed => Self::Closed,
			WsError::Io(io) => Self::Io(io),
			WsError::Capacity(_) => Self::Oversize,
			_ => Self::Invalid,
		}
	}
}

/// The read half of a native WebSocket, which [`WsStream`] reads through and
/// [`SplittableStream::into_split`] hands out inside its
/// [`WireReader`](crate::wire::WireReader).
///
/// [`SplittableStream::into_split`]: tightbeam::transport::SplittableStream::into_split
pub struct WsReadHalf<S> {
	inner: SplitStream<WebSocketStream<S>>,
}

/// The tungstenite kind of the [`WireStream`] contract. Ping, pong, and raw
/// frames skip as text does, because tungstenite answers each control frame
/// itself.
impl<S> WireStream for WsReadHalf<S>
where
	S: AsyncRead + AsyncWrite + Unpin + Send,
{
	async fn next_wire(&mut self) -> Wire {
		let message = self.inner.next().await;
		match message {
			None | Some(Ok(Message::Close(_))) => Wire::Closed,
			Some(Ok(Message::Binary(envelope))) => Wire::Envelope(envelope.into()),
			Some(Ok(_)) => Wire::Skip,
			Some(Err(error)) => Wire::Failed(error.into()),
		}
	}
}

/// The write half of a native WebSocket, which [`WsStream`] writes through and
/// [`SplittableStream::into_split`] hands out inside its
/// [`WireWriter`](crate::wire::WireWriter).
///
/// [`SplittableStream::into_split`]: tightbeam::transport::SplittableStream::into_split
pub struct WsWriteHalf<S> {
	inner: SplitSink<WebSocketStream<S>, Message>,
}

impl<S> WireSink for WsWriteHalf<S>
where
	S: AsyncRead + AsyncWrite + Unpin + Send,
{
	async fn send_envelope(&mut self, envelope: &[u8]) -> Result<(), WireFault> {
		let bytes = Bytes::copy_from_slice(envelope);
		let message = Message::Binary(bytes);

		self.inner.send(message).await?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use tightbeam::transport::{AsyncProtocolStream, TransportError, TransportFailure};
	use tokio::io::{duplex, DuplexStream};
	use tokio_tungstenite::tungstenite::protocol::Role;

	use super::*;

	type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

	/// The cap of every read in these tests.
	const CAP: usize = 8;

	/// The buffer of the in-memory pipe under each socket.
	const PIPE: usize = 1 << 16;

	/// A stream under test, and the tungstenite peer at the other end of its
	/// in-memory pipe.
	async fn connected() -> (WsStream<DuplexStream>, WebSocketStream<DuplexStream>) {
		let (near, far) = duplex(PIPE);
		let socket = WebSocketStream::from_raw_socket(near, Role::Client, None).await;
		let peer = WebSocketStream::from_raw_socket(far, Role::Server, None).await;

		(WsStream::from(socket), peer)
	}

	#[tokio::test]
	async fn a_text_message_is_skipped() -> TestResult {
		let (mut stream, mut peer) = connected().await;
		peer.send(Message::text("noise")).await?;
		peer.send(Message::binary(vec![1, 2, 3])).await?;

		let envelope = stream.read_frame(CAP).await?;
		assert_eq!(envelope, [1, 2, 3]);
		Ok(())
	}

	#[tokio::test]
	async fn an_envelope_past_the_cap_is_size_exceeded() -> TestResult {
		let (mut stream, mut peer) = connected().await;
		peer.send(Message::binary(vec![0; CAP + 1])).await?;

		let refused = stream.read_frame(CAP).await;
		let size_exceeded = matches!(refused, Err(TransportError::OperationFailed(TransportFailure::SizeExceeded)));
		assert!(size_exceeded);
		Ok(())
	}

	#[tokio::test]
	async fn a_close_ends_the_read_as_connection_closed() -> TestResult {
		let (mut stream, mut peer) = connected().await;
		peer.close(None).await?;

		let closed = stream.read_frame(CAP).await;
		assert!(matches!(closed, Err(TransportError::ConnectionClosed)));
		Ok(())
	}

	#[tokio::test]
	async fn an_envelope_leaves_as_one_binary_message() -> TestResult {
		let (mut stream, mut peer) = connected().await;
		stream.write_frame(&[1, 2, 3]).await?;

		let received = peer.next().await;
		assert!(matches!(received, Some(Ok(Message::Binary(envelope))) if envelope == [1, 2, 3][..]));
		Ok(())
	}
}
