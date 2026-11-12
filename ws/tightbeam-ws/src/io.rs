//! WebSocket message I/O for tightbeam, as `docs/ws.md` (Stream and envelope
//! rules) states it.
//!
//! # Sources
//!
//! - RFC 6455, The WebSocket Protocol, December 2011, section 5.5.1 (Close) and
//!   section 5.6 (Data Frames): <https://datatracker.ietf.org/doc/html/rfc6455>

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Bytes, Error as WsError, Message};
use tokio_tungstenite::{accept_async_with_config, connect_async_with_config, MaybeTlsStream, WebSocketStream};

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::transport::{AsyncProtocolStream, SplittableStream, TcpTransport, TransportError, TransportLimits};
use tightbeam_wire::{Wire, WireDuplex, WireFault, WireReader, WireSink, WireStream, WireWriter};

use crate::acceptor::WsInner;

/// A bidirectional WebSocket carrying tightbeam frames, one DER envelope per
/// binary message.
///
/// - The stream is the [`WireDuplex`] of [`WsReadHalf`] and [`WsWriteHalf`], so every read and write
///   runs the envelope rules of [`tightbeam_wire`].
/// - A dial or an accept of [`WsListener`](crate::protocol::WsListener) opens the socket under the
///   envelope ceiling of its endpoint.
///
/// # Examples
///
/// ```
/// use tightbeam::prelude::TightBeamSocketAddr;
/// use tightbeam::transport::{Protocol, SplittableStream};
/// use tightbeam_ws::protocol::WsListener;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let listener: WsListener = WsListener::bind_cleartext("127.0.0.1:0").await?;
/// let addr = TightBeamSocketAddr(listener.local_addr());
/// let stream = <WsListener as Protocol>::connect(addr).await?;
/// let (_read, _write) = stream.into_split();
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct WsStream<S>(WireDuplex<WsReadHalf<S>, WsWriteHalf<S>>);

impl<S: AsyncRead + AsyncWrite + Unpin> WsStream<S> {
	/// The duplex over the two halves of an upgraded WebSocket.
	fn over(socket: WebSocketStream<S>) -> Self {
		let (sink, stream) = socket.split();

		let read = WsReadHalf { inner: stream };
		let write = WsWriteHalf { inner: sink };
		Self(WireDuplex::new(read, write))
	}
}

impl WsStream<WsInner> {
	/// Dial the WebSocket at `url` under the ceilings of `limits`.
	///
	/// # Errors
	///
	/// - The [`TransportError`] of the [`WireFault`] class of the failed dial.
	pub(crate) async fn dial(url: &str, limits: &TransportLimits) -> Result<Self, TransportError> {
		let config = Self::socket_config(limits);
		let dialed = connect_async_with_config(url, Some(config), false).await;

		let (socket, _response) = dialed.map_err(fault)?;
		Ok(Self::over(socket))
	}

	/// Upgrade the accepted TCP socket `tcp` under the ceilings of `limits`.
	///
	/// # Errors
	///
	/// - The [`TransportError`] of the [`WireFault`] class of the failed upgrade.
	pub(crate) async fn upgrade(tcp: TcpStream, limits: &TransportLimits) -> Result<Self, TransportError> {
		let socket = MaybeTlsStream::Plain(tcp);
		let config = Self::socket_config(limits);
		let upgraded = accept_async_with_config(socket, Some(config)).await;

		let socket = upgraded.map_err(fault)?;
		Ok(Self::over(socket))
	}

	/// The WebSocket configuration that holds a peer to the larger ceiling of
	/// `limits`, which each read narrows to the cap of its phase.
	///
	/// - Tungstenite refuses a frame by its declared length before it sizes a buffer, as
	///   [`AsyncProtocolStream::read_frame`] requires of a stream.
	/// - Only the transport knows the phase of a read, so the socket holds the larger ceiling.
	fn socket_config(limits: &TransportLimits) -> WebSocketConfig {
		let ceiling = Some(limits.max_envelope());
		WebSocketConfig::default().max_message_size(ceiling).max_frame_size(ceiling)
	}
}

impl<S> AsyncProtocolStream for WsStream<S>
where
	S: AsyncRead + AsyncWrite + Unpin + Send,
{
	type Error = TransportError;

	async fn read_frame(&mut self, cap: usize) -> Result<Vec<u8>, Self::Error> {
		self.0.read_frame(cap).await
	}

	async fn write_frame(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		self.0.write_frame(buffer).await
	}

	fn is_alive(&self) -> bool {
		self.0.is_alive()
	}
}

impl<S> SplittableStream for WsStream<S>
where
	S: AsyncRead + AsyncWrite + Unpin + Send,
{
	type ReadHalf = WireReader<WsReadHalf<S>>;
	type WriteHalf = WireWriter<WsWriteHalf<S>>;

	fn into_split(self) -> (Self::ReadHalf, Self::WriteHalf) {
		self.0.into_split()
	}
}

/// A tightbeam transport whose framing is provided by a WebSocket connection.
pub type WsTransport<S, P = DefaultCryptoProvider> = TcpTransport<WsStream<S>, P>;

/// The fault class of a tungstenite error:
///
/// - A close, the end of the stream with no close, a send after the close, and
///   a use after the end are [`WireFault::Closed`].
/// - A failed byte stream, such as a write to a peer that left with no close,
///   is [`WireFault::Io`].
/// - A message past the socket configuration is [`WireFault::Oversize`].
/// - Every other error is a break of the protocol, which is [`WireFault::Invalid`].
fn fault(error: WsError) -> WireFault {
	match error {
		WsError::ConnectionClosed
		| WsError::AlreadyClosed
		| WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake | ProtocolError::SendAfterClosing) => {
			WireFault::Closed
		}
		WsError::Io(io) => WireFault::Io(io),
		WsError::Capacity(_) => WireFault::Oversize,
		_ => WireFault::Invalid,
	}
}

/// The read half of a native WebSocket, which [`WsStream`] reads through and
/// [`SplittableStream::into_split`] hands out inside its [`WireReader`].
#[derive(Debug)]
pub struct WsReadHalf<S> {
	inner: SplitStream<WebSocketStream<S>>,
}

/// The tungstenite kind of the [`WireStream`] contract. Ping, pong, and raw
/// frames skip as text does, because tungstenite answers each ping itself.
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
			Some(Err(error)) => Wire::Failed(fault(error)),
		}
	}
}

/// The write half of a native WebSocket, which [`WsStream`] writes through and
/// [`SplittableStream::into_split`] hands out inside its [`WireWriter`].
#[derive(Debug)]
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

		let sent = self.inner.send(message).await;
		sent.map_err(fault)
	}
}

#[cfg(test)]
mod tests {
	use tightbeam::transport::{LimitsRefusal, TransportFailure};
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

		(WsStream::over(socket), peer)
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
	async fn a_ping_and_a_pong_are_skipped() -> TestResult {
		let (mut stream, mut peer) = connected().await;
		peer.send(Message::Ping(Bytes::from_static(b"probe"))).await?;
		peer.send(Message::Pong(Bytes::from_static(b"probe"))).await?;
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
	async fn a_zero_cap_is_refused_as_invalid_limits() -> TestResult {
		let (mut stream, mut peer) = connected().await;
		peer.send(Message::binary(vec![1, 2, 3])).await?;

		let refused = stream.read_frame(0).await;
		let zero_ceiling = matches!(refused, Err(TransportError::InvalidLimits(LimitsRefusal::ZeroCeiling)));
		assert!(zero_ceiling);
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
	async fn a_reset_without_a_close_reads_as_connection_closed() -> TestResult {
		let (mut stream, peer) = connected().await;
		drop(peer);

		let reset = stream.read_frame(CAP).await;
		assert!(matches!(reset, Err(TransportError::ConnectionClosed)));
		Ok(())
	}

	#[tokio::test]
	async fn a_write_after_the_peer_closed_is_connection_closed() -> TestResult {
		let (mut stream, mut peer) = connected().await;
		peer.close(None).await?;
		let _closed = stream.read_frame(CAP).await;

		let refused = stream.write_frame(&[1, 2, 3]).await;
		assert!(matches!(refused, Err(TransportError::ConnectionClosed)));
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

	#[tokio::test]
	async fn a_stream_without_a_failure_reads_alive() -> TestResult {
		let (mut stream, mut peer) = connected().await;
		peer.send(Message::binary(vec![1, 2, 3])).await?;

		let _read = stream.read_frame(CAP).await?;
		stream.write_frame(&[1, 2, 3]).await?;

		assert!(stream.is_alive());
		Ok(())
	}

	#[tokio::test]
	async fn a_failed_read_marks_the_stream_dead() -> TestResult {
		let (mut stream, mut peer) = connected().await;
		peer.close(None).await?;

		let _closed = stream.read_frame(CAP).await;
		assert!(!stream.is_alive());
		Ok(())
	}

	#[tokio::test]
	async fn a_failed_write_marks_the_stream_dead() -> TestResult {
		let (mut stream, peer) = connected().await;
		drop(peer);

		let refused = stream.write_frame(&[1, 2, 3]).await;
		assert!(matches!(refused, Err(TransportError::IoError(_))));
		assert!(!stream.is_alive());
		Ok(())
	}
}
