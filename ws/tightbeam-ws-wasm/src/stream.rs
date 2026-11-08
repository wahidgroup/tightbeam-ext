//! Browser WebSocket stream adapting `gloo-net` to tightbeam's
//! [`AsyncProtocolStream`]. Compiled only for `wasm32` targets.
//!
//! Each DER-encoded tightbeam envelope travels as a single WebSocket message.
//! [`GlooStream`] also splits into exclusive halves ([`SplittableStream`]) so
//! a multiplexed connection can read and write concurrently.
//!
//! [`GlooReadHalf`] and [`GlooWriteHalf`] are the browser kinds of
//! [`WireStream`] and [`WireSink`], and [`GlooStream`] holds the
//! [`WireDuplex`] of the two, so every read and write runs the envelope rules
//! that the native transport runs.

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use gloo_net::websocket::futures::WebSocket;
use gloo_net::websocket::{Message, WebSocketError};

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::transport::{AsyncProtocolStream, SplittableStream, TcpTransport, TransportError};
use tightbeam_wire::{Wire, WireDuplex, WireFault, WireReader, WireSink, WireStream, WireWriter};

/// A browser WebSocket carrying tightbeam frames, one DER envelope per message.
///
/// The stream is the [`WireDuplex`] of the browser halves, so every read and
/// write settles into its liveness.
pub struct GlooStream(WireDuplex<GlooReadHalf, GlooWriteHalf>);

impl From<WebSocket> for GlooStream {
	fn from(socket: WebSocket) -> Self {
		let (sink, stream) = socket.split();

		let read = GlooReadHalf { inner: stream };
		let write = GlooWriteHalf { inner: sink };
		Self(WireDuplex::new(read, write))
	}
}

/// tightbeam's transport-agnostic transport instantiated over a browser
/// WebSocket. Parameterised by the crypto provider `P` so encrypted clients
/// can use their own provider.
pub type WsTransport<P = DefaultCryptoProvider> = TcpTransport<GlooStream, P>;

/// The fault class of a `gloo` error.
///
/// A close event is [`WireFault::Closed`]. A lost connection and a refused
/// send are [`WireFault::Invalid`], because `gloo` reports neither cause.
fn fault(error: WebSocketError) -> WireFault {
	match error {
		WebSocketError::ConnectionClose(_) => WireFault::Closed,
		_ => WireFault::Invalid,
	}
}

impl AsyncProtocolStream for GlooStream {
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

impl SplittableStream for GlooStream {
	type ReadHalf = WireReader<GlooReadHalf>;
	type WriteHalf = WireWriter<GlooWriteHalf>;

	fn into_split(self) -> (Self::ReadHalf, Self::WriteHalf) {
		self.0.into_split()
	}
}

/// The read half of a browser WebSocket, which [`GlooStream`] reads through
/// and [`SplittableStream::into_split`] hands out inside its [`WireReader`].
pub struct GlooReadHalf {
	inner: SplitStream<WebSocket>,
}

/// The `gloo` kind of the [`WireStream`] contract. The browser assembles each
/// message before it reaches JavaScript, so the cap of a read bounds what the
/// transport decodes, and `gloo` reports a close as its close event.
impl WireStream for GlooReadHalf {
	async fn next_wire(&mut self) -> Wire {
		let message = self.inner.next().await;
		match message {
			None | Some(Err(WebSocketError::ConnectionClose(_))) => Wire::Closed,
			Some(Ok(Message::Bytes(envelope))) => Wire::Envelope(envelope),
			Some(Ok(Message::Text(_))) => Wire::Skip,
			Some(Err(error)) => Wire::Failed(fault(error)),
		}
	}
}

/// The write half of a browser WebSocket, which [`GlooStream`] writes through
/// and [`SplittableStream::into_split`] hands out inside its [`WireWriter`].
pub struct GlooWriteHalf {
	inner: SplitSink<WebSocket, Message>,
}

impl WireSink for GlooWriteHalf {
	async fn send_envelope(&mut self, envelope: &[u8]) -> Result<(), WireFault> {
		let message = Message::Bytes(envelope.to_vec());
		let sent = self.inner.send(message).await;
		sent.map_err(fault)
	}
}
