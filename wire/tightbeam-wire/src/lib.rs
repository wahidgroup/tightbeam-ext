#![doc = include_str!("../README.md")]

// This module compiles every Rust example of the page under `docs/` that
// specifies this crate as a doctest, so a renamed item fails the build
// instead of leaving the page stale.
#[cfg(doctest)]
#[doc = include_str!("../../../docs/wire.md")]
mod docs_wire {}

use core::future::Future;
use core::num::NonZeroUsize;
use std::io;

use tightbeam::marker::MaybeSend;
use tightbeam::transport::{
	AsyncProtocolStream, AsyncReadStream, AsyncWriteStream, LimitsRefusal, SplittableStream, TransportError,
	TransportFailure,
};
use tightbeam::Errorizable;

/// One received message of a socket kind, as that kind classifies it.
///
/// A [`WireStream`] yields one value per message it receives, and the reader
/// of a [`WireDuplex`] decides what each value means for a read.
///
/// # Examples
///
/// ```
/// use tightbeam_wire::Wire;
///
/// /// The messages of a socket library.
/// enum Message {
///     Binary(Vec<u8>),
///     Text(String),
///     Close,
/// }
///
/// let classify = |message| match message {
///     Message::Binary(envelope) => Wire::Envelope(envelope),
///     Message::Text(_) => Wire::Skip,
///     Message::Close => Wire::Closed,
/// };
///
/// let wire = classify(Message::Text(String::from("ping")));
/// assert!(matches!(wire, Wire::Skip));
/// ```
#[derive(Debug)]
pub enum Wire {
	/// A message that carries one envelope.
	Envelope(Vec<u8>),
	/// A message outside the tightbeam wire format, such as a text or control
	/// message.
	Skip,
	/// The peer closed the connection, or the message stream ended.
	Closed,
	/// The socket failed.
	Failed(WireFault),
}

/// The class of a socket failure, which each socket kind reads from its own
/// error type.
///
/// # Examples
///
/// ```
/// use tightbeam::transport::{TransportError, TransportFailure};
/// use tightbeam_wire::WireFault;
///
/// let error = TransportError::from(WireFault::Oversize);
/// assert!(matches!(error, TransportError::OperationFailed(TransportFailure::SizeExceeded)));
/// ```
#[derive(Debug, Errorizable)]
pub enum WireFault {
	/// The connection closed before the operation finished.
	#[error("the connection closed")]
	Closed,
	/// The byte stream under the socket failed.
	#[error("i/o error: {0}")]
	Io(io::Error),
	/// A message passed a ceiling: the message ceiling of the socket, or the
	/// cap of a read.
	#[error("a message passed its ceiling")]
	Oversize,
	/// The socket broke its protocol, lost its connection, or refused a send.
	#[error("the socket failed")]
	Invalid,
}

/// The transport error of each fault class:
///
/// - [`WireFault::Closed`] -- [`TransportError::ConnectionClosed`].
/// - [`WireFault::Io`] -- [`TransportError::IoError`].
/// - [`WireFault::Oversize`] -- [`TransportError::OperationFailed`] with [`TransportFailure::SizeExceeded`].
/// - [`WireFault::Invalid`] -- [`TransportError::InvalidMessage`].
impl From<WireFault> for TransportError {
	fn from(fault: WireFault) -> Self {
		match fault {
			WireFault::Closed => Self::ConnectionClosed,
			WireFault::Io(error) => Self::IoError(error),
			WireFault::Oversize => Self::OperationFailed(TransportFailure::SizeExceeded),
			WireFault::Invalid => Self::InvalidMessage,
		}
	}
}

/// The read half of a socket kind, which classifies each message it receives.
///
/// Every kind meets one contract:
///
/// - A message that carries an envelope is [`Wire::Envelope`].
/// - A message outside the wire format is [`Wire::Skip`].
/// - A close, or the end of the message stream, is [`Wire::Closed`].
/// - Any other error is [`Wire::Failed`].
/// - A socket with a message ceiling refuses a message past it as
///   [`WireFault::Oversize`] before the kind sizes a buffer for it, because a
///   reader sees only whole messages and cannot refuse one any earlier. A
///   socket without one, such as a browser WebSocket, delivers every message
///   whole.
///
/// # Examples
///
/// ```
/// use tightbeam_wire::{Wire, WireStream};
///
/// /// Whether the peer of `socket` closed before it sent anything else.
/// async fn closed_first(socket: &mut impl WireStream) -> bool {
///     let first = socket.next_wire().await;
///     matches!(first, Wire::Closed)
/// }
/// ```
pub trait WireStream {
	/// The next message of the socket, classified.
	fn next_wire(&mut self) -> impl Future<Output = Wire> + MaybeSend;
}

/// The write half of a socket kind, which sends each envelope as one message.
///
/// # Examples
///
/// ```
/// use tightbeam_wire::{WireFault, WireSink};
///
/// /// Send the envelopes of `batch` through `socket` in order.
/// async fn send_all(socket: &mut impl WireSink, batch: &[Vec<u8>]) -> Result<(), WireFault> {
///     for envelope in batch {
///         socket.send_envelope(envelope).await?;
///     }
///     Ok(())
/// }
/// ```
pub trait WireSink {
	/// Send `envelope` as one message.
	///
	/// # Errors
	///
	/// - The [`WireFault`] of the failed send.
	fn send_envelope(&mut self, envelope: &[u8]) -> impl Future<Output = Result<(), WireFault>> + MaybeSend;
}

/// One read of an envelope from a [`WireStream`], under a cap.
///
/// The reader skips every message outside the wire format and admits the
/// first envelope within its cap. A close ends the read.
pub(crate) struct EnvelopeReader<'s, S> {
	stream: &'s mut S,
	cap: NonZeroUsize,
}

impl<'s, S: WireStream> EnvelopeReader<'s, S> {
	/// A read of `stream` that admits an envelope of at most `cap` octets.
	///
	/// A transport takes each cap from its [`CheckedLimits`], so every cap it
	/// passes is at least one octet.
	///
	/// [`CheckedLimits`]: tightbeam::transport::CheckedLimits
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidLimits`] with [`LimitsRefusal::ZeroCeiling`] -- `cap` is zero.
	pub(crate) fn new(stream: &'s mut S, cap: usize) -> Result<Self, TransportError> {
		let Some(cap) = NonZeroUsize::new(cap) else {
			return Err(TransportError::InvalidLimits(LimitsRefusal::ZeroCeiling));
		};

		Ok(Self { stream, cap })
	}

	/// The first envelope the stream delivers within the cap.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with [`TransportFailure::SizeExceeded`] -- the envelope
	///   passes the cap.
	/// - [`TransportError::ConnectionClosed`] -- the stream closed before an envelope arrived.
	/// - The [`TransportError`] of the [`WireFault`] that failed the stream.
	pub(crate) async fn read(self) -> Result<Vec<u8>, TransportError> {
		loop {
			let wire = self.stream.next_wire().await;
			let fault = match wire {
				Wire::Envelope(envelope) if envelope.len() <= self.cap.get() => return Ok(envelope),
				Wire::Envelope(_) => WireFault::Oversize,
				Wire::Skip => continue,
				Wire::Closed => WireFault::Closed,
				Wire::Failed(fault) => fault,
			};

			return Err(fault.into());
		}
	}
}

/// Whether a stream still reads as connected.
///
/// A [`WireDuplex`] records what its own reads and writes observed, because a
/// socket answers a liveness probe only through a read. The first failure
/// marks the duplex dead for good, so a pool passes over a failed socket.
#[derive(Debug)]
pub(crate) struct Liveness {
	alive: bool,
}

impl Liveness {
	/// Return `outcome`, and mark the stream dead when it failed.
	pub(crate) fn settle<T, E>(&mut self, outcome: Result<T, E>) -> Result<T, E> {
		if outcome.is_err() {
			self.alive = false;
		}

		outcome
	}

	/// Whether every read and write so far succeeded.
	pub(crate) fn is_alive(&self) -> bool {
		self.alive
	}
}

/// A stream that has seen no failure.
impl Default for Liveness {
	fn default() -> Self {
		Self { alive: true }
	}
}

/// The read half of a [`WireDuplex`], which reads every envelope of its socket
/// kind under the cap of each read.
#[derive(Debug)]
pub struct WireReader<R> {
	stream: R,
}

impl<R> AsyncReadStream for WireReader<R>
where
	R: WireStream + MaybeSend + Unpin,
{
	type Error = TransportError;

	async fn read_frame(&mut self, cap: usize) -> Result<Vec<u8>, Self::Error> {
		let reader = EnvelopeReader::new(&mut self.stream, cap)?;
		reader.read().await
	}
}

/// The write half of a [`WireDuplex`], which sends every envelope through the
/// [`WireSink`] of its socket kind.
#[derive(Debug)]
pub struct WireWriter<W> {
	sink: W,
}

impl<W> AsyncWriteStream for WireWriter<W>
where
	W: WireSink + MaybeSend + Unpin,
{
	type Error = TransportError;

	async fn write_frame(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		self.sink.send_envelope(buffer).await?;
		Ok(())
	}
}

/// One socket as a tightbeam stream: the read and write halves of a socket
/// kind, and whether both still read as connected.
///
/// Every read and write settles into one liveness record, so the duplex reads
/// as dead at its first failure. [`SplittableStream::into_split`] hands out
/// the two halves, which run the same rules apart.
///
/// Upstream [`AsyncProtocolStream::read_frame`] asks a stream to refuse a frame
/// past the cap of a read before it sizes any buffer. A socket kind hands over
/// only whole messages, so the duplex checks the cap of each read on a whole
/// message, and the message ceiling of the socket, where it has one, bounds
/// what a peer can make it buffer.
///
/// # Examples
///
/// ```
/// use tightbeam::transport::{AsyncProtocolStream, TransportError};
/// use tightbeam_wire::{WireDuplex, WireSink, WireStream};
///
/// /// The first envelope of the socket whose halves are `stream` and `sink`.
/// async fn first_envelope<R, W>(stream: R, sink: W) -> Result<Vec<u8>, TransportError>
/// where
///     R: WireStream + Send + Unpin,
///     W: WireSink + Send + Unpin,
/// {
///     let mut duplex = WireDuplex::new(stream, sink);
///     duplex.read_frame(64).await
/// }
/// ```
#[derive(Debug)]
pub struct WireDuplex<R, W> {
	read: WireReader<R>,
	write: WireWriter<W>,
	liveness: Liveness,
}

impl<R, W> WireDuplex<R, W> {
	/// A live duplex over the read half `stream` and the write half `sink` of
	/// one socket.
	pub fn new(stream: R, sink: W) -> Self {
		let read = WireReader { stream };
		let write = WireWriter { sink };
		Self { read, write, liveness: Liveness::default() }
	}
}

impl<R, W> AsyncProtocolStream for WireDuplex<R, W>
where
	R: WireStream + MaybeSend + Unpin,
	W: WireSink + MaybeSend + Unpin,
{
	type Error = TransportError;

	async fn read_frame(&mut self, cap: usize) -> Result<Vec<u8>, Self::Error> {
		let outcome = self.read.read_frame(cap).await;
		self.liveness.settle(outcome)
	}

	async fn write_frame(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		let outcome = self.write.write_frame(buffer).await;
		self.liveness.settle(outcome)
	}

	fn is_alive(&self) -> bool {
		self.liveness.is_alive()
	}
}

impl<R, W> SplittableStream for WireDuplex<R, W>
where
	R: WireStream + MaybeSend + Unpin,
	W: WireSink + MaybeSend + Unpin,
{
	type ReadHalf = WireReader<R>;
	type WriteHalf = WireWriter<W>;

	fn into_split(self) -> (Self::ReadHalf, Self::WriteHalf) {
		(self.read, self.write)
	}
}
