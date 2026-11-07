//! The envelope rules of a WebSocket half, which every socket kind shares.
//!
//! A tightbeam envelope travels as one binary WebSocket message. A socket kind
//! classifies its own messages and errors, and this module holds the rules
//! that every kind reads, writes, and fails by. It builds on the transport
//! errors of tightbeam alone, so the native `socket` feature and the browser
//! client share it.
//!
//! - [`WireStream`] and [`WireSink`] are the read and write halves of a socket kind.
//! - [`WireDuplex`] joins the two halves of a socket into one tightbeam stream, which splits into
//!   [`WireReader`] and [`WireWriter`].
//! - [`EnvelopeReader`] admits one envelope from a [`WireStream`].
//! - [`Liveness`] marks a duplex dead at its first failure.
//! - [`WireFault`] names each fault class and maps it into a [`TransportError`].
//!
//! # Sources
//!
//! - RFC 6455, The WebSocket Protocol, December 2011, section 5.5.1 (Close) and
//!   section 5.6 (Data Frames): <https://datatracker.ietf.org/doc/html/rfc6455>

use core::future::Future;
use core::num::NonZeroUsize;
use std::io;

use tightbeam::marker::MaybeSend;
use tightbeam::transport::{
	AsyncProtocolStream, AsyncReadStream, AsyncWriteStream, LimitsRefusal, SplittableStream, TransportError,
	TransportFailure,
};
use tightbeam::Errorizable;

/// One message of a WebSocket half, as its socket kind classifies it.
///
/// A [`WireStream`] yields one value per message it receives, and an
/// [`EnvelopeReader`] decides what each value means for a read.
///
/// # Examples
///
/// ```
/// use tightbeam_ws::wire::Wire;
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
	/// A binary message, which carries one envelope.
	Envelope(Vec<u8>),
	/// A message outside the tightbeam wire format, such as text or a ping.
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
/// use tightbeam_ws::wire::WireFault;
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
	/// A message passed a ceiling: the frame ceiling of the socket, or the cap
	/// of a read.
	#[error("a message passed its ceiling")]
	Oversize,
	/// The socket broke the WebSocket protocol, lost its connection, or
	/// refused a send.
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
/// - A binary message is [`Wire::Envelope`].
/// - A text or control message is [`Wire::Skip`].
/// - A close, or the end of the message stream, is [`Wire::Closed`].
/// - Any other error is [`Wire::Failed`].
///
/// # Examples
///
/// ```
/// use tightbeam_ws::wire::{EnvelopeReader, Wire, WireStream};
///
/// /// A socket that replays its messages, last first.
/// struct Replay(Vec<Wire>);
///
/// impl WireStream for Replay {
///     async fn next_wire(&mut self) -> Wire {
///         self.0.pop().unwrap_or(Wire::Closed)
///     }
/// }
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), Box<dyn core::error::Error>> {
/// let mut socket = Replay(vec![Wire::Envelope(vec![0x30, 0x00]), Wire::Skip]);
/// let reader = EnvelopeReader::new(&mut socket, 64)?;
///
/// let envelope = reader.read().await?;
/// assert_eq!(envelope, [0x30, 0x00]);
/// # Ok(())
/// # }
/// ```
pub trait WireStream {
	/// The next message of the socket, classified.
	fn next_wire(&mut self) -> impl Future<Output = Wire> + MaybeSend;
}

/// The write half of a socket kind, which sends each envelope as one binary
/// message.
///
/// # Examples
///
/// ```
/// use tightbeam_ws::wire::{WireFault, WireSink};
///
/// /// A socket that keeps every message it sends.
/// struct Outbox(Vec<Vec<u8>>);
///
/// impl WireSink for Outbox {
///     async fn send_envelope(&mut self, envelope: &[u8]) -> Result<(), WireFault> {
///         self.0.push(envelope.to_vec());
///         Ok(())
///     }
/// }
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), Box<dyn core::error::Error>> {
/// let mut socket = Outbox(Vec::new());
/// socket.send_envelope(&[0x30, 0x00]).await?;
///
/// assert_eq!(socket.0, [vec![0x30, 0x00]]);
/// # Ok(())
/// # }
/// ```
pub trait WireSink {
	/// Send `envelope` as one binary message.
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
///
/// # Examples
///
/// ```
/// use tightbeam::transport::{TransportError, TransportFailure};
/// use tightbeam_ws::wire::{EnvelopeReader, Wire, WireStream};
///
/// /// A socket that replays its messages, last first.
/// struct Replay(Vec<Wire>);
///
/// impl WireStream for Replay {
///     async fn next_wire(&mut self) -> Wire {
///         self.0.pop().unwrap_or(Wire::Closed)
///     }
/// }
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), Box<dyn core::error::Error>> {
/// let mut socket = Replay(vec![Wire::Envelope(vec![0; 65])]);
/// let reader = EnvelopeReader::new(&mut socket, 64)?;
///
/// let refused = reader.read().await;
/// assert!(matches!(refused, Err(TransportError::OperationFailed(TransportFailure::SizeExceeded))));
/// # Ok(())
/// # }
/// ```
pub struct EnvelopeReader<'s, S> {
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
	pub fn new(stream: &'s mut S, cap: usize) -> Result<Self, TransportError> {
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
	pub async fn read(self) -> Result<Vec<u8>, TransportError> {
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
///
/// # Examples
///
/// ```
/// use tightbeam::transport::TransportError;
/// use tightbeam_ws::wire::Liveness;
///
/// let mut liveness = Liveness::default();
/// let failed: Result<(), TransportError> = Err(TransportError::ConnectionClosed);
///
/// let _ = liveness.settle(failed);
/// assert!(!liveness.is_alive());
/// ```
#[derive(Debug)]
pub struct Liveness {
	alive: bool,
}

impl Liveness {
	/// Return `outcome`, and mark the stream dead when it failed.
	pub fn settle<T, E>(&mut self, outcome: Result<T, E>) -> Result<T, E> {
		if outcome.is_err() {
			self.alive = false;
		}

		outcome
	}

	/// Whether every read and write so far succeeded.
	#[must_use]
	pub fn is_alive(&self) -> bool {
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
/// kind through one [`EnvelopeReader`].
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

/// One WebSocket as a tightbeam stream: the read and write halves of a socket
/// kind, and the [`Liveness`] of both.
///
/// Every read and write settles into the one [`Liveness`], so the duplex reads
/// as dead at its first failure. [`SplittableStream::into_split`] hands out
/// the two halves, which run the same rules apart.
///
/// # Examples
///
/// ```
/// use tightbeam::transport::{AsyncProtocolStream, TransportError};
/// use tightbeam_ws::wire::{Wire, WireDuplex, WireFault, WireSink, WireStream};
///
/// /// A socket whose peer already closed.
/// struct Gone;
///
/// impl WireStream for Gone {
///     async fn next_wire(&mut self) -> Wire {
///         Wire::Closed
///     }
/// }
///
/// impl WireSink for Gone {
///     async fn send_envelope(&mut self, _envelope: &[u8]) -> Result<(), WireFault> {
///         Err(WireFault::Closed)
///     }
/// }
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let mut stream = WireDuplex::new(Gone, Gone);
/// let refused = stream.write_frame(&[0x30, 0x00]).await;
///
/// assert!(matches!(refused, Err(TransportError::ConnectionClosed)));
/// assert!(!stream.is_alive());
/// # }
/// ```
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

#[cfg(test)]
mod tests {
	use super::*;

	/// The cap of every read in these tests.
	const CAP: usize = 8;

	/// A read half that replays its messages, last first, then reads as
	/// closed.
	struct Script(Vec<Wire>);

	impl WireStream for Script {
		async fn next_wire(&mut self) -> Wire {
			self.0.pop().unwrap_or(Wire::Closed)
		}
	}

	/// A write half whose every send leaves.
	struct Accepting;

	impl WireSink for Accepting {
		async fn send_envelope(&mut self, _envelope: &[u8]) -> Result<(), WireFault> {
			Ok(())
		}
	}

	/// A write half whose every send meets a closed connection.
	struct Refusing;

	impl WireSink for Refusing {
		async fn send_envelope(&mut self, _envelope: &[u8]) -> Result<(), WireFault> {
			Err(WireFault::Closed)
		}
	}

	#[tokio::test]
	async fn a_zero_cap_is_refused_as_invalid_limits() {
		let mut stream = WireDuplex::new(Script(vec![Wire::Envelope(vec![1, 2, 3])]), Accepting);

		let refused = stream.read_frame(0).await;

		let zero_ceiling = matches!(refused, Err(TransportError::InvalidLimits(LimitsRefusal::ZeroCeiling)));
		assert!(zero_ceiling);
	}

	#[tokio::test]
	async fn a_stream_without_a_failure_reads_alive() {
		let mut stream = WireDuplex::new(Script(vec![Wire::Envelope(vec![1, 2, 3])]), Accepting);

		let _read = stream.read_frame(CAP).await;
		let _written = stream.write_frame(&[1, 2, 3]).await;

		assert!(stream.is_alive());
	}

	#[tokio::test]
	async fn a_failed_read_marks_the_stream_dead() {
		let mut stream = WireDuplex::new(Script(Vec::new()), Accepting);
		let _closed = stream.read_frame(CAP).await;
		assert!(!stream.is_alive());
	}

	#[tokio::test]
	async fn a_failed_write_marks_the_stream_dead() {
		let mut stream = WireDuplex::new(Script(Vec::new()), Refusing);
		let _refused = stream.write_frame(&[1, 2, 3]).await;
		assert!(!stream.is_alive());
	}
}
