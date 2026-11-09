//! gRPC message I/O for tightbeam.
//!
//! [`GrpcStream`] carries a tightbeam connection over one bidirectional gRPC
//! call, the tunnel: each envelope travels as one gRPC message. It implements
//! tightbeam's [`AsyncProtocolStream`] and splits into exclusive halves
//! ([`SplittableStream`]) so a multiplexed connection can read and write
//! concurrently.
//!
//! [`GrpcReadHalf`] and [`GrpcWriteHalf`] are the gRPC kinds of
//! [`WireStream`] and [`WireSink`], and [`GrpcStream`] holds the
//! [`WireDuplex`] of the two, so every read and write runs the envelope rules
//! of [`tightbeam_wire`].
//!
//! # Sources
//!
//! - gRPC over HTTP2, `grpc/grpc` `doc/PROTOCOL-HTTP2.md`: <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md>

use std::error::Error;
use std::io;

use http::uri::PathAndQuery;
use sync_wrapper::SyncWrapper;
use tokio::sync::mpsc::{self, Sender};
use tokio::sync::oneshot;
use tokio_stream::wrappers::ReceiverStream;
use tonic::client::Grpc;
use tonic::codec::Streaming;
use tonic::transport::Channel;
use tonic::{Code, Request, Status};

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::transport::{AsyncProtocolStream, SplittableStream, TcpTransport, TransportError, TransportLimits};
use tightbeam_wire::{Wire, WireDuplex, WireFault, WireReader, WireSink, WireStream, WireWriter};

use crate::edge::Dial;
use crate::protocol::GrpcAddr;
use crate::tunnel::{TunnelCodec, TUNNEL_PATH};

/// A tightbeam stream over one tunnel, one envelope per gRPC message.
///
/// The stream is the [`WireDuplex`] of its two halves, so every read and write
/// settles into its liveness. A stream comes only from a dial or an accept of
/// [`GrpcListener`](crate::protocol::GrpcListener), and each one sets the
/// message ceiling of both directions of its call to the envelope ceiling of
/// its endpoint.
///
/// # Examples
///
/// ```
/// use tightbeam::transport::{Protocol, SplittableStream};
/// use tightbeam_grpc::protocol::GrpcListener;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let listener: GrpcListener = GrpcListener::bind_cleartext("127.0.0.1:0").await?;
/// let addr = listener.local_addr().into();
/// let stream = <GrpcListener as Protocol>::connect(addr).await?;
/// let (_read, _write) = stream.into_split();
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct GrpcStream(WireDuplex<GrpcReadHalf, GrpcWriteHalf>);

impl GrpcStream {
	/// Dial the tunnel of the server at `addr` under `dial`, with every
	/// message of the call held to the envelope ceiling of `limits`.
	///
	/// The call owns its connection: the stream makes no other call on it, so
	/// a lost connection ends the tunnel rather than reconnecting under it.
	///
	/// # Errors
	///
	/// - The errors of [`Dial::channel`].
	/// - The [`TransportError`] of the [`WireFault`] class of the failed call.
	pub(crate) async fn dial(addr: &GrpcAddr, limits: &TransportLimits, dial: &Dial) -> Result<Self, TransportError> {
		let channel = dial.channel(addr).await?;

		let ceiling = limits.max_envelope();
		let client = Grpc::new(channel).max_decoding_message_size(ceiling);
		let mut client = client.max_encoding_message_size(ceiling);
		let ready = client.ready().await;
		ready.map_err(|error| EndClass::of_error(error.into()))?;

		let (sender, receiver) = mpsc::channel(1);
		let requests = Request::new(ReceiverStream::new(receiver));
		let path = PathAndQuery::from_static(TUNNEL_PATH);
		let called = client.streaming(requests, path, TunnelCodec).await;
		let response = called.map_err(|status| EndClass::of(&status))?;

		let read = GrpcReadHalf::open(response.into_inner(), None);
		let outbound = Outbound::Dialed { sender, _client: SyncWrapper::new(client) };
		let write = GrpcWriteHalf { outbound };
		Ok(Self(WireDuplex::new(read, write)))
	}

	/// The stream of an accepted tunnel call: its inbound `messages`, the
	/// `sender` of the messages the server answers with, and the `answer` that
	/// ends the response with a status that fails the inbound messages.
	pub(crate) fn accepted(
		messages: Streaming<Vec<u8>>,
		sender: Sender<Vec<u8>>,
		answer: oneshot::Sender<Status>,
	) -> Self {
		let read = GrpcReadHalf::open(messages, Some(answer));
		let write = GrpcWriteHalf { outbound: Outbound::Accepted { sender } };
		Self(WireDuplex::new(read, write))
	}

	/// The two ends of an in-process tunnel: each end reads, one envelope
	/// per message, what the other writes, under the same envelope rules as a
	/// tunnel call. A coupler opens its session to the accept queue of its own
	/// listener over it.
	#[cfg(feature = "couple")]
	pub(crate) fn loopback() -> (Self, Self) {
		let (to_server, from_client) = mpsc::channel(1);
		let (to_client, from_server) = mpsc::channel(1);

		let client = Self::looped(from_server, to_server);
		let server = Self::looped(from_client, to_client);
		(client, server)
	}

	/// One end of an in-process tunnel, which reads `inbound` and writes to
	/// `outbound`.
	#[cfg(feature = "couple")]
	fn looped(inbound: mpsc::Receiver<Vec<u8>>, outbound: Sender<Vec<u8>>) -> Self {
		let read = GrpcReadHalf { inbound: Inbound::Loopback(inbound), answer: None };
		let write = GrpcWriteHalf { outbound: Outbound::Loopback { sender: outbound } };
		Self(WireDuplex::new(read, write))
	}
}

impl AsyncProtocolStream for GrpcStream {
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

impl SplittableStream for GrpcStream {
	type ReadHalf = WireReader<GrpcReadHalf>;
	type WriteHalf = WireWriter<GrpcWriteHalf>;

	fn into_split(self) -> (Self::ReadHalf, Self::WriteHalf) {
		self.0.into_split()
	}
}

/// A tightbeam transport whose framing is provided by a tunnel call.
pub type GrpcTransport<P = DefaultCryptoProvider> = TcpTransport<GrpcStream, P>;

/// How a tunnel ended, which every later read of it returns.
///
/// The class is `Copy`, unlike the [`WireFault`] it maps to, so a read half
/// keeps it after the end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndClass {
	/// The call ended, or its connection closed or timed out.
	Closed,
	/// The byte stream under the call failed.
	Io(io::ErrorKind),
	/// A message passed the envelope ceiling.
	Oversize,
	/// The peer broke the gRPC or HTTP/2 protocol, or refused the call.
	Invalid,
}

impl EndClass {
	/// The class of `status`, the error a tunnel call ended with:
	///
	/// - An I/O error in its source chain, on its own or inside an HTTP/2
	///   error, is [`EndClass::Io`].
	/// - `OUT_OF_RANGE`, the status of the message ceiling, is [`EndClass::Oversize`].
	/// - `CANCELLED`, `UNAVAILABLE`, and `DEADLINE_EXCEEDED` are [`EndClass::Closed`].
	/// - Every other status is [`EndClass::Invalid`].
	fn of(status: &Status) -> Self {
		let mut source: Option<&(dyn Error + 'static)> = Some(status);
		while let Some(error) = source {
			let http2 = error.downcast_ref::<h2::Error>().and_then(h2::Error::get_io);
			if let Some(io) = error.downcast_ref::<io::Error>().or(http2) {
				return Self::Io(io.kind());
			}

			source = error.source();
		}

		match status.code() {
			Code::OutOfRange => Self::Oversize,
			Code::Cancelled | Code::Unavailable | Code::DeadlineExceeded => Self::Closed,
			_ => Self::Invalid,
		}
	}

	/// The class of `error`, a failure of tonic outside a call, read through
	/// the status tonic makes of it.
	pub(crate) fn of_error(error: Box<dyn Error + Send + Sync + 'static>) -> Self {
		let status = Status::from_error(error);
		Self::of(&status)
	}
}

/// The fault class of each end.
impl From<EndClass> for WireFault {
	fn from(end: EndClass) -> Self {
		match end {
			EndClass::Closed => Self::Closed,
			EndClass::Io(kind) => Self::Io(io::Error::from(kind)),
			EndClass::Oversize => Self::Oversize,
			EndClass::Invalid => Self::Invalid,
		}
	}
}

/// The transport error a failed dial returns.
impl From<EndClass> for TransportError {
	fn from(end: EndClass) -> Self {
		WireFault::from(end).into()
	}
}

/// The [`Wire`] of each end: a closed call reads as [`Wire::Closed`], and every
/// other end as the failure of its class.
impl From<EndClass> for Wire {
	fn from(end: EndClass) -> Self {
		match end {
			EndClass::Closed => Self::Closed,
			failed => Self::Failed(failed.into()),
		}
	}
}

/// The read half of a tunnel: its inbound messages until the call ends, and
/// the class of that end after it.
#[derive(Debug)]
pub struct GrpcReadHalf {
	inbound: Inbound,
	/// The end of the response of an accepted call, which a status that fails
	/// the inbound messages takes, so the peer reads the status of its own
	/// fault. A dialed tunnel answers no call.
	answer: Option<oneshot::Sender<Status>>,
}

#[derive(Debug)]
enum Inbound {
	Open(Box<Streaming<Vec<u8>>>),
	/// The read end of an in-process tunnel.
	#[cfg(feature = "couple")]
	Loopback(mpsc::Receiver<Vec<u8>>),
	Ended(EndClass),
}

impl GrpcReadHalf {
	fn open(messages: Streaming<Vec<u8>>, answer: Option<oneshot::Sender<Status>>) -> Self {
		let inbound = Inbound::Open(Box::new(messages));
		Self { inbound, answer }
	}

	/// End the response of an accepted call with `status`.
	fn answer(&mut self, status: Status) {
		if let Some(answer) = self.answer.take() {
			let _ = answer.send(status);
		}
	}
}

/// The gRPC kind of the [`WireStream`] contract. Every message of the call is
/// one envelope, so no message skips. The end of the call, or a status that
/// ends it, is read once, and every later read returns the same end.
impl WireStream for GrpcReadHalf {
	async fn next_wire(&mut self) -> Wire {
		let messages = match &mut self.inbound {
			Inbound::Open(messages) => messages,
			#[cfg(feature = "couple")]
			Inbound::Loopback(messages) => {
				if let Some(envelope) = messages.recv().await {
					return Wire::Envelope(envelope);
				}

				self.inbound = Inbound::Ended(EndClass::Closed);
				return Wire::Closed;
			}
			Inbound::Ended(end) => return Wire::from(*end),
		};

		let end = match messages.message().await {
			Ok(Some(envelope)) => return Wire::Envelope(envelope),
			Ok(None) => EndClass::Closed,
			Err(status) => {
				let end = EndClass::of(&status);
				self.answer(status);
				end
			}
		};

		self.inbound = Inbound::Ended(end);
		Wire::from(end)
	}
}

/// The write half of a tunnel, which sends each envelope as one message of
/// the call.
///
/// The channel to the call holds one envelope, and tonic batches the
/// envelopes it takes from it up to its yield threshold of 32 KiB before
/// HTTP/2 flow control applies.
#[derive(Debug)]
pub struct GrpcWriteHalf {
	outbound: Outbound,
}

#[derive(Debug)]
enum Outbound {
	/// The half of a dialed tunnel, which owns the client of its one call.
	Dialed { sender: Sender<Vec<u8>>, _client: SyncWrapper<Grpc<Channel>> },
	/// The half of an accepted tunnel, whose messages the server sends as its
	/// response.
	Accepted { sender: Sender<Vec<u8>> },
	/// The write end of an in-process tunnel.
	#[cfg(feature = "couple")]
	Loopback { sender: Sender<Vec<u8>> },
}

impl WireSink for GrpcWriteHalf {
	async fn send_envelope(&mut self, envelope: &[u8]) -> Result<(), WireFault> {
		let sender = match &self.outbound {
			Outbound::Dialed { sender, .. } | Outbound::Accepted { sender } => sender,
			#[cfg(feature = "couple")]
			Outbound::Loopback { sender } => sender,
		};

		let message = envelope.to_vec();
		let sent = sender.send(message).await;
		sent.map_err(|_| WireFault::Closed)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn each_status_code_ends_the_tunnel_in_its_class() {
		let cases = [
			(Code::OutOfRange, EndClass::Oversize),
			(Code::Cancelled, EndClass::Closed),
			(Code::Unavailable, EndClass::Closed),
			(Code::DeadlineExceeded, EndClass::Closed),
			(Code::Internal, EndClass::Invalid),
			(Code::Unimplemented, EndClass::Invalid),
			(Code::Unknown, EndClass::Invalid),
			(Code::Ok, EndClass::Invalid),
		];

		for (code, class) in cases {
			let status = Status::new(code, "");
			assert_eq!(EndClass::of(&status), class);
		}
	}

	#[test]
	fn an_io_error_in_the_source_chain_ends_the_tunnel_as_io() {
		let reset = io::Error::from(io::ErrorKind::ConnectionReset);
		let status = Status::from_error(Box::new(reset));
		assert_eq!(EndClass::of(&status), EndClass::Io(io::ErrorKind::ConnectionReset));
	}

	#[test]
	fn each_class_reads_as_its_wire() {
		assert!(matches!(Wire::from(EndClass::Closed), Wire::Closed));
		assert!(matches!(Wire::from(EndClass::Oversize), Wire::Failed(WireFault::Oversize)));
		assert!(matches!(Wire::from(EndClass::Invalid), Wire::Failed(WireFault::Invalid)));

		let io = Wire::from(EndClass::Io(io::ErrorKind::BrokenPipe));
		assert!(matches!(io, Wire::Failed(WireFault::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe));
	}
}
