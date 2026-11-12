//! Coupled streams. Each part is a signed frame behind a 4-byte big-endian
//! length, because a mux stream carries chunks of any size.

use core::error::Error;
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::task::{ready, Context, Poll};

use tightbeam::builder::TypeBuilder;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::der::asn1::OctetString;
use tightbeam::der::{Decode, Encode};
use tightbeam::policy::TransitStatus;
use tightbeam::transport::multiplex::{ReplySink, RequestSink, StreamBody};
use tightbeam::transport::{TransportError, TransportFailure};
use tightbeam::{Frame, TightBeamError, Version};
use tokio::sync::mpsc;
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinHandle;
use tokio_stream::Stream;
use tonic::codec::Streaming;
use tonic::{Code, Status};

use super::admit::{AdmissionFault, AdmissionTrust, AdmittedHead, AdmittedSigner, Origin};
use super::fault::CallFault;
use super::loopback::OpenedDuplex;
use super::message::{CoupledPart, CoupledReply, PartWire, StreamTerms};
use super::routes::{Arity, Servlet, Shape, StreamShape};
use super::saga::{CallEnding, CallHold};
use super::voucher::{HeadPart, RequestId};
use crate::deadline::Deadline;

/// The bytes of the length that leads each part.
const PREFIX: usize = 4;

/// The answers that a relay holds for a caller that has not read them.
const ANSWER_BACKLOG: usize = 1;

impl CoupledPart {
	/// The frame of `part` at `order` in the stream of the call `request_id`,
	/// signed under `signer`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a frame that does not build or sign.
	pub(crate) async fn signed(
		request_id: &[u8],
		order: u64,
		part: PartWire,
		signer: &SigningIdentity,
	) -> Result<Frame, TightBeamError> {
		let draft = Version::V1.compose().with_id(request_id).with_order(order);
		let mut frame = draft.with_message(Self { part }).build()?;
		frame.sign_with_provider(signer).await?;
		Ok(frame)
	}
}

/// The bytes that carry one frame as a part: its length, then its DER.
pub(crate) struct FramedPart(Vec<u8>);

impl FramedPart {
	/// The part of `frame`, or `None` when its DER does not encode or passes
	/// `ceiling`.
	pub(crate) fn of(frame: &Frame, ceiling: usize) -> Option<Self> {
		let der = frame.to_der().ok()?;
		let length = u32::try_from(der.len()).ok().filter(|_| der.len() <= ceiling)?;

		let mut bytes = Vec::with_capacity(PREFIX + der.len());
		bytes.extend_from_slice(&length.to_be_bytes());
		bytes.extend_from_slice(&der);
		Some(Self(bytes))
	}

	pub(crate) fn as_bytes(&self) -> &[u8] {
		&self.0
	}
}

/// Why the next part of a stream does not admit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PartFault {
	/// The stream failed, with the status of the party that ended it when it
	/// carries one, or it ended in the middle of a part.
	Broken(Option<TransitStatus>),
	/// A part passes its ceiling, or its frame does not decode, a request part
	/// carries an end, or a stream ends before its head.
	Malformed,
	/// A part does not verify under its signer, answers another call, comes
	/// out of order, does not decode as a part, or follows the last part.
	Refused,
	/// A part breaks the count of messages that its side takes.
	Breach,
}

impl PartFault {
	/// The fault of the coupler when the answer of a servlet fails so.
	fn of_answer(self) -> CallFault {
		match self {
			Self::Broken(Some(status)) => CallFault::Transit(status),
			Self::Broken(None) => CallFault::Unavailable,
			Self::Malformed | Self::Refused => CallFault::AnswerRefused,
			Self::Breach => CallFault::AnswerShape,
		}
	}

	/// The refusal that ends the stream of a servlet when a request part fails
	/// so. A stream ends on a transport status, which the caller reads. A
	/// count of requests that the method does not take is unimplemented, as
	/// gRPC answers a cardinality violation.
	pub(super) fn of_request(self) -> TightBeamError {
		let status = match self {
			Self::Broken(_) => TransitStatus::Unavailable,
			Self::Malformed => TransitStatus::InvalidArgument,
			Self::Breach => TransitStatus::Unimplemented,
			Self::Refused => TransitStatus::Unauthenticated,
		};
		TransportError::from(status).into()
	}
}

/// The bytes of a stream as they arrive, which split into whole parts.
pub(crate) struct PartBuffer {
	bytes: Vec<u8>,
	ceiling: usize,
}

impl PartBuffer {
	pub(crate) fn new(ceiling: usize) -> Self {
		Self { bytes: Vec::new(), ceiling }
	}

	pub(crate) fn extend(&mut self, chunk: &[u8]) {
		self.bytes.extend_from_slice(chunk);
	}

	fn is_empty(&self) -> bool {
		self.bytes.is_empty()
	}

	/// The frame of the part at the head of the buffer, once all of it came.
	///
	/// # Errors
	///
	/// - [`PartFault::Malformed`] -- the part declares a length past the
	///   ceiling, or its frame does not decode.
	pub(crate) fn split(&mut self) -> Result<Option<Frame>, PartFault> {
		let Some(prefix) = self.bytes.first_chunk::<PREFIX>() else {
			return Ok(None);
		};

		let declared = u32::from_be_bytes(*prefix);
		let length = usize::try_from(declared).map_err(|_| PartFault::Malformed)?;
		if length > self.ceiling {
			return Err(PartFault::Malformed);
		}

		let end = PREFIX + length;
		if self.bytes.len() < end {
			return Ok(None);
		}

		let frame = Frame::from_der(&self.bytes[PREFIX..end]).map_err(|_| PartFault::Malformed);
		self.bytes.drain(..end);
		frame.map(Some)
	}
}

/// The parts of a stream as they arrive, in chunks of any size.
struct PartReader {
	body: StreamBody,
	buffer: PartBuffer,
}

impl PartReader {
	fn new(body: StreamBody, ceiling: usize) -> Self {
		Self { body, buffer: PartBuffer::new(ceiling) }
	}

	/// Read each later part under `ceiling`.
	fn bound(&mut self, ceiling: usize) {
		self.buffer.ceiling = ceiling;
	}

	/// The frame of the next part, or `None` once the stream ends between
	/// parts. A cancelled read keeps every chunk it took.
	///
	/// # Errors
	///
	/// - The [`PartFault`] of a part that does not read.
	async fn next(&mut self) -> Result<Option<Frame>, PartFault> {
		loop {
			if let Some(frame) = self.buffer.split()? {
				return Ok(Some(frame));
			}

			match self.body.chunk().await {
				Ok(Some(chunk)) => self.buffer.extend(&chunk),
				Ok(None) if self.buffer.is_empty() => return Ok(None),
				Ok(None) => return Err(PartFault::Broken(None)),
				Err(error) => return Err(PartFault::Broken(error.transit_status())),
			}
		}
	}

	/// What follows the last part of the stream: `None` once the stream ends,
	/// or fails, with no byte after that part, and the frame of a part that
	/// follows it.
	///
	/// # Errors
	///
	/// - The [`PartFault`] of bytes after the last part that do not read whole.
	async fn rest(&mut self) -> Result<Option<Frame>, PartFault> {
		match self.next().await {
			Err(PartFault::Broken(_)) if self.buffer.is_empty() => Ok(None),
			read => read,
		}
	}

	/// Read the stream to its end, or to its failure, and drop what it carries.
	async fn drain(&mut self) {
		while let Ok(Some(_)) = self.body.chunk().await {}
	}
}

/// The order and the count of the parts of one stream in one direction: each
/// part answers the id of its call at the next order from 1, and the messages
/// keep to the arity of the side.
struct PartOrder {
	request_id: Vec<u8>,
	next: u64,
	arity: Arity,
	messages: u32,
}

impl PartOrder {
	/// The requests of a stream of `shape` for the call `request_id`.
	fn requests(request_id: &[u8], shape: Shape) -> Self {
		Self::of(request_id, shape.requests())
	}

	/// The answers of a stream of `shape` for the call `request_id`.
	fn answers(request_id: &[u8], shape: Shape) -> Self {
		Self::of(request_id, shape.responses())
	}

	fn of(request_id: &[u8], arity: Arity) -> Self {
		Self { request_id: request_id.to_vec(), next: 1, arity, messages: 0 }
	}

	/// The order of the next message of this side, or `None` when its arity
	/// takes no further message.
	fn next_message(&self) -> Option<u64> {
		self.arity.admits_another(self.messages).then_some(self.next)
	}

	/// Take the order of the next message of this side, or `None` when its
	/// arity takes no further message.
	fn take_message(&mut self) -> Option<u64> {
		let order = self.next_message()?;
		self.messages += 1;
		self.next += 1;
		Some(order)
	}

	fn take(&mut self) -> u64 {
		let order = self.next;
		self.next += 1;
		order
	}

	/// Whether this side may end with status 0 now.
	fn closes(&self) -> bool {
		self.arity.closes(self.messages)
	}

	/// The order of the part that ends this side with `code`.
	///
	/// # Errors
	///
	/// - [`PartFault::Breach`] -- status 0 short of the arity of the side.
	fn end(&mut self, code: Code) -> Result<u64, PartFault> {
		if code == Code::Ok && !self.closes() {
			return Err(PartFault::Breach);
		}

		Ok(self.take())
	}

	/// End this side with no part, as the requests of a stream end.
	///
	/// # Errors
	///
	/// - [`PartFault::Breach`] -- the arity of the side takes a message that never came.
	fn finish(&self) -> Result<(), PartFault> {
		if !self.closes() {
			return Err(PartFault::Breach);
		}

		Ok(())
	}

	/// The part that `frame` carries, once it answers the id of the call at
	/// the next order.
	///
	/// # Errors
	///
	/// - [`PartFault::Refused`] -- the part answers another call, comes out of order, or does not decode.
	fn placed(&self, frame: &Frame) -> Result<CoupledPart, PartFault> {
		let metadata = frame.metadata();
		let placed = metadata.id() == self.request_id.as_slice() && metadata.order() == self.next;
		if !placed {
			return Err(PartFault::Refused);
		}

		frame.decode_message().map_err(|_| PartFault::Refused)
	}

	/// The message of the request part `frame`, once it is in place and keeps
	/// to the arity.
	///
	/// # Errors
	///
	/// - The errors of [`PartOrder::placed`].
	/// - [`PartFault::Malformed`] -- an end, because the requests end by a close.
	/// - [`PartFault::Breach`] -- a message past the arity.
	fn request(&mut self, frame: &Frame) -> Result<OctetString, PartFault> {
		let message = self.placed(frame)?.part.carried().map_err(|_| PartFault::Malformed)?;
		self.take_message().ok_or(PartFault::Breach)?;
		Ok(message)
	}

	/// What the answer part `frame` carries, once it is in place and keeps to
	/// the arity: a message, or as `Err` the reply that ends the answer.
	///
	/// # Errors
	///
	/// - The errors of [`PartOrder::placed`].
	/// - [`PartFault::Breach`] -- a message past the arity, or an end of status 0 short of it.
	fn answer(&mut self, frame: &Frame) -> Result<Result<OctetString, CoupledReply>, PartFault> {
		let carried = self.placed(frame)?.part.carried();
		match &carried {
			Ok(_) => {
				self.take_message().ok_or(PartFault::Breach)?;
			}
			Err(end) => {
				self.end(end.code())?;
			}
		}

		Ok(carried)
	}
}

/// Whose key signs the parts that a stream admits.
enum PartVerifier {
	/// The servlet of a route, whose pinned signer signs its answers.
	Pinned(Servlet),
	/// The signer of the head that a servlet admitted.
	Admitted(AdmittedSigner),
}

impl PartVerifier {
	fn verifies(&self, frame: &Frame) -> bool {
		match self {
			Self::Pinned(servlet) => servlet.verifies(frame),
			Self::Admitted(signer) => signer.verifies(frame),
		}
	}
}

/// The parts that a stream admits: each one read whole, verified under its
/// signer, and in order.
struct PartStream {
	reader: PartReader,
	order: PartOrder,
	verifier: PartVerifier,
}

impl PartStream {
	/// The frame of the next part, verified under its signer, or `None` once
	/// the stream ends between parts.
	///
	/// # Errors
	///
	/// - The [`PartFault`] of a part that does not read or does not verify.
	async fn next(&mut self) -> Result<Option<Frame>, PartFault> {
		let Some(frame) = self.reader.next().await? else {
			return Ok(None);
		};

		if !self.verifier.verifies(&frame) {
			return Err(PartFault::Refused);
		}

		Ok(Some(frame))
	}

	/// The next request message, or `None` once the requests end by a close.
	///
	/// # Errors
	///
	/// - The [`PartFault`] of a part that does not read or does not admit, or
	///   of requests that end short of their arity.
	async fn request(&mut self) -> Result<Option<OctetString>, PartFault> {
		match self.next().await? {
			Some(frame) => self.order.request(&frame).map(Some),
			None => self.order.finish().map(|()| None),
		}
	}

	/// What the next answer part carries: a message, or as `Err` the reply
	/// that ends the answer. `None` once the stream ends between parts.
	///
	/// # Errors
	///
	/// - The [`PartFault`] of a part that does not read or does not admit.
	async fn answer(&mut self) -> Result<Option<Result<OctetString, CoupledReply>>, PartFault> {
		let Some(frame) = self.next().await? else {
			return Ok(None);
		};

		self.order.answer(&frame).map(Some)
	}
}

impl PartStream {
	/// Read the stream to its end after its last part, so the party that
	/// relays it finishes cleanly. A stream that fails with no byte after the
	/// last part leaves the status to that part, as when a gateway cancels a
	/// stream whose servlet ended before its requests did.
	///
	/// # Errors
	///
	/// - [`PartFault::Refused`] -- a part follows the last one.
	/// - The errors of [`PartReader::rest`].
	async fn finish(&mut self) -> Result<(), PartFault> {
		match self.reader.rest().await? {
			None => Ok(()),
			Some(_) => Err(PartFault::Refused),
		}
	}
}

/// Why a part does not send, where `F` is why a push of its channel fails.
#[derive(Debug)]
enum SendFault<F> {
	/// The arity of the side takes no further message, or no end yet.
	Breach,
	/// The part passes its ceiling.
	Oversize,
	/// The frame does not build or sign.
	Build(TightBeamError),
	/// The channel refused the push.
	Channel(F),
}

impl<F> fmt::Display for SendFault<F> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Breach => f.write_str("the side takes no further message, or no end yet"),
			Self::Oversize => f.write_str("the part passes its ceiling"),
			Self::Build(_) => f.write_str("the frame of the part does not build or sign"),
			Self::Channel(_) => f.write_str("the channel refused the push of the part"),
		}
	}
}

impl<F: Error + 'static> Error for SendFault<F> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Build(error) => Some(error),
			Self::Channel(fault) => Some(fault),
			Self::Breach | Self::Oversize => None,
		}
	}
}

impl SendFault<TransportError> {
	/// How the requests of the coupler end when a request part fails so. A
	/// push that the stream resolved under is severed, and any other failure
	/// is a fault of the call.
	fn of_request(self) -> ForwardEnd {
		match self {
			Self::Breach => ForwardEnd::Fault(CallFault::Shape),
			Self::Oversize => ForwardEnd::Fault(CallFault::Oversize),
			Self::Build(_) => ForwardEnd::Fault(CallFault::Internal),
			Self::Channel(
				TransportError::OperationFailed(TransportFailure::Cancelled) | TransportError::ConnectionClosed,
			) => ForwardEnd::Severed,
			Self::Channel(_) => ForwardEnd::Fault(CallFault::Unavailable),
		}
	}
}

/// How the requests of a coupled stream stop short of their close.
enum ForwardEnd {
	/// The fault that ends the call.
	Fault(CallFault),
	/// The stream resolved under a push or the close, as when the servlet
	/// ended it first, so the answer of the stream decides the call.
	Severed,
}

/// An answer part that does not send ends its stream with the status that
/// the peer reads too: 12 for a count of messages that the method does not
/// take, and 8 for a part past its ceiling.
impl From<SendFault<AnswerFault>> for TightBeamError {
	fn from(fault: SendFault<AnswerFault>) -> Self {
		match fault {
			SendFault::Breach => TransportError::from(TransitStatus::Unimplemented).into(),
			SendFault::Oversize => TransportError::from(TransitStatus::ResourceExhausted).into(),
			SendFault::Build(error) => error,
			SendFault::Channel(refused) => refused.into(),
		}
	}
}

/// The sink that carries the parts of one side of a stream: the requests of
/// a coupler, or the answers of a servlet.
trait PartChannel {
	/// Why a push of the channel fails.
	type Fault;

	/// Push the bytes of one part.
	fn push<'a>(&'a mut self, bytes: &'a [u8]) -> impl Future<Output = Result<(), Self::Fault>> + Send + 'a;
}

/// The requests of a coupler, whose relay sends no part after a push that it
/// ends: it drops the sink, or closes it once the answer decided the call.
impl PartChannel for RequestSink {
	type Fault = TransportError;

	fn push<'a>(&'a mut self, bytes: &'a [u8]) -> impl Future<Output = Result<(), TransportError>> + Send + 'a {
		RequestSink::push(self, bytes)
	}
}

/// How the last push of the answers of a servlet ended, which decides whether
/// the next part may send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnswerState {
	/// Every push landed.
	Open,
	/// A push stopped before it landed, as when a timeout drops it, so part of
	/// its part may be on the stream.
	Cut,
	/// A push failed on the stream.
	Failed,
}

/// Why an answer part does not push.
#[derive(Debug)]
enum AnswerFault {
	/// The stream failed the push.
	Transport(TransportError),
	/// An earlier push stopped before it landed.
	Cut,
	/// An earlier push failed on the stream.
	Failed,
}

impl fmt::Display for AnswerFault {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Transport(_) => f.write_str("the stream failed the push"),
			Self::Cut => f.write_str("an earlier push stopped before it landed"),
			Self::Failed => f.write_str("an earlier push failed on the stream"),
		}
	}
}

impl Error for AnswerFault {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Transport(error) => Some(error),
			Self::Cut | Self::Failed => None,
		}
	}
}

/// A part after a push that stopped ends its stream with 4, as the deadline
/// that cut the push does, and a part after a failed push with 14.
impl From<AnswerFault> for TightBeamError {
	fn from(fault: AnswerFault) -> Self {
		match fault {
			AnswerFault::Transport(error) => error.into(),
			AnswerFault::Cut => TransportError::from(TransitStatus::DeadlineExceeded).into(),
			AnswerFault::Failed => TransportError::from(TransitStatus::Unavailable).into(),
		}
	}
}

/// The answers of a servlet, which outlive a push that a timeout of the
/// servlet drops, and how their last push ended.
struct AnswerChannel {
	reply: ReplySink,
	state: AnswerState,
}

impl AnswerChannel {
	/// The answers on `reply`, before any push.
	fn new(reply: ReplySink) -> Self {
		Self { reply, state: AnswerState::Open }
	}
}

/// The channel stays cut from the start of a push until it lands, and fails
/// with the push that fails.
impl PartChannel for AnswerChannel {
	type Fault = AnswerFault;

	async fn push(&mut self, bytes: &[u8]) -> Result<(), AnswerFault> {
		match self.state {
			AnswerState::Open => {}
			AnswerState::Cut => return Err(AnswerFault::Cut),
			AnswerState::Failed => return Err(AnswerFault::Failed),
		}

		self.state = AnswerState::Cut;
		let pushed = self.reply.push(bytes).await;
		self.state = match pushed {
			Ok(()) => AnswerState::Open,
			Err(_) => AnswerState::Failed,
		};
		pushed.map_err(AnswerFault::Transport)
	}
}

/// The parts that one side of a stream sends on its sink `S`: each one signed
/// under the one signer of the side, in order, and within the ceiling. The
/// requests of a coupler end by a close, and the answers of a servlet by an
/// end part.
///
/// - A message takes its order once its push lands, so a refused part leaves
///   no gap.
struct PartSink<S> {
	sink: S,
	order: PartOrder,
	signer: SigningIdentity,
	ceiling: usize,
}

impl<S: PartChannel> PartSink<S> {
	/// The parts of `order` on `sink`, signed under `signer`, within `ceiling`.
	fn new(sink: S, order: PartOrder, signer: SigningIdentity, ceiling: usize) -> Self {
		Self { sink, order, signer, ceiling }
	}

	/// Send `body` as the next message.
	///
	/// # Errors
	///
	/// - The [`SendFault`] of a part that does not send.
	async fn send(&mut self, body: Vec<u8>) -> Result<(), SendFault<S::Fault>> {
		let order = self.order.next_message().ok_or(SendFault::Breach)?;
		let message = OctetString::new(body).map_err(|_| SendFault::Oversize)?;
		self.push(order, PartWire::Message(message)).await?;
		self.order.take_message();
		Ok(())
	}

	/// Sign `part` at `order` and push it.
	///
	/// # Errors
	///
	/// - The [`SendFault`] of a part that does not send.
	async fn push(&mut self, order: u64, part: PartWire) -> Result<(), SendFault<S::Fault>> {
		let signed = CoupledPart::signed(&self.order.request_id, order, part, &self.signer).await;
		let frame = signed.map_err(SendFault::Build)?;
		let framed = FramedPart::of(&frame, self.ceiling).ok_or(SendFault::Oversize)?;
		self.sink.push(framed.as_bytes()).await.map_err(SendFault::Channel)
	}
}

impl PartSink<RequestSink> {
	/// End the requests of a coupler.
	///
	/// # Errors
	///
	/// - [`SendFault::Breach`] -- the arity of the side takes a message that never came.
	/// - [`SendFault::Channel`] -- the stream failed.
	async fn close(self) -> Result<(), SendFault<TransportError>> {
		self.order.finish().map_err(|_| SendFault::Breach)?;
		self.sink.close().await.map_err(SendFault::Channel)
	}

	/// End the requests of a call that its answer decided, whatever their
	/// count, so a servlet that holds its stream until they end lets it go. A
	/// close that fails meets a stream that resolved already, whose end the
	/// relay then reads.
	async fn release(self) {
		let _ = self.sink.close().await;
	}
}

impl PartSink<AnswerChannel> {
	/// End the answers of a servlet with `end`, the status of an answer.
	///
	/// # Errors
	///
	/// - The [`SendFault`] of a part that does not send.
	async fn end(mut self, end: CoupledReply) -> Result<(), SendFault<AnswerFault>> {
		let order = self.order.end(end.code()).map_err(|_| SendFault::Breach)?;
		self.push(order, PartWire::End(end)).await
	}
}

/// A coupled stream that its servlet admitted from its duplex arm: its
/// origin, the messages that its caller sends, and the answer that the
/// servlet streams back under one signer.
///
/// - [`AdmittedStream::split`] parts the two directions, which the servlet
///   reads and answers through, each on its own.
pub struct AdmittedStream {
	origin: Origin,
	shape: StreamShape,
	requests: StreamRequests,
	answers: StreamAnswers,
}

impl AdmittedStream {
	/// Admit the stream of `body` by `trust`, with `reply` answering under
	/// `signer`.
	///
	/// - The first part is a head that admits as
	///   [`AdmittedCall::admit`](super::AdmittedCall::admit) admits a call
	///   with an empty body, so a claim on a stream covers its method and its
	///   TLS certificate.
	/// - The head fixes the shape of the method, so each side keeps its count of messages.
	/// - The head fixes the ceiling of every later part, at most that of `trust`.
	/// - Every later part must verify under the signer of the head.
	///
	/// Each error ends the stream with a status that the caller reads.
	///
	/// # Errors
	///
	/// Each refusal is the [`TightBeamError`] of its status:
	///
	/// - [`TransitStatus::Unauthenticated`] -- the head does not admit.
	/// - [`TransitStatus::InvalidArgument`] -- the stream carries no head, or
	///   its head is malformed, carries a body, or names no stream.
	/// - [`TransitStatus::ResourceExhausted`] -- the head declares a ceiling past that of `trust`.
	/// - [`TransitStatus::Unavailable`] -- the stream failed before its head.
	pub async fn admit(
		body: StreamBody,
		reply: ReplySink,
		trust: &AdmissionTrust,
		signer: SigningIdentity,
	) -> Result<Self, TightBeamError> {
		let mut reader = PartReader::new(body, trust.part_ceiling());
		let head = reader.next().await.map_err(PartFault::of_request)?;
		let head = head.ok_or_else(|| PartFault::Malformed.of_request())?;
		let refused = |fault: AdmissionFault| TightBeamError::from(TransportError::from(fault.status()));
		let AdmittedHead { origin, shape, ceiling, signer: admitted } =
			Origin::of_head(&head, trust).map_err(refused)?;
		reader.bound(ceiling);

		let order = PartOrder::requests(origin.request_id(), shape.into());
		let parts = PartStream { reader, order, verifier: PartVerifier::Admitted(admitted) };
		let order = PartOrder::answers(origin.request_id(), shape.into());
		let answers = PartSink::new(AnswerChannel::new(reply), order, signer, ceiling);
		let requests = StreamRequests { parts };
		let answers = StreamAnswers { answers };

		Ok(Self { origin, shape, requests, answers })
	}

	/// Who opened the stream, and what it carries beside its messages.
	pub fn origin(&self) -> &Origin {
		&self.origin
	}

	/// The origin, the requests, and the answers of the stream, apart.
	pub fn split(self) -> AdmittedStreamParts {
		AdmittedStreamParts { origin: self.origin, requests: self.requests, answers: self.answers }
	}

	/// How many messages each side of the stream sends, as its head declared.
	pub(crate) fn shape(&self) -> StreamShape {
		self.shape
	}
}

/// An admitted stream, apart, as [`AdmittedStream::split`] gives it.
pub struct AdmittedStreamParts {
	/// Who opened the stream, and what it carries beside its messages.
	pub origin: Origin,
	/// The messages that the caller sends.
	pub requests: StreamRequests,
	/// The answer that the servlet sends.
	pub answers: StreamAnswers,
}

/// The messages that the caller of an admitted stream sends, each verified
/// under the signer of its head and in order.
pub struct StreamRequests {
	parts: PartStream,
}

impl StreamRequests {
	/// The next message of the caller, or `None` once the caller ends its
	/// requests.
	///
	/// Each error ends the stream with a status that the caller reads.
	///
	/// # Errors
	///
	/// Each refusal is the [`TightBeamError`] of its status:
	///
	/// - [`TransitStatus::Unauthenticated`] -- a part does not verify under the signer of the head, answers
	///   another call, comes out of order, or does not decode as a part.
	/// - [`TransitStatus::InvalidArgument`] -- a part is malformed, or carries an end.
	/// - [`TransitStatus::Unimplemented`] -- a count of requests that the method does not take.
	/// - [`TransitStatus::Unavailable`] -- the stream failed.
	pub async fn next(&mut self) -> Result<Option<Vec<u8>>, TightBeamError> {
		let message = self.parts.request().await.map_err(PartFault::of_request)?;
		Ok(message.map(OctetString::into_bytes))
	}
}

/// The answer of an admitted stream, which the servlet sends under its one
/// signer.
pub struct StreamAnswers {
	answers: PartSink<AnswerChannel>,
}

impl StreamAnswers {
	/// Send `body` as the next response message.
	///
	/// # Errors
	///
	/// - [`TransitStatus::ResourceExhausted`] -- the part passes the ceiling that the head of the stream
	///   declared.
	/// - [`TransitStatus::Unimplemented`] -- the method takes no further response message.
	/// - [`TransitStatus::DeadlineExceeded`] -- an earlier push stopped before it landed.
	/// - [`TransitStatus::Unavailable`] -- an earlier push failed on the stream.
	/// - The [`TightBeamError`] of a part that does not build, sign, or send.
	pub async fn send(&mut self, body: impl Into<Vec<u8>>) -> Result<(), TightBeamError> {
		Ok(self.answers.send(body.into()).await?)
	}

	/// End the answer of the stream of `requests` with status 0.
	///
	/// # Errors
	///
	/// - The errors of [`StreamAnswers::end`].
	pub async fn finish(self, requests: StreamRequests) -> Result<(), TightBeamError> {
		self.end(requests, &Status::new(Code::Ok, "")).await
	}

	/// End the answer of the stream of `requests` with `status`: its code, its
	/// message, and its details.
	///
	/// The end then holds the stream until the caller ends its requests, and
	/// drops each request that comes, so a gateway relays the last answer part
	/// before the stream ends. A coupler ends its requests once it reads that
	/// part.
	///
	/// # Errors
	///
	/// - [`TransitStatus::Unimplemented`] -- `status` is 0, and the method takes a response message that
	///   never came.
	/// - The errors of [`StreamAnswers::send`].
	pub async fn end(self, requests: StreamRequests, status: &Status) -> Result<(), TightBeamError> {
		let end = CoupledReply::of_status(status, Vec::new())?;
		self.answers.end(end).await?;
		let StreamRequests { mut parts } = requests;
		parts.reader.drain().await;
		Ok(())
	}
}

/// A coupled stream whose head left: what its relay takes over, and the
/// terms its head declared.
pub(crate) struct OpenStream {
	hold: CallHold,
	request_id: RequestId,
	terms: StreamTerms,
	sink: RequestSink,
	body: StreamBody,
	/// The relay permit of the coupler, which the stream holds to its end.
	permit: OwnedSemaphorePermit,
}

impl OpenStream {
	/// The stream of the call that `hold` holds, whose `head` left on the
	/// sink of `opened`, and whose answer arrives on its body, under the relay
	/// `permit`.
	pub(crate) fn new(hold: CallHold, head: &HeadPart, opened: OpenedDuplex, permit: OwnedSemaphorePermit) -> Self {
		let OpenedDuplex { sink, body } = opened;
		Self { hold, request_id: *head.id(), terms: *head.terms(), sink, body, permit }
	}
}

/// The relay of one open coupled stream, on a task that owns the stream, its
/// lane, and its permit.
///
/// - Each request of the caller leaves as a part signed under the voucher.
/// - Each answer part verifies under the pinned signer of the route.
/// - The task ends at the deadline of the call, however slowly either side
///   reads.
pub(crate) struct StreamRelay {
	open: OpenStream,
	requests: Streaming<Vec<u8>>,
	signer: SigningIdentity,
	ending: CallEnding,
}

impl StreamRelay {
	pub(crate) fn new(
		open: OpenStream,
		requests: Streaming<Vec<u8>>,
		signer: SigningIdentity,
		ending: CallEnding,
	) -> Self {
		Self { open, requests, signer, ending }
	}

	/// Start the relay, and give the response stream of the caller.
	pub(crate) fn spawn(self) -> RelayStream {
		let (sender, answers) = mpsc::channel(ANSWER_BACKLOG);
		let task = tokio::spawn(self.run(sender));
		RelayStream { answers, task: Some(task) }
	}

	/// Relay the stream until its last answer part decides it, its deadline
	/// passes, or the caller drops its response, close the tail of a decided
	/// stream, free its slot and its relay permit, record its end, and give
	/// the status that ends the response.
	///
	/// - A caller that drops its response while the tail closes stops the
	///   tail, and the decided end stays.
	async fn run(self, answers: mpsc::Sender<Vec<u8>>) -> Result<(), Status> {
		let Self { open, requests, signer, ending } = self;
		let OpenStream { hold, request_id, terms, sink, body, permit } = open;
		let ceiling = terms.ceiling();
		let expires = hold.expires();

		let order = PartOrder::requests(request_id.as_bytes(), terms.shape());
		let upstream = PartSink::new(sink, order, signer, ceiling);
		let reader = PartReader::new(body, ceiling);
		let order = PartOrder::answers(request_id.as_bytes(), terms.shape());
		let verifier = PartVerifier::Pinned(hold.servlet().clone());
		let downstream = PartStream { reader, order, verifier };

		let gone = answers.clone();
		let relayed = expires.bound(Self::relay(requests, upstream, downstream, answers));
		let decided = tokio::select! {
			relayed = relayed => relayed.unwrap_or_else(|lapse| Err(lapse.into())),
			() = gone.closed() => Err(CallFault::Cancelled),
		};

		let end = match decided {
			Ok((end, tail)) => {
				let closed = tokio::select! {
					closed = tail.close(expires) => closed,
					() = gone.closed() => Ok(()),
				};
				closed.map(|()| end)
			}
			Err(fault) => Err(fault),
		};

		drop((hold, permit));
		ending.end(end.as_ref().map(CoupledReply::code).map_err(|fault| *fault));

		let answered = end.map_err(|fault| fault.status())?;
		answered.into_result().map(|_| ())
	}

	/// Each direction of the stream on its own, until the answer reads its
	/// last part or a request fails with a fault of the call. Requests that
	/// end, or that the stream resolved under, leave the end to the answer.
	/// A decided stream gives its end and its tail.
	async fn relay(
		requests: Streaming<Vec<u8>>,
		upstream: PartSink<RequestSink>,
		mut downstream: PartStream,
		answers: mpsc::Sender<Vec<u8>>,
	) -> Result<(CoupledReply, StreamTail), CallFault> {
		let mut upstream = Some(upstream);
		let forward = async {
			if let Err(ForwardEnd::Fault(fault)) = Self::forward(requests, &mut upstream).await {
				return Err(fault);
			}

			core::future::pending::<Result<CoupledReply, CallFault>>().await
		};

		let end = tokio::select! {
			end = Self::answer(&mut downstream, answers) => end,
			end = forward => end,
		}?;

		Ok((end, StreamTail { upstream, downstream }))
	}

	/// Send each request of the caller on as a signed part, then close the
	/// requests, which `upstream` holds until then.
	///
	/// # Errors
	///
	/// - [`ForwardEnd::Severed`] -- the stream resolved under a push or the close.
	/// - [`ForwardEnd::Fault`] -- the fault of the call:
	///   - [`CallFault::Shape`] -- the caller sends a count of messages that the method does not take.
	///   - [`CallFault::Oversize`] -- a part passes the ceiling of the edge.
	///   - [`CallFault::Refused`] -- tonic refuses a request message, such as one past the ceiling.
	///   - [`CallFault::Internal`] -- a part does not build or sign.
	///   - [`CallFault::Unavailable`] -- the stream to the servlet refused a part.
	async fn forward(
		mut requests: Streaming<Vec<u8>>,
		upstream: &mut Option<PartSink<RequestSink>>,
	) -> Result<(), ForwardEnd> {
		let refused = |status: Status| ForwardEnd::Fault(status.into());
		if let Some(sink) = upstream.as_mut() {
			while let Some(message) = requests.message().await.map_err(refused)? {
				sink.send(message).await.map_err(SendFault::of_request)?;
			}
		}

		match upstream.take() {
			Some(sink) => sink.close().await.map_err(SendFault::of_request),
			None => Ok(()),
		}
	}

	/// Hand each answer message to the caller, and give the status that the
	/// last answer part carries.
	///
	/// # Errors
	///
	/// - The [`CallFault`] of an answer part that does not admit.
	/// - [`CallFault::AnswerRefused`] -- the answer ends with no status.
	/// - [`CallFault::Cancelled`] -- the caller dropped its response.
	async fn answer(downstream: &mut PartStream, answers: mpsc::Sender<Vec<u8>>) -> Result<CoupledReply, CallFault> {
		loop {
			let part = downstream.answer().await.map_err(PartFault::of_answer)?;
			match part {
				Some(Ok(message)) => {
					let handed = answers.send(message.into_bytes()).await;
					handed.map_err(|_| CallFault::Cancelled)?;
				}
				Some(Err(end)) => return Ok(end),
				None => return Err(CallFault::AnswerRefused),
			}
		}
	}
}

/// What follows the last answer part of a coupled stream, which that part
/// decided: the requests that are still open, and the rest of the stream.
struct StreamTail {
	upstream: Option<PartSink<RequestSink>>,
	downstream: PartStream,
}

impl StreamTail {
	/// End the requests that are still open, then read the stream to its end
	/// before `expires`. The tail may only refuse a part that follows the last
	/// one, and a tail that passes `expires` keeps the decided end.
	///
	/// # Errors
	///
	/// - The [`CallFault`] of a part after the last answer part, or of bytes after it that do not read whole.
	async fn close(self, expires: &Deadline) -> Result<(), CallFault> {
		let Self { upstream, mut downstream } = self;
		let tail = async move {
			if let Some(open) = upstream {
				open.release().await;
			}

			downstream.finish().await
		};

		match expires.bound(tail).await {
			Ok(finished) => finished.map_err(PartFault::of_answer),
			Err(_) => Ok(()),
		}
	}
}

/// The response stream of a coupled stream: the messages of its relay, then
/// the status that ended it. Its drop closes the answers, so the relay ends
/// and records the call as cancelled.
pub(crate) struct RelayStream {
	answers: mpsc::Receiver<Vec<u8>>,
	task: Option<JoinHandle<Result<(), Status>>>,
}

impl Stream for RelayStream {
	type Item = Result<Vec<u8>, Status>;

	fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let this = self.get_mut();
		if let Some(message) = ready!(this.answers.poll_recv(cx)) {
			return Poll::Ready(Some(Ok(message)));
		}

		let Some(task) = this.task.as_mut() else {
			return Poll::Ready(None);
		};

		let ended = ready!(Pin::new(task).poll(cx));
		this.task = None;
		match ended {
			Ok(Ok(())) => Poll::Ready(None),
			Ok(Err(status)) => Poll::Ready(Some(Err(status))),
			Err(_) => Poll::Ready(Some(Err(Status::internal("the relay of the stream failed")))),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// An unsigned frame of `part` at `order` in the call `id`.
	fn part(id: &[u8], order: u64, part: PartWire) -> Frame {
		let draft = Version::V1.compose().with_id(id).with_order(order);
		draft.with_message(CoupledPart { part }).build().expect("a part frame builds")
	}

	fn message(body: &[u8]) -> PartWire {
		PartWire::Message(OctetString::new(body.to_vec()).expect("a message encodes"))
	}

	fn end(code: Code) -> PartWire {
		let status = Status::new(code, "");
		PartWire::End(CoupledReply::of_status(&status, Vec::new()).expect("an end encodes"))
	}

	/// The framed bytes of a part of 300 bytes, at order 1 of the call `call`.
	fn framed() -> (Frame, FramedPart) {
		let frame = part(b"call", 1, message(&[7; 300]));
		let framed = FramedPart::of(&frame, 4096).expect("the part fits");
		(frame, framed)
	}

	/// What `buffer` splits after the first `taken` bytes of the framed part.
	fn split_after(mut buffer: PartBuffer, taken: usize) -> Result<Option<Frame>, PartFault> {
		let (_, framed) = framed();
		buffer.extend(&framed.as_bytes()[..taken]);
		buffer.split()
	}

	tightbeam::tb_cases! {
		fn a_part_short_of_its_bytes_waits(taken: usize) {
			assert_eq!(split_after(PartBuffer::new(4096), taken), Ok(None));
		}

		cases {
			under_its_prefix => 3,
			short_of_its_length => 103,
		}
	}

	#[test]
	fn a_whole_part_reads_once_and_empties_the_buffer() {
		let (frame, framed) = framed();
		let mut buffer = PartBuffer::new(4096);
		buffer.extend(framed.as_bytes());

		let read = buffer.split();
		assert_eq!((read, buffer.is_empty()), (Ok(Some(frame)), true));
	}

	#[test]
	fn a_sender_refuses_a_part_past_its_ceiling() {
		let (frame, _) = framed();
		assert!(FramedPart::of(&frame, 100).is_none());
	}

	#[test]
	fn a_reader_refuses_a_declared_length_past_its_ceiling() {
		let (_, framed) = framed();
		assert_eq!(
			split_after(PartBuffer::new(100), framed.as_bytes().len()),
			Err(PartFault::Malformed)
		);
	}

	tightbeam::tb_cases! {
		fn a_part_out_of_place_is_refused((id, order): (&'static [u8], u64)) {
			let mut placed = PartOrder::answers(b"call", Shape::Bidi);
			let _first = placed.answer(&part(b"call", 1, message(b"a")));
			assert_eq!(placed.answer(&part(id, order, message(b"b"))), Err(PartFault::Refused));
		}

		cases {
			a_repeat => (b"call", 1),
			a_gap => (b"call", 3),
			another_call => (b"other", 2),
		}
	}

	#[test]
	fn the_next_part_in_place_is_accepted() {
		let mut placed = PartOrder::answers(b"call", Shape::Bidi);
		let _first = placed.answer(&part(b"call", 1, message(b"a")));
		assert!(placed.answer(&part(b"call", 2, message(b"b"))).is_ok());
	}

	#[test]
	fn a_side_of_one_message_refuses_a_second() {
		let mut twice = PartOrder::answers(b"call", Shape::Unary);
		let _first = twice.answer(&part(b"call", 1, message(b"a")));
		assert_eq!(twice.answer(&part(b"call", 2, message(b"b"))), Err(PartFault::Breach));
	}

	#[test]
	fn a_request_side_end_short_of_its_count_is_malformed() {
		let mut requests = PartOrder::requests(b"call", Shape::ServerStream);
		assert_eq!(
			requests.request(&part(b"call", 1, end(Code::Ok))).map(|_| ()),
			Err(PartFault::Malformed)
		);
	}

	tightbeam::tb_cases! {
		fn a_side_of_one_message_ends_by_its_code((code, expected): (Code, Result<(), PartFault>)) {
			let mut none = PartOrder::answers(b"call", Shape::Unary);
			assert_eq!(none.answer(&part(b"call", 1, end(code))).map(|_| ()), expected);
		}

		cases {
			zero_with_no_message => (Code::Ok, Err(PartFault::Breach)),
			a_failure_with_none => (Code::NotFound, Ok(())),
		}
	}
}
