//! The tunnel call: one bidirectional gRPC call that carries one tightbeam
//! connection. `docs/grpc.md` lists what the edge refuses.
//!
//! # Sources
//!
//! - gRPC over HTTP2, `grpc/grpc` `doc/PROTOCOL-HTTP2.md`:
//!   <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md>
//! - RFC 9110, HTTP Semantics, June 2022, sections 8.3.1, 15.5.6, and 15.5.16:
//!   <https://www.rfc-editor.org/rfc/rfc9110>

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;
use std::net::SocketAddr;

use bytes::{Buf, BufMut};
use http::header::ALLOW;
use http::request::Parts;
use http::{HeaderValue, Request as HttpRequest, Response as HttpResponse, StatusCode};
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::oneshot;
use tokio_stream::Stream;
use tonic::body::Body;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder, Streaming};
use tonic::server::{Grpc, StreamingService};
use tonic::{Request, Response, Status};

#[cfg(feature = "instrument")]
use std::borrow::Cow;

#[cfg(feature = "instrument")]
use tightbeam::trace::{EventValue, TraceCollector};
#[cfg(feature = "instrument")]
use tightbeam::urn::Urn;

#[cfg(feature = "couple")]
use tonic::Code;

#[cfg(feature = "couple")]
use crate::couple::{AccessRefusal, MethodPath};
#[cfg(feature = "instrument")]
use crate::events::EDGE_REFUSED;
#[cfg(all(feature = "instrument", feature = "couple"))]
use crate::events::{BACKEND_CALL_REFUSED, BACKEND_CALL_RELAYED};
use crate::incoming::{Arrivals, Claim, GrpcConnectInfo, LaneRefusal, Ticket};
use crate::io::GrpcStream;

/// The path of the tunnel call, which a proxy in front of the server routes.
pub const TUNNEL_PATH: &str = "/tightbeam.v1.Transport/Connect";

/// A boxed future that a server task can hold.
pub(crate) type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// What the server hands to the accept loop: a tunnel, or a failed TCP accept.
pub(crate) type Arrival = io::Result<Tunnel>;

/// The codec of the tunnel: each message is one envelope, its bytes unchanged.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TunnelCodec;

impl Codec for TunnelCodec {
	type Encode = Vec<u8>;
	type Decode = Vec<u8>;
	type Encoder = TunnelCodec;
	type Decoder = TunnelCodec;

	fn encoder(&mut self) -> Self::Encoder {
		*self
	}

	fn decoder(&mut self) -> Self::Decoder {
		*self
	}
}

impl Encoder for TunnelCodec {
	type Item = Vec<u8>;
	type Error = Status;

	fn encode(&mut self, envelope: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
		dst.put_slice(&envelope);
		Ok(())
	}
}

/// tonic hands the decoder exactly one whole message, which it already held
/// to the message ceiling before it sized a buffer.
impl Decoder for TunnelCodec {
	type Item = Vec<u8>;
	type Error = Status;

	fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Vec<u8>>, Status> {
		let length = src.remaining();
		let envelope = src.copy_to_bytes(length);
		Ok(Some(envelope.into()))
	}
}

/// Why the edge refuses a request that is no gRPC call, which it answers
/// with an HTTP status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeadRefusal {
	/// The method is not `POST`.
	Method,
	/// The content type is not `application/grpc` or a subtype of it.
	MediaType,
}

impl HeadRefusal {
	/// The name that the audit trail records the refusal under.
	#[cfg(feature = "instrument")]
	pub(crate) fn as_str(&self) -> &'static str {
		match self {
			Self::Method => "method",
			Self::MediaType => "media-type",
		}
	}

	/// The response of the refusal: HTTP 405 with `Allow: POST`, or HTTP 415.
	fn response(&self) -> HttpResponse<Body> {
		let mut response = HttpResponse::new(Body::default());
		match self {
			Self::Method => {
				*response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
				response.headers_mut().insert(ALLOW, HeaderValue::from_static("POST"));
			}
			Self::MediaType => *response.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE,
		}

		response
	}
}

/// Why the edge refuses a gRPC call before any session exists, which it
/// answers with a status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallRefusal {
	/// The edge serves no call on the path.
	Path,
	/// The request carries no connection of this server, which only a fault
	/// of the server itself can cause.
	Unconnected,
	/// The lane of the connection refuses the tunnel, for this reason.
	Lane(LaneRefusal),
	/// The queue of tunnels for a caller of `accept` is full.
	QueueFull,
}

impl CallRefusal {
	/// The name that the audit trail records the refusal under.
	#[cfg(feature = "instrument")]
	pub(crate) fn as_str(&self) -> &'static str {
		match self {
			Self::Path => "path",
			Self::Unconnected => "unconnected",
			Self::Lane(refusal) => refusal.as_str(),
			Self::QueueFull => "queue-full",
		}
	}

	/// The gRPC status that a caller reads of the refusal.
	fn status(&self) -> Status {
		match self {
			Self::Path => Status::unimplemented("the edge serves no call on this path"),
			Self::Unconnected => Status::internal("the call carries no connection of this server"),
			Self::Lane(_) => Status::unavailable("the connection cannot carry a tunnel now"),
			Self::QueueFull => Status::unavailable("the server has no room for another tunnel"),
		}
	}
}

/// A refusal of the lane of a connection is the refusal of its tunnel call.
impl From<LaneRefusal> for CallRefusal {
	fn from(refusal: LaneRefusal) -> Self {
		Self::Lane(refusal)
	}
}

/// What the audit trail of an edge records as refused before any session
/// exists: a request, a call, or a connection that never reached the HTTP/2
/// server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EdgeRefusal {
	/// A request that is no gRPC call, which the edge answers with its HTTP
	/// status.
	Head(HeadRefusal),
	/// A call that the edge answers with its status.
	Call(CallRefusal),
	/// A connection whose TLS handshake failed.
	Tls,
	/// A connection that passed neither its PROXY header nor its TLS
	/// handshake before the deadline of its lane.
	Late,
	/// A connection whose wait for its PROXY header and its TLS handshake the
	/// clock of the edge gave no timer.
	NoTimer,
}

#[cfg(feature = "instrument")]
impl EdgeRefusal {
	/// The name that the audit trail records the refusal under.
	pub(crate) fn as_str(&self) -> &'static str {
		match self {
			Self::Head(refusal) => refusal.as_str(),
			Self::Call(refusal) => refusal.as_str(),
			Self::Tls => "tls",
			Self::Late => "late",
			Self::NoTimer => "no-timer",
		}
	}
}

impl From<HeadRefusal> for EdgeRefusal {
	fn from(refusal: HeadRefusal) -> Self {
		Self::Head(refusal)
	}
}

impl From<CallRefusal> for EdgeRefusal {
	fn from(refusal: CallRefusal) -> Self {
		Self::Call(refusal)
	}
}

/// The audit trail of one listener or of one backend adapter, under the
/// `instrument` feature. A trail with no trace, or a build without the
/// feature, records nothing.
///
/// - A listener fixes the trace of its profile when it binds, and every
///   connection task of its server and its coupler share it.
/// - A `couple::Backend` holds one on the trace of `Backend::with_trace`.
#[derive(Default)]
pub(crate) struct EdgeAudit {
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
}

/// A clone records on the trace of the original.
impl Clone for EdgeAudit {
	fn clone(&self) -> Self {
		Self {
			#[cfg(feature = "instrument")]
			trace: self.trace.as_ref().map(TraceCollector::share),
		}
	}
}

impl EdgeAudit {
	/// The trail that records on `trace`.
	#[cfg(feature = "instrument")]
	pub(crate) fn on(trace: Option<TraceCollector>) -> Self {
		Self { trace }
	}

	/// Record `refusal`, then give its HTTP response.
	pub(crate) fn answer(&self, refusal: HeadRefusal) -> HttpResponse<Body> {
		self.refuse(refusal.into());
		refusal.response()
	}

	/// Record `refusal`, then give the status that ends its call.
	pub(crate) fn status(&self, refusal: CallRefusal) -> Status {
		self.refuse(refusal.into());
		refusal.status()
	}

	/// Record `refusal` as [`EDGE_REFUSED`].
	#[cfg(feature = "instrument")]
	pub(crate) fn refuse(&self, refusal: EdgeRefusal) {
		self.record(EDGE_REFUSED, refusal.as_str(), refusal.as_str());
	}

	#[cfg(not(feature = "instrument"))]
	pub(crate) fn refuse(&self, _refusal: EdgeRefusal) {}

	/// Record the relay of a call of `method` of the backend adapter, which
	/// the backend ended with `code`, as [`BACKEND_CALL_RELAYED`].
	#[cfg(all(feature = "instrument", feature = "couple"))]
	pub(crate) fn relayed(&self, method: &MethodPath, code: Code) {
		self.record(BACKEND_CALL_RELAYED, method.as_str().to_owned(), code as i32 as u32);
	}

	#[cfg(all(not(feature = "instrument"), feature = "couple"))]
	pub(crate) fn relayed(&self, _method: &MethodPath, _code: Code) {}

	/// Record a call that the policy of the backend adapter refused for
	/// `refusal`, as [`BACKEND_CALL_REFUSED`].
	#[cfg(all(feature = "instrument", feature = "couple"))]
	pub(crate) fn denied(&self, refusal: AccessRefusal) {
		self.record(BACKEND_CALL_REFUSED, refusal.as_str(), refusal.as_str());
	}

	#[cfg(all(not(feature = "instrument"), feature = "couple"))]
	pub(crate) fn denied(&self, _refusal: AccessRefusal) {}

	/// Record a part of a stream of the backend adapter that failed to admit
	/// or to send, which ended the stream, as [`BACKEND_CALL_REFUSED`] with
	/// `part`.
	#[cfg(all(feature = "instrument", feature = "couple"))]
	pub(crate) fn part_refused(&self) {
		self.record(BACKEND_CALL_REFUSED, "part", "part");
	}

	#[cfg(all(not(feature = "instrument"), feature = "couple"))]
	pub(crate) fn part_refused(&self) {}

	/// Record `event` with `label` and `value`.
	#[cfg(feature = "instrument")]
	pub(crate) fn record(
		&self,
		event: Urn<'static>,
		label: impl Into<Cow<'static, str>>,
		value: impl Into<EventValue>,
	) {
		if let Some(trace) = &self.trace {
			// The trace refuses an event only under the fault that the
			// `testing-fault` feature of tightbeam injects, and the edge
			// carries on either way.
			let _ = trace.emit_event_with_value(event, label, value);
		}
	}
}

/// The parsed head of one tunnel call: the claim that holds its connection,
/// and the address of its peer.
pub(crate) struct TunnelCall {
	claim: Claim,
	peer: SocketAddr,
}

impl TunnelCall {
	/// The tunnel of this call over `messages`, queued for a caller of
	/// `accept`, and the response stream the server answers it with. The
	/// response holds the claim, so the call ends when the response ends.
	fn admit(self, messages: Streaming<Vec<u8>>) -> (Tunnel, Responses) {
		let (sender, receiver) = mpsc::channel(1);
		let (answer, ending) = oneshot::channel();
		let stream = GrpcStream::accepted(messages, sender, answer);

		let tunnel = Tunnel { stream, peer: self.peer, holder: Holder::Call(self.claim.ticket()) };
		let responses = Responses { messages: receiver, ending: Ending::Watching(ending), claim: Some(self.claim) };
		(tunnel, responses)
	}
}

impl TunnelCall {
	/// The tunnel call of `head`, a head on the tunnel path, which claims the
	/// lane of its connection.
	///
	/// # Errors
	///
	/// - [`CallRefusal::Unconnected`] -- the head carries no connection of this server.
	/// - [`CallRefusal::Lane`] -- the lane refuses the tunnel.
	pub(crate) fn claim(head: &Parts) -> Result<Self, CallRefusal> {
		let connection = head.extensions.get::<GrpcConnectInfo>().ok_or(CallRefusal::Unconnected)?;
		let claim = connection.claim_tunnel()?;
		Ok(Self { peer: claim.peer(), claim })
	}
}

/// A tunnel waiting for a caller of `accept`, and what holds its stream.
pub(crate) struct Tunnel {
	stream: GrpcStream,
	peer: SocketAddr,
	holder: Holder,
}

/// What holds the stream of a tunnel.
enum Holder {
	/// A tunnel call on a connection, which the ticket hands to a caller.
	Call(Ticket),
	/// The in-process tunnel of the coupler of the listener, which lives
	/// until the coupler drops its end.
	#[cfg(feature = "couple")]
	Loopback,
}

impl Holder {
	/// Hand the stream to a caller: `false` when its call ended, or a later
	/// call on its connection replaced it.
	fn redeem(&self) -> bool {
		match self {
			Self::Call(ticket) => ticket.redeem(),
			#[cfg(feature = "couple")]
			Self::Loopback => true,
		}
	}
}

impl Tunnel {
	/// The in-process tunnel `stream` of the coupler of the listener bound at
	/// `local`.
	#[cfg(feature = "couple")]
	pub(crate) fn loopback(stream: GrpcStream, local: SocketAddr) -> Self {
		Self { stream, peer: local, holder: Holder::Loopback }
	}

	/// The stream of the tunnel and the address of its peer. A tunnel call
	/// returns the slot of its connection, because a caller now holds it.
	///
	/// `None` when the call ended, or a later call on its connection replaced
	/// it, before a caller took it.
	pub(crate) fn into_stream(self) -> Option<(GrpcStream, SocketAddr)> {
		self.holder.redeem().then_some((self.stream, self.peer))
	}
}

/// Whether a response still watches for the status that ends it.
enum Ending {
	/// The read half may answer a fault of the inbound messages.
	Watching(oneshot::Receiver<Status>),
	/// The read half dropped with no fault, so the messages alone end it.
	Quiet,
	/// The response ended with the fault status.
	Answered,
}

/// The messages the server answers a tunnel call with. The response ends when
/// the write half of the tunnel drops, or at once with the status that failed
/// the inbound messages, and its end ends the call.
pub(crate) struct Responses {
	messages: Receiver<Vec<u8>>,
	ending: Ending,
	/// The claim of the call, which the end of the response drops, before
	/// the server writes its trailers.
	claim: Option<Claim>,
}

impl Stream for Responses {
	type Item = Result<Vec<u8>, Status>;

	fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let this = self.get_mut();
		let next = this.poll_message(cx);
		if let Poll::Ready(None) = next {
			this.claim = None;
		}

		next
	}
}

impl Responses {
	/// The next message of the response, the status that ends it, or `None`
	/// at its end.
	fn poll_message(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Vec<u8>, Status>>> {
		if let Ending::Watching(answer) = &mut self.ending {
			match Pin::new(answer).poll(cx) {
				Poll::Ready(Ok(status)) => {
					self.ending = Ending::Answered;
					return Poll::Ready(Some(Err(status)));
				}
				Poll::Ready(Err(_)) => self.ending = Ending::Quiet,
				Poll::Pending => {}
			}
		}

		if let Ending::Answered = self.ending {
			return Poll::Ready(None);
		}

		let message = self.messages.poll_recv(cx);
		message.map(|envelope| envelope.map(Ok))
	}
}

/// The tunnel arm of the edge: it queues the tunnel of each call it admits for
/// a caller of `accept`.
#[derive(Clone)]
pub(crate) struct TunnelService {
	queue: Arrivals,
	ceiling: usize,
	audit: EdgeAudit,
}

impl TunnelService {
	/// A service that queues each tunnel on `queue`, with every message of
	/// its call held to `ceiling`, and records each refusal on `audit`.
	pub(crate) fn new(queue: Arrivals, ceiling: usize, audit: EdgeAudit) -> Self {
		Self { queue, ceiling, audit }
	}
}

impl TunnelService {
	/// Serve `call`, the claimed tunnel call of `request`, with every message
	/// held to the ceiling of the service.
	pub(crate) async fn serve(&self, call: TunnelCall, request: HttpRequest<Body>) -> HttpResponse<Body> {
		let grpc = Grpc::new(TunnelCodec).max_decoding_message_size(self.ceiling);
		let mut grpc = grpc.max_encoding_message_size(self.ceiling);
		let admission = Admission { call: Some(call), queue: self.queue.clone(), audit: self.audit.clone() };

		grpc.streaming(admission, request).await
	}
}

/// The admission of one parsed call, which tonic runs once it accepts the
/// encoding of the call, before any message decodes.
struct Admission {
	/// tonic calls the admission once, but its trait takes `&mut self`, so the
	/// call moves out of an option.
	call: Option<TunnelCall>,
	queue: Arrivals,
	audit: EdgeAudit,
}

impl StreamingService<Vec<u8>> for Admission {
	type Response = Vec<u8>;
	type ResponseStream = Responses;
	type Future = BoxFuture<Result<Response<Responses>, Status>>;

	fn call(&mut self, request: Request<Streaming<Vec<u8>>>) -> Self::Future {
		let call = self.call.take();
		let queue = self.queue.clone();
		let audit = self.audit.clone();

		Box::pin(async move {
			let call = call.ok_or_else(|| Status::internal("the tunnel admits one call"))?;
			let (tunnel, responses) = call.admit(request.into_inner());
			queue.queue(tunnel).map_err(|refusal| audit.status(refusal))?;
			Ok(Response::new(responses))
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use http::Method;

	/// The head of a call on the tunnel path with no connection.
	fn unconnected() -> Result<Parts, http::Error> {
		let request = HttpRequest::builder().method(Method::POST).uri(TUNNEL_PATH).body(())?;
		let (head, ()) = request.into_parts();
		Ok(head)
	}

	#[test]
	fn a_head_with_no_connection_claims_no_lane() -> Result<(), http::Error> {
		let refused = TunnelCall::claim(&unconnected()?).err();
		assert_eq!(refused, Some(CallRefusal::Unconnected));
		Ok(())
	}

	#[test]
	fn a_request_that_is_no_grpc_call_answers_its_http_status() {
		let method = HeadRefusal::Method.response();
		assert_eq!(method.status(), StatusCode::METHOD_NOT_ALLOWED);
		assert_eq!(method.headers().get(ALLOW).map(HeaderValue::as_bytes), Some(&b"POST"[..]));
		assert_eq!(HeadRefusal::MediaType.response().status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
	}

	tightbeam::tb_cases! {
		fn a_refused_grpc_call_answers_its_status((refusal, expected): (CallRefusal, &str)) {
			let response = refusal.status().into_http::<Body>();
			let status = response.headers().get("grpc-status").map(HeaderValue::as_bytes);
			assert_eq!((response.status(), status), (StatusCode::OK, Some(expected.as_bytes())));
		}

		cases {
			an_unserved_path => (CallRefusal::Path, "12"),
			no_free_slot => (CallRefusal::Lane(LaneRefusal::NoSlot), "14"),
			a_full_queue => (CallRefusal::QueueFull, "14"),
			no_connection => (CallRefusal::Unconnected, "13"),
		}
	}
}
