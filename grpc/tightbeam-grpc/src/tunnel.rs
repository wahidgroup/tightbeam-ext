//! The tunnel call: one bidirectional gRPC call that carries one tightbeam
//! connection.
//!
//! The call travels on [`TUNNEL_PATH`] under `application/grpc`, which tonic
//! writes on both ends, and each of its messages is the DER of one envelope,
//! unwrapped. The service of the edge parses the head of each call once, and
//! hands a call on the tunnel path to [`TunnelService`], which claims its lane
//! as a [`TunnelCall`]. Every call that the edge cannot carry refuses:
//!
//! | The call | Refused with |
//! | --- | --- |
//! | A method other than `POST` | HTTP 405, with `Allow: POST` |
//! | A content type outside `application/grpc` and its `+` subtypes | HTTP 415 |
//! | A path that the edge serves no call on | `grpc-status` 12, `UNIMPLEMENTED` |
//! | A connection with no free slot, or a full queue | `grpc-status` 14, `UNAVAILABLE` |
//!
//! tonic refuses the rest: an encoding other than identity with status 12, a
//! compressed message with no encoding with status 13, and a message past the
//! envelope ceiling with status 11.
//!
//! Under the `instrument` feature, each refusal of the table records on the
//! audit trail of the listener as [`TUNNEL_REFUSED`], before the server
//! answers it.
//!
//! [`TUNNEL_REFUSED`]: crate::events::TUNNEL_REFUSED
//!
//! # Sources
//!
//! - gRPC over HTTP2, `grpc/grpc` `doc/PROTOCOL-HTTP2.md`: <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md>
//! - RFC 9110, HTTP Semantics, June 2022, sections 8.3.1, 15.5.6, and 15.5.16: <https://www.rfc-editor.org/rfc/rfc9110>

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;
use std::net::SocketAddr;

use bytes::{Buf, BufMut};
use http::header::ALLOW;
use http::request::Parts;
use http::{HeaderValue, Request as HttpRequest, Response as HttpResponse, StatusCode};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::oneshot;
use tokio_stream::Stream;
use tonic::body::Body;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder, Streaming};
use tonic::server::{Grpc, StreamingService};
use tonic::{Request, Response, Status};

#[cfg(feature = "instrument")]
use std::sync::{Arc, Mutex, PoisonError};

#[cfg(feature = "instrument")]
use tightbeam::trace::TraceCollector;

#[cfg(feature = "instrument")]
use crate::events::TUNNEL_REFUSED;
use crate::incoming::{Claim, GrpcConnectInfo, Ticket};
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

/// Why the tunnel refuses a call.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
	/// The method is not `POST`.
	Method,
	/// The content type is not `application/grpc` or a subtype of it.
	MediaType,
	/// The edge serves no call on the path.
	Path,
	/// The connection has no free slot, or the queue is full.
	Busy,
	/// The request carries no connection of this server, which only a fault
	/// of the server itself can cause.
	Unconnected,
}

impl Refusal {
	/// The name that the audit trail records the refusal under.
	#[cfg(feature = "instrument")]
	const fn as_str(&self) -> &'static str {
		match self {
			Self::Method => "method",
			Self::MediaType => "media-type",
			Self::Path => "path",
			Self::Busy => "busy",
			Self::Unconnected => "unconnected",
		}
	}
}

/// The audit trail of the refusals of one listener, which every connection
/// task of its server shares: the trace that the listener attaches after it
/// binds, under the `instrument` feature. A trail with no trace, or a build
/// without the feature, records nothing.
#[derive(Clone, Default)]
pub(crate) struct RefusalAudit {
	#[cfg(feature = "instrument")]
	trace: Arc<Mutex<Option<TraceCollector>>>,
}

impl RefusalAudit {
	/// Record every later refusal on `trace`, in place of the trace of an
	/// earlier attach.
	#[cfg(feature = "instrument")]
	pub(crate) fn attach(&self, trace: TraceCollector) {
		let mut attached = self.trace.lock().unwrap_or_else(PoisonError::into_inner);
		*attached = Some(trace);
	}

	/// Record `refusal` on the trail.
	pub(crate) fn refused(&self, refusal: &Refusal) {
		#[cfg(feature = "instrument")]
		{
			let attached = self.trace.lock().unwrap_or_else(PoisonError::into_inner);
			if let Some(trace) = attached.as_ref() {
				let name = refusal.as_str();
				// The trace refuses an event only under the fault that the
				// `testing-fault` feature of tightbeam injects, and the server
				// answers the refusal either way.
				let _ = trace.emit_event_with_value(TUNNEL_REFUSED, name, name);
			}
		}

		#[cfg(not(feature = "instrument"))]
		let _ = refusal;
	}
}

/// The response of each refusal.
impl From<Refusal> for HttpResponse<Body> {
	fn from(refusal: Refusal) -> Self {
		match refusal {
			Refusal::Method => {
				let mut response = Self::new(Body::default());
				*response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
				response.headers_mut().insert(ALLOW, HeaderValue::from_static("POST"));
				response
			}
			Refusal::MediaType => {
				let mut response = Self::new(Body::default());
				*response.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
				response
			}
			Refusal::Path => Status::unimplemented("the edge serves no call on this path").into_http(),
			Refusal::Busy => Status::unavailable("the server has no free slot for a tunnel").into_http(),
			Refusal::Unconnected => Status::internal("the call carries no connection of this server").into_http(),
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
		let responses = Responses { messages: receiver, ending: Ending::Watching(ending), _claim: self.claim };
		(tunnel, responses)
	}
}

impl TunnelCall {
	/// The tunnel call of `head`, a head on the tunnel path, which claims the
	/// lane of its connection.
	///
	/// # Errors
	///
	/// - [`Refusal::Unconnected`] -- the head carries no connection of this server.
	/// - [`Refusal::Busy`] -- the lane refuses the tunnel.
	pub(crate) fn claim(head: &Parts) -> Result<Self, Refusal> {
		let connection = head.extensions.get::<GrpcConnectInfo>().ok_or(Refusal::Unconnected)?;
		let claim = connection.lane.claim_tunnel().ok_or(Refusal::Busy)?;
		Ok(Self { claim, peer: connection.peer })
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
		let live = match &self.holder {
			Holder::Call(ticket) => ticket.redeem(),
			#[cfg(feature = "couple")]
			Holder::Loopback => true,
		};
		live.then_some((self.stream, self.peer))
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
	_claim: Claim,
}

impl Stream for Responses {
	type Item = Result<Vec<u8>, Status>;

	fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let this = self.get_mut();
		if let Ending::Watching(answer) = &mut this.ending {
			match Pin::new(answer).poll(cx) {
				Poll::Ready(Ok(status)) => {
					this.ending = Ending::Answered;
					return Poll::Ready(Some(Err(status)));
				}
				Poll::Ready(Err(_)) => this.ending = Ending::Quiet,
				Poll::Pending => {}
			}
		}

		if let Ending::Answered = this.ending {
			return Poll::Ready(None);
		}

		let message = this.messages.poll_recv(cx);
		message.map(|envelope| envelope.map(Ok))
	}
}

/// The tunnel arm of the edge: it queues the tunnel of each call it admits for
/// a caller of `accept`.
#[derive(Clone)]
pub(crate) struct TunnelService {
	queue: Sender<Arrival>,
	ceiling: usize,
	refusals: RefusalAudit,
}

impl TunnelService {
	/// A service that queues each tunnel on `queue`, with every message of
	/// its call held to `ceiling`, and records each refusal on `refusals`.
	pub(crate) fn new(queue: Sender<Arrival>, ceiling: usize, refusals: RefusalAudit) -> Self {
		Self { queue, ceiling, refusals }
	}
}

impl TunnelService {
	/// Serve `call`, the claimed tunnel call of `request`, with every message
	/// held to the ceiling of the service.
	pub(crate) async fn serve(&self, call: TunnelCall, request: HttpRequest<Body>) -> HttpResponse<Body> {
		let grpc = Grpc::new(TunnelCodec).max_decoding_message_size(self.ceiling);
		let mut grpc = grpc.max_encoding_message_size(self.ceiling);
		let admission = Admission { call: Some(call), queue: self.queue.clone(), refusals: self.refusals.clone() };

		grpc.streaming(admission, request).await
	}
}

/// The admission of one parsed call, which tonic runs once it accepts the
/// encoding of the call, before any message decodes.
struct Admission {
	/// tonic calls the admission once, but its trait takes `&mut self`, so the
	/// call moves out of an option.
	call: Option<TunnelCall>,
	queue: Sender<Arrival>,
	refusals: RefusalAudit,
}

impl StreamingService<Vec<u8>> for Admission {
	type Response = Vec<u8>;
	type ResponseStream = Responses;
	type Future = BoxFuture<Result<Response<Responses>, Status>>;

	fn call(&mut self, request: Request<Streaming<Vec<u8>>>) -> Self::Future {
		let call = self.call.take();
		let queue = self.queue.clone();
		let refusals = self.refusals.clone();

		Box::pin(async move {
			let call = call.ok_or_else(|| Status::internal("the tunnel admits one call"))?;
			let (tunnel, responses) = call.admit(request.into_inner());

			// A live tunnel holds a slot, so only tunnels that ended before a
			// caller took them can fill the queue, and the call then refuses
			// as busy.
			if queue.try_send(Ok(tunnel)).is_err() {
				refusals.refused(&Refusal::Busy);
				return Err(Status::unavailable("the server has no free slot for a tunnel"));
			}

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
		assert_eq!(refused, Some(Refusal::Unconnected));
		Ok(())
	}

	#[test]
	fn each_refusal_answers_its_status() {
		let method = HttpResponse::from(Refusal::Method);
		assert_eq!(method.status(), StatusCode::METHOD_NOT_ALLOWED);
		assert_eq!(method.headers().get(ALLOW).map(HeaderValue::as_bytes), Some(&b"POST"[..]));

		let media = HttpResponse::from(Refusal::MediaType);
		assert_eq!(media.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

		let statuses = [(Refusal::Path, "12"), (Refusal::Busy, "14"), (Refusal::Unconnected, "13")];
		for (refusal, expected) in statuses {
			let response = HttpResponse::from(refusal);
			let status = response.headers().get("grpc-status").map(HeaderValue::as_bytes);
			assert_eq!(response.status(), StatusCode::OK);
			assert_eq!(status, Some(expected.as_bytes()));
		}
	}
}
