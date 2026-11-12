//! The `grpc.health.v1.Health` calls of an edge, `Check` and `Watch`, which
//! `docs/grpc.md` describes.
//!
//! # Sources
//!
//! - gRPC health checking, `grpc/grpc` `doc/health-checking.md`:
//!   <https://github.com/grpc/grpc/blob/master/doc/health-checking.md>

#[cfg(feature = "couple")]
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use http::{Request as HttpRequest, Response as HttpResponse};
use tokio_stream::Stream;
use tonic::body::Body;
use tonic::server::{Grpc, ServerStreamingService, UnaryService};
use tonic::{Request, Response, Status};

use tightbeam::clock::Lapse;

use crate::deadline::Deadline;
use crate::tunnel::TunnelCodec;

#[cfg(feature = "couple")]
use tokio::sync::watch;
#[cfg(feature = "couple")]
use tokio_stream::wrappers::WatchStream;

#[cfg(feature = "couple")]
use crate::deadline::DeadlineSleep;
#[cfg(feature = "couple")]
use crate::incoming::CoupledSlot;

macro_rules! health_service {
	() => {
		"/grpc.health.v1.Health/"
	};
}

/// The path of the health check, which a probe calls on every edge.
pub const HEALTH_CHECK_PATH: &str = concat!(health_service!(), "Check");

/// The path of the health watch, which a client-side load balancer calls on
/// every edge.
pub const HEALTH_WATCH_PATH: &str = concat!(health_service!(), "Watch");

/// The largest health request an edge decodes: the request names a service,
/// and the edge answers for the empty one alone.
const HEALTH_CEILING: usize = 1024;

/// The tag of field 1 as a length-delimited value: the `service` of a
/// `HealthCheckRequest`.
const SERVICE_TAG: u8 = 0x0a;

/// The tag of field 1 as a varint: the `status` of a `HealthCheckResponse`.
const STATUS_TAG: u8 = 0x08;

/// The `ServingStatus` of a health answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HealthStatus {
	Serving = 1,
	/// A coupled edge whose loopback session is not open.
	#[cfg(feature = "couple")]
	NotServing = 2,
	/// A watch that names a service, because the edge answers for the whole
	/// server alone.
	ServiceUnknown = 3,
}

impl HealthStatus {
	/// The status of an edge whose service carries calls when `serving`.
	#[cfg(feature = "couple")]
	pub(crate) fn of(serving: bool) -> Self {
		if serving {
			Self::Serving
		} else {
			Self::NotServing
		}
	}

	/// Serve the health check of `request` with this status.
	pub(crate) async fn serve(self, request: HttpRequest<Body>) -> HttpResponse<Body> {
		let mut grpc = Grpc::new(TunnelCodec).max_decoding_message_size(HEALTH_CEILING);
		grpc.unary(HealthCall(self), request).await
	}

	/// The answer to `request`, the encoded `HealthCheckRequest` of a probe.
	///
	/// # Errors
	///
	/// - [`Code::NotFound`](tonic::Code::NotFound) -- the request names a service, because the edge answers
	///   for the server alone.
	/// - [`Code::InvalidArgument`](tonic::Code::InvalidArgument) -- the request does not decode.
	fn answer(self, request: &[u8]) -> Result<Response<Vec<u8>>, Status> {
		match HealthRequest::try_from(request)? {
			HealthRequest::Server => Ok(Response::new(self.encoded())),
			HealthRequest::Service => Err(Status::not_found("the edge answers for the whole server alone")),
		}
	}

	/// The encoded `HealthCheckResponse` of the status.
	fn encoded(self) -> Vec<u8> {
		vec![STATUS_TAG, self as u8]
	}
}

/// What a `HealthCheckRequest` asks about: the whole server, which the edge
/// answers for, or a named service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HealthRequest {
	/// The empty service, which names the whole server.
	Server,
	/// A named service.
	Service,
}

/// Parses an encoded `HealthCheckRequest` by hand, because its one field is
/// field 1, the `service`.
///
/// # Errors
///
/// - [`Code::InvalidArgument`](tonic::Code::InvalidArgument) -- the request does not decode.
impl TryFrom<&[u8]> for HealthRequest {
	type Error = Status;

	fn try_from(request: &[u8]) -> Result<Self, Self::Error> {
		let malformed = || Status::invalid_argument("the health check request does not decode");
		let Some((&tag, rest)) = request.split_first() else {
			return Ok(Self::Server);
		};
		if tag != SERVICE_TAG {
			return Err(malformed());
		}

		let (length, rest) = Self::varint(rest).ok_or_else(malformed)?;
		let length = usize::try_from(length).map_err(|_| malformed())?;
		if rest.len() != length {
			return Err(malformed());
		}

		if rest.is_empty() {
			return Ok(Self::Server);
		}

		Ok(Self::Service)
	}
}

impl HealthRequest {
	/// The varint at the head of `bytes`, and the bytes after it.
	fn varint(bytes: &[u8]) -> Option<(u64, &[u8])> {
		let mut value = 0_u64;
		for (index, byte) in bytes.iter().enumerate().take(10) {
			value |= u64::from(byte & 0x7f) << (7 * index);
			if byte & 0x80 == 0 {
				return Some((value, &bytes[index + 1..]));
			}
		}

		None
	}
}

/// Where a watch reads the health of its edge.
enum HealthSource {
	/// A status that stays fixed, such as that of a tunnel edge.
	Steady(HealthStatus),
	/// Whether the loopback session of a coupled edge is open, as each change
	/// comes.
	#[cfg(feature = "couple")]
	Changing(watch::Receiver<bool>),
}

/// The coupled slot that a watch holds its connection under, and when it
/// lets go.
#[cfg(feature = "couple")]
pub(crate) struct WatchHold {
	slot: CoupledSlot,
	until: Deadline,
}

#[cfg(feature = "couple")]
impl WatchHold {
	/// Hold `slot` until `until`.
	pub(crate) fn new(slot: CoupledSlot, until: Deadline) -> Self {
		Self { slot, until }
	}
}

/// What one watch runs under: its source, and the hold of a watch that holds
/// its connection. A watch with no hold ends with its connection.
pub(crate) struct WatchTerms {
	source: HealthSource,
	#[cfg(feature = "couple")]
	hold: Option<WatchHold>,
}

impl WatchTerms {
	/// The terms of a watch of `status`, which stays fixed, such as that of a
	/// tunnel edge.
	pub(crate) fn steady(status: HealthStatus) -> Self {
		Self {
			source: HealthSource::Steady(status),
			#[cfg(feature = "couple")]
			hold: None,
		}
	}

	/// The terms of a watch of whether the loopback session of a coupled edge
	/// is open, as `serving` reads it, under `hold` when the watch holds its
	/// connection.
	#[cfg(feature = "couple")]
	pub(crate) fn changing(serving: watch::Receiver<bool>, hold: Option<WatchHold>) -> Self {
		Self { source: HealthSource::Changing(serving), hold }
	}

	/// Serve the watch of `request` under these terms. A watch that holds its
	/// connection ends at the until of its hold, the read of its request
	/// included.
	pub(crate) async fn serve(self, request: HttpRequest<Body>) -> HttpResponse<Body> {
		let until = self.until();
		let mut grpc = Grpc::new(TunnelCodec).max_decoding_message_size(HEALTH_CEILING);
		let watching = grpc.server_streaming(WatchCall(Some(self)), request);
		let Some(until) = until else {
			return watching.await;
		};

		until
			.bound(watching)
			.await
			.unwrap_or_else(|lapse| Self::lapsed(lapse).into_http())
	}

	/// The status that ends a watch whose bound lapsed: 4 once it passed the
	/// call limit, and 13 when the clock gave the wait no timer.
	fn lapsed(lapse: Lapse) -> Status {
		match lapse {
			Lapse::Passed => Status::deadline_exceeded("the watch passed the call limit"),
			Lapse::NoTimer => Status::internal("the clock of the edge gave the watch no timer"),
		}
	}

	/// When the watch ends with status 0, so the caller watches again, when it
	/// holds its connection.
	fn until(&self) -> Option<Deadline> {
		#[cfg(feature = "couple")]
		return self.hold.as_ref().map(|hold| hold.until.clone());

		#[cfg(not(feature = "couple"))]
		None
	}
}

/// The unary health check of one call.
struct HealthCall(HealthStatus);

impl UnaryService<Vec<u8>> for HealthCall {
	type Response = Vec<u8>;
	type Future = core::future::Ready<Result<Response<Vec<u8>>, Status>>;

	fn call(&mut self, request: Request<Vec<u8>>) -> Self::Future {
		let answer = self.0.answer(request.get_ref());
		core::future::ready(answer)
	}
}

/// The health watch of one call, which runs once under its terms.
struct WatchCall(Option<WatchTerms>);

impl ServerStreamingService<Vec<u8>> for WatchCall {
	type Response = Vec<u8>;
	type ResponseStream = HealthWatch;
	type Future = core::future::Ready<Result<Response<HealthWatch>, Status>>;

	fn call(&mut self, request: Request<Vec<u8>>) -> Self::Future {
		let terms = self.0.take().ok_or_else(|| Status::internal("a watch runs once"));
		let watch = terms.and_then(|terms| HealthWatch::of(request.get_ref(), terms));
		core::future::ready(watch.map(Response::new))
	}
}

/// The answers of one watch.
enum Answers {
	/// One status, which the watch answers once and holds.
	Steady(Option<HealthStatus>),
	/// The serving state of a coupled edge, now and at each change.
	#[cfg(feature = "couple")]
	Changing(WatchStream<bool>),
}

impl Answers {
	/// The next status of the watch, `Pending` until it changes, or `None`
	/// once the serving state of the edge ends.
	fn poll_status(&mut self, cx: &mut Context<'_>) -> Poll<Option<HealthStatus>> {
		#[cfg(not(feature = "couple"))]
		let _ = cx;

		match self {
			Self::Steady(status) => status.take().map_or(Poll::Pending, |status| Poll::Ready(Some(status))),
			#[cfg(feature = "couple")]
			Self::Changing(serving) => Pin::new(serving).poll_next(cx).map(|serving| serving.map(HealthStatus::of)),
		}
	}
}

/// The answers of one health watch: the status when the watch came, then
/// each change, until its hold ends it or the caller cancels.
struct HealthWatch {
	answers: Answers,
	/// The timer that ends a watch that holds its connection, and the slot it
	/// holds until then.
	#[cfg(feature = "couple")]
	hold: Option<(DeadlineSleep, CoupledSlot)>,
}

impl HealthWatch {
	/// The watch of `request`, the encoded `HealthCheckRequest` of a caller,
	/// under `terms`. A request that names a service reads
	/// `SERVICE_UNKNOWN`, because the edge answers for the whole server alone.
	///
	/// # Errors
	///
	/// - [`Code::InvalidArgument`](tonic::Code::InvalidArgument) -- the request does not decode.
	fn of(request: &[u8], terms: WatchTerms) -> Result<Self, Status> {
		let answers = match (HealthRequest::try_from(request)?, terms.source) {
			(HealthRequest::Service, _) => Answers::Steady(Some(HealthStatus::ServiceUnknown)),
			(HealthRequest::Server, HealthSource::Steady(status)) => Answers::Steady(Some(status)),
			#[cfg(feature = "couple")]
			(HealthRequest::Server, HealthSource::Changing(serving)) => Answers::Changing(WatchStream::new(serving)),
		};

		Ok(Self {
			answers,
			#[cfg(feature = "couple")]
			hold: terms.hold.map(|hold| (hold.until.sleep(), hold.slot)),
		})
	}
}

impl Stream for HealthWatch {
	type Item = Result<Vec<u8>, Status>;

	fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let this = self.get_mut();
		#[cfg(feature = "couple")]
		if let Some((until, _slot)) = &mut this.hold {
			if Pin::new(until).poll(cx).is_ready() {
				return Poll::Ready(None);
			}
		}

		let status = this.answers.poll_status(cx);
		status.map(|status| status.map(|status| Ok(status.encoded())))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	tightbeam::tb_cases! {
		fn a_check_reads_the_status_of_the_server((status, request, expected): (HealthStatus, &[u8], [u8; 2])) -> Result<(), Status> {
			let answer = status.answer(request)?;
			assert_eq!(answer.into_inner(), expected);
			Ok(())
		}

		cases {
			an_empty_request => (HealthStatus::Serving, &[], [0x08, 0x01]),
			an_empty_service => (HealthStatus::Serving, &[0x0a, 0x00], [0x08, 0x01]),
		}
	}

	#[test]
	fn a_check_of_a_named_service_reads_not_found() {
		let named = HealthStatus::Serving.answer(b"\x0a\x03abc");
		assert_eq!(named.map(|_| ()).map_err(|status| status.code()), Err(tonic::Code::NotFound));
	}

	tightbeam::tb_cases! {
		fn a_malformed_check_is_refused(request: &[u8]) {
			let refused = HealthStatus::Serving.answer(request);
			assert_eq!(refused.map(|_| ()).map_err(|status| status.code()), Err(tonic::Code::InvalidArgument));
		}

		cases {
			another_field => b"\x12\x00",
			a_length_past_the_bytes => b"\x0a\x05abc",
			an_unterminated_varint => b"\x0a\xff",
		}
	}

	/// A watch that holds its connection ends with 13 when the clock of the
	/// edge gives its bound no timer.
	#[test]
	fn a_watch_whose_clock_gives_no_timer_ends_with_internal() {
		assert_eq!(WatchTerms::lapsed(Lapse::NoTimer).code(), tonic::Code::Internal);
	}

	/// The next answer of `watch`, polled once.
	#[cfg(feature = "couple")]
	fn next_answer(watch: &mut HealthWatch) -> Poll<Option<Result<Vec<u8>, Status>>> {
		let waker = core::task::Waker::noop();
		let mut cx = Context::from_waker(waker);
		Pin::new(watch).poll_next(&mut cx)
	}

	/// A watch of a coupled edge whose session is not open, and the sender
	/// that opens it.
	#[cfg(feature = "couple")]
	fn changing() -> (HealthWatch, watch::Sender<bool>) {
		let (serving, receiver) = watch::channel(false);
		let terms = WatchTerms::changing(receiver, None);
		let watched = HealthWatch::of(&[], terms).expect("an empty request decodes");
		(watched, serving)
	}

	#[cfg(feature = "couple")]
	#[test]
	fn a_watch_answers_its_status_at_once() {
		let (mut watched, _serving) = changing();
		assert!(matches!(next_answer(&mut watched), Poll::Ready(Some(Ok(answer))) if answer == [0x08, 0x02]));
	}

	#[cfg(feature = "couple")]
	#[test]
	fn a_watch_answers_each_change() {
		let (mut watched, serving) = changing();
		let _now = next_answer(&mut watched);
		let _sent = serving.send(true);
		assert!(matches!(next_answer(&mut watched), Poll::Ready(Some(Ok(answer))) if answer == [0x08, 0x01]));
	}

	#[cfg(feature = "couple")]
	#[test]
	fn a_watch_holds_until_a_change() {
		let (mut watched, _serving) = changing();
		let _now = next_answer(&mut watched);
		assert!(next_answer(&mut watched).is_pending());
	}
}
