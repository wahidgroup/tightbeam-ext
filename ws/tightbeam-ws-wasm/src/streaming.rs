//! Progressive body streaming bridges for the multiplexed wasm client: the
//! tightbeam [`RequestSink`], [`StreamBody`], and [`ReplySink`] for
//! JavaScript.
//!
//! - Pushes reach the wire eagerly, so a duplex exchange may await a reply
//!   chunk between pushes.
//! - A known final chunk closes the body in one record through `closeWith`.
//! - A close consumes the handle it closes. The glue nulls the JavaScript
//!   wrapper, and the promise of the close holds the stream until it settles.
//! - Every other async method clones an `Rc` to shared state into its promise,
//!   so a free of the JavaScript wrapper mid-await keeps the call alive.
//! - The shared state of a client-initiated stream holds its connection, and
//!   so does the reply body of a duplex stream. The socket therefore stays
//!   open while the stream lives, even after its client is freed.

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::Pin;
use core::str::FromStr;
use std::rc::Rc;
use std::sync::Arc;

use futures_util::future::{AbortHandle, Abortable};
use js_sys::{Function, Promise, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use tightbeam::der::{Decode, Encode};
use tightbeam::marker::MaybeSend;
use tightbeam::policy::TransitStatus;
use tightbeam::transport::multiplex::{MuxDispatch, ReplySink, RequestSink, StreamBody, StreamRoute};
use tightbeam::transport::{ResponsePackage, TransportResult};
use tightbeam::urn::Urn;
use tightbeam::Frame;

use crate::fault::{JsFault, RefusalCode, TransitCode};
use crate::mux::Connection;
use crate::promise::{JsBytes, JsResponse, Record, Returned};

type FrameResponseFut = Pin<Box<dyn Future<Output = TransportResult<Option<Frame>>> + 'static>>;

/// Why a call on a closed stream half refuses.
const STREAM_CLOSED: &str = "the streaming handle is closed";

/// A stream half that one call at a time holds.
///
/// A call holds the half for the length of its await, so a second call in
/// that span finds the half busy rather than closed.
struct Slot<T>(Cell<SlotState<T>>);

/// What a [`Slot`] holds between calls.
enum SlotState<T> {
	/// The half waits for the next call.
	Ready(T),
	/// A call holds the half until its await ends.
	Busy,
	/// A close consumed the half.
	Closed,
}

impl<T> Slot<T> {
	/// A slot whose half waits for the first call.
	fn new(half: T) -> Self {
		Self(Cell::new(SlotState::Ready(half)))
	}

	/// Lend the half to `call` for the length of its await, then hand it back
	/// for the next call.
	///
	/// # Errors
	///
	/// - `StreamBusy` -- another call holds the half.
	/// - `StreamClosed` -- a close consumed the half.
	async fn lend<R>(&self, call: impl AsyncFnOnce(&mut T) -> R) -> Result<R, JsFault> {
		let mut half = self.take_leaving(SlotState::Busy)?;
		let outcome = call(&mut half).await;

		self.0.set(SlotState::Ready(half));
		Ok(outcome)
	}

	/// Take the half for a close, which consumes it.
	///
	/// # Errors
	///
	/// - The errors of [`Self::lend`].
	fn retire(&self) -> Result<T, JsFault> {
		self.take_leaving(SlotState::Closed)
	}

	/// Take the half and leave `next` in its place. A slot that holds no half
	/// keeps its state and refuses.
	fn take_leaving(&self, next: SlotState<T>) -> Result<T, JsFault> {
		match self.0.replace(next) {
			SlotState::Ready(half) => Ok(half),
			SlotState::Busy => {
				self.0.set(SlotState::Busy);
				Err(RefusalCode::StreamBusy.because("another call holds this stream half"))
			}
			SlotState::Closed => {
				self.0.set(SlotState::Closed);
				Err(RefusalCode::StreamClosed.because(STREAM_CLOSED))
			}
		}
	}
}

struct RequestInner {
	sink: Slot<RequestSink>,
	response: Cell<Option<FrameResponseFut>>,
	/// Holds the socket open while the stream lives.
	_connection: Rc<Connection>,
}

impl RequestInner {
	/// Await the stashed response future and surface its Frame DER.
	async fn resolve_response(&self) -> Result<JsValue, JsValue> {
		let pending = self.response.take();
		let fut = pending.ok_or_else(|| RefusalCode::StreamClosed.because(STREAM_CLOSED))?;
		let frame = fut.await.map_err(JsFault::from)?;

		let response = JsValue::try_from(JsResponse(frame))?;
		Ok(response)
	}
}

/// Client-initiated streaming request: push chunks, then close for the
/// reassembled Frame response (or `undefined`).
#[wasm_bindgen(js_name = MuxRequestStream)]
pub struct MuxRequestStream {
	inner: Rc<RequestInner>,
}

#[wasm_bindgen(js_class = MuxRequestStream)]
impl MuxRequestStream {
	/// Open a progressive request stream on `connection`, which the stream
	/// holds.
	pub(crate) fn open(connection: Rc<Connection>) -> Result<MuxRequestStream, JsFault> {
		let (sink, response) = connection.handle().open_stream().map_err(JsFault::from)?;
		Ok(Self::from_parts(sink, Box::pin(response), connection))
	}

	/// Open a progressive request routed to a servlet URN
	/// (`urn:<nid>:<nss>`). The Open carries the origin hop-budget
	/// sentinel so the first gateway applies its `max_hops` clamp.
	pub(crate) fn open_to(connection: Rc<Connection>, target: &str) -> Result<MuxRequestStream, JsFault> {
		let StreamTarget(urn) = StreamTarget::try_from(target)?;
		let (sink, response) = connection.handle().open_stream_to(urn).map_err(JsFault::from)?;
		Ok(Self::from_parts(sink, Box::pin(response), connection))
	}

	fn from_parts(sink: RequestSink, response: FrameResponseFut, connection: Rc<Connection>) -> Self {
		let response = Cell::new(Some(response));
		let inner = RequestInner { sink: Slot::new(sink), response, _connection: connection };
		Self { inner: Rc::new(inner) }
	}

	/// Push one request chunk. Empty chunks are no-ops on the wire.
	#[wasm_bindgen(js_name = push, unchecked_return_type = "Promise<void>")]
	pub fn push(&self, chunk: JsBytes) -> Promise {
		let chunk = chunk.read();
		let inner = Rc::clone(&self.inner);
		future_to_promise(async move {
			let chunk = chunk?;
			let outcome = inner.sink.lend(async |held| held.push(&chunk).await).await?;
			outcome.map_err(JsFault::from)?;

			Ok(JsValue::UNDEFINED)
		})
	}

	/// Flush `last`, then resolve with the response Frame DER (or
	/// `undefined`). Dropping without close cancels the stream.
	///
	/// The close consumes this handle. A close while a push is in flight
	/// refuses with `StreamBusy`, and the stream then cancels once that push
	/// settles.
	#[wasm_bindgen(js_name = close, unchecked_return_type = "Promise<Uint8Array | undefined>")]
	pub fn close(self) -> Promise {
		let inner = self.inner;
		future_to_promise(async move {
			let held = inner.sink.retire()?;
			held.close().await.map_err(JsFault::from)?;

			inner.resolve_response().await
		})
	}

	/// Push the final request chunk with `last` set (one record fewer
	/// than push-then-close), then resolve with the response Frame
	/// DER (or `undefined`).
	///
	/// The close consumes this handle, as [`close`](Self::close) does.
	#[wasm_bindgen(js_name = closeWith, unchecked_return_type = "Promise<Uint8Array | undefined>")]
	pub fn close_with(self, chunk: JsBytes) -> Promise {
		let chunk = chunk.read();
		let inner = self.inner;
		future_to_promise(async move {
			let chunk = chunk?;
			let held = inner.sink.retire()?;
			held.close_with(&chunk).await.map_err(JsFault::from)?;

			inner.resolve_response().await
		})
	}
}

struct DuplexInner {
	sink: Slot<RequestSink>,
	/// Holds the socket open while the stream lives.
	_connection: Rc<Connection>,
}

/// Client-initiated duplex stream: push request chunks, and read the reply
/// chunks through the body that [`takeBody`](Self::take_body) moves into a
/// handle of its own.
///
/// The request half and the reply body end apart. A close consumes this
/// handle, and the reply body still reads until the peer's `last`.
#[wasm_bindgen(js_name = MuxDuplexStream)]
pub struct MuxDuplexStream {
	inner: Rc<DuplexInner>,
	/// The reply body, until [`take_body`](Self::take_body) moves it out. A
	/// body still held here drops with this handle, which cancels the stream.
	body: Option<MuxStreamBody>,
}

#[wasm_bindgen(js_class = MuxDuplexStream)]
impl MuxDuplexStream {
	/// Open an unrouted duplex stream on `connection`, which the stream
	/// holds.
	pub(crate) fn open(connection: Rc<Connection>) -> Result<MuxDuplexStream, JsFault> {
		let (sink, body) = connection.handle().open_duplex().map_err(JsFault::from)?;
		Ok(Self::from_parts(sink, body, connection))
	}

	/// Open a duplex stream routed to a servlet URN (`urn:<nid>:<nss>`).
	///
	/// The Open carries the origin hop-budget sentinel so the first
	/// gateway applies its `max_hops` clamp.
	pub(crate) fn open_to(connection: Rc<Connection>, target: &str) -> Result<MuxDuplexStream, JsFault> {
		let StreamTarget(urn) = StreamTarget::try_from(target)?;
		let (sink, body) = connection.handle().open_duplex_to(urn).map_err(JsFault::from)?;
		Ok(Self::from_parts(sink, body, connection))
	}

	fn from_parts(sink: RequestSink, body: StreamBody, connection: Rc<Connection>) -> Self {
		let reply = MuxStreamBody::reply(body, Rc::clone(&connection));
		let inner = DuplexInner { sink: Slot::new(sink), _connection: connection };
		Self { inner: Rc::new(inner), body: Some(reply) }
	}

	/// Move the reply body into a handle of its own, once.
	///
	/// # Errors
	///
	/// - `StreamClosed` -- an earlier call took the body.
	#[wasm_bindgen(js_name = takeBody)]
	pub fn take_body(&mut self) -> Result<MuxStreamBody, JsFault> {
		let taken = || RefusalCode::StreamClosed.because("the reply body already moved to its own handle");
		self.body.take().ok_or_else(taken)
	}

	/// Push one request chunk. Chunks go out eagerly, so awaiting a
	/// reply chunk between pushes (a chunk-for-chunk conversation)
	/// is sound.
	#[wasm_bindgen(js_name = push, unchecked_return_type = "Promise<void>")]
	pub fn push(&self, chunk: JsBytes) -> Promise {
		let chunk = chunk.read();
		let inner = Rc::clone(&self.inner);
		future_to_promise(async move {
			let chunk = chunk?;
			let outcome = inner.sink.lend(async |held| held.push(&chunk).await).await?;
			outcome.map_err(JsFault::from)?;

			Ok(JsValue::UNDEFINED)
		})
	}

	/// Flush the request body's `last` flag.
	///
	/// The close consumes this handle, as [`MuxRequestStream::close`] does,
	/// and a reply body still held here drops with it.
	#[wasm_bindgen(js_name = close, unchecked_return_type = "Promise<void>")]
	pub fn close(self) -> Promise {
		let inner = self.inner;
		future_to_promise(async move {
			let held = inner.sink.retire()?;
			held.close().await.map_err(JsFault::from)?;

			Ok(JsValue::UNDEFINED)
		})
	}

	/// Push the final request chunk with `last` set, closing the
	/// request body in one record.
	///
	/// The close consumes this handle, as [`close`](Self::close) does.
	#[wasm_bindgen(js_name = closeWith, unchecked_return_type = "Promise<void>")]
	pub fn close_with(self, chunk: JsBytes) -> Promise {
		let chunk = chunk.read();
		let inner = self.inner;
		future_to_promise(async move {
			let chunk = chunk?;
			let held = inner.sink.retire()?;
			held.close_with(&chunk).await.map_err(JsFault::from)?;

			Ok(JsValue::UNDEFINED)
		})
	}
}

struct BodyInner {
	body: Slot<StreamBody>,
	/// The abort of the read in flight, which a free of the handle runs, so
	/// the read ends and the body drops with it.
	reading: Cell<Option<AbortHandle>>,
	/// Holds the socket open while the reply body of a client-initiated
	/// duplex stream lives. A served body leaves that hold to its serve loop.
	_connection: Option<Rc<Connection>>,
}

/// A streamed body that JavaScript reads chunk by chunk: the request body of
/// a stream that a `serveStreaming` or `serveDuplex` handler answers, or the
/// reply body of a client-initiated duplex stream.
///
/// A free of the handle before the peer's `last` discards the chunks still
/// to come. On a duplex reply body, it cancels the stream, and a read still
/// in flight ends with `undefined`, so the free cancels at once.
#[wasm_bindgen(js_name = MuxStreamBody)]
pub struct MuxStreamBody {
	inner: Rc<BodyInner>,
}

#[wasm_bindgen(js_class = MuxStreamBody)]
impl MuxStreamBody {
	/// The request body of a served stream.
	fn wrap(body: StreamBody) -> Self {
		let inner = BodyInner { body: Slot::new(body), reading: Cell::new(None), _connection: None };
		Self { inner: Rc::new(inner) }
	}

	/// The reply body of a duplex stream on `connection`, which the body
	/// holds.
	fn reply(body: StreamBody, connection: Rc<Connection>) -> Self {
		let inner = BodyInner { body: Slot::new(body), reading: Cell::new(None), _connection: Some(connection) };
		Self { inner: Rc::new(inner) }
	}

	/// Next chunk, or `undefined` after the peer's `last`, or once a free of
	/// the handle ended the read.
	#[wasm_bindgen(js_name = nextChunk, unchecked_return_type = "Promise<Uint8Array | undefined>")]
	pub fn next_chunk(&self) -> Promise {
		let inner = Rc::clone(&self.inner);

		// The abort exists before the read first runs, so a free that lands
		// before the spawned read starts still ends it.
		let (abort, registration) = AbortHandle::new_pair();
		inner.reading.set(Some(abort));

		future_to_promise(async move {
			let read = async move |held: &mut StreamBody| Abortable::new(held.chunk(), registration).await;
			let outcome = inner.body.lend(read).await;
			inner.reading.set(None);

			// A free ended the read: drop the body now, which cancels its stream.
			let outcome = outcome?;
			let Ok(outcome) = outcome else {
				drop(inner.body.retire());
				return Ok(JsValue::UNDEFINED);
			};

			let chunk = outcome.map_err(JsFault::from)?;
			Ok(match chunk {
				Some(bytes) => Uint8Array::from(bytes.as_slice()).into(),
				None => JsValue::UNDEFINED,
			})
		})
	}
}

/// A free of the handle ends the read in flight, whose future holds a share
/// of the body, so the body drops once that read returns.
impl Drop for MuxStreamBody {
	fn drop(&mut self) {
		if let Some(reading) = self.inner.reading.take() {
			reading.abort();
		}
	}
}

struct ReplyInner {
	sink: Slot<ReplySink>,
}

/// Reply half for a JS `serveDuplex` handler.
#[wasm_bindgen(js_name = MuxReplySink)]
pub struct MuxReplySink {
	inner: Rc<ReplyInner>,
}

#[wasm_bindgen(js_class = MuxReplySink)]
impl MuxReplySink {
	fn wrap(sink: ReplySink) -> Self {
		Self { inner: Rc::new(ReplyInner { sink: Slot::new(sink) }) }
	}

	/// Push one reply chunk toward the peer.
	#[wasm_bindgen(js_name = push, unchecked_return_type = "Promise<void>")]
	pub fn push(&self, chunk: JsBytes) -> Promise {
		let chunk = chunk.read();
		let inner = Rc::clone(&self.inner);
		future_to_promise(async move {
			let chunk = chunk?;
			let outcome = inner.sink.lend(async |held| held.push(&chunk).await).await?;
			outcome.map_err(JsFault::from)?;

			Ok(JsValue::UNDEFINED)
		})
	}
}

/// The handler slot of a started serve loop.
///
/// The loop reads the function in the slot for each stream it dispatches, so
/// a later `serve*` call in the same mode swaps the function for the streams
/// that arrive after it.
#[derive(Clone)]
pub(crate) struct ServeHandler(Rc<RefCell<Function>>);

impl ServeHandler {
	/// A slot that holds `function`.
	pub(crate) fn new(function: Function) -> Self {
		Self(Rc::new(RefCell::new(function)))
	}

	/// Swap in `function` for the streams dispatched after this call.
	pub(crate) fn replace(&self, function: Function) {
		self.0.replace(function);
	}

	/// A dispatch that answers unary streams through this slot.
	pub(crate) fn unary(self) -> impl MuxDispatch + 'static {
		UnaryDispatch(self)
	}

	/// A dispatch that answers streaming streams through this slot.
	pub(crate) fn streaming(self) -> impl MuxDispatch + 'static {
		StreamingDispatch(self)
	}

	/// A dispatch that answers duplex streams through this slot.
	pub(crate) fn duplex(self) -> impl MuxDispatch + 'static {
		DuplexDispatch(self)
	}

	/// The function that answers a stream dispatched now.
	fn current(&self) -> StreamHandler {
		let function = self.0.borrow().clone();
		StreamHandler(function)
	}
}

/// The function of a `serve*` call, as its serve loop read it for one
/// dispatched stream.
struct StreamHandler(Function);

impl StreamHandler {
	/// Answer one unary request.
	async fn respond(self, frame: Arc<Frame>) -> ResponsePackage {
		let outcome = self.call_unary(&frame).await;
		Self::answer(outcome)
	}

	/// Answer one streamed request through a [`MuxStreamBody`] plus the
	/// Open's [`StreamRoute`]. The function returns a Frame DER (or
	/// `undefined`).
	async fn respond_streaming(self, body: StreamBody, route: StreamRoute) -> ResponsePackage {
		let body_arg: JsValue = MuxStreamBody::wrap(body).into();
		let route_arg = JsValue::from(JsRoute(&route));

		let outcome = self.call_streaming(&body_arg, &route_arg).await;
		Self::answer(outcome)
	}

	/// The response to a stream whose function settled with `outcome`, for
	/// the unary and the streaming kinds alike. A rejection answers with the
	/// status [`TransitCode::of_js`] reads from it.
	fn answer(outcome: Result<ResponsePackage, JsValue>) -> ResponsePackage {
		outcome.unwrap_or_else(|rejection| ResponsePackage::new(TransitCode::of_js(&rejection), None))
	}

	/// Answer one duplex stream through a body, a reply, and the Open's
	/// [`StreamRoute`].
	async fn respond_duplex(self, body: StreamBody, reply: ReplySink, route: StreamRoute) -> TransitStatus {
		let body_arg: JsValue = MuxStreamBody::wrap(body).into();
		let reply_arg: JsValue = MuxReplySink::wrap(reply).into();
		let route_arg = JsValue::from(JsRoute(&route));
		match self.call_duplex(&body_arg, &reply_arg, &route_arg).await {
			Ok(status) => status,
			Err(rejection) => TransitCode::of_js(&rejection),
		}
	}

	/// Call the function with the request DER and read its resolution.
	async fn call_unary(&self, frame: &Frame) -> Result<ResponsePackage, JsValue> {
		let request_der = frame.to_der().map_err(JsFault::from)?;
		let argument = Uint8Array::from(request_der.as_slice());

		let returned = self.0.call1(&JsValue::UNDEFINED, &argument).map(Returned::from)?;
		Self::resolution(returned).await
	}

	/// Call the function with a streamed body and the Open's route, and read
	/// its resolution.
	async fn call_streaming(&self, body: &JsValue, route: &JsValue) -> Result<ResponsePackage, JsValue> {
		let returned = self.0.call2(&JsValue::UNDEFINED, body, route).map(Returned::from)?;
		Self::resolution(returned).await
	}

	/// The response that a function's return settles to, for the unary and
	/// the streaming kinds alike: `undefined` or `null` accepts without a
	/// body, and bytes decode as the response frame.
	///
	/// # Errors
	///
	/// - The rejection of a returned promise or thenable.
	/// - `InvalidBytes` -- the resolution is neither empty nor a `Uint8Array`.
	/// - `SerializationError` -- the bytes are no frame.
	async fn resolution(returned: Returned) -> Result<ResponsePackage, JsValue> {
		let settled = returned.settle().await?;
		let Some(settled) = Record::present(settled) else {
			return Ok(ResponsePackage::new(TransitStatus::Ok, None));
		};

		let response_der = JsBytes::read_value(&settled, "response")?;
		let response = Frame::from_der(&response_der).map_err(JsFault::from)?;
		Ok(ResponsePackage::new(TransitStatus::Ok, Some(response)))
	}

	/// Call the function with the body, the reply half, and the Open's route,
	/// and read the status its resolution names: `undefined` or `null`
	/// accepts, and any other value answers the status that
	/// [`TransitCode::of_js`] reads from it.
	async fn call_duplex(&self, body: &JsValue, reply: &JsValue, route: &JsValue) -> Result<TransitStatus, JsValue> {
		let returned = self.0.call3(&JsValue::UNDEFINED, body, reply, route).map(Returned::from)?;
		let settled = returned.settle().await?;
		let Some(settled) = Record::present(settled) else {
			return Ok(TransitStatus::Ok);
		};

		let status = TransitCode::of_js(&settled);
		Ok(status)
	}
}

/// The servlet URN that a routed stream open or a work submission targets.
pub(crate) struct StreamTarget(pub(crate) Urn<'static>);

impl TryFrom<&str> for StreamTarget {
	type Error = JsFault;

	/// Parse `target` as `urn:<nid>:<nss>`.
	///
	/// # Errors
	///
	/// - `InvalidStreamRoute` -- `target` is no URN.
	fn try_from(target: &str) -> Result<Self, Self::Error> {
		let urn = Urn::from_str(target);
		let refusal = |error| {
			let message = format!("stream target must be a URN (urn:<nid>:<nss>): {error}");
			RefusalCode::InvalidStreamRoute.because(message)
		};

		urn.map(Self).map_err(refusal)
	}
}

/// The Open's [`StreamRoute`] as a `serve*` handler reads it: the optional
/// target URN and the remaining hop budget.
struct JsRoute<'a>(&'a StreamRoute);

impl JsRoute<'_> {
	/// The target as `urn:<nid>:<nss>`. The route names a servlet by those
	/// two parts alone, so the string leaves out any component that
	/// [`Display`](core::fmt::Display) would write.
	fn target(&self) -> Option<String> {
		let urn = self.0.target()?;
		let target = format!("urn:{}:{}", urn.nid(), urn.nss());
		Some(target)
	}
}

impl From<JsRoute<'_>> for JsValue {
	fn from(route: JsRoute<'_>) -> Self {
		let hops_remaining = f64::from(route.0.hops_remaining());
		let record = Record::new();
		record.set_present("target", route.target());
		record.set("hopsRemaining", hops_remaining);
		record.into()
	}
}

/// Unary-only dispatch: forwards the request frame to JS. Other kinds
/// refuse through [`MuxDispatch`] defaults.
struct UnaryDispatch(ServeHandler);

impl MuxDispatch for UnaryDispatch {
	fn unary(&self, frame: Arc<Frame>) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		let handler = self.0.current();
		async move { Ok(handler.respond(frame).await) }
	}
}

/// Streaming-only dispatch: forwards body + Open route to JS. Other
/// kinds refuse through [`MuxDispatch`] defaults.
struct StreamingDispatch(ServeHandler);

impl MuxDispatch for StreamingDispatch {
	fn streaming(
		&self,
		body: StreamBody,
		route: StreamRoute,
	) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		let handler = self.0.current();
		async move { Ok(handler.respond_streaming(body, route).await) }
	}
}

/// Duplex-only dispatch: forwards body, reply, and Open route to JS.
struct DuplexDispatch(ServeHandler);

impl MuxDispatch for DuplexDispatch {
	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		route: StreamRoute,
	) -> impl Future<Output = TransportResult<TransitStatus>> + MaybeSend {
		let handler = self.0.current();
		async move { Ok(handler.respond_duplex(body, reply, route).await) }
	}
}

#[cfg(test)]
mod tests {
	use core::future::{pending, Future};

	use futures_util::FutureExt;
	use js_sys::Function;
	use tightbeam::policy::TransitStatus;
	use tightbeam::testing::TestFrame;
	use wasm_bindgen::JsValue;
	use wasm_bindgen_test::wasm_bindgen_test;

	use super::{Slot, StreamHandler};
	use crate::fault::{JsFault, Refused, TransitCode};

	/// A call that takes the half of `slot` and never hands it back.
	fn holding(slot: &Slot<()>) -> impl Future<Output = Result<(), JsFault>> + '_ {
		let mut call = Box::pin(slot.lend(async |_| pending::<()>().await));
		let _ = (&mut call).now_or_never();

		call
	}

	/// A call that hands the half of `slot` back at once.
	async fn passing(slot: &Slot<()>) -> Result<(), JsFault> {
		slot.lend(async |_| ()).await
	}

	/// A `serve*` handler that resolves with a number in place of bytes.
	fn numeric_handler() -> StreamHandler {
		let function = Function::new_no_args("return 7");
		StreamHandler(function)
	}

	/// A `serve*` handler that rejects with the code of a gRPC status.
	fn refusing_handler() -> StreamHandler {
		let function = Function::new_no_args("return Promise.reject({ code: 'PermissionDenied' })");
		StreamHandler(function)
	}

	/// A `serveDuplex` handler that resolves with the label `Ok`.
	fn resolving_ok_handler() -> StreamHandler {
		let function = Function::new_no_args("return Promise.resolve('Ok')");
		StreamHandler(function)
	}

	/// A `serve*` handler that rejects with the code `Ok`.
	fn rejecting_ok_handler() -> StreamHandler {
		let function = Function::new_no_args("return Promise.reject({ code: 'Ok' })");
		StreamHandler(function)
	}

	#[wasm_bindgen_test]
	async fn a_finished_call_hands_the_half_back() {
		let slot = Slot::new(());
		let _first = passing(&slot).await;

		let second = passing(&slot).await;
		assert!(second.is_ok());
	}

	#[wasm_bindgen_test]
	async fn a_held_half_reports_busy() {
		let slot = Slot::new(());
		let _held = holding(&slot);

		let first = passing(&slot).await;
		let second = passing(&slot).await;
		assert_eq!(first.code().as_deref(), Some("StreamBusy"));
		assert_eq!(second.code().as_deref(), Some("StreamBusy"));
	}

	#[wasm_bindgen_test]
	fn a_close_of_a_held_half_reports_busy() {
		let slot = Slot::new(());
		let _held = holding(&slot);

		let first = slot.retire();
		let second = slot.retire();
		assert_eq!(first.code().as_deref(), Some("StreamBusy"));
		assert_eq!(second.code().as_deref(), Some("StreamBusy"));
	}

	#[wasm_bindgen_test]
	async fn a_retired_half_reports_closed() {
		let slot = Slot::new(());
		let _retired = slot.retire();

		let first = passing(&slot).await;
		let second = passing(&slot).await;
		assert_eq!(first.code().as_deref(), Some("StreamClosed"));
		assert_eq!(second.code().as_deref(), Some("StreamClosed"));
	}

	#[wasm_bindgen_test]
	async fn a_number_from_a_unary_handler_is_no_response() {
		let frame = TestFrame::v0(None, None);
		let answered = numeric_handler().call_unary(&frame).await;
		assert_eq!(answered.code().as_deref(), Some("InvalidBytes"));
	}

	#[wasm_bindgen_test]
	async fn a_streaming_refusal_answers_with_its_code() {
		let undefined = JsValue::UNDEFINED;
		let outcome = refusing_handler().call_streaming(&undefined, &undefined).await;

		let answered = StreamHandler::answer(outcome);
		assert_eq!(answered.status(), TransitStatus::PermissionDenied);
	}

	#[wasm_bindgen_test]
	async fn a_number_from_a_streaming_handler_is_no_response() {
		let undefined = JsValue::UNDEFINED;
		let answered = numeric_handler().call_streaming(&undefined, &undefined).await;
		assert_eq!(answered.code().as_deref(), Some("InvalidBytes"));
	}

	#[wasm_bindgen_test]
	async fn a_duplex_handler_resolving_ok_answers_unknown() {
		let undefined = JsValue::UNDEFINED;
		let resolved = resolving_ok_handler().call_duplex(&undefined, &undefined, &undefined).await;
		assert_eq!(resolved.ok(), Some(TransitStatus::Unknown));
	}

	#[wasm_bindgen_test]
	async fn a_handler_rejecting_with_ok_answers_unknown_on_both_serve_paths() {
		let undefined = JsValue::UNDEFINED;
		let streamed = rejecting_ok_handler().call_streaming(&undefined, &undefined).await;
		let duplexed = rejecting_ok_handler().call_duplex(&undefined, &undefined, &undefined).await;

		let streamed_status = StreamHandler::answer(streamed).status();
		let duplexed_status = duplexed.map_err(|rejection| TransitCode::of_js(&rejection));
		assert_eq!(streamed_status, TransitStatus::Unknown);
		assert_eq!(duplexed_status, Err(TransitStatus::Unknown));
	}
}
