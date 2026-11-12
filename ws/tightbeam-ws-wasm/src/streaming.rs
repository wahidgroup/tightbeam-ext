//! The progressive and duplex bodies of the multiplexed client, as the
//! browser transport section of `docs/ws-wasm.md` describes.

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::Pin;
use core::str::FromStr;
use std::rc::Rc;
use std::sync::Arc;

use futures_util::future::{AbortHandle, AbortRegistration, Abortable};
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

/// The response of a request stream, which its close awaits once, and the
/// socket it arrives on.
struct FrameResponseFut {
	response: Pin<Box<dyn Future<Output = TransportResult<Option<Frame>>> + 'static>>,
	/// Holds the socket open while this response lives.
	_connection: Rc<Connection>,
}

impl FrameResponseFut {
	/// Await the response and surface its Frame DER.
	async fn resolve(self) -> Result<JsValue, JsValue> {
		let frame = self.response.await.map_err(JsFault::from)?;

		let response = JsValue::try_from(JsResponse(frame))?;
		Ok(response)
	}
}

/// TypeScript shapes of the route a served stream reads and of the handler
/// each `serve*` call takes.
#[wasm_bindgen(typescript_custom_section)]
const SERVE_HANDLERS_TS: &'static str = r#"
/**
 * The Open route stamped on a progressive or duplex stream.
 */
export interface StreamRoute {
	/**
	 * The servlet target as `urn:<nid>:<nss>`, when the Open named one.
	 */
	readonly target?: string;
	/**
	 * The hop budget that remains on this Open.
	 */
	readonly hopsRemaining: number;
}

/**
 * The handler of `serve`: the request frame DER, answered with the response
 * frame DER, or `undefined` for a bodiless acceptance. A throw or a rejection
 * with a `TransitRefusal` label answers with that status, and any other throw
 * or rejection answers `Unknown`.
 */
export type UnaryServeHandler = (
	requestDer: Uint8Array,
) => Promise<Uint8Array | undefined> | Uint8Array | undefined;

/**
 * The handler of `serveStreaming`: the request body and the Open route,
 * answered as a `UnaryServeHandler` answers.
 */
export type StreamingServeHandler = (
	body: MuxStreamBody,
	route: StreamRoute,
) => Promise<Uint8Array | undefined> | Uint8Array | undefined;

/**
 * The handler of `serveDuplex`: the request body, the reply half, and the
 * Open route, answered with the refusal that ends the stream, or `undefined`
 * for `Ok`. A throw or a rejection answers as it does for a
 * `UnaryServeHandler`.
 */
export type DuplexServeHandler = (
	body: MuxStreamBody,
	reply: MuxReplySink,
	route: StreamRoute,
) => Promise<TransitRefusal | undefined> | TransitRefusal | undefined;
"#;

/// Why a call on a closed stream half refuses.
const STREAM_CLOSED: &str = "the streaming handle is closed";

/// A stream half that one call at a time holds.
///
/// A call leases the half for the length of its await, so a second call in
/// that span finds the half busy rather than closed. The slot ends the call
/// that holds the half as it drops, so the half drops with its owner.
struct Slot<T>(Rc<Cell<SlotState<T>>>);

/// What a [`Slot`] holds between calls.
enum SlotState<T> {
	/// The half waits for the next call.
	Ready(T),
	/// A call holds the half, and the handle ends that call.
	Busy(AbortHandle),
	/// A close consumed the half, or the slot ended the call that held it.
	Closed,
}

impl<T> Slot<T> {
	/// A slot whose half waits for the first call.
	fn new(half: T) -> Self {
		Self(Rc::new(Cell::new(SlotState::Ready(half))))
	}

	/// Lease the half to one call now. The call runs once the lease is
	/// [run](Lease::run), and the slot can end it from this moment on.
	///
	/// # Errors
	///
	/// - `StreamBusy` -- another call holds the half.
	/// - `StreamClosed` -- a close consumed the half.
	fn lease(&self) -> Result<Lease<T>, JsFault> {
		let (abort, registration) = AbortHandle::new_pair();
		let half = self.take_leaving(SlotState::Busy(abort))?;
		let guard = LeaseGuard(Rc::clone(&self.0));

		Ok(Lease { guard, half, registration })
	}

	/// Take the half for a close, which consumes it.
	///
	/// # Errors
	///
	/// - The errors of [`Self::lease`].
	fn retire(&self) -> Result<T, JsFault> {
		self.take_leaving(SlotState::Closed)
	}

	/// Take the half and leave `next` in its place. A slot that holds no half
	/// keeps its state and refuses.
	fn take_leaving(&self, next: SlotState<T>) -> Result<T, JsFault> {
		match self.0.replace(next) {
			SlotState::Ready(half) => Ok(half),
			SlotState::Busy(abort) => {
				self.0.set(SlotState::Busy(abort));
				Err(RefusalCode::StreamBusy.because("another call holds this stream half"))
			}
			SlotState::Closed => {
				self.0.set(SlotState::Closed);
				Err(RefusalCode::StreamClosed.because(STREAM_CLOSED))
			}
		}
	}
}

/// The owner of the half is gone: the call that holds the half ends at once,
/// and a half that waits drops now.
impl<T> Drop for Slot<T> {
	fn drop(&mut self) {
		if let SlotState::Busy(abort) = self.0.replace(SlotState::Closed) {
			abort.abort();
		}
	}
}

/// The half of a [`Slot`] that one call holds.
struct Lease<T> {
	guard: LeaseGuard<T>,
	half: T,
	registration: AbortRegistration,
}

/// How a leased call ended.
enum Lent<R> {
	/// The call ran to its end.
	Done(R),
	/// The slot ended the call first.
	Ended,
}

impl<T> Lease<T> {
	/// Run `call` over the half, and hand the half back once it ends, unless
	/// the slot ended the call first.
	async fn run<R>(self, call: impl AsyncFnOnce(&mut T) -> R) -> Lent<R> {
		let Self { guard, mut half, registration } = self;

		let outcome = Abortable::new(call(&mut half), registration).await;
		match outcome {
			Ok(done) => {
				guard.hand_back(half);
				Lent::Done(done)
			}
			Err(_) => Lent::Ended,
		}
	}
}

impl<R> Lent<R> {
	/// The outcome of a call whose end by the slot reads as a closed half.
	///
	/// # Errors
	///
	/// - `StreamClosed` -- the slot ended the call.
	fn closed_if_ended(self) -> Result<R, JsFault> {
		match self {
			Self::Done(done) => Ok(done),
			Self::Ended => Err(RefusalCode::StreamClosed.because(STREAM_CLOSED)),
		}
	}
}

/// The hold of a [`Lease`] on its slot. A lease that drops before it hands
/// the half back leaves the slot closed, because the half drops with it.
struct LeaseGuard<T>(Rc<Cell<SlotState<T>>>);

impl<T> LeaseGuard<T> {
	/// Hand `half` back for the next call, unless the slot closed while the
	/// call ran.
	fn hand_back(self, half: T) {
		if let SlotState::Busy(_) = self.0.replace(SlotState::Closed) {
			self.0.set(SlotState::Ready(half));
		}
	}
}

impl<T> Drop for LeaseGuard<T> {
	fn drop(&mut self) {
		let current = self.0.replace(SlotState::Closed);
		if !matches!(current, SlotState::Busy(_)) {
			self.0.set(current);
		}
	}
}

/// A stream half that pushes one chunk per call toward the peer.
trait PushHalf {
	/// Push `chunk`. An empty chunk sends nothing to the peer.
	fn push_chunk(&mut self, chunk: &[u8]) -> impl Future<Output = TransportResult<()>>;
}

impl PushHalf for RequestSink {
	fn push_chunk(&mut self, chunk: &[u8]) -> impl Future<Output = TransportResult<()>> {
		self.push(chunk)
	}
}

impl PushHalf for ReplySink {
	fn push_chunk(&mut self, chunk: &[u8]) -> impl Future<Output = TransportResult<()>> {
		self.push(chunk)
	}
}

impl<T: PushHalf + 'static> Slot<T> {
	/// Push `chunk` through the half, and keep `holder`, the shared state of
	/// the stream, until the push settles.
	fn push(&self, chunk: JsBytes, holder: impl Sized + 'static) -> Promise {
		let leased = chunk.read().and_then(|chunk| Ok((chunk, self.lease()?)));
		future_to_promise(async move {
			let _holder = holder;
			let (chunk, lease) = leased?;
			let pushed = lease.run(async |half: &mut T| half.push_chunk(&chunk).await).await;
			pushed.closed_if_ended()?.map_err(JsFault::from)?;

			Ok(JsValue::UNDEFINED)
		})
	}
}

impl Slot<RequestSink> {
	/// Take the half for a close that sends `last` with no payload, and keep
	/// `holder`, the shared state of the stream, until the close settles.
	fn close(&self, holder: impl Sized + 'static) -> impl Future<Output = Result<(), JsValue>> + 'static {
		let held = self.retire();
		async move {
			let _holder = holder;
			held?.close().await.map_err(JsFault::from)?;

			Ok(())
		}
	}

	/// Take the half for a close that sends `chunk` with `last` set, and keep
	/// `holder`, the shared state of the stream, until the close settles.
	fn close_with(
		&self,
		chunk: JsBytes,
		holder: impl Sized + 'static,
	) -> impl Future<Output = Result<(), JsValue>> + 'static {
		let closing = chunk.read().and_then(|chunk| Ok((chunk, self.retire()?)));
		async move {
			let _holder = holder;
			let (chunk, held) = closing?;
			held.close_with(&chunk).await.map_err(JsFault::from)?;

			Ok(())
		}
	}
}

struct RequestInner {
	sink: Slot<RequestSink>,
	/// Holds the socket open for the handle of this stream, its pushes, and
	/// its close.
	_connection: Rc<Connection>,
}

/// Client-initiated streaming request: push chunks, then close for the
/// reassembled Frame response (or `undefined`).
#[wasm_bindgen(js_name = MuxRequestStream)]
pub struct MuxRequestStream {
	inner: Rc<RequestInner>,
	/// The response, which the close of this handle awaits.
	response: FrameResponseFut,
}

#[wasm_bindgen(js_class = MuxRequestStream)]
impl MuxRequestStream {
	/// Open a progressive request stream on `connection`, which the stream
	/// holds.
	pub(crate) fn open(connection: Rc<Connection>) -> Result<MuxRequestStream, JsFault> {
		let (sink, response) = connection.handle().open_stream().map_err(JsFault::from)?;
		Ok(Self::from_parts(sink, response, connection))
	}

	/// Open a progressive request routed to a servlet URN
	/// (`urn:<nid>:<nss>`). The Open carries the origin hop-budget
	/// sentinel so the first gateway applies its `max_hops` clamp.
	pub(crate) fn open_to(connection: Rc<Connection>, target: StreamTarget) -> Result<MuxRequestStream, JsFault> {
		let StreamTarget(urn) = target;
		let (sink, response) = connection.handle().open_stream_to(urn).map_err(JsFault::from)?;
		Ok(Self::from_parts(sink, response, connection))
	}

	fn from_parts(
		sink: RequestSink,
		response: impl Future<Output = TransportResult<Option<Frame>>> + 'static,
		connection: Rc<Connection>,
	) -> Self {
		let response = FrameResponseFut { response: Box::pin(response), _connection: Rc::clone(&connection) };
		let inner = RequestInner { sink: Slot::new(sink), _connection: connection };
		Self { inner: Rc::new(inner), response }
	}

	/// Push one request chunk. An empty chunk sends nothing.
	#[wasm_bindgen(js_name = push, unchecked_return_type = "Promise<void>")]
	pub fn push(&self, chunk: JsBytes) -> Promise {
		let holder = Rc::clone(&self.inner);
		self.inner.sink.push(chunk, holder)
	}

	/// Flush `last`, then resolve with the response Frame DER (or
	/// `undefined`). Dropping without close cancels the stream.
	///
	/// - The close consumes this handle.
	/// - A close while a push is in flight refuses with `StreamBusy`, and the stream then cancels once that
	///   push settles.
	#[wasm_bindgen(js_name = close, unchecked_return_type = "Promise<Uint8Array | undefined>")]
	pub fn close(self) -> Promise {
		let Self { inner, response } = self;
		let closing = inner.sink.close(Rc::clone(&inner));
		future_to_promise(async move {
			closing.await?;

			response.resolve().await
		})
	}

	/// Push the final request chunk with `last` set (one record fewer
	/// than push-then-close), then resolve with the response Frame
	/// DER (or `undefined`).
	///
	/// The close consumes this handle, as [`close`](Self::close) does.
	#[wasm_bindgen(js_name = closeWith, unchecked_return_type = "Promise<Uint8Array | undefined>")]
	pub fn close_with(self, chunk: JsBytes) -> Promise {
		let Self { inner, response } = self;
		let closing = inner.sink.close_with(chunk, Rc::clone(&inner));
		future_to_promise(async move {
			closing.await?;

			response.resolve().await
		})
	}
}

struct DuplexInner {
	sink: Slot<RequestSink>,
	/// Holds the socket open for the handle of this stream, its pushes, and
	/// its close.
	_connection: Rc<Connection>,
}

/// Client-initiated duplex stream: push request chunks, and read the reply
/// chunks through the body that [`takeBody`](Self::take_body) moves into a
/// handle of its own.
///
/// - The request half and the reply body end apart.
/// - A close consumes this handle, and the reply body still reads until the peer's `last`.
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
	pub(crate) fn open_to(connection: Rc<Connection>, target: StreamTarget) -> Result<MuxDuplexStream, JsFault> {
		let StreamTarget(urn) = target;
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
		let holder = Rc::clone(&self.inner);
		self.inner.sink.push(chunk, holder)
	}

	/// Flush the request body's `last` flag.
	///
	/// The close consumes this handle, as [`MuxRequestStream::close`] does,
	/// and a reply body still held here drops with it.
	#[wasm_bindgen(js_name = close, unchecked_return_type = "Promise<void>")]
	pub fn close(self) -> Promise {
		let inner = self.inner;
		let closing = inner.sink.close(Rc::clone(&inner));
		future_to_promise(async move {
			closing.await?;

			Ok(JsValue::UNDEFINED)
		})
	}

	/// Push the final request chunk with `last` set, closing the
	/// request body in one record.
	///
	/// The close consumes this handle, as [`close`](Self::close) does.
	#[wasm_bindgen(js_name = closeWith, unchecked_return_type = "Promise<void>")]
	pub fn close_with(self, chunk: JsBytes) -> Promise {
		let inner = self.inner;
		let closing = inner.sink.close_with(chunk, Rc::clone(&inner));
		future_to_promise(async move {
			closing.await?;

			Ok(JsValue::UNDEFINED)
		})
	}
}

struct BodyInner {
	body: Slot<StreamBody>,
	/// Holds the socket open while the reply body of a client-initiated
	/// duplex stream lives. A served body leaves that hold to its serve loop.
	_connection: Option<Rc<Connection>>,
}

/// A streamed body that JavaScript reads chunk by chunk: the request body of
/// a stream that a `serveStreaming` or `serveDuplex` handler answers, or the
/// reply body of a client-initiated duplex stream.
///
/// - A free of the handle before the peer's `last` discards the chunks still to come.
/// - On a duplex reply body, the free cancels the stream at once, and a read still in flight ends with
///   `undefined`.
#[wasm_bindgen(js_name = MuxStreamBody)]
pub struct MuxStreamBody {
	inner: Rc<BodyInner>,
}

#[wasm_bindgen(js_class = MuxStreamBody)]
impl MuxStreamBody {
	/// The request body of a served stream.
	fn wrap(body: StreamBody) -> Self {
		let inner = BodyInner { body: Slot::new(body), _connection: None };
		Self { inner: Rc::new(inner) }
	}

	/// The reply body of a duplex stream on `connection`, which the body
	/// holds.
	fn reply(body: StreamBody, connection: Rc<Connection>) -> Self {
		let inner = BodyInner { body: Slot::new(body), _connection: Some(connection) };
		Self { inner: Rc::new(inner) }
	}

	/// Next chunk, or `undefined` after the peer's `last`, or once a free of
	/// the handle ended the read.
	///
	/// The read holds the body from this call on, so a free that lands before
	/// the read first runs still ends it.
	#[wasm_bindgen(js_name = nextChunk, unchecked_return_type = "Promise<Uint8Array | undefined>")]
	pub fn next_chunk(&self) -> Promise {
		let lease = self.inner.body.lease();
		future_to_promise(async move {
			let read = lease?.run(async |held: &mut StreamBody| held.chunk().await).await;
			let Lent::Done(chunk) = read else {
				return Ok(JsValue::UNDEFINED);
			};

			let chunk = chunk.map_err(JsFault::from)?;
			Ok(match chunk {
				Some(bytes) => Uint8Array::from(bytes.as_slice()).into(),
				None => JsValue::UNDEFINED,
			})
		})
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
		let holder = Rc::clone(&self.inner);
		self.inner.sink.push(chunk, holder)
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
	/// status that [`Self::refused`] reads from it.
	fn answer(outcome: Result<ResponsePackage, JsValue>) -> ResponsePackage {
		outcome.unwrap_or_else(|rejection| ResponsePackage::new(Self::refused(&rejection), None))
	}

	/// The status that a settlement `value` refuses the stream with: the
	/// refusal its label names, and `Unknown` for `Ok` and for any value that
	/// is no label.
	fn refused(value: &JsValue) -> TransitStatus {
		let label = value.as_string();
		let refusal = label.as_deref().and_then(TransitCode::refusal);
		refusal.map_or(TransitStatus::Unknown, TransitStatus::from)
	}

	/// Answer one duplex stream through a body, a reply, and the Open's
	/// [`StreamRoute`].
	async fn respond_duplex(self, body: StreamBody, reply: ReplySink, route: StreamRoute) -> TransitStatus {
		let body_arg: JsValue = MuxStreamBody::wrap(body).into();
		let reply_arg: JsValue = MuxReplySink::wrap(reply).into();
		let route_arg = JsValue::from(JsRoute(&route));
		match self.call_duplex(&body_arg, &reply_arg, &route_arg).await {
			Ok(status) => status,
			Err(rejection) => Self::refused(&rejection),
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
	/// [`Self::refused`] reads from it.
	async fn call_duplex(&self, body: &JsValue, reply: &JsValue, route: &JsValue) -> Result<TransitStatus, JsValue> {
		let returned = self.0.call3(&JsValue::UNDEFINED, body, reply, route).map(Returned::from)?;
		let settled = returned.settle().await?;
		let Some(settled) = Record::present(settled) else {
			return Ok(TransitStatus::Ok);
		};

		let status = Self::refused(&settled);
		Ok(status)
	}
}

/// The servlet URN that a routed stream open or a work submission targets.
pub(crate) struct StreamTarget(pub(crate) Urn<'static>);

impl StreamTarget {
	/// Parse `value`, the field at `path`, as `urn:<nid>:<nss>`.
	///
	/// # Errors
	///
	/// - `InvalidStreamRoute` -- `value` is no URN string.
	pub(crate) fn read(value: &JsValue, path: &str) -> Result<Self, JsFault> {
		let refused = |message: String| RefusalCode::InvalidStreamRoute.because(message).at(path);
		let target = value.as_string().ok_or_else(|| refused(String::from("must be a string")))?;

		let urn = Urn::from_str(&target);
		let refusal = |error| refused(format!("stream target must be a URN (urn:<nid>:<nss>): {error}"));
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
	use core::cell::RefCell;
	use core::future::{pending, Future};
	use std::rc::Rc;

	use futures_util::FutureExt;
	use js_sys::{Function, Promise};
	use tightbeam::marker::MaybeSend;
	use tightbeam::policy::TransitStatus;
	use tightbeam::testing::TestFrame;
	use tightbeam::transport::multiplex::{MuxDispatch, ReplySink, StreamBody, StreamRoute};
	use tightbeam::transport::{TransportError, TransportFailure, TransportResult};
	use wasm_bindgen::JsValue;
	use wasm_bindgen_futures::{spawn_local, JsFuture};
	use wasm_bindgen_test::wasm_bindgen_test;

	use super::{MuxStreamBody, ServeHandler, Slot, StreamHandler};
	use crate::fault::{JsFault, Refused};
	use crate::loopback::{settled, Loopback};
	use crate::mux::SessionParts;

	/// A call that takes the half of `slot` and holds it until the call drops.
	fn holding(slot: &Slot<()>) -> impl Future<Output = Result<(), JsFault>> {
		let lease = slot.lease();
		let mut call = Box::pin(async move { lease?.run(async |_| pending::<()>().await).await.closed_if_ended() });
		let _ = (&mut call).now_or_never();

		call
	}

	/// A call that hands the half of `slot` back at once.
	async fn passing(slot: &Slot<()>) -> Result<(), JsFault> {
		slot.lease()?.run(async |_| ()).await.closed_if_ended()
	}

	/// A `serve*` handler that resolves with a number in place of bytes.
	fn numeric_handler() -> StreamHandler {
		let function = Function::new_no_args("return 7");
		StreamHandler(function)
	}

	/// A `serve*` handler that rejects with the label of a gRPC status.
	fn refusing_handler() -> Function {
		Function::new_no_args("return Promise.reject('PermissionDenied')")
	}

	/// A `serveDuplex` handler that resolves with the label `Ok`.
	fn resolving_ok_handler() -> StreamHandler {
		let function = Function::new_no_args("return Promise.resolve('Ok')");
		StreamHandler(function)
	}

	/// A `serve*` handler that rejects with the label `Ok`.
	fn rejecting_ok_handler() -> Function {
		Function::new_no_args("return Promise.reject('Ok')")
	}

	/// A `serve` handler that rethrows a peer refusal: an error whose `code`
	/// names the status `Unavailable`.
	fn peer_refusal_handler() -> Function {
		let body = "const refusal = new Error('the inner call was refused'); \
		            refusal.name = 'TightbeamTransportError'; refusal.code = 'Unavailable'; \
		            return Promise.reject(refusal)";
		Function::new_no_args(body)
	}

	/// Serve the streams of `server` through `dispatch` until the test ends.
	fn serve(server: SessionParts, dispatch: impl MuxDispatch + 'static) {
		spawn_local(async move {
			let served = server;
			let _ = served.responder.serve_with(dispatch).await;
			pending::<()>().await;
		});
	}

	/// The outcome of one emit that the server answers through a unary serve
	/// loop of `handler`, over a real socket.
	async fn served_unary(handler: Function) -> TransportResult<Option<tightbeam::Frame>> {
		let loopback = Loopback::open(1).await;
		let Loopback { client, server, .. } = loopback;
		serve(server, ServeHandler::new(handler).unary());

		settled(client.handle.emit_on_stream(&TestFrame::v0(None, None))).await
	}

	/// The response to one empty request stream that the server answers
	/// through a streaming serve loop of `handler`, over a real socket.
	async fn served_streaming(handler: Function) -> TransportResult<Option<tightbeam::Frame>> {
		let loopback = Loopback::open(1).await;
		let Loopback { client, server, .. } = loopback;
		serve(server, ServeHandler::new(handler).streaming());

		let (sink, response) = client.handle.open_stream()?;
		settled(sink.close()).await?;
		settled(response).await
	}

	/// The first read of the reply body of one empty duplex stream that the
	/// server answers through a duplex serve loop of `handler`, over a real
	/// socket.
	async fn served_duplex(handler: Function) -> TransportResult<Option<Vec<u8>>> {
		let loopback = Loopback::open(1).await;
		let Loopback { client, server, .. } = loopback;
		serve(server, ServeHandler::new(handler).duplex());

		let (sink, mut body) = client.handle.open_duplex()?;
		settled(sink.close()).await?;
		settled(body.chunk()).await
	}

	/// A served duplex stream whose reply half the test takes, and the promise
	/// that settles once the server dispatched it.
	struct ReplyHandoff {
		reply: Rc<RefCell<Option<ReplySink>>>,
		arrived: Function,
	}

	impl MuxDispatch for ReplyHandoff {
		fn duplex(
			&self,
			body: StreamBody,
			reply: ReplySink,
			_route: StreamRoute,
		) -> impl Future<Output = TransportResult<TransitStatus>> + MaybeSend {
			self.reply.borrow_mut().replace(reply);
			let _ = self.arrived.call0(&JsValue::UNDEFINED);

			async move {
				let _held = body;
				pending::<()>().await;
				Ok(TransitStatus::Ok)
			}
		}
	}

	/// The reply slot that a [`ReplyHandoff`] fills, the dispatch that fills
	/// it, and the promise of its arrival.
	fn reply_handoff() -> (Rc<RefCell<Option<ReplySink>>>, ReplyHandoff, Promise) {
		let reply = Rc::new(RefCell::new(None));
		let mut resolve = None;
		let arrival = Promise::new(&mut |settle, _reject| resolve = Some(settle));
		let arrived = resolve.expect("the promise executor runs at once");

		let handoff = ReplyHandoff { reply: Rc::clone(&reply), arrived };
		(reply, handoff, arrival)
	}

	#[wasm_bindgen_test]
	async fn a_free_ends_the_read_that_holds_the_body() {
		let loopback = Loopback::open(1).await;
		let Loopback { client, server, .. } = loopback;
		let (reply, handoff, arrival) = reply_handoff();
		serve(server, handoff);

		let (mut sink, body) = client.handle.open_duplex().expect("the client should open a duplex stream");
		let opened = settled(sink.push(b"open")).await;
		opened.expect("the first push should open the stream");
		let arrived = settled(JsFuture::from(arrival)).await;
		arrived.expect("the server should dispatch the stream");

		let body = MuxStreamBody::wrap(body);
		let reading = JsFuture::from(body.next_chunk());
		let busy = settled(JsFuture::from(body.next_chunk())).await;
		drop(body);

		let late = reply.borrow_mut().take().expect("the server holds the reply half");
		let _ = settled(async move {
			let mut late = late;
			late.push(b"late").await
		})
		.await;

		let first = settled(reading).await.expect("the read should settle");
		assert_eq!(busy.code().as_deref(), Some("StreamBusy"));
		assert!(first.is_undefined());
		drop(sink);
	}

	#[wasm_bindgen_test]
	async fn a_rejection_whose_code_names_a_status_answers_the_peer_unknown() {
		let answered = served_unary(peer_refusal_handler()).await;
		assert!(matches!(
			answered,
			Err(TransportError::OperationFailed(TransportFailure::Unknown))
		));
	}

	#[wasm_bindgen_test]
	async fn a_rejection_with_a_refusal_label_answers_the_peer_its_status() {
		let answered = served_unary(Function::new_no_args("return Promise.reject('NotFound')")).await;
		assert!(matches!(
			answered,
			Err(TransportError::OperationFailed(TransportFailure::NotFound))
		));
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
	async fn a_dropped_call_closes_the_half() {
		let slot = Slot::new(());
		drop(holding(&slot));

		let after = passing(&slot).await;
		assert_eq!(after.code().as_deref(), Some("StreamClosed"));
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
		let answered = settled(numeric_handler().call_unary(&frame)).await;
		assert_eq!(answered.code().as_deref(), Some("InvalidBytes"));
	}

	#[wasm_bindgen_test]
	async fn a_refusal_label_answers_its_status_on_both_serve_paths() {
		let streamed = served_streaming(refusing_handler()).await;
		let duplexed = served_duplex(refusing_handler()).await;

		assert!(matches!(
			streamed,
			Err(TransportError::OperationFailed(TransportFailure::PermissionDenied))
		));
		assert!(matches!(
			duplexed,
			Err(TransportError::OperationFailed(TransportFailure::PermissionDenied))
		));
	}

	#[wasm_bindgen_test]
	async fn a_number_from_a_streaming_handler_is_no_response() {
		let undefined = JsValue::UNDEFINED;
		let answered = settled(numeric_handler().call_streaming(&undefined, &undefined)).await;
		assert_eq!(answered.code().as_deref(), Some("InvalidBytes"));
	}

	#[wasm_bindgen_test]
	async fn a_duplex_handler_resolving_ok_answers_unknown() {
		let undefined = JsValue::UNDEFINED;
		let resolved = settled(resolving_ok_handler().call_duplex(&undefined, &undefined, &undefined)).await;
		assert_eq!(resolved.ok(), Some(TransitStatus::Unknown));
	}

	#[wasm_bindgen_test]
	async fn a_handler_rejecting_with_ok_answers_unknown_on_both_serve_paths() {
		let streamed = served_streaming(rejecting_ok_handler()).await;
		let duplexed = served_duplex(rejecting_ok_handler()).await;

		assert!(matches!(
			streamed,
			Err(TransportError::OperationFailed(TransportFailure::Unknown))
		));
		assert!(matches!(
			duplexed,
			Err(TransportError::OperationFailed(TransportFailure::Unknown))
		));
	}
}
