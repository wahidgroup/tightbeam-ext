//! Progressive body streaming bridges for the multiplexed wasm client.
//!
//! Wraps tightbeam [`RequestSink`] / [`StreamBody`] / [`ReplySink`] for
//! JavaScript. Pushes reach the wire eagerly, so a duplex exchange may
//! await a reply chunk between pushes. A known final chunk closes the
//! body in one record via `closeWith`.
//!
//! Every async method clones an `Rc` to shared state into the promise so
//! a GC of the JS wrapper mid-await cannot drop the response future.

use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use core::str::FromStr;
use std::rc::Rc;

use js_sys::{Function, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{future_to_promise, JsFuture};

use tightbeam::der::Decode;
use tightbeam::policy::TransitStatus;
use tightbeam::transport::multiplex::{
	MuxDispatch, MuxHandle, MuxResponder, ReplySink, RequestSink, StreamBody, StreamRoute,
};
use tightbeam::transport::{ResponsePackage, TransportResult};
use tightbeam::utils::marker::MaybeSend;
use tightbeam::utils::urn::Urn;
use tightbeam::Frame;

use crate::fault::{debug_coded, transport_to_js, validation};
use crate::mux::status_from_code;
use crate::promise::bytes_or_undefined;
use crate::secure::response_der;

type FrameResponseFut = Pin<Box<dyn Future<Output = TransportResult<Option<Frame>>> + 'static>>;

struct RequestInner {
	sink: Option<RequestSink>,
	response: Option<FrameResponseFut>,
}

/// Client-initiated streaming request: push chunks, then close for the
/// reassembled Frame response (or `undefined`).
#[wasm_bindgen(js_name = MuxRequestStream)]
pub struct MuxRequestStream {
	inner: Rc<RefCell<RequestInner>>,
}

#[wasm_bindgen(js_class = MuxRequestStream)]
impl MuxRequestStream {
	/// Open a progressive request stream on `handle`.
	pub(crate) fn open(handle: &MuxHandle) -> Result<MuxRequestStream, JsValue> {
		let (sink, response) = handle.open_stream().map_err(transport_to_js)?;
		Ok(Self::from_parts(sink, Box::pin(response)))
	}

	/// Open a progressive request routed to a servlet URN
	/// (`urn:<nid>:<nss>`). The Open carries the origin hop-budget
	/// sentinel so the first gateway applies its `max_hops` clamp.
	pub(crate) fn open_to(handle: &MuxHandle, target: &str) -> Result<MuxRequestStream, JsValue> {
		let urn = parse_stream_target(target)?;
		let (sink, response) = handle.open_stream_to(urn).map_err(transport_to_js)?;
		Ok(Self::from_parts(sink, Box::pin(response)))
	}

	fn from_parts(sink: RequestSink, response: FrameResponseFut) -> Self {
		Self {
			inner: Rc::new(RefCell::new(RequestInner { sink: Some(sink), response: Some(response) })),
		}
	}

	/// Push one request chunk. Empty chunks are no-ops on the wire.
	#[wasm_bindgen(js_name = push, unchecked_return_type = "Promise<void>")]
	pub fn push(&self, chunk: Vec<u8>) -> Promise {
		let inner = Rc::clone(&self.inner);
		future_to_promise(async move {
			let mut held = inner.borrow_mut().sink.take().ok_or_else(stream_closed)?;
			let outcome = held.push(&chunk).await;

			inner.borrow_mut().sink = Some(held);
			outcome.map_err(transport_to_js)?;

			Ok(JsValue::UNDEFINED)
		})
	}

	/// Flush `last`, then resolve with the response Frame DER (or
	/// `undefined`). Dropping without close cancels the stream.
	#[wasm_bindgen(js_name = close, unchecked_return_type = "Promise<Uint8Array | undefined>")]
	pub fn close(&self) -> Promise {
		let inner = Rc::clone(&self.inner);
		future_to_promise(async move {
			let held = inner.borrow_mut().sink.take().ok_or_else(stream_closed)?;
			held.close().await.map_err(transport_to_js)?;

			resolve_response(&inner).await
		})
	}

	/// Push the final request chunk with `last` set (one record fewer
	/// than push-then-close), then resolve with the response Frame
	/// DER (or `undefined`).
	#[wasm_bindgen(js_name = closeWith, unchecked_return_type = "Promise<Uint8Array | undefined>")]
	pub fn close_with(&self, chunk: Vec<u8>) -> Promise {
		let inner = Rc::clone(&self.inner);
		future_to_promise(async move {
			let held = inner.borrow_mut().sink.take().ok_or_else(stream_closed)?;
			held.close_with(&chunk).await.map_err(transport_to_js)?;

			resolve_response(&inner).await
		})
	}
}

/// Await the stashed response future and surface its Frame DER.
async fn resolve_response(inner: &RefCell<RequestInner>) -> Result<JsValue, JsValue> {
	let fut = inner.borrow_mut().response.take().ok_or_else(stream_closed)?;
	let frame = fut.await.map_err(transport_to_js)?;

	let der = response_der(frame)?;
	Ok(bytes_or_undefined(der))
}

struct DuplexInner {
	sink: Option<RequestSink>,
	body: Option<StreamBody>,
}

/// Client-initiated duplex stream: push request chunks while consuming
/// reply chunks via [`nextChunk`](Self::next_chunk).
#[wasm_bindgen(js_name = MuxDuplexStream)]
pub struct MuxDuplexStream {
	inner: Rc<RefCell<DuplexInner>>,
}

#[wasm_bindgen(js_class = MuxDuplexStream)]
impl MuxDuplexStream {
	/// Open an unrouted duplex stream on `handle`.
	pub(crate) fn open(handle: &MuxHandle) -> Result<MuxDuplexStream, JsValue> {
		let (sink, body) = handle.open_duplex().map_err(transport_to_js)?;
		Ok(Self::from_parts(sink, body))
	}

	/// Open a duplex stream routed to a servlet URN (`urn:<nid>:<nss>`).
	///
	/// The Open carries the origin hop-budget sentinel so the first
	/// gateway applies its `max_hops` clamp.
	pub(crate) fn open_to(handle: &MuxHandle, target: &str) -> Result<MuxDuplexStream, JsValue> {
		let urn = parse_stream_target(target)?;
		let (sink, body) = handle.open_duplex_to(urn).map_err(transport_to_js)?;
		Ok(Self::from_parts(sink, body))
	}

	fn from_parts(sink: RequestSink, body: StreamBody) -> Self {
		Self { inner: Rc::new(RefCell::new(DuplexInner { sink: Some(sink), body: Some(body) })) }
	}

	/// Push one request chunk. Chunks go out eagerly, so awaiting a
	/// reply chunk between pushes (a chunk-for-chunk conversation)
	/// is sound.
	#[wasm_bindgen(js_name = push, unchecked_return_type = "Promise<void>")]
	pub fn push(&self, chunk: Vec<u8>) -> Promise {
		let inner = Rc::clone(&self.inner);
		future_to_promise(async move {
			let mut held = inner.borrow_mut().sink.take().ok_or_else(stream_closed)?;
			let outcome = held.push(&chunk).await;

			inner.borrow_mut().sink = Some(held);
			outcome.map_err(transport_to_js)?;

			Ok(JsValue::UNDEFINED)
		})
	}

	/// Flush the request body's `last` flag.
	#[wasm_bindgen(js_name = close, unchecked_return_type = "Promise<void>")]
	pub fn close(&self) -> Promise {
		let inner = Rc::clone(&self.inner);
		future_to_promise(async move {
			let held = inner.borrow_mut().sink.take().ok_or_else(stream_closed)?;
			held.close().await.map_err(transport_to_js)?;

			Ok(JsValue::UNDEFINED)
		})
	}

	/// Push the final request chunk with `last` set, closing the
	/// request body in one record.
	#[wasm_bindgen(js_name = closeWith, unchecked_return_type = "Promise<void>")]
	pub fn close_with(&self, chunk: Vec<u8>) -> Promise {
		let inner = Rc::clone(&self.inner);
		future_to_promise(async move {
			let held = inner.borrow_mut().sink.take().ok_or_else(stream_closed)?;
			held.close_with(&chunk).await.map_err(transport_to_js)?;

			Ok(JsValue::UNDEFINED)
		})
	}

	/// Next reply chunk, or `undefined` after the peer's `last`.
	#[wasm_bindgen(js_name = nextChunk, unchecked_return_type = "Promise<Uint8Array | undefined>")]
	pub fn next_chunk(&self) -> Promise {
		let inner = Rc::clone(&self.inner);
		future_to_promise(async move {
			let mut held = inner.borrow_mut().body.take().ok_or_else(stream_closed)?;
			let outcome = held.chunk().await;

			inner.borrow_mut().body = Some(held);

			let chunk = outcome.map_err(transport_to_js)?;
			Ok(match chunk {
				Some(bytes) => Uint8Array::from(bytes.as_slice()).into(),
				None => JsValue::UNDEFINED,
			})
		})
	}
}

struct BodyInner {
	body: Option<StreamBody>,
}

/// Peer-initiated streaming body exposed to a JS `serveStreaming` handler.
#[wasm_bindgen(js_name = MuxStreamBody)]
pub struct MuxStreamBody {
	inner: Rc<RefCell<BodyInner>>,
}

#[wasm_bindgen(js_class = MuxStreamBody)]
impl MuxStreamBody {
	fn wrap(body: StreamBody) -> Self {
		Self { inner: Rc::new(RefCell::new(BodyInner { body: Some(body) })) }
	}

	/// Next request chunk, or `undefined` after the peer's `last`.
	#[wasm_bindgen(js_name = nextChunk, unchecked_return_type = "Promise<Uint8Array | undefined>")]
	pub fn next_chunk(&self) -> Promise {
		let inner = Rc::clone(&self.inner);
		future_to_promise(async move {
			let mut held = inner.borrow_mut().body.take().ok_or_else(stream_closed)?;
			let outcome = held.chunk().await;

			inner.borrow_mut().body = Some(held);

			let chunk = outcome.map_err(transport_to_js)?;
			Ok(match chunk {
				Some(bytes) => Uint8Array::from(bytes.as_slice()).into(),
				None => JsValue::UNDEFINED,
			})
		})
	}
}

struct ReplyInner {
	sink: Option<ReplySink>,
}

/// Reply half for a JS `serveDuplex` handler.
#[wasm_bindgen(js_name = MuxReplySink)]
pub struct MuxReplySink {
	inner: Rc<RefCell<ReplyInner>>,
}

#[wasm_bindgen(js_class = MuxReplySink)]
impl MuxReplySink {
	fn wrap(sink: ReplySink) -> Self {
		Self { inner: Rc::new(RefCell::new(ReplyInner { sink: Some(sink) })) }
	}

	/// Push one reply chunk toward the peer.
	#[wasm_bindgen(js_name = push, unchecked_return_type = "Promise<void>")]
	pub fn push(&self, chunk: Vec<u8>) -> Promise {
		let inner = Rc::clone(&self.inner);
		future_to_promise(async move {
			let mut held = inner.borrow_mut().sink.take().ok_or_else(stream_closed)?;
			let outcome = held.push(&chunk).await;

			inner.borrow_mut().sink = Some(held);
			outcome.map_err(transport_to_js)?;

			Ok(JsValue::UNDEFINED)
		})
	}
}

/// Drive `serve_streaming` through a JS handler that receives a
/// [`MuxStreamBody`] plus the Open's [`StreamRoute`], and returns a
/// Frame DER (or `undefined`).
pub(crate) async fn respond_streaming_via_js(
	handler: Function,
	body: StreamBody,
	route: StreamRoute,
) -> ResponsePackage {
	let body_arg: JsValue = MuxStreamBody::wrap(body).into();
	let route_arg = route_to_js(&route);
	match call_streaming_handler(&handler, &body_arg, &route_arg).await {
		Ok(response) => response,
		Err(_) => ResponsePackage::new(TransitStatus::Unknown, None),
	}
}

/// Drive `serve_duplex` through a JS handler that receives body, reply,
/// and the Open's [`StreamRoute`].
pub(crate) async fn respond_duplex_via_js(
	handler: Function,
	body: StreamBody,
	reply: ReplySink,
	route: StreamRoute,
) -> TransitStatus {
	let body_arg: JsValue = MuxStreamBody::wrap(body).into();
	let reply_arg: JsValue = MuxReplySink::wrap(reply).into();
	let route_arg = route_to_js(&route);
	match call_duplex_handler(&handler, &body_arg, &reply_arg, &route_arg).await {
		Ok(status) => status,
		Err(rejection) => refusal_status(&rejection),
	}
}

async fn call_streaming_handler(
	handler: &Function,
	body: &JsValue,
	route: &JsValue,
) -> Result<ResponsePackage, JsValue> {
	let returned = handler.call2(&JsValue::UNDEFINED, body, route)?;
	let settled = match returned.dyn_into::<Promise>() {
		Ok(promise) => JsFuture::from(promise).await?,
		Err(value) => value,
	};

	if settled.is_undefined() || settled.is_null() {
		return Ok(ResponsePackage::new(TransitStatus::Ok, None));
	}

	let response_der = Uint8Array::from(settled).to_vec();
	let response = Frame::from_der(&response_der).map_err(|error| debug_coded(&error))?;
	Ok(ResponsePackage::new(TransitStatus::Ok, Some(response)))
}

async fn call_duplex_handler(
	handler: &Function,
	body: &JsValue,
	reply: &JsValue,
	route: &JsValue,
) -> Result<TransitStatus, JsValue> {
	let returned = handler.call3(&JsValue::UNDEFINED, body, reply, route)?;
	let settled = match returned.dyn_into::<Promise>() {
		Ok(promise) => JsFuture::from(promise).await?,
		Err(value) => value,
	};

	if settled.is_undefined() || settled.is_null() {
		return Ok(TransitStatus::Ok);
	}

	let label = settled.as_string().ok_or_else(|| {
		validation(
			"InvalidDuplexStatus",
			"serveDuplex handler must resolve with a status name or undefined",
		)
	})?;
	if label == "Ok" {
		return Ok(TransitStatus::Ok);
	}

	Ok(status_from_code(&label))
}

fn refusal_status(rejection: &JsValue) -> TransitStatus {
	let code = Reflect::get(rejection, &JsValue::from_str("code"))
		.ok()
		.and_then(|value| value.as_string());
	match code {
		Some(name) => status_from_code(&name),
		None => TransitStatus::Unknown,
	}
}

fn stream_closed() -> JsValue {
	validation("StreamClosed", "the streaming handle is closed")
}

/// Parse a servlet target URN for routed stream opens.
fn parse_stream_target(target: &str) -> Result<Urn<'static>, JsValue> {
	Urn::from_str(target).map_err(|error| {
		validation(
			"InvalidStreamRoute",
			&format!("stream target must be a URN (urn:<nid>:<nss>): {error}"),
		)
	})
}

/// Format a servlet URN for JS without going through [`Display`].
fn urn_target_string(urn: &Urn<'_>) -> String {
	let mut target = String::with_capacity(4 + urn.nid.len() + 1 + urn.nss.len());
	target.push_str("urn:");
	target.push_str(urn.nid.as_ref());
	target.push(':');
	target.push_str(urn.nss.as_ref());
	target
}

/// JS view of the Open's [`StreamRoute`]: optional target string and
/// remaining hop budget.
fn route_to_js(route: &StreamRoute) -> JsValue {
	let object = Object::new();
	if let Some(target) = route.target() {
		let _ = Reflect::set(&object, &JsValue::from_str("target"), &JsValue::from(urn_target_string(target)));
	}

	let _ = Reflect::set(
		&object,
		&JsValue::from_str("hopsRemaining"),
		&JsValue::from(f64::from(route.hops_remaining())),
	);

	object.into()
}

/// Streaming-only dispatch: forwards body + Open route to JS. Other
/// kinds refuse through [`MuxDispatch`] defaults.
struct JsStreamingDispatch {
	handler: Rc<RefCell<Function>>,
}

impl MuxDispatch for JsStreamingDispatch {
	fn streaming(&self, body: StreamBody, route: StreamRoute) -> impl Future<Output = ResponsePackage> + MaybeSend {
		let current = self.handler.borrow().clone();
		async move { respond_streaming_via_js(current, body, route).await }
	}
}

/// Duplex-only dispatch: forwards body, reply, and Open route to JS.
struct JsDuplexDispatch {
	handler: Rc<RefCell<Function>>,
}

impl MuxDispatch for JsDuplexDispatch {
	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		route: StreamRoute,
	) -> impl Future<Output = TransitStatus> + MaybeSend {
		let current = self.handler.borrow().clone();
		async move { respond_duplex_via_js(current, body, reply, route).await }
	}
}

/// Spawn the streaming serve loop once, swapping out the responder.
pub(crate) fn start_serve_streaming(responder: MuxResponder, handler: Rc<RefCell<Function>>) {
	use wasm_bindgen_futures::spawn_local;

	spawn_local(async move {
		let _ = responder.serve_with(JsStreamingDispatch { handler }).await;
	});
}

/// Spawn the duplex serve loop once, swapping out the responder.
pub(crate) fn start_serve_duplex(responder: MuxResponder, handler: Rc<RefCell<Function>>) {
	use wasm_bindgen_futures::spawn_local;

	spawn_local(async move {
		let _ = responder.serve_with(JsDuplexDispatch { handler }).await;
	});
}
