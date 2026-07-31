//! Browser WebSocket construction with lifecycle observation. Compiled
//! only for `wasm32` targets.
//!
//! Every client opens its socket through [`open_observed`], which attaches
//! a `close` listener before any traffic flows. The resulting
//! [`SocketMonitor`] backs the `closed` promise and `readyState` getters
//! the bindings expose, so callers learn about connection loss without
//! waiting for the next emit to fail.

use core::cell::RefCell;
use std::rc::Rc;

use gloo_net::websocket::futures::WebSocket;
use js_sys::{Function, Object, Promise, Reflect};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{AddEventListenerOptions, CloseEvent};

use crate::fault::{connection_closed, to_js};

/// TypeScript shape of the value the `closed` promise resolves with.
#[wasm_bindgen(typescript_custom_section)]
const SOCKET_CLOSE_INFO_TS: &'static str = r#"
/**
 * How a WebSocket session ended: the close frame's code and reason, and
 * whether closure was clean.
 *
 * # Sources
 *
 * - RFC 6455 § 7.1.4, The WebSocket Connection Close Code:
 *   <https://datatracker.ietf.org/doc/html/rfc6455#section-7.1.4>
 * - RFC 6455 § 7.4, Status Codes:
 *   <https://datatracker.ietf.org/doc/html/rfc6455#section-7.4>
 */
export interface SocketCloseInfo {
	/**
	 * Close status code.
	 */
	readonly code: number;
	/**
	 * Close reason supplied by the peer, or empty.
	 */
	readonly reason: string;
	/**
	 * Whether the closing handshake completed cleanly.
	 */
	readonly wasClean: boolean;
}
"#;

/// A browser WebSocket plus its lifecycle monitor.
pub(crate) struct ObservedSocket {
	/// The socket, ready to carry tightbeam envelopes.
	pub(crate) socket: WebSocket,
	/// The lifecycle surface for the same connection.
	pub(crate) monitor: SocketMonitor,
}

/// Lifecycle observation for one WebSocket connection. Clones observe
/// the same socket, so abort paths can close it from inside a future
/// that must not borrow the wasm object.
#[derive(Clone)]
pub(crate) struct SocketMonitor {
	raw: web_sys::WebSocket,
	closed: Promise,
}

impl SocketMonitor {
	/// A promise resolving with a `SocketCloseInfo` when the socket closes.
	pub(crate) fn closed(&self) -> Promise {
		self.closed.clone()
	}

	/// The socket's readyState (0 CONNECTING, 1 OPEN, 2 CLOSING, 3 CLOSED).
	pub(crate) fn ready_state(&self) -> u16 {
		self.raw.ready_state()
	}

	/// Close the underlying socket. The `closed` promise resolves once the
	/// close completes. Does nothing on an already-closed socket.
	pub(crate) fn close(&self) {
		let _ = self.raw.close();
	}

	/// A promise resolving (with `undefined`) once the socket is open,
	/// rejecting with a structured `ConnectionClosed` error when it
	/// closes first: a failed dial.
	///
	/// Constructed on demand so sessions that never await it hold no
	/// rejectable promise that would surface as an unhandled rejection.
	pub(crate) fn opened(&self) -> Promise {
		const CONNECTING: u16 = 0;
		const OPEN: u16 = 1;

		match self.raw.ready_state() {
			OPEN => Promise::resolve(&JsValue::UNDEFINED),
			CONNECTING => open_promise(&self.raw),
			_ => Promise::reject(&connection_closed("the socket closed before it opened")),
		}
	}
}

/// Open `url` and attach the close observer before any traffic flows.
pub(crate) fn open_observed(url: &str) -> Result<ObservedSocket, JsValue> {
	let raw = web_sys::WebSocket::new(url)?;
	let closed = close_promise(&raw);

	let socket = WebSocket::try_from(raw.clone()).map_err(to_js)?;
	let monitor = SocketMonitor { raw, closed };
	Ok(ObservedSocket { socket, monitor })
}

/// The settlers and listeners pending on one connecting socket, taken as
/// a unit by whichever lifecycle event fires first.
struct OpenWatch {
	resolve: Function,
	reject: Function,
	on_open: Closure<dyn FnMut(JsValue)>,
	on_close: Closure<dyn FnMut(CloseEvent)>,
}

/// Shared slot the racing `open`/`close` listeners drain the watch from.
type OpenWatchSlot = Rc<RefCell<Option<OpenWatch>>>;

/// A promise settled by a connecting socket's first lifecycle event:
/// `open` resolves it, `close` rejects it with a structured
/// `ConnectionClosed` error. Whichever event fires first takes the watch,
/// detaching both listeners and freeing both closures.
fn open_promise(raw: &web_sys::WebSocket) -> Promise {
	let target = raw.clone();
	Promise::new(&mut move |resolve: Function, reject: Function| {
		let slot = OpenWatchSlot::default();

		let open_slot = Rc::clone(&slot);
		let open_target = target.clone();
		let on_open = Closure::<dyn FnMut(JsValue)>::new(move |_event: JsValue| {
			if let Some(watch) = take_watch(&open_slot, &open_target) {
				let _ = watch.resolve.call0(&JsValue::UNDEFINED);
			}
		});

		let close_slot = Rc::clone(&slot);
		let close_target = target.clone();
		let on_close = Closure::<dyn FnMut(CloseEvent)>::new(move |event: CloseEvent| {
			if let Some(watch) = take_watch(&close_slot, &close_target) {
				let message = format!("the socket closed before it opened (code {})", event.code());
				let _ = watch.reject.call1(&JsValue::UNDEFINED, &connection_closed(&message));
			}
		});

		listen_once(&target, "open", &on_open);
		listen_once(&target, "close", &on_close);

		slot.borrow_mut().replace(OpenWatch { resolve, reject, on_open, on_close });
	})
}

/// Drain the watch and detach both listeners. The caller settles the
/// promise and drops the watch; the closure currently executing is freed
/// once its call returns (the shim defers deallocation while invoked).
fn take_watch(slot: &OpenWatchSlot, target: &web_sys::WebSocket) -> Option<OpenWatch> {
	let watch = slot.borrow_mut().take()?;
	detach(target, "open", &watch.on_open);
	detach(target, "close", &watch.on_close);
	Some(watch)
}

/// Register `listener` for one dispatch of `event` on `target`.
fn listen_once<E>(target: &web_sys::WebSocket, event: &str, listener: &Closure<dyn FnMut(E)>) {
	let options = AddEventListenerOptions::new();
	options.set_once(true);

	let _ = target.add_event_listener_with_callback_and_add_event_listener_options(
		event,
		listener.as_ref().unchecked_ref(),
		&options,
	);
}

/// Detach `listener` from `event` on `target`.
fn detach<E>(target: &web_sys::WebSocket, event: &str, listener: &Closure<dyn FnMut(E)>) {
	let _ = target.remove_event_listener_with_callback(event, listener.as_ref().unchecked_ref());
}

/// Shared slot from which the `close` listener drains itself on dispatch.
type CloseListenerSlot = Rc<RefCell<Option<Closure<dyn FnMut(CloseEvent)>>>>;

/// A promise resolved with the connection's close info on the `close` event.
///
/// The `close` event reaches this target from two sources: the runtime's
/// genuine close event, and the synthetic one `gloo` dispatches when the
/// socket wrapper drops. The listener is registered with `once` so the
/// platform detaches it after the first dispatch, which also drains its
/// own closure from the shared slot to free it.
fn close_promise(raw: &web_sys::WebSocket) -> Promise {
	let target = raw.clone();
	Promise::new(&mut move |resolve: Function, _reject: Function| {
		let slot = CloseListenerSlot::default();

		let held = Rc::clone(&slot);
		// The resolver moves out on the first dispatch.
		let mut resolver = Some(resolve);
		let listener = Closure::<dyn FnMut(CloseEvent)>::new(move |event: CloseEvent| {
			drop(held.borrow_mut().take());
			if let Some(resolve) = resolver.take() {
				let info = close_info(&event);
				let _ = resolve.call1(&JsValue::UNDEFINED, &info);
			}
		});

		listen_once(&target, "close", &listener);
		slot.borrow_mut().replace(listener);
	})
}

/// The `SocketCloseInfo` object for one close event.
fn close_info(event: &CloseEvent) -> JsValue {
	let info = Object::new();

	let code = JsValue::from_f64(event.code().into());
	let reason = JsValue::from_str(&event.reason());
	let was_clean = JsValue::from_bool(event.was_clean());

	let _ = Reflect::set(&info, &JsValue::from_str("code"), &code);
	let _ = Reflect::set(&info, &JsValue::from_str("reason"), &reason);
	let _ = Reflect::set(&info, &JsValue::from_str("wasClean"), &was_clean);
	info.into()
}
