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
 * whether closure was clean (RFC 6455 § 7.1.4).
 */
export interface SocketCloseInfo {
	/** Close status code (RFC 6455 § 7.4). */
	readonly code: number;
	/** Close reason supplied by the peer, or empty. */
	readonly reason: string;
	/** Whether the closing handshake completed cleanly. */
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

/// A promise settled by a connecting socket's first lifecycle event:
/// `open` resolves it, `close` rejects it with a structured
/// `ConnectionClosed` error. Both listeners register with `once`, and the
/// shared settler slot keeps whichever event fires second a no-op.
fn open_promise(raw: &web_sys::WebSocket) -> Promise {
	let target = raw.clone();
	Promise::new(&mut move |resolve: Function, reject: Function| {
		let settlers = Rc::new(RefCell::new(Some((resolve, reject))));

		let open_slot = Rc::clone(&settlers);
		let on_open = Closure::<dyn FnMut(JsValue)>::new(move |_event: JsValue| {
			if let Some((resolve, _reject)) = open_slot.borrow_mut().take() {
				let _ = resolve.call0(&JsValue::UNDEFINED);
			}
		});

		let close_slot = Rc::clone(&settlers);
		let on_close = Closure::<dyn FnMut(CloseEvent)>::new(move |event: CloseEvent| {
			if let Some((_resolve, reject)) = close_slot.borrow_mut().take() {
				let message = format!("the socket closed before it opened (code {})", event.code());
				let _ = reject.call1(&JsValue::UNDEFINED, &connection_closed(&message));
			}
		});

		listen_once(&target, "open", &on_open);
		listen_once(&target, "close", &on_close);

		// The connection owns the listeners for its whole lifetime.
		on_open.forget();
		on_close.forget();
	})
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

/// A promise resolved with the connection's close info on the `close` event.
///
/// The `close` event reaches this target from two sources: the runtime's
/// genuine close event, and the synthetic one `gloo` dispatches when the
/// socket wrapper drops. The listener is registered with `once` so the
/// platform detaches it after the first dispatch, and the resolver guard
/// keeps later dispatches no-ops even if that registration changes.
fn close_promise(raw: &web_sys::WebSocket) -> Promise {
	let target = raw.clone();
	Promise::new(&mut move |resolve: Function, _reject: Function| {
		// The resolver moves out on the first dispatch.
		let mut resolver = Some(resolve);
		let listener = Closure::<dyn FnMut(CloseEvent)>::new(move |event: CloseEvent| {
			if let Some(resolve) = resolver.take() {
				let info = close_info(&event);
				let _ = resolve.call1(&JsValue::UNDEFINED, &info);
			}
		});

		listen_once(&target, "close", &listener);

		// The connection owns the listener for its whole lifetime.
		listener.forget();
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
