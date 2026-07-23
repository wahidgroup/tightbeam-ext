//! Browser WebSocket construction with lifecycle observation. Compiled
//! only for `wasm32` targets.
//!
//! Every client opens its socket through [`open_observed`], which attaches
//! a `close` listener before any traffic flows. The resulting
//! [`SocketMonitor`] backs the `closed` promise and `readyState` getters
//! the bindings expose, so callers learn about connection loss without
//! waiting for the next emit to fail.

use gloo_net::websocket::futures::WebSocket;
use js_sys::{Function, Object, Promise, Reflect};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{AddEventListenerOptions, CloseEvent};

use crate::fault::to_js;

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
}

/// Open `url` and attach the close observer before any traffic flows.
pub(crate) fn open_observed(url: &str) -> Result<ObservedSocket, JsValue> {
	let raw = web_sys::WebSocket::new(url)?;
	let closed = close_promise(&raw);

	let socket = WebSocket::try_from(raw.clone()).map_err(to_js)?;
	let monitor = SocketMonitor { raw, closed };
	Ok(ObservedSocket { socket, monitor })
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

		let options = AddEventListenerOptions::new();
		options.set_once(true);

		let _ = target.add_event_listener_with_callback_and_add_event_listener_options(
			"close",
			listener.as_ref().unchecked_ref(),
			&options,
		);

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
