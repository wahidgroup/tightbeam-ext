//! Browser WebSocket construction with lifecycle observation. Compiled
//! only for `wasm32` targets.
//!
//! Every client opens its socket through [`OpeningSocket::open`], which
//! attaches a `close` listener before any traffic flows. The opening socket
//! owns the open and close events of the socket, and runs each step that
//! opens or handshakes it [`within`](OpeningSocket::within) the abort signal
//! of the caller. The [`SocketMonitor`] it then hands over backs the `closed`
//! promise and `readyState` getters the bindings expose, so callers learn
//! about connection loss without waiting for the next emit to fail.

use core::cell::RefCell;
use core::future::Future;
use std::rc::Rc;

use gloo_net::websocket::futures::WebSocket;
use js_sys::{Function, Promise};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{AddEventListenerOptions, CloseEvent};

use crate::fault::{JsFault, RefusalCode, TransportCode};
use crate::promise::{AbortRace, Raced, Record};

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

/// Lifecycle observation for one established WebSocket connection. Clones
/// observe the same socket.
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

/// A browser WebSocket from its construction until its session is
/// established.
///
/// The socket owns its open and close events. Each step that opens or
/// handshakes it runs [`within`](Self::within) the abort signal of the
/// caller, which hands over the [`SocketMonitor`] once the step settles while
/// the signal stands.
pub(crate) struct OpeningSocket {
	/// The lifecycle surface the established connection keeps.
	monitor: SocketMonitor,
}

impl OpeningSocket {
	/// Open `url`, and attach the close observer before any traffic flows.
	///
	/// Returns the opening socket and the `gloo` carrier of the same socket,
	/// which a transport reads and writes envelopes on.
	///
	/// # Errors
	///
	/// - `InvalidUrl` -- the WebSocket refuses `url`.
	pub(crate) fn open(url: &str) -> Result<(Self, WebSocket), JsFault> {
		let raw = web_sys::WebSocket::new(url);
		let raw = raw.map_err(|_| RefusalCode::InvalidUrl.because(format!("the WebSocket refuses the URL {url}")))?;
		let closed = Self::close_promise(&raw);

		let carrier = WebSocket::try_from(raw.clone());
		let carrier = carrier.map_err(|error| RefusalCode::InvalidUrl.because(error))?;
		let monitor = SocketMonitor { raw, closed };

		let opening = Self { monitor };
		Ok((opening, carrier))
	}

	/// Settle once the socket is open, or reject with a structured
	/// `ConnectionClosed` error when it closes first: a failed dial.
	///
	/// The open promise is built on demand, so only a session that waits on
	/// the open holds a promise that can reject, and that session handles the
	/// rejection.
	pub(crate) fn opened(&self) -> impl Future<Output = Result<(), JsValue>> {
		const CONNECTING: u16 = 0;
		const OPEN: u16 = 1;

		let state = self.monitor.ready_state();
		let open = match state {
			OPEN => Promise::resolve(&JsValue::UNDEFINED),
			CONNECTING => self.open_promise(),
			_ => {
				let closed = TransportCode::ConnectionClosed.because("the socket closed before it opened");
				Promise::reject(&closed.into())
			}
		};

		let opening = JsFuture::from(open);
		async move {
			opening.await?;
			Ok(())
		}
	}

	/// Race `step` against `signal`, and hand over the monitor of this socket
	/// with the outcome of a step that settles while the signal stands.
	///
	/// An abort that wins the [race](AbortRace::race) closes this socket, so a
	/// connect returns a client only over a socket that outran its abort.
	///
	/// # Errors
	///
	/// - The error `step` settles with.
	/// - The abort reason of `signal`.
	pub(crate) async fn within<F, T>(self, signal: &impl AbortRace, step: F) -> Result<(T, SocketMonitor), JsValue>
	where
		F: Future<Output = Result<T, JsValue>>,
	{
		let raced = signal.race(step).await;
		match raced {
			Raced::Settled(outcome) => {
				let settled = outcome?;
				Ok((settled, self.monitor))
			}
			Raced::Aborted(reason) => {
				self.monitor.close();
				Err(reason)
			}
		}
	}

	/// A promise settled by the first lifecycle event of this connecting
	/// socket: `open` resolves it, and `close` rejects it with a structured
	/// `ConnectionClosed` error. Whichever event fires first takes the watch,
	/// and detaches and frees both listeners.
	fn open_promise(&self) -> Promise {
		let target = self.monitor.raw.clone();
		Promise::new(&mut move |resolve: Function, reject: Function| {
			let slot = OpenWatchSlot::default();

			let open_slot = slot.clone();
			let open_target = target.clone();
			let on_open = Closure::<dyn FnMut(JsValue)>::new(move |_event: JsValue| {
				if let Some(watch) = open_slot.take(&open_target) {
					let _ = watch.resolve.call0(&JsValue::UNDEFINED);
				}
			});

			let close_slot = slot.clone();
			let close_target = target.clone();
			let on_close = Closure::<dyn FnMut(CloseEvent)>::new(move |event: CloseEvent| {
				if let Some(watch) = close_slot.take(&close_target) {
					let message = format!("the socket closed before it opened (code {})", event.code());
					let closed: JsValue = TransportCode::ConnectionClosed.because(message).into();
					let _ = watch.reject.call1(&JsValue::UNDEFINED, &closed);
				}
			});

			Self::listen_once(&target, "open", &on_open);
			Self::listen_once(&target, "close", &on_close);

			slot.fill(OpenWatch { resolve, reject, on_open, on_close });
		})
	}

	/// A promise resolved with the close info of the connection on the
	/// `close` event of `raw`, which reaches the socket from two sources:
	///
	/// - The genuine close event of the runtime.
	/// - The synthetic one that `gloo` dispatches when the socket wrapper drops.
	///
	/// The listener registers with `once`, so the platform detaches it after
	/// the first dispatch, which also drains its own closure from the shared
	/// slot to free it. [`open`](Self::open) attaches it before the opening
	/// socket exists, so it takes the raw socket.
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
					let info = JsValue::from(CloseInfo(&event));
					let _ = resolve.call1(&JsValue::UNDEFINED, &info);
				}
			});

			Self::listen_once(&target, "close", &listener);
			slot.borrow_mut().replace(listener);
		})
	}

	/// Register `listener` on `target` for one dispatch of `event`.
	fn listen_once<E>(target: &web_sys::WebSocket, event: &str, listener: &Closure<dyn FnMut(E)>) {
		let options = AddEventListenerOptions::new();
		options.set_once(true);

		let callback = listener.as_ref().unchecked_ref();
		let _ = target.add_event_listener_with_callback_and_add_event_listener_options(event, callback, &options);
	}

	/// Detach `listener` from `event` on `target`.
	fn detach<E>(target: &web_sys::WebSocket, event: &str, listener: &Closure<dyn FnMut(E)>) {
		let callback = listener.as_ref().unchecked_ref();
		let _ = target.remove_event_listener_with_callback(event, callback);
	}
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
#[derive(Clone, Default)]
struct OpenWatchSlot(Rc<RefCell<Option<OpenWatch>>>);

impl OpenWatchSlot {
	/// Drain the watch and detach both of its listeners from `target`. The
	/// caller settles the promise and drops the watch. The closure that runs
	/// now is freed once its call returns (the shim defers deallocation while
	/// it runs).
	fn take(&self, target: &web_sys::WebSocket) -> Option<OpenWatch> {
		let watch = self.0.borrow_mut().take()?;
		OpeningSocket::detach(target, "open", &watch.on_open);
		OpeningSocket::detach(target, "close", &watch.on_close);
		Some(watch)
	}

	/// Hold `watch` until the first lifecycle event takes it.
	fn fill(&self, watch: OpenWatch) {
		self.0.borrow_mut().replace(watch);
	}
}

/// Shared slot from which the `close` listener drains itself on dispatch.
type CloseListenerSlot = Rc<RefCell<Option<Closure<dyn FnMut(CloseEvent)>>>>;

/// One close event, as the `closed` promise resolves with it: a
/// `SocketCloseInfo`.
struct CloseInfo<'a>(&'a CloseEvent);

impl From<CloseInfo<'_>> for JsValue {
	fn from(info: CloseInfo<'_>) -> Self {
		let event = info.0;
		let code = f64::from(event.code());

		let record = Record::new();
		record.set("code", code);
		record.set("reason", event.reason());
		record.set("wasClean", event.was_clean());
		record.into()
	}
}

#[cfg(test)]
pub(crate) mod tests {
	use core::future::Future;

	use gloo_net::websocket::futures::WebSocket;
	use wasm_bindgen::JsValue;
	use wasm_bindgen_test::wasm_bindgen_test;
	use web_sys::{AbortController, Event};

	use super::OpeningSocket;

	/// A port that nothing listens on and that no browser blocks, so a dial to
	/// it stays in progress for the length of a test that yields to microtasks
	/// alone.
	pub(crate) const UNREACHED_URL: &str = "ws://127.0.0.1:3/";

	/// A socket that is still connecting, the carrier that keeps it, and a
	/// controller whose signal stands.
	fn connecting() -> (OpeningSocket, WebSocket, AbortController) {
		let opened = OpeningSocket::open(UNREACHED_URL);
		let (opening, carrier) = opened.expect("the socket should construct");
		let controller = AbortController::new().expect("an abort controller should construct");

		(opening, carrier, controller)
	}

	/// Fire the `open` event of `socket` and abort `controller` in one turn,
	/// then wait on `opened`: an open that lands with its abort.
	async fn open_landing(
		socket: &web_sys::WebSocket,
		controller: &AbortController,
		opened: impl Future<Output = Result<(), JsValue>>,
	) -> Result<(), JsValue> {
		let open = Event::new("open").expect("an open event should construct");
		socket.dispatch_event(&open).expect("the socket should dispatch the open event");
		controller.abort();

		opened.await
	}

	/// Abort `controller`, and settle in the same turn: a handshake that lands
	/// with its abort.
	async fn handshake_landing(controller: &AbortController) -> Result<(), JsValue> {
		controller.abort();
		Ok(())
	}

	#[wasm_bindgen_test]
	async fn an_abort_that_lands_with_the_open_closes_the_socket() {
		let (opening, _carrier, controller) = connecting();
		let signal = controller.signal();
		let probe = opening.monitor.clone();
		let opened = opening.opened();
		let landing = open_landing(&probe.raw, &controller, opened);

		let raced = opening.within(&signal, landing).await;
		assert_eq!(raced.err(), Some(signal.reason()));
		assert_eq!(probe.ready_state(), web_sys::WebSocket::CLOSING);
	}

	#[wasm_bindgen_test]
	async fn an_abort_that_lands_with_the_handshake_closes_the_socket() {
		let (opening, _carrier, controller) = connecting();
		let signal = controller.signal();
		let probe = opening.monitor.clone();
		let landing = handshake_landing(&controller);

		let raced = opening.within(&signal, landing).await;
		assert_eq!(raced.err(), Some(signal.reason()));
		assert_eq!(probe.ready_state(), web_sys::WebSocket::CLOSING);
	}
}
