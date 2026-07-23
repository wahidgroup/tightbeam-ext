//! Promise-boundary helpers shared by the wasm bindings. Compiled only
//! for `wasm32` targets.
//!
//! Async bindings return `js_sys::Promise` from futures that own their
//! state (cloned handles, `Rc` transports) instead of borrowing the wasm
//! object. `free()` is then always safe: in-flight operations keep their
//! own state alive and settle through the connection, never through the
//! freed object.

use core::cell::RefCell;
use core::future::Future;
use std::rc::Rc;

use futures_util::future::{select, Either};
use js_sys::{Function, Promise, Uint8Array};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{AbortSignal, AddEventListenerOptions};

/// An optional response body as JavaScript sees it: bytes or `undefined`.
pub(crate) fn bytes_or_undefined(bytes: Option<Vec<u8>>) -> JsValue {
	match bytes {
		Some(bytes) => Uint8Array::from(bytes.as_slice()).into(),
		None => JsValue::UNDEFINED,
	}
}

/// A registered `abort` listener paired with the promise it resolves.
///
/// Detaches the listener and releases its closure on drop, so a
/// registration whose signal never fires does not accumulate on the
/// signal across repeated waits.
struct AbortWatch {
	target: AbortSignal,
	listener: Closure<dyn FnMut(JsValue)>,
}

impl AbortWatch {
	/// Attach to `signal`, returning the watch guard and a promise
	/// resolved (with `undefined`) on the signal's `abort` event.
	fn attach(signal: &AbortSignal) -> (Self, Promise) {
		let target = signal.clone();
		let resolver: Rc<RefCell<Option<Function>>> = Rc::default();

		let slot = Rc::clone(&resolver);
		let listener = Closure::once(move |_event: JsValue| {
			if let Some(resolve) = slot.borrow_mut().take() {
				let _ = resolve.call0(&JsValue::UNDEFINED);
			}
		});

		let options = AddEventListenerOptions::new();
		options.set_once(true);
		let _ = target.add_event_listener_with_callback_and_add_event_listener_options(
			"abort",
			listener.as_ref().unchecked_ref(),
			&options,
		);

		// The executor runs synchronously, filling the resolver slot the
		// listener reads on dispatch.
		let promise = Promise::new(&mut |resolve: Function, _reject: Function| {
			resolver.borrow_mut().replace(resolve);
		});

		(Self { target, listener }, promise)
	}
}

impl Drop for AbortWatch {
	fn drop(&mut self) {
		let _ = self
			.target
			.remove_event_listener_with_callback("abort", self.listener.as_ref().unchecked_ref());
	}
}

/// Race `future` against `signal`.
///
/// An abort drops the future (its drop path is the cancellation) and
/// yields the signal's abort reason. A signal already aborted rejects
/// before the future is polled. Either way the watch guard detaches the
/// abort listener once the race settles.
pub(crate) async fn race_abort<F, T>(signal: &AbortSignal, future: F) -> Result<T, JsValue>
where
	F: Future<Output = Result<T, JsValue>>,
{
	if signal.aborted() {
		return Err(signal.reason());
	}

	let (watch, abort) = AbortWatch::attach(signal);
	let pending = Box::pin(future);
	let aborted = Box::pin(JsFuture::from(abort));

	let outcome = match select(pending, aborted).await {
		Either::Left((outcome, _)) => outcome,
		Either::Right((_, pending)) => {
			drop(pending);
			Err(signal.reason())
		}
	};

	drop(watch);
	outcome
}

/// As [`race_abort`], for surfaces where the signal is optional: without
/// one the future runs with no race.
pub(crate) async fn race_optional_abort<F>(signal: Option<AbortSignal>, future: F) -> Result<JsValue, JsValue>
where
	F: Future<Output = Result<JsValue, JsValue>>,
{
	match signal {
		Some(signal) => race_abort(&signal, future).await,
		None => future.await,
	}
}
