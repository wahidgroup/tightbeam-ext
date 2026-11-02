//! The clock of a browser or Node build. Compiled only for `wasm32` targets.
//!
//! The standard library's clocks panic on `wasm32-unknown-unknown`, so
//! tightbeam names no clock there and the embedder installs one. This clock
//! reads the host's JavaScript globals, which a window, a worker, and Node
//! all carry.

use core::time::Duration;

use js_sys::{Date, Function, Promise, Reflect};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use tightbeam::clock::{Clock, MonotonicInstant, UnixMillis};
use tightbeam::marker::MaybeSendFuture;

/// The largest delay in milliseconds `setTimeout` honours. A larger delay
/// wraps to a timer that fires at once.
const MAX_TIMEOUT_MILLIS: f64 = i32::MAX as f64;

/// Read `performance.now()`, the host's monotonic clock in milliseconds.
fn performance_now() -> Option<f64> {
	let global = js_sys::global();
	let performance = Reflect::get(&global, &JsValue::from_str("performance")).ok()?;
	let now = Reflect::get(&performance, &JsValue::from_str("now")).ok()?;
	let now = now.dyn_into::<Function>().ok()?;

	now.call0(&performance).ok()?.as_f64()
}

/// Let the process exit past `timer`, when the host has that concept.
///
/// Node returns a timer object, and a browser returns a number. A live socket
/// holds a Node process open, so a pending sleep alone MUST NOT.
fn release(timer: &JsValue) {
	let unref = Reflect::get(timer, &JsValue::from_str("unref"));
	let unref = unref.ok().and_then(|value| value.dyn_into::<Function>().ok());
	if let Some(unref) = unref {
		let _ = unref.call0(timer);
	}
}

/// A promise that resolves once `span` has passed on the host's timers.
fn timeout(span: Duration) -> Promise {
	let millis = (span.as_secs_f64() * 1000.0).min(MAX_TIMEOUT_MILLIS);

	Promise::new(&mut |resolve, _reject| {
		let set_timeout = Reflect::get(&js_sys::global(), &JsValue::from_str("setTimeout"));
		let set_timeout = set_timeout.ok().and_then(|value| value.dyn_into::<Function>().ok());
		let armed = set_timeout.map(|timer| timer.call2(&JsValue::UNDEFINED, &resolve, &JsValue::from_f64(millis)));

		// A host with no timer resolves at once, so no caller waits forever.
		match armed {
			Some(Ok(timer)) => release(&timer),
			_ => {
				let _ = resolve.call0(&JsValue::UNDEFINED);
			}
		}
	})
}

/// The clock of the JavaScript host.
#[derive(Clone, Copy, Debug, Default)]
pub struct BrowserClock;

impl Clock for BrowserClock {
	fn unix(&self) -> UnixMillis {
		UnixMillis::now()
	}

	/// The span since the page or process origin. `Date.now()` stands in on a
	/// host with no `performance`, which leaves deadlines correct unless the
	/// system clock steps.
	fn monotonic(&self) -> MonotonicInstant {
		let millis = performance_now().unwrap_or_else(Date::now);
		let elapsed = Duration::try_from_secs_f64(millis / 1000.0).unwrap_or_default();
		MonotonicInstant::from_elapsed(elapsed)
	}

	fn sleep(&self, span: Duration) -> MaybeSendFuture<'_, ()> {
		let wait = JsFuture::from(timeout(span));
		Box::pin(async move {
			// The promise above never rejects.
			let _ = wait.await;
		})
	}
}
