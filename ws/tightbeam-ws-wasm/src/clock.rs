//! The clock of a browser or Node build, which reads the JavaScript globals of
//! the host, as the browser transport section of `docs/ws-wasm.md` describes.

use core::time::Duration;

use js_sys::{Date, Function, Promise, Reflect};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use tightbeam::clock::{Clock, MonotonicInstant, Timing, UnixMillis};
use tightbeam::marker::MaybeSendFuture;

/// The largest delay in milliseconds `setTimeout` honours. A larger delay
/// wraps to a timer that fires at once, so a longer sleep arms the timer in
/// steps of this bound.
const MAX_TIMEOUT_MILLIS: f64 = i32::MAX as f64;

/// The clock of the JavaScript host.
///
/// [`host`](Self::host) reads the timer once, so the clock decides its
/// [`Timing`] from what the host carries, and every sleep arms the timer it
/// read.
#[derive(Clone, Debug)]
pub struct BrowserClock {
	timer: Timer,
}

/// The timer of a host, by whether the host carries one.
#[derive(Clone, Debug)]
enum Timer {
	/// A host whose `setTimeout` arms each sleep, so a bound races its work.
	Timed(Function),
	/// A host with no `setTimeout`, so a bound refuses work that waits.
	NoTimer,
}

impl Timer {
	/// Arm this timer to call `resolve` once `millis` have passed. It answers
	/// `None` on a host with no timer, or when the host refuses the call.
	fn arm(&self, resolve: &Function, millis: f64) -> Option<HostTimer> {
		match self {
			Self::Timed(timer) => {
				let armed = timer.call2(&JsValue::UNDEFINED, resolve, &JsValue::from_f64(millis));
				armed.ok().map(HostTimer)
			}
			Self::NoTimer => None,
		}
	}

	/// The [`Timing`] of a sleep on this timer.
	fn timing(&self) -> Timing {
		match self {
			Self::Timed(_) => Timing::Races,
			Self::NoTimer => Timing::Absent,
		}
	}
}

impl BrowserClock {
	/// The clock of this host: a window, a worker, or Node.
	#[must_use]
	pub fn host() -> Self {
		Self::of(&js_sys::global())
	}

	/// The clock of the global object `global`, by its `setTimeout`.
	fn of(global: &JsValue) -> Self {
		let set_timeout = Reflect::get(global, &JsValue::from_str("setTimeout"));
		let set_timeout = set_timeout.ok().and_then(|value| value.dyn_into::<Function>().ok());

		let timer = match set_timeout {
			Some(timer) => Timer::Timed(timer),
			None => Timer::NoTimer,
		};
		Self { timer }
	}

	/// Read `performance.now()`, the host's monotonic clock in milliseconds.
	fn performance_now() -> Option<f64> {
		let global = js_sys::global();
		let performance = Reflect::get(&global, &JsValue::from_str("performance")).ok()?;
		let now = Reflect::get(&performance, &JsValue::from_str("now")).ok()?;
		let now = now.dyn_into::<Function>().ok()?;
		now.call0(&performance).ok()?.as_f64()
	}

	/// A promise that resolves once `millis` have passed on the timer of the
	/// host. A host with no timer resolves at once, because its
	/// [`Timing::Absent`] keeps every bound from waiting on the sleep.
	fn timeout(&self, millis: f64) -> Promise {
		Promise::new(&mut |resolve, _reject| match self.timer.arm(&resolve, millis) {
			Some(armed) => armed.release(),
			None => {
				let _ = resolve.call0(&JsValue::UNDEFINED);
			}
		})
	}
}

/// The delays in milliseconds that one sleep arms on the host timer, each
/// within [`MAX_TIMEOUT_MILLIS`], so a span past that bound arms the timer
/// again for the rest.
struct TimerSteps {
	remaining: f64,
	armed: bool,
}

impl TimerSteps {
	/// The steps of a sleep for `span`.
	fn of(span: Duration) -> Self {
		Self { remaining: span.as_secs_f64() * 1000.0, armed: false }
	}
}

impl Iterator for TimerSteps {
	type Item = f64;

	/// The next delay, or `None` once the span has passed. A span of none
	/// still arms one step, so the sleep yields to the host.
	fn next(&mut self) -> Option<f64> {
		if self.armed && self.remaining <= 0.0 {
			return None;
		}

		let step = self.remaining.min(MAX_TIMEOUT_MILLIS);
		self.remaining -= step;
		self.armed = true;
		Some(step)
	}
}

/// A timer that the host's `setTimeout` armed: a timer object under Node,
/// and a number in a browser.
struct HostTimer(JsValue);

impl HostTimer {
	/// Let the process exit past this timer, when the host has that concept.
	///
	/// A live socket holds a Node process open, so a pending sleep alone MUST
	/// NOT.
	fn release(&self) {
		let unref = Reflect::get(&self.0, &JsValue::from_str("unref"));
		let unref = unref.ok().and_then(|value| value.dyn_into::<Function>().ok());
		if let Some(unref) = unref {
			let _ = unref.call0(&self.0);
		}
	}
}

impl Clock for BrowserClock {
	fn unix(&self) -> UnixMillis {
		UnixMillis::now()
	}

	/// The span since the page or process origin. `Date.now()` stands in on a
	/// host with no `performance`, which leaves deadlines correct unless the
	/// system clock steps.
	fn monotonic(&self) -> MonotonicInstant {
		let millis = Self::performance_now().unwrap_or_else(Date::now);
		let elapsed = Duration::try_from_secs_f64(millis / 1000.0).unwrap_or_default();
		MonotonicInstant::from_elapsed(elapsed)
	}

	fn sleep(&self, span: Duration) -> MaybeSendFuture<'_, ()> {
		let steps = TimerSteps::of(span);
		Box::pin(async move {
			for step in steps {
				// The promise of a timeout always resolves, with `undefined`.
				let _ = JsFuture::from(self.timeout(step)).await;
			}
		})
	}

	/// A sleep on the timer of the host yields while it waits, so a bound
	/// races its work against it. A host with no timer has no such sleep.
	fn timing(&self) -> Timing {
		self.timer.timing()
	}
}

#[cfg(test)]
mod tests {
	use js_sys::Object;
	use tightbeam::clock::{Clock, Timing};
	use wasm_bindgen_test::wasm_bindgen_test;

	use core::time::Duration;

	use super::{BrowserClock, TimerSteps, MAX_TIMEOUT_MILLIS};

	/// A span of two whole timer steps and five milliseconds more.
	const PAST_TWO_STEPS: Duration = Duration::from_millis(2 * i32::MAX as u64 + 5);

	#[wasm_bindgen_test]
	fn a_sleep_past_the_timer_bound_arms_the_timer_again_for_the_rest() {
		let steps: Vec<f64> = TimerSteps::of(PAST_TWO_STEPS).collect();
		assert_eq!(steps, [MAX_TIMEOUT_MILLIS, MAX_TIMEOUT_MILLIS, 5.0]);
	}

	#[wasm_bindgen_test]
	fn a_sleep_inside_the_timer_bound_arms_the_timer_once() {
		let steps: Vec<f64> = TimerSteps::of(Duration::from_millis(1500)).collect();
		assert_eq!(steps, [1500.0]);
	}

	#[wasm_bindgen_test]
	fn a_sleep_of_no_span_still_yields_to_the_host_once() {
		let steps: Vec<f64> = TimerSteps::of(Duration::ZERO).collect();
		assert_eq!(steps, [0.0]);
	}

	#[wasm_bindgen_test]
	fn a_host_with_a_timer_races_its_bounds() {
		assert_eq!(BrowserClock::host().timing(), Timing::Races);
	}

	#[wasm_bindgen_test]
	fn a_host_without_a_timer_has_no_timing() {
		let bare = Object::new();
		assert_eq!(BrowserClock::of(&bare.into()).timing(), Timing::Absent);
	}
}
