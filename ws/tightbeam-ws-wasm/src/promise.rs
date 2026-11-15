//! The parses of the JavaScript values the bindings read, and their promise
//! boundary, as the parse-once section of `docs/ws-wasm.md` describes.

use core::cell::Cell;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::rc::Rc;

use futures_util::future::{select, Either};
use futures_util::task::noop_waker;
use js_sys::{Array, Function, Object, Promise, Reflect, Symbol, Uint8Array};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{future_to_promise, JsFuture};
use web_sys::{AbortSignal, AddEventListenerOptions};

use tightbeam::der::Encode;
use tightbeam::Frame;

use crate::fault::{JsFault, RefusalCode};

/// The `[[TypedArrayName]]` of a `Uint8Array`.
const UINT8_ARRAY: &str = "Uint8Array";

/// The first `number` past the range of `u64`, 2 to the power 64.
const U64_BOUND: f64 = 18_446_744_073_709_551_616.0;

#[wasm_bindgen]
extern "C" {
	/// A byte parameter as JavaScript hands it over: typed `Uint8Array` for
	/// TypeScript callers, and unread until [`JsBytes::read`].
	///
	/// - A plain `Vec<u8>` parameter copies any array-like value element by element: a number reads as no
	///   octets, and a wider view as its elements cut to octets.
	/// - A binding therefore takes each byte parameter as this type, and a `JsBytes` reader admits a
	///   `Uint8Array` alone.
	#[wasm_bindgen(typescript_type = "Uint8Array")]
	pub type JsBytes;
}

thread_local! {
	/// The getter of `%TypedArray%.prototype[Symbol.toStringTag]`, which
	/// reads the `[[TypedArrayName]]` slot of a typed array of any realm, and
	/// answers `undefined` for every other value.
	static TYPED_ARRAY_NAME: Function = {
		let uint8_array_prototype = Object::get_prototype_of(&Uint8Array::new_with_length(0));
		let typed_array_prototype = Object::get_prototype_of(&uint8_array_prototype);
		let tag = Symbol::to_string_tag();

		let descriptor = Object::get_own_property_descriptor(&typed_array_prototype, &tag);
		let getter = Reflect::get(&descriptor, &JsValue::from_str("get")).unwrap_or(JsValue::UNDEFINED);
		getter.unchecked_into()
	};

	/// The `Uint8Array` constructor, which copies the octets of a typed array
	/// it receives, and throws for one over a detached buffer or past the end
	/// of a shrunk one.
	static UINT8_ARRAY_CONSTRUCTOR: Function = Uint8Array::new_with_length(0).constructor();
}

impl JsBytes {
	/// Copy the octets of the parameter, which MUST arrive as a `Uint8Array`.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- the value is not a `Uint8Array`, or it admits no copy as
	///   [`Self::recognize`] states.
	pub(crate) fn read(&self) -> Result<Vec<u8>, JsFault> {
		let bytes = Self::recognize(self).octets();
		bytes.ok_or_else(|| RefusalCode::InvalidBytes.because("the value must be a Uint8Array"))
	}

	/// Copy the octets of `value`, the field at `path`, which a refusal names.
	///
	/// - A `Uint8Array` of any realm reads as its octets, a Node `Buffer` among them.
	/// - Every other value refuses, such as a number, an array of numbers, or a view of wider elements.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- `value` is not a `Uint8Array`, or it admits no copy as [`Self::recognize`] states.
	pub(crate) fn read_value(value: &JsValue, path: &str) -> Result<Vec<u8>, JsFault> {
		let bytes = Self::recognize(value).octets();
		bytes.ok_or_else(|| RefusalCode::InvalidBytes.because("must be a Uint8Array").at(path))
	}

	/// Copy the octets of the member that the last segment of `path` names
	/// on `object`, such as `envelopeDer` for `sealed.envelopeDer`.
	///
	/// # Errors
	///
	/// - The errors of [`Self::read_value`], for an absent member too.
	pub(crate) fn read_member(object: &JsValue, path: &str) -> Result<Vec<u8>, JsFault> {
		let member = Record::member(object, path);
		Self::read_value(&member, path)
	}

	/// What `value` holds: the octets of a `Uint8Array`, a `Uint8Array` that
	/// admits no copy, or no `Uint8Array` at all.
	///
	/// - The copy goes through a fresh `Uint8Array` over the same octets, whose length the engine reads from
	///   the internal slot of `value`.
	/// - The internal slot therefore sizes the copy, whatever `length` property the caller defines.
	/// - A `Uint8Array` over a detached buffer, or past the end of a shrunk one, admits no copy, so it is
	///   [`Recognized::Unreadable`].
	pub(crate) fn recognize(value: &JsValue) -> Recognized {
		let name = TYPED_ARRAY_NAME.with(|getter| getter.call0(value).ok());
		let named = name.and_then(|name| name.as_string());
		if named.as_deref() != Some(UINT8_ARRAY) {
			return Recognized::NotBytes;
		}

		let source = Array::of1(value);
		let copied = UINT8_ARRAY_CONSTRUCTOR.with(|constructor| Reflect::construct(constructor, &source));

		let bytes = copied.ok().and_then(|copy| copy.dyn_into::<Uint8Array>().ok());
		bytes.map_or(Recognized::Unreadable, |bytes| Recognized::Bytes(bytes.to_vec()))
	}
}

/// What [`JsBytes::recognize`] finds in a JavaScript value.
pub(crate) enum Recognized {
	/// The value is no `Uint8Array`.
	NotBytes,
	/// The value is a `Uint8Array` that admits no copy, over a detached
	/// buffer or past the end of a shrunk one.
	Unreadable,
	/// The octets of a `Uint8Array`.
	Bytes(Vec<u8>),
}

impl Recognized {
	/// The octets, or `None` for a value that holds none to read.
	pub(crate) fn octets(self) -> Option<Vec<u8>> {
		match self {
			Self::Bytes(octets) => Some(octets),
			Self::NotBytes | Self::Unreadable => None,
		}
	}
}

/// A JavaScript `number` read as a whole value of an unsigned type: no
/// fraction, no sign, and inside the range of that type.
pub(crate) struct WholeNumber;

impl WholeNumber {
	/// The value of `number` in `T`, or `None` when `number` is no whole value
	/// that `T` holds.
	pub(crate) fn of<T: TryFrom<u64>>(number: f64) -> Option<T> {
		let unsigned = number.fract() == 0.0 && (0.0..U64_BOUND).contains(&number);
		if !unsigned {
			return None;
		}

		T::try_from(number as u64).ok()
	}

	/// The value of `value` in `T`, or `None` when `value` is no `number` that
	/// [`Self::of`] reads.
	pub(crate) fn read<T: TryFrom<u64>>(value: &JsValue) -> Option<T> {
		let number = value.as_f64()?;
		Self::of(number)
	}

	/// The `u64` at `value`: a `number` that [`Self::of`] reads, or a `bigint`
	/// from 0 to `u64::MAX`. Any other value, a string among them, is `None`,
	/// so no coercion reaches the frame.
	pub(crate) fn u64_at(value: &JsValue) -> Option<u64> {
		if value.is_bigint() {
			let whole = u64::try_from(value.clone());
			return whole.ok();
		}

		Self::read(value)
	}
}

/// An `AbortSignal` that a caller may hand a binding.
pub(crate) struct Signal;

impl Signal {
	/// The signal at `value`, the field at `path`, or `None` when it is absent.
	///
	/// # Errors
	///
	/// - `InvalidSignal` -- `value` is neither absent nor an `AbortSignal`.
	pub(crate) fn read(value: &JsValue, path: &str) -> Result<Option<AbortSignal>, JsFault> {
		let Some(present) = Record::present(value.clone()) else {
			return Ok(None);
		};

		let signal = present.dyn_into::<AbortSignal>();
		let refusal = |_| RefusalCode::InvalidSignal.because("must be an AbortSignal").at(path);
		signal.map(Some).map_err(refusal)
	}
}

/// A function that a binding calls back.
pub(crate) struct Callback;

impl Callback {
	/// The function at `value`, the field at `path`.
	///
	/// # Errors
	///
	/// - `InvalidCallback` -- `value` is not a function.
	pub(crate) fn read(value: &JsValue, path: &str) -> Result<Function, JsFault> {
		let function = value.dyn_ref::<Function>().cloned();
		function.ok_or_else(|| RefusalCode::InvalidCallback.because("must be a function").at(path))
	}
}

/// A string that a binding reads.
pub(crate) struct Text;

impl Text {
	/// The string at `value`, the field at `path`.
	///
	/// # Errors
	///
	/// - `InvalidText` -- `value` is not a string.
	pub(crate) fn read(value: &JsValue, path: &str) -> Result<String, JsFault> {
		let refusal = || RefusalCode::InvalidText.because("must be a string").at(path);
		value.as_string().ok_or_else(refusal)
	}
}

/// A plain JavaScript object: one a binding builds field by field, or one a
/// caller hands over, read member by member.
pub(crate) struct Record(Object);

impl Record {
	pub(crate) fn new() -> Self {
		Self(Object::new())
	}

	/// The member of `object` that the last segment of `path` names, such as
	/// `envelopeDer` for `sealed.envelopeDer`, or `undefined` when it holds
	/// none.
	pub(crate) fn member(object: &JsValue, path: &str) -> JsValue {
		let name = path.rsplit('.').next().unwrap_or(path);
		Reflect::get(object, &JsValue::from_str(name)).unwrap_or(JsValue::UNDEFINED)
	}

	/// The optional member that [`Self::member`] reads, or `None` when it is
	/// absent as [`Self::present`] decides.
	pub(crate) fn optional_member(object: &JsValue, path: &str) -> Option<JsValue> {
		let member = Self::member(object, path);
		Self::present(member)
	}

	/// `value`, or `None` when it is `undefined` or `null`. JavaScript passes
	/// either one for an absent optional value.
	pub(crate) fn present(value: JsValue) -> Option<JsValue> {
		if value.is_undefined() || value.is_null() {
			return None;
		}

		Some(value)
	}

	/// Write `value` at `key`, in place of any value the key held.
	pub(crate) fn set(&self, key: &str, value: impl Into<JsValue>) {
		// `Reflect::set` on a plain object that a record built cannot fail.
		let _ = Reflect::set(&self.0, &JsValue::from_str(key), &value.into());
	}

	/// Set `key` to a `Uint8Array` copy of `bytes`.
	pub(crate) fn set_bytes(&self, key: &str, bytes: &[u8]) {
		self.set(key, Uint8Array::from(bytes));
	}

	/// Set `key` to `value` when there is one, and leave the field absent
	/// otherwise.
	pub(crate) fn set_present(&self, key: &str, value: Option<impl Into<JsValue>>) {
		if let Some(value) = value {
			self.set(key, value);
		}
	}
}

impl From<Record> for JsValue {
	fn from(record: Record) -> Self {
		record.0.into()
	}
}

/// A value that a JavaScript callback returned, which a binding awaits as
/// `await` does in JavaScript.
pub(crate) struct Returned(JsValue);

impl From<JsValue> for Returned {
	fn from(returned: JsValue) -> Self {
		Self(returned)
	}
}

impl Returned {
	/// Wait for this value to settle. A promise or a thenable settles with its
	/// outcome, and any other value settles as itself.
	///
	/// # Errors
	///
	/// - The rejection reason of a promise or a thenable that rejects.
	pub(crate) async fn settle(self) -> Result<JsValue, JsValue> {
		let adopted = Promise::resolve(&self.0);
		JsFuture::from(adopted).await
	}
}

/// The response frame of a stream on its way to JavaScript: its DER as a
/// `Uint8Array`, or `undefined` when the peer answered without a frame.
pub(crate) struct JsResponse(pub(crate) Option<Frame>);

impl TryFrom<JsResponse> for JsValue {
	type Error = JsFault;

	/// # Errors
	///
	/// - `SerializationError` -- the frame does not encode.
	fn try_from(response: JsResponse) -> Result<Self, Self::Error> {
		let Some(frame) = response.0 else {
			return Ok(Self::UNDEFINED);
		};

		let der = frame.to_der()?;
		let bytes = Uint8Array::from(der.as_slice());
		Ok(bytes.into())
	}
}

/// A call whose binding runs its synchronous start before it returns the
/// promise of its outcome.
///
/// - `future_to_promise` first polls a future on a later microtask, so a reservation such as the slot of a
///   stream would land only after the next statement of the caller.
/// - The first poll runs here instead, so the reservation lands before the binding returns.
pub(crate) trait StartNow: Future<Output = Result<JsValue, JsValue>> + Sized + 'static {
	/// The promise of this call, after its first poll.
	fn start_now(self) -> Promise {
		let mut call = Box::pin(self);
		let waker = noop_waker();
		let mut context = Context::from_waker(&waker);

		match call.as_mut().poll(&mut context) {
			Poll::Ready(Ok(value)) => Promise::resolve(&value),
			Poll::Ready(Err(error)) => Promise::reject(&error),
			Poll::Pending => future_to_promise(call),
		}
	}
}

impl<F: Future<Output = Result<JsValue, JsValue>> + 'static> StartNow for F {}

/// A registered `abort` listener, as a future that is ready once the signal
/// aborts.
///
/// - The listener wakes the task that last polled the watch, and the poll reads the aborted state of the
///   signal itself.
/// - The watch detaches the listener and releases its closure on drop, so no callback outlives the watch,
///   and across repeated waits the signal holds the listeners of live watches alone.
struct AbortWatch {
	target: AbortSignal,
	waker: Rc<Cell<Option<Waker>>>,
	listener: Closure<dyn FnMut(JsValue)>,
}

impl AbortWatch {
	/// Attach to `signal`.
	fn attach(signal: &AbortSignal) -> Self {
		let target = signal.clone();
		let waker: Rc<Cell<Option<Waker>>> = Rc::default();

		let slot = Rc::clone(&waker);
		let listener = Closure::once(move |_event: JsValue| {
			if let Some(waker) = slot.take() {
				waker.wake();
			}
		});

		let options = AddEventListenerOptions::new();
		options.set_once(true);
		let _ = target.add_event_listener_with_callback_and_add_event_listener_options(
			"abort",
			listener.as_ref().unchecked_ref(),
			&options,
		);

		Self { target, waker, listener }
	}
}

impl Future for AbortWatch {
	type Output = ();

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
		if self.target.aborted() {
			return Poll::Ready(());
		}

		self.waker.set(Some(cx.waker().clone()));
		Poll::Pending
	}
}

impl Drop for AbortWatch {
	fn drop(&mut self) {
		let _ = self
			.target
			.remove_event_listener_with_callback("abort", self.listener.as_ref().unchecked_ref());
	}
}

/// The winner of one call raced against the signal of its caller, which
/// [`AbortRace::race`] decides once.
pub(crate) enum Raced<T> {
	/// The call settled while the signal stood, and its outcome stands.
	Settled(T),
	/// The signal aborted before the race returned, with this abort reason.
	/// The call dropped, or the outcome it settled with dropped.
	Aborted(JsValue),
}

impl<T> Raced<Result<T, JsValue>> {
	/// The outcome as the caller of the call sees it: the outcome the call
	/// settled with, or the abort reason as its error.
	///
	/// # Errors
	///
	/// - The error the call settled with, or the abort reason of the signal.
	pub(crate) fn outcome(self) -> Result<T, JsValue> {
		match self {
			Self::Settled(outcome) => outcome,
			Self::Aborted(reason) => Err(reason),
		}
	}
}

/// A caller's way to give up on a call: an `AbortSignal`, or an optional one.
pub(crate) trait AbortRace {
	/// The abort reason, when the signal has already aborted.
	fn aborted_reason(&self) -> Option<JsValue>;

	/// Race `future` against the signal, and decide the winner once.
	///
	/// - The signal wins when it has aborted by the time the race returns:
	///   before the first poll, while the future is pending, or in the turn the
	///   future settles.
	/// - A win drops the future or its outcome, so the drop path of the future
	///   is the cancellation.
	/// - The abort listener detaches once the race settles.
	async fn race<F: Future>(&self, future: F) -> Raced<F::Output>;
}

impl AbortRace for AbortSignal {
	fn aborted_reason(&self) -> Option<JsValue> {
		if self.aborted() {
			return Some(self.reason());
		}

		None
	}

	async fn race<F: Future>(&self, future: F) -> Raced<F::Output> {
		if let Some(reason) = self.aborted_reason() {
			return Raced::Aborted(reason);
		}

		let watch = AbortWatch::attach(self);
		let pending = Box::pin(future);

		let first = select(pending, watch).await;
		let settled = match first {
			Either::Left((settled, _watch)) => settled,
			Either::Right((_, pending)) => {
				drop(pending);
				return Raced::Aborted(self.reason());
			}
		};

		match self.aborted_reason() {
			Some(reason) => Raced::Aborted(reason),
			None => Raced::Settled(settled),
		}
	}
}

/// Without a signal the future runs with no race.
impl AbortRace for Option<AbortSignal> {
	fn aborted_reason(&self) -> Option<JsValue> {
		self.as_ref()?.aborted_reason()
	}

	async fn race<F: Future>(&self, future: F) -> Raced<F::Output> {
		match self {
			Some(signal) => signal.race(future).await,
			None => Raced::Settled(future.await),
		}
	}
}

#[cfg(test)]
mod tests {
	use futures_util::future::{join, pending, ready};
	use js_sys::{Array, Function, Object, Reflect, Uint16Array, Uint8Array};
	use wasm_bindgen::closure::Closure;
	use wasm_bindgen::{externref_heap_live_count, JsValue};
	use wasm_bindgen_test::wasm_bindgen_test;
	use web_sys::AbortController;

	use super::{AbortRace, JsBytes, Raced, Recognized, Returned};
	use crate::loopback::settled;

	/// The races that the leak case runs, each of which the call wins.
	const RACES: u32 = 8;

	/// An object that is no promise, whose `then` resolves with `value`.
	fn thenable_of(value: JsValue) -> Object {
		let then = Closure::once_into_js(move |resolve: Function| resolve.call1(&JsValue::UNDEFINED, &value));
		let thenable = Object::new();
		let set = Reflect::set(&thenable, &JsValue::from_str("then"), &then);
		set.expect("the thenable should take a then");

		thenable
	}

	#[wasm_bindgen_test]
	fn a_number_is_no_bytes() {
		let number = JsValue::from_f64(7.0);
		assert!(matches!(JsBytes::recognize(&number), Recognized::NotBytes));
	}

	#[wasm_bindgen_test]
	fn an_array_is_no_bytes() {
		let numbers = Array::of2(&JsValue::from_f64(1.0), &JsValue::from_f64(2.0));
		assert!(matches!(JsBytes::recognize(&numbers), Recognized::NotBytes));
	}

	#[wasm_bindgen_test]
	fn a_wider_view_is_no_bytes() {
		let wide = Uint16Array::new_with_length(2);
		assert!(matches!(JsBytes::recognize(&wide), Recognized::NotBytes));
	}

	#[wasm_bindgen_test]
	fn a_uint8array_reads_as_its_bytes() {
		let bytes = Uint8Array::from([1u8, 2, 3].as_slice());
		assert_eq!(JsBytes::recognize(&bytes).octets(), Some(vec![1, 2, 3]));
	}

	#[wasm_bindgen_test]
	fn a_detached_uint8array_is_unreadable() {
		let bytes = Uint8Array::from([1u8, 2, 3].as_slice());
		let transferred = bytes.buffer().transfer();
		transferred.expect("the host should detach the buffer");
		assert!(matches!(JsBytes::recognize(&bytes), Recognized::Unreadable));
	}

	#[wasm_bindgen_test]
	async fn a_race_that_the_call_wins_leaves_no_javascript_value_held() {
		let controller = AbortController::new().expect("the host should build an AbortController");
		let signal = controller.signal();

		let before = externref_heap_live_count();
		for _ in 0..RACES {
			let raced = signal.race(ready(())).await;
			assert!(matches!(raced, Raced::Settled(())));
		}

		assert_eq!(externref_heap_live_count(), before);
	}

	#[wasm_bindgen_test]
	async fn an_abort_while_the_call_waits_wins_the_race() {
		let controller = AbortController::new().expect("the host should build an AbortController");
		let signal = controller.signal();
		let aborting = async { controller.abort() };

		let (raced, ()) = settled(join(signal.race(pending::<()>()), aborting)).await;
		assert!(matches!(raced, Raced::Aborted(reason) if reason == signal.reason()));
	}

	#[wasm_bindgen_test]
	async fn a_thenable_settles_with_its_value() {
		let thenable: JsValue = thenable_of(JsValue::from_f64(42.0)).into();
		let answered = settled(Returned::from(thenable).settle()).await;
		assert_eq!(answered.map(|value| value.as_f64()), Ok(Some(42.0)));
	}
}
