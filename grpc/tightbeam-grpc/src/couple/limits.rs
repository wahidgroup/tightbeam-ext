//! The limits of the calls of a coupled edge.
//!
//! # Sources
//!
//! - gRPC over HTTP2, `grpc/grpc` `doc/PROTOCOL-HTTP2.md`:
//!   <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md>

use core::num::{NonZeroU32, NonZeroUsize};
use core::time::Duration;

use http::{HeaderMap, HeaderValue};

use super::fault::CallFault;

/// The deadline of a call that sends no `grpc-timeout`, and the most that a
/// call may ask for, by default.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest span that a coupler counts, a call limit or a replay window,
/// so every deadline and every expiry stays in the range of the clock.
pub(super) const MAX_SPAN: Duration = Duration::from_secs(24 * 60 * 60);

/// The coupled connections that an edge holds at once, by default.
const DEFAULT_LANES: NonZeroUsize = NonZeroUsize::new(256).unwrap();

/// The calls that one coupled connection carries at once, by default.
const DEFAULT_STREAMS: NonZeroU32 = NonZeroU32::new(32).unwrap();

/// The most digits of a `grpc-timeout` value.
const TIMEOUT_DIGITS: usize = 8;

/// The limits of the calls of a coupled edge: 30 s for each call, 256
/// coupled connections, and 32 calls on each connection, unless a setter
/// replaces one.
///
/// # Examples
///
/// ```
/// use core::num::{NonZeroU32, NonZeroUsize};
/// use core::time::Duration;
///
/// use tightbeam_grpc::couple::CallLimits;
///
/// let limits = CallLimits::default()
/// 	.with_timeout(Duration::from_secs(10))
/// 	.with_lanes(NonZeroUsize::new(64).expect("64 is not zero"))
/// 	.with_streams(NonZeroU32::new(16).expect("16 is not zero"));
/// assert_eq!(limits.timeout(), Duration::from_secs(10));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallLimits {
	timeout: Duration,
	lanes: NonZeroUsize,
	streams: NonZeroU32,
}

impl CallLimits {
	/// Give each call at most `timeout`, whatever `grpc-timeout` it asks for.
	/// A call that sends no `grpc-timeout` gets `timeout`.
	///
	/// - A `timeout` past one day counts as one day.
	/// - A call that forgets the spend of its claim holds `timeout` once more for the forget.
	#[must_use]
	pub fn with_timeout(mut self, timeout: Duration) -> Self {
		self.timeout = timeout.min(MAX_SPAN);
		self
	}

	/// Hold at most `lanes` coupled connections at once.
	#[must_use]
	pub fn with_lanes(mut self, lanes: NonZeroUsize) -> Self {
		self.lanes = lanes;
		self
	}

	/// Carry at most `streams` calls on each coupled connection, and on the
	/// loopback session. Open streams take at most half of them, so a coupler
	/// with a streaming route needs 2 streams or more.
	#[must_use]
	pub fn with_streams(mut self, streams: NonZeroU32) -> Self {
		self.streams = streams;
		self
	}

	/// The deadline of each call.
	pub fn timeout(&self) -> Duration {
		self.timeout
	}

	/// The coupled connections that the edge holds at once.
	pub fn lanes(&self) -> NonZeroUsize {
		self.lanes
	}

	/// The calls that each coupled connection carries at once.
	pub fn streams(&self) -> NonZeroU32 {
		self.streams
	}

	/// The deadline of a call that asks for `asked`: what it asks, up to the
	/// call limit, or the call limit when it asks for none.
	pub(crate) fn deadline(&self, asked: Option<GrpcTimeout>) -> Duration {
		asked.map_or(self.timeout, |asked| asked.0.min(self.timeout))
	}

	/// The open streams that the loopback session carries at once: half its
	/// streams, so the unary calls keep the other half. `None` below 2
	/// streams, where no stream share leaves a stream for a unary call.
	pub(crate) fn relays(&self) -> Option<NonZeroUsize> {
		let half = usize::try_from(self.streams.get() / 2).ok()?;
		NonZeroUsize::new(half)
	}
}

/// The deadline that a call asks for in `grpc-timeout`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GrpcTimeout(Duration);

impl GrpcTimeout {
	/// The metadata key of the deadline that a call asks for.
	const HEADER: &'static str = "grpc-timeout";

	/// The deadline that `headers` ask for, or `None` when they carry no
	/// `grpc-timeout`.
	///
	/// # Errors
	///
	/// - [`CallFault::Timeout`] -- the value is off its grammar.
	pub(crate) fn of(headers: &HeaderMap) -> Result<Option<Self>, CallFault> {
		headers.get(Self::HEADER).map(Self::try_from).transpose()
	}
}

/// Parses one to eight ASCII digits and one unit of `H`, `M`, `S`, `m`, `u`,
/// or `n`.
///
/// # Errors
///
/// - [`CallFault::Timeout`] -- the value is off that grammar.
impl TryFrom<&HeaderValue> for GrpcTimeout {
	type Error = CallFault;

	fn try_from(value: &HeaderValue) -> Result<Self, Self::Error> {
		let text = value.to_str().map_err(|_| CallFault::Timeout)?;
		let split = text.len().checked_sub(1).ok_or(CallFault::Timeout)?;
		let (digits, unit) = text.split_at(split);

		let digit_count =
			(1..=TIMEOUT_DIGITS).contains(&digits.len()) && digits.bytes().all(|byte| byte.is_ascii_digit());
		if !digit_count {
			return Err(CallFault::Timeout);
		}

		let amount: u64 = digits.parse().map_err(|_| CallFault::Timeout)?;
		let duration = match unit {
			"H" => Duration::from_secs(amount * 3600),
			"M" => Duration::from_secs(amount * 60),
			"S" => Duration::from_secs(amount),
			"m" => Duration::from_millis(amount),
			"u" => Duration::from_micros(amount),
			"n" => Duration::from_nanos(amount),
			_ => return Err(CallFault::Timeout),
		};
		Ok(Self(duration))
	}
}

impl Default for CallLimits {
	fn default() -> Self {
		Self { timeout: DEFAULT_TIMEOUT, lanes: DEFAULT_LANES, streams: DEFAULT_STREAMS }
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_timeout_past_one_day_counts_as_one_day() {
		let limits = CallLimits::default().with_timeout(MAX_SPAN * 2);
		assert_eq!(limits.timeout(), MAX_SPAN);
	}

	fn streams(streams: u32) -> CallLimits {
		let streams = NonZeroU32::new(streams).expect("a test names 1 stream or more");
		CallLimits::default().with_streams(streams)
	}

	tightbeam::tb_cases! {
		fn open_streams_take_half_the_streams((count, relays): (u32, Option<usize>)) {
			assert_eq!(streams(count).relays().map(NonZeroUsize::get), relays);
		}

		cases {
			one_stream => (1, None),
			two_streams => (2, Some(1)),
			three_streams => (3, Some(1)),
			the_default => (32, Some(16)),
		}
	}

	tightbeam::tb_cases! {
		fn a_call_gets_what_it_asks_up_to_the_limit((asked, expected): (Option<&'static str>, Duration)) -> Result<(), CallFault> {
			let asked = asked.map(|value| GrpcTimeout::try_from(&HeaderValue::from_static(value))).transpose()?;
			let limits = CallLimits::default().with_timeout(Duration::from_secs(10));
			assert_eq!(limits.deadline(asked), expected);
			Ok(())
		}

		cases {
			nothing_asked => (None, Duration::from_secs(10)),
			less => (Some("200m"), Duration::from_millis(200)),
			more => (Some("1M"), Duration::from_secs(10)),
		}
	}

	tightbeam::tb_cases! {
		fn a_timeout_off_its_grammar_is_refused(value: &'static str) {
			assert_eq!(GrpcTimeout::try_from(&HeaderValue::from_static(value)), Err(CallFault::Timeout));
		}

		cases {
			no_unit => "100",
			no_digits => "m",
			nine_digits => "123456789m",
			another_unit => "10s",
		}
	}
}
