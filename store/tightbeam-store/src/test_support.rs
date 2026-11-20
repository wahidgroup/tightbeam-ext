//! What the unit tests read of a refusal.

use std::panic::{self, UnwindSafe};

/// The message that `build` panics with, or `None` when it returns.
///
/// A const constructor panics with a formatted message, so its payload is a
/// `String`. A literal panic carries a `&str`.
pub(crate) fn panic_message<T>(build: impl FnOnce() -> T + UnwindSafe) -> Option<String> {
	let payload = panic::catch_unwind(build).err()?;
	let formatted = payload.downcast_ref::<String>().cloned();
	formatted.or_else(|| payload.downcast_ref::<&str>().map(|message| (*message).to_owned()))
}
