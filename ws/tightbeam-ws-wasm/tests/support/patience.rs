//! The bound of a wasm test's wait on an event that should come, as the tests
//! section of `docs/ws-wasm.md` describes.

use core::future::Future;
use core::pin::pin;
use core::time::Duration;

use tightbeam::clock::Clock;

use super::BrowserClock;

/// The bound of a test's wait on an event that should come.
const PATIENCE: Duration = Duration::from_secs(10);

/// The output of `work`, which a test awaits under the [`PATIENCE`] of the
/// host clock.
///
/// # Panics
///
/// - `work` is still pending once [`PATIENCE`] passes.
pub(crate) async fn settled<F: Future>(work: F) -> F::Output {
	let clock: &dyn Clock = &BrowserClock::host();
	let settled = clock.within(PATIENCE, pin!(work)).await;
	settled.expect("the awaited work should end within the patience of the test")
}
