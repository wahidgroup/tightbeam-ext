//! The hang guard and the per-kind probe that the scenarios share, as
//! `docs/ws.md` (Test support) states.

use core::future::Future;
use core::time::Duration;

use futures_util::TryStreamExt;
use tightbeam::testing::TestFrame;
use tightbeam::transport::multiplex::MuxHandle;
use tightbeam::transport::TransportResult;
use tightbeam::{encode, Frame, TightBeamError};

/// How long a wait on a peer may take before the case fails instead of
/// hanging.
const PATIENCE: Duration = Duration::from_secs(5);

/// The duplex chunk that a probe sends.
const CHUNK: &[u8] = b"probe-duplex";

/// The output of `work`, a wait on a peer, within [`PATIENCE`].
///
/// # Errors
///
/// - The [`TightBeamError`] of a peer that holds the wait past [`PATIENCE`].
pub async fn bounded<F: Future>(work: F) -> Result<F::Output, TightBeamError> {
	let bounded = tokio::time::timeout(PATIENCE, work).await;
	bounded.map_err(|elapsed| TightBeamError::IoError(elapsed.into()))
}

/// What a client observes of a stream: its answer, or the debug form of the
/// error it failed with.
type Observed<T> = Result<T, String>;

/// What a client observes of one stream of each kind.
#[derive(Debug, PartialEq)]
pub struct Answers {
	unary: Observed<Option<Frame>>,
	streaming: Observed<Option<Frame>>,
	duplex: Observed<Vec<Vec<u8>>>,
}

impl Answers {
	/// Open one stream of each kind on `handle`, and observe how each ends.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a probe frame that does not encode, or of a
	///   stream that `handle` cannot open.
	/// - The errors of [`bounded`].
	pub async fn of(handle: &MuxHandle) -> Result<Self, TightBeamError> {
		let frame = TestFrame::v0(None, None);
		let der = encode(&frame)?;

		let unary = bounded(handle.emit_on_stream(&frame)).await?;

		let (sink, response) = handle.open_stream()?;
		let streaming = bounded(async move {
			let _closed = sink.close_with(&der).await;
			response.await
		})
		.await?;

		let (sink, body) = handle.open_duplex()?;
		let duplex = bounded(async move {
			let _closed = sink.close_with(CHUNK).await;
			body.try_collect().await
		})
		.await?;

		Ok(Self {
			unary: Self::observed(unary),
			streaming: Self::observed(streaming),
			duplex: Self::observed(duplex),
		})
	}

	/// The kinds whose stream answered, joined by commas in the order unary,
	/// streaming, and duplex.
	pub fn answered(&self) -> String {
		let kinds = [
			self.unary.is_ok().then_some("unary"),
			self.streaming.is_ok().then_some("streaming"),
			self.duplex.is_ok().then_some("duplex"),
		];

		let kinds: Vec<&str> = kinds.into_iter().flatten().collect();
		kinds.join(",")
	}

	/// The observation of a stream that ended in `outcome`.
	fn observed<T>(outcome: TransportResult<T>) -> Observed<T> {
		outcome.map_err(|error| format!("{error:?}"))
	}
}
