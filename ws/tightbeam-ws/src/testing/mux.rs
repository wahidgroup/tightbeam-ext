//! Shared behavior for the multiplexed echo server examples.
//!
//! Compiled only under the `testing` feature.

use std::env;
use std::sync::Arc;

use tightbeam::policy::TransitStatus;
use tightbeam::transport::error::TransportError;
use tightbeam::transport::multiplex::{GoAwayReason, MuxHandle};
use tightbeam::transport::ResponsePackage;
use tightbeam::Frame;

/// Frame-id prefix that asks the server to call the client back.
pub const CALL_ME: &[u8] = b"call-me";

/// Frame-id prefix that asks the server to drain the session with an
/// `EnhanceYourCalm` GoAway, exercising reason surfacing in clients.
pub const DRAIN_CALM: &[u8] = b"drain-calm";

/// Frame-id prefix that asks the server to accept without a response
/// frame, exercising the empty-response path in clients.
pub const SINK: &[u8] = b"sink";

/// Read a `u32` environment variable, falling back to `default`.
pub fn env_u32(name: &str, default: u32) -> u32 {
	env::var(name)
		.ok()
		.and_then(|value| value.parse::<u32>().ok())
		.unwrap_or(default)
}

/// Echo `frame`, or run the command its id selects: `call-me` answers the
/// stream with the client's own reply, `drain-calm` drains the session,
/// `sink` accepts without a response frame.
pub async fn echo_stream(handle: MuxHandle, frame: Arc<Frame>) -> ResponsePackage {
	if frame.metadata.id.starts_with(DRAIN_CALM) {
		return drain_session(handle).await;
	}
	if frame.metadata.id.starts_with(SINK) {
		return ResponsePackage::new(TransitStatus::Ok, None);
	}
	if !frame.metadata.id.starts_with(CALL_ME) {
		return ResponsePackage::new(TransitStatus::Ok, Some(Frame::clone(&frame)));
	}

	match handle.emit_on_stream(&frame).await {
		Ok(answer) => ResponsePackage::new(TransitStatus::Ok, answer),
		Err(error) => {
			eprintln!("[echo-mux] call-back stream failed: {error}");
			ResponsePackage::new(relayed_status(&error), None)
		}
	}
}

/// Relay a call-back failure to the requester.
///
/// A peer refusal keeps its status so the requester observes the exact code
/// the call-back handler answered with. Everything else (transport faults,
/// local failures) is the server's own trouble and answers `Internal`.
fn relayed_status(error: &TransportError) -> TransitStatus {
	let TransportError::OperationFailed(failure) = error else {
		return TransitStatus::Internal;
	};

	TransitStatus::try_from(*failure).unwrap_or(TransitStatus::Internal)
}

/// Drain the session with an `EnhanceYourCalm` GoAway.
///
/// The GoAway and the writer stop are queued ahead of this stream's
/// response, so the requester observes the drain rather than an echo.
async fn drain_session(handle: MuxHandle) -> ResponsePackage {
	if let Err(error) = handle.shutdown_with(GoAwayReason::EnhanceYourCalm).await {
		eprintln!("[echo-mux] drain failed: {error}");
	}

	ResponsePackage::new(TransitStatus::Ok, None)
}
