//! Shared behavior for the multiplexed echo server examples.
//!
//! Compiled only under the `testing` feature.

use std::env;
use std::future::Future;
use std::sync::Arc;

use tightbeam::policy::TransitStatus;
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::transport::error::TransportError;
use tightbeam::transport::multiplex::{MuxDispatch, MuxHandle, ReplySink, StreamBody};
use tightbeam::transport::ResponsePackage;
use tightbeam::utils::marker::MaybeSend;
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

/// Unary Frame echo plus progressive-body echo for `openStream`.
///
/// [`MuxResponder::serve_streaming`] refuses unary; `emit` stamps unary.
/// This dispatch serves both kinds so demo echo covers Frame RPC and
/// streamed bodies on one connection.
pub struct EchoFrames {
	handle: MuxHandle,
}

impl EchoFrames {
	/// Pin the connection handle used for call-back / drain commands.
	pub fn new(handle: MuxHandle) -> Self {
		Self { handle }
	}
}

impl MuxDispatch for EchoFrames {
	fn unary(&self, frame: Arc<Frame>) -> impl Future<Output = ResponsePackage> + MaybeSend {
		let handle = self.handle.clone();
		async move { echo_stream(handle, frame).await }
	}

	fn streaming(&self, body: StreamBody) -> impl Future<Output = ResponsePackage> + MaybeSend {
		let handle = self.handle.clone();
		async move { echo_streaming(handle, body).await }
	}
}

/// Progressive-body echo: reassemble via [`StreamBody::into_frame`], then
/// run [`echo_stream`]. Transport drain failures answer `Cancelled`;
/// invalid DER answers `InvalidArgument`.
pub async fn echo_streaming(handle: MuxHandle, body: StreamBody) -> ResponsePackage {
	match body.into_frame().await {
		Ok(frame) => echo_stream(handle, Arc::new(frame)).await,
		Err(TransportError::DerError(_)) => ResponsePackage::new(TransitStatus::InvalidArgument, None),
		Err(_) => ResponsePackage::new(TransitStatus::Cancelled, None),
	}
}

/// Duplex chunk echo: every request chunk is pushed straight back.
pub async fn echo_duplex(mut body: StreamBody, mut reply: ReplySink) -> TransitStatus {
	loop {
		match body.chunk().await {
			Ok(Some(chunk)) => {
				if reply.push(&chunk).await.is_err() {
					return TransitStatus::Cancelled;
				}
			}
			Ok(None) => return TransitStatus::Ok,
			Err(_) => return TransitStatus::Cancelled,
		}
	}
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
pub(crate) fn relayed_status(error: &TransportError) -> TransitStatus {
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

#[cfg(test)]
mod tests {
	use super::*;
	use tightbeam::transport::error::TransportFailure;

	#[test]
	fn relayed_status_keeps_peer_refusal_code() {
		let error = TransportError::OperationFailed(TransportFailure::Unavailable);
		assert_eq!(relayed_status(&error), TransitStatus::Unavailable);
	}

	#[test]
	fn relayed_status_maps_non_operation_to_internal() {
		let error = TransportError::ConnectionClosed;
		assert_eq!(relayed_status(&error), TransitStatus::Internal);
	}

	#[test]
	fn echo_command_prefixes_do_not_overlap() {
		assert!(!CALL_ME.starts_with(DRAIN_CALM));
		assert!(!DRAIN_CALM.starts_with(CALL_ME));
		assert!(!SINK.starts_with(CALL_ME));
	}
}
