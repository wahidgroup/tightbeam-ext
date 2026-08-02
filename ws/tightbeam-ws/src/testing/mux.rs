//! Shared behavior for the multiplexed echo server examples.
//!
//! Compiled only under the `testing` feature.
//!
//! Progressive-body echoes stamp the Open route onto the response frame
//! id as `routed:<target>:<hops>` (empty target when unrouted) so Node
//! e2e can assert `openStream` / `openStreamTo` without a colony.

use core::str::{from_utf8, FromStr};
use std::env;
use std::future::Future;
use std::sync::Arc;

use tightbeam::der::Encode;
use tightbeam::policy::TransitStatus;
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::transport::error::TransportError;
use tightbeam::transport::multiplex::{MuxDispatch, MuxHandle, ReplySink, StreamBody, StreamRoute};
use tightbeam::transport::ResponsePackage;
use tightbeam::utils::marker::MaybeSend;
use tightbeam::utils::urn::Urn;
use tightbeam::Frame;

/// Frame-id prefix that asks the server to call the client back.
pub const CALL_ME: &[u8] = b"call-me";

/// Frame-id prefix that asks the server to open a progressive body to
/// the client, routed to the URN that follows this prefix.
///
/// Example id: `call-me-stream:urn:tb:echo`. Checked before
/// [`CALL_ME`] because that prefix is a leading substring.
pub const CALL_ME_STREAM: &[u8] = b"call-me-stream:";

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
/// [`MuxResponder::serve_streaming`](tightbeam::transport::multiplex::MuxResponder::serve_streaming)
/// refuses unary. `emit` stamps unary. This dispatch serves both kinds so
/// demo echo covers Frame RPC and streamed bodies on one connection.
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

	fn streaming(&self, body: StreamBody, route: StreamRoute) -> impl Future<Output = ResponsePackage> + MaybeSend {
		let handle = self.handle.clone();
		async move { echo_streaming(handle, body, route).await }
	}
}

/// Progressive-body echo: reassemble via [`StreamBody::into_frame`], stamp
/// the Open route onto the frame id as `routed:<target>:<hops>` (empty
/// target when unrouted), then run [`echo_stream`].
///
/// Transport drain failures answer `Cancelled`. Invalid DER answers
/// `InvalidArgument`.
pub async fn echo_streaming(handle: MuxHandle, body: StreamBody, route: StreamRoute) -> ResponsePackage {
	match body.into_frame().await {
		Ok(mut frame) => {
			frame.metadata.id = route_stamp(&route);
			echo_stream(handle, Arc::new(frame)).await
		}
		Err(TransportError::DerError(_)) => ResponsePackage::new(TransitStatus::InvalidArgument, None),
		Err(_) => ResponsePackage::new(TransitStatus::Cancelled, None),
	}
}

/// Frame id carrying the Open route for e2e assertions.
fn route_stamp(route: &StreamRoute) -> Vec<u8> {
	let hops = route.hops_remaining();
	match route.target() {
		Some(target) => format!("routed:{target}:{hops}").into_bytes(),
		None => format!("routed::{hops}").into_bytes(),
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
/// stream with the client's own reply, `call-me-stream:<urn>` opens a
/// progressive body routed to that URN, `drain-calm` drains the session,
/// `sink` accepts without a response frame.
pub async fn echo_stream(handle: MuxHandle, frame: Arc<Frame>) -> ResponsePackage {
	if frame.metadata.id.starts_with(DRAIN_CALM) {
		return drain_session(handle).await;
	}
	if frame.metadata.id.starts_with(SINK) {
		return ResponsePackage::new(TransitStatus::Ok, None);
	}
	if frame.metadata.id.starts_with(CALL_ME_STREAM) {
		let target = frame.metadata.id[CALL_ME_STREAM.len()..].to_vec();
		return call_me_stream(handle, frame, &target).await;
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

/// Open a progressive body to the peer with `target` stamped on the Open,
/// push the request frame DER as the body, and relay the peer's Frame reply.
async fn call_me_stream(handle: MuxHandle, frame: Arc<Frame>, target: &[u8]) -> ResponsePackage {
	let Ok(target) = from_utf8(target) else {
		return ResponsePackage::new(TransitStatus::InvalidArgument, None);
	};
	let Ok(urn) = Urn::from_str(target) else {
		return ResponsePackage::new(TransitStatus::InvalidArgument, None);
	};
	let Ok(der) = frame.to_der() else {
		return ResponsePackage::new(TransitStatus::Internal, None);
	};

	let opened = handle.open_stream_to(urn);
	let Ok((sink, response)) = opened else {
		return ResponsePackage::new(TransitStatus::Internal, None);
	};

	if sink.close_with(der).await.is_err() {
		return ResponsePackage::new(TransitStatus::Cancelled, None);
	}

	match response.await {
		Ok(answer) => ResponsePackage::new(TransitStatus::Ok, answer),
		Err(error) => {
			eprintln!("[echo-mux] routed call-back stream failed: {error}");
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
		assert!(CALL_ME_STREAM.starts_with(CALL_ME));
	}
}
