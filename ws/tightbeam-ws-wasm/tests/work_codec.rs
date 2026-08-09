//! Byte-level pin of the work-plane codec against upstream colony.
//!
//! The codec in `src/work.rs` re-states the `ClusterRequest::Work` and
//! `ClusterWorkResponse` wire shapes because the browser target cannot
//! link the `colony` feature. Upstream stays canonical. This native-only
//! test encodes with the upstream types and decodes with the local codec (and
//! vice versa), so any wire drift between the two fails here first.

#![cfg(not(target_arch = "wasm32"))]

use tightbeam::colony::cluster::{ClusterRequest, ClusterWorkRequest, ClusterWorkResponse};
use tightbeam::policy::TransitStatus;
use tightbeam::utils::urn::Urn;
use tightbeam::{encode, Frame, Metadata, TightBeamError, Version};
use tightbeam_ws_wasm::{WorkReply, WorkRequestEnvelope};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The servlet type both encoders target.
fn ping_urn() -> Result<Urn<'static>, BoxError> {
	Ok("urn:tightbeam::servlet:ping".parse()?)
}

/// A distinctive end-to-end frame standing in for the caller's signed
/// work (the pin is byte fidelity, not signature validity).
fn work_frame(id: &[u8], order: u64) -> Frame {
	let mut metadata = Metadata::default();
	metadata.id = id.to_vec();
	metadata.order = order;

	Frame {
		version: Version::V0,
		metadata,
		message: vec![0x04, 0x03, 0x01, 0x02, 0x03],
		integrity: None,
		nonrepudiation: None,
	}
}

/// The gateway reply frame carrying an upstream-encoded work response.
fn reply_carrier(response: &ClusterWorkResponse) -> Result<Frame, BoxError> {
	let mut carrier = work_frame(b"reply", 0);
	carrier.message = encode(response)?;
	Ok(carrier)
}

/// Resolve a locally decoded reply built from upstream-encoded `response`.
fn served_via_local_codec(response: &ClusterWorkResponse) -> Result<Result<Frame, TightBeamError>, BoxError> {
	let carrier = reply_carrier(response)?;
	Ok(WorkReply::try_from(&carrier)?.served())
}

#[test]
fn local_envelope_matches_upstream_cluster_request_bytes() -> Result<(), BoxError> {
	let work = work_frame(b"pin-work", 21);

	let upstream = encode(&ClusterRequest::Work(ClusterWorkRequest::new(ping_urn()?, &work)?))?;
	let local_bytes = WorkRequestEnvelope::new(ping_urn()?, &work)?.into_transport_frame()?;
	assert_eq!(
		local_bytes.message, upstream,
		"local codec envelope bytes must match the canonical ClusterRequest::Work encoding"
	);
	Ok(())
}

#[test]
fn local_wrapper_matches_upstream_transport_conventions() -> Result<(), BoxError> {
	let work = work_frame(b"pin-wrapper", 3);
	let wrapper = WorkRequestEnvelope::new(ping_urn()?, &work)?.into_transport_frame()?;
	assert_eq!(
		wrapper.metadata.id, work.metadata.id,
		"wrapper must reuse the work frame id for correlation, as upstream work_transport does"
	);
	assert_eq!(wrapper.version, Version::V0, "wrapper must stay a V0 hop-local frame");
	assert!(
		wrapper.integrity.is_none() && wrapper.nonrepudiation.is_none(),
		"wrapper must carry no integrity or nonrepudiation of its own"
	);
	Ok(())
}

#[test]
fn local_codec_serves_upstream_ok_reply_byte_for_byte() -> Result<(), BoxError> {
	let servlet_frame = work_frame(b"pin-reply", 9);
	let served = served_via_local_codec(&ClusterWorkResponse::ok(encode(&servlet_frame)?))??;
	assert_eq!(
		encode(&served)?,
		encode(&servlet_frame)?,
		"the served frame must be the upstream-nested servlet frame byte-for-byte"
	);
	Ok(())
}

#[test]
fn local_codec_maps_upstream_refusal_to_work_refused() -> Result<(), BoxError> {
	let served = served_via_local_codec(&ClusterWorkResponse::err(TransitStatus::Unavailable))?;
	assert!(
		matches!(served, Err(TightBeamError::WorkRefused(TransitStatus::Unavailable))),
		"an upstream refusal must resolve to WorkRefused with the same status, got {served:?}"
	);
	Ok(())
}

#[test]
fn local_codec_refuses_upstream_non_ok_reply_with_payload() -> Result<(), BoxError> {
	let stray = ClusterWorkResponse {
		status: TransitStatus::ResourceExhausted,
		payload: Some(encode(&work_frame(b"stray", 1))?),
	};

	let served = served_via_local_codec(&stray)?;
	assert!(
		matches!(served, Err(TightBeamError::WorkRefused(TransitStatus::ResourceExhausted))),
		"a non-Ok status must refuse regardless of payload, got {served:?}"
	);
	Ok(())
}

#[test]
fn local_codec_maps_upstream_bodiless_ok_to_missing_response() -> Result<(), BoxError> {
	let bodiless = ClusterWorkResponse { status: TransitStatus::Ok, payload: None };
	let served = served_via_local_codec(&bodiless)?;
	assert!(
		matches!(served, Err(TightBeamError::MissingResponse)),
		"an Ok reply without a payload violates the plane contract, got {served:?}"
	);
	Ok(())
}
