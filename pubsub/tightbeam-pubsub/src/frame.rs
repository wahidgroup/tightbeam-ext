//! Update-frame construction and payload extraction.
//!
//! The registry alone stamps `metadata.id` (topic) and `metadata.order`
//! (dense per-topic sequence) when it builds an update. Callers never
//! mutate a finished frame, so integrity and non-repudiation artifacts
//! stay valid.
//!
//! The body is an ASN.1 SEQUENCE of one OCTET STRING. That matches the
//! ws client's opaque profile so TypeScript subscribers reuse ordinary
//! codecs.

use der::asn1::OctetString;
use der::{Decode, Sequence};

use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::{Beamable, Frame, TightBeamError, Version};

use crate::topic::{Topic, END_PREFIX};

/// Frame body: ASN.1 SEQUENCE wrapping one application OCTET STRING.
#[derive(Beamable, Clone, Debug, PartialEq, Eq, Sequence)]
#[beam(min_version = "V0")]
pub(crate) struct OpaqueBody {
	/// Application octets inside the opaque SEQUENCE.
	pub(crate) body: OctetString,
}

pub(crate) fn update_frame(topic: &Topic, order: u64, payload: &[u8]) -> Result<Frame, TightBeamError> {
	build(topic.as_str(), order, payload)
}

pub(crate) fn end_frame(topic: &Topic, order: u64) -> Result<Frame, TightBeamError> {
	let id = format!("{END_PREFIX}{topic}");
	build(&id, order, &[])
}

pub(crate) fn build(id: &str, order: u64, payload: &[u8]) -> Result<Frame, TightBeamError> {
	let body = OpaqueBody { body: OctetString::new(payload)? };

	FrameBuilder::<OpaqueBody>::from(Version::V0)
		.with_id(id)
		.with_order(order)
		.with_message(body)
		.build()
}

/// Recover application octets from an opaque-body frame.
///
/// Inverse of the body [`TopicRegistry::publish`](crate::TopicRegistry::publish)
/// installs. Relays that accept client-built `pub/<topic>` frames use this
/// to lift the payload.
///
/// # Errors
///
/// Returns [`TightBeamError`] when `frame.message` is not a well-formed
/// opaque body SEQUENCE wrapping one OCTET STRING.
pub fn opaque_payload(frame: &Frame) -> Result<Vec<u8>, TightBeamError> {
	let body = OpaqueBody::from_der(&frame.message)?;
	Ok(body.body.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
	use super::*;

	fn topic(name: &str) -> Topic {
		name.parse().expect("test topics should parse")
	}

	fn built_update(topic: &Topic, order: u64, payload: &[u8]) -> Frame {
		update_frame(topic, order, payload).expect("the update frame should build")
	}

	fn built_end(topic: &Topic, order: u64) -> Frame {
		end_frame(topic, order).expect("the end frame should build")
	}

	fn payload_of(frame: &Frame) -> Vec<u8> {
		opaque_payload(frame).expect("the opaque body should decode")
	}

	#[test]
	fn update_frame_carries_topic_order_and_payload() {
		let frame = built_update(&topic("prices/spot"), 7, b"payload");
		assert_eq!(frame.metadata.id, b"prices/spot");
		assert_eq!(frame.metadata.order, 7);
		assert_eq!(payload_of(&frame), b"payload");
	}

	#[test]
	fn end_frame_prefixes_the_topic_and_carries_no_payload() {
		let frame = built_end(&topic("prices/spot"), 8);
		assert_eq!(frame.metadata.id, b"end/prices/spot");
		assert_eq!(frame.metadata.order, 8);
		assert_eq!(payload_of(&frame), b"");
	}
}
