//! Update-frame construction and payload extraction.
//!
//! The registry is the single frame authority for updates: it owns
//! `metadata.id` (the topic) and `metadata.order` (the dense per-topic
//! stamp) at build time, so no caller-built frame is ever mutated and no
//! `integrity`/`nonrepudiation` artifact can be invalidated.
//!
//! The body encoding matches the ws client's opaque profile body: an ASN.1
//! SEQUENCE wrapping one OCTET STRING, so TypeScript subscribers decode
//! updates with their ordinary codecs.

use der::asn1::OctetString;
use der::{Decode, Sequence};

use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::{Beamable, Frame, TightBeamError, Version};

use crate::topic::{Topic, END_PREFIX};

/// Opaque payload wrapper carried as the frame body.
#[derive(Beamable, Clone, Debug, PartialEq, Eq, Sequence)]
#[beam(min_version = "V0")]
pub(crate) struct OpaqueBody {
	/// The wrapped payload octets.
	pub(crate) body: OctetString,
}

/// Build one topic update: id = topic, order = the dense stamp, body =
/// the application payload.
pub(crate) fn update_frame(topic: &Topic, order: u64, payload: &[u8]) -> Result<Frame, TightBeamError> {
	build(topic.as_str(), order, payload)
}

/// Build one completion push: id = `end/<topic>`, empty body.
pub(crate) fn end_frame(topic: &Topic, order: u64) -> Result<Frame, TightBeamError> {
	let id = format!("{END_PREFIX}{topic}");
	build(&id, order, &[])
}

/// Assemble a V0 frame around the opaque body.
pub(crate) fn build(id: &str, order: u64, payload: &[u8]) -> Result<Frame, TightBeamError> {
	let body = OpaqueBody { body: OctetString::new(payload)? };

	FrameBuilder::<OpaqueBody>::from(Version::V0)
		.with_id(id)
		.with_order(order)
		.with_message(body)
		.build()
}

/// The application payload carried by an opaque-body frame.
///
/// The inverse of what [`TopicRegistry::publish`](crate::TopicRegistry::publish)
/// installs; servers relaying client-built frames (the demo's `pub/`
/// command) use it to lift the payload back out.
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

	/// Build one update frame, expecting the builder to accept it.
	fn built_update(topic: &Topic, order: u64, payload: &[u8]) -> Frame {
		update_frame(topic, order, payload).expect("the update frame should build")
	}

	/// Build one completion frame, expecting the builder to accept it.
	fn built_end(topic: &Topic, order: u64) -> Frame {
		end_frame(topic, order).expect("the end frame should build")
	}

	/// Decode the opaque body, expecting a well-formed frame.
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
