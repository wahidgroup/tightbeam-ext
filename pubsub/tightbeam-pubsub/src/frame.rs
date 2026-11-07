//! Update-frame construction.
//!
//! The registry alone stamps `metadata.id` (topic) and `metadata.order`
//! (dense per-topic sequence) when it builds an update. Callers never
//! mutate a finished frame, so integrity and non-repudiation artifacts
//! stay valid.
//!
//! The body is an [`Opaque`], an ASN.1 SEQUENCE of one OCTET STRING. That
//! matches the ws client's opaque profile so TypeScript subscribers reuse
//! ordinary codecs, and a Rust reader lifts the payload with
//! [`Frame::decode_message`].

use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::{Frame, Opaque, TightBeamError, Version};

use crate::topic::{Topic, END_PREFIX};

/// One frame of the pub/sub profile: an [`Opaque`] body of `payload` under
/// the message id `id` and the order stamp `order`.
///
/// Every frame the wire carries has this shape: a topic update, an
/// `end/<topic>` completion, and each client command.
///
/// # Examples
///
/// ```
/// use tightbeam_pubsub::testing::OpaqueFrame;
///
/// let command = OpaqueFrame { id: "sub/prices", order: 1, payload: b"" };
/// let frame = command.build()?;
/// assert_eq!(frame.metadata().id(), b"sub/prices");
/// # Ok::<(), tightbeam::TightBeamError>(())
/// ```
pub struct OpaqueFrame<'a> {
	/// The message id, such as a topic name or a command like `sub/prices`.
	pub id: &'a str,
	/// The order stamp.
	pub order: u64,
	/// The payload octets the body carries.
	pub payload: &'a [u8],
}

impl OpaqueFrame<'_> {
	/// Build the V0 frame.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`]: the body or the frame fails
	///   to encode as DER.
	pub fn build(&self) -> Result<Frame, TightBeamError> {
		let framed = self.framed(Version::V0)?;
		framed.build()
	}

	/// The builder of a frame at `version` with this id, order, and body.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`]: the body fails to encode as
	///   DER.
	pub(crate) fn framed(&self, version: Version) -> Result<FrameBuilder<Opaque>, TightBeamError> {
		let body = Opaque::new(self.payload)?;

		let versioned = FrameBuilder::<Opaque>::from(version);
		let framed = versioned.with_id(self.id).with_order(self.order).with_message(body);
		Ok(framed)
	}
}

impl Topic {
	/// The update of this topic at `order` that carries `payload`.
	pub(crate) fn update_frame(&self, order: u64, payload: &[u8]) -> Result<Frame, TightBeamError> {
		let frame = OpaqueFrame { id: self.as_str(), order, payload };
		frame.build()
	}

	/// The `end/<topic>` completion of this topic at `order`.
	pub(crate) fn end_frame(&self, order: u64) -> Result<Frame, TightBeamError> {
		let id = format!("{END_PREFIX}{self}");
		let frame = OpaqueFrame { id: &id, order, payload: &[] };
		frame.build()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn built_update(topic: &Topic, order: u64, payload: &[u8]) -> Frame {
		topic.update_frame(order, payload).expect("the update frame should build")
	}

	fn built_end(topic: &Topic, order: u64) -> Frame {
		topic.end_frame(order).expect("the end frame should build")
	}

	fn payload_of(frame: &Frame) -> Vec<u8> {
		let body = frame.decode_message::<Opaque>().expect("the opaque body should decode");
		body.into_bytes()
	}

	#[test]
	fn update_frame_carries_topic_order_and_payload() {
		let frame = built_update(&Topic::fixture("prices/spot"), 7, b"payload");
		assert_eq!(frame.metadata().id(), b"prices/spot");
		assert_eq!(frame.metadata().order(), 7);
		assert_eq!(payload_of(&frame), b"payload");
	}

	#[test]
	fn end_frame_prefixes_the_topic_and_carries_no_payload() {
		let frame = built_end(&Topic::fixture("prices/spot"), 8);
		assert_eq!(frame.metadata().id(), b"end/prices/spot");
		assert_eq!(frame.metadata().order(), 8);
		assert_eq!(payload_of(&frame), b"");
	}
}
