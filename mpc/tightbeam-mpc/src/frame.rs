//! MPC payload framing: opaque protocol bytes inside a tightbeam frame.
//!
//! The engine's messages are already self-describing (bincode-encoded
//! `WrappedMessage`s), so the frame carries them untouched inside an
//! `OCTET STRING` body. A lane discriminant separates engine traffic
//! from control traffic (program submission, digest exchange, reveals)
//! so higher layers never have to sniff payload contents. Sender
//! attribution comes from the authenticated link a frame arrived on,
//! never from frame metadata, so the id is a constant and the order
//! stamp exists purely for wire diagnostics.

use der::asn1::OctetString;
use der::{Decode, Sequence};
use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::{Beamable, Frame, TightBeamError, Version};

use crate::error::Error;

/// Constant frame id: attribution never reads it, diagnostics do.
const FRAME_ID: &str = "mpc";

/// Which local consumer an inbound payload belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
	/// MPC engine traffic: `WrappedMessage` bytes for `process`.
	Engine,
	/// Control-plane traffic: program submission, digest exchange,
	/// reveal share exchange.
	Control,
}

impl From<Lane> for u8 {
	fn from(lane: Lane) -> Self {
		match lane {
			Lane::Engine => 0,
			Lane::Control => 1,
		}
	}
}

impl TryFrom<u8> for Lane {
	type Error = Error;

	fn try_from(value: u8) -> core::result::Result<Self, Self::Error> {
		match value {
			0 => Ok(Self::Engine),
			1 => Ok(Self::Control),
			_ => Err(Error::UnknownLane { lane: value }),
		}
	}
}

/// Opaque payload wrapper carried as the frame body.
#[derive(Beamable, Clone, Debug, PartialEq, Eq, Sequence)]
#[beam(min_version = "V0")]
pub(crate) struct OpaqueBody {
	/// The lane discriminant octet.
	pub(crate) lane: u8,
	/// The wrapped MPC message octets.
	pub(crate) body: OctetString,
}

/// Assemble a V0 frame around the opaque MPC payload.
pub(crate) fn build(order: u64, lane: Lane, payload: &[u8]) -> core::result::Result<Frame, TightBeamError> {
	let body = OpaqueBody { lane: u8::from(lane), body: OctetString::new(payload)? };

	FrameBuilder::<OpaqueBody>::from(Version::V0)
		.with_id(FRAME_ID)
		.with_order(order)
		.with_message(body)
		.build()
}

/// Lift the lane and payload back out of a received frame.
pub(crate) fn open(frame: &Frame) -> core::result::Result<(Lane, Vec<u8>), Error> {
	let body = OpaqueBody::from_der(&frame.message).map_err(TightBeamError::from)?;
	let lane = Lane::try_from(body.lane)?;
	let payload = body.body.as_bytes().to_vec();
	Ok((lane, payload))
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Build one frame, expecting the builder to accept it.
	fn built(order: u64, lane: Lane, bytes: &[u8]) -> Frame {
		build(order, lane, bytes).expect("the frame should build")
	}

	#[test]
	fn payload_round_trips() {
		let frame = built(7, Lane::Engine, b"wrapped-message");
		let (lane, lifted) = open(&frame).expect("the opaque body should decode");
		assert_eq!(lane, Lane::Engine);
		assert_eq!(lifted, b"wrapped-message");
	}

	#[test]
	fn control_lane_round_trips() {
		let frame = built(3, Lane::Control, b"program-bytes");
		let (lane, lifted) = open(&frame).expect("the opaque body should decode");
		assert_eq!(lane, Lane::Control);
		assert_eq!(lifted, b"program-bytes");
	}

	#[test]
	fn empty_payload_round_trips() {
		let frame = built(0, Lane::Engine, b"");
		let (_, lifted) = open(&frame).expect("the opaque body should decode");
		assert_eq!(lifted, b"");
	}

	#[test]
	fn unknown_lane_octets_are_rejected() {
		let outcome = Lane::try_from(9);
		assert!(matches!(outcome, Err(Error::UnknownLane { lane: 9 })));
	}

	#[test]
	fn frame_metadata_carries_the_diagnostics() {
		let frame = built(42, Lane::Engine, b"x");
		assert_eq!(frame.metadata.id, b"mpc");
		assert_eq!(frame.metadata.order, 42);
	}
}
