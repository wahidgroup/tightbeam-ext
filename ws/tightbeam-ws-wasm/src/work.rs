//! Local codec for the cluster work plane, compiled for both targets.
//!
//! The browser build cannot link upstream's `colony` module (its `tokio`
//! requirement has no wasm32 implementation), so this module re-states the
//! two wire shapes a work-submitting client needs: the
//! `ClusterRequest::Work` envelope around a `ClusterWorkRequest`, and the
//! `ClusterWorkResponse` reply. Upstream stays the single source of truth.
//! The native-only `tests/work_codec.rs` pin test fails on any drift
//! between this module and the canonical colony encodings.
//!
//! # Wire shapes (upstream `colony/common/messages.rs`)
//!
//! ```text
//! ClusterWorkRequest ::= SEQUENCE {
//!     servletType  UTF8String,
//!     payload      OCTET STRING,
//!     hopsRemaining INTEGER DEFAULT 255
//! }
//! ClusterRequest ::= CHOICE { ..., work [2] ClusterWorkRequest, ... }
//! ClusterWorkResponse ::= SEQUENCE {
//!     status   ENUMERATED,
//!     payload  OCTET STRING OPTIONAL
//! }
//! ```
//!
//! An origin client always stamps the sentinel hop budget, which equals
//! the DER DEFAULT and is therefore omitted on the wire (X.690 section
//! 11.5). This encoder is origin-only, so it never emits the field.

use der::asn1::{ContextSpecificRef, OctetString, OctetStringRef};
use der::{
	Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Tag, TagMode, TagNumber, Writer,
};

use tightbeam::policy::TransitStatus;
use tightbeam::urn::Urn;
use tightbeam::{decode, encode, Frame, TightBeamError, Version};

use crate::build::FrameConfig;

/// The `ClusterRequest` CHOICE context tag of the `Work` variant.
const WORK_VARIANT_TAG: TagNumber = TagNumber::N2;

/// The `ClusterWorkRequest` SEQUENCE body: the target servlet type plus
/// the caller's nested frame bytes.
///
/// Borrowed so the envelope's already-encoded work DER is written to the
/// wire without another copy. The origin hop budget is the DER DEFAULT
/// and is never encoded here (module docs).
struct WorkRequestBody<'a> {
	servlet_type: &'a Urn<'static>,
	payload: &'a [u8],
}

impl FixedTag for WorkRequestBody<'_> {
	const TAG: Tag = Tag::Sequence;
}

impl EncodeValue for WorkRequestBody<'_> {
	fn value_len(&self) -> der::Result<Length> {
		let payload = OctetStringRef::new(self.payload)?;
		self.servlet_type.encoded_len()? + payload.encoded_len()?
	}

	fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
		let payload = OctetStringRef::new(self.payload)?;
		self.servlet_type.encode(writer)?;
		payload.encode(writer)
	}
}

/// Work request envelope for cluster routing, matching upstream
/// `ClusterWorkRequest` inside `ClusterRequest::Work`.
///
/// The caller's complete end-to-end [`Frame`] nests as the payload
/// byte-for-byte, so its signature, integrity, and previous-frame
/// linkage stay verifiable at the servlet.
pub struct WorkRequestEnvelope {
	servlet_type: Urn<'static>,
	work_der: Vec<u8>,
	correlation_id: Vec<u8>,
}

impl WorkRequestEnvelope {
	/// Build origin work targeting `servlet_type`, nesting the complete
	/// `work` frame as the end-to-end payload.
	///
	/// DER is canonical, so re-encoding the caller's frame reproduces the
	/// caller's bytes. Call sites that already hold the encoded frame use
	/// the crate-internal `from_encoded` constructor and skip the
	/// re-encode.
	pub fn new(servlet_type: impl Into<Urn<'static>>, work: &Frame) -> Result<Self, TightBeamError> {
		Ok(Self::from_encoded(servlet_type.into(), encode(work)?, work))
	}

	/// Build origin work from the caller's already-encoded frame bytes,
	/// nesting them directly.
	///
	/// `work` MUST be the decoded view of `work_der`. The wasm boundary
	/// receives DER and decodes it once for validation, so nesting the
	/// original bytes keeps the end-to-end payload untouched by any
	/// codec round trip.
	pub(crate) fn from_encoded(servlet_type: Urn<'static>, work_der: Vec<u8>, work: &Frame) -> Self {
		Self { servlet_type, work_der, correlation_id: work.metadata().id().to_vec() }
	}

	/// Wrap the envelope in the hop-local transport frame the gateway
	/// expects, matching upstream `work_transport`.
	///
	/// The wrapper is for routing only. It reuses the work frame's
	/// id for correlation and carries the encoded `ClusterRequest::Work`
	/// envelope as its message, with no integrity or nonrepudiation of
	/// its own.
	pub fn into_transport_frame(self) -> Result<Frame, TightBeamError> {
		let body = WorkRequestBody { servlet_type: &self.servlet_type, payload: &self.work_der };
		let tagged = ContextSpecificRef { tag_number: WORK_VARIANT_TAG, tag_mode: TagMode::Explicit, value: &body };
		let message = encode(&tagged)?;

		let wrapper = FrameConfig {
			version: Some(Version::V0),
			id: self.correlation_id,
			message,
			..FrameConfig::default()
		};

		Ok(Frame::from_der(&wrapper.build()?)?)
	}
}

/// Work reply from the cluster, matching upstream `ClusterWorkResponse`.
///
/// Decode one from the gateway's reply frame with [`TryFrom`], then
/// resolve success and refusal in one step with [`WorkReply::served`].
pub struct WorkReply {
	status: TransitStatus,
	payload: Option<Vec<u8>>,
}

impl FixedTag for WorkReply {
	const TAG: Tag = Tag::Sequence;
}

impl<'a> DecodeValue<'a> for WorkReply {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
		reader.read_nested(header.length, |reader| {
			let status = reader.decode()?;
			let payload = Option::<OctetString>::decode(reader)?.map(OctetString::into_bytes);
			Ok(Self { status, payload })
		})
	}
}

impl TryFrom<&Frame> for WorkReply {
	type Error = TightBeamError;

	/// Decode the work reply carried in the gateway reply frame's message.
	fn try_from(frame: &Frame) -> Result<Self, Self::Error> {
		decode(frame.message())
	}
}

impl WorkReply {
	/// Resolve the reply into the servlet's complete response frame or a
	/// typed error, matching upstream `ClusterWorkResponse::served`.
	///
	/// The unary work plane is request-reply, so a served request always
	/// carries the servlet's complete response frame. A non-Ok status is
	/// a refusal and maps to [`TightBeamError::WorkRefused`] regardless
	/// of any payload. A bodiless Ok violates the plane contract and
	/// maps to [`TightBeamError::MissingResponse`].
	pub fn served(self) -> Result<Frame, TightBeamError> {
		let payload = self.refusal_checked()?;
		decode(&payload)
	}

	/// As [`WorkReply::served`], returning the servlet frame's original
	/// DER bytes after validating that they decode as a [`Frame`].
	///
	/// The wasm boundary hands DER back to JavaScript, so returning the
	/// received bytes keeps the servlet's end-to-end frame untouched by
	/// any codec round trip. Gated to that only consumer, so native
	/// builds carry no dead helper.
	#[cfg(target_arch = "wasm32")]
	pub(crate) fn served_der(self) -> Result<Vec<u8>, TightBeamError> {
		let payload = self.refusal_checked()?;
		let _: Frame = decode(&payload)?;
		Ok(payload)
	}

	/// The refusal-or-payload resolution shared by both served forms.
	fn refusal_checked(self) -> Result<Vec<u8>, TightBeamError> {
		if self.status != TransitStatus::Ok {
			return Err(TightBeamError::WorkRefused(self.status));
		}

		self.payload.ok_or(TightBeamError::MissingResponse)
	}
}

#[cfg(test)]
mod tests {
	use der::asn1::ContextSpecific;

	use super::*;

	type TestResult = core::result::Result<(), Box<dyn core::error::Error>>;
	type AnyResult<T> = core::result::Result<T, Box<dyn core::error::Error>>;

	/// Decoded view of the request body, for asserting what the envelope
	/// wrote. Decoding only the two always-present fields inside
	/// `read_nested` makes any encoded hop-budget field a hard error.
	struct ProbeBody {
		servlet_type: Urn<'static>,
		payload: Vec<u8>,
	}

	impl FixedTag for ProbeBody {
		const TAG: Tag = Tag::Sequence;
	}

	impl<'a> DecodeValue<'a> for ProbeBody {
		fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
			reader.read_nested(header.length, |reader| {
				let servlet_type = reader.decode()?;
				let payload = OctetString::decode(reader)?.into_bytes();
				Ok(Self { servlet_type, payload })
			})
		}
	}

	/// Encoder for reply bytes, standing in for the upstream encoder the
	/// unit tests cannot link. The pin test covers the real one.
	struct ProbeReply {
		status: TransitStatus,
		payload: Option<Vec<u8>>,
	}

	impl FixedTag for ProbeReply {
		const TAG: Tag = Tag::Sequence;
	}

	impl EncodeValue for ProbeReply {
		fn value_len(&self) -> der::Result<Length> {
			let payload = self.payload.as_deref().map(OctetStringRef::new).transpose()?;
			self.status.encoded_len()? + payload.encoded_len()?
		}

		fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
			let payload = self.payload.as_deref().map(OctetStringRef::new).transpose()?;
			self.status.encode(writer)?;
			payload.encode(writer)
		}
	}

	fn ping_urn() -> AnyResult<Urn<'static>> {
		Ok("urn:tightbeam::servlet:ping".parse()?)
	}

	fn carrier(id: &[u8], message: Vec<u8>) -> AnyResult<Frame> {
		let config = FrameConfig {
			version: Some(Version::V0),
			id: id.to_vec(),
			order: 7,
			message,
			..FrameConfig::default()
		};

		Ok(Frame::from_der(&config.build()?)?)
	}

	fn work_frame(id: &[u8]) -> AnyResult<Frame> {
		carrier(id, vec![0x04, 0x01, 0x2A])
	}

	fn transport_frame(id: &[u8]) -> AnyResult<Frame> {
		Ok(WorkRequestEnvelope::new(ping_urn()?, &work_frame(id)?)?.into_transport_frame()?)
	}

	fn decode_body(message: &[u8]) -> AnyResult<ProbeBody> {
		let tagged = ContextSpecific::<ProbeBody>::from_der(message)?;
		Ok(tagged.value)
	}

	fn served_of(status: TransitStatus, payload: Option<Vec<u8>>) -> Result<Frame, TightBeamError> {
		WorkReply { status, payload }.served()
	}

	#[test]
	fn envelope_nests_the_work_frame_bytes_untouched() -> TestResult {
		let work = work_frame(b"work-1")?;
		let body = decode_body(transport_frame(b"work-1")?.message())?;
		assert_eq!(body.payload, encode(&work)?);
		assert_eq!(body.servlet_type, ping_urn()?);
		Ok(())
	}

	#[test]
	fn origin_envelope_omits_the_default_hop_budget() -> TestResult {
		// ProbeBody decodes exactly two fields inside read_nested, so an
		// encoded hop-budget field would fail this decode with trailing
		// data inside the sequence.
		decode_body(transport_frame(b"work-2")?.message())?;
		Ok(())
	}

	#[test]
	fn transport_wrapper_is_hop_local_only() -> TestResult {
		let wrapper = transport_frame(b"work-3")?;
		assert_eq!(wrapper.version(), Version::V0);
		assert_eq!(wrapper.metadata().id(), b"work-3");
		assert_eq!(wrapper.metadata().order(), 0);
		assert!(wrapper.integrity().is_none());
		assert!(wrapper.nonrepudiation().is_none());
		Ok(())
	}

	#[test]
	fn served_reply_round_trips_the_servlet_frame_bytes() -> TestResult {
		let servlet_frame = work_frame(b"reply-1")?;
		let reply_der = ProbeReply { status: TransitStatus::Ok, payload: Some(encode(&servlet_frame)?) };

		let reply = carrier(b"reply-1", encode(&reply_der)?)?;
		let served = WorkReply::try_from(&reply)?.served()?;
		assert_eq!(encode(&served)?, encode(&servlet_frame)?);
		Ok(())
	}

	#[test]
	fn refusal_maps_to_work_refused_with_its_status() {
		let served = served_of(TransitStatus::Unavailable, None);
		assert!(matches!(served, Err(TightBeamError::WorkRefused(TransitStatus::Unavailable))));
	}

	#[test]
	fn refusal_wins_over_a_stray_payload() {
		let served = served_of(TransitStatus::ResourceExhausted, Some(vec![0x30, 0x00]));
		assert!(matches!(
			served,
			Err(TightBeamError::WorkRefused(TransitStatus::ResourceExhausted))
		));
	}

	#[test]
	fn bodiless_ok_maps_to_missing_response() {
		let served = served_of(TransitStatus::Ok, None);
		assert!(matches!(served, Err(TightBeamError::MissingResponse)));
	}
}
