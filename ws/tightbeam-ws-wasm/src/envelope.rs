//! Cleartext transport-envelope codec.

use tightbeam::der::{Decode, Encode};
use tightbeam::transport::{TransportEnvelope, WireEnvelope};
use tightbeam::Frame;

use crate::error::{Error, Result};

/// Wrap a DER-encoded [`Frame`] in a cleartext request envelope, returning DER.
pub fn encode_cleartext_request(frame_der: &[u8]) -> Result<Vec<u8>> {
	let frame = Frame::from_der(frame_der)?;
	let envelope = WireEnvelope::Cleartext(TransportEnvelope::new_request(frame));
	Ok(envelope.to_der()?)
}

/// Decode a cleartext response envelope, yielding the response frame as DER.
pub fn decode_response(envelope_der: &[u8]) -> Result<Option<Vec<u8>>> {
	let envelope = WireEnvelope::from_der(envelope_der)?;
	let WireEnvelope::Cleartext(TransportEnvelope::Response(response)) = envelope else {
		return Err(Error::UnexpectedEnvelope);
	};

	let Some(frame) = response.message() else {
		return Ok(None);
	};

	Ok(Some(frame.as_ref().to_der()?))
}

#[cfg(test)]
mod tests {
	use tightbeam::der::{Decode, Encode};
	use tightbeam::policy::TransitStatus;
	use tightbeam::testing::create_v0_tightbeam;
	use tightbeam::transport::{ResponsePackage, TransportEnvelope, WireEnvelope};
	use tightbeam::Frame;

	use super::{decode_response, encode_cleartext_request, Error};

	type TestResult = core::result::Result<(), Box<dyn core::error::Error>>;

	fn sample_frame() -> Frame {
		create_v0_tightbeam(None, None)
	}

	fn response_envelope(frame: Frame) -> core::result::Result<Vec<u8>, tightbeam::der::Error> {
		let package = ResponsePackage::new(TransitStatus::Accepted, Some(frame));
		WireEnvelope::Cleartext(TransportEnvelope::Response(package)).to_der()
	}

	#[test]
	fn encodes_a_cleartext_request_frame() -> TestResult {
		let frame_der = sample_frame().to_der()?;

		let request_der = encode_cleartext_request(&frame_der)?;
		let decoded = WireEnvelope::from_der(&request_der)?;
		assert!(matches!(decoded, WireEnvelope::Cleartext(TransportEnvelope::Request(_))));
		Ok(())
	}

	#[test]
	fn decodes_a_cleartext_response_frame() -> TestResult {
		let frame = sample_frame();
		let frame_der = frame.to_der()?;
		let envelope_der = response_envelope(frame)?;

		let recovered = decode_response(&envelope_der)?;
		assert_eq!(recovered, Some(frame_der));
		Ok(())
	}

	#[test]
	fn rejects_a_non_response_envelope() -> TestResult {
		let request_der = encode_cleartext_request(&sample_frame().to_der()?)?;
		let outcome = decode_response(&request_der);
		assert!(matches!(outcome, Err(Error::UnexpectedEnvelope)));
		Ok(())
	}
}
