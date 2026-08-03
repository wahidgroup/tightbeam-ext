//! Control-lane message codec: program submission, digest echoes, and
//! reveal share exchange.
//!
//! Every message rides the tightbeam control lane as
//! `SEQUENCE { kind, body }`; the body is itself DER, interpreted per
//! kind. Sender attribution comes from the authenticated link, so no
//! identity travels in the message.

use der::asn1::OctetString;
use der::{Decode, Encode, Sequence};

use crate::codec::ProgramDigest;
use crate::error::CodecError;

/// Digest octet width: SHA3-256.
const DIGEST_LEN: usize = 32;

/// One control-lane message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlMessage {
	/// Consumer to party: the DER bytes of a program to execute.
	Submit {
		/// The program's canonical DER bytes.
		program: Vec<u8>,
	},
	/// Party to consumer: the digest the party derived, and whether it
	/// validated and will execute.
	Echo {
		/// SHA3-256 the party computed over the received bytes.
		digest: ProgramDigest,
		/// Whether the party accepted the program.
		accept: bool,
	},
	/// Party to party: shares opened for one `Reveal` instruction.
	Reveal {
		/// The reveal's program-order ordinal.
		ordinal: u32,
		/// Compressed arkworks serialization of the share values.
		payload: Vec<u8>,
	},
}

/// Wire kind octets. Stable: changing one breaks live meshes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Kind {
	Submit = 1,
	Echo = 2,
	Reveal = 3,
}

/// The uniform control envelope.
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
struct WireControl {
	/// The [`Kind`] octet.
	kind: u8,
	/// Kind-specific DER body.
	body: OctetString,
}

/// Echo body.
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
struct WireEcho {
	/// The digest octets.
	digest: OctetString,
	/// Acceptance flag.
	accept: bool,
}

/// Reveal body.
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
struct WireReveal {
	/// Program-order reveal ordinal.
	ordinal: u32,
	/// Compressed share values.
	payload: OctetString,
}

impl ControlMessage {
	/// Serialize to control-lane bytes.
	pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
		let (kind, body) = match self {
			Self::Submit { program } => (Kind::Submit, program.clone()),
			Self::Echo { digest, accept } => {
				let echo = WireEcho { digest: OctetString::new(digest.0.as_slice())?, accept: *accept };
				(Kind::Echo, echo.to_der()?)
			}
			Self::Reveal { ordinal, payload } => {
				let reveal = WireReveal { ordinal: *ordinal, payload: OctetString::new(payload.as_slice())? };
				(Kind::Reveal, reveal.to_der()?)
			}
		};

		let wire = WireControl { kind: kind as u8, body: OctetString::new(body)? };
		let bytes = wire.to_der()?;
		Ok(bytes)
	}

	/// Parse control-lane bytes.
	pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
		let wire = WireControl::from_der(bytes)?;
		let body = wire.body.as_bytes();

		match wire.kind {
			kind if kind == Kind::Submit as u8 => Ok(Self::Submit { program: body.to_vec() }),
			kind if kind == Kind::Echo as u8 => {
				let echo = WireEcho::from_der(body)?;
				let octets = echo.digest.as_bytes();
				let digest: [u8; DIGEST_LEN] = octets
					.try_into()
					.map_err(|_| CodecError::MalformedControlDigest { len: octets.len() })?;
				Ok(Self::Echo { digest: ProgramDigest(digest), accept: echo.accept })
			}
			kind if kind == Kind::Reveal as u8 => {
				let reveal = WireReveal::from_der(body)?;
				Ok(Self::Reveal { ordinal: reveal.ordinal, payload: reveal.payload.as_bytes().to_vec() })
			}
			kind => Err(CodecError::UnknownControlKind { kind }),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn submissions_round_trip() {
		let message = ControlMessage::Submit { program: b"program-der".to_vec() };
		let bytes = message.encode().expect("the submission encodes");
		let recovered = ControlMessage::decode(&bytes).expect("the bytes decode");
		assert_eq!(recovered, message);
	}

	#[test]
	fn echoes_round_trip_with_both_verdicts() {
		for accept in [true, false] {
			let message = ControlMessage::Echo { digest: ProgramDigest([9; 32]), accept };
			let bytes = message.encode().expect("the echo encodes");
			let recovered = ControlMessage::decode(&bytes).expect("the bytes decode");
			assert_eq!(recovered, message);
		}
	}

	#[test]
	fn reveals_round_trip() {
		let message = ControlMessage::Reveal { ordinal: 7, payload: vec![1, 2, 3] };
		let bytes = message.encode().expect("the reveal encodes");
		let recovered = ControlMessage::decode(&bytes).expect("the bytes decode");
		assert_eq!(recovered, message);
	}

	#[test]
	fn unknown_kinds_are_refused() {
		let wire = WireControl { kind: 200, body: OctetString::new(b"x".as_slice()).expect("the body wraps") };
		let bytes = wire.to_der().expect("the envelope encodes");
		let outcome = ControlMessage::decode(&bytes);
		assert!(matches!(outcome, Err(CodecError::UnknownControlKind { kind: 200 })));
	}

	#[test]
	fn short_digests_are_refused() {
		let echo = WireEcho {
			digest: OctetString::new(b"short".as_slice()).expect("the digest wraps"),
			accept: true,
		};
		let wire = WireControl {
			kind: Kind::Echo as u8,
			body: OctetString::new(echo.to_der().expect("the echo encodes")).expect("the body wraps"),
		};
		let bytes = wire.to_der().expect("the envelope encodes");
		let outcome = ControlMessage::decode(&bytes);
		assert!(matches!(outcome, Err(CodecError::MalformedControlDigest { len: 5 })));
	}
}
