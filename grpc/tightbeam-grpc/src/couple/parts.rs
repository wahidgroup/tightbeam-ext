//! The parts of a coupled stream as any peer writes and reads them, which
//! `testing` exports.

use tightbeam::builder::TypeBuilder;
use tightbeam::clock::UnixMillis;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::der::asn1::OctetString;
use tightbeam::policy::TransitStatus;
use tightbeam::transport::TransportError;
use tightbeam::{Frame, TightBeamError, Version};
use tonic::Status;

use super::message::{CoupledCall, CoupledPart, CoupledReply, PartWire, StreamTerms};
use super::method::MethodPath;
use super::routes::StreamShape;
use super::stream::{FramedPart, PartBuffer, PartFault};

/// The refusal of a part that does not frame or does not decode.
fn malformed() -> TightBeamError {
	TransportError::from(TransitStatus::InvalidArgument).into()
}

/// The parts of one side of a coupled stream: each frame signed under the
/// identity that the peer picks, under the id of the stream, and in order
/// from 1, behind its 4-byte big-endian length.
pub struct StreamParts {
	id: Vec<u8>,
	signer: SigningIdentity,
	next: u64,
	ceiling: usize,
}

/// The identities that sign a stream that a direct caller opens: the one of
/// its head, and the one of each part after it.
#[derive(Clone, Copy)]
pub struct StreamSigners<'a> {
	/// The identity that signs the head.
	pub head: &'a SigningIdentity,
	/// The identity that signs each part after the head.
	pub parts: &'a SigningIdentity,
}

/// A stream that a direct caller opens: its framed head, and the parts after
/// it.
pub struct OpenedStream {
	/// The framed bytes of the head.
	pub head: Vec<u8>,
	/// The parts after the head.
	pub parts: StreamParts,
}

impl StreamParts {
	/// The framed head of a bidirectional stream of `method` that a direct
	/// caller opens under the id `id`, which declares `part_ceiling`, and the
	/// parts after it, each signed as `signers` names.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a head that does not build, sign, encode, or fit `part_ceiling`.
	pub async fn open(
		method: &str,
		id: &[u8],
		part_ceiling: u64,
		signers: StreamSigners<'_>,
	) -> Result<OpenedStream, TightBeamError> {
		let terms = StreamTerms::new(StreamShape::Bidi, part_ceiling);
		let method = MethodPath::try_from(method).map_err(|_| malformed())?;
		let call = CoupledCall::head(&method, terms).map_err(|_| malformed())?;
		let draft = Version::V1.compose().with_id(id).with_order(UnixMillis::now().get());
		let mut frame = draft.with_message(call).build()?;
		frame.sign_with_provider(signers.head).await?;

		let ceiling = terms.ceiling();
		let framed = FramedPart::of(&frame, ceiling).ok_or_else(malformed)?;
		let parts = Self::after(&frame, signers.parts.clone(), ceiling);
		Ok(OpenedStream { head: framed.as_bytes().to_vec(), parts })
	}

	/// The parts after `head`, under its id, each signed under `signer`,
	/// within `ceiling`.
	pub fn after(head: &Frame, signer: SigningIdentity, ceiling: usize) -> Self {
		Self { id: head.metadata().id().to_vec(), signer, next: 1, ceiling }
	}

	/// The framed bytes of the next part, a message of `body`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a part that does not build, sign, encode, or fit the ceiling.
	pub async fn message(&mut self, body: &[u8]) -> Result<Vec<u8>, TightBeamError> {
		let message = OctetString::new(body.to_vec())?;
		self.part(PartWire::Message(message)).await
	}

	/// The framed bytes of the next part, the end of an answer with `status`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a part that does not build, sign, encode, or fit the ceiling.
	pub async fn end(&mut self, status: &Status) -> Result<Vec<u8>, TightBeamError> {
		let end = CoupledReply::of_status(status, Vec::new())?;
		self.part(PartWire::End(end)).await
	}

	/// The framed bytes of `part` at the next order.
	async fn part(&mut self, part: PartWire) -> Result<Vec<u8>, TightBeamError> {
		let frame = CoupledPart::signed(&self.id, self.next, part, &self.signer).await?;
		let framed = FramedPart::of(&frame, self.ceiling).ok_or_else(malformed)?;
		self.next += 1;
		Ok(framed.as_bytes().to_vec())
	}

	/// The message that `part` carries, or `None` for the end of an answer.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a frame that holds no part of a stream.
	pub fn message_of(part: &Frame) -> Result<Option<Vec<u8>>, TightBeamError> {
		let part: CoupledPart = part.decode_message()?;
		Ok(part.part.carried().ok().map(OctetString::into_bytes))
	}
}

/// The parts of a stream as they arrive, in chunks of any size, as any peer
/// reads them.
pub struct PartFrames {
	buffer: PartBuffer,
}

impl PartFrames {
	/// A reader of parts of at most `ceiling` bytes.
	pub fn new(ceiling: usize) -> Self {
		Self { buffer: PartBuffer::new(ceiling) }
	}

	/// Take `chunk`, the next bytes of the stream.
	pub fn extend(&mut self, chunk: &[u8]) {
		self.buffer.extend(chunk);
	}

	/// The frame of the next whole part, once all of it came.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a part past the ceiling, or whose frame does not decode.
	pub fn next_frame(&mut self) -> Result<Option<Frame>, TightBeamError> {
		self.buffer.split().map_err(PartFault::of_request)
	}
}

#[cfg(test)]
mod tests {
	use core::time::Duration;

	use tightbeam_ws::testing::Identity;

	use super::*;

	/// The part ceiling that the stream of these tests declares.
	const CEILING: usize = 2048;

	#[tokio::test]
	async fn a_part_after_one_past_the_ceiling_takes_the_first_order() -> Result<(), TightBeamError> {
		let signer = Identity::mint("CN=parts", 1, Duration::from_secs(60))?.signing_identity();
		let signers = StreamSigners { head: &signer, parts: &signer };
		let declared = u64::try_from(CEILING).expect("the ceiling fits a u64");
		let opened = StreamParts::open("/orders.v1.Orders/Chat", b"stream", declared, signers).await?;
		let OpenedStream { mut parts, .. } = opened;

		let past = parts.message(&[7; CEILING]).await;
		assert!(past.is_err(), "a part past the ceiling MUST refuse");

		let mut frames = PartFrames::new(CEILING);
		frames.extend(&parts.message(b"next").await?);
		let order = frames.next_frame()?.map(|frame| frame.metadata().order());
		assert_eq!(order, Some(1), "the part after a refused one MUST take the first order");
		Ok(())
	}
}
