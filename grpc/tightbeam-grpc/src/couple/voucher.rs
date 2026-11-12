//! The identities under which a coupler speaks for its callers, and what it
//! signs for them.

use core::fmt;
use std::sync::Arc;

use tightbeam::builder::TypeBuilder;
use tightbeam::clock::UnixMillis;
use tightbeam::colony::work::ClusterWorkRequest;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::der::Encode;
use tightbeam::urn::Urn;
use tightbeam::{Frame, Version};

use super::fault::CallFault;
use super::message::{CoupledCall, StreamTerms};
use super::stream::FramedPart;

/// The two identities of a coupler: the one its loopback session presents in
/// the tightbeam handshake of the edge, and the one that signs each call it
/// vouches for.
///
/// - The handshake identity carries the client role, which the edge
///   authenticates.
/// - The signer carries the signing purpose, which a servlet admits in its
///   vouchers.
/// - A clone shares the identities of the original.
#[derive(Clone)]
pub struct Voucher {
	identities: Arc<Identities>,
}

/// The two identities of a voucher.
pub struct Identities {
	/// The identity that the loopback session presents in the tightbeam
	/// handshake of the edge.
	pub handshake: SigningIdentity,
	/// The identity that signs each call that the voucher vouches for, and
	/// each request part of a stream of the coupler.
	pub signer: SigningIdentity,
}

impl Voucher {
	/// A voucher of `identities`.
	#[must_use]
	pub fn new(identities: Identities) -> Self {
		Self { identities: Arc::new(identities) }
	}

	/// The identity of the loopback session in the tightbeam handshake.
	pub(crate) fn handshake(&self) -> &SigningIdentity {
		&self.identities.handshake
	}

	/// The identity that signs each request part of a stream of the coupler.
	pub(crate) fn signer(&self) -> &SigningIdentity {
		&self.identities.signer
	}

	/// Sign `call` under the id `id` and the signer of the voucher.
	///
	/// # Errors
	///
	/// - [`CallFault::Internal`] -- the frame does not build or sign.
	pub(crate) async fn sign(&self, call: CoupledCall, id: RequestId) -> Result<Signed, CallFault> {
		let order = UnixMillis::now().get();
		let draft = Version::V1.compose().with_id(id.0).with_order(order).with_message(call);
		let mut frame: Frame = draft.build().map_err(|_| CallFault::Internal)?;
		let signed = frame.sign_with_provider(&self.identities.signer).await;
		signed.map_err(|_| CallFault::Internal)?;

		Ok(Signed { frame, id })
	}
}

impl fmt::Debug for Voucher {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Voucher").finish_non_exhaustive()
	}
}

/// The id of one call of a coupler, which every frame and part of the call
/// carries, and its answer answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RequestId([u8; 16]);

impl RequestId {
	pub(crate) fn new(id: [u8; 16]) -> Self {
		Self(id)
	}

	pub(crate) fn as_bytes(&self) -> &[u8; 16] {
		&self.0
	}
}

/// A coupled call that a voucher signed, and the id that it signed it under.
/// Only [`Voucher::sign`] builds one.
pub(crate) struct Signed {
	frame: Frame,
	id: RequestId,
}

impl Signed {
	/// The work request of the servlet type `servlet` that carries the call.
	///
	/// # Errors
	///
	/// - [`CallFault::Oversize`] -- the work request passes `ceiling`, the envelope ceiling of the edge.
	/// - [`CallFault::Internal`] -- the work request does not build or encode.
	pub(crate) fn into_work(self, servlet: &Urn<'static>, ceiling: usize) -> Result<WorkRequest, CallFault> {
		let work =
			ClusterWorkRequest::transport_frame(servlet.clone(), &self.frame).map_err(|_| CallFault::Internal)?;

		let size = work.encoded_len().map_err(|_| CallFault::Internal)?;
		if usize::try_from(size).map_or(true, |size| size > ceiling) {
			return Err(CallFault::Oversize);
		}

		Ok(WorkRequest { frame: work, id: self.id })
	}

	/// The call as the head of a stream under `terms`, which the call carries:
	/// its first part, within the part ceiling of the terms.
	///
	/// # Errors
	///
	/// - [`CallFault::Oversize`] -- the head passes the part ceiling.
	pub(crate) fn into_head(self, terms: StreamTerms) -> Result<HeadPart, CallFault> {
		let part = FramedPart::of(&self.frame, terms.ceiling()).ok_or(CallFault::Oversize)?;
		Ok(HeadPart { part, id: self.id, terms })
	}
}

/// What a unary call sends: the work request of its servlet, and the id of
/// the call that it carries.
pub(crate) struct WorkRequest {
	frame: Frame,
	id: RequestId,
}

impl WorkRequest {
	pub(crate) fn frame(&self) -> &Frame {
		&self.frame
	}

	/// The id of the call, which its answer answers.
	pub(crate) fn id(&self) -> &RequestId {
		&self.id
	}
}

/// What a stream sends first: its head as a part, the id of its call, and
/// the terms that the head declares.
pub(crate) struct HeadPart {
	part: FramedPart,
	id: RequestId,
	terms: StreamTerms,
}

impl HeadPart {
	pub(crate) fn as_bytes(&self) -> &[u8] {
		self.part.as_bytes()
	}

	/// The id of the call, which every later part carries.
	pub(crate) fn id(&self) -> &RequestId {
		&self.id
	}

	/// The terms that the head declares, which both ends keep to.
	pub(crate) fn terms(&self) -> &StreamTerms {
		&self.terms
	}
}
