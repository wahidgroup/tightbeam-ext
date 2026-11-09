//! The identities under which a coupler speaks for its callers.

use core::fmt;
use std::sync::Arc;

use tightbeam::builder::TypeBuilder;
use tightbeam::clock::UnixMillis;
use tightbeam::colony::work::ClusterWorkRequest;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::der::asn1::OctetString;
use tightbeam::der::Encode;
use tightbeam::{Frame, Version};

use super::fault::CallFault;
use super::message::{CoupledCall, VouchedOrigin};
use super::saga::{Permitted, VouchedWork};

/// The two identities of a coupler: the one its loopback session presents in
/// the tightbeam handshake of the edge, and the one that signs each call it
/// vouches for.
///
/// Each certificate carries one purpose: the handshake identity the client
/// role that the edge authenticates, and the signer the signing purpose that
/// a servlet admits in its vouchers.
///
/// A clone shares the identities of the original.
#[derive(Clone)]
pub struct Voucher {
	identities: Arc<Identities>,
}

/// The two identities of a voucher.
struct Identities {
	handshake: SigningIdentity,
	signer: SigningIdentity,
}

impl Voucher {
	/// A voucher that opens its session under `handshake` and signs its work
	/// under `signer`.
	#[must_use]
	pub fn new(handshake: SigningIdentity, signer: SigningIdentity) -> Self {
		Self { identities: Arc::new(Identities { handshake, signer }) }
	}

	/// The identity of the loopback session in the tightbeam handshake.
	pub(crate) fn handshake(&self) -> &SigningIdentity {
		&self.identities.handshake
	}

	/// Vouch for the permitted call: the frame of its [`CoupledCall`] under
	/// the id `request_id`, signed under the signer of the voucher, in the
	/// work request of its servlet.
	///
	/// # Errors
	///
	/// - [`CallFault::Oversize`] -- the work request passes `ceiling`, the envelope ceiling of the edge.
	/// - [`CallFault::Internal`] -- the frame does not build, sign, or encode.
	pub(crate) async fn vouch(
		&self,
		permitted: Permitted,
		request_id: [u8; 16],
		ceiling: usize,
	) -> Result<VouchedWork, CallFault> {
		let internal = |_| CallFault::Internal;
		let claim = permitted
			.claim()
			.map(|claim| OctetString::new(claim.forwarded().to_vec()))
			.transpose()
			.map_err(internal)?;

		let principal = permitted.principal().into();
		let vouched = Some(VouchedOrigin { principal, claim });
		let body = OctetString::new(permitted.body().to_vec()).map_err(internal)?;
		let call = CoupledCall { method: permitted.method().to_owned(), vouched, body };

		let order = UnixMillis::now().get();
		let draft = Version::V1.compose().with_id(request_id).with_order(order).with_message(call);
		let mut frame: Frame = draft.build().map_err(|_| CallFault::Internal)?;
		frame
			.sign_with_provider(&self.identities.signer)
			.await
			.map_err(|_| CallFault::Internal)?;

		let servlet = permitted.servlet().clone();
		let work = ClusterWorkRequest::transport_frame(servlet, &frame).map_err(|_| CallFault::Internal)?;
		let size = work.encoded_len().map_err(internal)?;
		if usize::try_from(size).map_or(true, |size| size > ceiling) {
			return Err(CallFault::Oversize);
		}

		Ok(permitted.vouched(work, request_id))
	}
}

impl fmt::Debug for Voucher {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Voucher").finish_non_exhaustive()
	}
}
