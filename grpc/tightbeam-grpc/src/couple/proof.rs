//! What a coupled call proves about its caller, which decides its assurance.

use super::claim::{ForwardedClaim, ReplayGuard, SpentClaim, VerifiedClaim};
use super::fault::CallFault;
use super::routes::Assurance;
use crate::deadline::Deadline;

/// What a coupled call proves about its caller. `C` is what a signed call
/// carries: the verified claim at the edge, and the forwarded claim of a
/// vouched call, or none for a direct caller, at the servlet.
#[derive(Debug)]
pub(crate) enum Proof<C> {
	/// A bearer token, which anyone who holds it can present.
	Bearer,
	/// A TLS client chain, its own or one that a pinned proxy forwards.
	Vouched,
	/// A signature of the caller itself: its claim, or its direct call.
	Signed(C),
}

impl<C> Proof<C> {
	/// How much the call proves.
	pub(crate) fn assurance(&self) -> Assurance {
		match self {
			Self::Bearer => Assurance::Bearer,
			Self::Vouched => Assurance::Vouched,
			Self::Signed(_) => Assurance::Signed,
		}
	}
}

impl Proof<VerifiedClaim> {
	/// Spend the claim of a signed call under `guard` by `deadline`, the
	/// deadline of the call. A call with no claim spends nothing.
	///
	/// # Errors
	///
	/// - The errors of [`VerifiedClaim::spend`].
	pub(crate) async fn spend(
		&self,
		guard: &ReplayGuard,
		deadline: &Deadline,
	) -> Result<Option<SpentClaim>, CallFault> {
		match self {
			Self::Signed(claim) => claim.spend(guard, deadline).await.map(Some),
			Self::Bearer | Self::Vouched => Ok(None),
		}
	}
}

impl Proof<Option<ForwardedClaim>> {
	/// The DER of the claim that a vouched call forwards, which a backend
	/// forwards on.
	pub(crate) fn forwarded(&self) -> Option<&[u8]> {
		match self {
			Self::Signed(Some(claim)) => Some(claim.forwarded()),
			Self::Signed(None) | Self::Bearer | Self::Vouched => None,
		}
	}
}
