//! Demo session-budget paywall for encrypted mux examples and e2e.
//!
//! A paywalled [`Security`](super::Security) installs [`DemoPaywall`] on each
//! accepted transport and advertises its ceiling. Clients pay its invoice
//! through [`FixedWallet`] (or a JS `approveReceipt`). The invoice, the
//! payment, and the ceiling are stack facts, which
//! [`DemoConfig::from_env`](super::DemoConfig::from_env) reads.

use core::sync::atomic::{AtomicUsize, Ordering};

use tightbeam::der::asn1::OctetString;
use tightbeam::marker::MaybeSendFuture;
use tightbeam::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, TransportAuthorizer, TransportOffer,
};
use tightbeam::transport::handshake::receipt::{ApprovalRefusal, ReceiptApprover, SessionReceipt};
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;

/// Application refusal when settlement payment does not match.
pub const DEMO_INVOICE_REFUSAL: u32 = 0x7462_7731;
/// Application refusal when [`FixedWallet`] has no remaining payments.
pub const DEMO_WALLET_EMPTY: u32 = 0x7462_7732;
/// Application refusal when a client requests no budgets.
const DEMO_BUDGETS_REQUIRED: u32 = 0x7462_7733;

/// Demo authorizer that invoices every session and renewal.
///
/// Grants the per-direction minimum of the client's request and this
/// paywall's ceiling. Upstream `authorize_transport` replaces the local
/// offer clamp with the authorizer verdict, so the ceiling MUST be applied
/// here or an oversized request would be granted.
///
/// The invoice rides in the session receipt, and only a session with budgets
/// has a receipt. A client that requests no budgets is refused, because
/// upstream aborts a challenge that has no budgets to carry it.
///
/// # Examples
///
/// ```
/// use tightbeam::transport::handshake::negotiation::MuxBudgets;
/// use tightbeam_ws::testing::DemoPaywall;
///
/// let ceiling = MuxBudgets { client_to_server: 600, server_to_client: 700 };
/// let paywall = DemoPaywall::new(b"invoice", b"payment", ceiling)?;
/// assert_eq!(paywall.ceiling(), ceiling);
/// # Ok::<(), tightbeam::TightBeamError>(())
/// ```
pub struct DemoPaywall {
	invoice: OctetString,
	expected_payment: OctetString,
	ceiling: MuxBudgets,
}

impl DemoPaywall {
	/// The paywall that challenges each session with `invoice`, settles on
	/// `payment`, and grants at most `ceiling` in each direction.
	///
	/// # Errors
	///
	/// - [`TightBeamError`]: the invoice or the payment does not encode as an
	///   octet string.
	pub fn new(
		invoice: impl AsRef<[u8]>,
		payment: impl AsRef<[u8]>,
		ceiling: MuxBudgets,
	) -> Result<Self, TightBeamError> {
		let invoice = OctetString::new(invoice.as_ref())?;
		let expected_payment = OctetString::new(payment.as_ref())?;
		Ok(Self { invoice, expected_payment, ceiling })
	}

	/// The per-direction budget ceiling that this paywall grants and that a
	/// metered offer advertises.
	#[must_use]
	pub fn ceiling(&self) -> MuxBudgets {
		self.ceiling
	}

	/// A wallet that pays the invoice of this paywall `payments` times.
	pub(super) fn wallet(&self, payments: usize) -> FixedWallet {
		let payment = self.expected_payment.clone();
		FixedWallet { payment, remaining: AtomicUsize::new(payments) }
	}
}

impl TransportAuthorizer for DemoPaywall {
	fn authorize<'a>(
		&'a self,
		offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
		Box::pin(async move {
			let Some(requested) = offer.requested_budgets else {
				return Err(AuthorizationRefusal { code: DEMO_BUDGETS_REQUIRED });
			};

			let budgets = requested.min(self.ceiling);
			let grant = AuthorizationGrant { budgets: Some(budgets), challenge: Some(self.invoice.to_owned()) };
			Ok(grant)
		})
	}

	fn challenge_renewal<'a>(
		&'a self,
		_prior: &'a SessionReceipt,
	) -> MaybeSendFuture<'a, Result<Option<OctetString>, AuthorizationRefusal>> {
		Box::pin(async move { Ok(Some(self.invoice.to_owned())) })
	}

	fn settle<'a>(
		&'a self,
		_receipt: &'a SessionReceipt,
		response: Option<&'a [u8]>,
		_client: &'a Certificate,
	) -> MaybeSendFuture<'a, Result<(), AuthorizationRefusal>> {
		Box::pin(async move {
			if response == Some(self.expected_payment.as_bytes()) {
				return Ok(());
			}

			Err(AuthorizationRefusal { code: DEMO_INVOICE_REFUSAL })
		})
	}
}

/// Pays the first `payments` invoices, then refuses with [`DEMO_WALLET_EMPTY`].
///
/// # Examples
///
/// ```
/// use tightbeam_ws::testing::FixedWallet;
///
/// let _approver = FixedWallet::new(b"payment", 2)?;
/// # Ok::<(), tightbeam::TightBeamError>(())
/// ```
pub struct FixedWallet {
	payment: OctetString,
	remaining: AtomicUsize,
}

impl FixedWallet {
	/// Wallet that answers `payments` invoices (handshake + renewals) with
	/// `payment`.
	///
	/// # Errors
	///
	/// - [`TightBeamError`]: the payment does not encode as an octet string.
	pub fn new(payment: impl AsRef<[u8]>, payments: usize) -> Result<Self, TightBeamError> {
		let payment = OctetString::new(payment.as_ref())?;
		Ok(Self { payment, remaining: AtomicUsize::new(payments) })
	}
}

impl ReceiptApprover for FixedWallet {
	fn approve<'a>(
		&'a self,
		_receipt: &'a SessionReceipt,
	) -> MaybeSendFuture<'a, Result<Option<OctetString>, ApprovalRefusal>> {
		Box::pin(async move {
			loop {
				let left = self.remaining.load(Ordering::SeqCst);
				if left == 0 {
					return Err(ApprovalRefusal { code: DEMO_WALLET_EMPTY });
				}
				if self
					.remaining
					.compare_exchange(left, left - 1, Ordering::SeqCst, Ordering::SeqCst)
					.is_ok()
				{
					return Ok(Some(self.payment.to_owned()));
				}
			}
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tightbeam::asn1::DigestInfo;
	use tightbeam::oids::HASH_SHA3_256;
	use tightbeam::spki::AlgorithmIdentifier;
	use tightbeam::testing::{TestCertificate, TestKey};
	use tightbeam::transport::handshake::negotiation::TransportOffer;

	/// A paywall that settles on `payment` under a 100 and 200 credit
	/// ceiling.
	fn paywall() -> DemoPaywall {
		let ceiling = MuxBudgets { client_to_server: 100, server_to_client: 200 };
		DemoPaywall::new(b"invoice", b"payment", ceiling).expect("the invoice and the payment encode")
	}

	#[tokio::test]
	async fn authorize_clamps_request_to_ceiling() -> Result<(), Box<dyn core::error::Error>> {
		let offer = TransportOffer::mux(8).with_budgets(MuxBudgets { client_to_server: 10_000, server_to_client: 50 });
		let grant = paywall().authorize(&offer).await;

		let budgets = Some(MuxBudgets { client_to_server: 100, server_to_client: 50 });
		let challenge = Some(OctetString::new(b"invoice")?);
		assert_eq!(grant, Ok(AuthorizationGrant { budgets, challenge }));
		Ok(())
	}

	#[tokio::test]
	async fn authorize_refuses_an_offer_without_budgets() {
		let offer = TransportOffer::mux(8);
		let verdict = paywall().authorize(&offer).await;
		assert_eq!(verdict, Err(AuthorizationRefusal { code: DEMO_BUDGETS_REQUIRED }));
	}

	#[tokio::test]
	async fn settle_accepts_only_demo_payment() {
		let paywall = paywall();
		let receipt = stub_receipt();
		let client = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());

		let paid = paywall.settle(&receipt, Some(b"payment"), &client).await;
		let refused = paywall.settle(&receipt, Some(b"wrong"), &client).await;
		assert_eq!(paid, Ok(()));
		assert_eq!(refused, Err(AuthorizationRefusal { code: DEMO_INVOICE_REFUSAL }));
	}

	fn stub_receipt() -> SessionReceipt {
		let algorithm = AlgorithmIdentifier { oid: HASH_SHA3_256, parameters: None };
		let digest = OctetString::new([0u8; 32]).expect("digest");
		SessionReceipt {
			transcript_hash: DigestInfo { algorithm, digest },
			budgets: MuxBudgets { client_to_server: 1, server_to_client: 1 },
			credit_unit: 1024,
			ancillary: None,
		}
	}
}
