//! The demo session-budget paywall of the e2e stack, as `docs/ws.md` (Test
//! support) states it.

use core::sync::atomic::{AtomicUsize, Ordering};

use tightbeam::der::asn1::OctetString;
use tightbeam::marker::MaybeSendFuture;
use tightbeam::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, TransportAuthorizer, TransportOffer,
};
use tightbeam::transport::handshake::receipt::{ApprovalRefusal, ReceiptApprover, SessionReceipt};
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;

/// The application refusal code of a payment that does not settle the
/// invoice.
const DEMO_INVOICE_REFUSAL: u32 = 0x7462_7731;

/// The application refusal code of a [`FixedWallet`] with no payment left.
const DEMO_WALLET_EMPTY: u32 = 0x7462_7732;

/// The application refusal code of a client that requests no budgets.
const DEMO_BUDGETS_REQUIRED: u32 = 0x7462_7733;

/// The demo authorizer, which invoices every session and renewal.
///
/// - It grants the smaller of the request and the ceiling in each direction, because upstream
///   `authorize_transport` takes the verdict of the authorizer in place of the offer clamp.
/// - The session receipt carries the invoice, and only a session with budgets has a receipt, so the
///   paywall refuses a client that requests no budgets.
///
/// # Examples
///
/// ```
/// use tightbeam::transport::handshake::negotiation::MuxBudgets;
/// use tightbeam_ws::testing::{DemoPaywall, DemoSettlement};
///
/// let settlement = DemoSettlement { invoice: b"invoice", payment: b"payment" };
/// let ceiling = MuxBudgets { client_to_server: 600, server_to_client: 700 };
/// let paywall = DemoPaywall::new(settlement, ceiling)?;
/// assert_eq!(paywall.ceiling(), ceiling);
/// # Ok::<(), tightbeam::TightBeamError>(())
/// ```
pub struct DemoPaywall {
	invoice: OctetString,
	expected_payment: OctetString,
	ceiling: MuxBudgets,
}

/// The invoice that a [`DemoPaywall`] challenges each session with, and the
/// payment that settles it.
pub struct DemoSettlement<'a> {
	/// The invoice of each session and renewal.
	pub invoice: &'a [u8],
	/// The payment that settles the invoice.
	pub payment: &'a [u8],
}

impl DemoPaywall {
	/// The paywall that challenges each session with the invoice of
	/// `settlement`, settles on its payment, and grants at most `ceiling` in
	/// each direction.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of an invoice or a payment that does not encode as an octet string.
	pub fn new(settlement: DemoSettlement<'_>, ceiling: MuxBudgets) -> Result<Self, TightBeamError> {
		let DemoSettlement { invoice, payment } = settlement;
		let invoice = OctetString::new(invoice)?;
		let expected_payment = OctetString::new(payment)?;
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

/// Pays the first `payments` invoices, at the handshake and at each renewal,
/// then refuses with the application code `DEMO_WALLET_EMPTY`.
///
/// The paywalled kind of [`Security`](super::Security) creates the wallet of
/// each dial from its [`DemoPaywall`].
pub(crate) struct FixedWallet {
	payment: OctetString,
	remaining: AtomicUsize,
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
		let settlement = DemoSettlement { invoice: b"invoice", payment: b"payment" };
		let ceiling = MuxBudgets { client_to_server: 100, server_to_client: 200 };
		DemoPaywall::new(settlement, ceiling).expect("the invoice and the payment encode")
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
		let receipt = receipt();
		let client = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());

		let paid = paywall.settle(&receipt, Some(b"payment"), &client).await;
		let refused = paywall.settle(&receipt, Some(b"wrong"), &client).await;
		assert_eq!(paid, Ok(()));
		assert_eq!(refused, Err(AuthorizationRefusal { code: DEMO_INVOICE_REFUSAL }));
	}

	/// A session receipt of one credit in each direction.
	fn receipt() -> SessionReceipt {
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
