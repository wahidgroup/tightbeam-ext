//! Demo session-budget paywall for encrypted mux examples and e2e.
//!
//! Env-gated: when [`paywall_enabled`] is true, servers install
//! [`DemoPaywall`] and advertise a budget ceiling. Clients pay the
//! fixed invoice through [`FixedWallet`] (or a JS `approveReceipt`).

use core::sync::atomic::{AtomicUsize, Ordering};
use std::env;
use std::sync::Arc;

use tightbeam::der::asn1::OctetString;
use tightbeam::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, TransportAuthorizer, TransportOffer,
};
use tightbeam::transport::handshake::receipt::{ApprovalRefusal, ReceiptApprover, SessionReceipt};
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::TightBeamError;

/// Invoice bytes embedded in every grant and renewal challenge.
pub const DEMO_INVOICE: &[u8] = b"tbws-demo-invoice-v1";
/// Payment bytes [`FixedWallet`] and e2e clients return for a paid invoice.
pub const DEMO_PAYMENT: &[u8] = b"tbws-demo-payment-v1";
/// Application refusal when settlement payment does not match.
pub const DEMO_INVOICE_REFUSAL: u32 = 0x7462_7731;
/// Application refusal when [`FixedWallet`] has no remaining payments.
pub const DEMO_WALLET_EMPTY: u32 = 0x7462_7732;

/// True when `TBWS_PAYWALL=1` (or any non-empty value other than `0`/`false`).
pub fn paywall_enabled() -> bool {
	match env::var("TBWS_PAYWALL") {
		Ok(value) => {
			let trimmed = value.trim();
			trimmed != "0" && !trimmed.eq_ignore_ascii_case("false") && !trimmed.is_empty()
		}
		Err(_) => false,
	}
}

/// Default per-direction grant for the demo paywall.
///
/// Must clear the mux drain reserve
/// (`2 * (local_cap + peer_cap) + 1` records × `ceil(chunk / credit_unit)`
/// credits). With the default 8/8 caps, 16 KiB chunks, and 1 KiB credit
/// unit that reserve is 528 credits. A grant of 64 leaves zero usable budget.
pub const DEMO_BUDGET_CREDITS: u64 = 4096;

/// Per-direction budget ceiling from `TBWS_MUX_BUDGET_C2S` /
/// `TBWS_MUX_BUDGET_S2C` (defaults: [`DEMO_BUDGET_CREDITS`]).
pub fn budget_ceiling() -> MuxBudgets {
	MuxBudgets {
		client_to_server: env_u64("TBWS_MUX_BUDGET_C2S", DEMO_BUDGET_CREDITS),
		server_to_client: env_u64("TBWS_MUX_BUDGET_S2C", DEMO_BUDGET_CREDITS),
	}
}

fn env_u64(name: &str, default: u64) -> u64 {
	env::var(name)
		.ok()
		.and_then(|value| value.parse::<u64>().ok())
		.unwrap_or(default)
}

/// Demo authorizer that invoices every session and renewal.
///
/// Grants the per-direction minimum of the client's request and this
/// paywall's ceiling. Upstream `authorize_transport` replaces the local
/// offer clamp with the authorizer verdict, so the ceiling MUST be applied
/// here or an oversized request would be granted.
pub struct DemoPaywall {
	invoice: OctetString,
	expected_payment: OctetString,
	ceiling: MuxBudgets,
}

impl DemoPaywall {
	/// Build the demo authorizer with the fixed invoice/payment pair and
	/// the env-derived [`budget_ceiling`].
	pub fn open() -> Result<Self, TightBeamError> {
		let invoice = OctetString::new(DEMO_INVOICE)?;
		let expected_payment = OctetString::new(DEMO_PAYMENT)?;
		let ceiling = budget_ceiling();
		Ok(Self { invoice, expected_payment, ceiling })
	}

	/// Shared authorizer for server transport configuration.
	pub fn shared() -> Result<Arc<dyn TransportAuthorizer>, TightBeamError> {
		let paywall = Self::open()?;
		Ok(Arc::new(paywall))
	}
}

impl TransportAuthorizer for DemoPaywall {
	fn authorize<'a>(
		&'a self,
		offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
		Box::pin(async move {
			let budgets = offer.requested_budgets.map(|requested| requested.min(self.ceiling));
			let grant = AuthorizationGrant { budgets, challenge: Some(self.invoice.to_owned()) };
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
pub struct FixedWallet {
	payment: OctetString,
	remaining: AtomicUsize,
}

impl FixedWallet {
	/// Wallet that can settle `payments` invoices (handshake + renewals).
	pub fn with_payments(payments: usize) -> Result<Self, TightBeamError> {
		let payment = OctetString::new(DEMO_PAYMENT)?;
		Ok(Self { payment, remaining: AtomicUsize::new(payments) })
	}

	/// Shared approver for client transport configuration.
	pub fn shared(payments: usize) -> Result<Arc<dyn ReceiptApprover>, TightBeamError> {
		let wallet = Self::with_payments(payments)?;
		Ok(Arc::new(wallet))
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
	use tightbeam::transport::handshake::negotiation::TransportOffer;

	#[tokio::test]
	async fn authorize_clamps_request_to_ceiling() {
		let paywall = DemoPaywall {
			invoice: OctetString::new(DEMO_INVOICE).expect("invoice"),
			expected_payment: OctetString::new(DEMO_PAYMENT).expect("payment"),
			ceiling: MuxBudgets { client_to_server: 100, server_to_client: 200 },
		};
		let offer = TransportOffer::mux(8).with_budgets(MuxBudgets { client_to_server: 10_000, server_to_client: 50 });

		let grant = paywall.authorize(&offer).await.expect("grant");
		assert_eq!(grant.budgets, Some(MuxBudgets { client_to_server: 100, server_to_client: 50 }));
	}

	#[tokio::test]
	async fn settle_accepts_only_demo_payment() {
		let paywall = DemoPaywall::open().expect("paywall");
		let receipt = stub_receipt();
		paywall.settle(&receipt, Some(DEMO_PAYMENT)).await.expect("paid");
		let refused = paywall.settle(&receipt, Some(b"wrong")).await;
		assert!(matches!(refused, Err(AuthorizationRefusal { code: DEMO_INVOICE_REFUSAL })));
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
