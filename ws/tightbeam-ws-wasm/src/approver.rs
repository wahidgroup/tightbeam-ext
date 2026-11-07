//! JavaScript-backed receipt approver. Compiled only for `wasm32` targets.
//!
//! Pays settlement challenges at handshake and each in-band renewal by
//! calling into an async JS function. Without an approver, challenge-bearing
//! receipts fail closed upstream.

use std::sync::Arc;

use js_sys::{Function, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

use tightbeam::der::asn1::OctetString;
use tightbeam::der::Encode;
use tightbeam::marker::MaybeSendFuture;
use tightbeam::transport::handshake::negotiation::MuxBudgets;
use tightbeam::transport::handshake::receipt::{ApprovalRefusal, ReceiptApprover, SessionReceipt};

use crate::fault::{JsFault, RefusalCode};
use crate::promise::{JsBytes, Record, Returned, WholeNumber};

/// Application refusal when the JS approver rejects or returns a bad shape.
const APPROVER_REFUSAL: u32 = 0x7462_7761;

/// Upper bound on settlement answer octets from `approveReceipt`.
const MAX_SETTLEMENT_ANSWER: usize = 4096;

/// [`ReceiptApprover`] that forwards each receipt to a JavaScript callback.
pub struct JsReceiptApprover {
	callback: Function,
}

impl JsReceiptApprover {
	/// Wrap a JS function `(input) => Uint8Array | undefined | Promise<...>`.
	pub fn new(callback: Function) -> Self {
		Self { callback }
	}

	/// Erase to the trait object the handshake consumes.
	pub fn into_approver(self) -> Arc<dyn ReceiptApprover> {
		Arc::new(self)
	}
}

impl ReceiptApprover for JsReceiptApprover {
	fn approve<'a>(
		&'a self,
		receipt: &'a SessionReceipt,
	) -> MaybeSendFuture<'a, Result<Option<OctetString>, ApprovalRefusal>> {
		Box::pin(async move {
			let receipt_der = receipt.to_der().map_err(|_| ApprovalRefusal { code: APPROVER_REFUSAL })?;
			let input = js_sys::Object::new();
			Reflect::set(
				&input,
				&JsValue::from_str("receiptDer"),
				&Uint8Array::from(receipt_der.as_slice()),
			)
			.map_err(|_| ApprovalRefusal { code: APPROVER_REFUSAL })?;

			if let Some(challenge) = receipt.ancillary.as_ref() {
				Reflect::set(&input, &JsValue::from_str("challenge"), &Uint8Array::from(challenge.as_bytes()))
					.map_err(|_| ApprovalRefusal { code: APPROVER_REFUSAL })?;
			}

			let invoked = self
				.callback
				.call1(&JsValue::UNDEFINED, &input)
				.map(Returned::from)
				.map_err(|_| ApprovalRefusal { code: APPROVER_REFUSAL })?;

			let resolved = invoked.settle().await.map_err(|_| ApprovalRefusal { code: APPROVER_REFUSAL })?;
			let Some(resolved) = Record::present(resolved) else {
				return Ok(None);
			};

			let bytes = JsBytes::recognize(&resolved).ok_or(ApprovalRefusal { code: APPROVER_REFUSAL })?;
			if bytes.len() > MAX_SETTLEMENT_ANSWER {
				return Err(ApprovalRefusal { code: APPROVER_REFUSAL });
			}

			let answer = OctetString::new(bytes).map_err(|_| ApprovalRefusal { code: APPROVER_REFUSAL })?;
			Ok(Some(answer))
		})
	}
}

impl core::fmt::Debug for JsReceiptApprover {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("JsReceiptApprover").finish_non_exhaustive()
	}
}

impl TryFrom<&JsValue> for JsReceiptApprover {
	type Error = JsFault;

	/// Read an `approveReceipt` callback.
	///
	/// # Errors
	///
	/// - `InvalidApproveReceipt` -- `value` is not a function.
	fn try_from(value: &JsValue) -> Result<Self, Self::Error> {
		let function = value.dyn_ref::<Function>();
		let refusal = || {
			RefusalCode::InvalidApproveReceipt
				.because("must be a function")
				.at("approveReceipt")
		};

		let function = function.ok_or_else(refusal)?;
		Ok(Self::new(function.clone()))
	}
}

/// The session budgets a mutual-auth dial offers, as JavaScript hands them
/// over: `{ clientToServer, serverToClient }` in whole credits.
pub(crate) struct OfferedBudgets(pub(crate) MuxBudgets);

impl TryFrom<&JsValue> for OfferedBudgets {
	type Error = JsFault;

	/// Read the two budgets of the object `value`.
	///
	/// # Errors
	///
	/// - `InvalidBudgets` -- a budget is no whole, non-negative number.
	fn try_from(value: &JsValue) -> Result<Self, Self::Error> {
		let client = Record::member(value, "budgets.clientToServer");
		let server = Record::member(value, "budgets.serverToClient");
		let refusal = || RefusalCode::InvalidBudgets.because("budget credits must be non-negative integers");

		let client_to_server = WholeNumber::read(&client).ok_or_else(refusal)?;
		let server_to_client = WholeNumber::read(&server).ok_or_else(refusal)?;
		Ok(Self(MuxBudgets { client_to_server, server_to_client }))
	}
}

/// The authorization token a mutual-auth dial offers, as JavaScript hands it
/// over.
pub(crate) struct OfferedAuthorization(pub(crate) OctetString);

impl TryFrom<&JsValue> for OfferedAuthorization {
	type Error = JsFault;

	/// Read the token octets of `value`.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- `value` is not a `Uint8Array`.
	/// - `InvalidAuthorization` -- the octets do not fit an `OCTET STRING`.
	fn try_from(value: &JsValue) -> Result<Self, Self::Error> {
		let bytes = JsBytes::read_value(value, "options.authorization")?;
		let token = OctetString::new(bytes);

		let malformed = "options.authorization is not a valid OCTET STRING";
		let token = token.map_err(|_| RefusalCode::InvalidAuthorization.because(malformed))?;
		Ok(Self(token))
	}
}

#[cfg(test)]
mod tests {
	use js_sys::Function;
	use tightbeam::asn1::{AlgorithmIdentifierOwned, DigestInfo};
	use tightbeam::der::asn1::OctetString;
	use tightbeam::oids::HASH_SHA3_256;
	use tightbeam::transport::handshake::negotiation::MuxBudgets;
	use tightbeam::transport::handshake::receipt::{ApprovalRefusal, ReceiptApprover, SessionReceipt};
	use wasm_bindgen::JsValue;
	use wasm_bindgen_test::wasm_bindgen_test;

	use super::{JsReceiptApprover, OfferedAuthorization, APPROVER_REFUSAL};
	use crate::fault::Refused;

	/// A receipt over a fixed transcript that carries no settlement challenge.
	fn receipt() -> SessionReceipt {
		let algorithm = AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None };
		let digest = OctetString::new([0x07; 32]).expect("32 octets fit an OCTET STRING");

		let transcript_hash = DigestInfo { algorithm, digest };
		let budgets = MuxBudgets { client_to_server: 1, server_to_client: 1 };
		SessionReceipt { transcript_hash, budgets, credit_unit: 1024, ancillary: None }
	}

	#[wasm_bindgen_test]
	async fn a_number_from_the_approver_is_no_settlement_answer() {
		let approver = JsReceiptApprover::new(Function::new_no_args("return 7"));
		let receipt = receipt();

		let approved = approver.approve(&receipt).await;
		assert_eq!(approved, Err(ApprovalRefusal { code: APPROVER_REFUSAL }));
	}

	#[wasm_bindgen_test]
	fn a_number_is_no_authorization_token() {
		let number = JsValue::from_f64(7.0);
		let authorization = OfferedAuthorization::try_from(&number);
		assert_eq!(authorization.code().as_deref(), Some("InvalidBytes"));
	}
}
