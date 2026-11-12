//! The JavaScript approver of session receipts and the session knobs of a
//! mutual dial, as the parse-once section of `docs/ws-wasm.md` describes.

use std::sync::Arc;

use js_sys::{Function, Uint8Array};
use wasm_bindgen::prelude::*;

use tightbeam::der::asn1::OctetString;
use tightbeam::der::Encode;
use tightbeam::marker::MaybeSendFuture;
use tightbeam::transport::handshake::negotiation::MuxBudgets;
use tightbeam::transport::handshake::receipt::{ApprovalRefusal, ReceiptApprover, SessionReceipt};

use crate::fault::{JsFault, RefusalCode};
use crate::promise::{Callback, JsBytes, Record, Returned, WholeNumber};

/// Application refusal when the JS approver rejects or returns a bad shape.
const REFUSED: ApprovalRefusal = ApprovalRefusal { code: 0x7462_7761 };

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
			let receipt_der = receipt.to_der().map_err(|_| REFUSED)?;
			let challenge = receipt.ancillary.as_ref().map(OctetString::as_bytes);
			let input = Record::new();
			input.set_bytes("receiptDer", &receipt_der);
			input.set_present("challenge", challenge.map(Uint8Array::from));

			let invoked = self.callback.call1(&JsValue::UNDEFINED, &input.into());
			let invoked = invoked.map(Returned::from).map_err(|_| REFUSED)?;

			let resolved = invoked.settle().await.map_err(|_| REFUSED)?;
			let Some(resolved) = Record::present(resolved) else {
				return Ok(None);
			};

			let bytes = JsBytes::recognize(&resolved).ok_or(REFUSED)?;
			if bytes.len() > MAX_SETTLEMENT_ANSWER {
				return Err(REFUSED);
			}

			let answer = OctetString::new(bytes).map_err(|_| REFUSED)?;
			Ok(Some(answer))
		})
	}
}

impl core::fmt::Debug for JsReceiptApprover {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("JsReceiptApprover").finish_non_exhaustive()
	}
}

impl JsReceiptApprover {
	/// The approver that the callback at `value`, the field at `path`, backs.
	///
	/// # Errors
	///
	/// - `InvalidCallback` -- `value` is not a function.
	pub(crate) fn read(value: &JsValue, path: &str) -> Result<Self, JsFault> {
		let callback = Callback::read(value, path)?;
		Ok(Self::new(callback))
	}
}

/// The session budgets a mutual-auth dial offers, as JavaScript hands them
/// over: `{ clientToServer, serverToClient }` in whole credits.
pub(crate) struct OfferedBudgets(pub(crate) MuxBudgets);

impl OfferedBudgets {
	/// Read the two budgets of the object `value`, the field at `path`.
	///
	/// # Errors
	///
	/// - `InvalidBudgets` -- a budget is no whole, non-negative number.
	pub(crate) fn read(value: &JsValue, path: &str) -> Result<Self, JsFault> {
		let client = Record::member(value, "clientToServer");
		let server = Record::member(value, "serverToClient");
		let refusal = || {
			RefusalCode::InvalidBudgets
				.because("budget credits must be non-negative integers")
				.at(path)
		};

		let client_to_server = WholeNumber::read(&client).ok_or_else(refusal)?;
		let server_to_client = WholeNumber::read(&server).ok_or_else(refusal)?;
		Ok(Self(MuxBudgets { client_to_server, server_to_client }))
	}
}

/// The authorization token a mutual-auth dial offers, as JavaScript hands it
/// over.
pub(crate) struct OfferedAuthorization(pub(crate) OctetString);

impl OfferedAuthorization {
	/// Read the token octets of `value`, the field at `path`.
	///
	/// # Errors
	///
	/// - `InvalidBytes` -- `value` is not a `Uint8Array`.
	/// - `InvalidAuthorization` -- the octets do not fit an `OCTET STRING`.
	pub(crate) fn read(value: &JsValue, path: &str) -> Result<Self, JsFault> {
		let bytes = JsBytes::read_value(value, path)?;
		let token = OctetString::new(bytes);

		let refusal = |_| RefusalCode::InvalidAuthorization.because("must fit an OCTET STRING").at(path);
		let token = token.map_err(refusal)?;
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
	use tightbeam::transport::handshake::receipt::{ReceiptApprover, SessionReceipt};
	use wasm_bindgen::JsValue;
	use wasm_bindgen_test::wasm_bindgen_test;

	use super::{JsReceiptApprover, OfferedAuthorization, REFUSED};
	use crate::fault::Refused;
	use crate::loopback::settled;

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

		let approved = settled(approver.approve(&receipt)).await;
		assert_eq!(approved, Err(REFUSED));
	}

	#[wasm_bindgen_test]
	fn a_number_is_no_authorization_token() {
		let number = JsValue::from_f64(7.0);
		let authorization = OfferedAuthorization::read(&number, "options.authorization");
		assert_eq!(authorization.code().as_deref(), Some("InvalidBytes"));
	}
}
