//! JavaScript-backed receipt approver. Compiled only for `wasm32` targets.
//!
//! Pays settlement challenges at handshake and each in-band renewal by
//! calling into an async JS function. Without an approver, challenge-bearing
//! receipts fail closed upstream.

use std::sync::Arc;

use js_sys::{Function, Promise, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use tightbeam::der::asn1::OctetString;
use tightbeam::der::Encode;
use tightbeam::transport::handshake::negotiation::MuxBudgets;
use tightbeam::transport::handshake::receipt::{ApprovalRefusal, ReceiptApprover, SessionReceipt};
use tightbeam::utils::marker::MaybeSendFuture;

use crate::fault::validation;

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
				.map_err(|_| ApprovalRefusal { code: APPROVER_REFUSAL })?;

			let resolved = if invoked.has_type::<Promise>() {
				let promise: Promise = invoked.unchecked_into();
				JsFuture::from(promise)
					.await
					.map_err(|_| ApprovalRefusal { code: APPROVER_REFUSAL })?
			} else {
				invoked
			};

			if resolved.is_undefined() || resolved.is_null() {
				return Ok(None);
			}

			let bytes = Uint8Array::new(&resolved).to_vec();
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

/// Parse an optional JS approveReceipt function.
pub fn approver_from_js(value: &JsValue) -> Result<Option<Arc<dyn ReceiptApprover>>, JsValue> {
	if value.is_undefined() || value.is_null() {
		return Ok(None);
	}

	let function = value
		.dyn_ref::<Function>()
		.ok_or_else(|| validation("InvalidApproveReceipt", "approveReceipt must be a function"))?;
	let approver = JsReceiptApprover::new(function.clone()).into_approver();
	Ok(Some(approver))
}

/// Parse optional budget pair `{ clientToServer, serverToClient }`.
pub fn budgets_from_js(value: &JsValue) -> Result<Option<MuxBudgets>, JsValue> {
	if value.is_undefined() || value.is_null() {
		return Ok(None);
	}

	let client = Reflect::get(value, &JsValue::from_str("clientToServer"))?
		.as_f64()
		.ok_or_else(|| validation("InvalidBudgets", "budgets.clientToServer must be a number"))?;
	let server = Reflect::get(value, &JsValue::from_str("serverToClient"))?
		.as_f64()
		.ok_or_else(|| validation("InvalidBudgets", "budgets.serverToClient must be a number"))?;

	if client.fract() != 0.0 || server.fract() != 0.0 || client < 0.0 || server < 0.0 {
		return Err(validation("InvalidBudgets", "budget credits must be non-negative integers"));
	}

	Ok(Some(MuxBudgets {
		client_to_server: client as u64,
		server_to_client: server as u64,
	}))
}

/// Parse optional authorization token bytes.
pub fn authorization_from_js(value: &JsValue) -> Result<Option<OctetString>, JsValue> {
	if value.is_undefined() || value.is_null() {
		return Ok(None);
	}

	let bytes = Uint8Array::new(value).to_vec();
	let token = OctetString::new(bytes)
		.map_err(|_| validation("InvalidAuthorization", "authorization token is not a valid OCTET STRING"))?;
	Ok(Some(token))
}
