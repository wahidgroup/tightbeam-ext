//! The labels JavaScript reads a GoAway reason by, and the parse of the
//! reason JavaScript hands over.

use wasm_bindgen::prelude::*;

use tightbeam::transport::envelopes::GoAwayReason;

#[cfg(target_arch = "wasm32")]
use crate::fault::{JsFault, RefusalCode};
#[cfg(target_arch = "wasm32")]
use crate::promise::WholeNumber;

/// Reason carried by the peer's GoAway (RFC 9113 § 6.8 analog), by the label
/// tightbeam writes for it.
///
/// `"application"` is a code outside the protocol-reserved range. Read the
/// raw value from `goawayCode`.
///
/// # Sources
///
/// - RFC 9113 § 6.8, GOAWAY frame:
///   <https://datatracker.ietf.org/doc/html/rfc9113#section-6.8>
#[wasm_bindgen(js_name = GoAwayReason)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoAwayLabel {
	/// The sender initiated an orderly shutdown.
	Shutdown = "shutdown",
	/// The peer violated the multiplexing protocol.
	ProtocolError = "protocol-error",
	/// The peer exceeded the cancel budget.
	EnhanceYourCalm = "enhance-your-calm",
	/// The session budget is spent down to the drain headroom.
	BudgetExhausted = "budget-exhausted",
	/// The settlement or the approval of a renewed receipt was refused.
	SettlementFailed = "settlement-failed",
	/// An application-defined code.
	Application = "application",
}

/// The label of each reason. The match covers every reason tightbeam
/// defines, so a new reason fails to compile here until it has a label.
impl From<GoAwayReason> for GoAwayLabel {
	fn from(reason: GoAwayReason) -> Self {
		match reason {
			GoAwayReason::Shutdown => Self::Shutdown,
			GoAwayReason::ProtocolError => Self::ProtocolError,
			GoAwayReason::EnhanceYourCalm => Self::EnhanceYourCalm,
			GoAwayReason::BudgetExhausted => Self::BudgetExhausted,
			GoAwayReason::SettlementFailed => Self::SettlementFailed,
			GoAwayReason::Application(_) => Self::Application,
		}
	}
}

#[cfg(target_arch = "wasm32")]
impl GoAwayLabel {
	/// Parse a JavaScript GoAway reason: a label for the reserved variants,
	/// or a numeric code (application-defined outside the reserved range).
	///
	/// # Errors
	///
	/// - `InvalidGoAwayReason` -- `value` is a number outside the u32 codes.
	/// - `InvalidGoAwayReason` -- `value` is a label that names no reserved variant, such as
	///   `"application"`.
	pub(crate) fn shutdown_reason(value: &JsValue) -> Result<GoAwayReason, JsFault> {
		if let Some(number) = value.as_f64() {
			let code: Option<u32> = WholeNumber::of(number);
			let refusal = || RefusalCode::InvalidGoAwayReason.because("a numeric GoAway reason must be a u32 code");
			return code.map(GoAwayReason::from).ok_or_else(refusal);
		}

		let reason = value.as_string().and_then(|label| label.parse().ok());
		let message = "a GoAway reason is a reserved GoAwayReason label or a numeric code";
		reason.ok_or_else(|| RefusalCode::InvalidGoAwayReason.because(message))
	}
}

#[cfg(test)]
mod tests {
	use tightbeam::tb_cases;
	use tightbeam::transport::envelopes::GoAwayReason;
	#[cfg(target_arch = "wasm32")]
	use wasm_bindgen::JsValue;
	#[cfg(target_arch = "wasm32")]
	use wasm_bindgen_test::wasm_bindgen_test;

	use super::GoAwayLabel;
	#[cfg(target_arch = "wasm32")]
	use crate::fault::Refused;

	type TestResult = core::result::Result<(), Box<dyn core::error::Error>>;

	// Each label is the name tightbeam writes for its reason, so TypeScript
	// reads the reason by the name every peer uses.
	tb_cases! {
		fn the_label_is_the_name_tightbeam_writes(reason: GoAwayReason) -> TestResult {
			assert_eq!(GoAwayLabel::from(reason).to_str(), reason.as_str());
			Ok(())
		}
		cases {
			shutdown => GoAwayReason::Shutdown,
			protocol_error => GoAwayReason::ProtocolError,
			enhance_your_calm => GoAwayReason::EnhanceYourCalm,
			budget_exhausted => GoAwayReason::BudgetExhausted,
			settlement_failed => GoAwayReason::SettlementFailed,
			application => GoAwayReason::Application(0x0001_0000),
		}
	}

	#[cfg(target_arch = "wasm32")]
	#[wasm_bindgen_test]
	fn an_application_label_is_no_goaway_reason() {
		let label = JsValue::from_str("application");
		let reason = GoAwayLabel::shutdown_reason(&label);
		assert_eq!(reason.code().as_deref(), Some("InvalidGoAwayReason"));
	}

	#[cfg(target_arch = "wasm32")]
	#[wasm_bindgen_test]
	fn a_fractional_code_is_no_goaway_reason() {
		let code = JsValue::from_f64(1.5);
		let reason = GoAwayLabel::shutdown_reason(&code);
		assert_eq!(reason.code().as_deref(), Some("InvalidGoAwayReason"));
	}
}
