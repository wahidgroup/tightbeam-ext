//! The labels JavaScript reads a protocol version and a message priority by,
//! as the codes section of `docs/ws-wasm.md` describes.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::convert::TryFromJsValue;
use wasm_bindgen::prelude::*;

use tightbeam::{MessagePriority, Version};

#[cfg(target_arch = "wasm32")]
use crate::fault::{JsFault, RefusalCode};
#[cfg(target_arch = "wasm32")]
use crate::promise::WholeNumber;

/// A frame protocol version, valued by its encoded ordinal. Each version
/// admits a larger metadata field set than the one before it.
#[wasm_bindgen(js_name = Version)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionLabel {
	/// The base envelope: id, order, and message body.
	V0 = 0,
	/// Adds message integrity, confidentiality, frame integrity, and the
	/// signature.
	V1 = 1,
	/// Adds priority, lifetime, and previous-frame linkage.
	V2 = 2,
	/// Adds the routing matrix.
	V3 = 3,
}

impl From<Version> for VersionLabel {
	fn from(version: Version) -> Self {
		match version {
			Version::V0 => Self::V0,
			Version::V1 => Self::V1,
			Version::V2 => Self::V2,
			Version::V3 => Self::V3,
		}
	}
}

impl From<VersionLabel> for Version {
	fn from(label: VersionLabel) -> Self {
		match label {
			VersionLabel::V0 => Self::V0,
			VersionLabel::V1 => Self::V1,
			VersionLabel::V2 => Self::V2,
			VersionLabel::V3 => Self::V3,
		}
	}
}

/// A version as JavaScript passes it: a member of `Version`, which is its
/// ordinal, so a fraction such as `1.5` refuses with `InvalidVersion`.
#[cfg(target_arch = "wasm32")]
impl TryFrom<&JsValue> for VersionLabel {
	type Error = JsFault;

	/// # Errors
	///
	/// - `InvalidVersion` -- the value is no ordinal of a version.
	fn try_from(value: &JsValue) -> Result<Self, Self::Error> {
		let ordinal = WholeNumber::read::<u32>(value).map(JsValue::from);
		let label = ordinal.as_ref().and_then(Self::try_from_js_value_ref);
		label.ok_or_else(|| RefusalCode::InvalidVersion.because("must be a member of Version").at("version"))
	}
}

/// The priority of a message (V2+), valued by its encoded ordinal. A higher
/// ordinal requests earlier scheduling under congestion.
#[wasm_bindgen(js_name = MessagePriority)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PriorityLabel {
	/// Lowest effort: defer under load.
	LowEffort = 0,
	/// Default application traffic.
	Standard = 1,
	/// Bulk throughput over latency.
	HighThroughput = 2,
	/// Latency-sensitive application traffic.
	LowLatency = 3,
	/// Expedited delivery ahead of ordinary application traffic.
	Expedited = 4,
	/// Network control and keep-alive traffic.
	NetworkControl = 5,
}

impl From<MessagePriority> for PriorityLabel {
	fn from(priority: MessagePriority) -> Self {
		match priority {
			MessagePriority::LowEffort => Self::LowEffort,
			MessagePriority::Standard => Self::Standard,
			MessagePriority::HighThroughput => Self::HighThroughput,
			MessagePriority::LowLatency => Self::LowLatency,
			MessagePriority::Expedited => Self::Expedited,
			MessagePriority::NetworkControl => Self::NetworkControl,
		}
	}
}

/// A priority as JavaScript passes it: a member of `MessagePriority`, which
/// is its ordinal, so a fraction refuses with `InvalidPriority`.
#[cfg(target_arch = "wasm32")]
impl TryFrom<&JsValue> for PriorityLabel {
	type Error = JsFault;

	/// # Errors
	///
	/// - `InvalidPriority` -- the value is no ordinal of a priority.
	fn try_from(value: &JsValue) -> Result<Self, Self::Error> {
		let ordinal = WholeNumber::read::<u32>(value).map(JsValue::from);
		let label = ordinal.as_ref().and_then(Self::try_from_js_value_ref);
		label.ok_or_else(|| {
			RefusalCode::InvalidPriority
				.because("must be a member of MessagePriority")
				.at("priority")
		})
	}
}

impl From<PriorityLabel> for MessagePriority {
	fn from(label: PriorityLabel) -> Self {
		match label {
			PriorityLabel::LowEffort => Self::LowEffort,
			PriorityLabel::Standard => Self::Standard,
			PriorityLabel::HighThroughput => Self::HighThroughput,
			PriorityLabel::LowLatency => Self::LowLatency,
			PriorityLabel::Expedited => Self::Expedited,
			PriorityLabel::NetworkControl => Self::NetworkControl,
		}
	}
}

#[cfg(test)]
mod tests {
	use tightbeam::tb_cases;
	use tightbeam::{MessagePriority, Version};

	use super::{PriorityLabel, VersionLabel};

	type TestResult = core::result::Result<(), Box<dyn core::error::Error>>;

	// Each label carries the encoded ordinal of its version, and maps back to
	// it.
	tb_cases! {
		fn the_version_label_carries_the_wire_ordinal(version: Version) -> TestResult {
			let label = VersionLabel::from(version);
			assert_eq!(label as u8, version as u8);
			assert_eq!(Version::from(label), version);
			Ok(())
		}
		cases {
			v0 => Version::V0,
			v1 => Version::V1,
			v2 => Version::V2,
			v3 => Version::V3,
		}
	}

	// Each label carries the encoded ordinal of its priority, and maps back to
	// it.
	tb_cases! {
		fn the_priority_label_carries_the_wire_ordinal(priority: MessagePriority) -> TestResult {
			let label = PriorityLabel::from(priority);
			assert_eq!(label as u8, priority as u8);
			assert_eq!(MessagePriority::from(label), priority);
			Ok(())
		}
		cases {
			low_effort => MessagePriority::LowEffort,
			standard => MessagePriority::Standard,
			high_throughput => MessagePriority::HighThroughput,
			low_latency => MessagePriority::LowLatency,
			expedited => MessagePriority::Expedited,
			network_control => MessagePriority::NetworkControl,
		}
	}
}
