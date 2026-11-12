//! The codes and the structured JavaScript errors of the wasm bindings, as
//! the codes section of `docs/ws-wasm.md` describes.

#[cfg(target_arch = "wasm32")]
use core::fmt::Display;

#[cfg(target_arch = "wasm32")]
use js_sys::{Error as JsError, Reflect};
use wasm_bindgen::prelude::*;

#[cfg(any(test, target_arch = "wasm32"))]
use tightbeam::asn1::BodyTransform;
use tightbeam::policy::TransitStatus;
#[cfg(any(test, target_arch = "wasm32"))]
use tightbeam::transport::{TransportError, TransportFailure};
#[cfg(any(test, target_arch = "wasm32"))]
use tightbeam::TightBeamError;

#[cfg(any(test, target_arch = "wasm32"))]
use crate::build::BuildRefusal;
#[cfg(target_arch = "wasm32")]
use crate::build::SharedKeyRefusal;
#[cfg(target_arch = "wasm32")]
use crate::build::StepError;
#[cfg(any(test, target_arch = "wasm32"))]
use crate::compress::ZstdRefusal;
#[cfg(target_arch = "wasm32")]
use crate::profile::Aes256Gcm;
#[cfg(target_arch = "wasm32")]
use crate::promise::Record;

/// A string enum and its TypeScript union, from one list of variants.
///
/// - A `fault` clause makes the enum a code family: a const assertion holds
///   each label equal to the name of its variant, and the union of the family
///   member of `EngineFault` is emitted with it.
/// - A code family lists its labels in `LABELS`, which [`FAMILIES`] reads.
/// - A `refusing` clause names the variant that names no refusal, and the
///   refusal type that the family faults with.
macro_rules! code_enum {
	(
		$(#[$meta:meta])*
		pub enum $name:ident in $section:ident, fault $fault:ident {
			$(
				$(#[$doc:meta])*
				$variant:ident = $label:tt,
			)*
		}
	) => {
		code_enum! {
			@enum $(#[$meta])* $name { $( $(#[$doc])* $variant = $label, )* }
		}
		code_enum! {
			@named $name { $( $variant = $label, )* }
		}

		#[cfg(target_arch = "wasm32")]
		#[wasm_bindgen(typescript_custom_section)]
		const $section: &'static str = concat!(
			"\n/**\n * Every `code` label of `", stringify!($name), "`.\n */\nexport type ", stringify!($name), " =",
			$("\n\t| \"", $label, "\"",)*
			";\n\n/**\n * A transport error whose `code` is a `", stringify!($name), "`.\n */\nexport type ",
			stringify!($fault), " = FaultOf<", stringify!($name), ">;\n"
		);
	};
	(
		$(#[$meta:meta])*
		pub enum $name:ident in $section:ident, fault $fault:ident refusing $ok:ident as $refusal:ident {
			$(
				$(#[$doc:meta])*
				$variant:ident = $label:tt,
			)*
		}
	) => {
		code_enum! {
			@enum $(#[$meta])* $name { $( $(#[$doc])* $variant = $label, )* }
		}
		code_enum! {
			@named $name { $( $variant = $label, )* }
		}

		impl $name {
			/// The refusal that `label` names: a variant other than the one
			/// that names no refusal, or `None`.
			#[cfg(any(test, target_arch = "wasm32"))]
			pub(crate) fn refusal(label: &str) -> Option<Self> {
				Self::from_str(label).filter(|code| *code != Self::$ok)
			}
		}

		#[cfg(target_arch = "wasm32")]
		#[wasm_bindgen(typescript_custom_section)]
		const $section: &'static str = concat!(
			"\n/**\n * Every `code` label of `", stringify!($name), "`.\n */\nexport type ", stringify!($name), " =",
			$("\n\t| \"", $label, "\"",)*
			";\n\n/**\n * Every label of `", stringify!($name), "` but `", stringify!($ok),
			"`, which names no refusal.\n */\nexport type ", stringify!($refusal), " = Exclude<", stringify!($name),
			", \"", stringify!($ok), "\">;\n\n/**\n * A transport error whose `code` is a `", stringify!($refusal),
			"`.\n */\nexport type ", stringify!($fault), " = FaultOf<", stringify!($refusal), ">;\n"
		);
	};
	(
		@enum $(#[$meta:meta])* $name:ident {
			$( $(#[$doc:meta])* $variant:ident = $label:tt, )*
		}
	) => {
		$(#[$meta])*
		#[wasm_bindgen]
		#[derive(Clone, Copy, Debug, PartialEq, Eq)]
		pub enum $name {
			$(
				$(#[$doc])*
				$variant = $label,
			)*
		}

	};
	(
		@named $name:ident { $( $variant:ident = $label:tt, )* }
	) => {
		impl $name {
			/// Every `code` label of this family.
			const LABELS: &'static [&'static str] = &[$($label),*];
		}

		const _: () = {
			$(
				assert!(
					Label::same(stringify!($variant), $label),
					concat!("the label of ", stringify!($name), "::", stringify!($variant), " differs from its name")
				);
			)*
		};
	};
	(
		$(#[$meta:meta])*
		pub enum $name:ident in $section:ident {
			$(
				$(#[$doc:meta])*
				$variant:ident = $label:tt,
			)*
		}
	) => {
		code_enum! {
			@enum $(#[$meta])* $name { $( $(#[$doc])* $variant = $label, )* }
		}

		#[cfg(target_arch = "wasm32")]
		#[wasm_bindgen(typescript_custom_section)]
		const $section: &'static str = concat!(
			"\n/**\n * Every label of `", stringify!($name), "`.\n */\nexport type ", stringify!($name), " =",
			$("\n\t| \"", $label, "\"",)*
			";\n"
		);
	};
}

/// A `code` label, compared in a const context.
struct Label;

impl Label {
	/// Whether `left` and `right` hold the same octets.
	const fn same(left: &str, right: &str) -> bool {
		let (left, right) = (left.as_bytes(), right.as_bytes());
		if left.len() != right.len() {
			return false;
		}

		let mut index = 0;
		while index < left.len() {
			if left[index] != right[index] {
				return false;
			}
			index += 1;
		}

		true
	}

	/// Whether no label of one family in `families` is a label of another.
	const fn disjoint(families: &[&[&str]]) -> bool {
		let mut family = 0;
		while family < families.len() {
			let mut other = family + 1;
			while other < families.len() {
				if Self::shared(families[family], families[other]) {
					return false;
				}
				other += 1;
			}
			family += 1;
		}

		true
	}

	/// Whether a label of `left` is a label of `right`.
	const fn shared(left: &[&str], right: &[&str]) -> bool {
		let mut index = 0;
		while index < left.len() {
			let mut other = 0;
			while other < right.len() {
				if Self::same(left[index], right[other]) {
					return true;
				}
				other += 1;
			}
			index += 1;
		}

		false
	}
}

/// The label of a refused work submission, which carries its transit status.
macro_rules! work_refused {
	() => {
		"WorkRefused"
	};
}

/// The label of a body that a read cannot reverse, which carries its layer.
macro_rules! opaque_body {
	() => {
		"OpaqueBody"
	};
}

/// The member of a structured transport error that holds its code.
#[cfg(target_arch = "wasm32")]
macro_rules! code_member {
	() => {
		"code"
	};
}

/// The member of a structured transport error that holds the field the
/// failure concerns.
#[cfg(target_arch = "wasm32")]
macro_rules! path_member {
	() => {
		"path"
	};
}

/// The member of a refused work submission that holds its transit status.
#[cfg(target_arch = "wasm32")]
macro_rules! status_member {
	() => {
		"status"
	};
}

/// The member of an opaque body refusal that holds the layer it lacks.
#[cfg(target_arch = "wasm32")]
macro_rules! layer_member {
	() => {
		"layer"
	};
}

/// The `name` carried by every structured transport error, as a literal that
/// both the Rust constant and the TypeScript type read.
#[cfg(target_arch = "wasm32")]
macro_rules! transport_error_name {
	() => {
		"TightbeamTransportError"
	};
}

/// The `name` carried by every structured transport error.
#[cfg(target_arch = "wasm32")]
const TRANSPORT_ERROR_NAME: &str = transport_error_name!();

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(typescript_custom_section)]
const TRANSPORT_ERROR_NAME_TYPE: &'static str = concat!(
	"\n/**\n * The `name` of every structured transport error.\n */\nexport type TransportErrorName = \"",
	transport_error_name!(),
	"\";\n"
);

/// TypeScript shapes of the structured errors, one member per [`Code`]
/// variant.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(typescript_custom_section)]
const ENGINE_FAULT_TS: &'static str = concat!(
	r#"
/**
 * The members of a structured transport error whose `code` is a label of
 * `Code`.
 */
export interface FaultOf<Code extends string> extends Error {
	/**
	 * The name brand of every structured transport error.
	 */
	readonly name: TransportErrorName;
	/**
	 * The code that names the failure.
	 */
	readonly "#,
	code_member!(),
	r#": Code;
	/**
	 * The field the failure concerns, as a TypeScript access such as
	 * `matrix.n`, when it concerns one.
	 */
	readonly "#,
	path_member!(),
	r#"?: string;
}

/**
 * A refused work submission, with the transit status of the gateway.
 */
export interface WorkRefusedFault extends FaultOf<""#,
	work_refused!(),
	r#""> {
	/**
	 * The gRPC canonical status that the gateway refused the work with.
	 */
	readonly "#,
	status_member!(),
	r#": TransitCode;
}

/**
 * A body that a read cannot reverse, with the layer it lacks a capability
 * for.
 */
export interface OpaqueBodyFault extends FaultOf<""#,
	opaque_body!(),
	r#""> {
	/**
	 * The layer of the body that the read holds no capability for.
	 */
	readonly "#,
	layer_member!(),
	r#": BodyLayer;
}

/**
 * A structured transport error of the engine, one member per family of its
 * code, so a check of `code` narrows to its member.
 */
export type EngineFault = RefusalFault | TransportFault | TransitFault | WorkRefusedFault | OpaqueBodyFault;
"#
);

code_enum! {
	/// A value the bindings refuse before an engine or a transport error
	/// exists. The label is the `code` JavaScript reads.
	pub enum RefusalCode in REFUSAL_CODE_UNION, fault RefusalFault {
		/// A byte value is not a `Uint8Array`.
		InvalidBytes = "InvalidBytes",
		/// A value is no dotted object identifier the engine encodes.
		InvalidOid = "InvalidOid",
		/// A matrix dimension is no integer from 1 to 255.
		InvalidMatrixDimension = "InvalidMatrixDimension",
		/// The matrix data does not hold `n * n` octets.
		InvalidMatrixData = "InvalidMatrixData",
		/// A secp256k1 scalar is not 32 octets, or names no key.
		InvalidSigningKey = "InvalidSigningKey",
		/// A SEC1 point names no secp256k1 public key.
		InvalidVerifyingKey = "InvalidVerifyingKey",
		/// The key cannot sign the prehash.
		InvalidPrehash = "InvalidPrehash",
		/// A client key is neither a raw scalar nor a `TransportSigner`.
		InvalidClientKey = "InvalidClientKey",
		/// The session budgets are not two non-negative integers.
		InvalidBudgets = "InvalidBudgets",
		/// The authorization token is no `OCTET STRING`.
		InvalidAuthorization = "InvalidAuthorization",
		/// A GoAway reason is neither a reserved label nor a u32 code.
		InvalidGoAwayReason = "InvalidGoAwayReason",
		/// A stream target is no URN.
		InvalidStreamRoute = "InvalidStreamRoute",
		/// A `serve*` claim names another mode than the running loop.
		ServeModeConflict = "ServeModeConflict",
		/// An exclusive claim owns the dispatch.
		ServeDispatchClaimed = "ServeDispatchClaimed",
		/// An exclusive claim meets a running shared handler.
		ServeDispatchShared = "ServeDispatchShared",
		/// Another call holds the stream half.
		StreamBusy = "StreamBusy",
		/// A close consumed the stream half.
		StreamClosed = "StreamClosed",
		/// The WebSocket refuses the URL.
		InvalidUrl = "InvalidUrl",
		/// A value is not a string.
		InvalidText = "InvalidText",
		/// A value is neither absent nor an `AbortSignal`.
		InvalidSignal = "InvalidSignal",
		/// A value is not a function.
		InvalidCallback = "InvalidCallback",
		/// The options of a dial are not an object.
		InvalidConnectOptions = "InvalidConnectOptions",
		/// A stream cap is no whole number from 1 to the `u32` ceiling.
		InvalidStreamCap = "InvalidStreamCap",
		/// A dial without mutual authentication names a session knob.
		SessionOfferRequiresMutual = "SessionOfferRequiresMutual",
		/// A frame lifetime is no whole number that a `u64` holds.
		InvalidLifetime = "InvalidLifetime",
		/// A version is no ordinal of a frame protocol version.
		InvalidVersion = "InvalidVersion",
		/// A priority is no ordinal of a message priority.
		InvalidPriority = "InvalidPriority",
		/// A serve claim is neither `shared` nor `exclusive`.
		InvalidServeClaim = "InvalidServeClaim",
		/// A decompression ceiling is no whole number that a `usize` holds.
		InvalidMaxOutput = "InvalidMaxOutput",
		/// A commitment salt moved out already, so its handle holds no salt.
		CommitmentSpent = "CommitmentSpent",
		/// A digest holds no octets, so it commits to nothing.
		EmptyDigest = "EmptyDigest",
		/// A shared key identifier holds no octets, so it names no key.
		EmptyKeyId = "EmptyKeyId",
		/// A signer key identifier holds no octets, so it names no certificate.
		EmptySignerId = "EmptySignerId",
		/// A frame builds at another version than its builder asserted.
		VersionMismatch = "VersionMismatch",
		/// A zstd frame declares a window past the rounded ceiling.
		WindowTooLarge = "WindowTooLarge",
		/// A zstd frame inflates past the ceiling.
		OutputLimitExceeded = "OutputLimitExceeded",
		/// The input ends inside the zstd frame.
		Truncated = "Truncated",
		/// Octets follow the zstd frame.
		TrailingBytes = "TrailingBytes",
		/// A zstd decode step consumed no input.
		Stalled = "Stalled",
		/// The octets are no well-formed zstd frame.
		Malformed = "Malformed",
	}
}

code_enum! {
	/// An error of the tightbeam engine or transport, by the variant behind it.
	/// The label is the `code` JavaScript reads.
	///
	/// - A peer refusal names the [`TransitCode`] of the status the peer answered with.
	/// - A refused work submission and an opaque body each name a [`Code`] variant that carries its detail.
	pub enum TransportCode in TRANSPORT_CODE_UNION, fault TransportFault {
		/// `TransportError::ConnectionClosed`.
		ConnectionClosed = "ConnectionClosed",
		/// `TransportError::PeerClosedBeforeHandshake`.
		PeerClosedBeforeHandshake = "PeerClosedBeforeHandshake",
		/// `TransportError::ConnectionFailed`.
		ConnectionFailed = "ConnectionFailed",
		/// `TransportError::SendFailed`.
		SendFailed = "SendFailed",
		/// `TransportError::MissingEncryption`.
		MissingEncryption = "MissingEncryption",
		/// `TransportError::UnsupportedHandshakeProtocol`.
		UnsupportedHandshakeProtocol = "UnsupportedHandshakeProtocol",
		/// `TransportError::MissingServerCertificateChain`.
		MissingServerCertificateChain = "MissingServerCertificateChain",
		/// `TransportError::MissingKeyAgreementIdentity`.
		MissingKeyAgreementIdentity = "MissingKeyAgreementIdentity",
		/// `TransportError::PeerAuthenticationUnconfigured`.
		PeerAuthenticationUnconfigured = "PeerAuthenticationUnconfigured",
		/// `TransportError::InvalidMessage`.
		InvalidMessage = "InvalidMessage",
		/// `TransportError::InvalidReply`.
		InvalidReply = "InvalidReply",
		/// `TransportError::MissingRequest`.
		MissingRequest = "MissingRequest",
		/// `TransportError::MaxRetriesExceeded`.
		MaxRetriesExceeded = "MaxRetriesExceeded",
		/// `TransportError::InvalidAddress`.
		InvalidAddress = "InvalidAddress",
		/// `TransportError::InvalidState`.
		InvalidState = "InvalidState",
		/// `TransportError::NotServed`.
		NotServed = "NotServed",
		/// `TransportError::Draining`.
		Draining = "Draining",
		/// `TransportError::InvalidCertificate`.
		InvalidCertificate = "InvalidCertificate",
		/// `TransportError::InvalidLimits`.
		InvalidLimits = "InvalidLimits",
		/// `TransportError::HandshakeError`, and
		/// `TightBeamError::HandshakeError`.
		HandshakeError = "HandshakeError",
		/// `TransportError::DerError`.
		DerError = "DerError",
		/// `TransportError::IoError`, and `TightBeamError::IoError`.
		IoError = "IoError",
		/// `TransportFailure::EncodingFailed`.
		EncodingFailed = "EncodingFailed",
		/// `TransportFailure::EncryptionFailed`.
		EncryptionFailed = "EncryptionFailed",
		/// `TransportFailure::SizeExceeded`.
		SizeExceeded = "SizeExceeded",
		/// `TransportFailure::EncryptorUnavailable`.
		EncryptorUnavailable = "EncryptorUnavailable",
		/// `TransportFailure::NonceGenerationFailed`.
		NonceGenerationFailed = "NonceGenerationFailed",
		/// `TransportFailure::RekeyRequired`, and
		/// `TightBeamError::RekeyRequired`.
		RekeyRequired = "RekeyRequired",
		/// `TransportFailure::RenewalBoundExceeded`, and
		/// `TightBeamError::RenewalBoundExceeded`.
		RenewalBoundExceeded = "RenewalBoundExceeded",
		/// `TransportFailure::TamperDetected`.
		TamperDetected = "TamperDetected",
		/// `TransportFailure::StreamsExhausted`.
		StreamsExhausted = "StreamsExhausted",
		/// `TransportFailure::BudgetExhausted`.
		BudgetExhausted = "BudgetExhausted",
		/// `TransportFailure::PolicyRejection`.
		PolicyRejection = "PolicyRejection",
		/// `TightBeamError::MatrixError`.
		MatrixError = "MatrixError",
		/// `TightBeamError::RouterError`.
		RouterError = "RouterError",
		/// `TightBeamError::BuildError`.
		BuildError = "BuildError",
		/// `TightBeamError::LockPoisoned`.
		LockPoisoned = "LockPoisoned",
		/// `TightBeamError::InvalidOID`.
		InvalidOID = "InvalidOID",
		/// `TightBeamError::SignatureError`.
		SignatureError = "SignatureError",
		/// `TightBeamError::EllipticCurveError`.
		EllipticCurveError = "EllipticCurveError",
		/// `TightBeamError::SerializationError`.
		SerializationError = "SerializationError",
		/// `TightBeamError::CompressionError`.
		CompressionError = "CompressionError",
		/// `TightBeamError::UnsupportedVersion`.
		UnsupportedVersion = "UnsupportedVersion",
		/// `TightBeamError::UnsupportedField`.
		UnsupportedField = "UnsupportedField",
		/// `TightBeamError::InstallOutOfOrder`.
		InstallOutOfOrder = "InstallOutOfOrder",
		/// `TightBeamError::UrnValidationError`.
		UrnValidationError = "UrnValidationError",
		/// `TightBeamError::EncryptionError`.
		EncryptionError = "EncryptionError",
		/// `TightBeamError::InvalidKeyLength`.
		InvalidKeyLength = "InvalidKeyLength",
		/// `TightBeamError::HpkeError`.
		HpkeError = "HpkeError",
		/// `TightBeamError::EnvelopeError`.
		EnvelopeError = "EnvelopeError",
		/// `TightBeamError::CertificateValidationError`.
		CertificateValidationError = "CertificateValidationError",
		/// `TightBeamError::KeyListError`.
		KeyListError = "KeyListError",
		/// `TightBeamError::KeyDerivationError`.
		KeyDerivationError = "KeyDerivationError",
		/// `TightBeamError::KeyError`.
		KeyError = "KeyError",
		/// `TightBeamError::OsRngError`.
		OsRngError = "OsRngError",
		/// `TightBeamError::SpkiError`.
		SpkiError = "SpkiError",
		/// `TightBeamError::X509BuilderError`.
		X509BuilderError = "X509BuilderError",
		/// `TightBeamError::RecvTimeoutError`.
		RecvTimeoutError = "RecvTimeoutError",
		/// `TightBeamError::SignatureEncodingError`.
		SignatureEncodingError = "SignatureEncodingError",
		/// `TightBeamError::Signer`.
		Signer = "Signer",
		/// `TightBeamError::InvalidMetadata`.
		InvalidMetadata = "InvalidMetadata",
		/// `TightBeamError::InvalidBody`.
		InvalidBody = "InvalidBody",
		/// `TightBeamError::InvalidOverflowValue`.
		InvalidOverflowValue = "InvalidOverflowValue",
		/// `TightBeamError::InvalidOrder`.
		InvalidOrder = "InvalidOrder",
		/// `TightBeamError::MissingOrder`.
		MissingOrder = "MissingOrder",
		/// `TightBeamError::MissingInflator`.
		MissingInflator = "MissingInflator",
		/// `TightBeamError::MissingFeature`.
		MissingFeature = "MissingFeature",
		/// `TightBeamError::MissingProtection`.
		MissingProtection = "MissingProtection",
		/// `TightBeamError::Requirement`.
		Requirement = "Requirement",
		/// `TightBeamError::MissingResponse`.
		MissingResponse = "MissingResponse",
		/// `TightBeamError::ChannelClosed`.
		ChannelClosed = "ChannelClosed",
		/// `TightBeamError::MissingSignature`.
		MissingSignature = "MissingSignature",
		/// `TightBeamError::MissingSignatureInfo`.
		MissingSignatureInfo = "MissingSignatureInfo",
		/// `TightBeamError::MissingEncryptionInfo`.
		MissingEncryptionInfo = "MissingEncryptionInfo",
		/// `TightBeamError::InvalidSaltLength`.
		InvalidSaltLength = "InvalidSaltLength",
		/// `TightBeamError::NonceExhausted`.
		NonceExhausted = "NonceExhausted",
		/// `TightBeamError::NonceReplayed`.
		NonceReplayed = "NonceReplayed",
		/// `TightBeamError::RecordEpoch`.
		RecordEpoch = "RecordEpoch",
		/// `TightBeamError::MissingDigestInfo`.
		MissingDigestInfo = "MissingDigestInfo",
		/// `TightBeamError::InvalidAlgorithm`.
		InvalidAlgorithm = "InvalidAlgorithm",
		/// `TightBeamError::UnexpectedAlgorithm`.
		UnexpectedAlgorithm = "UnexpectedAlgorithm",
		/// `TightBeamError::MissingConfiguration`.
		MissingConfiguration = "MissingConfiguration",
		/// `TightBeamError::Sequence`.
		Sequence = "Sequence",
		/// A variant that tightbeam added after this crate, which
		/// `#[non_exhaustive]` lets reach the last arm.
		Unrecognized = "Unrecognized",
	}
}

code_enum! {
	/// A gRPC canonical status (`google.rpc.Code`), by the name tightbeam
	/// writes for it: the code of a peer refusal, and the status a stream
	/// handler answers with.
	///
	/// - The labels copy the names of [`TransitStatus::as_str`], because a `wasm-bindgen` string enum takes
	///   literal discriminants.
	/// - The pin test `transit_code_labels_match_transit_status` holds them equal.
	pub enum TransitCode in TRANSIT_CODE_UNION, fault TransitFault refusing Ok as TransitRefusal {
		/// `TransitStatus::Ok`.
		Ok = "Ok",
		/// `TransitStatus::Cancelled`.
		Cancelled = "Cancelled",
		/// `TransitStatus::Unknown`.
		Unknown = "Unknown",
		/// `TransitStatus::InvalidArgument`.
		InvalidArgument = "InvalidArgument",
		/// `TransitStatus::DeadlineExceeded`.
		DeadlineExceeded = "DeadlineExceeded",
		/// `TransitStatus::NotFound`.
		NotFound = "NotFound",
		/// `TransitStatus::AlreadyExists`.
		AlreadyExists = "AlreadyExists",
		/// `TransitStatus::PermissionDenied`.
		PermissionDenied = "PermissionDenied",
		/// `TransitStatus::ResourceExhausted`.
		ResourceExhausted = "ResourceExhausted",
		/// `TransitStatus::FailedPrecondition`.
		FailedPrecondition = "FailedPrecondition",
		/// `TransitStatus::Aborted`.
		Aborted = "Aborted",
		/// `TransitStatus::OutOfRange`.
		OutOfRange = "OutOfRange",
		/// `TransitStatus::Unimplemented`.
		Unimplemented = "Unimplemented",
		/// `TransitStatus::Internal`.
		Internal = "Internal",
		/// `TransitStatus::Unavailable`.
		Unavailable = "Unavailable",
		/// `TransitStatus::DataLoss`.
		DataLoss = "DataLoss",
		/// `TransitStatus::Unauthenticated`.
		Unauthenticated = "Unauthenticated",
	}
}

/// The code of each status. The match covers every status tightbeam
/// defines, so a new status fails to compile here until it has a code.
impl From<TransitStatus> for TransitCode {
	fn from(status: TransitStatus) -> Self {
		match status {
			TransitStatus::Ok => Self::Ok,
			TransitStatus::Cancelled => Self::Cancelled,
			TransitStatus::Unknown => Self::Unknown,
			TransitStatus::InvalidArgument => Self::InvalidArgument,
			TransitStatus::DeadlineExceeded => Self::DeadlineExceeded,
			TransitStatus::NotFound => Self::NotFound,
			TransitStatus::AlreadyExists => Self::AlreadyExists,
			TransitStatus::PermissionDenied => Self::PermissionDenied,
			TransitStatus::ResourceExhausted => Self::ResourceExhausted,
			TransitStatus::FailedPrecondition => Self::FailedPrecondition,
			TransitStatus::Aborted => Self::Aborted,
			TransitStatus::OutOfRange => Self::OutOfRange,
			TransitStatus::Unimplemented => Self::Unimplemented,
			TransitStatus::Internal => Self::Internal,
			TransitStatus::Unavailable => Self::Unavailable,
			TransitStatus::DataLoss => Self::DataLoss,
			TransitStatus::Unauthenticated => Self::Unauthenticated,
		}
	}
}

impl From<TransitCode> for TransitStatus {
	fn from(code: TransitCode) -> Self {
		match code {
			TransitCode::Ok => Self::Ok,
			TransitCode::Cancelled => Self::Cancelled,
			TransitCode::Unknown => Self::Unknown,
			TransitCode::InvalidArgument => Self::InvalidArgument,
			TransitCode::DeadlineExceeded => Self::DeadlineExceeded,
			TransitCode::NotFound => Self::NotFound,
			TransitCode::AlreadyExists => Self::AlreadyExists,
			TransitCode::PermissionDenied => Self::PermissionDenied,
			TransitCode::ResourceExhausted => Self::ResourceExhausted,
			TransitCode::FailedPrecondition => Self::FailedPrecondition,
			TransitCode::Aborted => Self::Aborted,
			TransitCode::OutOfRange => Self::OutOfRange,
			TransitCode::Unimplemented => Self::Unimplemented,
			TransitCode::Internal => Self::Internal,
			TransitCode::Unavailable => Self::Unavailable,
			TransitCode::DataLoss => Self::DataLoss,
			TransitCode::Unauthenticated => Self::Unauthenticated,
			TransitCode::__Invalid => Self::Unknown,
		}
	}
}

code_enum! {
	/// The layer of a frame body that a read cannot reverse without a
	/// capability, by the name of the capability that reverses it.
	pub enum BodyLayer in BODY_LAYER_UNION {
		/// The seal, which an opener opens.
		Opener = "opener",
		/// The compression, which an inflator inflates.
		Inflator = "inflator",
	}
}

/// The labels of every code family, and the two labels whose code carries a
/// detail. [`Code::read`] tries the families in turn, so a label names one
/// family alone.
const FAMILIES: [&[&str]; 4] = [
	RefusalCode::LABELS,
	TransportCode::LABELS,
	TransitCode::LABELS,
	&[work_refused!(), opaque_body!()],
];

const _: () = assert!(Label::disjoint(&FAMILIES), "a code label names more than one family");

#[cfg(any(test, target_arch = "wasm32"))]
impl From<BodyTransform> for BodyLayer {
	fn from(transform: BodyTransform) -> Self {
		match transform {
			BodyTransform::Decrypt => Self::Opener,
			BodyTransform::Inflate => Self::Inflator,
		}
	}
}

#[cfg(any(test, target_arch = "wasm32"))]
/// The code of one failure, from the family that decides it, with the detail
/// that the family carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Code {
	/// A value the bindings refused.
	Refusal(RefusalCode),
	/// An error of the engine or the transport.
	Transport(TransportCode),
	/// A refusal of the peer, by the status it answered with.
	Transit(TransitCode),
	/// A refused work submission, by the transit status of the gateway.
	WorkRefused(TransitCode),
	/// A body that a read cannot reverse, by the layer it lacks.
	OpaqueBody(BodyLayer),
}

/// The members of the JavaScript error that one [`Code`] encodes.
#[cfg(target_arch = "wasm32")]
struct Members {
	/// The label of the `code` member.
	code: &'static str,
	/// The member a code carries besides its label: the `status` of a refused
	/// work submission, or the `layer` of an opaque body.
	detail: Option<Detail>,
}

/// A member of a JavaScript error, by its name and the label it holds.
#[cfg(target_arch = "wasm32")]
struct Detail {
	member: &'static str,
	label: &'static str,
}

#[cfg(target_arch = "wasm32")]
impl Code {
	/// The members that JavaScript reads for this code.
	fn members(self) -> Members {
		match self {
			Self::Refusal(code) => Members { code: code.to_str(), detail: None },
			Self::Transport(code) => Members { code: code.to_str(), detail: None },
			Self::Transit(code) => Members { code: code.to_str(), detail: None },
			Self::WorkRefused(status) => {
				let detail = Detail { member: status_member!(), label: status.to_str() };
				Members { code: work_refused!(), detail: Some(detail) }
			}
			Self::OpaqueBody(layer) => {
				let detail = Detail { member: layer_member!(), label: layer.to_str() };
				Members { code: opaque_body!(), detail: Some(detail) }
			}
		}
	}

	/// The code of `value`, read back from a structured error as
	/// [`JsFault`] writes one, or `None` for any other value.
	fn read(value: &JsValue) -> Option<Self> {
		let error = value.dyn_ref::<JsError>()?;
		if error.name() != TRANSPORT_ERROR_NAME {
			return None;
		}

		let label = Record::member(value, code_member!()).as_string()?;
		let detail = |member: &str| Record::member(value, member).as_string();
		match label.as_str() {
			work_refused!() => TransitCode::from_str(&detail(status_member!())?).map(Self::WorkRefused),
			opaque_body!() => BodyLayer::from_str(&detail(layer_member!())?).map(Self::OpaqueBody),
			other => RefusalCode::from_str(other)
				.map(Self::Refusal)
				.or_else(|| TransportCode::from_str(other).map(Self::Transport))
				.or_else(|| TransitCode::refusal(other).map(Self::Transit)),
		}
	}
}

#[cfg(any(test, target_arch = "wasm32"))]
impl From<RefusalCode> for Code {
	fn from(code: RefusalCode) -> Self {
		Self::Refusal(code)
	}
}

#[cfg(any(test, target_arch = "wasm32"))]
impl From<TransportCode> for Code {
	fn from(code: TransportCode) -> Self {
		Self::Transport(code)
	}
}

#[cfg(any(test, target_arch = "wasm32"))]
/// A local failure names its [`TransportCode`], and a peer refusal names the
/// [`TransitCode`] of the status it carries.
///
/// - The pin test `a_peer_failure_names_the_code_of_its_status` holds these pairs equal to those of
///   `TryFrom<TransportFailure> for TransitStatus`.
/// - The type is exhaustive, so a failure that tightbeam adds fails to compile here until it has a code.
impl From<TransportFailure> for Code {
	fn from(failure: TransportFailure) -> Self {
		let local = match failure {
			TransportFailure::EncodingFailed => TransportCode::EncodingFailed,
			TransportFailure::EncryptionFailed => TransportCode::EncryptionFailed,
			TransportFailure::SizeExceeded => TransportCode::SizeExceeded,
			TransportFailure::EncryptorUnavailable => TransportCode::EncryptorUnavailable,
			TransportFailure::NonceGenerationFailed => TransportCode::NonceGenerationFailed,
			TransportFailure::RekeyRequired => TransportCode::RekeyRequired,
			TransportFailure::RenewalBoundExceeded => TransportCode::RenewalBoundExceeded,
			TransportFailure::TamperDetected => TransportCode::TamperDetected,
			TransportFailure::StreamsExhausted => TransportCode::StreamsExhausted,
			TransportFailure::BudgetExhausted => TransportCode::BudgetExhausted,
			TransportFailure::PolicyRejection => TransportCode::PolicyRejection,
			TransportFailure::Cancelled => return Self::Transit(TransitCode::Cancelled),
			TransportFailure::Unknown => return Self::Transit(TransitCode::Unknown),
			TransportFailure::InvalidArgument => return Self::Transit(TransitCode::InvalidArgument),
			TransportFailure::DeadlineExceeded => return Self::Transit(TransitCode::DeadlineExceeded),
			TransportFailure::NotFound => return Self::Transit(TransitCode::NotFound),
			TransportFailure::AlreadyExists => return Self::Transit(TransitCode::AlreadyExists),
			TransportFailure::PermissionDenied => return Self::Transit(TransitCode::PermissionDenied),
			TransportFailure::ResourceExhausted => return Self::Transit(TransitCode::ResourceExhausted),
			TransportFailure::FailedPrecondition => return Self::Transit(TransitCode::FailedPrecondition),
			TransportFailure::Aborted => return Self::Transit(TransitCode::Aborted),
			TransportFailure::OutOfRange => return Self::Transit(TransitCode::OutOfRange),
			TransportFailure::Unimplemented => return Self::Transit(TransitCode::Unimplemented),
			TransportFailure::Internal => return Self::Transit(TransitCode::Internal),
			TransportFailure::Unavailable => return Self::Transit(TransitCode::Unavailable),
			TransportFailure::DataLoss => return Self::Transit(TransitCode::DataLoss),
			TransportFailure::Unauthenticated => return Self::Transit(TransitCode::Unauthenticated),
		};

		Self::Transport(local)
	}
}

#[cfg(any(test, target_arch = "wasm32"))]
/// One arm per variant of `TransportError`. An operation failure names its
/// inner failure, which is the signal callers branch on. The type is
/// `#[non_exhaustive]`, so the last arm names each variant outside the list
/// as [`TransportCode::Unrecognized`].
impl From<&TransportError> for Code {
	fn from(error: &TransportError) -> Self {
		let code = match error {
			TransportError::ConnectionClosed => TransportCode::ConnectionClosed,
			TransportError::PeerClosedBeforeHandshake => TransportCode::PeerClosedBeforeHandshake,
			TransportError::ConnectionFailed => TransportCode::ConnectionFailed,
			TransportError::SendFailed => TransportCode::SendFailed,
			TransportError::MissingEncryption => TransportCode::MissingEncryption,
			TransportError::UnsupportedHandshakeProtocol(..) => TransportCode::UnsupportedHandshakeProtocol,
			TransportError::MissingServerCertificateChain => TransportCode::MissingServerCertificateChain,
			TransportError::MissingKeyAgreementIdentity => TransportCode::MissingKeyAgreementIdentity,
			TransportError::PeerAuthenticationUnconfigured => TransportCode::PeerAuthenticationUnconfigured,
			TransportError::InvalidMessage => TransportCode::InvalidMessage,
			TransportError::InvalidReply => TransportCode::InvalidReply,
			TransportError::MissingRequest => TransportCode::MissingRequest,
			TransportError::MaxRetriesExceeded => TransportCode::MaxRetriesExceeded,
			TransportError::InvalidAddress => TransportCode::InvalidAddress,
			TransportError::InvalidState => TransportCode::InvalidState,
			TransportError::NotServed => TransportCode::NotServed,
			TransportError::Draining => TransportCode::Draining,
			TransportError::InvalidCertificate(..) => TransportCode::InvalidCertificate,
			TransportError::InvalidLimits(..) => TransportCode::InvalidLimits,
			TransportError::HandshakeError(..) => TransportCode::HandshakeError,
			TransportError::DerError(..) => TransportCode::DerError,
			TransportError::IoError(..) => TransportCode::IoError,
			TransportError::MessageNotSent(_, failure) | TransportError::OperationFailed(failure) => {
				return Self::from(*failure);
			}
			_ => TransportCode::Unrecognized,
		};

		Self::Transport(code)
	}
}

#[cfg(any(test, target_arch = "wasm32"))]
/// One arm per variant of `TightBeamError` under the features this crate
/// enables. A transport error names its own code, and the type is
/// `#[non_exhaustive]`, so the last arm names each variant outside the list
/// as [`TransportCode::Unrecognized`].
impl From<&TightBeamError> for Code {
	fn from(error: &TightBeamError) -> Self {
		let code = match error {
			TightBeamError::TransportError(inner) => return Self::from(inner),
			TightBeamError::MatrixError(..) => TransportCode::MatrixError,
			TightBeamError::RouterError(..) => TransportCode::RouterError,
			TightBeamError::BuildError(..) => TransportCode::BuildError,
			TightBeamError::IoError(..) => TransportCode::IoError,
			TightBeamError::LockPoisoned => TransportCode::LockPoisoned,
			TightBeamError::InvalidOID(..) => TransportCode::InvalidOID,
			TightBeamError::SignatureError(..) => TransportCode::SignatureError,
			TightBeamError::EllipticCurveError(..) => TransportCode::EllipticCurveError,
			TightBeamError::SerializationError(..) => TransportCode::SerializationError,
			TightBeamError::CompressionError(..) => TransportCode::CompressionError,
			TightBeamError::HandshakeError(..) => TransportCode::HandshakeError,
			TightBeamError::UnsupportedVersion(..) => TransportCode::UnsupportedVersion,
			TightBeamError::UnsupportedField { .. } => TransportCode::UnsupportedField,
			TightBeamError::InstallOutOfOrder { .. } => TransportCode::InstallOutOfOrder,
			TightBeamError::UrnValidationError(..) => TransportCode::UrnValidationError,
			TightBeamError::EncryptionError(..) => TransportCode::EncryptionError,
			TightBeamError::InvalidKeyLength(..) => TransportCode::InvalidKeyLength,
			TightBeamError::HpkeError(..) => TransportCode::HpkeError,
			TightBeamError::EnvelopeError(..) => TransportCode::EnvelopeError,
			TightBeamError::CertificateValidationError(..) => TransportCode::CertificateValidationError,
			TightBeamError::KeyListError(..) => TransportCode::KeyListError,
			TightBeamError::KeyDerivationError(..) => TransportCode::KeyDerivationError,
			TightBeamError::KeyError(..) => TransportCode::KeyError,
			TightBeamError::OsRngError(..) => TransportCode::OsRngError,
			TightBeamError::SpkiError(..) => TransportCode::SpkiError,
			TightBeamError::X509BuilderError(..) => TransportCode::X509BuilderError,
			TightBeamError::RecvTimeoutError => TransportCode::RecvTimeoutError,
			TightBeamError::SignatureEncodingError => TransportCode::SignatureEncodingError,
			TightBeamError::Signer(..) => TransportCode::Signer,
			TightBeamError::InvalidMetadata => TransportCode::InvalidMetadata,
			TightBeamError::InvalidBody => TransportCode::InvalidBody,
			TightBeamError::InvalidOverflowValue => TransportCode::InvalidOverflowValue,
			TightBeamError::InvalidOrder => TransportCode::InvalidOrder,
			TightBeamError::MissingOrder => TransportCode::MissingOrder,
			TightBeamError::MissingInflator => TransportCode::MissingInflator,
			TightBeamError::MissingFeature(..) => TransportCode::MissingFeature,
			TightBeamError::MissingProtection { .. } => TransportCode::MissingProtection,
			TightBeamError::Requirement(..) => TransportCode::Requirement,
			TightBeamError::OpaqueBody(transform) => return Self::OpaqueBody(BodyLayer::from(*transform)),
			TightBeamError::MissingResponse => TransportCode::MissingResponse,
			TightBeamError::WorkRefused(status) => return Self::WorkRefused(TransitCode::from(*status)),
			TightBeamError::ChannelClosed => TransportCode::ChannelClosed,
			TightBeamError::MissingSignature => TransportCode::MissingSignature,
			TightBeamError::MissingSignatureInfo => TransportCode::MissingSignatureInfo,
			TightBeamError::MissingEncryptionInfo => TransportCode::MissingEncryptionInfo,
			TightBeamError::InvalidSaltLength(..) => TransportCode::InvalidSaltLength,
			TightBeamError::NonceExhausted => TransportCode::NonceExhausted,
			TightBeamError::RekeyRequired => TransportCode::RekeyRequired,
			TightBeamError::RenewalBoundExceeded => TransportCode::RenewalBoundExceeded,
			TightBeamError::NonceReplayed(..) => TransportCode::NonceReplayed,
			TightBeamError::RecordEpoch(..) => TransportCode::RecordEpoch,
			TightBeamError::MissingDigestInfo => TransportCode::MissingDigestInfo,
			TightBeamError::InvalidAlgorithm => TransportCode::InvalidAlgorithm,
			TightBeamError::UnexpectedAlgorithm(..) => TransportCode::UnexpectedAlgorithm,
			TightBeamError::MissingConfiguration => TransportCode::MissingConfiguration,
			TightBeamError::Sequence(..) => TransportCode::Sequence,
			_ => TransportCode::Unrecognized,
		};

		Self::Transport(code)
	}
}

#[cfg(any(test, target_arch = "wasm32"))]
/// The refusal code of each zstd refusal.
impl From<&ZstdRefusal> for RefusalCode {
	fn from(refusal: &ZstdRefusal) -> Self {
		match refusal {
			ZstdRefusal::WindowTooLarge { .. } => Self::WindowTooLarge,
			ZstdRefusal::OutputLimitExceeded(_) => Self::OutputLimitExceeded,
			ZstdRefusal::Truncated => Self::Truncated,
			ZstdRefusal::TrailingBytes(_) => Self::TrailingBytes,
			ZstdRefusal::Stalled => Self::Stalled,
			ZstdRefusal::Malformed => Self::Malformed,
		}
	}
}

#[cfg(any(test, target_arch = "wasm32"))]
/// The refusal code of each build refusal.
impl From<&BuildRefusal> for RefusalCode {
	fn from(refusal: &BuildRefusal) -> Self {
		match refusal {
			BuildRefusal::EmptyDigest => Self::EmptyDigest,
			BuildRefusal::EmptySignerId => Self::EmptySignerId,
			BuildRefusal::VersionMismatch { .. } => Self::VersionMismatch,
		}
	}
}

/// The recognizer of the structured transport errors of the engine.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct Codes;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl Codes {
	/// Whether `value` is a structured transport error of the engine.
	///
	/// - It is an `Error` named `TightbeamTransportError` whose `code` the
	///   engine declares.
	/// - A `WorkRefused` carries a `status`, and an `OpaqueBody` a `layer`,
	///   that the engine declares.
	pub fn recognizes(#[wasm_bindgen(unchecked_param_type = "unknown")] value: JsValue) -> bool {
		Code::read(&value).is_some()
	}
}

/// A structured JavaScript error: an `Error` named `TightbeamTransportError`.
///
/// - Its `code` names the failure, and it carries the detail of its code.
/// - Its `path` names the field that a refusal concerns.
/// - Engine, transport, and binding failures convert into it, so a binding returns `Result<_, JsFault>` and
///   reaches each conversion through `?`.
#[cfg(target_arch = "wasm32")]
#[derive(Debug)]
pub struct JsFault {
	code: Code,
	message: String,
	path: String,
}

#[cfg(target_arch = "wasm32")]
impl JsFault {
	/// The failure `code`, explained by `message`, at no field.
	fn new(code: impl Into<Code>, message: impl Display) -> Self {
		Self { code: code.into(), message: message.to_string(), path: String::new() }
	}

	/// This refusal, one field deeper: `field` heads the path, as `matrix`
	/// heads `matrix.n`. The path reads as a TypeScript access, as the
	/// `FieldError` of `tightbeam-asn` reads.
	#[must_use]
	pub(crate) fn at(mut self, field: &str) -> Self {
		self.path = if self.path.is_empty() {
			field.to_owned()
		} else {
			format!("{field}.{}", self.path)
		};
		self
	}
}

#[cfg(target_arch = "wasm32")]
impl From<JsFault> for JsValue {
	fn from(fault: JsFault) -> Self {
		let JsFault { code, message, path } = fault;
		let text = if path.is_empty() {
			message
		} else {
			format!("{path}: {message}")
		};

		let js_error = JsError::new(&text);
		js_error.set_name(TRANSPORT_ERROR_NAME);
		let error: JsValue = js_error.into();

		let Members { code, detail } = code.members();

		// `Reflect::set` on a freshly built `Error` object cannot fail.
		let _ = Reflect::set(&error, &JsValue::from_str(code_member!()), &JsValue::from_str(code));
		if !path.is_empty() {
			let _ = Reflect::set(&error, &JsValue::from_str(path_member!()), &JsValue::from_str(&path));
		}
		if let Some(Detail { member, label }) = detail {
			let _ = Reflect::set(&error, &JsValue::from_str(member), &JsValue::from_str(label));
		}

		error
	}
}

#[cfg(target_arch = "wasm32")]
impl RefusalCode {
	/// This refusal, explained by `message`.
	pub(crate) fn because(self, message: impl Display) -> JsFault {
		JsFault::new(self, message)
	}
}

#[cfg(target_arch = "wasm32")]
impl TransportCode {
	/// A failure the bindings detect first that tightbeam names too, such as
	/// a socket that closed before the transport reported it, explained by
	/// `message`.
	pub(crate) fn because(self, message: impl Display) -> JsFault {
		JsFault::new(self, message)
	}
}

#[cfg(target_arch = "wasm32")]
impl From<TransportError> for JsFault {
	fn from(error: TransportError) -> Self {
		let code = Code::from(&error);
		Self::new(code, error)
	}
}

#[cfg(target_arch = "wasm32")]
impl From<TightBeamError> for JsFault {
	fn from(error: TightBeamError) -> Self {
		let code = Code::from(&error);
		Self::new(code, error)
	}
}

#[cfg(target_arch = "wasm32")]
impl From<BuildRefusal> for JsFault {
	fn from(refusal: BuildRefusal) -> Self {
		let code = RefusalCode::from(&refusal);
		code.because(refusal)
	}
}

#[cfg(target_arch = "wasm32")]
impl From<ZstdRefusal> for JsFault {
	fn from(refusal: ZstdRefusal) -> Self {
		let code = RefusalCode::from(&refusal);
		code.because(refusal)
	}
}

#[cfg(target_arch = "wasm32")]
/// A shared key refusal names its code at the member of the `SharedKey` it
/// concerns: its own refusal code at the key identifier, or the code of the
/// error that tightbeam refuses the key with at the key.
impl From<SharedKeyRefusal> for JsFault {
	fn from(refusal: SharedKeyRefusal) -> Self {
		let (code, member) = match &refusal {
			SharedKeyRefusal::EmptyKeyId => (Code::Refusal(RefusalCode::EmptyKeyId), Aes256Gcm::KEY_ID),
			SharedKeyRefusal::Key(error) => (Code::from(error), Aes256Gcm::KEY),
		};

		Self::new(code, refusal).at(member)
	}
}

#[cfg(target_arch = "wasm32")]
impl From<StepError> for JsFault {
	fn from(error: StepError) -> Self {
		match error {
			StepError::Refused(refusal) => Self::from(refusal),
			StepError::Engine(error) => Self::from(error),
		}
	}
}

#[cfg(target_arch = "wasm32")]
impl From<tightbeam::der::Error> for JsFault {
	fn from(error: tightbeam::der::Error) -> Self {
		Self::from(TightBeamError::from(error))
	}
}

/// The outcome of a binding call, as the unit tests of every binding read
/// its refusal.
#[cfg(all(test, target_arch = "wasm32"))]
pub(crate) trait Refused: Sized {
	/// The `code` and the `path` that a refused outcome carries, as a
	/// JavaScript caller reads them, or `None` for an outcome that succeeded.
	fn refusal(self) -> Option<(String, String)>;

	/// The `code` that a refused outcome carries, or `None` for an outcome
	/// that succeeded.
	fn code(self) -> Option<String> {
		self.refusal().map(|(code, _)| code)
	}
}

#[cfg(all(test, target_arch = "wasm32"))]
impl<T, E: Into<JsValue>> Refused for Result<T, E> {
	fn refusal(self) -> Option<(String, String)> {
		let refusal: JsValue = self.err()?.into();
		let code = Record::member(&refusal, code_member!()).as_string()?;
		let path = Record::member(&refusal, path_member!()).as_string().unwrap_or_default();
		Some((code, path))
	}
}

#[cfg(test)]
mod tests {
	use tightbeam::asn1::BodyTransform;
	use tightbeam::policy::TransitStatus;
	use tightbeam::tb_cases;
	use tightbeam::transport::{TransportError, TransportFailure};
	use tightbeam::TightBeamError;

	use super::{BodyLayer, Code, TransitCode, TransportCode};

	type TestResult = core::result::Result<(), Box<dyn core::error::Error>>;

	// Each label is the name tightbeam writes for its status, so a handler
	// and a peer read one status by one name.
	tb_cases! {
		fn transit_code_labels_match_transit_status(status: TransitStatus) -> TestResult {
			assert_eq!(TransitCode::from(status).to_str(), status.as_str());
			assert_eq!(TransitStatus::from(TransitCode::from(status)), status);
			Ok(())
		}
		cases {
			ok => TransitStatus::Ok,
			cancelled => TransitStatus::Cancelled,
			unknown => TransitStatus::Unknown,
			invalid_argument => TransitStatus::InvalidArgument,
			deadline_exceeded => TransitStatus::DeadlineExceeded,
			not_found => TransitStatus::NotFound,
			already_exists => TransitStatus::AlreadyExists,
			permission_denied => TransitStatus::PermissionDenied,
			resource_exhausted => TransitStatus::ResourceExhausted,
			failed_precondition => TransitStatus::FailedPrecondition,
			aborted => TransitStatus::Aborted,
			out_of_range => TransitStatus::OutOfRange,
			unimplemented => TransitStatus::Unimplemented,
			internal => TransitStatus::Internal,
			unavailable => TransitStatus::Unavailable,
			data_loss => TransitStatus::DataLoss,
			unauthenticated => TransitStatus::Unauthenticated,
		}
	}

	// Each peer failure names the code of the status tightbeam pairs it with,
	// and each local failure names a transport code.
	tb_cases! {
		fn a_peer_failure_names_the_code_of_its_status(failure: TransportFailure) -> TestResult {
			let code = match TransitStatus::try_from(failure) {
				Ok(status) => Code::Transit(TransitCode::from(status)),
				Err(_) => return Err("a peer failure carries a status".into()),
			};

			assert_eq!(Code::from(failure), code);
			Ok(())
		}
		cases {
			cancelled => TransportFailure::Cancelled,
			unknown => TransportFailure::Unknown,
			invalid_argument => TransportFailure::InvalidArgument,
			deadline_exceeded => TransportFailure::DeadlineExceeded,
			not_found => TransportFailure::NotFound,
			already_exists => TransportFailure::AlreadyExists,
			permission_denied => TransportFailure::PermissionDenied,
			resource_exhausted => TransportFailure::ResourceExhausted,
			failed_precondition => TransportFailure::FailedPrecondition,
			aborted => TransportFailure::Aborted,
			out_of_range => TransportFailure::OutOfRange,
			unimplemented => TransportFailure::Unimplemented,
			internal => TransportFailure::Internal,
			unavailable => TransportFailure::Unavailable,
			data_loss => TransportFailure::DataLoss,
			unauthenticated => TransportFailure::Unauthenticated,
		}
	}

	tb_cases! {
		fn a_local_failure_carries_no_status(failure: TransportFailure) -> TestResult {
			assert!(TransitStatus::try_from(failure).is_err());
			assert!(matches!(Code::from(failure), Code::Transport(_)));
			Ok(())
		}
		cases {
			encoding_failed => TransportFailure::EncodingFailed,
			encryption_failed => TransportFailure::EncryptionFailed,
			size_exceeded => TransportFailure::SizeExceeded,
			encryptor_unavailable => TransportFailure::EncryptorUnavailable,
			nonce_generation_failed => TransportFailure::NonceGenerationFailed,
			rekey_required => TransportFailure::RekeyRequired,
			renewal_bound_exceeded => TransportFailure::RenewalBoundExceeded,
			tamper_detected => TransportFailure::TamperDetected,
			streams_exhausted => TransportFailure::StreamsExhausted,
			budget_exhausted => TransportFailure::BudgetExhausted,
			policy_rejection => TransportFailure::PolicyRejection,
		}
	}

	#[test]
	fn a_peer_refusal_names_the_transit_code_of_its_status() {
		let refused = TransportError::OperationFailed(TransportFailure::ResourceExhausted);
		assert_eq!(Code::from(&refused), Code::Transit(TransitCode::ResourceExhausted));
	}

	#[test]
	fn a_local_failure_names_its_transport_code() {
		let exhausted = TransportError::OperationFailed(TransportFailure::StreamsExhausted);
		assert_eq!(Code::from(&exhausted), Code::Transport(TransportCode::StreamsExhausted));
	}

	#[test]
	fn a_transport_error_inside_an_engine_error_names_its_own_code() {
		let closed = TightBeamError::TransportError(TransportError::ConnectionClosed);
		assert_eq!(Code::from(&closed), Code::Transport(TransportCode::ConnectionClosed));
	}

	#[test]
	fn an_opaque_body_names_the_layer_it_lacks() {
		let sealed = TightBeamError::OpaqueBody(BodyTransform::Decrypt);
		let compressed = TightBeamError::OpaqueBody(BodyTransform::Inflate);
		assert_eq!(Code::from(&sealed), Code::OpaqueBody(BodyLayer::Opener));
		assert_eq!(Code::from(&compressed), Code::OpaqueBody(BodyLayer::Inflator));
	}

	#[test]
	fn a_refused_work_submission_names_the_status_of_the_gateway() {
		let refused = TightBeamError::WorkRefused(TransitStatus::PermissionDenied);
		assert_eq!(Code::from(&refused), Code::WorkRefused(TransitCode::PermissionDenied));
	}

	tb_cases! {
		fn only_ok_names_no_refusal(status: TransitStatus) -> TestResult {
			let code = TransitCode::from(status);
			let refused = TransitCode::refusal(code.to_str());
			assert_eq!(refused.is_none(), status == TransitStatus::Ok);
			Ok(())
		}
		cases {
			ok => TransitStatus::Ok,
			cancelled => TransitStatus::Cancelled,
			unknown => TransitStatus::Unknown,
			not_found => TransitStatus::NotFound,
			unavailable => TransitStatus::Unavailable,
			unauthenticated => TransitStatus::Unauthenticated,
		}
	}
}
