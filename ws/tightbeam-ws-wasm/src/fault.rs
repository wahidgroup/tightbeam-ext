//! The codes and the structured JavaScript errors of the wasm bindings.
//!
//! A failure crosses the boundary as a JavaScript `Error` named
//! `TightbeamTransportError`. Its `code` is a variant of one of three string
//! enums, and the declarations that `wasm-bindgen` writes carry each enum as a
//! TypeScript union, so every code a TypeScript caller observes has one
//! declaration:
//!
//! - [`RefusalCode`]: a value the bindings refuse before an engine or a transport error exists.
//! - [`TransportCode`]: an error of the tightbeam engine or transport.
//! - [`TransitCode`]: a gRPC canonical status, the code of a peer refusal.
//!
//! A refusal of one field names it on `path`, such as `matrix.n`, and a
//! refused work submission carries its transit status on `status`.

#[cfg(target_arch = "wasm32")]
use core::fmt::Display;

#[cfg(target_arch = "wasm32")]
use js_sys::{Error as JsError, Reflect};
use wasm_bindgen::prelude::*;

use tightbeam::policy::TransitStatus;
#[cfg(any(test, target_arch = "wasm32"))]
use tightbeam::transport::{TransportError, TransportFailure};
#[cfg(any(test, target_arch = "wasm32"))]
use tightbeam::TightBeamError;

#[cfg(any(test, target_arch = "wasm32"))]
use crate::build::BuildRefusal;
#[cfg(any(test, target_arch = "wasm32"))]
use crate::compress::ZstdRefusal;
#[cfg(target_arch = "wasm32")]
use crate::promise::Record;

/// A code enum and its TypeScript union, from one list of variants. The
/// label of each variant is the `code` JavaScript reads, and the declarations
/// that `wasm-bindgen` writes carry the union of the labels, so TypeScript
/// copies no code by hand.
macro_rules! code_enum {
	(
		$(#[$meta:meta])*
		pub enum $name:ident in $section:ident {
			$(
				$(#[$doc:meta])*
				$variant:ident = $label:tt,
			)*
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

		#[cfg(target_arch = "wasm32")]
		impl $name {
			/// Whether `label` is the label of a variant.
			fn contains(label: &str) -> bool {
				matches!(label, $($label)|*)
			}
		}

		#[cfg(target_arch = "wasm32")]
		#[wasm_bindgen(typescript_custom_section)]
		const $section: &'static str = concat!(
			"\n/**\n * Every `code` label of `",
			stringify!($name),
			"`.\n */\nexport type ",
			stringify!($name),
			" =",
			$("\n\t| \"", $label, "\"",)*
			";\n"
		);
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

code_enum! {
	/// A value the bindings refuse before an engine or a transport error exists.
	/// The label is the `code` JavaScript reads.
	pub enum RefusalCode in REFUSAL_CODE_UNION {
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
		/// The `signPrehash` member of a `TransportSigner` is not a function.
		InvalidSigner = "InvalidSigner",
		/// `approveReceipt` is not a function.
		InvalidApproveReceipt = "InvalidApproveReceipt",
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
		/// The options of a dial are not an object, or their signal is no
		/// `AbortSignal`.
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
	/// A peer refusal carries no transport code: its code is the
	/// [`TransitCode`] of the status the peer answered with.
	pub enum TransportCode in TRANSPORT_CODE_UNION {
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
		/// `TransportError::HandshakeError`, and `TightBeamError::HandshakeError`.
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
		/// `TransportFailure::RekeyRequired`, and `TightBeamError::RekeyRequired`.
		RekeyRequired = "RekeyRequired",
		/// `TransportFailure::RenewalBoundExceeded`, and `TightBeamError::RenewalBoundExceeded`.
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
		/// `TightBeamError::WorkRefused`.
		WorkRefused = "WorkRefused",
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
		/// `TightBeamError::OpaqueBody`.
		OpaqueBody = "OpaqueBody",
		/// a variant that tightbeam added after this crate, which `#[non_exhaustive]` lets reach the last arm.
		Unrecognized = "Unrecognized",
	}
}

code_enum! {
	/// A gRPC canonical status (`google.rpc.Code`), by the name tightbeam writes
	/// for it: the code of a peer refusal, and the status a stream handler
	/// answers with.
	///
	/// The labels copy the names of [`TransitStatus::as_str`], because a
	/// `wasm-bindgen` string enum takes literal discriminants, and the pin test
	/// `transit_code_labels_match_transit_status` holds them equal.
	pub enum TransitCode in TRANSIT_CODE_UNION {
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

/// The status of each code. The match covers every status tightbeam
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

#[cfg(any(test, target_arch = "wasm32"))]
/// The code of one failure, from the family that decides it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Code {
	/// A value the bindings refused.
	Refusal(RefusalCode),
	/// An error of the engine or the transport.
	Transport(TransportCode),
	/// A refusal of the peer, by the status it answered with.
	Transit(TransitCode),
}

#[cfg(target_arch = "wasm32")]
impl Code {
	/// The label JavaScript reads.
	pub(crate) fn to_str(self) -> &'static str {
		match self {
			Self::Refusal(code) => code.to_str(),
			Self::Transport(code) => code.to_str(),
			Self::Transit(code) => code.to_str(),
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
impl From<TransitCode> for Code {
	fn from(code: TransitCode) -> Self {
		Self::Transit(code)
	}
}

#[cfg(any(test, target_arch = "wasm32"))]
/// A peer refusal names the [`TransitCode`] of its status, through
/// tightbeam's own conversion, and a local failure names its
/// [`TransportCode`].
impl From<TransportFailure> for Code {
	fn from(failure: TransportFailure) -> Self {
		match TransitStatus::try_from(failure) {
			Ok(status) => Self::Transit(TransitCode::from(status)),
			Err(_) => Self::Transport(TransportCode::local(failure)),
		}
	}
}

#[cfg(any(test, target_arch = "wasm32"))]
impl TransportCode {
	/// The code of a failure that carries no wire status. A peer refusal
	/// never reaches its arm, because [`Code::from`] reads its status first.
	fn local(failure: TransportFailure) -> Self {
		match failure {
			TransportFailure::EncodingFailed => Self::EncodingFailed,
			TransportFailure::EncryptionFailed => Self::EncryptionFailed,
			TransportFailure::SizeExceeded => Self::SizeExceeded,
			TransportFailure::EncryptorUnavailable => Self::EncryptorUnavailable,
			TransportFailure::NonceGenerationFailed => Self::NonceGenerationFailed,
			TransportFailure::RekeyRequired => Self::RekeyRequired,
			TransportFailure::RenewalBoundExceeded => Self::RenewalBoundExceeded,
			TransportFailure::TamperDetected => Self::TamperDetected,
			TransportFailure::StreamsExhausted => Self::StreamsExhausted,
			TransportFailure::BudgetExhausted => Self::BudgetExhausted,
			TransportFailure::PolicyRejection => Self::PolicyRejection,
			// A peer refusal carries a wire status, which `Code::from` reads first,
			// so these arms never run. Each variant has an arm, so a failure that
			// tightbeam adds fails to compile here until it has a code.
			TransportFailure::Cancelled
			| TransportFailure::Unknown
			| TransportFailure::InvalidArgument
			| TransportFailure::DeadlineExceeded
			| TransportFailure::NotFound
			| TransportFailure::AlreadyExists
			| TransportFailure::PermissionDenied
			| TransportFailure::ResourceExhausted
			| TransportFailure::FailedPrecondition
			| TransportFailure::Aborted
			| TransportFailure::OutOfRange
			| TransportFailure::Unimplemented
			| TransportFailure::Internal
			| TransportFailure::Unavailable
			| TransportFailure::DataLoss
			| TransportFailure::Unauthenticated => Self::Unrecognized,
		}
	}
}

#[cfg(any(test, target_arch = "wasm32"))]
/// One arm per variant of `TransportError`. An operation failure names its
/// inner failure, which is the signal callers branch on. The type is
/// `#[non_exhaustive]`, so the last arm names a variant this crate does not
/// know as [`TransportCode::Unrecognized`].
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
/// `#[non_exhaustive]`, so the last arm names a variant this crate does not
/// know as [`TransportCode::Unrecognized`].
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
			TightBeamError::OpaqueBody(..) => TransportCode::OpaqueBody,
			TightBeamError::MissingResponse => TransportCode::MissingResponse,
			TightBeamError::WorkRefused(..) => TransportCode::WorkRefused,
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
			BuildRefusal::EmptyKeyId => Self::EmptyKeyId,
			BuildRefusal::EmptySignerId => Self::EmptySignerId,
		}
	}
}

/// The code labels a structured transport error carries, as one membership
/// check, so a guard narrows an unknown value to a transport error only when
/// its `code` is a label the engine declares.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct Codes;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl Codes {
	/// Whether `label` is a code of [`RefusalCode`] or [`TransportCode`], or
	/// a refusal of [`TransitCode`]. `Ok` names no refusal, so no transport
	/// error carries it.
	pub fn has(label: &str) -> bool {
		let refusal = RefusalCode::contains(label);
		let transport = TransportCode::contains(label);
		let transit = label != TransitCode::Ok.to_str() && TransitCode::contains(label);
		refusal || transport || transit
	}
}

/// A structured JavaScript error: an `Error` named `TightbeamTransportError`
/// whose `code` names the failure, whose `path` names the field a refusal
/// concerns, and whose `status` names the transit status of a refused work
/// submission.
///
/// Engine, transport, and binding failures convert into it, so a binding
/// returns `Result<_, JsFault>` and reaches each conversion through `?`.
#[cfg(target_arch = "wasm32")]
#[derive(Debug)]
pub struct JsFault {
	code: Code,
	message: String,
	path: String,
	status: Option<TransitCode>,
}

#[cfg(target_arch = "wasm32")]
impl JsFault {
	/// The failure `code`, explained by `message`, at no field.
	fn new(code: impl Into<Code>, message: impl Display) -> Self {
		Self {
			code: code.into(),
			message: message.to_string(),
			path: String::new(),
			status: None,
		}
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
		let JsFault { code, message, path, status } = fault;
		let text = if path.is_empty() {
			message
		} else {
			format!("{path}: {message}")
		};

		let js_error = JsError::new(&text);
		js_error.set_name(TRANSPORT_ERROR_NAME);
		let error: JsValue = js_error.into();

		// `Reflect::set` on a freshly built `Error` object cannot fail.
		let _ = Reflect::set(&error, &JsValue::from_str("code"), &JsValue::from_str(code.to_str()));
		if !path.is_empty() {
			let _ = Reflect::set(&error, &JsValue::from_str("path"), &JsValue::from_str(&path));
		}
		if let Some(status) = status {
			let _ = Reflect::set(&error, &JsValue::from_str("status"), &JsValue::from_str(status.to_str()));
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

/// A refusal of a work submission also carries the gateway's transit status
/// on `status`, the gRPC canonical name the serve path uses too, so a
/// JavaScript caller branches on the status without parsing the message.
#[cfg(target_arch = "wasm32")]
impl From<TightBeamError> for JsFault {
	fn from(error: TightBeamError) -> Self {
		let code = Code::from(&error);
		let status = match &error {
			TightBeamError::WorkRefused(status) => Some(TransitCode::from(*status)),
			_ => None,
		};

		let fault = Self::new(code, error);
		Self { status, ..fault }
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
impl From<tightbeam::der::Error> for JsFault {
	fn from(error: tightbeam::der::Error) -> Self {
		Self::from(TightBeamError::from(error))
	}
}

#[cfg(target_arch = "wasm32")]
impl TransitCode {
	/// The status that a stream handler's settlement answers with: the status
	/// `value` names, as a label or as the `code` of a rejection. `Ok` names
	/// no refusal, so it answers `Unknown`, as every other value does.
	pub(crate) fn of_js(value: &JsValue) -> TransitStatus {
		let label = value.as_string();
		let label = label.or_else(|| Record::member(value, "settled.code").as_string());
		let named = label.as_deref().and_then(Self::from_str);

		match named {
			Some(Self::Ok) | None => TransitStatus::Unknown,
			Some(code) => TransitStatus::from(code),
		}
	}
}

/// The outcome of a binding call, as the unit tests of every binding read
/// its refusal.
#[cfg(all(test, target_arch = "wasm32"))]
pub(crate) trait Refused {
	/// The `code` that a refused outcome carries, as a JavaScript caller
	/// reads it, or `None` for an outcome that succeeded.
	fn code(self) -> Option<String>;
}

#[cfg(all(test, target_arch = "wasm32"))]
impl<T, E: Into<JsValue>> Refused for Result<T, E> {
	fn code(self) -> Option<String> {
		let refusal: JsValue = self.err()?.into();
		let code = Record::member(&refusal, "refusal.code");
		code.as_string()
	}
}

#[cfg(test)]
mod tests {
	use tightbeam::asn1::BodyTransform;
	use tightbeam::policy::TransitStatus;
	use tightbeam::tb_cases;
	use tightbeam::transport::{TransportError, TransportFailure};
	use tightbeam::TightBeamError;

	use super::{Code, TransitCode, TransportCode};

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
	fn an_opaque_body_names_the_label_of_its_upstream_variant() {
		let sealed = TightBeamError::OpaqueBody(BodyTransform::Decrypt);
		assert_eq!(Code::from(&sealed), Code::Transport(TransportCode::OpaqueBody));
		assert_eq!(TransportCode::OpaqueBody.to_str(), "OpaqueBody");
	}
}
