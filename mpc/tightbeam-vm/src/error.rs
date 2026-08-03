//! Typed failures for the bytecode VM, split by pipeline stage.
//!
//! [`CodecError`] covers wire decoding, [`ValidationError`] covers
//! static program checks, and [`VmError`] is the umbrella the hosts
//! (party and consumer) surface at runtime.

use core::fmt;
use std::error::Error as StdError;

use ark_serialize::SerializationError;
use stoffelcrypto::common::share::ShareError;
use stoffelcrypto::honeybadger::robust_interpolate::InterpolateError;
use stoffelnet::network_utils::{ClientId, PartyId};
use tightbeam_mpc::{Error as AdapterError, SessionError};

use crate::isa::Opcode;

/// Which register bank a diagnostic refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bank {
	/// Public registers.
	Clear,
	/// Share-holding registers.
	Secret,
}

impl fmt::Display for Bank {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Clear => f.write_str("clear"),
			Self::Secret => f.write_str("secret"),
		}
	}
}

/// Why program or control-message bytes refused to decode.
#[derive(Debug)]
pub enum CodecError {
	/// The DER envelope is malformed.
	Der(der::Error),
	/// A wire instruction names an opcode this build does not know.
	UnknownOpcode {
		/// The unrecognized opcode octet.
		opcode: u8,
	},
	/// A control message names a kind this build does not know.
	UnknownControlKind {
		/// The unrecognized kind octet.
		kind: u8,
	},
	/// A wire instruction's argument list does not fit its opcode.
	MalformedArguments {
		/// The opcode whose argument shape was violated.
		opcode: Opcode,
	},
	/// The program was built against a format this build does not read.
	UnsupportedVersion {
		/// The version the program names.
		found: u32,
	},
	/// An argument exceeds the register index space.
	RegisterOverflow {
		/// The oversized argument.
		value: u64,
	},
	/// A field-element payload refused to deserialize.
	Share(SerializationError),
	/// A control echo carried a digest of the wrong width.
	MalformedControlDigest {
		/// The received octet count.
		len: usize,
	},
}

impl fmt::Display for CodecError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Der(cause) => write!(f, "the DER envelope is malformed: {cause}"),
			Self::UnknownOpcode { opcode } => write!(f, "unknown opcode {opcode}"),
			Self::UnknownControlKind { kind } => write!(f, "unknown control message kind {kind}"),
			Self::MalformedArguments { opcode } => {
				write!(f, "malformed arguments for opcode {opcode:?}")
			}
			Self::UnsupportedVersion { found } => {
				write!(f, "unsupported bytecode version {found}")
			}
			Self::RegisterOverflow { value } => {
				write!(f, "argument {value} exceeds the register index space")
			}
			Self::Share(cause) => write!(f, "the field payload refused to deserialize: {cause}"),
			Self::MalformedControlDigest { len } => {
				write!(f, "a control echo carried a {len}-octet digest, expected 32")
			}
		}
	}
}

impl StdError for CodecError {
	fn source(&self) -> Option<&(dyn StdError + 'static)> {
		match self {
			Self::Der(cause) => Some(cause),
			_ => None,
		}
	}
}

impl From<der::Error> for CodecError {
	fn from(cause: der::Error) -> Self {
		Self::Der(cause)
	}
}

impl From<SerializationError> for CodecError {
	fn from(cause: SerializationError) -> Self {
		Self::Share(cause)
	}
}

/// Why a decoded program was refused before execution.
#[derive(Debug)]
pub enum ValidationError {
	/// The instruction stream is empty.
	EmptyProgram,
	/// The instruction stream exceeds the execution ceiling.
	TooManyInstructions {
		/// Instructions in the program.
		count: usize,
		/// The ceiling.
		max: usize,
	},
	/// A range runs past the end of its register bank.
	BankExceeded {
		/// The offending bank.
		bank: Bank,
		/// One past the highest register the range touches.
		end: u64,
		/// The bank size.
		max: u64,
	},
	/// A zero-length operand carries no work.
	EmptyRange {
		/// The offending instruction's index.
		index: usize,
	},
	/// Operand ranges of one instruction disagree on length.
	LengthMismatch {
		/// The offending instruction's index.
		index: usize,
	},
	/// A register is read before anything wrote it.
	UninitializedRead {
		/// The offending instruction's index.
		index: usize,
		/// The bank holding the register.
		bank: Bank,
		/// The register that was never written.
		register: u64,
	},
	/// The program never delivers a result.
	MissingOut,
	/// `Out` must be the final instruction.
	OutNotLast {
		/// The offending instruction's index.
		index: usize,
	},
	/// Only one `Out` is supported per program.
	MultipleOut {
		/// The second `Out`'s index.
		index: usize,
	},
	/// Two input declarations name the same client.
	DuplicateInputClient {
		/// The repeated client.
		client: ClientId,
	},
	/// Two input declarations write overlapping registers.
	OverlappingInputs {
		/// The client whose declaration overlaps an earlier one.
		client: ClientId,
	},
	/// A fixed-point precision is unusable (f = 0, k <= f, or k too wide).
	InvalidPrecision {
		/// The offending instruction's index.
		index: usize,
	},
	/// A fixed-point division names a zero divisor.
	ZeroDivisor {
		/// The offending instruction's index.
		index: usize,
	},
	/// Two fixed-point instructions name different precisions; the
	/// engine pins one format per program.
	MixedPrecision {
		/// The offending instruction's index.
		index: usize,
	},
}

impl fmt::Display for ValidationError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::EmptyProgram => f.write_str("the program has no instructions"),
			Self::TooManyInstructions { count, max } => {
				write!(f, "the program has {count} instructions, the ceiling is {max}")
			}
			Self::BankExceeded { bank, end, max } => {
				write!(f, "a range runs to {end} in the {bank} bank of size {max}")
			}
			Self::EmptyRange { index } => {
				write!(f, "instruction {index} carries a zero-length operand")
			}
			Self::LengthMismatch { index } => {
				write!(f, "instruction {index} has operands of differing lengths")
			}
			Self::UninitializedRead { index, bank, register } => {
				write!(f, "instruction {index} reads {bank} register {register} before any write")
			}
			Self::MissingOut => f.write_str("the program never delivers a result"),
			Self::OutNotLast { index } => {
				write!(f, "instruction {index} is Out but not the final instruction")
			}
			Self::MultipleOut { index } => {
				write!(f, "instruction {index} is a second Out")
			}
			Self::DuplicateInputClient { client } => {
				write!(f, "client {client} declares inputs twice")
			}
			Self::OverlappingInputs { client } => {
				write!(f, "the inputs of client {client} overlap an earlier declaration")
			}
			Self::InvalidPrecision { index } => {
				write!(f, "instruction {index} carries an unusable fixed-point precision")
			}
			Self::ZeroDivisor { index } => {
				write!(f, "instruction {index} divides by zero")
			}
			Self::MixedPrecision { index } => {
				write!(f, "instruction {index} names a second fixed-point precision")
			}
		}
	}
}

impl StdError for ValidationError {}

/// Why a VM host operation failed.
#[derive(Debug)]
pub enum VmError {
	/// Wire bytes refused to decode.
	Codec(CodecError),
	/// The program failed static validation.
	Validation(ValidationError),
	/// The session round machine or the engine failed.
	Session(SessionError),
	/// The tightbeam adapter failed.
	Adapter(AdapterError),
	/// Reveal reconstruction failed after every sender reported.
	Interpolate(InterpolateError),
	/// Local share arithmetic failed (degree or id disagreement).
	Share(ShareError),
	/// A reveal did not gather enough shares before its deadline.
	RevealTimeout {
		/// The reveal's program-order ordinal.
		ordinal: u32,
	},
	/// The control inbox closed mid-protocol.
	ControlClosed,
	/// No program arrived before the submission deadline.
	SubmissionTimeout,
	/// A party echoed a different digest than the one submitted.
	DigestMismatch {
		/// The disagreeing party.
		party: PartyId,
	},
	/// A party rejected the submitted program.
	Rejected {
		/// The rejecting party.
		party: PartyId,
	},
	/// The input store never produced shares for a declared client.
	MissingInput {
		/// The declared client with no shares.
		client: ClientId,
	},
	/// The engine cannot serve a program's fixed-point precision: the
	/// process-global format is already pinned to a different one.
	PrecisionUnsupported {
		/// Total bits the program asked for.
		k: u8,
		/// Fractional bits the program asked for.
		f: u8,
	},
	/// A client's derived share count disagrees with its declaration.
	InputArity {
		/// The declaring client.
		client: ClientId,
		/// Elements the declaration names.
		expected: usize,
		/// Elements the input store produced.
		got: usize,
	},
	/// A share or reconstructed polynomial carried no field elements.
	EmptySecret,
}

impl fmt::Display for VmError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Codec(cause) => write!(f, "the wire bytes refused to decode: {cause}"),
			Self::Validation(cause) => write!(f, "the program failed validation: {cause}"),
			Self::Session(cause) => write!(f, "the session failed: {cause}"),
			Self::Adapter(cause) => write!(f, "the tightbeam adapter failed: {cause}"),
			Self::Interpolate(cause) => write!(f, "reveal reconstruction failed: {cause}"),
			Self::Share(cause) => write!(f, "share arithmetic failed: {cause}"),
			Self::RevealTimeout { ordinal } => {
				write!(f, "reveal {ordinal} missed its share deadline")
			}
			Self::ControlClosed => f.write_str("the control inbox closed mid-protocol"),
			Self::SubmissionTimeout => f.write_str("no program arrived before the deadline"),
			Self::DigestMismatch { party } => {
				write!(f, "party {party} echoed a different program digest")
			}
			Self::Rejected { party } => {
				write!(f, "party {party} rejected the program")
			}
			Self::MissingInput { client } => {
				write!(f, "no input shares for declared client {client}")
			}
			Self::PrecisionUnsupported { k, f: fractional } => {
				write!(f, "the engine cannot serve fixed-point precision ({k}, {fractional})")
			}
			Self::InputArity { client, expected, got } => {
				write!(f, "client {client} declared {expected} inputs, the store produced {got}")
			}
			Self::EmptySecret => f.write_str("a share or reconstructed polynomial was empty"),
		}
	}
}

impl StdError for VmError {
	fn source(&self) -> Option<&(dyn StdError + 'static)> {
		match self {
			Self::Codec(cause) => Some(cause),
			Self::Validation(cause) => Some(cause),
			Self::Session(cause) => Some(cause),
			Self::Adapter(cause) => Some(cause),
			Self::Interpolate(cause) => Some(cause),
			Self::Share(cause) => Some(cause),
			_ => None,
		}
	}
}

impl From<CodecError> for VmError {
	fn from(cause: CodecError) -> Self {
		Self::Codec(cause)
	}
}

impl From<ValidationError> for VmError {
	fn from(cause: ValidationError) -> Self {
		Self::Validation(cause)
	}
}

impl From<SessionError> for VmError {
	fn from(cause: SessionError) -> Self {
		Self::Session(cause)
	}
}

impl From<AdapterError> for VmError {
	fn from(cause: AdapterError) -> Self {
		Self::Adapter(cause)
	}
}

impl From<InterpolateError> for VmError {
	fn from(cause: InterpolateError) -> Self {
		Self::Interpolate(cause)
	}
}

impl From<ShareError> for VmError {
	fn from(cause: ShareError) -> Self {
		Self::Share(cause)
	}
}

/// Crate-wide result alias.
pub type Result<T> = core::result::Result<T, VmError>;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn every_stage_error_displays_context() {
		let errors = [
			VmError::Codec(CodecError::UnknownOpcode { opcode: 200 }),
			VmError::Validation(ValidationError::MissingOut),
			VmError::RevealTimeout { ordinal: 3 },
			VmError::ControlClosed,
			VmError::SubmissionTimeout,
			VmError::DigestMismatch { party: 2 },
			VmError::Rejected { party: 4 },
		];

		let all_named = errors.iter().all(|error| !error.to_string().is_empty());
		assert!(all_named);
	}

	#[test]
	fn stage_causes_are_chained() {
		let error = VmError::from(CodecError::UnsupportedVersion { found: 9 });
		assert!(error.source().is_some());
	}

	#[test]
	fn uninitialized_reads_name_bank_and_register() {
		let error = ValidationError::UninitializedRead { index: 2, bank: Bank::Secret, register: 7 };
		let text = error.to_string();
		assert!(text.contains("secret"));
		assert!(text.contains('7'));
	}
}
