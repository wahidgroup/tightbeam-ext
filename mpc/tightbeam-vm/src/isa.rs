//! The instruction set: a closed data model over two typed register banks.
//!
//! Registers hold field elements: the clear bank is public, the secret
//! bank holds shares. Operands are contiguous ranges, and interactive
//! instructions carry unrestricted argument lists so one instruction costs
//! one batched protocol round regardless of how many values it touches.

use stoffelnet::network_utils::ClientId;

use crate::error::CodecError;

/// A contiguous run of clear (public) registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClearRange {
	/// First register index in the run.
	pub base: u32,
	/// Number of registers in the run.
	pub len: u32,
}

/// A contiguous run of secret (share-holding) registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretRange {
	/// First register index in the run.
	pub base: u32,
	/// Number of registers in the run.
	pub len: u32,
}

impl ClearRange {
	/// One register past the end of the run.
	pub fn end(&self) -> u64 {
		u64::from(self.base) + u64::from(self.len)
	}
}

impl SecretRange {
	/// One register past the end of the run.
	pub fn end(&self) -> u64 {
		u64::from(self.base) + u64::from(self.len)
	}
}

/// One element-wise multiplication: `dest = a * b`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MulTriple {
	/// Where the products land.
	pub dest: SecretRange,
	/// Left factors.
	pub a: SecretRange,
	/// Right factors.
	pub b: SecretRange,
}

/// A fixed-point format: `k` total bits, `f` of them fractional. A raw
/// register value `v` represents the real number `v / 2^f`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedPrecision {
	/// Total bit width of the represented values.
	pub k: u8,
	/// Fractional bits (the truncation amount per multiplication).
	pub f: u8,
}

/// A consumer's input declaration: which client feeds which registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputDecl {
	/// The client providing the secrets.
	pub client: ClientId,
	/// Where the derived input shares land.
	pub dest: SecretRange,
}

/// One VM instruction. Linear operations run locally; `MulS`, `Reveal`,
/// and `Out` are interactive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
	/// Load public immediates into clear registers.
	LdC {
		/// Where the immediates land; `dest.len == values.len()`.
		dest: ClearRange,
		/// The immediates, lifted into the field at execution.
		values: Vec<u64>,
	},
	/// Element-wise secret addition: `dest = a + b`.
	AddS {
		/// Where the sums land.
		dest: SecretRange,
		/// Left addends.
		a: SecretRange,
		/// Right addends.
		b: SecretRange,
	},
	/// Element-wise secret subtraction: `dest = a - b`.
	SubS {
		/// Where the differences land.
		dest: SecretRange,
		/// Minuends.
		a: SecretRange,
		/// Subtrahends.
		b: SecretRange,
	},
	/// Element-wise clear addend: `dest = a + c`.
	AddC {
		/// Where the sums land.
		dest: SecretRange,
		/// Secret addends.
		a: SecretRange,
		/// Clear addends.
		c: ClearRange,
	},
	/// Element-wise clear subtrahend: `dest = a - c`.
	SubC {
		/// Where the differences land.
		dest: SecretRange,
		/// Secret minuends.
		a: SecretRange,
		/// Clear subtrahends.
		c: ClearRange,
	},
	/// Element-wise clear scaling: `dest = a * c`.
	MulC {
		/// Where the products land.
		dest: SecretRange,
		/// Secret factors.
		a: SecretRange,
		/// Clear factors.
		c: ClearRange,
	},
	/// Batched Beaver multiplication: every triple in one protocol
	/// round.
	MulS {
		/// The element-wise multiplications to run together.
		pairs: Vec<MulTriple>,
	},
	/// Element-wise fixed-point multiplication with probabilistic
	/// truncation: `dest = (a * b) / 2^f`, one engine round per element.
	FpMulS {
		/// Where the truncated products land.
		dest: SecretRange,
		/// Left factors (raw fixed-point values).
		a: SecretRange,
		/// Right factors (raw fixed-point values).
		b: SecretRange,
		/// The fixed-point format all three ranges share.
		precision: FixedPrecision,
	},
	/// Element-wise fixed-point division by a public constant:
	/// `dest = a / divisor`, with probabilistic truncation.
	FpDivC {
		/// Where the quotients land.
		dest: SecretRange,
		/// Secret dividends (raw fixed-point values).
		a: SecretRange,
		/// The public divisor's raw fixed-point value (`real * 2^f`).
		divisor: u64,
		/// The fixed-point format dividend and divisor share.
		precision: FixedPrecision,
	},
	/// Reveal secrets to every party: `dest = open(src)`.
	Reveal {
		/// Where the revealed values land.
		dest: ClearRange,
		/// The shares to open.
		src: SecretRange,
	},
	/// Send result shares to one client, which reconstructs privately.
	Out {
		/// The receiving client.
		client: ClientId,
		/// The shares to send.
		src: SecretRange,
	},
}

/// Wire discriminants for [`Instruction`]. Values are stable: they are
/// covered by the program digest and reused across releases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
	/// [`Instruction::LdC`].
	LdC = 1,
	/// [`Instruction::AddS`].
	AddS = 2,
	/// [`Instruction::SubS`].
	SubS = 3,
	/// [`Instruction::AddC`].
	AddC = 4,
	/// [`Instruction::SubC`].
	SubC = 5,
	/// [`Instruction::MulC`].
	MulC = 6,
	/// [`Instruction::MulS`].
	MulS = 7,
	/// [`Instruction::Reveal`].
	Reveal = 8,
	/// [`Instruction::Out`].
	Out = 9,
	/// [`Instruction::FpMulS`].
	FpMulS = 10,
	/// [`Instruction::FpDivC`].
	FpDivC = 11,
}

impl From<Opcode> for u8 {
	fn from(opcode: Opcode) -> Self {
		opcode as u8
	}
}

impl TryFrom<u8> for Opcode {
	type Error = CodecError;

	fn try_from(value: u8) -> core::result::Result<Self, Self::Error> {
		match value {
			1 => Ok(Self::LdC),
			2 => Ok(Self::AddS),
			3 => Ok(Self::SubS),
			4 => Ok(Self::AddC),
			5 => Ok(Self::SubC),
			6 => Ok(Self::MulC),
			7 => Ok(Self::MulS),
			8 => Ok(Self::Reveal),
			9 => Ok(Self::Out),
			10 => Ok(Self::FpMulS),
			11 => Ok(Self::FpDivC),
			_ => Err(CodecError::UnknownOpcode { opcode: value }),
		}
	}
}

impl Instruction {
	/// The wire discriminant for this instruction.
	pub fn opcode(&self) -> Opcode {
		match self {
			Self::LdC { .. } => Opcode::LdC,
			Self::AddS { .. } => Opcode::AddS,
			Self::SubS { .. } => Opcode::SubS,
			Self::AddC { .. } => Opcode::AddC,
			Self::SubC { .. } => Opcode::SubC,
			Self::MulC { .. } => Opcode::MulC,
			Self::MulS { .. } => Opcode::MulS,
			Self::FpMulS { .. } => Opcode::FpMulS,
			Self::FpDivC { .. } => Opcode::FpDivC,
			Self::Reveal { .. } => Opcode::Reveal,
			Self::Out { .. } => Opcode::Out,
		}
	}
}

/// A decoded, not yet validated program.
///
/// Only [`ValidProgram::try_from`](crate::validate::ValidProgram) and
/// [`ValidProgram::from_der`](crate::validate::ValidProgram::from_der)
/// turn this into something the executor accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
	/// Bytecode format version this program was built against.
	pub version: u32,
	/// Which clients feed which secret registers before execution.
	pub inputs: Vec<InputDecl>,
	/// The straight-line instruction stream.
	pub instructions: Vec<Instruction>,
}

/// The bytecode format version this build reads and writes.
pub const VERSION: u32 = 1;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn unknown_opcode_octets_are_rejected() {
		let outcome = Opcode::try_from(0);
		assert!(matches!(outcome, Err(CodecError::UnknownOpcode { opcode: 0 })));
	}

	#[test]
	fn instructions_name_their_opcode() {
		let mul = Instruction::MulS { pairs: Vec::new() };
		assert_eq!(mul.opcode(), Opcode::MulS);

		let out = Instruction::Out { client: 100, src: SecretRange { base: 0, len: 1 } };
		assert_eq!(out.opcode(), Opcode::Out);
	}

	#[test]
	fn range_ends_do_not_overflow() {
		let range = SecretRange { base: u32::MAX, len: u32::MAX };
		assert_eq!(range.end(), u64::from(u32::MAX) * 2);
	}
}
