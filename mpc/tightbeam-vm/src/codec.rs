//! Program wire format: X.690 DER, digest-addressed.
//!
//! Every instruction rides as `SEQUENCE { opcode, args }` with a flat
//! `u64` argument list, so the DER layer stays uniform and the opcode
//! table owns each argument shape. The program digest is SHA3-256 over
//! the exact DER bytes.

use core::fmt;

use der::{Decode, Encode, Sequence};
use stoffelnet::network_utils::ClientId;
use tightbeam::crypto::hash::{Digest, Sha3_256};

use crate::error::CodecError;
use crate::isa::{
	ClearRange, FixedPrecision, InputDecl, Instruction, MulTriple, Opcode, Program, SecretRange, VERSION,
};

/// SHA3-256 of a program's DER bytes: its identity across parties.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramDigest(
	/// Digest octets in engine byte order.
	pub [u8; 32],
);

impl ProgramDigest {
	/// A 32-bit engine instance id derived from the digest, so every
	/// party and the consumer key their protocol sessions identically.
	pub fn instance_id(&self) -> u32 {
		u32::from_le_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
	}
}

impl fmt::Display for ProgramDigest {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		for byte in self.0 {
			write!(f, "{byte:02x}")?;
		}

		Ok(())
	}
}

impl AsRef<[u8]> for ProgramDigest {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

/// One input declaration on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
struct WireInput {
	/// The providing client.
	client: u64,
	/// First destination register.
	base: u32,
	/// Number of inputs.
	len: u32,
}

/// One instruction on the wire: opcode plus a flat argument list.
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
struct WireInstruction {
	/// The [`Opcode`] octet.
	opcode: u8,
	/// Arguments, interpreted per opcode.
	args: Vec<u64>,
}

/// The full program envelope.
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
struct WireProgram {
	/// Bytecode format version.
	version: u32,
	/// Input declarations.
	inputs: Vec<WireInput>,
	/// The instruction stream.
	instructions: Vec<WireInstruction>,
}

/// Narrow a wire argument into the register index space.
fn register(value: u64) -> Result<u32, CodecError> {
	u32::try_from(value).map_err(|_| CodecError::RegisterOverflow { value })
}

/// Read `[base, len]` at `at` as a secret range.
fn secret_range(args: &[u64], at: usize, opcode: Opcode) -> Result<SecretRange, CodecError> {
	let base = args.get(at).ok_or(CodecError::MalformedArguments { opcode })?;
	let len = args.get(at + 1).ok_or(CodecError::MalformedArguments { opcode })?;
	Ok(SecretRange { base: register(*base)?, len: register(*len)? })
}

/// Read `[base, len]` at `at` as a clear range.
fn clear_range(args: &[u64], at: usize, opcode: Opcode) -> Result<ClearRange, CodecError> {
	let secret = secret_range(args, at, opcode)?;
	Ok(ClearRange { base: secret.base, len: secret.len })
}

/// Narrow a wire argument into a bit width octet (`Pack`'s width).
fn width_component(value: u64, opcode: Opcode) -> Result<u8, CodecError> {
	u8::try_from(value).map_err(|_| CodecError::MalformedArguments { opcode })
}

impl From<&Instruction> for WireInstruction {
	fn from(instruction: &Instruction) -> Self {
		let opcode = u8::from(instruction.opcode());
		let args = match instruction {
			Instruction::LdC { dest, values } => {
				let mut args = vec![u64::from(dest.base), u64::from(dest.len)];
				args.extend(values.iter().copied());
				args
			}
			Instruction::AddS { dest, a, b } | Instruction::SubS { dest, a, b } => {
				vec![u64::from(dest.base), u64::from(a.base), u64::from(b.base), u64::from(dest.len)]
			}
			Instruction::AddC { dest, a, c } | Instruction::SubC { dest, a, c } | Instruction::MulC { dest, a, c } => {
				vec![u64::from(dest.base), u64::from(a.base), u64::from(c.base), u64::from(dest.len)]
			}
			Instruction::MulS { pairs } | Instruction::AndS { pairs } | Instruction::XorS { pairs } => {
				let mut args = Vec::with_capacity(pairs.len() * 4);
				for pair in pairs {
					args.push(u64::from(pair.dest.base));
					args.push(u64::from(pair.a.base));
					args.push(u64::from(pair.b.base));
					args.push(u64::from(pair.dest.len));
				}

				args
			}
			Instruction::NotS { dest, a } => {
				vec![u64::from(dest.base), u64::from(a.base), u64::from(dest.len)]
			}
			Instruction::Mux { dest, cond, t, f } => {
				vec![
					u64::from(dest.base),
					u64::from(cond.base),
					u64::from(t.base),
					u64::from(f.base),
					u64::from(dest.len),
				]
			}
			Instruction::Pack { dest, src, width } => {
				vec![
					u64::from(dest.base),
					u64::from(src.base),
					u64::from(dest.len),
					u64::from(*width),
				]
			}
			Instruction::BitDec { dest, src, width } => {
				vec![u64::from(dest.base), u64::from(src.base), u64::from(src.len), u64::from(*width)]
			}
			Instruction::Sbox { dest, src } => {
				vec![u64::from(dest.base), u64::from(src.base), u64::from(dest.len / 8)]
			}
			Instruction::ByteXor { dest, a, b } => {
				vec![u64::from(dest.base), u64::from(a.base), u64::from(b.base), u64::from(dest.len)]
			}
			Instruction::FpMulS { dest, a, b, precision } => {
				vec![
					u64::from(dest.base),
					u64::from(a.base),
					u64::from(b.base),
					u64::from(dest.len),
					u64::from(precision.k),
					u64::from(precision.f),
				]
			}
			Instruction::FpDivC { dest, a, divisor, precision } => {
				vec![
					u64::from(dest.base),
					u64::from(a.base),
					u64::from(dest.len),
					*divisor,
					u64::from(precision.k),
					u64::from(precision.f),
				]
			}
			Instruction::Reveal { dest, src } => {
				vec![u64::from(dest.base), u64::from(src.base), u64::from(dest.len)]
			}
			Instruction::Out { client, src } => {
				vec![*client as u64, u64::from(src.base), u64::from(src.len)]
			}
		};

		Self { opcode, args }
	}
}

impl TryFrom<&WireInstruction> for Instruction {
	type Error = CodecError;

	fn try_from(wire: &WireInstruction) -> Result<Self, Self::Error> {
		let opcode = Opcode::try_from(wire.opcode)?;
		let args = wire.args.as_slice();

		match opcode {
			Opcode::LdC => decode_ldc(args),
			Opcode::AddS | Opcode::SubS => decode_binary_secret(opcode, args),
			Opcode::AddC | Opcode::SubC | Opcode::MulC => decode_clear_operand(opcode, args),
			Opcode::MulS => Ok(Instruction::MulS { pairs: decode_pairs(opcode, args)? }),
			Opcode::AndS => Ok(Instruction::AndS { pairs: decode_pairs(opcode, args)? }),
			Opcode::XorS => Ok(Instruction::XorS { pairs: decode_pairs(opcode, args)? }),
			Opcode::NotS => decode_not(args),
			Opcode::Mux => decode_mux(args),
			Opcode::Pack => decode_pack(args),
			Opcode::BitDec => decode_bit_dec(args),
			Opcode::Sbox => decode_sbox(args),
			Opcode::ByteXor => decode_byte_xor(args),
			Opcode::FpMulS => decode_fp_mul(args),
			Opcode::FpDivC => decode_fp_div(args),
			Opcode::Reveal => decode_reveal(args),
			Opcode::Out => decode_out(args),
		}
	}
}

/// Narrow a wire argument into a precision component.
fn precision_component(value: u64, opcode: Opcode) -> Result<u8, CodecError> {
	u8::try_from(value).map_err(|_| CodecError::MalformedArguments { opcode })
}

fn decode_fp_mul(args: &[u64]) -> Result<Instruction, CodecError> {
	let opcode = Opcode::FpMulS;
	if args.len() != 6 {
		return Err(CodecError::MalformedArguments { opcode });
	}

	let len = register(args[3])?;
	let dest = SecretRange { base: register(args[0])?, len };
	let a = SecretRange { base: register(args[1])?, len };
	let b = SecretRange { base: register(args[2])?, len };
	let precision = FixedPrecision {
		k: precision_component(args[4], opcode)?,
		f: precision_component(args[5], opcode)?,
	};

	Ok(Instruction::FpMulS { dest, a, b, precision })
}

fn decode_fp_div(args: &[u64]) -> Result<Instruction, CodecError> {
	let opcode = Opcode::FpDivC;
	if args.len() != 6 {
		return Err(CodecError::MalformedArguments { opcode });
	}

	let len = register(args[2])?;
	let dest = SecretRange { base: register(args[0])?, len };
	let a = SecretRange { base: register(args[1])?, len };
	let divisor = args[3];
	let precision = FixedPrecision {
		k: precision_component(args[4], opcode)?,
		f: precision_component(args[5], opcode)?,
	};

	Ok(Instruction::FpDivC { dest, a, divisor, precision })
}

fn decode_ldc(args: &[u64]) -> Result<Instruction, CodecError> {
	let opcode = Opcode::LdC;
	let dest = clear_range(args, 0, opcode)?;
	let values: Vec<u64> = args[2..].to_vec();
	if values.len() != dest.len as usize {
		return Err(CodecError::MalformedArguments { opcode });
	}

	Ok(Instruction::LdC { dest, values })
}

fn decode_binary_secret(opcode: Opcode, args: &[u64]) -> Result<Instruction, CodecError> {
	if args.len() != 4 {
		return Err(CodecError::MalformedArguments { opcode });
	}

	let len = register(args[3])?;
	let dest = SecretRange { base: register(args[0])?, len };
	let a = SecretRange { base: register(args[1])?, len };
	let b = SecretRange { base: register(args[2])?, len };

	match opcode {
		Opcode::AddS => Ok(Instruction::AddS { dest, a, b }),
		_ => Ok(Instruction::SubS { dest, a, b }),
	}
}

fn decode_clear_operand(opcode: Opcode, args: &[u64]) -> Result<Instruction, CodecError> {
	if args.len() != 4 {
		return Err(CodecError::MalformedArguments { opcode });
	}

	let len = register(args[3])?;
	let dest = SecretRange { base: register(args[0])?, len };
	let a = SecretRange { base: register(args[1])?, len };
	let c = ClearRange { base: register(args[2])?, len };

	match opcode {
		Opcode::AddC => Ok(Instruction::AddC { dest, a, c }),
		Opcode::SubC => Ok(Instruction::SubC { dest, a, c }),
		_ => Ok(Instruction::MulC { dest, a, c }),
	}
}

/// Decode a batched-pairs argument list shared by `MulS`, `AndS`, and
/// `XorS`: `[dest, a, b, len]` repeated once per element-wise operand
/// pair.
fn decode_pairs(opcode: Opcode, args: &[u64]) -> Result<Vec<MulTriple>, CodecError> {
	if args.is_empty() || args.len() % 4 != 0 {
		return Err(CodecError::MalformedArguments { opcode });
	}

	let mut pairs = Vec::with_capacity(args.len() / 4);
	for chunk in args.chunks_exact(4) {
		let len = register(chunk[3])?;
		let dest = SecretRange { base: register(chunk[0])?, len };
		let a = SecretRange { base: register(chunk[1])?, len };
		let b = SecretRange { base: register(chunk[2])?, len };
		pairs.push(MulTriple { dest, a, b });
	}

	Ok(pairs)
}

fn decode_not(args: &[u64]) -> Result<Instruction, CodecError> {
	let opcode = Opcode::NotS;
	if args.len() != 3 {
		return Err(CodecError::MalformedArguments { opcode });
	}

	let len = register(args[2])?;
	let dest = SecretRange { base: register(args[0])?, len };
	let a = SecretRange { base: register(args[1])?, len };

	Ok(Instruction::NotS { dest, a })
}

fn decode_mux(args: &[u64]) -> Result<Instruction, CodecError> {
	let opcode = Opcode::Mux;
	if args.len() != 5 {
		return Err(CodecError::MalformedArguments { opcode });
	}

	let len = register(args[4])?;
	let dest = SecretRange { base: register(args[0])?, len };
	let cond = SecretRange { base: register(args[1])?, len: 1 };
	let t = SecretRange { base: register(args[2])?, len };
	let f = SecretRange { base: register(args[3])?, len };

	Ok(Instruction::Mux { dest, cond, t, f })
}

fn decode_pack(args: &[u64]) -> Result<Instruction, CodecError> {
	let opcode = Opcode::Pack;
	if args.len() != 4 {
		return Err(CodecError::MalformedArguments { opcode });
	}

	let width = width_component(args[3], opcode)?;
	let dest_len = register(args[2])?;
	let dest = SecretRange { base: register(args[0])?, len: dest_len };
	let src_len = u64::from(dest_len) * u64::from(width);
	let src = SecretRange { base: register(args[1])?, len: register(src_len)? };

	Ok(Instruction::Pack { dest, src, width })
}

/// `BitDec` carries the source element count on the wire (the given
/// quantity a builder call already knows) and derives the destination
/// bit count as `src.len * width`, the inverse of `Pack`'s derivation.
fn decode_bit_dec(args: &[u64]) -> Result<Instruction, CodecError> {
	let opcode = Opcode::BitDec;
	if args.len() != 4 {
		return Err(CodecError::MalformedArguments { opcode });
	}

	let width = width_component(args[3], opcode)?;
	let src_len = register(args[2])?;
	let src = SecretRange { base: register(args[1])?, len: src_len };
	let dest_len = u64::from(src_len) * u64::from(width);
	let dest = SecretRange { base: register(args[0])?, len: register(dest_len)? };

	Ok(Instruction::BitDec { dest, src, width })
}

fn decode_sbox(args: &[u64]) -> Result<Instruction, CodecError> {
	let opcode = Opcode::Sbox;
	if args.len() != 3 {
		return Err(CodecError::MalformedArguments { opcode });
	}

	let nbytes = register(args[2])?;
	let bit_len = register(u64::from(nbytes) * 8)?;
	let dest = SecretRange { base: register(args[0])?, len: bit_len };
	let src = SecretRange { base: register(args[1])?, len: bit_len };

	Ok(Instruction::Sbox { dest, src })
}

fn decode_byte_xor(args: &[u64]) -> Result<Instruction, CodecError> {
	let opcode = Opcode::ByteXor;
	if args.len() != 4 {
		return Err(CodecError::MalformedArguments { opcode });
	}

	let len = register(args[3])?;
	let dest = SecretRange { base: register(args[0])?, len };
	let a = SecretRange { base: register(args[1])?, len };
	let b = SecretRange { base: register(args[2])?, len };

	Ok(Instruction::ByteXor { dest, a, b })
}

fn decode_reveal(args: &[u64]) -> Result<Instruction, CodecError> {
	let opcode = Opcode::Reveal;
	if args.len() != 3 {
		return Err(CodecError::MalformedArguments { opcode });
	}

	let len = register(args[2])?;
	let dest = ClearRange { base: register(args[0])?, len };
	let src = SecretRange { base: register(args[1])?, len };

	Ok(Instruction::Reveal { dest, src })
}

fn decode_out(args: &[u64]) -> Result<Instruction, CodecError> {
	let opcode = Opcode::Out;
	if args.len() != 3 {
		return Err(CodecError::MalformedArguments { opcode });
	}

	let client = args[0] as ClientId;
	let src = SecretRange { base: register(args[1])?, len: register(args[2])? };

	Ok(Instruction::Out { client, src })
}

/// Serialize a program to its canonical DER bytes.
pub fn encode(program: &Program) -> Result<Vec<u8>, CodecError> {
	let inputs = program
		.inputs
		.iter()
		.map(|decl| WireInput { client: decl.client as u64, base: decl.dest.base, len: decl.dest.len })
		.collect();
	let instructions = program.instructions.iter().map(WireInstruction::from).collect();

	let wire = WireProgram { version: program.version, inputs, instructions };
	let bytes = wire.to_der()?;
	Ok(bytes)
}

/// Parse DER bytes into a (not yet validated) program.
pub fn decode(bytes: &[u8]) -> Result<Program, CodecError> {
	let wire = WireProgram::from_der(bytes)?;
	if wire.version != VERSION {
		return Err(CodecError::UnsupportedVersion { found: wire.version });
	}

	let inputs = wire
		.inputs
		.iter()
		.map(|decl| InputDecl {
			client: decl.client as ClientId,
			dest: SecretRange { base: decl.base, len: decl.len },
		})
		.collect();

	let instructions = wire
		.instructions
		.iter()
		.map(Instruction::try_from)
		.collect::<Result<Vec<Instruction>, CodecError>>()?;

	Ok(Program { version: wire.version, inputs, instructions })
}

/// FIPS 202 SHA3-256 over the exact DER bytes.
pub fn digest(bytes: &[u8]) -> ProgramDigest {
	let hashed = Sha3_256::digest(bytes);
	ProgramDigest(hashed.into())
}

#[cfg(test)]
mod tests {
	use super::*;

	fn must_encode(program: &Program) -> Vec<u8> {
		encode(program).expect("the program encodes")
	}

	fn must_decode(bytes: &[u8]) -> Program {
		decode(bytes).expect("the bytes decode")
	}

	fn must_instruction(wire: &WireInstruction) -> Instruction {
		Instruction::try_from(wire).expect("the instruction decodes")
	}

	fn sample_program() -> Program {
		Program {
			version: VERSION,
			inputs: vec![InputDecl { client: 100, dest: SecretRange { base: 0, len: 2 } }],
			instructions: vec![
				Instruction::LdC { dest: ClearRange { base: 0, len: 2 }, values: vec![3, 5] },
				Instruction::MulC {
					dest: SecretRange { base: 2, len: 2 },
					a: SecretRange { base: 0, len: 2 },
					c: ClearRange { base: 0, len: 2 },
				},
				Instruction::MulS {
					pairs: vec![MulTriple {
						dest: SecretRange { base: 4, len: 1 },
						a: SecretRange { base: 2, len: 1 },
						b: SecretRange { base: 3, len: 1 },
					}],
				},
				Instruction::FpMulS {
					dest: SecretRange { base: 5, len: 1 },
					a: SecretRange { base: 2, len: 1 },
					b: SecretRange { base: 3, len: 1 },
					precision: FixedPrecision { k: 16, f: 4 },
				},
				Instruction::FpDivC {
					dest: SecretRange { base: 6, len: 1 },
					a: SecretRange { base: 5, len: 1 },
					divisor: 32,
					precision: FixedPrecision { k: 16, f: 4 },
				},
				Instruction::Reveal { dest: ClearRange { base: 2, len: 1 }, src: SecretRange { base: 4, len: 1 } },
				Instruction::AndS {
					pairs: vec![MulTriple {
						dest: SecretRange { base: 7, len: 1 },
						a: SecretRange { base: 2, len: 1 },
						b: SecretRange { base: 3, len: 1 },
					}],
				},
				Instruction::XorS {
					pairs: vec![MulTriple {
						dest: SecretRange { base: 8, len: 1 },
						a: SecretRange { base: 2, len: 1 },
						b: SecretRange { base: 3, len: 1 },
					}],
				},
				Instruction::NotS { dest: SecretRange { base: 9, len: 1 }, a: SecretRange { base: 7, len: 1 } },
				Instruction::Mux {
					dest: SecretRange { base: 10, len: 1 },
					cond: SecretRange { base: 9, len: 1 },
					t: SecretRange { base: 7, len: 1 },
					f: SecretRange { base: 8, len: 1 },
				},
				Instruction::Pack {
					dest: SecretRange { base: 11, len: 1 },
					src: SecretRange { base: 7, len: 3 },
					width: 3,
				},
				Instruction::BitDec {
					dest: SecretRange { base: 12, len: 4 },
					src: SecretRange { base: 11, len: 2 },
					width: 2,
				},
				Instruction::Sbox { dest: SecretRange { base: 24, len: 8 }, src: SecretRange { base: 16, len: 8 } },
				Instruction::ByteXor {
					dest: SecretRange { base: 32, len: 1 },
					a: SecretRange { base: 11, len: 1 },
					b: SecretRange { base: 11, len: 1 },
				},
				Instruction::Out { client: 100, src: SecretRange { base: 4, len: 1 } },
			],
		}
	}

	#[test]
	fn programs_round_trip_through_der() {
		let program = sample_program();
		let bytes = must_encode(&program);
		let recovered = must_decode(&bytes);
		assert_eq!(recovered, program);
	}

	#[test]
	fn digests_are_stable_and_content_addressed() {
		let program = sample_program();
		let bytes = must_encode(&program);
		let first = digest(&bytes);
		let second = digest(&bytes);
		assert_eq!(first, second);

		let mut altered = program;
		altered.instructions.pop();

		let altered_bytes = must_encode(&altered);
		assert_ne!(digest(&altered_bytes), first);
	}

	#[test]
	fn instance_ids_derive_from_the_digest_prefix() {
		let fixed = ProgramDigest([7; 32]);
		assert_eq!(fixed.instance_id(), u32::from_le_bytes([7, 7, 7, 7]));
	}

	#[test]
	fn digests_display_as_hex() {
		let fixed = ProgramDigest([0xab; 32]);
		let text = fixed.to_string();
		assert_eq!(text.len(), 64);
		assert!(text.chars().all(|c| c == 'a' || c == 'b'));
	}

	#[test]
	fn foreign_versions_are_refused() {
		let program = Program { version: 99, inputs: Vec::new(), instructions: Vec::new() };
		let bytes = must_encode(&program);
		let outcome = decode(&bytes);
		assert!(matches!(outcome, Err(CodecError::UnsupportedVersion { found: 99 })));
	}

	#[test]
	fn truncated_bytes_are_refused() {
		let program = sample_program();
		let bytes = must_encode(&program);
		let outcome = decode(&bytes[..bytes.len() - 3]);
		assert!(matches!(outcome, Err(CodecError::Der(_))));
	}

	#[test]
	fn ldc_value_count_must_match_its_range() {
		let wire = WireInstruction { opcode: u8::from(Opcode::LdC), args: vec![0, 3, 1, 2] };
		let outcome = Instruction::try_from(&wire);
		assert!(matches!(outcome, Err(CodecError::MalformedArguments { opcode: Opcode::LdC })));
	}

	#[test]
	fn muls_argument_lists_must_be_whole_triples() {
		let wire = WireInstruction { opcode: u8::from(Opcode::MulS), args: vec![0, 1, 2] };
		let outcome = Instruction::try_from(&wire);
		assert!(matches!(outcome, Err(CodecError::MalformedArguments { opcode: Opcode::MulS })));
	}

	#[test]
	fn ands_argument_lists_must_be_whole_triples() {
		let wire = WireInstruction { opcode: u8::from(Opcode::AndS), args: vec![0, 1, 2] };
		let outcome = Instruction::try_from(&wire);
		assert!(matches!(outcome, Err(CodecError::MalformedArguments { opcode: Opcode::AndS })));
	}

	#[test]
	fn xors_argument_lists_must_be_whole_triples() {
		let wire = WireInstruction { opcode: u8::from(Opcode::XorS), args: vec![0, 1, 2] };
		let outcome = Instruction::try_from(&wire);
		assert!(matches!(outcome, Err(CodecError::MalformedArguments { opcode: Opcode::XorS })));
	}

	#[test]
	fn nots_argument_lists_must_have_three_entries() {
		let wire = WireInstruction { opcode: u8::from(Opcode::NotS), args: vec![0, 1] };
		let outcome = Instruction::try_from(&wire);
		assert!(matches!(outcome, Err(CodecError::MalformedArguments { opcode: Opcode::NotS })));
	}

	#[test]
	fn mux_argument_lists_must_have_five_entries() {
		let wire = WireInstruction { opcode: u8::from(Opcode::Mux), args: vec![0, 1, 2, 3] };
		let outcome = Instruction::try_from(&wire);
		assert!(matches!(outcome, Err(CodecError::MalformedArguments { opcode: Opcode::Mux })));
	}

	#[test]
	fn pack_argument_lists_must_have_four_entries() {
		let wire = WireInstruction { opcode: u8::from(Opcode::Pack), args: vec![0, 1, 2] };
		let outcome = Instruction::try_from(&wire);
		assert!(matches!(outcome, Err(CodecError::MalformedArguments { opcode: Opcode::Pack })));
	}

	#[test]
	fn pack_width_must_fit_one_octet() {
		let wire = WireInstruction { opcode: u8::from(Opcode::Pack), args: vec![0, 1, 1, 300] };
		let outcome = Instruction::try_from(&wire);
		assert!(matches!(outcome, Err(CodecError::MalformedArguments { opcode: Opcode::Pack })));
	}

	#[test]
	fn pack_derives_its_source_range_from_dest_len_times_width() {
		let wire = WireInstruction { opcode: u8::from(Opcode::Pack), args: vec![10, 0, 2, 3] };
		let instruction = must_instruction(&wire);
		assert!(matches!(
			instruction,
			Instruction::Pack {
				dest: SecretRange { base: 10, len: 2 },
				src: SecretRange { base: 0, len: 6 },
				width: 3
			}
		));
	}

	#[test]
	fn bit_dec_argument_lists_must_have_four_entries() {
		let wire = WireInstruction { opcode: u8::from(Opcode::BitDec), args: vec![0, 1, 2] };
		let outcome = Instruction::try_from(&wire);
		assert!(matches!(
			outcome,
			Err(CodecError::MalformedArguments { opcode: Opcode::BitDec })
		));
	}

	#[test]
	fn bit_dec_width_must_fit_one_octet() {
		let wire = WireInstruction { opcode: u8::from(Opcode::BitDec), args: vec![0, 1, 1, 300] };
		let outcome = Instruction::try_from(&wire);
		assert!(matches!(
			outcome,
			Err(CodecError::MalformedArguments { opcode: Opcode::BitDec })
		));
	}

	#[test]
	fn bit_dec_derives_its_dest_range_from_src_len_times_width() {
		let wire = WireInstruction { opcode: u8::from(Opcode::BitDec), args: vec![10, 0, 2, 3] };
		let instruction = must_instruction(&wire);
		assert!(matches!(
			instruction,
			Instruction::BitDec {
				dest: SecretRange { base: 10, len: 6 },
				src: SecretRange { base: 0, len: 2 },
				width: 3
			}
		));
	}

	#[test]
	fn mux_fixes_cond_width_at_one() {
		let wire = WireInstruction { opcode: u8::from(Opcode::Mux), args: vec![5, 2, 0, 1, 2] };
		let instruction = must_instruction(&wire);
		assert!(matches!(
			instruction,
			Instruction::Mux {
				dest: SecretRange { base: 5, len: 2 },
				cond: SecretRange { base: 2, len: 1 },
				t: SecretRange { base: 0, len: 2 },
				f: SecretRange { base: 1, len: 2 },
			}
		));
	}

	#[test]
	fn fixed_point_precision_components_must_fit_one_octet() {
		let wire = WireInstruction { opcode: u8::from(Opcode::FpMulS), args: vec![0, 1, 2, 1, 300, 4] };
		let outcome = Instruction::try_from(&wire);
		assert!(matches!(
			outcome,
			Err(CodecError::MalformedArguments { opcode: Opcode::FpMulS })
		));
	}

	#[test]
	fn oversized_register_indexes_are_refused() {
		let oversized = u64::from(u32::MAX) + 1;
		let wire = WireInstruction { opcode: u8::from(Opcode::Reveal), args: vec![oversized, 0, 1] };
		let outcome = Instruction::try_from(&wire);
		assert!(matches!(outcome, Err(CodecError::RegisterOverflow { .. })));
	}
}
