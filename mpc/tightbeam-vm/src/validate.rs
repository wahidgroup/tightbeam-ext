//! Static program validation: parse, don't validate.
//!
//! A [`ValidProgram`] is the only thing the executor accepts, so every
//! runtime invariant - bounds, operand shapes, def-before-use, exactly
//! one terminal `Out` - is discharged here, once, before any protocol
//! round runs. The check also prices the program: the [`Budget`] tells
//! the engine how much preprocessing material to generate up front.

use crate::codec::{decode, digest, encode, ProgramDigest};
use crate::error::{Bank, Result, ValidationError};
use crate::isa::{ClearRange, FixedPrecision, InputDecl, Instruction, MulTriple, Program, SecretRange};

/// Instruction ceiling: bounds worst-case execution work per program.
pub const MAX_INSTRUCTIONS: usize = 4096;

/// Registers per bank: bounds executor memory (one field element each).
pub const BANK_SIZE: u64 = 1 << 16;

/// Widest fixed-point format a program may name. Keeps the engine's
/// statistical-security headroom (`kappa + 2k - f` bits) far inside
/// the field's bit width.
pub const MAX_PRECISION_BITS: u8 = 32;

/// Preprocessing material one program consumes.
///
/// Fixed-point truncation is priced per element from the engine's own
/// accounting: each truncation burns `f` shared random bits and one
/// shared random integer, and generating each random bit itself costs
/// one Beaver triple and one random share.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Budget {
	/// Beaver triples: one per element-wise secret multiplication,
	/// plus the random-bit generation cost of fixed-point truncation.
	pub triples: usize,
	/// Random mask shares: one per declared input element, plus the
	/// random-bit generation cost of fixed-point truncation.
	pub random_shares: usize,
	/// Shared random bits: `f` per fixed-point truncation.
	pub prandbits: usize,
	/// Shared random integers: one per fixed-point truncation.
	pub prandints: usize,
}

/// A program that passed every static check, plus its identity and
/// price. The only entry points are [`ValidProgram::from_der`] (party
/// side) and [`ValidProgram::try_from`] a [`Program`] (consumer side),
/// so holding one proves the checks ran.
#[derive(Clone, Debug)]
pub struct ValidProgram {
	program: Program,
	bytes: Vec<u8>,
	digest: ProgramDigest,
	budget: Budget,
	precision: Option<FixedPrecision>,
	clear_top: u32,
	secret_top: u32,
}

impl ValidProgram {
	/// Decode and validate wire bytes (the party-side entry point).
	pub fn from_der(bytes: &[u8]) -> Result<Self> {
		let program = decode(bytes)?;
		let (budget, precision) = check(&program)?;
		let identity = digest(bytes);
		let (clear_top, secret_top) = tops(&program);

		Ok(Self {
			program,
			bytes: bytes.to_vec(),
			digest: identity,
			budget,
			precision,
			clear_top,
			secret_top,
		})
	}

	/// The validated instruction stream.
	pub fn program(&self) -> &Program {
		&self.program
	}

	/// The canonical DER bytes the digest covers.
	pub fn bytes(&self) -> &[u8] {
		&self.bytes
	}

	/// The program's identity across parties.
	pub fn digest(&self) -> ProgramDigest {
		self.digest
	}

	/// Preprocessing material the program consumes.
	pub fn budget(&self) -> Budget {
		self.budget
	}

	/// The program's single fixed-point format, if any instruction
	/// names one. Validation refuses mixed precisions.
	pub fn precision(&self) -> Option<FixedPrecision> {
		self.precision
	}

	/// One past the highest clear register touched: the clear-bank size
	/// the executor allocates.
	pub fn clear_top(&self) -> u32 {
		self.clear_top
	}

	/// One past the highest secret register touched: the secret-bank
	/// size the executor allocates.
	pub fn secret_top(&self) -> u32 {
		self.secret_top
	}
}

impl TryFrom<Program> for ValidProgram {
	type Error = crate::error::VmError;

	/// Encode and validate an in-memory program (the consumer-side
	/// entry point). The canonical bytes produced here are the ones
	/// submitted, so both sides digest identical input.
	fn try_from(program: Program) -> Result<Self> {
		let (budget, precision) = check(&program)?;
		let bytes = encode(&program)?;
		let identity = digest(&bytes);
		let (clear_top, secret_top) = tops(&program);

		Ok(Self { program, bytes, digest: identity, budget, precision, clear_top, secret_top })
	}
}

/// One past the highest register each bank touches. Runs on validated
/// programs, so `u32` cannot overflow (every end fits the bank size).
fn tops(program: &Program) -> (u32, u32) {
	let mut clear_top = 0u64;
	let mut secret_top = 0u64;

	for decl in &program.inputs {
		secret_top = secret_top.max(decl.dest.end());
	}

	for instruction in &program.instructions {
		match instruction {
			Instruction::LdC { dest, .. } => {
				clear_top = clear_top.max(dest.end());
			}
			Instruction::AddS { dest, a, b } | Instruction::SubS { dest, a, b } => {
				secret_top = secret_top.max(dest.end()).max(a.end()).max(b.end());
			}
			Instruction::AddC { dest, a, c } | Instruction::SubC { dest, a, c } | Instruction::MulC { dest, a, c } => {
				secret_top = secret_top.max(dest.end()).max(a.end());
				clear_top = clear_top.max(c.end());
			}
			Instruction::MulS { pairs } => {
				for pair in pairs {
					secret_top = secret_top.max(pair.dest.end()).max(pair.a.end()).max(pair.b.end());
				}
			}
			Instruction::FpMulS { dest, a, b, .. } => {
				secret_top = secret_top.max(dest.end()).max(a.end()).max(b.end());
			}
			Instruction::FpDivC { dest, a, .. } => {
				secret_top = secret_top.max(dest.end()).max(a.end());
			}
			Instruction::Reveal { dest, src } => {
				clear_top = clear_top.max(dest.end());
				secret_top = secret_top.max(src.end());
			}
			Instruction::Out { src, .. } => {
				secret_top = secret_top.max(src.end());
			}
		}
	}

	(clear_top as u32, secret_top as u32)
}

/// Written-register tracking for one bank.
struct WriteSet {
	bank: Bank,
	written: Vec<bool>,
}

impl WriteSet {
	fn new(bank: Bank) -> Self {
		Self { bank, written: vec![false; BANK_SIZE as usize] }
	}

	fn mark(&mut self, base: u32, len: u32) {
		for register in base..base + len {
			self.written[register as usize] = true;
		}
	}

	fn require(&self, index: usize, base: u32, len: u32) -> Result<()> {
		for register in base..base + len {
			if !self.written[register as usize] {
				return Err(ValidationError::UninitializedRead {
					index,
					bank: self.bank,
					register: u64::from(register),
				}
				.into());
			}
		}

		Ok(())
	}
}

fn check_secret_bounds(index: usize, range: &SecretRange) -> Result<()> {
	if range.len == 0 {
		return Err(ValidationError::EmptyRange { index }.into());
	}
	if range.end() > BANK_SIZE {
		return Err(ValidationError::BankExceeded { bank: Bank::Secret, end: range.end(), max: BANK_SIZE }.into());
	}

	Ok(())
}

fn check_clear_bounds(index: usize, range: &ClearRange) -> Result<()> {
	if range.len == 0 {
		return Err(ValidationError::EmptyRange { index }.into());
	}
	if range.end() > BANK_SIZE {
		return Err(ValidationError::BankExceeded { bank: Bank::Clear, end: range.end(), max: BANK_SIZE }.into());
	}

	Ok(())
}

fn check_inputs(inputs: &[InputDecl], secret: &mut WriteSet) -> Result<usize> {
	let mut seen_clients = Vec::new();
	let mut claimed: Vec<(u64, u64)> = Vec::new();
	let mut random_shares = 0usize;

	for decl in inputs {
		check_secret_bounds(0, &decl.dest)?;

		if seen_clients.contains(&decl.client) {
			return Err(ValidationError::DuplicateInputClient { client: decl.client }.into());
		}

		seen_clients.push(decl.client);

		let start = u64::from(decl.dest.base);
		let end = decl.dest.end();
		let overlaps = claimed.iter().any(|(from, to)| start < *to && end > *from);
		if overlaps {
			return Err(ValidationError::OverlappingInputs { client: decl.client }.into());
		}

		claimed.push((start, end));
		secret.mark(decl.dest.base, decl.dest.len);
		random_shares += decl.dest.len as usize;
	}

	Ok(random_shares)
}

/// Working state of one validation pass: written-register tracking,
/// the accruing [`Budget`], and the program's pinned fixed-point
/// format.
struct Checker {
	clear: WriteSet,
	secret: WriteSet,
	budget: Budget,
	fixed: Option<FixedPrecision>,
}

impl Default for Checker {
	fn default() -> Self {
		Self {
			clear: WriteSet::new(Bank::Clear),
			secret: WriteSet::new(Bank::Secret),
			budget: Budget::default(),
			fixed: None,
		}
	}
}

impl Checker {
	/// Refuse operand runs whose lengths disagree with the destination.
	fn require_lengths(index: usize, dest: u32, operands: &[u32]) -> Result<()> {
		if operands.iter().any(|len| *len != dest) {
			return Err(ValidationError::LengthMismatch { index }.into());
		}

		Ok(())
	}

	/// `LdC`: immediates land in clear registers, one per value.
	fn check_ldc(&mut self, index: usize, dest: &ClearRange, values: &[u64]) -> Result<()> {
		check_clear_bounds(index, dest)?;
		if values.len() != dest.len as usize {
			return Err(ValidationError::LengthMismatch { index }.into());
		}

		self.clear.mark(dest.base, dest.len);
		Ok(())
	}

	/// `AddS` / `SubS`: two written secret runs into a fresh one.
	fn check_binary_secret(
		&mut self,
		index: usize,
		dest: &SecretRange,
		a: &SecretRange,
		b: &SecretRange,
	) -> Result<()> {
		check_secret_bounds(index, dest)?;
		check_secret_bounds(index, a)?;
		check_secret_bounds(index, b)?;
		Self::require_lengths(index, dest.len, &[a.len, b.len])?;

		self.secret.require(index, a.base, a.len)?;
		self.secret.require(index, b.base, b.len)?;
		self.secret.mark(dest.base, dest.len);
		Ok(())
	}

	/// `AddC` / `SubC` / `MulC`: a written secret run against a written
	/// clear run.
	fn check_clear_operand(&mut self, index: usize, dest: &SecretRange, a: &SecretRange, c: &ClearRange) -> Result<()> {
		check_secret_bounds(index, dest)?;
		check_secret_bounds(index, a)?;
		check_clear_bounds(index, c)?;
		Self::require_lengths(index, dest.len, &[a.len, c.len])?;

		self.secret.require(index, a.base, a.len)?;
		self.clear.require(index, c.base, c.len)?;
		self.secret.mark(dest.base, dest.len);
		Ok(())
	}

	/// `MulS`: every batched pair checked like a binary secret op, each
	/// element priced at one Beaver triple.
	fn check_mul(&mut self, index: usize, pairs: &[MulTriple]) -> Result<()> {
		if pairs.is_empty() {
			return Err(ValidationError::EmptyRange { index }.into());
		}

		for pair in pairs {
			self.check_binary_secret(index, &pair.dest, &pair.a, &pair.b)?;
			self.budget.triples += pair.dest.len as usize;
		}

		Ok(())
	}

	/// `FpMulS`: a binary secret op plus one truncation per element,
	/// priced on top of the element-wise triples.
	fn check_fp_mul(
		&mut self,
		index: usize,
		dest: &SecretRange,
		operands: (&SecretRange, &SecretRange),
		precision: &FixedPrecision,
	) -> Result<()> {
		let (a, b) = operands;
		self.check_precision(index, precision)?;
		self.check_binary_secret(index, dest, a, b)?;

		let elements = dest.len as usize;
		self.budget.triples += elements;
		self.price_truncation(elements, precision);
		Ok(())
	}

	/// `FpDivC`: one written secret run scaled by a public divisor,
	/// plus one truncation per element.
	fn check_fp_div(
		&mut self,
		index: usize,
		dest: &SecretRange,
		a: &SecretRange,
		divisor: u64,
		precision: &FixedPrecision,
	) -> Result<()> {
		check_secret_bounds(index, dest)?;
		check_secret_bounds(index, a)?;
		self.check_precision(index, precision)?;

		if divisor == 0 {
			return Err(ValidationError::ZeroDivisor { index }.into());
		}
		Self::require_lengths(index, dest.len, &[a.len])?;

		self.secret.require(index, a.base, a.len)?;
		self.secret.mark(dest.base, dest.len);
		self.price_truncation(dest.len as usize, precision);
		Ok(())
	}

	/// `Reveal`: a written secret run opened into clear registers.
	fn check_reveal(&mut self, index: usize, dest: &ClearRange, src: &SecretRange) -> Result<()> {
		check_clear_bounds(index, dest)?;
		check_secret_bounds(index, src)?;
		Self::require_lengths(index, dest.len, &[src.len])?;

		self.secret.require(index, src.base, src.len)?;
		self.clear.mark(dest.base, dest.len);
		Ok(())
	}

	/// `Out`: terminal only, over a written secret run.
	fn check_out(&mut self, index: usize, last: usize, src: &SecretRange) -> Result<()> {
		if index != last {
			return Err(ValidationError::OutNotLast { index }.into());
		}

		check_secret_bounds(index, src)?;
		self.secret.require(index, src.base, src.len)?;
		Ok(())
	}

	/// Judge one instruction's fixed-point format and hold the program
	/// to a single one: the engine pins one precision per program run.
	fn check_precision(&mut self, index: usize, precision: &FixedPrecision) -> Result<()> {
		if precision.f == 0 || precision.k <= precision.f || precision.k > MAX_PRECISION_BITS {
			return Err(ValidationError::InvalidPrecision { index }.into());
		}

		match &self.fixed {
			Some(existing) if existing != precision => Err(ValidationError::MixedPrecision { index }.into()),
			Some(_) => Ok(()),
			None => {
				self.fixed = Some(*precision);
				Ok(())
			}
		}
	}

	/// Accrue the preprocessing cost of `elements` probabilistic
	/// truncations: `f` shared random bits each (one triple and one
	/// random share per bit) plus one shared random integer.
	fn price_truncation(&mut self, elements: usize, precision: &FixedPrecision) {
		let bits = elements * precision.f as usize;
		self.budget.triples += bits;
		self.budget.random_shares += bits;
		self.budget.prandbits += bits;
		self.budget.prandints += elements;
	}
}

/// Run every static check and price the program.
fn check(program: &Program) -> Result<(Budget, Option<FixedPrecision>)> {
	let count = program.instructions.len();

	if program.instructions.is_empty() {
		return Err(ValidationError::EmptyProgram.into());
	}

	if count > MAX_INSTRUCTIONS {
		return Err(ValidationError::TooManyInstructions { count, max: MAX_INSTRUCTIONS }.into());
	}

	let mut checker = Checker::default();
	checker.budget.random_shares = check_inputs(&program.inputs, &mut checker.secret)?;
	let last = count - 1;

	for (index, instruction) in program.instructions.iter().enumerate() {
		match instruction {
			Instruction::LdC { dest, values } => checker.check_ldc(index, dest, values)?,
			Instruction::AddS { dest, a, b } | Instruction::SubS { dest, a, b } => {
				checker.check_binary_secret(index, dest, a, b)?;
			}
			Instruction::AddC { dest, a, c } | Instruction::SubC { dest, a, c } | Instruction::MulC { dest, a, c } => {
				checker.check_clear_operand(index, dest, a, c)?;
			}
			Instruction::MulS { pairs } => checker.check_mul(index, pairs)?,
			Instruction::FpMulS { dest, a, b, precision } => {
				checker.check_fp_mul(index, dest, (a, b), precision)?;
			}
			Instruction::FpDivC { dest, a, divisor, precision } => {
				checker.check_fp_div(index, dest, a, *divisor, precision)?;
			}
			Instruction::Reveal { dest, src } => checker.check_reveal(index, dest, src)?,
			Instruction::Out { src, .. } => checker.check_out(index, last, src)?,
		}
	}

	let terminal = program.instructions.last();
	if !matches!(terminal, Some(Instruction::Out { .. })) {
		return Err(ValidationError::MissingOut.into());
	}

	Ok((checker.budget, checker.fixed))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::error::VmError;
	use crate::isa::VERSION;

	fn program(inputs: Vec<InputDecl>, instructions: Vec<Instruction>) -> Program {
		Program { version: VERSION, inputs, instructions }
	}

	fn two_input_product() -> Program {
		program(
			vec![InputDecl { client: 100, dest: SecretRange { base: 0, len: 2 } }],
			vec![
				Instruction::MulS {
					pairs: vec![MulTriple {
						dest: SecretRange { base: 2, len: 1 },
						a: SecretRange { base: 0, len: 1 },
						b: SecretRange { base: 1, len: 1 },
					}],
				},
				Instruction::Out { client: 100, src: SecretRange { base: 2, len: 1 } },
			],
		)
	}

	#[test]
	fn a_sound_program_is_priced() {
		let valid = ValidProgram::try_from(two_input_product()).expect("the program should validate");
		assert_eq!(valid.budget(), Budget { triples: 1, random_shares: 2, ..Budget::default() });
	}

	#[test]
	fn digests_match_the_wire_bytes() {
		let valid = ValidProgram::try_from(two_input_product()).expect("the program should validate");
		let reparsed = ValidProgram::from_der(valid.bytes()).expect("the bytes should re-validate");
		assert_eq!(reparsed.digest(), valid.digest());
	}

	#[test]
	fn empty_programs_are_refused() {
		let outcome = ValidProgram::try_from(program(Vec::new(), Vec::new()));
		assert!(matches!(outcome, Err(VmError::Validation(ValidationError::EmptyProgram))));
	}

	#[test]
	fn reads_of_never_written_secrets_are_refused() {
		let unsound = program(
			Vec::new(),
			vec![Instruction::Out { client: 100, src: SecretRange { base: 0, len: 1 } }],
		);

		let outcome = ValidProgram::try_from(unsound);
		assert!(matches!(
			outcome,
			Err(VmError::Validation(ValidationError::UninitializedRead {
				index: 0,
				bank: Bank::Secret,
				register: 0
			}))
		));
	}

	#[test]
	fn reads_of_never_written_clears_are_refused() {
		let unsound = program(
			vec![InputDecl { client: 100, dest: SecretRange { base: 0, len: 1 } }],
			vec![
				Instruction::MulC {
					dest: SecretRange { base: 1, len: 1 },
					a: SecretRange { base: 0, len: 1 },
					c: ClearRange { base: 0, len: 1 },
				},
				Instruction::Out { client: 100, src: SecretRange { base: 1, len: 1 } },
			],
		);

		let outcome = ValidProgram::try_from(unsound);
		assert!(matches!(
			outcome,
			Err(VmError::Validation(ValidationError::UninitializedRead {
				bank: Bank::Clear,
				..
			}))
		));
	}

	#[test]
	fn out_must_be_terminal() {
		let unsound = program(
			vec![InputDecl { client: 100, dest: SecretRange { base: 0, len: 2 } }],
			vec![
				Instruction::Out { client: 100, src: SecretRange { base: 0, len: 1 } },
				Instruction::AddS {
					dest: SecretRange { base: 2, len: 1 },
					a: SecretRange { base: 0, len: 1 },
					b: SecretRange { base: 1, len: 1 },
				},
			],
		);

		let outcome = ValidProgram::try_from(unsound);
		assert!(matches!(
			outcome,
			Err(VmError::Validation(ValidationError::OutNotLast { index: 0 }))
		));
	}

	#[test]
	fn programs_without_out_are_refused() {
		let unsound = program(
			vec![InputDecl { client: 100, dest: SecretRange { base: 0, len: 2 } }],
			vec![Instruction::AddS {
				dest: SecretRange { base: 2, len: 1 },
				a: SecretRange { base: 0, len: 1 },
				b: SecretRange { base: 1, len: 1 },
			}],
		);

		let outcome = ValidProgram::try_from(unsound);
		assert!(matches!(outcome, Err(VmError::Validation(ValidationError::MissingOut))));
	}

	#[test]
	fn operand_length_disagreements_are_refused() {
		let unsound = program(
			vec![InputDecl { client: 100, dest: SecretRange { base: 0, len: 3 } }],
			vec![
				Instruction::AddS {
					dest: SecretRange { base: 3, len: 2 },
					a: SecretRange { base: 0, len: 2 },
					b: SecretRange { base: 2, len: 1 },
				},
				Instruction::Out { client: 100, src: SecretRange { base: 3, len: 2 } },
			],
		);

		let outcome = ValidProgram::try_from(unsound);
		assert!(matches!(
			outcome,
			Err(VmError::Validation(ValidationError::LengthMismatch { index: 0 }))
		));
	}

	#[test]
	fn bank_overruns_are_refused() {
		let unsound = program(
			vec![InputDecl { client: 100, dest: SecretRange { base: u32::MAX - 1, len: 2 } }],
			vec![Instruction::Out { client: 100, src: SecretRange { base: 0, len: 1 } }],
		);

		let outcome = ValidProgram::try_from(unsound);
		assert!(matches!(
			outcome,
			Err(VmError::Validation(ValidationError::BankExceeded { bank: Bank::Secret, .. }))
		));
	}

	#[test]
	fn duplicate_input_clients_are_refused() {
		let unsound = program(
			vec![
				InputDecl { client: 100, dest: SecretRange { base: 0, len: 1 } },
				InputDecl { client: 100, dest: SecretRange { base: 1, len: 1 } },
			],
			vec![Instruction::Out { client: 100, src: SecretRange { base: 0, len: 1 } }],
		);

		let outcome = ValidProgram::try_from(unsound);
		assert!(matches!(
			outcome,
			Err(VmError::Validation(ValidationError::DuplicateInputClient { client: 100 }))
		));
	}

	#[test]
	fn overlapping_input_ranges_are_refused() {
		let unsound = program(
			vec![
				InputDecl { client: 100, dest: SecretRange { base: 0, len: 2 } },
				InputDecl { client: 101, dest: SecretRange { base: 1, len: 2 } },
			],
			vec![Instruction::Out { client: 100, src: SecretRange { base: 0, len: 1 } }],
		);

		let outcome = ValidProgram::try_from(unsound);
		assert!(matches!(
			outcome,
			Err(VmError::Validation(ValidationError::OverlappingInputs { client: 101 }))
		));
	}

	#[test]
	fn budgets_price_every_batched_triple() {
		let batched = program(
			vec![InputDecl { client: 100, dest: SecretRange { base: 0, len: 4 } }],
			vec![
				Instruction::MulS {
					pairs: vec![
						MulTriple {
							dest: SecretRange { base: 4, len: 2 },
							a: SecretRange { base: 0, len: 2 },
							b: SecretRange { base: 2, len: 2 },
						},
						MulTriple {
							dest: SecretRange { base: 6, len: 1 },
							a: SecretRange { base: 0, len: 1 },
							b: SecretRange { base: 1, len: 1 },
						},
					],
				},
				Instruction::Out { client: 100, src: SecretRange { base: 4, len: 3 } },
			],
		);

		let valid = ValidProgram::try_from(batched).expect("the program should validate");
		assert_eq!(valid.budget(), Budget { triples: 3, random_shares: 4, ..Budget::default() });
	}

	fn fixed_point_pipeline(mul_precision: FixedPrecision, div_precision: FixedPrecision, divisor: u64) -> Program {
		program(
			vec![InputDecl { client: 100, dest: SecretRange { base: 0, len: 2 } }],
			vec![
				Instruction::FpMulS {
					dest: SecretRange { base: 2, len: 1 },
					a: SecretRange { base: 0, len: 1 },
					b: SecretRange { base: 1, len: 1 },
					precision: mul_precision,
				},
				Instruction::FpDivC {
					dest: SecretRange { base: 3, len: 1 },
					a: SecretRange { base: 2, len: 1 },
					divisor,
					precision: div_precision,
				},
				Instruction::Out { client: 100, src: SecretRange { base: 3, len: 1 } },
			],
		)
	}

	#[test]
	fn fixed_point_truncation_is_priced() {
		let precision = FixedPrecision { k: 16, f: 4 };
		let valid = ValidProgram::try_from(fixed_point_pipeline(precision, precision, 32))
			.expect("the program should validate");

		// FpMulS: 1 mul triple + 4 bit triples; FpDivC: 4 bit triples.
		// Random shares: 2 inputs + 4 + 4 bits. One prandint each.
		assert_eq!(
			valid.budget(),
			Budget { triples: 9, random_shares: 10, prandbits: 8, prandints: 2 }
		);
		assert_eq!(valid.precision(), Some(precision));
	}

	#[test]
	fn unusable_precisions_are_refused() {
		let degenerate = FixedPrecision { k: 4, f: 4 };
		let outcome = ValidProgram::try_from(fixed_point_pipeline(degenerate, degenerate, 32));
		assert!(matches!(
			outcome,
			Err(VmError::Validation(ValidationError::InvalidPrecision { index: 0 }))
		));
	}

	#[test]
	fn mixed_precisions_are_refused() {
		let first = FixedPrecision { k: 16, f: 4 };
		let second = FixedPrecision { k: 16, f: 8 };
		let outcome = ValidProgram::try_from(fixed_point_pipeline(first, second, 32));
		assert!(matches!(
			outcome,
			Err(VmError::Validation(ValidationError::MixedPrecision { index: 1 }))
		));
	}

	#[test]
	fn zero_divisors_are_refused() {
		let precision = FixedPrecision { k: 16, f: 4 };
		let outcome = ValidProgram::try_from(fixed_point_pipeline(precision, precision, 0));
		assert!(matches!(
			outcome,
			Err(VmError::Validation(ValidationError::ZeroDivisor { index: 1 }))
		));
	}
}
