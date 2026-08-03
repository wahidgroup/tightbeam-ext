//! Consumer-side program construction with typed register handles.
//!
//! [`Secret`] and [`Clear`] handles are opaque range tokens minted by
//! the builder, so programs written through it cannot alias banks or
//! read unallocated registers by construction. The fluent surface is
//! infallible; every remaining soundness question (operand lengths,
//! terminal `Out`) is answered once by [`ProgramBuilder::build`], which
//! returns the same [`ValidProgram`] the parties re-derive from the
//! wire.

use stoffelnet::network_utils::ClientId;

use crate::error::Result;
use crate::isa::{ClearRange, FixedPrecision, InputDecl, Instruction, MulTriple, Program, SecretRange, VERSION};
use crate::validate::ValidProgram;

/// A handle to builder-allocated secret registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Secret {
	range: SecretRange,
}

impl Secret {
	/// Number of elements behind the handle.
	pub fn len(&self) -> u32 {
		self.range.len
	}

	/// Whether the handle is empty (never true for minted handles).
	pub fn is_empty(&self) -> bool {
		self.range.len == 0
	}
}

/// A handle to builder-allocated clear registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clear {
	range: ClearRange,
}

impl Clear {
	/// Number of elements behind the handle.
	pub fn len(&self) -> u32 {
		self.range.len
	}

	/// Whether the handle is empty (never true for minted handles).
	pub fn is_empty(&self) -> bool {
		self.range.len == 0
	}
}

/// Fluent straight-line program assembly.
#[derive(Debug, Default)]
pub struct ProgramBuilder {
	inputs: Vec<InputDecl>,
	instructions: Vec<Instruction>,
	outputs: Vec<(ClientId, SecretRange)>,
	next_secret: u32,
	next_clear: u32,
}

impl ProgramBuilder {
	fn alloc_secret(&mut self, len: u32) -> SecretRange {
		let range = SecretRange { base: self.next_secret, len };
		self.next_secret += len;
		range
	}

	fn alloc_clear(&mut self, len: u32) -> ClearRange {
		let range = ClearRange { base: self.next_clear, len };
		self.next_clear += len;
		range
	}

	/// Declare `len` secret inputs provided by `client`.
	pub fn input(&mut self, client: ClientId, len: u32) -> Secret {
		let dest = self.alloc_secret(len);
		self.inputs.push(InputDecl { client, dest });
		Secret { range: dest }
	}

	/// Load public constants, lifted into the field at execution.
	pub fn constants(&mut self, values: impl AsRef<[u64]>) -> Clear {
		let values = values.as_ref().to_vec();
		let dest = self.alloc_clear(values.len() as u32);
		self.instructions.push(Instruction::LdC { dest, values });
		Clear { range: dest }
	}

	/// Element-wise secret addition.
	pub fn add(&mut self, a: Secret, b: Secret) -> Secret {
		let dest = self.alloc_secret(a.range.len);
		self.instructions.push(Instruction::AddS { dest, a: a.range, b: b.range });
		Secret { range: dest }
	}

	/// Element-wise secret subtraction.
	pub fn sub(&mut self, a: Secret, b: Secret) -> Secret {
		let dest = self.alloc_secret(a.range.len);
		self.instructions.push(Instruction::SubS { dest, a: a.range, b: b.range });
		Secret { range: dest }
	}

	/// Element-wise clear addend.
	pub fn add_clear(&mut self, a: Secret, c: Clear) -> Secret {
		let dest = self.alloc_secret(a.range.len);
		self.instructions.push(Instruction::AddC { dest, a: a.range, c: c.range });
		Secret { range: dest }
	}

	/// Element-wise clear subtrahend.
	pub fn sub_clear(&mut self, a: Secret, c: Clear) -> Secret {
		let dest = self.alloc_secret(a.range.len);
		self.instructions.push(Instruction::SubC { dest, a: a.range, c: c.range });
		Secret { range: dest }
	}

	/// Element-wise clear scaling.
	pub fn mul_clear(&mut self, a: Secret, c: Clear) -> Secret {
		let dest = self.alloc_secret(a.range.len);
		self.instructions.push(Instruction::MulC { dest, a: a.range, c: c.range });
		Secret { range: dest }
	}

	/// Element-wise secret multiplication: one protocol round.
	pub fn mul(&mut self, a: Secret, b: Secret) -> Secret {
		let width = a.range.len;
		let products = self.mul_many(&[(a, b)]);
		match products.into_iter().next() {
			Some(product) => product,
			None => Secret { range: self.alloc_secret(width) },
		}
	}

	/// Batched secret multiplications: every pair in one protocol
	/// round, the round-efficiency workhorse.
	pub fn mul_many(&mut self, factors: &[(Secret, Secret)]) -> Vec<Secret> {
		let mut destinations = Vec::with_capacity(factors.len());
		let mut pairs = Vec::with_capacity(factors.len());

		for (a, b) in factors {
			let dest = self.alloc_secret(a.range.len);
			pairs.push(MulTriple { dest, a: a.range, b: b.range });
			destinations.push(Secret { range: dest });
		}

		self.instructions.push(Instruction::MulS { pairs });
		destinations
	}

	/// Element-wise fixed-point multiplication: the raw products are
	/// truncated by `2^f`, one protocol round per element.
	pub fn fp_mul(&mut self, a: Secret, b: Secret, precision: FixedPrecision) -> Secret {
		let dest = self.alloc_secret(a.range.len);
		self.instructions
			.push(Instruction::FpMulS { dest, a: a.range, b: b.range, precision });
		Secret { range: dest }
	}

	/// Element-wise fixed-point division by one public raw fixed-point
	/// divisor (`real * 2^f`).
	pub fn fp_div(&mut self, a: Secret, divisor: u64, precision: FixedPrecision) -> Secret {
		let dest = self.alloc_secret(a.range.len);
		self.instructions
			.push(Instruction::FpDivC { dest, a: a.range, divisor, precision });
		Secret { range: dest }
	}

	/// Open secrets to every party.
	pub fn reveal(&mut self, src: Secret) -> Clear {
		let dest = self.alloc_clear(src.range.len);
		self.instructions.push(Instruction::Reveal { dest, src: src.range });
		Clear { range: dest }
	}

	/// Deliver result shares to `client` as the program's terminal step.
	pub fn output(&mut self, client: ClientId, src: Secret) {
		self.outputs.push((client, src.range));
	}

	/// Assemble and statically validate the program.
	pub fn build(self) -> Result<ValidProgram> {
		let mut instructions = self.instructions;
		for (client, src) in self.outputs {
			instructions.push(Instruction::Out { client, src });
		}

		let program = Program { version: VERSION, inputs: self.inputs, instructions };
		let validated = ValidProgram::try_from(program)?;
		Ok(validated)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::error::{ValidationError, VmError};
	use crate::validate::Budget;

	const CLIENT: ClientId = 100;

	#[test]
	fn a_fluent_program_validates_and_prices() {
		let mut builder = ProgramBuilder::default();
		let inputs = builder.input(CLIENT, 2);
		let two = builder.constants([2, 2]);
		let doubled = builder.mul_clear(inputs, two);
		let product = builder.mul(doubled, inputs);
		let _opened = builder.reveal(product);
		builder.output(CLIENT, product);

		let valid = builder.build().expect("the built program should validate");
		assert_eq!(valid.budget(), Budget { triples: 2, random_shares: 2, ..Budget::default() });
	}

	#[test]
	fn built_programs_round_trip_to_the_same_digest() {
		let mut builder = ProgramBuilder::default();
		let inputs = builder.input(CLIENT, 2);
		let sum = builder.add(inputs, inputs);
		builder.output(CLIENT, sum);

		let valid = builder.build().expect("the built program should validate");
		let reparsed = ValidProgram::from_der(valid.bytes()).expect("the wire bytes should re-validate");
		assert_eq!(reparsed.digest(), valid.digest());
	}

	#[test]
	fn programs_without_output_are_refused_at_build() {
		let mut builder = ProgramBuilder::default();
		let inputs = builder.input(CLIENT, 2);
		let _sum = builder.add(inputs, inputs);

		let outcome = builder.build();
		assert!(matches!(outcome, Err(VmError::Validation(ValidationError::MissingOut))));
	}

	#[test]
	fn mismatched_operand_lengths_surface_at_build() {
		let mut builder = ProgramBuilder::default();
		let wide = builder.input(CLIENT, 3);
		let narrow = builder.input(101, 1);
		let sum = builder.add(wide, narrow);
		builder.output(CLIENT, sum);

		let outcome = builder.build();
		assert!(matches!(
			outcome,
			Err(VmError::Validation(ValidationError::LengthMismatch { .. }))
		));
	}

	#[test]
	fn second_outputs_surface_at_build() {
		let mut builder = ProgramBuilder::default();
		let inputs = builder.input(CLIENT, 2);
		let sum = builder.add(inputs, inputs);
		builder.output(CLIENT, sum);
		builder.output(101, sum);

		let outcome = builder.build();
		assert!(matches!(outcome, Err(VmError::Validation(ValidationError::OutNotLast { .. }))));
	}

	#[test]
	fn fixed_point_pipelines_validate_and_price_truncation() {
		let precision = FixedPrecision { k: 16, f: 4 };
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 1);
		let y = builder.input(101, 1);
		let product = builder.fp_mul(x, y, precision);
		let quotient = builder.fp_div(product, 32, precision);
		builder.output(CLIENT, quotient);

		let valid = builder.build().expect("the built program should validate");
		assert_eq!(
			valid.budget(),
			Budget { triples: 9, random_shares: 10, prandbits: 8, prandints: 2 }
		);
		assert_eq!(valid.precision(), Some(precision));
	}

	#[test]
	fn batched_multiplication_emits_one_instruction() {
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 2);
		let y = builder.input(101, 2);
		let products = builder.mul_many(&[(x, y), (y, x)]);
		builder.output(CLIENT, products[0]);

		let valid = builder.build().expect("the built program should validate");
		let muls = valid
			.program()
			.instructions
			.iter()
			.filter(|instruction| matches!(instruction, Instruction::MulS { .. }))
			.count();
		assert_eq!(muls, 1);
		assert_eq!(valid.budget().triples, 4);
	}
}
