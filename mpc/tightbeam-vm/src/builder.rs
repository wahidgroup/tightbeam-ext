//! Consumer-side program construction with typed register handles.
//!
//! [`Secret`] and [`Clear`] handles are opaque range tokens minted by
//! the builder, so programs written through it cannot alias banks or
//! read unallocated registers by construction. The fluent surface is
//! infallible. Every remaining soundness question (operand lengths,
//! terminal `Out`) is answered once by [`ProgramBuilder::build`], which
//! returns the same [`ValidProgram`] the parties re-derive from the
//! wire.

use stoffelnet::network_utils::ClientId;

use crate::error::Result;
use crate::isa::{ClearRange, FixedPrecision, InputDecl, Instruction, MulTriple, Program, SecretRange, VERSION};
use crate::validate::ValidProgram;

/// Whole packed-element count for a bit range at `width`, rounded down
/// so callers never read a partial element by construction.
fn bit_elements(range: SecretRange, width: u8) -> u32 {
	match width {
		0 => 0,
		width => range.len / u32::from(width),
	}
}

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

	/// Zero-cost view of one element. Out-of-range indices are not
	/// checked here: validation rejects any use of unwritten registers
	/// when the program is built.
	#[must_use]
	pub fn get(&self, index: u32) -> Self {
		Self { range: SecretRange { base: self.range.base.saturating_add(index), len: 1 } }
	}

	/// Zero-cost view of a contiguous subrange. Out-of-range views are
	/// not checked here: validation rejects any use of unwritten
	/// registers when the program is built.
	#[must_use]
	pub fn slice(&self, start: u32, len: u32) -> Self {
		Self { range: SecretRange { base: self.range.base.saturating_add(start), len } }
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

/// A handle to builder-allocated secret registers holding field bits
/// in `{0,1}`, `width` of them per packed element, LSB-first.
///
/// Only bit-producing operations (`bit_dec`, `and`, `xor`, `not`,
/// [`Bits::assume`]) mint a `Bits` handle: a plain [`Secret`] never
/// silently becomes one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bits {
	range: SecretRange,
	width: u8,
}

impl Bits {
	/// Treat an existing [`Secret`] as `width`-wide bit groups without
	/// a protocol round.
	///
	/// This is the documented escape hatch for advanced callers who
	/// already hold registers they know satisfy the `{0,1}` bit
	/// invariant (for example, values seeded outside `bit_dec`).
	/// It stays infallible at build time even when `width` is zero or
	/// does not divide the underlying range evenly: [`Bits::len`] then
	/// reports the whole-element count via checked division, and any
	/// mismatch surfaces as a wrong protocol result, not a panic.
	/// Callers MUST NOT reach for `assume` on the AES path or any
	/// other computation whose correctness depends on XOR/AND algebraic
	/// identities: a non-`{0,1}` value silently breaks them.
	#[must_use]
	pub fn assume(secret: Secret, width: u8) -> Self {
		Self { range: secret.range, width }
	}

	/// Packed element count (`register count / width`, rounded down).
	pub fn len(&self) -> u32 {
		bit_elements(self.range, self.width)
	}

	/// Whether the handle holds zero packed elements.
	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Bits per packed element.
	pub fn width(&self) -> u8 {
		self.width
	}

	/// Zero-cost view of one packed element's bits. Out-of-range indices
	/// are not checked here: validation rejects any use of unwritten
	/// registers when the program is built.
	#[must_use]
	pub fn get(&self, element: u32) -> Self {
		let width = u32::from(self.width);
		Self {
			range: SecretRange { base: self.range.base.saturating_add(element.saturating_mul(width)), len: width },
			width: self.width,
		}
	}

	/// Zero-cost view of one bit inside a packed element, as width 1.
	/// Out-of-range indices are not checked here: validation rejects
	/// any use of unwritten registers when the program is built.
	#[must_use]
	pub fn bit(&self, element: u32, position: u8) -> Self {
		let width = u32::from(self.width);
		let offset = element.saturating_mul(width).saturating_add(u32::from(position));
		Self {
			range: SecretRange { base: self.range.base.saturating_add(offset), len: 1 },
			width: 1,
		}
	}

	/// Reinterpret contiguous bit registers as `width`-wide groups.
	/// The register count is unchanged. Callers must ensure `width`
	/// divides the underlying range when they later [`ProgramBuilder::pack`].
	#[must_use]
	pub fn regroup(self, width: u8) -> Self {
		Self { range: self.range, width }
	}
}

impl From<Bits> for Secret {
	/// A `Bits` group's registers are always valid secret registers,
	/// so downcasting to the untyped handle (for `output`, `reveal`,
	/// or further affine ops) never loses soundness. The reverse
	/// direction stays deliberately unavailable: only bit-producing
	/// operations mint a `Bits`.
	fn from(bits: Bits) -> Self {
		Self { range: bits.range }
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

	/// Declare `len` secret inputs provided by `client`, each a byte
	/// in `0..=255`. This is documentation over
	/// [`ProgramBuilder::input`]: no distinct wire shape and no extra
	/// check. Callers who need the bit representation follow with
	/// `bit_dec(input, 8)`.
	pub fn input_bytes(&mut self, client: ClientId, len: u32) -> Secret {
		self.input(client, len)
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

	/// Bitwise AND on `{0,1}` field elements: one protocol round.
	pub fn and(&mut self, a: Bits, b: Bits) -> Bits {
		let width = a.width;
		let mut results = self.and_many([(a, b)]);
		match results.pop() {
			Some(result) => result,
			None => Bits { range: self.alloc_secret(a.range.len), width },
		}
	}

	/// Batched bitwise AND: every pair in one protocol round, the
	/// round-efficiency workhorse `and`/`xor` alone cannot give (see
	/// `mul_many`).
	pub fn and_many(&mut self, pairs: impl IntoIterator<Item = (Bits, Bits)>) -> Vec<Bits> {
		let pairs: Vec<(Bits, Bits)> = pairs.into_iter().collect();
		let mut destinations = Vec::with_capacity(pairs.len());
		let mut triples = Vec::with_capacity(pairs.len());

		for (a, b) in pairs {
			let dest = self.alloc_secret(a.range.len);
			triples.push(MulTriple { dest, a: a.range, b: b.range });
			destinations.push(Bits { range: dest, width: a.width });
		}

		self.instructions.push(Instruction::AndS { pairs: triples });
		destinations
	}

	/// Bitwise XOR on `{0,1}` field elements (`a + b - 2ab`): one
	/// protocol round.
	pub fn xor(&mut self, a: Bits, b: Bits) -> Bits {
		let width = a.width;
		let mut results = self.xor_many([(a, b)]);
		match results.pop() {
			Some(result) => result,
			None => Bits { range: self.alloc_secret(a.range.len), width },
		}
	}

	/// Batched bitwise XOR: every pair in one protocol round.
	pub fn xor_many(&mut self, pairs: impl IntoIterator<Item = (Bits, Bits)>) -> Vec<Bits> {
		let pairs: Vec<(Bits, Bits)> = pairs.into_iter().collect();
		let mut destinations = Vec::with_capacity(pairs.len());
		let mut triples = Vec::with_capacity(pairs.len());

		for (a, b) in pairs {
			let dest = self.alloc_secret(a.range.len);
			triples.push(MulTriple { dest, a: a.range, b: b.range });
			destinations.push(Bits { range: dest, width: a.width });
		}

		self.instructions.push(Instruction::XorS { pairs: triples });
		destinations
	}

	/// Bitwise NOT on a `{0,1}` field element: local, no protocol
	/// round.
	pub fn not(&mut self, a: Bits) -> Bits {
		let dest = self.alloc_secret(a.range.len);
		self.instructions.push(Instruction::NotS { dest, a: a.range });
		Bits { range: dest, width: a.width }
	}

	/// Bit-selected choice: `cond` is a single bit broadcast across
	/// every element of `t` and `f`, which share `t`'s length.
	pub fn mux(&mut self, cond: Bits, t: Secret, f: Secret) -> Secret {
		let dest = self.alloc_secret(t.range.len);
		self.instructions
			.push(Instruction::Mux { dest, cond: cond.range, t: t.range, f: f.range });
		Secret { range: dest }
	}

	/// Local little-endian bit packing: fold `bits` into one secret
	/// element per group of `bits.width()` registers.
	pub fn pack(&mut self, bits: Bits) -> Secret {
		let dest = self.alloc_secret(bits.len());
		self.instructions
			.push(Instruction::Pack { dest, src: bits.range, width: bits.width });
		Secret { range: dest }
	}

	/// Interactive mask-and-reveal decomposition: every element of
	/// `src` becomes `width` LSB-first `{0,1}` bits of `src[j] mod
	/// 2^width`, one protocol round for the whole batch.
	pub fn bit_dec(&mut self, src: Secret, width: u8) -> Bits {
		let bit_count = u64::from(src.range.len) * u64::from(width);
		let bit_count = u32::try_from(bit_count).unwrap_or(u32::MAX);
		let dest = self.alloc_secret(bit_count);
		self.instructions.push(Instruction::BitDec { dest, src: src.range, width });
		Bits { range: dest, width }
	}

	/// Batched AES S-box on width-8 bit groups: TinyTable online open
	/// plus a mux tree that returns substituted bits.
	pub fn sbox(&mut self, src: Bits) -> Bits {
		let dest = self.alloc_secret(src.range.len);
		self.instructions.push(Instruction::Sbox { dest, src: src.range });
		Bits { range: dest, width: 8 }
	}

	/// Element-wise XOR on byte-valued secrets.
	pub fn byte_xor(&mut self, a: Secret, b: Secret) -> Secret {
		let dest = self.alloc_secret(a.range.len);
		self.instructions.push(Instruction::ByteXor { dest, a: a.range, b: b.range });
		Secret { range: dest }
	}

	/// Copy `parts` into one contiguous secret run via local
	/// `AddC` with a zero clear addend (no protocol round).
	pub fn concat(&mut self, parts: impl AsRef<[Secret]>) -> Secret {
		let parts = parts.as_ref();
		let total: u32 = parts.iter().map(|part| part.range.len).sum();
		if total == 0 {
			return Secret { range: self.alloc_secret(0) };
		}

		let first_base = self.next_secret;
		for part in parts {
			let zeros = self.constants(vec![0u64; part.range.len as usize]);
			let _copied = self.add_clear(*part, zeros);
		}

		Secret { range: SecretRange { base: first_base, len: total } }
	}

	/// Element-wise equality over the low `width` bits of `a` and
	/// `b`. Biases `a - b` by `2^width` before decomposing: `SubS`
	/// wraps a negative difference to `p - (b - a)` in the field, and
	/// with `p` astronomically larger than `2^width` the biased value
	/// always lands in `(0, 2^(width+1))`, so its low `width` bits are
	/// exactly `(a - b) mod 2^width` in every case. `width` rounds
	/// (one `bit_dec`, then `width - 1` folding `AndS` rounds).
	pub fn eq(&mut self, a: Secret, b: Secret, width: u8) -> Bits {
		let count = a.range.len as usize;
		let bias = 1u64.checked_shl(u32::from(width)).unwrap_or(0);
		let diff = self.sub(a, b);
		let offset = self.constants(vec![bias; count]);
		let biased = self.add_clear(diff, offset);
		let diff_bits = self.bit_dec(biased, width);
		let equal_bits = self.not(diff_bits);
		self.and_fold(equal_bits)
	}

	/// Element-wise unsigned less-than over the low `width` bits of
	/// `a` and `b`. `SubS` wraps `a - b < 0` to `p - (b - a)` in the
	/// field. Adding `2^width` before decomposing lands the biased
	/// value in `(0, 2^width)` when `a < b` and in `[2^width,
	/// 2^(width+1))` when `a >= b` (`p` is astronomically larger than
	/// `2^(width+1)`, so this holds regardless of `p`'s residues), so
	/// the decomposed value's top bit is exactly the comparison's
	/// borrow. `width + 1` rounds (one `bit_dec`, the rest local).
	pub fn lt(&mut self, a: Secret, b: Secret, width: u8) -> Bits {
		let count = a.range.len as usize;
		let bias = 1u64.checked_shl(u32::from(width)).unwrap_or(0);
		let diff = self.sub(a, b);
		let offset = self.constants(vec![bias; count]);
		let biased = self.add_clear(diff, offset);
		let decomposed = self.bit_dec(biased, width.saturating_add(1));
		let borrow_out = self.gather(decomposed, width);
		self.not(borrow_out)
	}

	/// Fold `bits` (`count` elements, `width` registers each) down to
	/// one register per element via a sequential pairwise `AndS`
	/// chain: element `j`'s result is `1` iff every one of its
	/// `width` inputs was `1`. `width - 1` protocol rounds, each
	/// batched across every element at once.
	fn and_fold(&mut self, bits: Bits) -> Bits {
		let count = bits.len();
		let width = bits.width;
		if count == 0 || width == 0 {
			return Bits { range: self.alloc_secret(count), width: 1 };
		}
		if width == 1 {
			return Bits { range: bits.range, width: 1 };
		}

		let base = bits.range.base;
		let element_base = |element: u32| base + element * u32::from(width);

		let mut pairs = Vec::with_capacity(count as usize);
		for element in 0..count {
			let start = element_base(element);
			let a = Bits { range: SecretRange { base: start, len: 1 }, width: 1 };
			let b = Bits { range: SecretRange { base: start + 1, len: 1 }, width: 1 };
			pairs.push((a, b));
		}
		let mut accumulator = self.and_many(pairs);

		for position in 2..width {
			let acc_base = match accumulator.first() {
				Some(first) => first.range.base,
				None => return Bits { range: self.alloc_secret(count), width: 1 },
			};

			let mut pairs = Vec::with_capacity(count as usize);
			for element in 0..count {
				let a = Bits { range: SecretRange { base: acc_base + element, len: 1 }, width: 1 };
				let b_base = element_base(element) + u32::from(position);
				let b = Bits { range: SecretRange { base: b_base, len: 1 }, width: 1 };
				pairs.push((a, b));
			}
			accumulator = self.and_many(pairs);
		}

		match accumulator.first() {
			Some(first) => Bits { range: SecretRange { base: first.range.base, len: count }, width: 1 },
			None => Bits { range: self.alloc_secret(count), width: 1 },
		}
	}

	/// Copy register `position` of every element in `bits` into one
	/// fresh, contiguous register per element. Two passes of the
	/// local `NotS` copy the strided source into a plain, freshly
	/// allocated range and back, resolving the stride at zero
	/// protocol cost.
	pub fn bit_lane(&mut self, bits: Bits, position: u8) -> Bits {
		self.gather(bits, position)
	}

	/// Copy single-bit handles into one contiguous width-1 [`Bits`]
	/// via a double `NotS` pass (local, zero protocol rounds).
	pub fn join_bits(&mut self, bits: impl AsRef<[Bits]>) -> Bits {
		let bits = bits.as_ref();
		let count = bits.len() as u32;
		if count == 0 {
			return Bits { range: self.alloc_secret(0), width: 1 };
		}

		let mut negated = Vec::with_capacity(bits.len());
		for bit in bits {
			negated.push(self.not(*bit));
		}

		match negated.first() {
			Some(first) => {
				let flipped = Bits { range: SecretRange { base: first.range.base, len: count }, width: 1 };
				self.not(flipped)
			}
			None => Bits { range: self.alloc_secret(0), width: 1 },
		}
	}

	fn gather(&mut self, bits: Bits, position: u8) -> Bits {
		let count = bits.len();
		if count == 0 {
			return Bits { range: self.alloc_secret(0), width: 1 };
		}

		let base = bits.range.base;
		let width = u32::from(bits.width);
		let mut negated = Vec::with_capacity(count as usize);
		for element in 0..count {
			let offset = base + element * width + u32::from(position);
			let single = Bits { range: SecretRange { base: offset, len: 1 }, width: 1 };
			negated.push(self.not(single));
		}

		match negated.first() {
			Some(first) => {
				let flipped = Bits { range: SecretRange { base: first.range.base, len: count }, width: 1 };
				self.not(flipped)
			}
			None => Bits { range: self.alloc_secret(0), width: 1 },
		}
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

	fn must_build(builder: ProgramBuilder) -> ValidProgram {
		builder.build().expect("the built program should validate")
	}

	fn must_from_der(bytes: &[u8]) -> ValidProgram {
		ValidProgram::from_der(bytes).expect("the wire bytes should re-validate")
	}

	#[test]
	fn a_fluent_program_validates_and_prices() {
		let mut builder = ProgramBuilder::default();
		let inputs = builder.input(CLIENT, 2);
		let two = builder.constants([2, 2]);
		let doubled = builder.mul_clear(inputs, two);
		let product = builder.mul(doubled, inputs);
		let _opened = builder.reveal(product);
		builder.output(CLIENT, product);

		let valid = must_build(builder);
		assert_eq!(valid.budget(), Budget { triples: 2, random_shares: 2, ..Budget::default() });
	}

	#[test]
	fn built_programs_round_trip_to_the_same_digest() {
		let mut builder = ProgramBuilder::default();
		let inputs = builder.input(CLIENT, 2);
		let sum = builder.add(inputs, inputs);
		builder.output(CLIENT, sum);

		let valid = must_build(builder);
		let reparsed = must_from_der(valid.bytes());
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

		let valid = must_build(builder);
		assert_eq!(
			valid.budget(),
			Budget { triples: 9, random_shares: 10, prandbits: 8, prandints: 2, ..Budget::default() }
		);
		assert_eq!(valid.precision(), Some(precision));
	}

	#[test]
	fn assume_with_zero_width_reports_zero_elements_without_panicking() {
		let mut builder = ProgramBuilder::default();
		let secret = builder.input(CLIENT, 4);
		let bits = Bits::assume(secret, 0);

		assert_eq!(bits.len(), 0);
		assert!(bits.is_empty());
	}

	#[test]
	fn and_many_and_xor_many_each_emit_one_instruction_and_price_a_triple_per_element() {
		let mut builder = ProgramBuilder::default();
		let x = Bits::assume(builder.input(CLIENT, 2), 1);
		let y = Bits::assume(builder.input(101, 2), 1);
		let ands = builder.and_many([(x, y), (y, x)]);
		let xors = builder.xor_many([(x, y)]);
		builder.output(CLIENT, Secret::from(ands[0]));
		let _ = xors;

		let valid = must_build(builder);
		let and_instructions = valid
			.program()
			.instructions
			.iter()
			.filter(|i| matches!(i, Instruction::AndS { .. }))
			.count();
		let xor_instructions = valid
			.program()
			.instructions
			.iter()
			.filter(|i| matches!(i, Instruction::XorS { .. }))
			.count();

		assert_eq!(and_instructions, 1);
		assert_eq!(xor_instructions, 1);
		// 2 AndS pairs * 2 elements + 1 XorS pair * 2 elements = 6 triples.
		assert_eq!(valid.budget().triples, 6);
	}

	#[test]
	fn mux_selects_through_the_fluent_surface_and_prices_a_triple_per_element() {
		let mut builder = ProgramBuilder::default();
		let cond = Bits::assume(builder.input(CLIENT, 1), 1);
		let t = builder.input(101, 2);
		let f = builder.input(102, 2);
		let selected = builder.mux(cond, t, f);
		builder.output(CLIENT, selected);

		let valid = must_build(builder);
		assert_eq!(valid.budget().triples, 2);
	}

	#[test]
	fn bit_dec_prices_a_prandbit_and_two_triples_per_bit() {
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 2);
		let bits = builder.bit_dec(x, 3);
		builder.output(CLIENT, Secret::from(bits));

		let valid = must_build(builder);
		assert_eq!(bits.len(), 2);
		assert_eq!(bits.width(), 3);
		assert_eq!(
			valid.budget(),
			Budget { triples: 12, random_shares: 2, prandbits: 6, prandints: 0, ..Budget::default() }
		);
	}

	#[test]
	fn input_bytes_declares_a_plain_secret_input() {
		let mut builder = ProgramBuilder::default();
		let bytes = builder.input_bytes(CLIENT, 4);
		builder.output(CLIENT, bytes);

		let valid = must_build(builder);
		assert_eq!(bytes.len(), 4);
		assert_eq!(valid.program().inputs, vec![InputDecl { client: CLIENT, dest: bytes.range }]);
	}

	#[test]
	fn eq_and_lt_each_fold_down_to_one_bit_per_element() {
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 2);
		let y = builder.input(101, 2);
		let equal = builder.eq(x, y, 3);
		let less = builder.lt(x, y, 3);
		builder.output(CLIENT, Secret::from(equal));
		let _ = less;

		let valid = must_build(builder);
		assert_eq!(equal.len(), 2);
		assert_eq!(equal.width(), 1);
		assert_eq!(less.len(), 2);
		assert_eq!(less.width(), 1);
		assert!(valid.budget().triples > 0);
	}

	#[test]
	fn batched_multiplication_emits_one_instruction() {
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 2);
		let y = builder.input(101, 2);
		let products = builder.mul_many(&[(x, y), (y, x)]);
		builder.output(CLIENT, products[0]);

		let valid = must_build(builder);
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
