//! The interpreter: straight-line execution of a [`ValidProgram`] over
//! a [`SecretOps`] backend.
//!
//! The executor owns the register files and instruction dispatch and
//! nothing else - every protocol interaction goes through the backend
//! trait, so the interpreter runs identically over the HoneyBadger
//! engine and over the plain in-memory backend the unit tests use.
//! Static validation already proved bounds, operand shapes, and
//! def-before-use, so the register accesses here re-check only as a
//! defensive invariant.

use std::collections::HashMap;

use ark_ff::PrimeField;
use stoffelnet::network_utils::ClientId;
use tightbeam_mpc::TraceHandle;

use crate::backend::SecretOps;
use crate::error::{Bank, Result, ValidationError, VmError};
use crate::events;
use crate::isa::{ClearRange, Instruction, SecretRange};
use crate::validate::ValidProgram;

/// The terminal result: shares destined for one client.
#[derive(Clone, Debug)]
pub struct Output<S> {
	/// The receiving client.
	pub client: ClientId,
	/// The result shares, one per output element.
	pub shares: Vec<S>,
}

/// One bank of registers, each empty until first written.
struct RegisterFile<T> {
	bank: Bank,
	slots: Vec<Option<T>>,
}

impl<T> RegisterFile<T>
where
	T: Clone,
{
	fn new(bank: Bank, top: u32) -> Self {
		let mut slots = Vec::new();
		slots.resize_with(top as usize, || None);
		Self { bank, slots }
	}

	fn read(&self, index: usize, base: u32, len: u32) -> Result<Vec<T>> {
		let mut values = Vec::with_capacity(len as usize);
		for register in base..base + len {
			let value = self.slots[register as usize]
				.clone()
				.ok_or(ValidationError::UninitializedRead { index, bank: self.bank, register: u64::from(register) })?;
			values.push(value);
		}
		Ok(values)
	}

	fn write(&mut self, base: u32, values: Vec<T>) {
		for (offset, value) in values.into_iter().enumerate() {
			self.slots[base as usize + offset] = Some(value);
		}
	}
}

/// The two register files of one execution.
struct Registers<F, S> {
	clear: RegisterFile<F>,
	secret: RegisterFile<S>,
}

impl<F, S> Registers<F, S>
where
	F: Clone,
	S: Clone,
{
	fn new(clear_top: u32, secret_top: u32) -> Self {
		Self {
			clear: RegisterFile::new(Bank::Clear, clear_top),
			secret: RegisterFile::new(Bank::Secret, secret_top),
		}
	}

	fn read_clear(&self, index: usize, range: &ClearRange) -> Result<Vec<F>> {
		self.clear.read(index, range.base, range.len)
	}

	fn read_secret(&self, index: usize, range: &SecretRange) -> Result<Vec<S>> {
		self.secret.read(index, range.base, range.len)
	}

	fn write_clear(&mut self, range: &ClearRange, values: Vec<F>) {
		self.clear.write(range.base, values);
	}

	fn write_secret(&mut self, range: &SecretRange, shares: Vec<S>) {
		self.secret.write(range.base, shares);
	}
}

/// Element-wise application of one local binary secret operation.
fn zip_secret<F, B>(
	backend: &B,
	a: &[B::Share],
	b: &[B::Share],
	op: impl Fn(&B, &B::Share, &B::Share) -> Result<B::Share>,
) -> Result<Vec<B::Share>>
where
	B: SecretOps<F>,
{
	let mut results = Vec::with_capacity(a.len());
	for (left, right) in a.iter().zip(b) {
		results.push(op(backend, left, right)?);
	}
	Ok(results)
}

/// Element-wise application of one local secret-by-clear operation.
fn zip_clear<F, B>(
	backend: &B,
	a: &[B::Share],
	c: &[F],
	op: impl Fn(&B, &B::Share, F) -> Result<B::Share>,
) -> Result<Vec<B::Share>>
where
	F: Copy,
	B: SecretOps<F>,
{
	let mut results = Vec::with_capacity(a.len());
	for (share, constant) in a.iter().zip(c) {
		results.push(op(backend, share, *constant)?);
	}
	Ok(results)
}

/// Run one validated program to its terminal [`Output`].
///
/// `inputs` carries the derived input shares per declared client, as
/// produced by the engine's input protocol.
///
/// The program bytes carry no tracing of their own. `trace` is the
/// injected observation point, so whoever hosts the execution (and by
/// extension the consumer driving it) chooses where the interpreter's
/// lifecycle events land.
pub async fn execute<F, B>(
	valid: &ValidProgram,
	inputs: HashMap<ClientId, Vec<B::Share>>,
	backend: &mut B,
	trace: &TraceHandle,
) -> Result<Output<B::Share>>
where
	F: PrimeField,
	B: SecretOps<F>,
{
	let program = valid.program();
	let mut registers: Registers<F, B::Share> = Registers::new(valid.clear_top(), valid.secret_top());
	trace.event(&events::PROGRAM_START)?;

	for decl in &program.inputs {
		let shares = inputs.get(&decl.client).ok_or(VmError::MissingInput { client: decl.client })?;
		if shares.len() != decl.dest.len as usize {
			return Err(VmError::InputArity {
				client: decl.client,
				expected: decl.dest.len as usize,
				got: shares.len(),
			});
		}
		registers.write_secret(&decl.dest, shares.clone());
	}

	let mut reveal_ordinal = 0u32;
	let mut delivered = None;

	for (index, instruction) in program.instructions.iter().enumerate() {
		match instruction {
			Instruction::LdC { dest, values } => {
				let lifted: Vec<F> = values.iter().map(|value| F::from(*value)).collect();
				registers.write_clear(dest, lifted);
			}
			Instruction::AddS { dest, a, b } => {
				let left = registers.read_secret(index, a)?;
				let right = registers.read_secret(index, b)?;
				let sums = zip_secret(backend, &left, &right, B::add)?;
				registers.write_secret(dest, sums);
			}
			Instruction::SubS { dest, a, b } => {
				let left = registers.read_secret(index, a)?;
				let right = registers.read_secret(index, b)?;
				let differences = zip_secret(backend, &left, &right, B::sub)?;
				registers.write_secret(dest, differences);
			}
			Instruction::AddC { dest, a, c } => {
				let shares = registers.read_secret(index, a)?;
				let constants = registers.read_clear(index, c)?;
				let sums = zip_clear(backend, &shares, &constants, B::add_clear)?;
				registers.write_secret(dest, sums);
			}
			Instruction::SubC { dest, a, c } => {
				let shares = registers.read_secret(index, a)?;
				let constants = registers.read_clear(index, c)?;
				let differences = zip_clear(backend, &shares, &constants, B::sub_clear)?;
				registers.write_secret(dest, differences);
			}
			Instruction::MulC { dest, a, c } => {
				let shares = registers.read_secret(index, a)?;
				let constants = registers.read_clear(index, c)?;
				let scaled = zip_clear(backend, &shares, &constants, B::mul_clear)?;
				registers.write_secret(dest, scaled);
			}
			Instruction::MulS { pairs } => {
				let mut x = Vec::new();
				let mut y = Vec::new();
				for pair in pairs {
					x.extend(registers.read_secret(index, &pair.a)?);
					y.extend(registers.read_secret(index, &pair.b)?);
				}

				let mut products = backend.mul_batch(x, y).await?.into_iter();
				for pair in pairs {
					let chunk: Vec<B::Share> = products.by_ref().take(pair.dest.len as usize).collect();
					registers.write_secret(&pair.dest, chunk);
				}
			}
			Instruction::FpMulS { dest, a, b, precision } => {
				let left = registers.read_secret(index, a)?;
				let right = registers.read_secret(index, b)?;
				let products = backend.fp_mul_batch(left, right, *precision).await?;
				registers.write_secret(dest, products);
			}
			Instruction::FpDivC { dest, a, divisor, precision } => {
				let dividends = registers.read_secret(index, a)?;
				let quotients = backend.fp_div_clear_batch(dividends, F::from(*divisor), *precision).await?;
				registers.write_secret(dest, quotients);
			}
			Instruction::Reveal { dest, src } => {
				trace.event(&events::REVEAL)?;
				let shares = registers.read_secret(index, src)?;
				let opened = backend.reveal(reveal_ordinal, &shares).await?;
				reveal_ordinal += 1;
				registers.write_clear(dest, opened);
			}
			Instruction::Out { client, src } => {
				let shares = registers.read_secret(index, src)?;
				delivered = Some(Output { client: *client, shares });
			}
			Instruction::AndS { pairs } => {
				let mut x = Vec::new();
				let mut y = Vec::new();
				for pair in pairs {
					x.extend(registers.read_secret(index, &pair.a)?);
					y.extend(registers.read_secret(index, &pair.b)?);
				}

				let mut products = backend.mul_batch(x, y).await?.into_iter();
				for pair in pairs {
					let chunk: Vec<B::Share> = products.by_ref().take(pair.dest.len as usize).collect();
					registers.write_secret(&pair.dest, chunk);
				}
			}
			Instruction::XorS { pairs } => {
				let mut x = Vec::new();
				let mut y = Vec::new();
				for pair in pairs {
					x.extend(registers.read_secret(index, &pair.a)?);
					y.extend(registers.read_secret(index, &pair.b)?);
				}

				let mut products = backend.mul_batch(x.clone(), y.clone()).await?.into_iter();
				for pair in pairs {
					let len = pair.dest.len as usize;
					let a: Vec<B::Share> = x.drain(..len).collect();
					let b: Vec<B::Share> = y.drain(..len).collect();
					let products: Vec<B::Share> = products.by_ref().take(len).collect();

					let mut xors = Vec::with_capacity(len);
					for ((left, right), product) in a.into_iter().zip(b).zip(products) {
						let sum = backend.add(&left, &right)?;
						let doubled = backend.mul_clear(&product, F::from(2u64))?;
						xors.push(backend.sub(&sum, &doubled)?);
					}
					registers.write_secret(&pair.dest, xors);
				}
			}
			Instruction::NotS { dest, a } => {
				let bits = registers.read_secret(index, a)?;
				let mut negated = Vec::with_capacity(bits.len());
				for bit in &bits {
					let flipped = backend.mul_clear(bit, -F::from(1u64))?;
					negated.push(backend.add_clear(&flipped, F::from(1u64))?);
				}
				registers.write_secret(dest, negated);
			}
			Instruction::Mux { dest, cond, t, f } => {
				let selector = registers.read_secret(index, cond)?;
				let choices_t = registers.read_secret(index, t)?;
				let choices_f = registers.read_secret(index, f)?;
				let width = choices_t.len();

				let mut differences = Vec::with_capacity(width);
				for (left, right) in choices_t.iter().zip(&choices_f) {
					differences.push(backend.sub(left, right)?);
				}

				let selectors = vec![selector[0].clone(); width];
				let scaled = backend.mul_batch(differences, selectors).await?;

				let mut selected = Vec::with_capacity(width);
				for (base, delta) in choices_f.into_iter().zip(scaled) {
					selected.push(backend.add(&base, &delta)?);
				}
				registers.write_secret(dest, selected);
			}
			Instruction::BitDec { dest, src, width } => {
				trace.event(&events::BIT_DEC)?;
				let elements = registers.read_secret(index, src)?;
				let bits = backend.bit_dec(reveal_ordinal, elements, *width).await?;
				reveal_ordinal += 1;
				registers.write_secret(dest, bits);
			}
			Instruction::Pack { dest, src, width } => {
				let bits = registers.read_secret(index, src)?;
				let width = *width as usize;
				let mut packed = Vec::with_capacity(dest.len as usize);

				for chunk in bits.chunks(width) {
					let mut accumulator = backend.mul_clear(&chunk[0], F::from(1u64))?;
					for (position, bit) in chunk.iter().enumerate().skip(1) {
						let weighted = backend.mul_clear(bit, F::from(1u64 << position))?;
						accumulator = backend.add(&accumulator, &weighted)?;
					}
					packed.push(accumulator);
				}
				registers.write_secret(dest, packed);
			}
			Instruction::Sbox { dest, src } => {
				trace.event(&events::SBOX)?;
				let elements = registers.read_secret(index, src)?;
				let substituted = backend.sbox_batch(reveal_ordinal, elements).await?;
				// δ open + follow-up bit_dec of the selected byte.
				reveal_ordinal = reveal_ordinal.saturating_add(2);
				registers.write_secret(dest, substituted);
			}
			Instruction::ByteXor { dest, a, b } => {
				let left = registers.read_secret(index, a)?;
				let right = registers.read_secret(index, b)?;
				let xors = backend.byte_xor_batch(reveal_ordinal, left, right).await?;
				reveal_ordinal = reveal_ordinal.saturating_add(2);
				registers.write_secret(dest, xors);
			}
		}
	}

	let output = delivered.ok_or(ValidationError::MissingOut)?;
	trace.event(&events::PROGRAM_END)?;
	Ok(output)
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_bls12_381::Fr;
	use ark_ff::BigInteger;

	use crate::builder::{Bits, ProgramBuilder, Secret};
	use crate::isa::FixedPrecision;
	use crate::validate::ValidProgram;

	const CLIENT: ClientId = 100;

	fn must_build(builder: ProgramBuilder) -> ValidProgram {
		builder.build().expect("the program should validate")
	}

	async fn must_execute(
		valid: &ValidProgram,
		inputs: HashMap<ClientId, Vec<Fr>>,
		backend: &mut PlainBackend,
		trace: &TraceHandle,
	) -> Output<Fr> {
		execute(valid, inputs, backend, trace).await.expect("execution should complete")
	}

	/// Read a small plain value back out of the field.
	fn to_u128(value: &Fr) -> u128 {
		let bytes = value.into_bigint().to_bytes_le();
		let mut buf = [0u8; 16];
		buf.copy_from_slice(&bytes[..16]);
		u128::from_le_bytes(buf)
	}

	/// Plaintext backend: shares are the field values themselves, so
	/// interpreter semantics are checked without any protocol.
	#[derive(Default)]
	struct PlainBackend {
		reveals: usize,
	}

	impl SecretOps<Fr> for PlainBackend {
		type Share = Fr;

		fn add(&self, a: &Fr, b: &Fr) -> Result<Fr> {
			Ok(*a + *b)
		}

		fn sub(&self, a: &Fr, b: &Fr) -> Result<Fr> {
			Ok(*a - *b)
		}

		fn add_clear(&self, a: &Fr, c: Fr) -> Result<Fr> {
			Ok(*a + c)
		}

		fn sub_clear(&self, a: &Fr, c: Fr) -> Result<Fr> {
			Ok(*a - c)
		}

		fn mul_clear(&self, a: &Fr, c: Fr) -> Result<Fr> {
			Ok(*a * c)
		}

		async fn mul_batch(&mut self, x: Vec<Fr>, y: Vec<Fr>) -> Result<Vec<Fr>> {
			let products = x.into_iter().zip(y).map(|(a, b)| a * b).collect();
			Ok(products)
		}

		async fn fp_mul_batch(&mut self, x: Vec<Fr>, y: Vec<Fr>, precision: FixedPrecision) -> Result<Vec<Fr>> {
			let products = x
				.into_iter()
				.zip(y)
				.map(|(a, b)| Fr::from((to_u128(&a) * to_u128(&b)) >> precision.f))
				.collect();
			Ok(products)
		}

		async fn fp_div_clear_batch(&mut self, x: Vec<Fr>, divisor: Fr, precision: FixedPrecision) -> Result<Vec<Fr>> {
			// The engine's plan: scale by the rounded reciprocal
			// `2^(2f) / d`, then truncate by `2^f`.
			let d = to_u128(&divisor);
			let reciprocal = ((1u128 << (2 * precision.f)) + (d >> 1)) / d;
			let quotients = x
				.into_iter()
				.map(|a| Fr::from((to_u128(&a) * reciprocal) >> precision.f))
				.collect();
			Ok(quotients)
		}

		async fn reveal(&mut self, _ordinal: u32, shares: &[Fr]) -> Result<Vec<Fr>> {
			self.reveals += 1;
			Ok(shares.to_vec())
		}

		/// The plaintext backend has direct access to each element's
		/// value, so it decomposes bits by reading the field integer
		/// directly: the real mask-and-reveal protocol lives on
		/// `HoneyBadgerBackend` and is exercised by the engine e2e
		/// suite, not by this interpreter-dispatch test double.
		async fn bit_dec(&mut self, _ordinal: u32, x: Vec<Fr>, width: u8) -> Result<Vec<Fr>> {
			let mut bits = Vec::with_capacity(x.len() * width as usize);
			for value in x {
				let integer = to_u128(&value);
				for position in 0..width {
					bits.push(Fr::from((integer >> position) & 1));
				}
			}
			Ok(bits)
		}

		async fn sbox_batch(&mut self, _ordinal: u32, x_bits: Vec<Fr>) -> Result<Vec<Fr>> {
			use crate::circuits::aes128::AES_SBOX;

			let mut out = Vec::with_capacity(x_bits.len());
			for bits in x_bits.chunks_exact(8) {
				let mut byte = 0u8;
				for (position, bit) in bits.iter().enumerate() {
					if to_u128(bit) & 1 == 1 {
						byte |= 1 << position;
					}
				}
				let substituted = AES_SBOX[usize::from(byte)];
				for position in 0..8 {
					out.push(Fr::from(u64::from((substituted >> position) & 1)));
				}
			}
			Ok(out)
		}

		async fn byte_xor_batch(&mut self, _ordinal: u32, a: Vec<Fr>, b: Vec<Fr>) -> Result<Vec<Fr>> {
			let mut out = Vec::with_capacity(a.len());
			for (left, right) in a.into_iter().zip(b) {
				let x = (to_u128(&left) & 0xff) as u8;
				let y = (to_u128(&right) & 0xff) as u8;
				out.push(Fr::from(u64::from(x ^ y)));
			}
			Ok(out)
		}
	}

	fn plain_inputs(values: &[u64]) -> HashMap<ClientId, Vec<Fr>> {
		let shares = values.iter().map(|value| Fr::from(*value)).collect();
		HashMap::from([(CLIENT, shares)])
	}

	#[tokio::test]
	async fn squares_flow_through_the_interpreter() {
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 2);
		let squared = builder.mul(x, x);
		builder.output(CLIENT, squared);
		let valid = must_build(builder);

		let mut backend = PlainBackend::default();
		let output = must_execute(&valid, plain_inputs(&[3, 4]), &mut backend, &TraceHandle::default()).await;

		assert_eq!(output.client, CLIENT);
		assert_eq!(output.shares, vec![Fr::from(9u64), Fr::from(16u64)]);
	}

	#[tokio::test]
	async fn affine_pipelines_compose() {
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 2);
		let scale = builder.constants([2, 3]);
		let offset = builder.constants([5, 7]);
		let scaled = builder.mul_clear(x, scale);
		let shifted = builder.add_clear(scaled, offset);
		builder.output(CLIENT, shifted);
		let valid = must_build(builder);

		let mut backend = PlainBackend::default();
		let output = must_execute(&valid, plain_inputs(&[10, 20]), &mut backend, &TraceHandle::default()).await;

		assert_eq!(output.shares, vec![Fr::from(25u64), Fr::from(67u64)]);
	}

	#[tokio::test]
	async fn revealed_values_feed_clear_arithmetic() {
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 1);
		let y = builder.input(101, 1);
		let opened = builder.reveal(x);
		let scaled = builder.mul_clear(y, opened);
		builder.output(CLIENT, scaled);
		let valid = must_build(builder);

		let mut inputs = plain_inputs(&[2]);
		inputs.insert(101, vec![Fr::from(3u64)]);

		let mut backend = PlainBackend::default();
		let output = must_execute(&valid, inputs, &mut backend, &TraceHandle::default()).await;

		assert_eq!(output.shares, vec![Fr::from(6u64)]);
		assert_eq!(backend.reveals, 1);
	}

	#[tokio::test]
	async fn subtraction_variants_agree_with_field_arithmetic() {
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 1);
		let y = builder.input(101, 1);
		let difference = builder.sub(x, y);
		let offset = builder.constants([1]);
		let adjusted = builder.sub_clear(difference, offset);
		builder.output(CLIENT, adjusted);
		let valid = must_build(builder);

		let mut inputs = plain_inputs(&[10]);
		inputs.insert(101, vec![Fr::from(4u64)]);

		let mut backend = PlainBackend::default();
		let output = must_execute(&valid, inputs, &mut backend, &TraceHandle::default()).await;

		assert_eq!(output.shares, vec![Fr::from(5u64)]);
	}

	#[tokio::test]
	async fn batched_multiplications_land_in_their_destinations() {
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 2);
		let y = builder.input(101, 2);
		let products = builder.mul_many(&[(x, y), (x, x)]);
		let combined = builder.add(products[0], products[1]);
		builder.output(CLIENT, combined);
		let valid = must_build(builder);

		let mut inputs = plain_inputs(&[2, 3]);
		inputs.insert(101, vec![Fr::from(5u64), Fr::from(7u64)]);

		let mut backend = PlainBackend::default();
		let output = must_execute(&valid, inputs, &mut backend, &TraceHandle::default()).await;

		// (x*y) + (x*x) = [10 + 4, 21 + 9]
		assert_eq!(output.shares, vec![Fr::from(14u64), Fr::from(30u64)]);
	}

	#[tokio::test]
	async fn fixed_point_ops_truncate_by_the_fractional_width() {
		// f = 4: x = 5.5 (raw 88), y = 2.0 (raw 32).
		// x * y = 11.0 (raw 176). 11.0 / 2.0 = 5.5 (raw 88).
		let precision = FixedPrecision { k: 16, f: 4 };
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 1);
		let y = builder.input(101, 1);
		let product = builder.fp_mul(x, y, precision);
		let quotient = builder.fp_div(product, 32, precision);
		builder.output(CLIENT, quotient);
		let valid = must_build(builder);

		let mut inputs = plain_inputs(&[88]);
		inputs.insert(101, vec![Fr::from(32u64)]);

		let mut backend = PlainBackend::default();
		let output = must_execute(&valid, inputs, &mut backend, &TraceHandle::default()).await;

		assert_eq!(output.shares, vec![Fr::from(88u64)]);
	}

	#[tokio::test]
	async fn execution_traces_its_lifecycle() {
		use tightbeam::testing::assertions::AssertionLabel;

		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 1);
		let opened = builder.reveal(x);
		let scaled = builder.mul_clear(x, opened);
		builder.output(CLIENT, scaled);
		let valid = must_build(builder);

		let trace = TraceHandle::default();
		let mut backend = PlainBackend::default();
		let _output = must_execute(&valid, plain_inputs(&[2]), &mut backend, &trace).await;

		let labels: Vec<AssertionLabel> = trace
			.collector()
			.drain_assertions()
			.into_iter()
			.map(|assertion| assertion.label)
			.collect();
		let expected = vec![
			AssertionLabel::Custom(events::PROGRAM_START.urn().to_string().into()),
			AssertionLabel::Custom(events::REVEAL.urn().to_string().into()),
			AssertionLabel::Custom(events::PROGRAM_END.urn().to_string().into()),
		];
		assert_eq!(labels, expected);
	}

	#[tokio::test]
	async fn bit_dec_traces_under_its_own_event_distinct_from_reveal() {
		use tightbeam::testing::assertions::AssertionLabel;

		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 1);
		let bits = builder.bit_dec(x, 3);
		builder.output(CLIENT, Secret::from(bits));
		let valid = must_build(builder);

		let trace = TraceHandle::default();
		let mut backend = PlainBackend::default();
		let _output = must_execute(&valid, plain_inputs(&[5]), &mut backend, &trace).await;

		let labels: Vec<AssertionLabel> = trace
			.collector()
			.drain_assertions()
			.into_iter()
			.map(|assertion| assertion.label)
			.collect();
		let expected = vec![
			AssertionLabel::Custom(events::PROGRAM_START.urn().to_string().into()),
			AssertionLabel::Custom(events::BIT_DEC.urn().to_string().into()),
			AssertionLabel::Custom(events::PROGRAM_END.urn().to_string().into()),
		];
		assert_eq!(labels, expected);
	}

	#[tokio::test]
	async fn missing_declared_inputs_are_refused() {
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 1);
		builder.output(CLIENT, x);
		let valid = must_build(builder);

		let mut backend = PlainBackend::default();
		let outcome = execute(&valid, HashMap::new(), &mut backend, &TraceHandle::default()).await;
		assert!(matches!(outcome, Err(VmError::MissingInput { client: CLIENT })));
	}

	/// Feed a `{0,1}` pair straight into secret registers, bypassing
	/// `input` and `BitDec`: the gates under test here are pure
	/// functions of `{0,1}` inputs, so seeding bits directly through
	/// `Bits::assume` keeps each case focused on the gate's own
	/// dispatch arm rather than the unrelated decomposition round.
	fn bit_pair_program(gate: impl FnOnce(&mut ProgramBuilder, Bits, Bits) -> Bits) -> ValidProgram {
		let mut builder = ProgramBuilder::default();
		let a = Bits::assume(builder.input(CLIENT, 1), 1);
		let b = Bits::assume(builder.input(101, 1), 1);
		let result = gate(&mut builder, a, b);
		builder.output(CLIENT, Secret::from(result));
		builder.build().expect("the gate program should validate")
	}

	async fn run_bit_pair(valid: &ValidProgram, a: u64, b: u64) -> Fr {
		let mut inputs = plain_inputs(&[a]);
		inputs.insert(101, vec![Fr::from(b)]);
		let mut backend = PlainBackend::default();
		let output = must_execute(valid, inputs, &mut backend, &TraceHandle::default()).await;
		output.shares[0]
	}

	#[tokio::test]
	async fn ands_matches_boolean_and_over_every_bit_pair() {
		let valid = bit_pair_program(|builder, a, b| builder.and(a, b));
		for (a, b, expected) in [(0u64, 0u64, 0u64), (0, 1, 0), (1, 0, 0), (1, 1, 1)] {
			let output = run_bit_pair(&valid, a, b).await;
			assert_eq!(output, Fr::from(expected));
		}
	}

	#[tokio::test]
	async fn xors_matches_boolean_xor_over_every_bit_pair() {
		let valid = bit_pair_program(|builder, a, b| builder.xor(a, b));
		for (a, b, expected) in [(0u64, 0u64, 0u64), (0, 1, 1), (1, 0, 1), (1, 1, 0)] {
			let output = run_bit_pair(&valid, a, b).await;
			assert_eq!(output, Fr::from(expected));
		}
	}

	#[tokio::test]
	async fn nots_flips_a_bit_in_place() {
		let mut builder = ProgramBuilder::default();
		let a = Bits::assume(builder.input(CLIENT, 1), 1);
		let negated = builder.not(a);
		builder.output(CLIENT, Secret::from(negated));
		let valid = must_build(builder);

		for (a, expected) in [(0u64, 1u64), (1, 0)] {
			let mut backend = PlainBackend::default();
			let output = must_execute(&valid, plain_inputs(&[a]), &mut backend, &TraceHandle::default()).await;
			assert_eq!(output.shares[0], Fr::from(expected));
		}
	}

	#[tokio::test]
	async fn mux_selects_t_when_cond_is_one_and_f_when_cond_is_zero() {
		let mut builder = ProgramBuilder::default();
		let cond = builder.input(CLIENT, 1);
		let t = builder.input(101, 1);
		let f = builder.input(102, 1);
		let selected = builder.mux(Bits::assume(cond, 1), t, f);
		builder.output(CLIENT, selected);
		let valid = must_build(builder);

		for (cond_bit, expected) in [(1u64, 30u64), (0u64, 40u64)] {
			let mut inputs = plain_inputs(&[cond_bit]);
			inputs.insert(101, vec![Fr::from(30u64)]);
			inputs.insert(102, vec![Fr::from(40u64)]);

			let mut backend = PlainBackend::default();
			let output = must_execute(&valid, inputs, &mut backend, &TraceHandle::default()).await;
			assert_eq!(output.shares[0], Fr::from(expected));
		}
	}

	#[tokio::test]
	async fn pack_reconstructs_a_byte_from_its_lsb_first_bits() {
		// 0xB4 = 0b1011_0100, LSB first: [0,0,1,0,1,1,0,1].
		let mut builder = ProgramBuilder::default();
		let bits = builder.input(CLIENT, 8);
		let packed = builder.pack(Bits::assume(bits, 8));
		builder.output(CLIENT, packed);
		let valid = must_build(builder);

		let lsb_first = [0u64, 0, 1, 0, 1, 1, 0, 1];
		let mut backend = PlainBackend::default();
		let output = must_execute(&valid, plain_inputs(&lsb_first), &mut backend, &TraceHandle::default()).await;

		assert_eq!(output.shares[0], Fr::from(0xB4u64));
	}

	#[tokio::test]
	async fn bit_dec_recovers_lsb_first_bits_for_every_element() {
		let mut builder = ProgramBuilder::default();
		let elements = builder.input(CLIENT, 2);
		let decomposed = builder.bit_dec(elements, 3);
		builder.output(CLIENT, Secret::from(decomposed));
		let valid = must_build(builder);

		let mut backend = PlainBackend::default();
		let output = must_execute(&valid, plain_inputs(&[0b101, 0b011]), &mut backend, &TraceHandle::default()).await;

		let expected: Vec<Fr> = [1u64, 0, 1, 1, 1, 0].into_iter().map(Fr::from).collect();
		assert_eq!(output.shares, expected);
	}

	#[tokio::test]
	async fn eq_reports_whether_every_low_bit_of_a_and_b_agrees() {
		for (a, b, width, expected) in [(5u64, 5u64, 3u8, 1u64), (5, 6, 3, 0), (0, 8, 3, 1)] {
			let mut builder = ProgramBuilder::default();
			let x = builder.input(CLIENT, 1);
			let y = builder.input(101, 1);
			let equal = builder.eq(x, y, width);
			builder.output(CLIENT, Secret::from(equal));
			let valid = must_build(builder);

			let mut inputs = plain_inputs(&[a]);
			inputs.insert(101, vec![Fr::from(b)]);
			let mut backend = PlainBackend::default();
			let output = must_execute(&valid, inputs, &mut backend, &TraceHandle::default()).await;

			assert_eq!(output.shares[0], Fr::from(expected));
		}
	}

	#[tokio::test]
	async fn lt_reports_unsigned_less_than_over_the_low_bits() {
		for (a, b, width, expected) in [(3u64, 5u64, 3u8, 1u64), (5, 3, 3, 0), (5, 5, 3, 0), (0, 7, 3, 1)] {
			let mut builder = ProgramBuilder::default();
			let x = builder.input(CLIENT, 1);
			let y = builder.input(101, 1);
			let less = builder.lt(x, y, width);
			builder.output(CLIENT, Secret::from(less));
			let valid = must_build(builder);

			let mut inputs = plain_inputs(&[a]);
			inputs.insert(101, vec![Fr::from(b)]);
			let mut backend = PlainBackend::default();
			let output = must_execute(&valid, inputs, &mut backend, &TraceHandle::default()).await;

			assert_eq!(output.shares[0], Fr::from(expected));
		}
	}

	#[tokio::test]
	async fn eq_and_lt_batch_every_element_in_one_call() {
		// a = [2, 5, 1], b = [2, 4, 7]: one equal pair, one greater, one less.
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 3);
		let y = builder.input(101, 3);
		let equal = builder.eq(x, y, 3);
		builder.output(CLIENT, Secret::from(equal));
		let valid_eq = must_build(builder);

		let mut inputs = plain_inputs(&[2u64, 5, 1]);
		inputs.insert(101, vec![Fr::from(2u64), Fr::from(4u64), Fr::from(7u64)]);
		let mut backend = PlainBackend::default();
		let output = must_execute(&valid_eq, inputs, &mut backend, &TraceHandle::default()).await;
		assert_eq!(output.shares, vec![Fr::from(1u64), Fr::from(0u64), Fr::from(0u64)]);

		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 3);
		let y = builder.input(101, 3);
		let less = builder.lt(x, y, 3);
		builder.output(CLIENT, Secret::from(less));
		let valid_lt = must_build(builder);

		let mut inputs = plain_inputs(&[2u64, 5, 1]);
		inputs.insert(101, vec![Fr::from(2u64), Fr::from(4u64), Fr::from(7u64)]);
		let mut backend = PlainBackend::default();
		let output = must_execute(&valid_lt, inputs, &mut backend, &TraceHandle::default()).await;
		assert_eq!(output.shares, vec![Fr::from(0u64), Fr::from(0u64), Fr::from(1u64)]);
	}

	#[tokio::test]
	async fn input_arity_disagreements_are_refused() {
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 2);
		builder.output(CLIENT, x);
		let valid = must_build(builder);

		let mut backend = PlainBackend::default();
		let outcome = execute(&valid, plain_inputs(&[1]), &mut backend, &TraceHandle::default()).await;
		assert!(matches!(
			outcome,
			Err(VmError::InputArity { client: CLIENT, expected: 2, got: 1 })
		));
	}

	#[tokio::test]
	async fn sbox_and_byte_xor_match_clear_byte_ops() {
		use crate::circuits::aes128::AES_SBOX;

		let mut builder = ProgramBuilder::default();
		let x = builder.input_bytes(CLIENT, 2);
		let y = builder.input_bytes(101, 2);
		let x_bits = builder.bit_dec(x, 8);
		let substituted_bits = builder.sbox(x_bits);
		let substituted = builder.pack(substituted_bits);
		let xored = builder.byte_xor(substituted, y);
		builder.output(CLIENT, xored);
		let valid = must_build(builder);

		let mut inputs = plain_inputs(&[0x53u64, 0xff]);
		inputs.insert(101, vec![Fr::from(0x11u64), Fr::from(0x22u64)]);
		let mut backend = PlainBackend::default();
		let output = must_execute(&valid, inputs, &mut backend, &TraceHandle::default()).await;

		assert_eq!(
			output.shares,
			vec![
				Fr::from(u64::from(AES_SBOX[0x53] ^ 0x11)),
				Fr::from(u64::from(AES_SBOX[0xff] ^ 0x22)),
			]
		);
	}

	#[tokio::test]
	async fn aes128_encrypt_block_matches_clear_reference() {
		use crate::circuits::aes128::{encrypt_block, BLOCK_LEN};
		use aes::Aes128;
		use cipher::{BlockEncrypt, KeyInit};

		// FIPS 197 Appendix C.1.
		const KEY: [u8; 16] = [
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		];
		const PLAIN: [u8; 16] = [
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		];

		let mut builder = ProgramBuilder::default();
		let inputs = builder.input_bytes(CLIENT, BLOCK_LEN * 2);
		let key = inputs.slice(0, BLOCK_LEN);
		let block = inputs.slice(BLOCK_LEN, BLOCK_LEN);
		let ciphertext = encrypt_block(&mut builder, key, block);
		builder.output(CLIENT, ciphertext);
		let valid = match builder.build() {
			Ok(program) => program,
			Err(error) => panic!("the AES program should validate: {error}"),
		};

		let mut values = Vec::with_capacity(32);
		values.extend(KEY.iter().map(|byte| u64::from(*byte)));
		values.extend(PLAIN.iter().map(|byte| u64::from(*byte)));

		let mut backend = PlainBackend::default();
		let output = match execute(&valid, plain_inputs(&values), &mut backend, &TraceHandle::default()).await {
			Ok(output) => output,
			Err(error) => panic!("AES execution should complete: {error}"),
		};

		let mut reference = PLAIN;
		let cipher = match Aes128::new_from_slice(&KEY) {
			Ok(cipher) => cipher,
			Err(error) => panic!("AES-128 key length is fixed: {error}"),
		};
		cipher.encrypt_block((&mut reference).into());

		let recovered: Vec<u8> = output.shares.iter().map(|share| to_u128(share) as u8).collect();
		assert_eq!(recovered, reference.as_slice());
	}
}
