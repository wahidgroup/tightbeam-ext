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
/// The program bytes carry no tracing of their own; `trace` is the
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

	use crate::builder::ProgramBuilder;
	use crate::isa::FixedPrecision;

	const CLIENT: ClientId = 100;

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
		let valid = builder.build().expect("the program should validate");

		let mut backend = PlainBackend::default();
		let output = execute(&valid, plain_inputs(&[3, 4]), &mut backend, &TraceHandle::default())
			.await
			.expect("execution should complete");

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
		let valid = builder.build().expect("the program should validate");

		let mut backend = PlainBackend::default();
		let output = execute(&valid, plain_inputs(&[10, 20]), &mut backend, &TraceHandle::default())
			.await
			.expect("execution should complete");

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
		let valid = builder.build().expect("the program should validate");

		let mut inputs = plain_inputs(&[2]);
		inputs.insert(101, vec![Fr::from(3u64)]);

		let mut backend = PlainBackend::default();
		let output = execute(&valid, inputs, &mut backend, &TraceHandle::default())
			.await
			.expect("execution should complete");

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
		let valid = builder.build().expect("the program should validate");

		let mut inputs = plain_inputs(&[10]);
		inputs.insert(101, vec![Fr::from(4u64)]);

		let mut backend = PlainBackend::default();
		let output = execute(&valid, inputs, &mut backend, &TraceHandle::default())
			.await
			.expect("execution should complete");

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
		let valid = builder.build().expect("the program should validate");

		let mut inputs = plain_inputs(&[2, 3]);
		inputs.insert(101, vec![Fr::from(5u64), Fr::from(7u64)]);

		let mut backend = PlainBackend::default();
		let output = execute(&valid, inputs, &mut backend, &TraceHandle::default())
			.await
			.expect("execution should complete");

		// (x*y) + (x*x) = [10 + 4, 21 + 9]
		assert_eq!(output.shares, vec![Fr::from(14u64), Fr::from(30u64)]);
	}

	#[tokio::test]
	async fn fixed_point_ops_truncate_by_the_fractional_width() {
		// f = 4: x = 5.5 (raw 88), y = 2.0 (raw 32).
		// x * y = 11.0 (raw 176); 11.0 / 2.0 = 5.5 (raw 88).
		let precision = FixedPrecision { k: 16, f: 4 };
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 1);
		let y = builder.input(101, 1);
		let product = builder.fp_mul(x, y, precision);
		let quotient = builder.fp_div(product, 32, precision);
		builder.output(CLIENT, quotient);
		let valid = builder.build().expect("the program should validate");

		let mut inputs = plain_inputs(&[88]);
		inputs.insert(101, vec![Fr::from(32u64)]);

		let mut backend = PlainBackend::default();
		let output = execute(&valid, inputs, &mut backend, &TraceHandle::default())
			.await
			.expect("execution should complete");

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
		let valid = builder.build().expect("the program should validate");

		let trace = TraceHandle::default();
		let mut backend = PlainBackend::default();
		execute(&valid, plain_inputs(&[2]), &mut backend, &trace)
			.await
			.expect("execution should complete");

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
	async fn missing_declared_inputs_are_refused() {
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 1);
		builder.output(CLIENT, x);
		let valid = builder.build().expect("the program should validate");

		let mut backend = PlainBackend::default();
		let outcome = execute(&valid, HashMap::new(), &mut backend, &TraceHandle::default()).await;
		assert!(matches!(outcome, Err(VmError::MissingInput { client: CLIENT })));
	}

	#[tokio::test]
	async fn input_arity_disagreements_are_refused() {
		let mut builder = ProgramBuilder::default();
		let x = builder.input(CLIENT, 2);
		builder.output(CLIENT, x);
		let valid = builder.build().expect("the program should validate");

		let mut backend = PlainBackend::default();
		let outcome = execute(&valid, plain_inputs(&[1]), &mut backend, &TraceHandle::default()).await;
		assert!(matches!(
			outcome,
			Err(VmError::InputArity { client: CLIENT, expected: 2, got: 1 })
		));
	}
}
