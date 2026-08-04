//! Execution backends: the segregated engine surface the executor
//! drives.
//!
//! [`SecretOps`] is everything the interpreter needs - local linear
//! arithmetic, batched interactive multiplication, and reveal. The
//! HoneyBadger implementation is the crate's single boundary with
//! engine internals. The executor itself never touches the node, the
//! network, or the control lane.

use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;

use ark_ff::{BigInteger, FftField, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use stoffelcrypto::common::types::fixed::{
	global_precision, try_init_global_precision, ClearFixedPoint, FixedPointPrecision, SecretFixedPoint,
};
use stoffelcrypto::common::{MPCProtocol, MPCTypeOps, RBC};
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::{batch_recover_secret, RobustShare};
use stoffelcrypto::honeybadger::{HoneyBadgerMPCNode, SessionId};
use stoffelnet::network_utils::PartyId;
use tightbeam_mpc::{Delivery, SessionError, TightbeamNetwork};
use tokio::sync::mpsc::Receiver;
use tokio::time::Instant;

use crate::circuits::aes128::AES_SBOX;
use crate::control::ControlMessage;
use crate::error::{CodecError, Result, VmError};
use crate::isa::FixedPrecision;

/// The engine surface one program execution drives.
///
/// Linear operations are local (no protocol round). `mul_batch` and
/// `reveal` are interactive. `reveal` takes the reveal's program-order
/// ordinal so every party pairs shares of the same instruction.
pub trait SecretOps<F> {
	/// The share representation flowing through secret registers.
	type Share: Clone + Send;

	/// Element-wise secret addition.
	fn add(&self, a: &Self::Share, b: &Self::Share) -> Result<Self::Share>;

	/// Element-wise secret subtraction.
	fn sub(&self, a: &Self::Share, b: &Self::Share) -> Result<Self::Share>;

	/// Add a public constant to a share.
	fn add_clear(&self, a: &Self::Share, c: F) -> Result<Self::Share>;

	/// Subtract a public constant from a share.
	fn sub_clear(&self, a: &Self::Share, c: F) -> Result<Self::Share>;

	/// Scale a share by a public constant.
	fn mul_clear(&self, a: &Self::Share, c: F) -> Result<Self::Share>;

	/// Batched Beaver multiplication: one protocol round for the whole
	/// batch.
	fn mul_batch(
		&mut self,
		x: Vec<Self::Share>,
		y: Vec<Self::Share>,
	) -> impl core::future::Future<Output = Result<Vec<Self::Share>>> + Send;

	/// Element-wise fixed-point multiplication with probabilistic
	/// truncation by `2^f`.
	fn fp_mul_batch(
		&mut self,
		x: Vec<Self::Share>,
		y: Vec<Self::Share>,
		precision: FixedPrecision,
	) -> impl core::future::Future<Output = Result<Vec<Self::Share>>> + Send;

	/// Element-wise fixed-point division by one public divisor (a raw
	/// fixed-point value), with probabilistic truncation.
	fn fp_div_clear_batch(
		&mut self,
		x: Vec<Self::Share>,
		divisor: F,
		precision: FixedPrecision,
	) -> impl core::future::Future<Output = Result<Vec<Self::Share>>> + Send;

	/// Open shares to every party and return the reconstructed values.
	fn reveal(
		&mut self,
		ordinal: u32,
		shares: &[Self::Share],
	) -> impl core::future::Future<Output = Result<Vec<F>>> + Send;

	/// Decompose every element of `x` into its `width` low bits,
	/// LSB-first, via mask-and-reveal: one interactive round per bit
	/// position, batched across every element of `x` at once.
	/// `ordinal` shares the reveal-pairing ordinal space with
	/// [`SecretOps::reveal`], since the mask step opens one batch of
	/// values under the hood.
	///
	/// Every element of `x` MUST already be known (by the caller's
	/// construction) to fit in `width` bits. The result is the
	/// low-`width`-bit representation of `x mod 2^width`, not a
	/// range proof.
	fn bit_dec(
		&mut self,
		ordinal: u32,
		x: Vec<Self::Share>,
		width: u8,
	) -> impl core::future::Future<Output = Result<Vec<Self::Share>>> + Send;

	/// Batched AES S-box on LSB-first byte bit groups (`x.len` is a
	/// multiple of 8). Consumes one reveal ordinal to open `δ = x ⊕ r`.
	fn sbox_batch(
		&mut self,
		ordinal: u32,
		x: Vec<Self::Share>,
	) -> impl core::future::Future<Output = Result<Vec<Self::Share>>> + Send;

	/// Element-wise XOR on byte-valued secrets. Consumes two reveal
	/// ordinals for the two width-8 decompositions.
	fn byte_xor_batch(
		&mut self,
		ordinal: u32,
		a: Vec<Self::Share>,
		b: Vec<Self::Share>,
	) -> impl core::future::Future<Output = Result<Vec<Self::Share>>> + Send;
}

/// Translate a program's fixed-point format into the engine's and pin
/// (or match) the process-global precision without tripping the
/// engine's asserts: stoffelcrypto locks one format per process, so a
/// disagreeing program is refused here with an error.
fn align_precision<F>(precision: FixedPrecision) -> Result<FixedPointPrecision>
where
	F: PrimeField,
{
	let unsupported = VmError::PrecisionUnsupported { k: precision.k, f: precision.f };
	if precision.f >= precision.k || u32::from(precision.k) >= F::MODULUS_BIT_SIZE {
		return Err(unsupported);
	}

	let desired = FixedPointPrecision::new(usize::from(precision.k), usize::from(precision.f));
	let _ = try_init_global_precision(desired);
	if *global_precision() != desired {
		return Err(unsupported);
	}

	Ok(desired)
}

/// [`SecretOps`] over a HoneyBadger node and the tightbeam control
/// lane.
pub struct HoneyBadgerBackend<'a, F, R>
where
	F: PrimeField,
	R: RBC<Id = SessionId>,
{
	node: &'a mut HoneyBadgerMPCNode<F, R>,
	network: Arc<TightbeamNetwork>,
	control: &'a mut Receiver<Delivery>,
	/// Shares that arrived for a future reveal while an earlier one was
	/// still collecting: a faster peer may already be one reveal ahead.
	pending: HashMap<u32, Vec<(PartyId, Vec<F>)>>,
	parties: usize,
	threshold: usize,
	reveal_deadline: Duration,
}

impl<'a, F, R> HoneyBadgerBackend<'a, F, R>
where
	F: PrimeField + FftField,
	R: RBC<Id = SessionId>,
{
	/// Assemble a backend over the engine node, the mesh, and the
	/// taken control inbox.
	pub fn new(
		node: &'a mut HoneyBadgerMPCNode<F, R>,
		network: Arc<TightbeamNetwork>,
		control: &'a mut Receiver<Delivery>,
		parties: usize,
		threshold: usize,
		reveal_deadline: Duration,
	) -> Self {
		Self {
			node,
			network,
			control,
			pending: HashMap::new(),
			parties,
			threshold,
			reveal_deadline,
		}
	}

	/// Accept one inbound reveal share batch if it is well formed and
	/// from a mesh party. Buffer future ordinals.
	fn absorb(
		&mut self,
		ordinal: u32,
		width: usize,
		sender: PartyId,
		raw: &[u8],
		collected: &mut Vec<(PartyId, Vec<F>)>,
	) {
		if sender >= self.parties {
			return;
		}

		let Ok(ControlMessage::Reveal { ordinal: seen, payload }) = ControlMessage::decode(raw) else {
			return;
		};
		let Ok(values) = Vec::<F>::deserialize_compressed(payload.as_slice()) else {
			return;
		};
		if values.len() != width {
			return;
		}

		let duplicate = |entries: &[(PartyId, Vec<F>)]| entries.iter().any(|(id, _)| *id == sender);
		if seen == ordinal && !duplicate(collected) {
			collected.push((sender, values));
			return;
		}
		if seen > ordinal {
			let bucket = self.pending.entry(seen).or_default();
			if !duplicate(bucket) {
				bucket.push((sender, values));
			}
		}
	}

	/// Attempt reconstruction once enough senders reported. `Ok(None)`
	/// means keep collecting. An interpolation failure is only final
	/// once every party reported.
	fn reconstruct(&self, collected: &[(PartyId, Vec<F>)]) -> Result<Option<Vec<F>>> {
		let needed = 2 * self.threshold + 1;
		if collected.len() < needed {
			return Ok(None);
		}

		let outcome = batch_recover_secret(collected, self.parties, self.threshold, self.threshold);
		match outcome {
			Ok(decoded) => {
				let mut secrets = Vec::with_capacity(decoded.len());
				for coeffs in decoded {
					let Some(secret) = coeffs.into_iter().next() else {
						return Err(VmError::EmptySecret);
					};
					secrets.push(secret);
				}
				Ok(Some(secrets))
			}
			Err(cause) => {
				if collected.len() == self.parties {
					return Err(VmError::Interpolate(cause));
				}
				Ok(None)
			}
		}
	}
}

impl<F, R> SecretOps<F> for HoneyBadgerBackend<'_, F, R>
where
	F: PrimeField + FftField,
	R: RBC<Id = SessionId> + Send + Sync,
{
	type Share = RobustShare<F>;

	fn add(&self, a: &Self::Share, b: &Self::Share) -> Result<Self::Share> {
		let sum = (a.clone() + b.clone())?;
		Ok(sum)
	}

	fn sub(&self, a: &Self::Share, b: &Self::Share) -> Result<Self::Share> {
		let difference = (a.clone() - b.clone())?;
		Ok(difference)
	}

	fn add_clear(&self, a: &Self::Share, c: F) -> Result<Self::Share> {
		let sum = (a.clone() + c)?;
		Ok(sum)
	}

	fn sub_clear(&self, a: &Self::Share, c: F) -> Result<Self::Share> {
		let difference = (a.clone() - c)?;
		Ok(difference)
	}

	fn mul_clear(&self, a: &Self::Share, c: F) -> Result<Self::Share> {
		let scaled = (a.clone() * c)?;
		Ok(scaled)
	}

	async fn mul_batch(&mut self, x: Vec<Self::Share>, y: Vec<Self::Share>) -> Result<Vec<Self::Share>> {
		let network = Arc::clone(&self.network);
		let products = self.node.mul(x, y, network).await.map_err(SessionError::from)?;
		Ok(products)
	}

	async fn fp_mul_batch(
		&mut self,
		x: Vec<Self::Share>,
		y: Vec<Self::Share>,
		precision: FixedPrecision,
	) -> Result<Vec<Self::Share>> {
		let format = align_precision::<F>(precision)?;

		// The engine's fixed-point multiplication is per element: each
		// carries its own truncation session.
		let mut products = Vec::with_capacity(x.len());
		for (a, b) in x.into_iter().zip(y) {
			let left = SecretFixedPoint::new_with_precision(a, format);
			let right = SecretFixedPoint::new_with_precision(b, format);
			let network = Arc::clone(&self.network);
			let product = self.node.mul_fixed(left, right, network).await.map_err(SessionError::from)?;
			products.push(product.value().clone());
		}

		Ok(products)
	}

	async fn fp_div_clear_batch(
		&mut self,
		x: Vec<Self::Share>,
		divisor: F,
		precision: FixedPrecision,
	) -> Result<Vec<Self::Share>> {
		let format = align_precision::<F>(precision)?;
		let clear = ClearFixedPoint::new_with_precision(divisor, format);

		let mut quotients = Vec::with_capacity(x.len());
		for a in x {
			let dividend = SecretFixedPoint::new_with_precision(a, format);
			let network = Arc::clone(&self.network);
			let quotient = self
				.node
				.div_with_const_fixed(dividend, clear, network)
				.await
				.map_err(SessionError::from)?;
			quotients.push(quotient.value().clone());
		}

		Ok(quotients)
	}

	async fn reveal(&mut self, ordinal: u32, shares: &[Self::Share]) -> Result<Vec<F>> {
		let width = shares.len();
		let mut values = Vec::with_capacity(shares.len());
		for share in shares {
			let Some(value) = share.share.first().copied() else {
				return Err(VmError::EmptySecret);
			};
			values.push(value);
		}

		let mut payload = Vec::new();
		values.serialize_compressed(&mut payload).map_err(CodecError::from)?;
		let message = ControlMessage::Reveal { ordinal, payload }.encode()?;

		for peer in 0..self.parties {
			self.network.send_control(peer, &message).await?;
		}

		let mut collected = self.pending.remove(&ordinal).unwrap_or_default();
		collected.retain(|(_, entry)| entry.len() == width);
		if let Some(secrets) = self.reconstruct(&collected)? {
			return Ok(secrets);
		}

		let deadline = Instant::now() + self.reveal_deadline;
		loop {
			let now = Instant::now();
			if now >= deadline {
				return Err(VmError::RevealTimeout { ordinal });
			}

			let arrival = tokio::time::timeout(deadline - now, self.control.recv()).await;
			let Ok(delivery) = arrival else {
				return Err(VmError::RevealTimeout { ordinal });
			};
			let Some((sender, raw)) = delivery else {
				return Err(VmError::ControlClosed);
			};

			self.absorb(ordinal, width, sender, &raw, &mut collected);
			if let Some(secrets) = self.reconstruct(&collected)? {
				return Ok(secrets);
			}
		}
	}

	async fn bit_dec(&mut self, ordinal: u32, x: Vec<Self::Share>, width: u8) -> Result<Vec<Self::Share>> {
		let count = x.len();
		let width = width as usize;
		if count == 0 || width == 0 {
			return Ok(Vec::new());
		}

		let drained = {
			let mut store = self.node.preprocessing_material.lock().await;
			store.take_prandbit_shares(count * width).map_err(SessionError::from)?
		};
		let mask_bits: Vec<Self::Share> = drained.into_iter().map(|(share, _companion)| share).collect();

		let mut masked = Vec::with_capacity(count);
		for (element, bits) in x.iter().zip(mask_bits.chunks(width)) {
			masked.push(self.mask(element, bits)?);
		}

		let opened = self.reveal(ordinal, &masked).await?;
		let public_bits: Vec<Vec<F>> = opened.iter().map(|value| public_bit_vector(*value, width)).collect();

		let zero_borrow = self.sub(&mask_bits[0], &mask_bits[0])?;
		let mut borrow = vec![zero_borrow; count];
		let mut planes: Vec<Vec<Self::Share>> = vec![Vec::with_capacity(width); count];

		for position in 0..width {
			let bit_shares: Vec<&Self::Share> =
				(0..count).map(|element| &mask_bits[element * width + position]).collect();
			let position_public: Vec<F> = (0..count).map(|element| public_bits[element][position]).collect();
			let bit_xor_public: Vec<Self::Share> = (0..count)
				.map(|element| self.xor_with_public(bit_shares[element], position_public[element]))
				.collect::<Result<Vec<_>>>()?;

			let round = self
				.subtractor_round(&bit_xor_public, bit_shares.as_slice(), &position_public, &borrow)
				.await?;
			for (element, plane) in planes.iter_mut().enumerate() {
				plane.push(round.difference[element].clone());
			}
			borrow = round.borrow_out;
		}

		let mut bits = Vec::with_capacity(count * width);
		for plane in planes {
			bits.extend(plane);
		}
		Ok(bits)
	}

	async fn sbox_batch(&mut self, ordinal: u32, x_bits: Vec<Self::Share>) -> Result<Vec<Self::Share>> {
		if x_bits.is_empty() {
			return Ok(Vec::new());
		}
		let count = x_bits.len() / 8;

		// v1 mask material: one random byte per lookup, held as bits.
		let mask_bits = {
			let mut store = self.node.preprocessing_material.lock().await;
			let drained = store.take_prandbit_shares(count * 8).map_err(SessionError::from)?;
			drained.into_iter().map(|(share, _companion)| share).collect::<Vec<_>>()
		};

		let products = self.mul_batch(x_bits.clone(), mask_bits.clone()).await?;
		let mut delta_bits = Vec::with_capacity(count * 8);
		for ((left, right), product) in x_bits.into_iter().zip(mask_bits.iter().cloned()).zip(products) {
			let sum = self.add(&left, &right)?;
			let doubled = self.mul_clear(&product, F::from(2u64))?;
			delta_bits.push(self.sub(&sum, &doubled)?);
		}

		let mut deltas = Vec::with_capacity(count);
		for element in 0..count {
			let bits = &delta_bits[element * 8..element * 8 + 8];
			let mut accumulator = self.mul_clear(&bits[0], F::from(1u64))?;
			for (position, bit) in bits.iter().enumerate().skip(1) {
				let weighted = self.mul_clear(bit, F::from(1u64 << position))?;
				accumulator = self.add(&accumulator, &weighted)?;
			}
			deltas.push(accumulator);
		}

		let opened = self.reveal(ordinal, &deltas).await?;
		let bytes = self.select_sbox_bytes(&mask_bits, &opened).await?;
		// Return bit planes so AES linear layers stay on `XorS` wires.
		self.bit_dec(ordinal.saturating_add(1), bytes, 8).await
	}

	async fn byte_xor_batch(
		&mut self,
		ordinal: u32,
		a: Vec<Self::Share>,
		b: Vec<Self::Share>,
	) -> Result<Vec<Self::Share>> {
		let count = a.len();
		if count == 0 {
			return Ok(Vec::new());
		}

		let a_bits = self.bit_dec(ordinal, a, 8).await?;
		let b_bits = self.bit_dec(ordinal + 1, b, 8).await?;
		let products = self.mul_batch(a_bits.clone(), b_bits.clone()).await?;

		let mut xor_bits = Vec::with_capacity(count * 8);
		for ((left, right), product) in a_bits.into_iter().zip(b_bits).zip(products) {
			let sum = self.add(&left, &right)?;
			let doubled = self.mul_clear(&product, F::from(2u64))?;
			xor_bits.push(self.sub(&sum, &doubled)?);
		}

		let mut outputs = Vec::with_capacity(count);
		for element in 0..count {
			let bits = &xor_bits[element * 8..element * 8 + 8];
			let mut accumulator = self.mul_clear(&bits[0], F::from(1u64))?;
			for (position, bit) in bits.iter().enumerate().skip(1) {
				let weighted = self.mul_clear(bit, F::from(1u64 << position))?;
				accumulator = self.add(&accumulator, &weighted)?;
			}
			outputs.push(accumulator);
		}
		Ok(outputs)
	}
}

/// Low byte of a revealed field element.
fn field_byte<F: PrimeField>(value: F) -> u8 {
	let bytes = value.into_bigint().to_bytes_le();
	match bytes.first() {
		Some(byte) => *byte,
		None => 0,
	}
}

/// The low `width` bits of `value`, LSB-first, lifted back into the
/// field as `{0,1}` elements for use as public mask-and-reveal
/// coefficients.
fn public_bit_vector<F: PrimeField>(value: F, width: usize) -> Vec<F> {
	let bits = value.into_bigint().to_bits_le();
	(0..width)
		.map(|position| {
			if bits.get(position).copied().unwrap_or(false) {
				F::from(1u64)
			} else {
				F::from(0u64)
			}
		})
		.collect()
}

/// One ripple-borrow-subtractor stage's outputs: the recovered
/// difference bit and the borrow propagated into the next, higher,
/// bit position.
struct SubtractorStage<S> {
	difference: Vec<S>,
	borrow_out: Vec<S>,
}

impl<'a, F, R> HoneyBadgerBackend<'a, F, R>
where
	F: PrimeField + FftField,
	R: RBC<Id = SessionId> + Send + Sync,
{
	/// Combine `bits` (LSB-first, `{0,1}` shares) into one arithmetic
	/// mask and add it to `element`: the local masking step of
	/// `bit_dec`.
	fn mask(&self, element: &RobustShare<F>, bits: &[RobustShare<F>]) -> Result<RobustShare<F>> {
		let mut accumulator = self.mul_clear(&bits[0], F::from(1u64))?;
		for (position, bit) in bits.iter().enumerate().skip(1) {
			let weighted = self.mul_clear(bit, F::from(1u64 << position))?;
			accumulator = self.add(&accumulator, &weighted)?;
		}
		self.add(element, &accumulator)
	}

	/// Local XOR of a secret bit against a public bit. `a + b - 2ab`
	/// degenerates to an affine function of the secret operand when
	/// one operand is public, so no protocol round is needed.
	fn xor_with_public(&self, secret: &RobustShare<F>, public: F) -> Result<RobustShare<F>> {
		let coefficient = F::from(1u64) - public - public;
		let scaled = self.mul_clear(secret, coefficient)?;
		self.add_clear(&scaled, public)
	}

	/// One bit position of the mask-and-reveal ripple-borrow
	/// subtractor `x = c - r` (mod `2^width`): recovers the
	/// difference bit and the borrow into the next position from the
	/// public minuend bit `c_i`, the secret subtrahend bit `r_i`, and
	/// the incoming secret borrow. One batched protocol round covers
	/// every element at this bit position together.
	async fn subtractor_round(
		&mut self,
		bit_xor_public: &[RobustShare<F>],
		bit_shares: &[&RobustShare<F>],
		public_bits: &[F],
		borrow_in: &[RobustShare<F>],
	) -> Result<SubtractorStage<RobustShare<F>>> {
		let count = borrow_in.len();
		let mut x_batch = bit_xor_public.to_vec();
		x_batch.extend(bit_shares.iter().map(|share| (*share).clone()));
		let mut y_batch = borrow_in.to_vec();
		y_batch.extend(borrow_in.iter().cloned());

		let products = self.mul_batch(x_batch, y_batch).await?;
		let (diff_products, borrow_products) = products.split_at(count);

		let mut difference = Vec::with_capacity(count);
		let mut borrow_out = Vec::with_capacity(count);
		for element in 0..count {
			let sum = self.add(&bit_xor_public[element], &borrow_in[element])?;
			let doubled = self.mul_clear(&diff_products[element], F::from(2u64))?;
			difference.push(self.sub(&sum, &doubled)?);

			let public = public_bits[element];
			let borrow_coefficient = public + public - F::from(1u64);
			let complement = F::from(1u64) - public;
			let from_borrow_product = self.mul_clear(&borrow_products[element], borrow_coefficient)?;
			let from_bit = self.mul_clear(bit_shares[element], complement)?;
			let from_borrow_in = self.mul_clear(&borrow_in[element], complement)?;
			let partial = self.add(&from_borrow_product, &from_bit)?;
			borrow_out.push(self.add(&partial, &from_borrow_in)?);
		}

		Ok(SubtractorStage { difference, borrow_out })
	}

	/// One depth-8 mux tree per byte over the public row
	/// `V[k] = S(δ ⊕ k)`, driven by the secret mask bits. The first
	/// level is local against public leaves. Remaining levels cost
	/// [`crate::validate::SBOX_ONLINE_MUXES`] Beaver muls per byte.
	async fn select_sbox_bytes(&mut self, mask_bits: &[RobustShare<F>], opened: &[F]) -> Result<Vec<RobustShare<F>>> {
		let count = opened.len();
		let mut level: Vec<RobustShare<F>> = Vec::with_capacity(count * 128);
		for (element, delta) in opened.iter().enumerate() {
			let delta_byte = field_byte(*delta);
			let bit0 = &mask_bits[element * 8];
			for index in 0..128u8 {
				let left = AES_SBOX[usize::from(delta_byte ^ (index << 1))];
				let right = AES_SBOX[usize::from(delta_byte ^ ((index << 1) | 1))];
				let delta_val = F::from(u64::from(right)) - F::from(u64::from(left));
				let scaled = self.mul_clear(bit0, delta_val)?;
				level.push(self.add_clear(&scaled, F::from(u64::from(left)))?);
			}
		}

		for mask_bit in 1..8 {
			let width = 128 >> mask_bit;
			let mut differences = Vec::with_capacity(count * width);
			let mut bases = Vec::with_capacity(count * width);
			let mut selectors = Vec::with_capacity(count * width);
			for element in 0..count {
				let bit = &mask_bits[element * 8 + mask_bit];
				let base = element * (width * 2);
				for index in 0..width {
					let left = &level[base + index * 2];
					let right = &level[base + index * 2 + 1];
					bases.push(left.clone());
					differences.push(self.sub(right, left)?);
					selectors.push(bit.clone());
				}
			}
			let scaled = self.mul_batch(differences, selectors).await?;
			let mut next = Vec::with_capacity(count * width);
			for (base, delta) in bases.into_iter().zip(scaled) {
				next.push(self.add(&base, &delta)?);
			}
			level = next;
		}

		Ok(level)
	}
}
