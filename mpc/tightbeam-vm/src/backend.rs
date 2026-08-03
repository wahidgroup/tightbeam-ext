//! Execution backends: the segregated engine surface the executor
//! drives.
//!
//! [`SecretOps`] is everything the interpreter needs - local linear
//! arithmetic, batched interactive multiplication, and reveal. The
//! HoneyBadger implementation is the crate's single boundary with
//! engine internals; the executor itself never touches the node, the
//! network, or the control lane.

use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;

use ark_ff::{FftField, PrimeField};
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

use crate::control::ControlMessage;
use crate::error::{CodecError, Result, VmError};
use crate::isa::FixedPrecision;

/// The engine surface one program execution drives.
///
/// Linear operations are local (no protocol round); `mul_batch` and
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
	/// from a mesh party; buffer future ordinals.
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
	/// means keep collecting; an interpolation failure is only final
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
}
