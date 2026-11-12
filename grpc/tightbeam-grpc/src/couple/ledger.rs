//! The ledger that a coupler spends the claims of its calls in: a driver
//! contract, so replicas of an edge share any store that keeps it.
//!
//! # Sources
//!
//! - CWE-294, Authentication Bypass by Capture-replay: <https://cwe.mitre.org/data/definitions/294.html>
//! - tightbeam README, section 5.7.1: <https://github.com/wahidgroup/tightbeam/blob/master/README.md>

use core::fmt;
use core::future::Future;
use core::pin::Pin;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use tightbeam::colony::hive::gates::REPLAY_GUARD_CAPACITY;

/// The most live spends of one signer that a [`MemoryLedger`] holds, the
/// bound of the replay guard of a tightbeam hive.
const PER_SIGNER: usize = REPLAY_GUARD_CAPACITY;

/// The future of one operation of a ledger.
pub type LedgerFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, LedgerError>> + Send + 'a>>;

/// Where a coupler spends the claims of its calls.
///
/// A driver MUST keep this contract. `testing::LedgerConformance` checks each
/// clause but the last:
///
/// - [`ClaimLedger::spend`] holds [`ClaimSpend::key`] until
///   [`ClaimSpend::expires`], and answers `true` for the one spend that took
///   it.
/// - Each spend reads the time from the `now` of the coupler, not from a clock of the driver.
/// - A spend of a key that a live spend holds answers `false`, whichever holder took it.
/// - A spend whose expiry is not after `now` answers `false`.
/// - Each key is a spend of its own, so two keys of one signer both take.
/// - The test of a key and its take are one atomic operation, so of concurrent
///   spends of one key, exactly one answers `true`.
/// - [`ClaimLedger::forget`] frees a key only for the holder that took it.
/// - A key frees itself at its expiry.
/// - A failure answers [`LedgerError`]. A failed spend refuses the call with
///   14, and a failed forget keeps the claim spent. A forget that the driver
///   does not answer within the call limit of the coupler counts as failed.
///
/// A driver MAY refuse:
///
/// - A fresh key of a signer that holds [`REPLAY_GUARD_CAPACITY`] live spends
///   or more, as the replay guard of a tightbeam hive bounds each signer. The
///   coupler reads that refusal as a replay.
pub trait ClaimLedger: Send + Sync + 'static {
	/// Take the key of `spend` at `now`, the time of the coupler, until its
	/// expiry.
	///
	/// # Errors
	///
	/// - The [`LedgerError`] of a store of the driver that failed.
	fn spend<'a>(&'a self, spend: &'a ClaimSpend, now: SystemTime) -> LedgerFuture<'a, bool>;

	/// Free the key of `spend`, when its holder took it.
	///
	/// # Errors
	///
	/// - The [`LedgerError`] of a store of the driver that failed.
	fn forget<'a>(&'a self, spend: &'a ClaimSpend) -> LedgerFuture<'a, ()>;
}

/// The key of a spend: the SHA-256 of the signer and the order of its claim,
/// which names the claim on every replica. One signer issues one claim at one
/// order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClaimKey([u8; 32]);

impl ClaimKey {
	/// The key of the digest `bytes`.
	pub(crate) fn new(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// The bytes of the key, which a driver stores.
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// The SHA-256 of the certificate of the signer of a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SignerDigest([u8; 32]);

impl SignerDigest {
	/// The signer of the digest `bytes`.
	pub(crate) fn new(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// The bytes of the digest, which a driver stores.
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// The holder of one spend of a claim, which alone may forget it. Each spend
/// that a coupler makes takes a holder of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HolderId([u8; 16]);

impl HolderId {
	/// The holder of the id `bytes`.
	pub(crate) fn new(bytes: [u8; 16]) -> Self {
		Self(bytes)
	}

	/// The bytes of the id, which a driver stores.
	pub fn as_bytes(&self) -> &[u8; 16] {
		&self.0
	}
}

/// One spend of a claim: the key that names it on every replica, the signer
/// that made it, when it stops being fresh, and the holder of the spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimSpend {
	key: ClaimKey,
	signer: SignerDigest,
	expires: SystemTime,
	holder: HolderId,
}

impl ClaimSpend {
	/// The spend of the claim named `key`, of `signer`, until `expires`, by
	/// `holder`.
	pub(crate) fn new(key: ClaimKey, signer: SignerDigest, expires: SystemTime, holder: HolderId) -> Self {
		Self { key, signer, expires, holder }
	}

	/// The key that names the claim on every replica.
	pub fn key(&self) -> &ClaimKey {
		&self.key
	}

	/// The digest of the certificate that signed the claim.
	pub fn signer(&self) -> &SignerDigest {
		&self.signer
	}

	/// When the claim leaves the replay window, after which no coupler admits
	/// it, so its key may free.
	pub fn expires(&self) -> SystemTime {
		self.expires
	}

	/// The holder of the spend, which alone may forget it.
	pub fn holder(&self) -> &HolderId {
		&self.holder
	}
}

/// A failure of the store of a ledger driver.
#[derive(Debug)]
pub struct LedgerError(Box<dyn std::error::Error + Send + Sync>);

impl LedgerError {
	/// The failure `source` of the store.
	pub fn new(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
		Self(source.into())
	}
}

impl fmt::Display for LedgerError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "the claim ledger failed: {}", self.0)
	}
}

impl std::error::Error for LedgerError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		Some(&*self.0)
	}
}

/// One live spend of a [`MemoryLedger`].
struct Live {
	signer: SignerDigest,
	expires: SystemTime,
	holder: HolderId,
}

/// The live spends of a [`MemoryLedger`], by key, by expiry, and by signer.
#[derive(Default)]
struct Spends {
	live: HashMap<ClaimKey, Live>,
	expiring: BTreeSet<(SystemTime, ClaimKey)>,
	per_signer: HashMap<SignerDigest, usize>,
}

impl Spends {
	/// Free every spend that expired by `now`.
	fn prune(&mut self, now: SystemTime) {
		while let Some(&(expires, key)) = self.expiring.first() {
			if expires > now {
				return;
			}

			self.expiring.pop_first();
			self.remove(&key);
		}
	}

	/// Free the spend of `key`.
	fn remove(&mut self, key: &ClaimKey) {
		let Some(live) = self.live.remove(key) else {
			return;
		};

		self.expiring.remove(&(live.expires, *key));
		if let Some(count) = self.per_signer.get_mut(&live.signer) {
			*count -= 1;
			if *count == 0 {
				self.per_signer.remove(&live.signer);
			}
		}
	}

	/// Take the key of `spend` at `now`, or `false` when a live spend holds
	/// it, its expiry passed, or its signer holds [`PER_SIGNER`] live spends.
	fn take(&mut self, spend: &ClaimSpend, now: SystemTime) -> bool {
		self.prune(now);
		let held = self.live.contains_key(&spend.key);
		let count = self.per_signer.get(&spend.signer).copied().unwrap_or(0);
		if held || count >= PER_SIGNER || spend.expires <= now {
			return false;
		}

		self.live.insert(
			spend.key,
			Live { signer: spend.signer, expires: spend.expires, holder: spend.holder },
		);
		self.expiring.insert((spend.expires, spend.key));
		*self.per_signer.entry(spend.signer).or_insert(0) += 1;
		true
	}

	/// Free the key of `spend`, when its holder took it.
	fn forget(&mut self, spend: &ClaimSpend) {
		let held = self.live.get(&spend.key).is_some_and(|live| live.holder == spend.holder);
		if held {
			self.remove(&spend.key);
		}
	}
}

/// The ledger of one process, which every coupler that holds a clone of its
/// `Arc` shares. It serves an edge with no replica, or replicas in one
/// process.
#[derive(Default)]
pub struct MemoryLedger {
	spends: Mutex<Spends>,
}

impl MemoryLedger {
	/// A ledger with no spend.
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}
}

impl ClaimLedger for MemoryLedger {
	fn spend<'a>(&'a self, spend: &'a ClaimSpend, now: SystemTime) -> LedgerFuture<'a, bool> {
		let mut spends = self.spends.lock().unwrap_or_else(PoisonError::into_inner);
		let taken = spends.take(spend, now);
		Box::pin(core::future::ready(Ok(taken)))
	}

	fn forget<'a>(&'a self, spend: &'a ClaimSpend) -> LedgerFuture<'a, ()> {
		let mut spends = self.spends.lock().unwrap_or_else(PoisonError::into_inner);
		spends.forget(spend);
		Box::pin(core::future::ready(Ok(())))
	}
}

impl fmt::Debug for MemoryLedger {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("MemoryLedger").finish_non_exhaustive()
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use super::*;
	use crate::testing::{LedgerBreach, LedgerConformance};

	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn the_memory_ledger_keeps_the_contract() {
		let checked = LedgerConformance::new(Arc::new(MemoryLedger::new())).check().await;
		assert!(checked.is_ok(), "the memory ledger MUST keep the contract, got {checked:?}");
	}

	#[tokio::test]
	async fn a_check_on_a_current_thread_runtime_refuses_its_runtime() {
		let checked = LedgerConformance::new(Arc::new(MemoryLedger::new())).check().await;
		assert!(
			matches!(checked, Err(LedgerBreach::Runtime)),
			"a check on a current-thread runtime MUST refuse its runtime, got {checked:?}"
		);
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
	async fn a_check_on_one_worker_refuses_its_runtime() {
		let checked = LedgerConformance::new(Arc::new(MemoryLedger::new())).check().await;
		assert!(
			matches!(checked, Err(LedgerBreach::Runtime)),
			"a check on one worker MUST refuse its runtime, got {checked:?}"
		);
	}

	/// The spend of key `index` by `signer`, until a minute after `now`.
	fn spend(index: usize, signer: u8, now: SystemTime) -> ClaimSpend {
		let mut key = [signer; 32];
		key[..8].copy_from_slice(&index.to_be_bytes());
		let expires = now + core::time::Duration::from_secs(60);
		ClaimSpend::new(
			ClaimKey::new(key),
			SignerDigest::new([signer; 32]),
			expires,
			HolderId::new([0; 16]),
		)
	}

	/// Spends that hold [`PER_SIGNER`] live spends of signer 1.
	fn full(now: SystemTime) -> Spends {
		let mut spends = Spends::default();
		for index in 0..PER_SIGNER {
			spends.take(&spend(index, 1, now), now);
		}
		spends
	}

	#[test]
	fn a_signer_past_its_share_is_refused() {
		let now = SystemTime::now();
		assert!(!full(now).take(&spend(PER_SIGNER, 1, now), now));
	}

	#[test]
	fn another_signer_keeps_its_share() {
		let now = SystemTime::now();
		assert!(full(now).take(&spend(0, 2, now), now));
	}

	#[test]
	fn an_expired_spend_frees_its_share() {
		let now = SystemTime::now();
		let later = now + core::time::Duration::from_secs(120);
		assert!(full(now).take(&spend(PER_SIGNER, 1, later), later));
	}
}
