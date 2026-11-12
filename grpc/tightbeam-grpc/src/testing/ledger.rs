//! The contract of a claim ledger driver, which a driver runs against a store
//! of its own in its tests.

use core::fmt;
use core::time::Duration;
use std::sync::Arc;
use std::time::SystemTime;

use rand_core::{OsRng, RngCore};

use tokio::runtime::Handle;
use tokio::sync::Barrier;
use tokio::task::JoinError;

use crate::couple::{ClaimKey, ClaimLedger, ClaimSpend, HolderId, LedgerError, SignerDigest};

/// How many spends of one key race in the atomicity clause.
const RACERS: usize = 16;

/// How long the key of the expiry clause lives.
const EXPIRY: Duration = Duration::from_millis(200);

/// The clause of the contract of [`ClaimLedger`] that a driver breaks.
#[derive(Debug)]
pub enum LedgerBreach {
	/// The first spend of a fresh key answered `false`.
	FirstSpendRefused,
	/// A second spend of a live key answered `true`.
	SecondSpendTaken,
	/// A spend whose expiry passed answered `true`.
	ExpiredSpendTaken,
	/// A second key of one signer answered `false`, as a driver that keys a
	/// spend by its signer does.
	SecondKeyRefused,
	/// A forget by a holder that did not take the key freed it.
	ForgetOfAnotherHolder,
	/// A forget by the holder that took the key left it taken.
	ForgetOfTheHolder,
	/// A key outlived its expiry.
	NoExpiry,
	/// Of concurrent spends of one key, this many answered `true`, not one.
	Race(usize),
	/// The store failed, with its error.
	Store(LedgerError),
	/// A racer of the atomicity clause panicked, or the runtime cancelled it.
	Racer(JoinError),
	/// The check ran off a tokio runtime of two workers or more, whose
	/// workers alone run the racers of the atomicity clause at once.
	Runtime,
}

impl fmt::Display for LedgerBreach {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::FirstSpendRefused => f.write_str("the first spend of a fresh key was refused"),
			Self::SecondSpendTaken => f.write_str("a second spend of a live key was taken"),
			Self::ExpiredSpendTaken => f.write_str("a spend past its expiry was taken"),
			Self::SecondKeyRefused => f.write_str("a second key of one signer was refused"),
			Self::ForgetOfAnotherHolder => f.write_str("a forget by another holder freed the key"),
			Self::ForgetOfTheHolder => f.write_str("a forget by its holder left the key taken"),
			Self::NoExpiry => f.write_str("a key outlived its expiry"),
			Self::Race(taken) => write!(f, "{taken} of {RACERS} concurrent spends of one key were taken"),
			Self::Store(error) => write!(f, "the store failed: {error}"),
			Self::Racer(error) => write!(f, "a racing spend did not finish: {error}"),
			Self::Runtime => f.write_str("the check ran off a tokio runtime of two workers or more"),
		}
	}
}

impl std::error::Error for LedgerBreach {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Store(error) => Some(error),
			Self::Racer(error) => Some(error),
			Self::FirstSpendRefused
			| Self::SecondSpendTaken
			| Self::ExpiredSpendTaken
			| Self::SecondKeyRefused
			| Self::ForgetOfAnotherHolder
			| Self::ForgetOfTheHolder
			| Self::NoExpiry
			| Self::Race(_)
			| Self::Runtime => None,
		}
	}
}

/// The contract of [`ClaimLedger`], as one check of one driver.
///
/// Each clause spends keys fresh to the store of the driver, each of a signer
/// of its own unless the clause names one signer.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
///
/// use tightbeam_grpc::couple::MemoryLedger;
/// use tightbeam_grpc::testing::LedgerConformance;
///
/// # #[tokio::main(flavor = "multi_thread", worker_threads = 2)]
/// # async fn main() -> Result<(), tightbeam_grpc::testing::LedgerBreach> {
/// LedgerConformance::new(Arc::new(MemoryLedger::new())).check().await
/// # }
/// ```
pub struct LedgerConformance {
	ledger: Arc<dyn ClaimLedger>,
}

impl LedgerConformance {
	/// The check of the driver `ledger`.
	pub fn new(ledger: Arc<dyn ClaimLedger>) -> Self {
		Self { ledger }
	}

	/// Check six clauses of the contract on a clock of its own: one spend of
	/// a key wins, a spend past its expiry loses, each key of one signer wins,
	/// a forget frees a key for its holder alone, a key frees at its expiry,
	/// and of concurrent spends of one key exactly one wins.
	///
	/// - The check runs on a tokio runtime of two workers or more, whose workers
	///   run the concurrent spends at once.
	///
	/// # Errors
	///
	/// - [`LedgerBreach::Runtime`] -- the check runs off a tokio runtime of two workers or more.
	/// - The [`LedgerBreach`] of the first clause that the ledger breaks.
	pub async fn check(&self) -> Result<(), LedgerBreach> {
		let now = SystemTime::now();
		self.spends_once(now).await?;
		self.refuses_an_expired_spend(now).await?;
		self.takes_each_key_of_one_signer(now).await?;
		self.forgets_for_its_holder(now).await?;
		self.expires(now).await?;
		self.races(now).await
	}

	/// A key that the first spend at `now` takes, and a second refuses.
	async fn spends_once(&self, now: SystemTime) -> Result<(), LedgerBreach> {
		let key = Self::fresh();
		let first = self
			.spend(&Self::spend_of(key, Self::signer(), Self::holder(), Self::later(now)), now)
			.await?;
		Self::expect(first, LedgerBreach::FirstSpendRefused)?;

		let second = self
			.spend(&Self::spend_of(key, Self::signer(), Self::holder(), Self::later(now)), now)
			.await?;
		Self::expect(!second, LedgerBreach::SecondSpendTaken)
	}

	/// A fresh key whose expiry passed by `now`, which no spend takes.
	async fn refuses_an_expired_spend(&self, now: SystemTime) -> Result<(), LedgerBreach> {
		let expired = now - EXPIRY;
		let taken = self
			.spend(&Self::spend_of(Self::fresh(), Self::signer(), Self::holder(), expired), now)
			.await?;
		Self::expect(!taken, LedgerBreach::ExpiredSpendTaken)
	}

	/// Two fresh keys of one signer, which both take at `now`.
	async fn takes_each_key_of_one_signer(&self, now: SystemTime) -> Result<(), LedgerBreach> {
		let signer = Self::signer();
		let first = self
			.spend(&Self::spend_of(Self::fresh(), signer, Self::holder(), Self::later(now)), now)
			.await?;

		Self::expect(first, LedgerBreach::FirstSpendRefused)?;

		let second = self
			.spend(&Self::spend_of(Self::fresh(), signer, Self::holder(), Self::later(now)), now)
			.await?;
		Self::expect(second, LedgerBreach::SecondKeyRefused)
	}

	/// A key that a forget of another holder keeps taken, and a forget of its
	/// holder frees.
	async fn forgets_for_its_holder(&self, now: SystemTime) -> Result<(), LedgerBreach> {
		let (key, signer, holder) = (Self::fresh(), Self::signer(), Self::holder());
		let later = Self::later(now);
		self.spend(&Self::spend_of(key, signer, holder, later), now).await?;

		self.forget(&Self::spend_of(key, signer, Self::holder(), later)).await?;
		let freed = self.spend(&Self::spend_of(key, signer, Self::holder(), later), now).await?;
		Self::expect(!freed, LedgerBreach::ForgetOfAnotherHolder)?;

		self.forget(&Self::spend_of(key, signer, holder, later)).await?;
		let freed = self.spend(&Self::spend_of(key, signer, Self::holder(), later), now).await?;
		Self::expect(freed, LedgerBreach::ForgetOfTheHolder)
	}

	/// A key that a spend at `now` takes until [`EXPIRY`] later, and that a
	/// spend past its expiry finds free.
	async fn expires(&self, now: SystemTime) -> Result<(), LedgerBreach> {
		let (key, signer) = (Self::fresh(), Self::signer());
		self.spend(&Self::spend_of(key, signer, Self::holder(), now + EXPIRY), now)
			.await?;

		let past = now + EXPIRY * 2;
		let freed = self
			.spend(&Self::spend_of(key, signer, Self::holder(), Self::later(past)), past)
			.await?;
		Self::expect(freed, LedgerBreach::NoExpiry)
	}

	/// A key that [`RACERS`] concurrent spends at `now` race for, which
	/// exactly one takes. The racers start together on the workers of a tokio
	/// runtime of two workers or more.
	async fn races(&self, now: SystemTime) -> Result<(), LedgerBreach> {
		let workers = Handle::try_current().map(|runtime| runtime.metrics().num_workers());
		Self::expect(workers.is_ok_and(|workers| workers >= 2), LedgerBreach::Runtime)?;

		let (key, signer) = (Self::fresh(), Self::signer());
		let start = Arc::new(Barrier::new(RACERS));
		let mut racers = tokio::task::JoinSet::new();
		for _ in 0..RACERS {
			let ledger = Arc::clone(&self.ledger);
			let together = Arc::clone(&start);
			let spend = Self::spend_of(key, signer, Self::holder(), Self::later(now));
			racers.spawn(async move {
				together.wait().await;
				ledger.spend(&spend, now).await
			});
		}

		let mut taken = 0;
		while let Some(raced) = racers.join_next().await {
			let raced = raced.map_err(LedgerBreach::Racer)?;
			taken += usize::from(raced.map_err(LedgerBreach::Store)?);
		}

		Self::expect(taken == 1, LedgerBreach::Race(taken))
	}

	/// What the ledger answers to `spend` at `now`.
	async fn spend(&self, spend: &ClaimSpend, now: SystemTime) -> Result<bool, LedgerBreach> {
		self.ledger.spend(spend, now).await.map_err(LedgerBreach::Store)
	}

	async fn forget(&self, spend: &ClaimSpend) -> Result<(), LedgerBreach> {
		self.ledger.forget(spend).await.map_err(LedgerBreach::Store)
	}

	/// The spend of `key` of `signer` by `holder` until `expires`.
	fn spend_of(key: ClaimKey, signer: SignerDigest, holder: HolderId, expires: SystemTime) -> ClaimSpend {
		ClaimSpend::new(key, signer, expires, holder)
	}

	/// `breach` unless `held`.
	fn expect(held: bool, breach: LedgerBreach) -> Result<(), LedgerBreach> {
		if held {
			return Ok(());
		}

		Err(breach)
	}

	/// A key that no earlier clause took.
	fn fresh() -> ClaimKey {
		let mut key = [0_u8; 32];
		OsRng.fill_bytes(&mut key);
		ClaimKey::new(key)
	}

	/// A signer that no earlier clause named.
	fn signer() -> SignerDigest {
		let mut signer = [0_u8; 32];
		OsRng.fill_bytes(&mut signer);
		SignerDigest::new(signer)
	}

	/// A holder that no earlier clause named.
	fn holder() -> HolderId {
		let mut holder = [0_u8; 16];
		OsRng.fill_bytes(&mut holder);
		HolderId::new(holder)
	}

	/// An expiry that every clause at `now` outlives.
	fn later(now: SystemTime) -> SystemTime {
		now + Duration::from_secs(60)
	}
}
