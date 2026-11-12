//! The claim of a caller: its own signature over one call, bound to its
//! principal and to the SHA-256 of its TLS certificate, and its one spend in
//! the ledger of a coupler.
//!
//! # Sources
//!
//! - RFC 5652, CMS, September 2009, section 5: <https://www.rfc-editor.org/rfc/rfc5652#section-5>
//! - CWE-294, Authentication Bypass by Capture-replay: <https://cwe.mitre.org/data/definitions/294.html>

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use rand_core::{OsRng, RngCore};
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use tightbeam::builder::TypeBuilder;
use tightbeam::clock::{Clock, Lapse, UnixMillis};
use tightbeam::colony::cluster::FreshnessWindow;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::crypto::x509::{Certificate, ErasedSigning, KeyPurposes, PeerCertificate};
use tightbeam::der::asn1::OctetString;
use tightbeam::der::{Decode, Encode};
use tightbeam::{Frame, TightBeamError, Version};
use tonic::metadata::{MetadataMap, MetadataValue};

use super::fault::CallFault;
use super::ledger::{ClaimKey, ClaimLedger, ClaimSpend, HolderId, SignerDigest};
use super::loopback::SendFailure;
use super::message::{ClaimBody, ClaimEnvelope};
use super::method::MethodPath;
use super::principal::{LeafDigest, Principal};
use super::saga::CallRecorder;
use crate::deadline::{Deadline, WallClock};

/// Signs the claims of one caller, under its tightbeam identity, bound to its
/// TLS certificate.
///
/// - Each claim takes a strictly increasing order: the current time, or one
///   past the last order when the clock has not moved on. The replay window
///   of the edge refuses two claims of one signer at one order.
///
/// # Examples
///
/// ```
/// use tightbeam_grpc::couple::ClaimSigner;
/// # use tightbeam_grpc::testing::TlsAuthority;
/// # use tightbeam_ws::testing::Identity;
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let lifetime = core::time::Duration::from_secs(60);
/// # let identity = Identity::mint("CN=web,O=acme", 1, lifetime)?.signing_identity();
/// # let tls_leaf = TlsAuthority::mint("CN=edge root", lifetime)?.caller("CN=web,O=acme", None)?.leaf().clone();
/// # let body = b"order".to_vec();
///
/// let signer = ClaimSigner::new(identity, [], &tls_leaf);
/// let claim = signer.sign(&"/orders.v1.Orders/Place".parse()?, &body).await?;
/// let mut request = tonic::Request::new(body);
/// claim.attach(request.metadata_mut());
/// # Ok(())
/// # }
/// ```
pub struct ClaimSigner {
	identity: SigningIdentity,
	issuers: Vec<Certificate>,
	leaf: LeafDigest,
	last_order: AtomicU64,
}

impl ClaimSigner {
	/// A signer under `identity`, whose certificate the certificates of
	/// `issuers` issue, for the caller that presents the TLS certificate
	/// `tls_leaf`.
	pub fn new(
		identity: SigningIdentity,
		issuers: impl IntoIterator<Item = Certificate>,
		tls_leaf: &CertificateDer<'_>,
	) -> Self {
		let issuers = issuers.into_iter().collect();
		let leaf = LeafDigest::of(tls_leaf.as_ref());
		Self { identity, issuers, leaf, last_order: AtomicU64::new(0) }
	}

	/// The claim of the call of `method` with the encoded request `body`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a frame that does not build, sign, or encode.
	pub async fn sign(&self, method: &MethodPath, body: &[u8]) -> Result<CallClaim, TightBeamError> {
		let order = self.next_order();
		let body_digest = OctetString::new(Sha256::digest(body).to_vec())?;
		let leaf_digest = OctetString::new(self.leaf.as_bytes().to_vec())?;
		let claimed = ClaimBody { method: method.as_str().to_owned(), body_digest, leaf_digest };

		let id = order.to_be_bytes();
		let draft = Version::V1.compose().with_id(id).with_order(order).with_message(claimed);
		let mut frame = draft.build()?;
		frame.sign_with_provider(&self.identity).await?;

		let frame = OctetString::new(frame.to_der()?)?;
		let signer = self.identity.certificate().clone();
		let envelope = ClaimEnvelope { frame, signer, issuers: self.issuers.clone() };
		let encoded = envelope.to_der()?;
		Ok(CallClaim { envelope, encoded })
	}

	/// The next order: the current time in milliseconds, or one past the last
	/// order.
	fn next_order(&self) -> u64 {
		let now = UnixMillis::now().get();
		let previous = self
			.last_order
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |last| Some(now.max(last + 1)));
		let last = previous.unwrap_or_else(|last| last);
		now.max(last + 1)
	}
}

/// The claim of one call, as a caller attaches it and as the edge reads it.
#[derive(Clone, Debug)]
pub struct CallClaim {
	envelope: ClaimEnvelope,
	/// The DER of the envelope as it arrived, which a coupled call forwards
	/// unchanged.
	encoded: Vec<u8>,
}

impl CallClaim {
	/// The binary metadata key that carries a claim.
	pub const METADATA_KEY: &'static str = "tightbeam-claim-bin";

	/// Attach the claim to the metadata of a request.
	pub fn attach(&self, metadata: &mut MetadataMap) {
		metadata.insert_bin(Self::METADATA_KEY, MetadataValue::from_bytes(&self.encoded));
	}

	/// The claim of `metadata`, the metadata of a call head, `None` when the
	/// head carries none.
	///
	/// # Errors
	///
	/// - [`CallFault::ClaimRefused`] -- the head carries a claim that does not
	///   decode, or carries two.
	pub(crate) fn of_head(metadata: &MetadataMap) -> Result<Option<Self>, CallFault> {
		let mut values = metadata.get_all_bin(Self::METADATA_KEY).iter();
		let Some(value) = values.next() else {
			return Ok(None);
		};
		if values.next().is_some() {
			return Err(CallFault::ClaimRefused);
		}

		let encoded = value.to_bytes().map_err(|_| CallFault::ClaimRefused)?;
		Self::from_der(&encoded).map(Some)
	}

	/// Verify the claim of `principal` for the call of `method` with `body`
	/// on a connection whose TLS certificate digests to `leaf`, under the
	/// claim store `claims`:
	///
	/// 1. The signer path verifies under `claims`, and the signer certificate
	///    is admitted for signing.
	/// 2. The claim frame verifies under the signer.
	/// 3. The signer certificate names `principal`.
	/// 4. The claim covers `method`, the SHA-256 of `body`, and `leaf`.
	///
	/// # Errors
	///
	/// - [`CallFault::ClaimRefused`] -- a step fails.
	pub(crate) fn verify(
		self,
		principal: &Principal,
		leaf: &LeafDigest,
		method: &MethodPath,
		body: &[u8],
		claims: &dyn CertificateTrust,
	) -> Result<VerifiedClaim, CallFault> {
		let opened = self.open(method, body, claims, principal)?;
		let bound = opened.body.leaf_digest.as_bytes() == leaf.as_bytes();
		if !bound {
			return Err(CallFault::ClaimRefused);
		}

		Ok(VerifiedClaim { signer_key: opened.signer_key, order: opened.order, forwarded: opened.forwarded })
	}

	/// Verify the claim for `method` and `body` of `principal`, as a servlet
	/// can: steps 1 to 3 of [`CallClaim::verify`], and step 4 with no TLS
	/// certificate to compare.
	///
	/// # Errors
	///
	/// - [`CallFault::ClaimRefused`] -- a step fails.
	pub(crate) fn verify_for(
		self,
		principal: &Principal,
		method: &MethodPath,
		body: &[u8],
		claims: &dyn CertificateTrust,
	) -> Result<ForwardedClaim, CallFault> {
		let opened = self.open(method, body, claims, principal)?;
		Ok(ForwardedClaim { forwarded: opened.forwarded })
	}

	/// The claim that `encoded` holds, in the DER that a coupled call forwards.
	pub(crate) fn from_der(encoded: &[u8]) -> Result<Self, CallFault> {
		let envelope = ClaimEnvelope::from_der(encoded).map_err(|_| CallFault::ClaimRefused)?;
		Ok(Self { envelope, encoded: encoded.to_vec() })
	}

	/// Steps 1 to 4 of [`CallClaim::verify`] with the certificate digest left
	/// to the caller.
	fn open(
		self,
		method: &MethodPath,
		body: &[u8],
		claims: &dyn CertificateTrust,
		principal: &Principal,
	) -> Result<Opened, CallFault> {
		let ClaimEnvelope { frame, signer, issuers } = self.envelope;
		let forwarded = self.encoded;
		let refused = |_| CallFault::ClaimRefused;

		claims.verify_presented(&issuers, &signer).map_err(refused)?;

		let signer_key = signer.to_der().map_err(|_| CallFault::ClaimRefused)?;
		let named = Principal::of(&signer);
		let peer = PeerCertificate::<ErasedSigning>::parse(signer, KeyPurposes::HOUSE.signer).map_err(refused)?;

		let frame = Frame::from_der(frame.as_bytes()).map_err(|_| CallFault::ClaimRefused)?;
		let verified = frame.verify_under(&peer, claims.to_policy_ref());
		verified.map_err(|_| CallFault::ClaimRefused)?;

		if named.as_ref() != Some(principal) {
			return Err(CallFault::ClaimRefused);
		}

		let claimed: ClaimBody = frame.decode_message().map_err(|_| CallFault::ClaimRefused)?;
		let digest = Sha256::digest(body);
		let covers = claimed.method == method.as_str() && claimed.body_digest.as_bytes() == digest.as_slice();
		if !covers {
			return Err(CallFault::ClaimRefused);
		}

		let order = UnixMillis::new(frame.metadata().order());
		Ok(Opened { body: claimed, signer_key, order, forwarded })
	}
}

/// A claim whose signer and coverage verified, before its certificate digest
/// is compared.
struct Opened {
	body: ClaimBody,
	signer_key: Vec<u8>,
	order: UnixMillis,
	forwarded: Vec<u8>,
}

/// A claim that verified for its call on the connection of its caller. Only
/// [`CallClaim::verify`] builds one, and the coupler spends it once.
#[derive(Debug)]
pub(crate) struct VerifiedClaim {
	signer_key: Vec<u8>,
	order: UnixMillis,
	forwarded: Vec<u8>,
}

impl VerifiedClaim {
	/// The DER of the claim, which the coupled call forwards to the servlet.
	pub(crate) fn forwarded(&self) -> &[u8] {
		&self.forwarded
	}

	/// Spend the claim under `guard` by `deadline`, the deadline of its call:
	/// its key is the SHA-256 of its signer and its order.
	///
	/// # Errors
	///
	/// - The errors of [`ReplayGuard::spend`].
	pub(crate) async fn spend(&self, guard: &ReplayGuard, deadline: &Deadline) -> Result<SpentClaim, CallFault> {
		let key = Sha256::new()
			.chain_update(&self.signer_key)
			.chain_update(self.order.get().to_be_bytes());
		let key = ClaimKey::new(key.finalize().into());
		let signer = SignerDigest::new(Sha256::digest(&self.signer_key).into());
		guard.spend(key, signer, self.order, deadline).await
	}
}

/// A claim that a servlet verified for the call that forwards it, which the
/// servlet forwards on. Only [`CallClaim::verify_for`] builds one.
#[derive(Debug)]
pub(crate) struct ForwardedClaim {
	forwarded: Vec<u8>,
}

impl ForwardedClaim {
	/// The DER of the claim, which a backend forwards on.
	pub(crate) fn forwarded(&self) -> &[u8] {
		&self.forwarded
	}
}

/// The replay guard of one live coupler: the ledger that it spends each
/// claim in, the window around its clock that a fresh claim falls in, the
/// audit trail of its spends, the clock of the coupler, and the call limit
/// that each forget holds.
pub(crate) struct ReplayGuard {
	ledger: Arc<dyn ClaimLedger>,
	window: Duration,
	freshness: FreshnessWindow,
	recorder: CallRecorder,
	clock: Arc<dyn Clock>,
	limit: Duration,
}

impl ReplayGuard {
	/// The guard that spends in `ledger` within `window` around the unix time
	/// of `clock`, forgets within `limit` on `clock`, and records each spend
	/// on `recorder`.
	pub(crate) fn new(
		ledger: Arc<dyn ClaimLedger>,
		window: Duration,
		limit: Duration,
		recorder: CallRecorder,
		clock: &Arc<dyn Clock>,
	) -> Self {
		let freshness = FreshnessWindow::new(window);
		Self { ledger, window, freshness, recorder, clock: Arc::clone(clock), limit }
	}

	/// Spend the claim named `key` of `signer` at `order` by `deadline`, under
	/// a holder of its own, held in the ledger until the order leaves the
	/// replay window.
	///
	/// - A ledger that answers at `deadline` or later, or whose wait the clock
	///   gives no timer, may have taken the key, so the guard forgets the
	///   spend before it answers. The forget holds the call limit from its own
	///   start, and a call that its caller ends during the forget keeps its
	///   claim.
	///
	/// # Errors
	///
	/// - [`CallFault::Replayed`] -- the claim is stale, a coupler of the ledger spent it, or the ledger
	///   refuses a signer that holds its share of live spends.
	/// - [`CallFault::Internal`] -- the expiry of the claim passes the range of the clock, or the clock gives
	///   the wait for the ledger no timer.
	/// - [`CallFault::Unavailable`] -- the ledger failed.
	/// - [`CallFault::Deadline`] -- the ledger answered at `deadline` or later.
	pub(crate) async fn spend(
		&self,
		key: ClaimKey,
		signer: SignerDigest,
		order: UnixMillis,
		deadline: &Deadline,
	) -> Result<SpentClaim, CallFault> {
		let wall = WallClock::of(&self.clock);
		if !self.freshness.admits(order, wall.unix()) {
			return Err(CallFault::Replayed);
		}

		let expires = UNIX_EPOCH
			.checked_add(Duration::from_millis(order.get()))
			.and_then(|order| order.checked_add(self.window))
			.ok_or(CallFault::Internal)?;
		let mut holder = [0_u8; 16];
		OsRng.fill_bytes(&mut holder);
		let spend = ClaimSpend::new(key, signer, expires, HolderId::new(holder));
		let spending = Spending {
			spend,
			ledger: Arc::clone(&self.ledger),
			recorder: self.recorder.clone(),
			clock: Arc::clone(&self.clock),
			limit: self.limit,
		};

		let taken = match deadline.bound(self.ledger.spend(&spending.spend, wall.now())).await {
			Ok(taken) => taken,
			Err(lapse) => {
				spending.forget(Forgotten::from(lapse)).await;
				return Err(lapse.into());
			}
		};
		if !taken.map_err(|_| CallFault::Unavailable)? {
			return Err(CallFault::Replayed);
		}

		self.recorder.spent();
		Ok(SpentClaim(spending))
	}
}

/// The spend of a claim from the moment the guard asks the ledger, which may
/// take it from then on, and the clock and the call limit of its forget.
struct Spending {
	spend: ClaimSpend,
	ledger: Arc<dyn ClaimLedger>,
	recorder: CallRecorder,
	clock: Arc<dyn Clock>,
	limit: Duration,
}

impl Spending {
	/// The one compensation of the spend: forget it in the ledger for `cause`
	/// within the call limit, counted from the start of the forget, and
	/// record the forget. A forget that fails, or that the ledger does not
	/// answer within the call limit, keeps the claim spent, the outcome that
	/// fails closed.
	async fn forget(self, cause: Forgotten) {
		let within = Deadline::after(&self.clock, self.limit);
		let forgot = within.bound(self.ledger.forget(&self.spend)).await;
		if matches!(forgot, Ok(Ok(()))) {
			self.recorder.forgot(cause);
		}
	}
}

/// Why the coupler forgot the spend of a claim, as its audit trail records
/// it.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Forgotten {
	/// The send of the call proved that its frame stayed in the loopback
	/// session.
	Unsent,
	/// The ledger answered the spend past the deadline of the call.
	Deadline,
	/// The clock gave the wait for the ledger no timer.
	NoTimer,
}

/// A bound on the spend that lapsed is the cause of its forget: the deadline
/// when the span passed, and the want of a timer when the clock gave the wait
/// none.
impl From<Lapse> for Forgotten {
	fn from(lapse: Lapse) -> Self {
		match lapse {
			Lapse::Passed => Self::Deadline,
			Lapse::NoTimer => Self::NoTimer,
		}
	}
}

impl Forgotten {
	/// The name that the audit trail records the cause under.
	#[cfg(feature = "instrument")]
	pub(crate) const fn as_str(self) -> &'static str {
		match self {
			Self::Unsent => "unsent",
			Self::Deadline => "deadline",
			Self::NoTimer => "no-timer",
		}
	}
}

/// A claim that the ledger took, which the send of its call releases when the
/// frame stayed in the loopback session.
pub(crate) struct SpentClaim(Spending);

impl SpentClaim {
	/// Compensate the spend for `failure`, the send that failed: forget the
	/// spend when the send proves that its frame stayed in the session, so the
	/// caller may retry the claim, and keep it spent otherwise.
	pub(crate) async fn release(self, failure: &SendFailure) {
		if failure.proves_unsent() {
			self.0.forget(Forgotten::Unsent).await;
		}
	}
}

#[cfg(test)]
mod tests {
	use core::future::Future;
	use core::pin::pin;
	use core::task::{Context, Poll, Waker};
	use std::borrow::Cow;
	use std::time::SystemTime;

	use tightbeam::clock::{Clock, ManualClock, SystemClock};
	use tightbeam::colony::hive::gates::REPLAY_GUARD_CAPACITY;
	use tightbeam::trace::TraceCollector;

	use super::*;
	use crate::couple::{LedgerFuture, MemoryLedger};
	use crate::events::COUPLED_CLAIM_FORGOTTEN;
	use crate::tunnel::EdgeAudit;

	#[tokio::test]
	async fn a_send_that_expired_waiting_for_a_stream_frees_its_claim() {
		let ledger: Arc<dyn ClaimLedger> = Arc::new(MemoryLedger::new());
		let expires = SystemTime::now() + Duration::from_secs(60);
		let spend = ClaimSpend::new(
			ClaimKey::new([7; 32]),
			SignerDigest::new([7; 32]),
			expires,
			HolderId::new([1; 16]),
		);
		assert_eq!(ledger.spend(&spend, SystemTime::now()).await.ok(), Some(true));

		let recorder = CallRecorder::new(EdgeAudit::default());
		let clock: Arc<dyn Clock> = Arc::new(SystemClock);
		let limit = Duration::from_secs(60);
		let spent = SpentClaim(Spending { spend: spend.clone(), ledger: Arc::clone(&ledger), recorder, clock, limit });
		spent.release(&SendFailure::Expired).await;
		assert_eq!(
			ledger.spend(&spend, SystemTime::now()).await.ok(),
			Some(true),
			"a send that never left MUST free its claim"
		);
	}

	#[tokio::test]
	async fn an_expiry_past_the_clock_refuses_its_spend() {
		let claim = VerifiedClaim { signer_key: vec![7; 32], order: UnixMillis::now(), forwarded: Vec::new() };
		let recorder = CallRecorder::new(EdgeAudit::default());
		let clock: Arc<dyn Clock> = Arc::new(SystemClock);
		let guard = ReplayGuard::new(Arc::new(MemoryLedger::new()), Duration::MAX, Duration::MAX, recorder, &clock);
		let deadline = Deadline::after(&clock, Duration::from_secs(60));
		assert_eq!(claim.spend(&guard, &deadline).await.err(), Some(CallFault::Internal));
	}

	/// A claim of `signer_key` at `order`.
	fn claim(signer_key: &[u8], order: UnixMillis) -> VerifiedClaim {
		VerifiedClaim { signer_key: signer_key.to_vec(), order, forwarded: Vec::new() }
	}

	#[tokio::test]
	async fn a_signer_whose_spends_expire_on_the_clock_of_the_edge_spends_again() {
		let manual = Arc::new(ManualClock::default());
		let clock: Arc<dyn Clock> = manual.clone();
		let window = Duration::from_secs(60);
		let recorder = CallRecorder::new(EdgeAudit::default());
		let guard = ReplayGuard::new(Arc::new(MemoryLedger::new()), window, window, recorder, &clock);
		let deadline = Deadline::after(&clock, window);
		let start = clock.unix().get();
		let capacity = u64::try_from(REPLAY_GUARD_CAPACITY).expect("the capacity fits a u64");
		for back in 0..=capacity {
			let spent = claim(&[7; 32], UnixMillis::new(start - back)).spend(&guard, &deadline).await;
			let expected = if back < capacity {
				None
			} else {
				Some(CallFault::Replayed)
			};
			assert_eq!(spent.err(), expected, "the signer MUST hold its share and no more");
		}

		manual.advance(window + Duration::from_millis(1));
		let deadline = Deadline::after(&clock, window);
		let fresh = claim(&[7; 32], clock.unix()).spend(&guard, &deadline).await;
		assert!(
			fresh.is_ok(),
			"the spends that expired on the clock of the edge MUST free the share"
		);
	}

	/// A ledger over a [`MemoryLedger`] that takes each key, then waits once
	/// before it answers, as the client of a store across a link does.
	struct WaitingLedger(Arc<MemoryLedger>);

	impl ClaimLedger for WaitingLedger {
		fn spend<'a>(&'a self, spend: &'a ClaimSpend, now: SystemTime) -> LedgerFuture<'a, bool> {
			Box::pin(async move {
				let taken = self.0.spend(spend, now).await;
				let mut waited = false;
				core::future::poll_fn(|context| {
					if core::mem::replace(&mut waited, true) {
						return Poll::Ready(());
					}

					context.waker().wake_by_ref();
					Poll::Pending
				})
				.await;
				taken
			})
		}

		fn forget<'a>(&'a self, spend: &'a ClaimSpend) -> LedgerFuture<'a, ()> {
			self.0.forget(spend)
		}
	}

	/// A spend whose ledger takes the key and then waits, polled off any
	/// tokio runtime, where `SystemClock` gives the wait no timer, refuses
	/// with 13 and forgets the spend for want of a timer, so the next spend
	/// of the key takes it.
	#[test]
	fn a_spend_whose_ledger_wait_gets_no_timer_is_forgotten() {
		let inner = Arc::new(MemoryLedger::new());
		let trace = TraceCollector::new();
		let recorder = CallRecorder::new(EdgeAudit::on(Some(trace.share())));
		let clock: Arc<dyn Clock> = Arc::new(SystemClock);
		let ledger = Arc::new(WaitingLedger(Arc::clone(&inner)));
		let window = Duration::from_secs(60);
		let guard = ReplayGuard::new(ledger, window, window, recorder, &clock);
		let deadline = Deadline::after(&clock, Duration::from_secs(60));
		let (key, signer) = (ClaimKey::new([7; 32]), SignerDigest::new([7; 32]));

		let mut spent = pin!(guard.spend(key, signer, clock.unix(), &deadline));
		let refused = match spent.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
			Poll::Ready(spent) => spent.err(),
			Poll::Pending => None,
		};
		assert_eq!(
			refused,
			Some(CallFault::Internal),
			"a ledger wait with no timer MUST refuse the spend with 13"
		);

		let later = SystemTime::now() + Duration::from_secs(60);
		let again = ClaimSpend::new(key, signer, later, HolderId::new([2; 16]));
		let mut taken = inner.spend(&again, SystemTime::now());
		let taken = match taken.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
			Poll::Ready(taken) => taken.ok(),
			Poll::Pending => None,
		};
		assert_eq!(taken, Some(true), "the spend that the wait gave no timer MUST be forgotten");

		let forgotten: Vec<_> = trace
			.drain_events()
			.into_iter()
			.filter(|event| event.urn == COUPLED_CLAIM_FORGOTTEN)
			.map(|event| event.label.map(Cow::into_owned))
			.collect();
		assert_eq!(
			forgotten,
			[Some("no-timer".to_owned())],
			"the forget MUST record its want of a timer"
		);
	}

	/// The DER of a claim body is the `ClaimBody` of `docs/grpc.md`, field by
	/// field, so a signer in another language can build it.
	#[test]
	fn a_claim_body_encodes_as_its_documented_sequence() -> Result<(), tightbeam::der::Error> {
		let body = ClaimBody {
			method: "/a.B/C".to_owned(),
			body_digest: OctetString::new(vec![0x01; 32])?,
			leaf_digest: OctetString::new(vec![0x02; 32])?,
		};

		let method = [0x0c, 0x06, b'/', b'a', b'.', b'B', b'/', b'C'];
		let expected = [
			&[0x30, 0x4c][..],
			&method,
			&[0x04, 0x20],
			&[0x01; 32],
			&[0x04, 0x20],
			&[0x02; 32],
		]
		.concat();
		assert_eq!(body.to_der()?, expected);
		Ok(())
	}
}
