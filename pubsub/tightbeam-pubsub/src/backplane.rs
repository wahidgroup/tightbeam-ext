//! Per-topic sequencing and distribution behind the registry. The page
//! `docs/pubsub.md` (Backplane) states the contract of every backplane.

use core::error::Error;
use core::fmt;
use core::hash::BuildHasher;
use core::mem;
use core::num::NonZeroUsize;
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};

use tightbeam::marker::MaybeSendFuture;
use tightbeam::TightBeamError;

use crate::registry::{Delivered, NodeSink};
use crate::topic::Topic;

/// Why a publish produced no fan-out.
///
/// The registry and every [`Backplane`] answer a publish with this one set,
/// whichever node refused it.
#[derive(Debug)]
pub enum PublishError {
	/// The registry is draining, or every node that answered drains.
	Draining,
	/// The update frame failed to encode for delivery.
	Build(TightBeamError),
	/// The backplane counts its limit of topics, and every counted topic has
	/// a live member, so no counter can leave to make room for a new topic.
	TopicLimit,
	/// The distribution fabric of a multi-node backplane failed.
	Unavailable(BackplaneFault),
}

impl From<TightBeamError> for PublishError {
	fn from(cause: TightBeamError) -> Self {
		Self::Build(cause)
	}
}

impl fmt::Display for PublishError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Draining => f.write_str("the registry is draining"),
			Self::Build(cause) => write!(f, "the update frame failed to build: {cause}"),
			Self::TopicLimit => f.write_str("every counted topic has a live member, so no new topic fits"),
			Self::Unavailable(fault) => write!(f, "the backplane is unavailable: {fault}"),
		}
	}
}

impl Error for PublishError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Build(cause) => Some(cause),
			Self::Unavailable(fault) => Some(fault),
			Self::Draining | Self::TopicLimit => None,
		}
	}
}

/// Why a node refused one sequenced update.
#[derive(Debug)]
pub enum DeliverError {
	/// The node is draining: its topics already completed.
	///
	/// Soft: other nodes may still accept the publish.
	Draining,
	/// The update frame failed to build.
	///
	/// Hard: the publish fails even when another node accepted.
	Build(TightBeamError),
}

impl fmt::Display for DeliverError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Draining => f.write_str("the node is draining"),
			Self::Build(cause) => write!(f, "the update frame failed to build: {cause}"),
		}
	}
}

impl From<TightBeamError> for DeliverError {
	fn from(cause: TightBeamError) -> Self {
		Self::Build(cause)
	}
}

impl Error for DeliverError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Build(cause) => Some(cause),
			Self::Draining => None,
		}
	}
}

impl DeliverError {
	/// Whether this refusal fails a multi-node publish when another node
	/// already accepted.
	fn is_hard(&self) -> bool {
		!matches!(self, Self::Draining)
	}
}

impl From<DeliverError> for PublishError {
	/// The publish refusal of a node refusal: a draining node reads as a
	/// draining registry, and a failed build keeps its cause.
	fn from(refusal: DeliverError) -> Self {
		match refusal {
			DeliverError::Draining => Self::Draining,
			DeliverError::Build(cause) => Self::Build(cause),
		}
	}
}

/// Why the distribution fabric of a multi-node backplane failed a publish.
///
/// A backplane that crosses a network or a queue reports a fault of that
/// fabric through [`PublishError::Unavailable`].
#[derive(Debug)]
pub enum BackplaneFault {
	/// The fabric holds as much pending work as it admits. A retry after the
	/// fabric drains may succeed.
	Saturated,
	/// The fabric rejected or lost the publish.
	Failed(Box<dyn Error + Send + Sync>),
}

impl fmt::Display for BackplaneFault {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Saturated => f.write_str("the backplane fabric is saturated"),
			Self::Failed(cause) => write!(f, "the backplane fabric failed: {cause}"),
		}
	}
}

impl Error for BackplaneFault {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Failed(cause) => Some(cause.as_ref()),
			Self::Saturated => None,
		}
	}
}

/// Per-topic sequencing and distribution behind the registry.
///
/// A backplane reaches each registry through the [`NodeSink`] that the
/// registry attaches.
pub trait Backplane: Send + Sync {
	/// Attach one node.
	fn attach(&self, sink: NodeSink);

	/// Assign the next dense order for `topic`, distribute `payload` to every
	/// attached node, and resolve with the outcome once every node answered.
	///
	/// # Errors
	///
	/// - [`PublishError::Draining`] -- every node refused with [`DeliverError::Draining`].
	/// - [`PublishError::Build`] -- a node refused with [`DeliverError::Build`]. The stamp still burns
	///   when another node accepted.
	/// - [`PublishError::TopicLimit`] -- `topic` is new, and the backplane has no room for its counter.
	/// - [`PublishError::Unavailable`] -- the distribution fabric of a multi-node backplane failed.
	fn publish<'a>(&'a self, topic: &'a Topic, payload: &'a [u8]) -> MaybeSendFuture<'a, Result<(), PublishError>>;

	/// The last committed dense order for `topic`. It is `0` before the first
	/// accepted publish of `topic`, and again once its counter left.
	///
	/// [`TopicRegistry::drain`](crate::TopicRegistry::drain) stamps each
	/// `end/<topic>` with this order, so completion burns no order.
	fn last_order<'a>(&'a self, topic: &'a Topic) -> MaybeSendFuture<'a, u64>;

	/// The last local member of `topic` on one attached node left, so its
	/// counter may leave at the topic limit.
	///
	/// - A backplane that evicts counters asks [`NodeSink::has_members`] before one leaves.
	/// - A backplane with no topic limit lets the report go.
	///
	/// # Examples
	///
	/// A backplane that wraps [`Local`] passes each report on.
	///
	/// ```
	/// use tightbeam::marker::MaybeSendFuture;
	/// use tightbeam_pubsub::{Backplane, Local, NodeSink, PublishError, Topic};
	///
	/// struct Wrapped(Local);
	///
	/// impl Backplane for Wrapped {
	/// 	fn attach(&self, sink: NodeSink) {
	/// 		self.0.attach(sink);
	/// 	}
	///
	/// 	fn publish<'a>(
	/// 		&'a self,
	/// 		topic: &'a Topic,
	/// 		payload: &'a [u8],
	/// 	) -> MaybeSendFuture<'a, Result<(), PublishError>> {
	/// 		self.0.publish(topic, payload)
	/// 	}
	///
	/// 	fn last_order<'a>(&'a self, topic: &'a Topic) -> MaybeSendFuture<'a, u64> {
	/// 		self.0.last_order(topic)
	/// 	}
	///
	/// 	fn vacated(&self, topic: &Topic) {
	/// 		self.0.vacated(topic);
	/// 	}
	/// }
	///
	/// # #[tokio::main(flavor = "current_thread")]
	/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// let backplane = Wrapped(Local::default());
	/// let topic: Topic = "prices".parse()?;
	/// backplane.publish(&topic, b"tick").await?;
	/// backplane.vacated(&topic);
	/// assert_eq!(backplane.last_order(&topic).await, 1);
	/// # Ok(())
	/// # }
	/// ```
	fn vacated(&self, topic: &Topic);
}

/// Distinct topics one [`Local`] counts by default.
const DEFAULT_MAX_TOPICS: NonZeroUsize = match NonZeroUsize::new(65_536) {
	Some(topics) => topics,
	None => panic!("the default topic limit counts one topic or more"),
};

/// The turns of one [`Local`]: each topic takes the turn of its shard.
const TURNS: usize = 64;

/// The counted topics that may have no member, oldest first, each one once.
/// A counter that a refused publish restores goes back to the head, even
/// ahead of older candidates.
#[derive(Default)]
struct Candidates {
	queue: VecDeque<Topic>,
	queued: HashSet<Topic>,
}

impl Candidates {
	/// Queue `topic` last, unless it already waits.
	fn push(&mut self, topic: &Topic) {
		if self.queued.insert(topic.clone()) {
			self.queue.push_back(topic.clone());
		}
	}

	/// Queue `topic` first again, unless it already waits.
	fn restore(&mut self, topic: &Topic) {
		if self.queued.insert(topic.clone()) {
			self.queue.push_front(topic.clone());
		}
	}

	fn pop(&mut self) -> Option<Topic> {
		let topic = self.queue.pop_front()?;
		self.queued.remove(&topic);
		Some(topic)
	}
}

/// The counter that one publish removed to make room for its topic, with
/// its last order, or none when the topic is counted or the limit has room.
///
/// A publish that every node refuses undoes the eviction.
#[must_use = "a refused publish undoes its eviction"]
struct Eviction {
	evicted: Option<(Topic, u64)>,
}

impl Eviction {
	/// Restore the evicted counter to `orders`, queued at the head of
	/// `candidates`, while no publish counted its topic since.
	fn undo(self, orders: &mut HashMap<Topic, u64>, candidates: &mut Candidates) {
		let Some((evicted, order)) = self.evicted else {
			return;
		};
		if orders.contains_key(&evicted) {
			return;
		}

		candidates.restore(&evicted);
		orders.insert(evicted, order);
	}
}

/// The nodes attached to one [`Local`].
#[derive(Default)]
struct Nodes(Vec<NodeSink>);

impl Nodes {
	/// Attach `sink`, and let go of every node that is gone.
	fn attach(&mut self, sink: NodeSink) {
		self.prune();
		self.0.push(sink);
	}

	/// Let go of every node that is gone.
	fn prune(&mut self) {
		self.0.retain(NodeSink::is_attached);
	}

	/// Whether any node has a member of `topic`.
	fn hold(&self, topic: &Topic) -> bool {
		self.0.iter().any(|sink| sink.has_members(topic))
	}

	/// A second handle on every node, for a delivery that runs with no lock
	/// of the backplane held.
	fn share(&self) -> Self {
		Self(self.0.iter().map(NodeSink::share).collect())
	}
}

/// What the nodes of one publish answered: whether one accepted, the first
/// hard and the first soft refusal, and the topics the deliveries vacated.
#[derive(Default)]
struct Fanned {
	accepted: bool,
	hard: Option<DeliverError>,
	soft: Option<DeliverError>,
	vacated: Vec<Topic>,
}

/// What one publish comes to, once every node answered.
enum Answer {
	/// The order burns: a node accepted, or no live node was attached. A hard
	/// refusal of another node still fails the publish.
	Burns(Option<DeliverError>),
	/// Every node refused, so the order stays.
	Refused(DeliverError),
}

impl Fanned {
	/// Record the answer of one node.
	fn record(&mut self, delivered: Result<Delivered, DeliverError>) {
		let refusal = match delivered {
			Ok(delivered) => {
				self.accepted = true;
				self.vacated.extend(delivered.into_vacated());
				return;
			}
			Err(refusal) => refusal,
		};

		let first = if refusal.is_hard() {
			&mut self.hard
		} else {
			&mut self.soft
		};
		first.get_or_insert(refusal);
	}

	/// What the publish comes to, with the topics its deliveries vacated. The
	/// hard refusal wins over the soft one.
	fn answer(self) -> (Answer, Vec<Topic>) {
		let Self { accepted, hard, soft, vacated } = self;
		if accepted {
			return (Answer::Burns(hard), vacated);
		}

		let answer = match hard.or(soft) {
			Some(refusal) => Answer::Refused(refusal),
			None => Answer::Burns(None),
		};
		(answer, vacated)
	}

	/// The answers of a delivery that unwound inside a node. That node may
	/// have queued the update for a subscriber, so it counts as accepted.
	fn unwound(self) -> Self {
		Self { accepted: true, ..self }
	}
}

/// The stamp of one publish in flight: its order, whether it holds a seat
/// for a new counter, the nodes it delivers to, the answer of each node so
/// far, and the eviction it undoes when refused.
///
/// It settles once, through [`settle`](Self::settle) or through its drop.
#[must_use = "a stamp settles with the answers of its delivery"]
struct Stamp<'a> {
	state: &'a Mutex<LocalState>,
	topic: &'a Topic,
	order: u64,
	seated: bool,
	nodes: Nodes,
	fanned: Fanned,
	/// The eviction of the stamp, which its one settle takes.
	eviction: Option<Eviction>,
}

impl Stamp<'_> {
	/// Deliver `payload` at the order of the stamp to each of its nodes, and
	/// record the answer of each node as it returns.
	fn deliver(&mut self, payload: &[u8]) {
		for sink in &self.nodes.0 {
			if let Some(delivered) = sink.deliver(self.topic, self.order, payload) {
				self.fanned.record(delivered);
			}
		}
	}

	/// Settle with the answers of every node.
	///
	/// # Errors
	///
	/// - The errors of [`LocalState::settle`].
	fn settle(mut self) -> Result<(), PublishError> {
		let fanned = mem::take(&mut self.fanned);
		self.close(fanned)
	}

	/// Settle with `fanned`, unless the stamp settled already.
	///
	/// # Errors
	///
	/// - The errors of [`LocalState::settle`].
	fn close(&mut self, fanned: Fanned) -> Result<(), PublishError> {
		let Some(eviction) = self.eviction.take() else {
			return Ok(());
		};

		let mut state = LocalState::lock(self.state);
		state.settle(self.topic, self.order, self.seated, eviction, fanned)
	}
}

impl Drop for Stamp<'_> {
	/// Settle a stamp whose delivery unwound inside a node, with the answers
	/// it recorded, so its order burns.
	fn drop(&mut self) {
		let fanned = mem::take(&mut self.fanned).unwound();
		// The publish that unwound reads no answer.
		let _ = self.close(fanned);
	}
}

struct LocalState {
	max_topics: NonZeroUsize,
	orders: HashMap<Topic, u64>,
	/// A subset of the counted topics, because a counter enters here when it
	/// is new and leaves only after its pop.
	candidates: Candidates,
	/// Publishes at the limit that found no free candidate since the last
	/// [sweep](Self::sweep).
	unswept: usize,
	/// The topics whose publish is between its stamp and its settle, which no
	/// eviction takes.
	stamping: HashSet<Topic>,
	/// The seats that the publishes of new topics in flight hold against the
	/// limit.
	seated: usize,
	nodes: Nodes,
}

impl LocalState {
	fn lock(state: &Mutex<Self>) -> MutexGuard<'_, Self> {
		state.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// Stamp the next order of `topic` in `state`, evict the counter that
	/// makes room for it, and share the nodes its delivery reaches.
	///
	/// # Errors
	///
	/// - [`PublishError::TopicLimit`] -- see [`evict_for`](Self::evict_for).
	fn stamp<'a>(state: &'a Mutex<Self>, topic: &'a Topic) -> Result<Stamp<'a>, PublishError> {
		let mut this = Self::lock(state);
		let counted = this.orders.contains_key(topic);
		let eviction = this.evict_for(counted)?;
		let seated = !counted;
		if seated {
			this.seated += 1;
		}

		let order = this.orders.get(topic).copied().unwrap_or(0).saturating_add(1);
		this.stamping.insert(topic.clone());
		let nodes = this.nodes.share();
		let fanned = Fanned::default();
		Ok(Stamp { state, topic, order, seated, nodes, fanned, eviction: Some(eviction) })
	}

	/// Settle the publish of `topic` at `order` with `fanned`, the answers of
	/// its delivery: commit the order, or undo `eviction`, in one step. The
	/// topics the delivery vacated become candidates.
	///
	/// # Errors
	///
	/// - The [`PublishError`] of the refusal that fails the publish.
	fn settle(
		&mut self,
		topic: &Topic,
		order: u64,
		seated: bool,
		eviction: Eviction,
		fanned: Fanned,
	) -> Result<(), PublishError> {
		self.stamping.remove(topic);
		if seated {
			self.seated -= 1;
		}

		let (answer, vacated) = fanned.answer();
		for vacant in &vacated {
			self.vacated(vacant);
		}

		self.nodes.prune();
		match answer {
			Answer::Burns(refusal) => {
				self.commit(topic, order);
				refusal.map_or(Ok(()), |refusal| Err(refusal.into()))
			}
			Answer::Refused(refusal) => {
				eviction.undo(&mut self.orders, &mut self.candidates);
				Err(refusal.into())
			}
		}
	}

	/// Evict the counter that leaves to make room for the topic of a stamp,
	/// unless that topic is `counted` or the limit has room. The counter has
	/// no member on any live node and no publish in flight.
	///
	/// - The first such candidate in the order of [`Candidates`] leaves. A candidate with a member
	///   leaves the queue. The page `docs/pubsub.md` (Backplane) lists how a topic enters it.
	/// - When no candidate is free, a [sweep](Self::sweep) may find one.
	///
	/// # Errors
	///
	/// - [`PublishError::TopicLimit`] -- every candidate has a member or a publish in flight, and no
	///   sweep ran or found one.
	fn evict_for(&mut self, counted: bool) -> Result<Eviction, PublishError> {
		let room = self.orders.len() + self.seated < self.max_topics.get();
		if counted || room {
			return Ok(Eviction { evicted: None });
		}

		let free = self.free_candidate().or_else(|| self.sweep());
		let evicted = free.and_then(|candidate| self.orders.remove_entry(&candidate));
		let evicted = evicted.ok_or(PublishError::TopicLimit)?;
		Ok(Eviction { evicted: Some(evicted) })
	}

	/// Whether the counter of `candidate` may leave: no publish of it is in
	/// flight, and no node has a member of it.
	fn may_leave(&self, candidate: &Topic) -> bool {
		!self.stamping.contains(candidate) && !self.nodes.hold(candidate)
	}

	/// Pop candidates until one may leave. A candidate whose publish is in
	/// flight returns to the head of the queue, in the order it had.
	///
	/// Each candidate that it asks about costs at most one question per node
	/// and leaves the queue, so a topic is asked about once per time it enters.
	fn free_candidate(&mut self) -> Option<Topic> {
		let mut busy = Vec::new();
		let mut free = None;
		while let Some(candidate) = self.candidates.pop() {
			if self.stamping.contains(&candidate) {
				busy.push(candidate);
				continue;
			}
			if self.may_leave(&candidate) {
				free = Some(candidate);
				break;
			}
		}

		for waiting in busy.iter().rev() {
			self.candidates.restore(waiting);
		}

		free
	}

	/// Ask about every counted topic when a sweep is due, take the first one
	/// that may leave, and queue the rest. The queue holds only candidates
	/// whose publish is in flight. The page `docs/pubsub.md` (Backplane) states
	/// the cadence.
	fn sweep(&mut self) -> Option<Topic> {
		self.unswept = self.unswept.saturating_add(1);
		let due = self.unswept > self.orders.len();
		if !due {
			return None;
		}

		self.unswept = 0;
		let unoccupied = self.orders.keys().filter(|counted| self.may_leave(counted));
		let free: Vec<Topic> = unoccupied.cloned().collect();
		let (taken, rest) = free.split_first()?;
		for candidate in rest {
			self.candidates.push(candidate);
		}

		Some(taken.clone())
	}

	/// Record `order` as the last order of `topic`. A new counter becomes a
	/// candidate.
	fn commit(&mut self, topic: &Topic, order: u64) {
		let fresh = self.orders.insert(topic.clone(), order).is_none();
		if fresh {
			self.candidates.push(topic);
		}
	}

	/// Queue a counted topic that lost its last member on one node.
	fn vacated(&mut self, topic: &Topic) {
		if self.orders.contains_key(topic) {
			self.candidates.push(topic);
		}
	}
}

/// The in-process backplane: one counter per topic, direct delivery to
/// every attached registry. The default.
///
/// - A publish holds the turn of its topic across its stamp and its delivery, so two racing
///   publishes of one topic reach each subscriber queue in stamp order.
/// - [`last_order`](Backplane::last_order) of a topic answers once its delivery in flight returned.
/// - Publishes of topics on other turns run beside it.
///
/// # Topic limit
///
/// - A publish to a new topic at the limit of [`with_max_topics`](Self::with_max_topics) evicts
///   the counter of a topic with no member on any attached node and no publish in flight.
/// - When every counted topic has a member, the publish fails with [`PublishError::TopicLimit`].
///
/// The page `docs/pubsub.md` (Backplane) states how an eviction finds its
/// counter.
pub struct Local {
	state: Mutex<LocalState>,
	turns: Box<[Mutex<()>]>,
	shards: RandomState,
}

impl Default for Local {
	fn default() -> Self {
		let state = LocalState {
			max_topics: DEFAULT_MAX_TOPICS,
			orders: HashMap::new(),
			candidates: Candidates::default(),
			unswept: 0,
			stamping: HashSet::new(),
			seated: 0,
			nodes: Nodes::default(),
		};

		let turns = (0..TURNS).map(|_| Mutex::new(())).collect();
		Self { state: Mutex::new(state), turns, shards: RandomState::new() }
	}
}

impl Local {
	/// Count at most `max_topics` distinct topics. The default is 65,536.
	///
	/// The type documentation describes a publish at the limit.
	#[must_use]
	pub fn with_max_topics(self, max_topics: NonZeroUsize) -> Self {
		self.lock_state().max_topics = max_topics;
		self
	}

	fn lock_state(&self) -> MutexGuard<'_, LocalState> {
		LocalState::lock(&self.state)
	}

	/// The index of the turn that `topic` takes.
	fn shard(&self, topic: &Topic) -> usize {
		let hash = self.shards.hash_one(topic);
		usize::try_from(hash % TURNS as u64).unwrap_or(0)
	}

	/// Take the turn of `topic`.
	fn turn(&self, topic: &Topic) -> MutexGuard<'_, ()> {
		let turn = &self.turns[self.shard(topic)];
		turn.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// Stamp and deliver one publish under the turn of its topic.
	///
	/// The stamp of a new topic at the limit evicts a counter before delivery,
	/// and a publish that every node refuses undoes the eviction. The settle
	/// queues the topics that the deliveries vacated.
	fn publish_now(&self, topic: &Topic, payload: &[u8]) -> Result<(), PublishError> {
		let _turn = self.turn(topic);
		let mut stamp = LocalState::stamp(&self.state, topic)?;
		stamp.deliver(payload);
		stamp.settle()
	}

	/// The last order of `topic`, once its delivery in flight returned.
	fn last_order_now(&self, topic: &Topic) -> u64 {
		let _turn = self.turn(topic);
		self.lock_state().orders.get(topic).copied().unwrap_or(0)
	}
}

impl Backplane for Local {
	fn attach(&self, sink: NodeSink) {
		self.lock_state().nodes.attach(sink);
	}

	fn publish<'a>(&'a self, topic: &'a Topic, payload: &'a [u8]) -> MaybeSendFuture<'a, Result<(), PublishError>> {
		Box::pin(async move { self.publish_now(topic, payload) })
	}

	fn last_order<'a>(&'a self, topic: &'a Topic) -> MaybeSendFuture<'a, u64> {
		Box::pin(async move { self.last_order_now(topic) })
	}

	/// Queue `topic` as a candidate for eviction.
	fn vacated(&self, topic: &Topic) {
		self.lock_state().vacated(topic);
	}
}

#[cfg(test)]
mod tests {
	use std::io;
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::sync::mpsc::{channel, Receiver, Sender};
	use std::sync::Arc;

	use tightbeam::clock::{Clock, SystemClock};
	use tightbeam::testing::SetupEnv;
	use tightbeam::trace::TraceCollector;
	use tightbeam::urn::Urn;
	use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn};
	use tokio::runtime::Handle;
	use tokio::sync::Notify;
	use tokio::task::{spawn_blocking, JoinHandle};

	use super::*;
	use crate::dispatch::PubsubCommands;
	use crate::events::{CONNECTION_ADMITTED, CONNECTION_EXPELLED, UPDATE_DROPPED};
	use crate::policy::{AllowAll, DeliveryPolicy, DeliveryVerdict};
	use crate::registry::{RegistryOptions, RegistryView, TopicRegistry};
	use crate::testing::conformance::{Clause, PAST_DER_LIMIT};
	use crate::testing::nodes::Admitted;
	use crate::testing::{BackplaneBreach, BackplaneConformance, Dial, Peer};

	fn count(value: usize) -> NonZeroUsize {
		NonZeroUsize::new(value).expect("test counts should be above zero")
	}

	/// A backplane that counts one topic at most.
	fn limited() -> Arc<Local> {
		Arc::new(Local::default().with_max_topics(NonZeroUsize::MIN))
	}

	/// Publish `payload` to `name` through `backplane`, expecting acceptance.
	async fn published(backplane: &Local, name: &str, payload: &[u8]) {
		let topic: Topic = name.parse().expect("the name should be a topic");
		let outcome = backplane.publish(&topic, payload).await;
		outcome.expect("the publish should be accepted");
	}

	/// The last order of `name` on `backplane`.
	async fn last_order(backplane: &Local, name: &str) -> u64 {
		backplane
			.last_order(&name.parse::<Topic>().expect("the name should be a topic"))
			.await
	}

	/// A registry on `backplane` with no connection.
	fn registry_on(backplane: &Arc<Local>) -> TopicRegistry {
		let shared = Arc::clone(backplane) as Arc<dyn Backplane>;
		TopicRegistry::new(RegistryOptions { backplane: shared, ..RegistryOptions::default() })
	}

	/// A drained registry on `backplane`, which refuses every delivery.
	async fn drained_on(backplane: &Arc<Local>) -> TopicRegistry {
		let registry = registry_on(backplane);
		registry.drain().await.expect("a drain with no topic completes");
		registry
	}

	/// A registry on `backplane` whose one connection holds a member of each
	/// of `names`.
	async fn members_on(backplane: &Arc<Local>, names: &[&str]) -> (TopicRegistry, Admitted) {
		let registry = registry_on(backplane);
		let admitted = Admitted::to(&registry).await;
		for name in names {
			admitted.subscribe(name);
		}

		(registry, admitted)
	}

	#[tokio::test]
	async fn local_keeps_the_backplane_contract() {
		let fresh = |limit: NonZeroUsize| Arc::new(Local::default().with_max_topics(limit));
		let checked = BackplaneConformance::new(fresh).check().await;
		assert!(checked.is_ok(), "Local should keep the backplane contract: {checked:?}");
	}

	#[tokio::test]
	async fn publish_with_no_nodes_still_sequences() {
		let backplane = Local::default();

		published(&backplane, "prices", b"one").await;
		published(&backplane, "prices", b"two").await;

		assert_eq!(last_order(&backplane, "prices").await, 2);
	}

	#[tokio::test]
	async fn publish_survives_a_dropped_node() {
		let backplane = Arc::new(Local::default());
		let _live = registry_on(&backplane);
		let dead = registry_on(&backplane);
		drop(dead);

		let outcome = backplane
			.publish(&"prices".parse::<Topic>().expect("the name should be a topic"), b"tick")
			.await;
		assert!(outcome.is_ok());
		assert_eq!(last_order(&backplane, "prices").await, 1);
	}

	#[tokio::test]
	async fn publish_refused_everywhere_surfaces_the_refusal() {
		let backplane = Arc::new(Local::default());
		let _draining = drained_on(&backplane).await;

		let outcome = backplane
			.publish(&"prices".parse::<Topic>().expect("the name should be a topic"), b"tick")
			.await;
		assert!(matches!(outcome, Err(PublishError::Draining)));
		assert_eq!(last_order(&backplane, "prices").await, 0);
	}

	#[tokio::test]
	async fn publish_accepted_with_a_draining_node_is_ok() {
		let backplane = Arc::new(Local::default());
		let _draining = drained_on(&backplane).await;
		let _live = registry_on(&backplane);

		let outcome = backplane
			.publish(&"prices".parse::<Topic>().expect("the name should be a topic"), b"tick")
			.await;
		assert!(outcome.is_ok());
		assert_eq!(last_order(&backplane, "prices").await, 1);
	}

	#[tokio::test]
	async fn an_update_past_the_der_length_limit_fails_and_burns_no_order() {
		let backplane = Arc::new(Local::default());
		let _node = registry_on(&backplane);
		let payload = vec![0_u8; PAST_DER_LIMIT];

		let outcome = backplane
			.publish(&"prices".parse::<Topic>().expect("the name should be a topic"), &payload)
			.await;
		assert!(matches!(outcome, Err(PublishError::Build(_))));
		assert_eq!(last_order(&backplane, "prices").await, 0);
	}

	#[tokio::test]
	async fn a_new_topic_at_the_limit_evicts_a_memberless_counter() {
		let backplane = limited();
		published(&backplane, "prices", b"one").await;
		published(&backplane, "chat", b"hello").await;
		assert_eq!(last_order(&backplane, "prices").await, 0);
		assert_eq!(last_order(&backplane, "chat").await, 1);
	}

	#[tokio::test]
	async fn a_new_topic_at_the_limit_spares_a_live_counter() {
		let backplane = limited();
		let _members = members_on(&backplane, &["prices"]).await;
		published(&backplane, "prices", b"one").await;

		let outcome = backplane
			.publish(&"chat".parse::<Topic>().expect("the name should be a topic"), b"hello")
			.await;
		assert!(matches!(outcome, Err(PublishError::TopicLimit)));
		assert_eq!(last_order(&backplane, "prices").await, 1);
	}

	#[tokio::test]
	async fn refusals_at_the_limit_leave_every_counted_topic_its_order() {
		let backplane = Arc::new(Local::default().with_max_topics(count(2)));
		let _members = members_on(&backplane, &["prices", "chat"]).await;
		published(&backplane, "prices", b"one").await;
		published(&backplane, "chat", b"hello").await;

		let first = backplane
			.publish(&"news".parse::<Topic>().expect("the name should be a topic"), b"extra")
			.await;
		let second = backplane
			.publish(&"sports".parse::<Topic>().expect("the name should be a topic"), b"extra")
			.await;
		assert!(matches!(first, Err(PublishError::TopicLimit)));
		assert!(matches!(second, Err(PublishError::TopicLimit)));
		assert_eq!(last_order(&backplane, "prices").await, 1);
		assert_eq!(last_order(&backplane, "chat").await, 1);
		assert_eq!(last_order(&backplane, "news").await, 0);
	}

	#[tokio::test]
	async fn a_refused_publish_at_the_limit_evicts_nothing() {
		let backplane = limited();
		published(&backplane, "prices", b"one").await;
		let _draining = drained_on(&backplane).await;

		let outcome = backplane
			.publish(&"chat".parse::<Topic>().expect("the name should be a topic"), b"hello")
			.await;
		assert!(matches!(outcome, Err(PublishError::Draining)));
		assert_eq!(last_order(&backplane, "prices").await, 1);
	}

	#[tokio::test]
	async fn a_refused_publish_undoes_its_eviction() {
		let backplane = limited();
		published(&backplane, "prices", b"one").await;
		let draining = drained_on(&backplane).await;
		let refused = backplane
			.publish(&"chat".parse::<Topic>().expect("the name should be a topic"), b"hello")
			.await;

		drop(draining);

		let outcome = backplane
			.publish(&"chat".parse::<Topic>().expect("the name should be a topic"), b"hello")
			.await;
		assert!(matches!(refused, Err(PublishError::Draining)));
		assert!(outcome.is_ok());
	}

	#[tokio::test]
	async fn a_refused_eviction_leaves_a_counter_that_counted_again() {
		let backplane = Arc::new(Local::default().with_max_topics(count(2)));
		published(&backplane, "prices", b"one").await;
		published(&backplane, "prices", b"two").await;
		published(&backplane, "news", b"one").await;
		let _draining = drained_on(&backplane).await;

		let chat: Topic = "chat".parse().expect("chat is a topic");
		let mut evicting = LocalState::stamp(&backplane.state, &chat).expect("chat evicts prices");
		let _live = registry_on(&backplane);
		published(&backplane, "prices", b"again").await;

		evicting.deliver(b"hello");
		let settled = evicting.settle();
		assert!(matches!(settled, Err(PublishError::Draining)));
		assert_eq!(last_order(&backplane, "prices").await, 1);
	}

	#[tokio::test]
	async fn the_older_of_two_candidates_in_flight_leaves_first() {
		let backplane = Arc::new(Local::default().with_max_topics(count(3)));
		published(&backplane, "prices", b"one").await;
		published(&backplane, "chat", b"one").await;
		published(&backplane, "news", b"one").await;

		let prices: Topic = "prices".parse().expect("prices is a topic");
		let chat: Topic = "chat".parse().expect("chat is a topic");
		let held_prices = LocalState::stamp(&backplane.state, &prices).expect("prices is counted");
		let held_chat = LocalState::stamp(&backplane.state, &chat).expect("chat is counted");
		published(&backplane, "sports", b"one").await;
		held_prices.settle().expect("a publish with no node burns its order");
		held_chat.settle().expect("a publish with no node burns its order");

		published(&backplane, "weather", b"one").await;

		assert_eq!(last_order(&backplane, "prices").await, 0);
		assert_eq!(last_order(&backplane, "chat").await, 2);
	}

	#[tokio::test]
	async fn an_accepted_publish_commits_its_eviction() {
		let backplane = limited();
		let _node = registry_on(&backplane);
		published(&backplane, "prices", b"one").await;
		published(&backplane, "chat", b"hello").await;
		assert_eq!(last_order(&backplane, "prices").await, 0);
		assert_eq!(last_order(&backplane, "chat").await, 1);
	}

	impl From<BackplaneBreach> for TightBeamError {
		fn from(breach: BackplaneBreach) -> Self {
			Self::IoError(io::Error::other(breach))
		}
	}

	/// A registry on `backplane` whose every update overflows the byte budget
	/// of its connection, so `delivery` decides each one.
	fn overflowing_on(backplane: &Arc<Local>, delivery: Arc<dyn DeliveryPolicy>) -> TopicRegistry {
		let shared = Arc::clone(backplane) as Arc<dyn Backplane>;
		let options = RegistryOptions {
			backplane: shared,
			connection_queue_bytes: NonZeroUsize::MIN,
			delivery,
			..RegistryOptions::default()
		};
		TopicRegistry::new(options)
	}

	/// A peer of `registry` subscribed to `topic`, on a link that records on
	/// `trace`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a link that failed to open or to subscribe.
	async fn subscriber(
		registry: &TopicRegistry,
		topic: &Topic,
		trace: &TraceCollector,
	) -> Result<Peer, TightBeamError> {
		let commands = PubsubCommands::new(registry.clone(), AllowAll);
		let peer = Peer::connect(&commands, &Dial::traced(trace)).await?;
		peer.subscribe(topic).await?;
		Ok(peer)
	}

	/// Publish one update to `topic` through `registry` on a thread of the
	/// blocking pool, so the scenario goes on while the delivery holds or
	/// unwinds.
	fn publishing(registry: &TopicRegistry, topic: &Topic) -> JoinHandle<Result<(), PublishError>> {
		let registry = registry.clone();
		let topic = topic.clone();
		let runtime = Handle::current();
		spawn_blocking(move || runtime.block_on(registry.publish(&topic, b"scenario")))
	}

	/// Wait for the publish task `publishing` at `step` of `clause`,
	/// expecting acceptance.
	///
	/// # Errors
	///
	/// - [`BackplaneBreach::Lapsed`] -- the publish did not settle in time.
	/// - The [`TightBeamError`] of a publish that panicked or was refused.
	async fn accepted(
		clause: Clause<'_>,
		step: &'static str,
		publishing: JoinHandle<Result<(), PublishError>>,
	) -> Result<(), TightBeamError> {
		let joined = clause.within(step, publishing).await?;
		let published = joined.map_err(io::Error::other)?;
		published.map_err(io::Error::other)?;
		Ok(())
	}

	/// A delivery policy that holds the thread of each delivery it decides
	/// until its [`Hold`] releases it, and then votes the connection off.
	struct Holding {
		held: Arc<Notify>,
		released: Mutex<Receiver<()>>,
	}

	impl DeliveryPolicy for Holding {
		fn on_full(&self, _registry: RegistryView<'_>, _topic: &Topic, _dropped_so_far: u64) -> DeliveryVerdict {
			self.held.notify_one();
			let released = self.released.lock().unwrap_or_else(PoisonError::into_inner);
			// A hold whose scenario ended lets the delivery go at once.
			let _ = released.recv();
			DeliveryVerdict::Disconnect
		}
	}

	/// The scenario end of a [`Holding`] policy.
	struct Hold {
		held: Arc<Notify>,
		release: Sender<()>,
	}

	impl Hold {
		/// A hold, and the policy that it releases.
		fn new() -> (Self, Holding) {
			let held = Arc::new(Notify::new());
			let (release, released) = channel();
			let holding = Holding { held: Arc::clone(&held), released: Mutex::new(released) };
			(Self { held, release }, holding)
		}

		/// Wait at `step` of `clause` until the policy holds a delivery.
		///
		/// # Errors
		///
		/// - [`BackplaneBreach::Lapsed`] -- no delivery reached the policy in time.
		async fn held(&self, clause: Clause<'_>, step: &'static str) -> Result<(), BackplaneBreach> {
			clause.within(step, self.held.notified()).await
		}

		/// Release the delivery that the policy holds.
		fn release(&self) {
			// The registry of the policy lives through the scenario, so the
			// send lands.
			let _ = self.release.send(());
		}
	}

	/// The last order of the evicting topic, once its publish settled.
	const COMMITTED: Urn<'static> = urn!("test", "event:pubsub-backplane/committed");

	/// The first order that the subscriber of the evicted topic reads, once
	/// the eviction settled.
	const RESTARTED: Urn<'static> = urn!("test", "event:pubsub-backplane/restarted");

	tb_assert_spec! {
		pub RacingEvictionSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CONNECTION_ADMITTED, exactly!(3)),
				(CONNECTION_EXPELLED, exactly!(2), equals!("enhance-your-calm")),
				(UPDATE_DROPPED, exactly!(0)),
				(COMMITTED, exactly!(1), equals!(1u64)),
				(RESTARTED, exactly!(1), equals!(1u64))
			]
		}
	}

	/// One run of the racing eviction: a [`Local`] of one counted topic, a
	/// node whose every delivery holds, the evicted topic, and the topic whose
	/// publish evicts it, on another turn.
	struct Race {
		local: Arc<Local>,
		hold: Hold,
		held: TopicRegistry,
		evicted: Topic,
		evicting: Topic,
	}

	impl Race {
		fn new() -> Self {
			let local = limited();
			let (hold, holding) = Hold::new();
			let held = overflowing_on(&local, Arc::new(holding));
			let evicted: Topic = "race/evicted".parse().expect("the name should be a topic");
			let evicting = Self::beside(&local, &evicted);
			Self { local, hold, held, evicted, evicting }
		}

		/// The first topic whose publish takes another turn of `local` than a
		/// publish of `topic` does.
		fn beside(local: &Local, topic: &Topic) -> Topic {
			let probes = (0..=TURNS).map(|probe| format!("race/evicting/{probe}"));
			let mut topics = probes.map(|name| name.parse::<Topic>().expect("the name should be a topic"));
			let beside = topics.find(|probe| local.shard(probe) != local.shard(topic));
			beside.expect("a probe should take another turn")
		}

		/// Count the evicted topic, hold the publish of the evicting topic in
		/// its delivery once its stamp evicted that counter, and race a publish
		/// of the evicted topic on another node against the hold. Then release
		/// the hold, and read the evicted topic restart at 1.
		///
		/// # Errors
		///
		/// - [`BackplaneBreach::Lapsed`] -- a step did not happen in time.
		/// - The [`TightBeamError`] of a peer that failed, or of a publish that failed.
		async fn run(&self, trace: &TraceCollector) -> Result<(), TightBeamError> {
			let clock: Arc<dyn Clock> = Arc::new(SystemClock);
			let clause = Clause::named("a racing publish finds the counter its eviction removed", &clock);
			let _first = subscriber(&self.held, &self.evicted, trace).await?;
			let counting = publishing(&self.held, &self.evicted);
			self.hold
				.held(clause, "the hold of the publish that counts the evicted topic")
				.await?;
			self.hold.release();
			accepted(clause, "the publish that counts the evicted topic", counting).await?;

			let _member = subscriber(&self.held, &self.evicting, trace).await?;
			let eviction = publishing(&self.held, &self.evicting);
			self.hold
				.held(clause, "the hold of the publish that evicts the counter")
				.await?;

			let open = registry_on(&self.local);
			let mut racer = subscriber(&open, &self.evicted, trace).await?;
			let racing = publishing(&open, &self.evicted);
			let racing = clause.within("the racing publish of the evicted topic", racing).await?;
			self.hold.release();

			let raced = racing.map_err(io::Error::other)?;
			assert!(
				matches!(raced, Err(PublishError::TopicLimit)),
				"the racing publish should find no room: {raced:?}"
			);

			accepted(clause, "the publish that evicts the counter", eviction).await?;
			let committed = self.local.last_order(&self.evicting).await;
			trace.event_with(COMMITTED, &[], committed)?;

			open.publish(&self.evicted, b"restart").await.map_err(io::Error::other)?;
			let restarted = clause.within("the read of the restarted topic", racer.next_update()).await?;
			trace.event_with(RESTARTED, &[], restarted.map_or(0, |update| update.metadata().order()))?;

			let past: Topic = "race/past-limit".parse().expect("the name should be a topic");
			let refused = open.publish(&past, b"past").await;
			assert!(
				matches!(refused, Err(PublishError::TopicLimit)),
				"a new topic should find no room: {refused:?}"
			);
			Ok(())
		}
	}

	// A publish to a new topic at the limit evicts a counter in its stamp and
	// holds in its delivery. A publish of the evicted topic on another turn
	// races it and finds no room, and the evicted topic restarts at 1 once the
	// eviction settles. The held delivery votes each held connection off.
	tb_scenario! {
		name: a_racing_publish_finds_the_counter_its_eviction_removed,
		spec: RacingEvictionSpec,
		environment Bare {
			context: Race::new(),
			exec: |SetupEnv { trace, context }| async move { context.run(&trace).await }
		}
	}

	/// How many publishes of the new topic answered `TopicLimit`.
	const LIMITED: Urn<'static> = urn!("test", "event:pubsub-backplane/limited");

	/// The last order of the new topic, once each publish of it answered.
	const NEW_ORDER: Urn<'static> = urn!("test", "event:pubsub-backplane/new-order");

	tb_assert_spec! {
		pub BusySweepSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CONNECTION_ADMITTED, exactly!(1)),
				(CONNECTION_EXPELLED, exactly!(1), equals!("enhance-your-calm")),
				(UPDATE_DROPPED, exactly!(0)),
				(LIMITED, exactly!(1), equals!(3u64)),
				(NEW_ORDER, exactly!(1), equals!(0u64))
			]
		}
	}

	// A limit of two counted topics: one has a member, and a publish of the
	// other holds in its delivery. A new topic on another turn publishes until
	// a sweep is due, and each publish answers `TopicLimit`, so the new topic
	// stays uncounted.
	tb_scenario! {
		name: a_sweep_spares_a_counter_whose_publish_is_in_flight,
		spec: BusySweepSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let clock: Arc<dyn Clock> = Arc::new(SystemClock);
				let clause = Clause::named("the sweep beside a publish in flight", &clock);
				let local = Arc::new(Local::default().with_max_topics(count(2)));
				let (_open, _member) = members_on(&local, &["sweep/kept"]).await;
				published(&local, "sweep/kept", b"kept").await;
				published(&local, "sweep/busy", b"busy").await;

				let (hold, holding) = Hold::new();
				let held = overflowing_on(&local, Arc::new(holding));
				let busy: Topic = "sweep/busy".parse().expect("the name should be a topic");
				let _holder = subscriber(&held, &busy, &trace).await?;
				let in_flight = publishing(&held, &busy);
				hold.held(clause, "the hold of the publish in flight").await?;

				// A sweep runs once the publishes that found no free candidate
				// outnumber the two counted topics.
				let new = Race::beside(&local, &busy);
				let mut limited = 0_u64;
				for _ in 0..3 {
					let answered = local.publish(&new, b"new").await;
					if matches!(answered, Err(PublishError::TopicLimit)) {
						limited += 1;
					}
				}
				trace.event_with(LIMITED, &[], limited)?;

				hold.release();
				accepted(clause, "the publish in flight", in_flight).await?;
				let order = local.last_order(&new).await;
				trace.event_with(NEW_ORDER, &[], order)?;
				Ok(())
			}
		}
	}

	/// A delivery policy that votes the first connection it decides off, and
	/// panics at each later one, as a policy with a defect does.
	#[derive(Default)]
	struct Panicking {
		voted: AtomicBool,
	}

	impl DeliveryPolicy for Panicking {
		fn on_full(&self, _registry: RegistryView<'_>, _topic: &Topic, _dropped_so_far: u64) -> DeliveryVerdict {
			let voted = self.voted.swap(true, Ordering::Relaxed);
			if voted {
				panic!("the delivery policy of the scenario panics");
			}

			DeliveryVerdict::Disconnect
		}
	}

	/// The order that a subscriber reads from the publish after the one whose
	/// delivery unwound.
	const NEXT_ORDER: Urn<'static> = urn!("test", "event:pubsub-backplane/next-order");

	tb_assert_spec! {
		pub UnwoundDeliverySpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CONNECTION_ADMITTED, exactly!(3)),
				(CONNECTION_EXPELLED, exactly!(1), equals!("enhance-your-calm")),
				(UPDATE_DROPPED, exactly!(0)),
				(NEXT_ORDER, exactly!(1), equals!(2u64))
			]
		}
	}

	// A publish to a new topic unwinds in the delivery policy of one node, at
	// the member after the one that the policy votes off, once the other node
	// refused it as draining. The voted connection leaves, the order burns, a
	// later subscriber reads the next order, and the seat of the counter frees.
	tb_scenario! {
		name: a_publish_whose_delivery_policy_panics_still_settles,
		spec: UnwoundDeliverySpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let clock: Arc<dyn Clock> = Arc::new(SystemClock);
				let clause = Clause::named("a publish whose delivery policy panics still settles", &clock);
				let local = Arc::new(Local::default().with_max_topics(count(2)));
				let _draining = drained_on(&local).await;
				let panicking = overflowing_on(&local, Arc::new(Panicking::default()));
				let prices: Topic = "prices".parse().expect("the name should be a topic");
				let first = subscriber(&panicking, &prices, &trace).await?;
				let second = subscriber(&panicking, &prices, &trace).await?;

				let unwound = clause.within("the publish whose delivery unwinds", publishing(&panicking, &prices)).await?;
				assert!(unwound.is_err_and(|error| error.is_panic()), "the publish should unwind out of its task");
				let voted = async {
					tokio::select! {
						_ = first.goaway() => &second,
						_ = second.goaway() => &first,
					}
				};
				let staying = clause.within("the GoAway of the voted connection", voted).await?;
				staying.unsubscribe(&prices).await?;

				let open = registry_on(&local);
				let mut reader = subscriber(&open, &prices, &trace).await?;
				open.publish(&prices, b"next").await.map_err(io::Error::other)?;
				let next = clause.within("the read of the next publish", reader.next_update()).await?;
				trace.event_with(NEXT_ORDER, &[], next.map_or(0, |update| update.metadata().order()))?;

				let chat: Topic = "chat".parse().expect("the name should be a topic");
				let fits = open.publish(&chat, b"hello").await;
				assert!(fits.is_ok(), "the seat of the unwound publish should be free: {fits:?}");
				Ok(())
			}
		}
	}
}
