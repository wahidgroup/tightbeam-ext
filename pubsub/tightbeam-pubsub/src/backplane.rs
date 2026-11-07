//! The backplane: per-topic sequencing and update distribution.
//!
//! [`TopicRegistry`](crate::TopicRegistry) owns local fan-out (lanes,
//! queues, delivery policies) and delegates two decisions here: who
//! assigns the dense per-topic `order`, and how a publish reaches other
//! nodes. [`Local`] answers both in process and is the default. A
//! Redis/Postgres/NATS implementation swaps in through
//! [`RegistryOptions`](crate::RegistryOptions) without touching the wire
//! format or the TypeScript client.
//!
//! # Contract
//!
//! - Orders MUST be dense (`1, 2, 3, ...`) per topic across every node.
//!   The client `TopicGate` reads a hole as message loss and reports a
//!   gap. Redis `INCR`/`XADD` qualify. Raw Postgres sequences do not,
//!   because rollbacks leave holes. Use a locked counter row instead.
//! - Deliveries for one topic MUST NOT run concurrently. The registry
//!   relies on arrival order matching stamp order. [`Local`] holds its
//!   lock across delivery. A remote implementation gets this from a
//!   single consumer task.
//! - Every non-draining attached sink MUST observe every accepted update,
//!   including the publishing node's own. A [`DeliverError::Draining`]
//!   refusal means that sink is leaving, so the publish stands when another
//!   sink accepted. A [`DeliverError::Build`] refusal fails the publish.
//! - The order stamp burns when at least one sink accepted. An all-refuse
//!   publish leaves the counter untouched so subscribers never see a gap
//!   for an update no node fanned out.
//! - A topic's counter MAY leave only while no attached sink has a member
//!   of that topic ([`UpdateSink::has_members`]). The next publish then
//!   restarts the topic at `1`, which every client classifies as fresh: no
//!   subscription saw the old counter, because `subscribe` builds a new
//!   `TopicGate` and `reattach` resets each gate. [`Local`] evicts a counter
//!   only to make room at its topic limit ([`Local::with_max_topics`]).
//! - The registry reports each topic that loses its last local member
//!   ([`Backplane::vacated`]). [`Local`] describes how it reads those
//!   reports at its topic limit.
//! - Async fabrics MAY return [`Ok`] after durable enqueue when they
//!   document at-most-once delivery. [`Local`] is stamp-then-deliver.

use core::error::Error;
use core::fmt;
use core::mem;
use core::num::NonZeroUsize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError, Weak};

use tightbeam::TightBeamError;

use crate::registry::PublishError;
use crate::topic::Topic;

/// Why a node refused one sequenced update.
#[derive(Debug)]
pub enum DeliverError {
	/// The node is quiescing: its topics already completed.
	///
	/// Soft: other sinks may still accept the publish.
	Draining,
	/// The update frame failed to build.
	///
	/// Hard: the publish fails even when another sink accepted.
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
	/// Whether this refusal fails a multi-sink publish when another sink
	/// already accepted.
	fn is_hard(&self) -> bool {
		!matches!(self, Self::Draining)
	}
}

impl From<DeliverError> for PublishError {
	/// The publish refusal of a sink refusal: a draining sink reads as a
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

/// One node's local delivery hook. The registry attaches itself at
/// construction through a [`NodeSink`]. The backplane calls back with every
/// sequenced update.
pub trait UpdateSink: Send + Sync {
	/// Fan `payload` out to this node's subscribers of `topic` at the
	/// backplane-assigned `order`.
	///
	/// # Errors
	///
	/// - [`DeliverError::Draining`]: this node is quiescing.
	/// - [`DeliverError::Build`]: the update frame failed to encode.
	fn deliver(&self, topic: &Topic, order: u64, payload: &[u8]) -> Result<(), DeliverError>;

	/// Whether this node has a live subscriber of `topic`.
	///
	/// A backplane may ask while it holds its own lock, so an implementation
	/// MUST answer from its own state, and MUST NOT publish or call back into
	/// the backplane. The owner of the sink reports a topic that loses its
	/// last member through [`Backplane::vacated`], as the registry does.
	fn has_members(&self, topic: &Topic) -> bool;
}

/// One attached node, as a backplane holds it: a handle that reaches the
/// [`UpdateSink`] of the node while the node lives.
///
/// The handle never owns the node, and it offers no way to own it. A
/// backplane that the registry holds therefore cannot keep the registry
/// alive, so a dropped registry falls out of distribution on its own.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
///
/// use tightbeam_pubsub::{DeliverError, NodeSink, Topic, UpdateSink};
///
/// struct Silent;
///
/// impl UpdateSink for Silent {
///     fn deliver(&self, _topic: &Topic, _order: u64, _payload: &[u8]) -> Result<(), DeliverError> {
///         Ok(())
///     }
///
///     fn has_members(&self, _topic: &Topic) -> bool {
///         false
///     }
/// }
///
/// let node = Arc::new(Silent);
/// let sink = NodeSink::from(&node);
/// assert!(sink.is_attached());
///
/// drop(node);
/// assert!(!sink.is_attached());
/// ```
pub struct NodeSink(Weak<dyn UpdateSink>);

impl<S: UpdateSink + 'static> From<&Arc<S>> for NodeSink {
	fn from(node: &Arc<S>) -> Self {
		let node: Arc<dyn UpdateSink> = Arc::clone(node) as Arc<dyn UpdateSink>;
		Self(Arc::downgrade(&node))
	}
}

impl NodeSink {
	/// Whether the node still lives.
	#[must_use]
	pub fn is_attached(&self) -> bool {
		self.0.strong_count() > 0
	}

	/// Deliver to the node as [`UpdateSink::deliver`] does, or `None` once the
	/// node is gone.
	pub fn deliver(&self, topic: &Topic, order: u64, payload: &[u8]) -> Option<Result<(), DeliverError>> {
		let node = self.0.upgrade()?;
		Some(node.deliver(topic, order, payload))
	}

	/// Whether the node has a live member of `topic`. A gone node has none.
	#[must_use]
	pub fn has_members(&self, topic: &Topic) -> bool {
		let node = self.0.upgrade();
		node.is_some_and(|node| node.has_members(topic))
	}
}

/// Per-topic sequencing and distribution behind the registry.
///
/// A backplane reads the registry only through the [`NodeSink`] it is
/// attached, and holds no [`TopicRegistry`](crate::TopicRegistry).
pub trait Backplane: Send + Sync {
	/// Attach one node's delivery hook.
	fn attach(&self, sink: NodeSink);

	/// Assign the next dense order for `topic` and distribute `payload`
	/// to every attached node.
	///
	/// For [`Local`], success means every non-draining live sink accepted.
	/// Async fabrics that only enqueue MUST document at-most-once ack.
	///
	/// # Errors
	///
	/// - [`PublishError::Draining`]: every sink refused with [`DeliverError::Draining`].
	/// - [`PublishError::Build`]: a sink refused with [`DeliverError::Build`]. The stamp still burns
	///   when another sink accepted.
	/// - [`PublishError::TopicLimit`]: `topic` is new, and the backplane has no room for its counter.
	/// - [`PublishError::Unavailable`]: the distribution fabric of a multi-node backplane failed.
	///   [`Local`] distributes in process, so it returns only the other three.
	fn publish(&self, topic: &Topic, payload: &[u8]) -> Result<(), PublishError>;

	/// Last committed dense order for `topic`, or `0` when the topic has
	/// never accepted a publish or its counter left.
	///
	/// [`TopicRegistry::quiesce`](crate::TopicRegistry::quiesce) stamps each
	/// `end/<topic>` with this order, so completion burns no order and every
	/// other node keeps a dense sequence.
	///
	/// - An implementation MUST return only after every [`UpdateSink::deliver`] of `topic` in flight
	///   has returned. `quiesce` queues `end/<topic>` once this call returns, so the completion
	///   follows every update it counts. [`Local`] meets this because its lock spans each delivery.
	/// - Callers MUST NOT hold a registry lock across this call, because [`Local::publish`] holds the
	///   backplane lock while it re-enters [`UpdateSink::deliver`].
	fn last_order(&self, topic: &Topic) -> u64;

	/// The last member of `topic` on one attached sink left, so its counter
	/// may leave at the topic limit.
	///
	/// A backplane that evicts counters asks [`UpdateSink::has_members`]
	/// before one leaves. A backplane with no topic limit lets the report go.
	///
	/// The registry calls this with its own lock held, at times from inside
	/// an [`UpdateSink::deliver`] of this backplane. An implementation MUST
	/// NOT wait on a lock that a publish holds across delivery, and MUST NOT
	/// publish or call back into a sink.
	///
	/// # Examples
	///
	/// A backplane that wraps [`Local`] passes each report on.
	///
	/// ```
	/// use tightbeam_pubsub::{Backplane, Local, NodeSink, PublishError, Topic};
	///
	/// struct Wrapped(Local);
	///
	/// impl Backplane for Wrapped {
	///     fn attach(&self, sink: NodeSink) {
	///         self.0.attach(sink);
	///     }
	///
	///     fn publish(&self, topic: &Topic, payload: &[u8]) -> Result<(), PublishError> {
	///         self.0.publish(topic, payload)
	///     }
	///
	///     fn last_order(&self, topic: &Topic) -> u64 {
	///         self.0.last_order(topic)
	///     }
	///
	///     fn vacated(&self, topic: &Topic) {
	///         self.0.vacated(topic);
	///     }
	/// }
	///
	/// let backplane = Wrapped(Local::default());
	/// let topic = Topic::fixture("prices");
	/// backplane.publish(&topic, b"tick")?;
	/// backplane.vacated(&topic);
	/// assert_eq!(backplane.last_order(&topic), 1);
	/// # Ok::<(), PublishError>(())
	/// ```
	fn vacated(&self, topic: &Topic);
}

/// Distinct topics one [`Local`] counts by default.
const DEFAULT_MAX_TOPICS: NonZeroUsize = match NonZeroUsize::new(65_536) {
	Some(topics) => topics,
	None => panic!("the default topic limit counts one topic or more"),
};

/// The counted topics that may have no member, oldest first, each one
/// once: the only topics an eviction asks about.
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

	/// Take the oldest candidate.
	fn pop(&mut self) -> Option<Topic> {
		let topic = self.queue.pop_front()?;
		self.queued.remove(&topic);
		Some(topic)
	}
}

/// The counter that one publish removes to make room for its topic: the
/// oldest candidate free of members, or none when the topic is counted or
/// the limit has room.
///
/// The publish commits the eviction with its order, or undoes it when every
/// sink refuses, so a refused publish evicts nothing.
#[must_use = "a publish commits its eviction or undoes it"]
struct Eviction {
	candidate: Option<Topic>,
}

impl Eviction {
	/// Drop the counter of the evicted candidate from `orders`.
	fn commit(self, orders: &mut HashMap<Topic, u64>) {
		if let Some(evicted) = self.candidate {
			orders.remove(&evicted);
		}
	}

	/// Queue the evicted candidate first in `candidates` again, where the
	/// refused publish found it.
	fn undo(self, candidates: &mut Candidates) {
		if let Some(evicted) = self.candidate {
			candidates.restore(&evicted);
		}
	}
}

/// The nodes attached to one [`Local`].
#[derive(Default)]
struct Nodes(Vec<NodeSink>);

impl Nodes {
	/// Attach `sink`, and let go of every node that is gone.
	fn attach(&mut self, sink: NodeSink) {
		self.0.retain(NodeSink::is_attached);
		self.0.push(sink);
	}

	/// Whether any node has a member of `topic`.
	fn hold(&self, topic: &Topic) -> bool {
		self.0.iter().any(|sink| sink.has_members(topic))
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
	nodes: Nodes,
}

impl LocalState {
	/// The counter that leaves to make room for `topic`.
	///
	/// A counted topic needs no room, and neither does a new topic under the
	/// limit. Otherwise the oldest candidate with no member on any live sink
	/// leaves. A candidate with a member leaves the queue, and returns when
	/// the registry reports it vacated. When no candidate is free, a
	/// [sweep](Self::sweep) may find one.
	///
	/// # Errors
	///
	/// - [`PublishError::TopicLimit`]: no candidate is free of members, and
	///   no sweep ran or found one.
	fn evict_for(&mut self, topic: &Topic) -> Result<Eviction, PublishError> {
		let counted = self.orders.contains_key(topic);
		let room = self.orders.len() < self.max_topics.get();
		if counted || room {
			return Ok(Eviction { candidate: None });
		}

		let free = self.free_candidate().or_else(|| self.sweep());
		let evicted = free.ok_or(PublishError::TopicLimit)?;
		Ok(Eviction { candidate: Some(evicted) })
	}

	/// Pop candidates until one has no member on any attached node.
	///
	/// Each candidate costs one question per sink and leaves the queue, so a
	/// topic is asked about once per time it enters.
	fn free_candidate(&mut self) -> Option<Topic> {
		while let Some(candidate) = self.candidates.pop() {
			let occupied = self.nodes.hold(&candidate);
			if !occupied {
				return Some(candidate);
			}
		}

		None
	}

	/// Ask about every counted topic, queue each one free of members, and
	/// take the oldest, when a sweep is due. [`Local`] states the cadence.
	fn sweep(&mut self) -> Option<Topic> {
		self.unswept = self.unswept.saturating_add(1);
		let due = self.unswept > self.orders.len();
		if !due {
			return None;
		}

		self.unswept = 0;
		let unoccupied = self.orders.keys().filter(|counted| !self.nodes.hold(counted));
		let free: Vec<Topic> = unoccupied.cloned().collect();
		for topic in &free {
			self.candidates.push(topic);
		}

		self.candidates.pop()
	}

	/// Record `order` as the last order of `topic`, and commit `eviction`, in
	/// one step. A new counter becomes a candidate.
	fn commit(&mut self, topic: &Topic, order: u64, eviction: Eviction) {
		eviction.commit(&mut self.orders);

		let fresh = self.orders.insert(topic.clone(), order).is_none();
		if fresh {
			self.candidates.push(topic);
		}
	}

	/// Queue a counted topic that lost its last member on one sink.
	fn vacated(&mut self, topic: &Topic) {
		if self.orders.contains_key(topic) {
			self.candidates.push(topic);
		}
	}
}

/// The in-process backplane: one counter per topic, direct synchronous
/// delivery to every attached registry. The default.
///
/// The lock spans sequencing and delivery, so two racing publishes can
/// never reach a subscriber queue out of stamp order.
///
/// # Topic limit
///
/// A publish to a new topic at the limit of
/// [`with_max_topics`](Self::with_max_topics) evicts the counter of a topic
/// with no member on any attached sink. The candidates are the new counters
/// and the topics reported through [`Backplane::vacated`], and each one
/// costs one question per sink.
///
/// When no candidate is free, a sweep asks about every counted topic, so a
/// member that left with no report frees its counter too. A sweep runs once
/// the refusals since the last one outnumber the counted topics, so it asks
/// fewer questions per sink than there were refusals before it.
///
/// When every counted topic has a member, the publish fails with
/// [`PublishError::TopicLimit`].
pub struct Local {
	state: Mutex<LocalState>,
	/// Vacancies reported while a publish held `state`, which the next
	/// publish or vacancy takes in.
	vacancies: Mutex<Vec<Topic>>,
}

impl Default for Local {
	fn default() -> Self {
		let state = LocalState {
			max_topics: DEFAULT_MAX_TOPICS,
			orders: HashMap::new(),
			candidates: Candidates::default(),
			unswept: 0,
			nodes: Nodes::default(),
		};

		Self { state: Mutex::new(state), vacancies: Mutex::new(Vec::new()) }
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
		self.state.lock().unwrap_or_else(PoisonError::into_inner)
	}

	fn lock_vacancies(&self) -> MutexGuard<'_, Vec<Topic>> {
		self.vacancies.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// Take in every vacancy reported while a publish held `state`.
	fn absorb(&self, state: &mut LocalState) {
		let reported = mem::take(&mut *self.lock_vacancies());
		for topic in &reported {
			state.vacated(topic);
		}
	}
}

impl Backplane for Local {
	fn attach(&self, sink: NodeSink) {
		self.lock_state().nodes.attach(sink);
	}

	/// Stamp and deliver one publish as one transaction under the lock.
	///
	/// A new topic at the limit picks a counter to evict before delivery. The
	/// eviction commits with the new order, and a publish that every sink
	/// refuses undoes it, so that publish evicts nothing.
	fn publish(&self, topic: &Topic, payload: &[u8]) -> Result<(), PublishError> {
		let mut state = self.lock_state();
		self.absorb(&mut state);

		let eviction = state.evict_for(topic)?;
		let order = state.orders.get(topic).copied().unwrap_or(0).saturating_add(1);

		let mut delivered_any = false;
		let mut first_hard = None;
		let mut first_soft = None;
		state.nodes.0.retain(|sink| {
			let Some(delivered) = sink.deliver(topic, order, payload) else {
				return false;
			};

			match delivered {
				Ok(()) => delivered_any = true,
				Err(cause) => {
					if cause.is_hard() {
						if first_hard.is_none() {
							first_hard = Some(cause);
						}
					} else if first_soft.is_none() {
						first_soft = Some(cause);
					}
				}
			}
			true
		});

		if delivered_any {
			state.commit(topic, order, eviction);
			if let Some(refusal) = first_hard {
				return Err(refusal.into());
			}

			return Ok(());
		}

		match first_hard.or(first_soft) {
			Some(refusal) => {
				eviction.undo(&mut state.candidates);
				Err(refusal.into())
			}
			None => {
				// No live sinks: still advance the dense counter.
				state.commit(topic, order, eviction);
				Ok(())
			}
		}
	}

	fn last_order(&self, topic: &Topic) -> u64 {
		self.lock_state().orders.get(topic).copied().unwrap_or(0)
	}

	/// Queue `topic` as a candidate for eviction.
	///
	/// This method only tries the lock, because the registry may report from
	/// inside a delivery that a publish of this backplane holds the lock
	/// across. A report that finds the lock held waits beside it for the next
	/// taker.
	fn vacated(&self, topic: &Topic) {
		let mut state = match self.state.try_lock() {
			Ok(state) => state,
			Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
			Err(TryLockError::WouldBlock) => {
				self.lock_vacancies().push(topic.clone());
				return;
			}
		};

		self.absorb(&mut state);
		state.vacated(topic);
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use crate::testing::faults::Rejector;

	/// Publish `payload` to `name` through `backplane`, expecting acceptance.
	fn published(backplane: &Local, name: &str, payload: &[u8]) {
		let topic = Topic::fixture(name);
		backplane.publish(&topic, payload).expect("the publish should be accepted");
	}

	/// Records every delivery. Refuses once `draining` flips.
	#[derive(Default)]
	struct Recorder {
		orders: Mutex<Vec<(Topic, u64)>>,
		draining: bool,
	}

	impl UpdateSink for Recorder {
		fn deliver(&self, topic: &Topic, order: u64, _payload: &[u8]) -> Result<(), DeliverError> {
			if self.draining {
				return Err(DeliverError::Draining);
			}

			self.orders
				.lock()
				.unwrap_or_else(PoisonError::into_inner)
				.push((topic.clone(), order));

			Ok(())
		}

		fn has_members(&self, _topic: &Topic) -> bool {
			false
		}
	}

	/// Accepts every delivery and holds a live member of one topic.
	struct Holding(Topic);

	impl UpdateSink for Holding {
		fn deliver(&self, _topic: &Topic, _order: u64, _payload: &[u8]) -> Result<(), DeliverError> {
			Ok(())
		}

		fn has_members(&self, topic: &Topic) -> bool {
			*topic == self.0
		}
	}

	fn count(value: usize) -> NonZeroUsize {
		NonZeroUsize::new(value).expect("test counts should be above zero")
	}

	/// A backplane that counts one topic at most.
	fn limited() -> Local {
		Local::default().with_max_topics(NonZeroUsize::MIN)
	}

	fn recorded(recorder: &Recorder) -> Vec<(Topic, u64)> {
		recorder.orders.lock().unwrap_or_else(PoisonError::into_inner).clone()
	}

	/// Attach one fresh recorder node to `backplane`.
	fn attached(backplane: &Local, draining: bool) -> Arc<Recorder> {
		let node = Arc::new(Recorder { draining, ..Recorder::default() });
		backplane.attach(NodeSink::from(&node));
		node
	}

	#[test]
	fn publish_assigns_dense_orders_per_topic() {
		let backplane = Local::default();
		let node = attached(&backplane, false);

		published(&backplane, "prices", b"one");
		published(&backplane, "prices", b"two");
		published(&backplane, "chat", b"hello");

		let expected = [
			(Topic::fixture("prices"), 1),
			(Topic::fixture("prices"), 2),
			(Topic::fixture("chat"), 1),
		];
		assert_eq!(recorded(&node), expected);
	}

	#[test]
	fn publish_reaches_every_attached_node() {
		let backplane = Local::default();
		let first = attached(&backplane, false);
		let second = attached(&backplane, false);

		published(&backplane, "prices", b"tick");

		assert_eq!(recorded(&first), [(Topic::fixture("prices"), 1)]);
		assert_eq!(recorded(&second), [(Topic::fixture("prices"), 1)]);
	}

	#[test]
	fn publish_survives_a_dropped_node() {
		let backplane = Local::default();
		let live = attached(&backplane, false);
		let dead = attached(&backplane, false);
		drop(dead);

		let outcome = backplane.publish(&Topic::fixture("prices"), b"tick");
		assert!(outcome.is_ok());
		assert_eq!(recorded(&live), [(Topic::fixture("prices"), 1)]);
	}

	#[test]
	fn publish_with_no_nodes_still_sequences() {
		let backplane = Local::default();

		published(&backplane, "prices", b"one");
		published(&backplane, "prices", b"two");

		let node = attached(&backplane, false);
		published(&backplane, "prices", b"three");

		assert_eq!(recorded(&node), [(Topic::fixture("prices"), 3)]);
	}

	#[test]
	fn publish_refused_everywhere_surfaces_the_refusal() {
		let backplane = Local::default();
		let _draining = attached(&backplane, true);

		let outcome = backplane.publish(&Topic::fixture("prices"), b"tick");
		assert!(matches!(outcome, Err(PublishError::Draining)));
	}

	#[test]
	fn a_refused_publish_does_not_burn_the_order() {
		let backplane = Local::default();
		let draining = attached(&backplane, true);

		let refused = backplane.publish(&Topic::fixture("prices"), b"tick");
		assert!(matches!(refused, Err(PublishError::Draining)));

		drop(draining);

		let node = attached(&backplane, false);
		published(&backplane, "prices", b"tick");

		assert_eq!(recorded(&node), [(Topic::fixture("prices"), 1)]);
	}

	#[test]
	fn publish_accepted_with_draining_peer_is_ok() {
		let backplane = Local::default();
		let _draining = attached(&backplane, true);
		let live = attached(&backplane, false);

		let outcome = backplane.publish(&Topic::fixture("prices"), b"tick");
		assert!(outcome.is_ok());
		assert_eq!(recorded(&live), [(Topic::fixture("prices"), 1)]);
	}

	#[test]
	fn publish_hard_refusal_fails_even_when_a_peer_accepted() {
		let backplane = Local::default();
		let live = attached(&backplane, false);
		let rejector = Arc::new(Rejector);

		backplane.attach(NodeSink::from(&rejector));

		let outcome = backplane.publish(&Topic::fixture("prices"), b"tick");
		assert!(matches!(outcome, Err(PublishError::Build(_))));
		assert_eq!(recorded(&live), [(Topic::fixture("prices"), 1)]);
		assert_eq!(backplane.last_order(&Topic::fixture("prices")), 1);
	}

	#[test]
	fn a_new_topic_at_the_limit_evicts_a_memberless_counter() {
		let backplane = limited();
		published(&backplane, "prices", b"one");
		published(&backplane, "chat", b"hello");
		assert_eq!(backplane.last_order(&Topic::fixture("prices")), 0);
		assert_eq!(backplane.last_order(&Topic::fixture("chat")), 1);
	}

	#[test]
	fn a_new_topic_at_the_limit_spares_a_live_counter() {
		let backplane = limited();
		let member = Arc::new(Holding(Topic::fixture("prices")));

		backplane.attach(NodeSink::from(&member));
		published(&backplane, "prices", b"one");

		let outcome = backplane.publish(&Topic::fixture("chat"), b"hello");
		assert!(matches!(outcome, Err(PublishError::TopicLimit)));
		assert_eq!(backplane.last_order(&Topic::fixture("prices")), 1);
	}

	/// Accepts every delivery, and holds a live member of every topic, as a
	/// registry whose every topic has a subscriber answers.
	#[derive(Default)]
	struct Crowded;

	impl UpdateSink for Crowded {
		fn deliver(&self, _topic: &Topic, _order: u64, _payload: &[u8]) -> Result<(), DeliverError> {
			Ok(())
		}

		fn has_members(&self, _topic: &Topic) -> bool {
			true
		}
	}

	#[test]
	fn refusals_at_the_limit_leave_every_counted_topic_its_order() {
		let backplane = Local::default().with_max_topics(count(2));
		let crowd = Arc::new(Crowded);

		backplane.attach(NodeSink::from(&crowd));
		published(&backplane, "prices", b"one");
		published(&backplane, "chat", b"hello");

		let first = backplane.publish(&Topic::fixture("news"), b"extra");
		let second = backplane.publish(&Topic::fixture("sports"), b"extra");
		assert!(matches!(first, Err(PublishError::TopicLimit)));
		assert!(matches!(second, Err(PublishError::TopicLimit)));
		assert_eq!(backplane.last_order(&Topic::fixture("prices")), 1);
		assert_eq!(backplane.last_order(&Topic::fixture("chat")), 1);
		assert_eq!(backplane.last_order(&Topic::fixture("news")), 0);
	}

	/// Accepts every delivery, and holds a live member of each topic in its
	/// set. A member leaves with no report to the backplane, which a registry
	/// always sends.
	#[derive(Default)]
	struct Members(Mutex<HashSet<Topic>>);

	impl Members {
		fn lock(&self) -> MutexGuard<'_, HashSet<Topic>> {
			self.0.lock().unwrap_or_else(PoisonError::into_inner)
		}

		fn leave(&self, name: &str) {
			let topic = Topic::fixture(name);
			self.lock().remove(&topic);
		}
	}

	impl UpdateSink for Members {
		fn deliver(&self, _topic: &Topic, _order: u64, _payload: &[u8]) -> Result<(), DeliverError> {
			Ok(())
		}

		fn has_members(&self, topic: &Topic) -> bool {
			self.lock().contains(topic)
		}
	}

	/// Attach a sink to `backplane` that holds a member of each of `names`,
	/// and publish once to each of them.
	fn crowded(backplane: &Local, names: &[&str]) -> Arc<Members> {
		let topics = names.iter().map(|name| Topic::fixture(name));
		let members = Arc::new(Members(Mutex::new(topics.collect())));
		backplane.attach(NodeSink::from(&members));

		for name in names {
			published(backplane, name, b"one");
		}

		members
	}

	#[test]
	fn a_member_that_leaves_with_no_report_frees_its_counter_on_a_sweep() {
		let backplane = limited();
		let members = crowded(&backplane, &["prices"]);
		let refused = backplane.publish(&Topic::fixture("chat"), b"hello");
		members.leave("prices");

		let outcome = backplane.publish(&Topic::fixture("chat"), b"hello");
		assert!(matches!(refused, Err(PublishError::TopicLimit)));
		assert!(outcome.is_ok());
	}

	#[test]
	fn vacancies_reported_while_the_lock_is_held_reach_the_next_publish() {
		let backplane = Local::default().with_max_topics(count(3));
		let members = crowded(&backplane, &["prices", "chat", "news"]);
		let refused = backplane.publish(&Topic::fixture("sports"), b"extra");

		members.leave("prices");
		members.leave("chat");

		let held = backplane.lock_state();
		backplane.vacated(&Topic::fixture("prices"));
		backplane.vacated(&Topic::fixture("chat"));
		drop(held);

		let first = backplane.publish(&Topic::fixture("sports"), b"extra");
		let second = backplane.publish(&Topic::fixture("weather"), b"extra");
		assert!(matches!(refused, Err(PublishError::TopicLimit)));
		assert!(first.is_ok());
		assert!(second.is_ok());
	}

	#[test]
	fn a_vacated_topic_makes_room_at_the_limit() {
		let backplane = Local::default().with_max_topics(count(2));
		let members = crowded(&backplane, &["prices", "chat"]);
		let refused = backplane.publish(&Topic::fixture("news"), b"hello");

		members.leave("prices");
		backplane.vacated(&Topic::fixture("prices"));

		let outcome = backplane.publish(&Topic::fixture("news"), b"hello");
		assert!(matches!(refused, Err(PublishError::TopicLimit)));
		assert!(outcome.is_ok());
	}

	#[test]
	fn a_refused_publish_at_the_limit_evicts_nothing() {
		let backplane = limited();
		published(&backplane, "prices", b"one");

		let _draining = attached(&backplane, true);

		let outcome = backplane.publish(&Topic::fixture("chat"), b"hello");
		assert!(matches!(outcome, Err(PublishError::Draining)));
		assert_eq!(backplane.last_order(&Topic::fixture("prices")), 1);
	}

	#[test]
	fn a_refused_publish_undoes_its_eviction() {
		let backplane = limited();
		published(&backplane, "prices", b"one");

		let draining = attached(&backplane, true);
		let refused = backplane.publish(&Topic::fixture("chat"), b"hello");

		drop(draining);

		let outcome = backplane.publish(&Topic::fixture("chat"), b"hello");
		assert!(matches!(refused, Err(PublishError::Draining)));
		assert!(outcome.is_ok());
	}

	#[test]
	fn an_accepted_publish_commits_its_eviction() {
		let backplane = limited();
		let _node = attached(&backplane, false);
		published(&backplane, "prices", b"one");
		published(&backplane, "chat", b"hello");
		assert_eq!(backplane.last_order(&Topic::fixture("prices")), 0);
		assert_eq!(backplane.last_order(&Topic::fixture("chat")), 1);
	}
}
