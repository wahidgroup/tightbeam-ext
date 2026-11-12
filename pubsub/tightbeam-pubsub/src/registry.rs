//! The topic registry: membership, publish fan-out, and the delivery lane of
//! each subscription. The page `docs/pubsub.md` (Registry) states its bounds.

use core::error::Error;
use core::fmt;
use core::future::pending;
use core::mem;
use core::num::NonZeroUsize;
use core::ops::{Deref, DerefMut};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use der::Encode;
use tightbeam::constants::MAX_MUX_CONNECTION_REASSEMBLY_BYTES;
use tightbeam::policy::SessionContext;
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::{Frame, TightBeamError};
use tightbeam_ws::serve::ServedMux;
use tokio::sync::oneshot::{self, Receiver, Sender};
use tokio::sync::{watch, Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard, Notify};
use tokio::task::JoinHandle;

use crate::audit::{ConnectionAudit, Departure};
use crate::backplane::{Backplane, DeliverError, Local, PublishError};
use crate::emit::{EmitDeadline, Emitter, LinkLost, Paced, Settled};
use crate::policy::{DeliveryPolicy, DeliveryVerdict, DropOldest};
use crate::serve::ConnectionContext;
use crate::topic::Topic;

/// Updates one subscriber queue holds before the delivery policy decides.
const DEFAULT_QUEUE_CAPACITY: NonZeroUsize = match NonZeroUsize::new(32) {
	Some(capacity) => capacity,
	None => panic!("the default queue holds one update or more"),
};

/// Live subscriptions one connection may hold before further `sub/`
/// commands are refused.
const DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION: NonZeroUsize = match NonZeroUsize::new(64) {
	Some(cap) => cap,
	None => panic!("the default subscription cap takes one subscription or more"),
};

/// Payload octets one connection may hold queued: the reassembly ceiling
/// that one tightbeam connection already grants its peer.
const DEFAULT_CONNECTION_QUEUE_BYTES: NonZeroUsize = match NonZeroUsize::new(MAX_MUX_CONNECTION_REASSEMBLY_BYTES) {
	Some(bytes) => bytes,
	None => panic!("the default byte budget holds one octet or more"),
};

/// One connection that a registry admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct ConnectionId(u64);

/// One live subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct SubscriberId(u64);

/// Registry construction knobs.
pub struct RegistryOptions {
	/// Bounded queue length per subscriber.
	pub queue_capacity: NonZeroUsize,
	/// Cap on live subscriptions one connection may hold.
	///
	/// A new `sub/` for a topic the connection does not already hold is
	/// refused once this many subscriptions are live. Re-subscribe of an
	/// existing topic stays idempotent and keeps its one count.
	pub max_subscriptions_per_connection: NonZeroUsize,
	/// Payload octets one connection may hold queued or in flight, across
	/// every subscription it holds.
	///
	/// - An update that does not fit counts as a full queue, so the delivery policy decides its fate.
	/// - The default is [`MAX_MUX_CONNECTION_REASSEMBLY_BYTES`], the reassembly ceiling of one
	///   tightbeam connection.
	pub connection_queue_bytes: NonZeroUsize,
	/// How long one emit of a served connection may take: each update, and
	/// each emit of the application through
	/// [`ConnectionContext::emitter`]. An update past the deadline expels its
	/// connection.
	pub emit_deadline: EmitDeadline,
	/// Consulted when a subscriber queue is full.
	pub delivery: Arc<dyn DeliveryPolicy>,
	/// Sequencing and distribution: [`Local`] (single node) by default.
	pub backplane: Arc<dyn Backplane>,
}

impl Default for RegistryOptions {
	fn default() -> Self {
		Self {
			queue_capacity: DEFAULT_QUEUE_CAPACITY,
			max_subscriptions_per_connection: DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION,
			connection_queue_bytes: DEFAULT_CONNECTION_QUEUE_BYTES,
			emit_deadline: EmitDeadline::default(),
			delivery: Arc::new(DropOldest),
			backplane: Arc::new(Local::default()),
		}
	}
}

/// Why a subscription was not registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegisterError {
	/// The connection left the registry, or the registry is gone.
	UnknownConnection,
	/// The registry is draining: no new subscriptions.
	Draining,
	/// The connection already holds
	/// [`RegistryOptions::max_subscriptions_per_connection`] subscriptions.
	LimitReached,
}

impl fmt::Display for RegisterError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::UnknownConnection => f.write_str("the connection is not registered"),
			Self::Draining => f.write_str("the registry is draining"),
			Self::LimitReached => f.write_str("the connection holds too many subscriptions"),
		}
	}
}

impl Error for RegisterError {}

/// The payload octets one connection holds in its lanes, against
/// [`RegistryOptions::connection_queue_bytes`].
///
/// The count is atomic, so a reservation returns its octets on drop with no
/// lock held.
struct ConnectionBudget {
	limit: NonZeroUsize,
	queued: AtomicUsize,
}

impl ConnectionBudget {
	fn new(limit: NonZeroUsize) -> Arc<Self> {
		Arc::new(Self { limit, queued: AtomicUsize::new(0) })
	}

	/// Claim `len` octets, or `None` when they do not fit under the limit.
	fn reserve(self: &Arc<Self>, len: usize) -> Option<ByteReservation> {
		let limit = self.limit.get();
		let fits = |queued: usize| queued.checked_add(len).filter(|total| *total <= limit);

		self.queued.fetch_update(Ordering::AcqRel, Ordering::Acquire, fits).ok()?;
		Some(ByteReservation { budget: Arc::clone(self), len })
	}
}

/// Octets claimed from a [`ConnectionBudget`]. The drop returns them.
struct ByteReservation {
	budget: Arc<ConnectionBudget>,
	len: usize,
}

impl Drop for ByteReservation {
	fn drop(&mut self) {
		self.budget.queued.fetch_sub(self.len, Ordering::AcqRel);
	}
}

/// One update in a lane. It holds its octets against the connection budget
/// until it leaves the lane.
struct Queued {
	update: Arc<Frame>,
	_reservation: ByteReservation,
}

/// The drain task of one lane.
///
/// The drop aborts the task, so a lane that lets go of its queue has no
/// task left.
struct DrainTask(JoinHandle<()>);

impl DrainTask {
	/// Abort the task, and resolve once it ended, so no frame of the task
	/// leaves after the caller goes on.
	///
	/// A running task stops only once its current poll returns, so the wait
	/// covers the frame that poll queues.
	async fn ended(mut self) {
		self.0.abort();
		// A cancelled task answers a `JoinError`, and both outcomes mean that
		// it ended.
		let _ = (&mut self.0).await;
	}
}

impl Drop for DrainTask {
	fn drop(&mut self) {
		self.0.abort();
	}
}

/// The updates one lane holds, and the drain task that serves them.
struct Queue {
	entries: VecDeque<Queued>,
	/// A popped update is being emitted right now.
	in_flight: bool,
	task: DrainTask,
}

impl Queue {
	fn new(task: DrainTask) -> Self {
		Self { entries: VecDeque::new(), in_flight: false, task }
	}

	/// Queue `update` when the queue holds fewer than `capacity` updates and
	/// `budget` has room for its `len` octets.
	fn offer(
		&mut self,
		update: &Arc<Frame>,
		len: usize,
		budget: &Arc<ConnectionBudget>,
		capacity: NonZeroUsize,
	) -> Offer {
		if self.entries.len() >= capacity.get() {
			return Offer::Full;
		}
		let Some(reservation) = budget.reserve(len) else {
			return Offer::Full;
		};

		let queued = Queued { update: Arc::clone(update), _reservation: reservation };
		self.entries.push_back(queued);
		Offer::Queued
	}

	/// Take the oldest update, which counts in flight until [`Lane::settle`].
	fn pop(&mut self) -> Option<Queued> {
		let popped = self.entries.pop_front();
		self.in_flight = popped.is_some();
		popped
	}
}

/// What one offer of an update to a lane did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Offer {
	/// The update entered the queue.
	Queued,
	/// The queue or the connection byte budget has no room.
	Full,
	/// The lane takes no more updates: the subscription completed or ended.
	Shut,
}

/// One subscriber's delivery lane. An open or finishing lane holds the
/// queue and its drain task, and a closed lane holds neither.
enum Lane {
	/// Takes updates, and the drain task emits them in order.
	Open(Queue),
	/// Takes no more updates. The drain task empties the queue, then emits
	/// `end`, the completion of the topic.
	Finishing { queue: Queue, end: Arc<Frame> },
	/// Delivery ended: the subscription left, its topic completed, or an emit
	/// ended in [`LinkLost`].
	Closed,
}

/// What the drain task does next.
enum Step {
	/// Emit this update.
	Emit(Queued),
	/// Emit the completion frame, the last frame the lane sends.
	End(Arc<Frame>),
	/// Wait for the next offer.
	Wait,
	/// Stop, because the lane closed.
	Stop,
}

impl Lane {
	/// Queue `update` when the lane is open and has room. See
	/// [`Queue::offer`].
	fn offer(
		&mut self,
		update: &Arc<Frame>,
		len: usize,
		budget: &Arc<ConnectionBudget>,
		capacity: NonZeroUsize,
	) -> Offer {
		let Self::Open(queue) = self else {
			return Offer::Shut;
		};

		queue.offer(update, len, budget, capacity)
	}

	/// Drop the oldest queued update. Returns whether the lane held one.
	fn evict_oldest(&mut self) -> bool {
		let Self::Open(queue) = self else {
			return false;
		};

		queue.entries.pop_front().is_some()
	}

	/// The next step of the drain task.
	fn next_step(&mut self) -> Step {
		match self {
			Self::Open(queue) => queue.pop().map_or(Step::Wait, Step::Emit),
			Self::Finishing { queue, end } => queue.pop().map_or_else(|| Step::End(Arc::clone(end)), Step::Emit),
			Self::Closed => Step::Stop,
		}
	}

	/// Count the update in flight as gone.
	fn settle(&mut self) {
		if let Self::Open(queue) | Self::Finishing { queue, .. } = self {
			queue.in_flight = false;
		}
	}

	/// Take no more updates, and emit `end` once the queue empties.
	fn finish(&mut self, end: &Arc<Frame>) {
		let lane = mem::replace(self, Self::Closed);
		*self = match lane {
			Self::Open(queue) => Self::Finishing { queue, end: Arc::clone(end) },
			finished => finished,
		};
	}

	/// End delivery. The queue drops, which returns every reserved octet, and
	/// an open or finishing lane hands over its drain task.
	fn close(&mut self) -> Option<DrainTask> {
		let lane = mem::replace(self, Self::Closed);
		match lane {
			Self::Open(queue) | Self::Finishing { queue, .. } => Some(queue.task),
			Self::Closed => None,
		}
	}

	/// Whether an update or the completion frame has yet to leave.
	fn pending(&self) -> bool {
		match self {
			Self::Open(queue) => queue.in_flight || !queue.entries.is_empty(),
			Self::Finishing { .. } => true,
			Self::Closed => false,
		}
	}
}

/// The count of lanes with an update or a completion yet to leave.
///
/// Every change of a lane runs through a [`LaneTurn`], whose drop moves the
/// count, so the count is exact. Every waiter of [`idle`](Self::idle) reads
/// the same count, so each one wakes when it reaches zero.
struct Backlog(watch::Sender<usize>);

impl Backlog {
	fn new() -> Arc<Self> {
		Arc::new(Self(watch::Sender::new(0)))
	}

	/// Count one more lane with an update or a completion yet to leave.
	fn rose(&self) {
		self.0.send_modify(|pending| *pending += 1);
	}

	/// Count one fewer lane with an update or a completion yet to leave.
	fn fell(&self) {
		self.0.send_modify(|pending| *pending -= 1);
	}

	/// Resolve once no lane has anything left to emit.
	async fn idle(&self) {
		let mut pending = self.0.subscribe();
		// The sender lives in this backlog, so the wait ends at an idle count.
		let _ = pending.wait_for(|lanes| *lanes == 0).await;
	}
}

/// The hold of one change on a lane. The drop moves the [`Backlog`] by what
/// the change did to the lane.
struct LaneTurn<'a> {
	lane: MutexGuard<'a, Lane>,
	was: bool,
	backlog: &'a Backlog,
}

impl Deref for LaneTurn<'_> {
	type Target = Lane;

	fn deref(&self) -> &Lane {
		&self.lane
	}
}

impl DerefMut for LaneTurn<'_> {
	fn deref_mut(&mut self) -> &mut Lane {
		&mut self.lane
	}
}

impl Drop for LaneTurn<'_> {
	fn drop(&mut self) {
		let now = self.lane.pending();
		match (self.was, now) {
			(false, true) => self.backlog.rose(),
			(true, false) => self.backlog.fell(),
			_ => {}
		}
	}
}

/// What one admission asks of the fan-out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
	/// The update was queued or dropped.
	Settled,
	/// The delivery policy gave up on the whole connection.
	Disconnect,
}

/// One subscription's delivery: the lane its drain task feeds from, and the
/// count of updates it dropped.
struct Subscriber {
	id: SubscriberId,
	topic: Topic,
	connection: ConnectionId,
	/// Held weakly, so the registry drops while its drain tasks run.
	registry: Weak<Inner>,
	budget: Arc<ConnectionBudget>,
	lane: Mutex<Lane>,
	notify: Notify,
	dropped: AtomicU64,
	/// Shared with the registry. See [`TopicRegistry::drain`].
	backlog: Arc<Backlog>,
	/// Shared with the connection, which records each update that the
	/// subscription drops on it.
	audit: ConnectionAudit,
}

impl Subscriber {
	/// Start delivery for the subscription `id` of `connected`, under the
	/// options of `registry`.
	///
	/// The lane opens under its own lock, so the drain task first reads an
	/// open lane.
	fn spawn(
		id: SubscriberId,
		topic: Topic,
		connection: ConnectionId,
		connected: &ConnectionState,
		registry: &Arc<Inner>,
	) -> Arc<Self> {
		let subscriber = Arc::new(Self {
			id,
			topic,
			connection,
			registry: Arc::downgrade(registry),
			budget: Arc::clone(&connected.budget),
			lane: Mutex::new(Lane::Closed),
			notify: Notify::new(),
			dropped: AtomicU64::new(0),
			backlog: Arc::clone(&registry.backlog),
			audit: connected.audit.share(),
		});

		let mut lane = subscriber.lane();
		let run = Arc::clone(&subscriber).run(connected.emitter.clone());
		let task = DrainTask(tokio::spawn(run));

		*lane = Lane::Open(Queue::new(task));
		drop(lane);

		subscriber
	}

	/// The lane, held for one change.
	fn lane(&self) -> LaneTurn<'_> {
		let lane = self.lane.lock().unwrap_or_else(PoisonError::into_inner);
		let was = lane.pending();
		LaneTurn { lane, was, backlog: &self.backlog }
	}

	/// End delivery, whatever the drain task is doing, and hand over the
	/// drain task of a lane that was still open. Its drop aborts it.
	fn close(&self) -> Option<DrainTask> {
		self.lane().close()
	}

	/// End delivery, and take the subscription out of the registry at once,
	/// so a later `sub/` of the topic starts a new subscription.
	fn retire(&self) {
		if let Some(registry) = self.registry.upgrade() {
			registry.retire(self.connection, &self.topic, self.id);
		}

		self.close();
	}

	/// Emit `end` after every queued update, then end delivery.
	fn finish(&self, end: &Arc<Frame>) {
		self.lane().finish(end);
		self.notify.notify_one();
	}

	fn count_drop(&self) {
		let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
		self.audit.dropped(&self.topic, dropped);
	}

	/// Queue `update` of `len` payload octets, consulting the delivery policy
	/// when the lane or the connection budget is full.
	///
	/// - The policy of `registry` runs with no registry lock held, on a [`RegistryView`] of it.
	/// - `DropOldest` evicts one queued update and offers once more, and a second refusal drops the
	///   new update as `DropNew` does.
	fn admit(&self, update: &Arc<Frame>, len: usize, registry: &Inner) -> Admission {
		let options = &registry.options;
		let capacity = options.queue_capacity;
		let offered = self.offer(update, len, capacity);
		if offered != Offer::Full {
			return Admission::Settled;
		}

		let dropped_so_far = self.dropped.load(Ordering::Relaxed);
		let view = RegistryView::of(registry);
		let verdict = options.delivery.on_full(view, &self.topic, dropped_so_far);
		match verdict {
			DeliveryVerdict::DropOldest => {
				let evicted = self.lane().evict_oldest();
				if evicted {
					self.count_drop();
				}

				let retried = self.offer(update, len, capacity);
				if retried == Offer::Full {
					self.count_drop();
				}

				Admission::Settled
			}
			DeliveryVerdict::DropNew => {
				self.count_drop();
				Admission::Settled
			}
			DeliveryVerdict::Disconnect => Admission::Disconnect,
		}
	}

	/// Offer `update` to the lane once, and wake the drain task when it
	/// queued.
	fn offer(&self, update: &Arc<Frame>, len: usize, capacity: NonZeroUsize) -> Offer {
		let offered = self.lane().offer(update, len, &self.budget, capacity);
		if offered == Offer::Queued {
			self.notify.notify_one();
		}

		offered
	}

	/// Drain the lane until it closes, and run the expulsion it ends with.
	///
	/// The task holds a [`Retirement`], which retires the subscription on
	/// every exit.
	async fn run(self: Arc<Self>, emitter: Emitter) {
		let _retirement = Retirement(Arc::clone(&self));
		let lost = self.drain(&emitter).await;

		let registry = self.registry.upgrade();
		if let (Some(expulsion), Some(registry)) = (lost, registry) {
			expulsion.run(&registry);
		}
	}

	/// Emit queued updates in order until the lane closes. An emit that
	/// counts as the end of the link ends the lane with the expulsion of its
	/// connection.
	///
	/// - The lane counts the popped update in flight until its emit settles, so an idle lane means
	///   every update left.
	/// - Every emit runs under the deadline of `emitter`, on one timer of the clock of the link.
	async fn drain(&self, emitter: &Emitter) -> Option<Expulsion> {
		let mut paced = emitter.paced();

		loop {
			let step = self.lane().next_step();
			match step {
				Step::Emit(queued) => {
					let delivered = self.emit(&mut paced, &queued.update).await;
					drop(queued);

					if delivered.is_err() {
						return Some(Expulsion { connection: self.connection });
					}

					self.lane().settle();
				}
				Step::End(end) => {
					// The topic completes whether or not its end/ arrives, and
					// the drain dismisses the connection next.
					let _ = paced.until_settled(&end).await;
					return None;
				}
				Step::Wait => self.notify.notified().await,
				Step::Stop => return None,
			}
		}
	}

	/// Emit one update, and count it dropped when the emit settles as
	/// [`Settled::Refused`].
	///
	/// # Errors
	///
	/// - The [`LinkLost`] of an emit that counts as the end of the link, which ends the lane.
	async fn emit(&self, paced: &mut Paced<'_>, update: &Frame) -> Result<(), LinkLost> {
		let settled = paced.until_settled(update).await?;
		if let Settled::Refused(_) = settled {
			self.count_drop();
		}

		Ok(())
	}
}

/// A subscriber that drops closes its lane, so the backlog counts the live
/// lanes alone.
impl Drop for Subscriber {
	fn drop(&mut self) {
		self.close();
	}
}

/// The act a drain task leaves for its registry once an emit counts as the
/// end of the link: the expulsion of the whole connection, so its client
/// reads a GoAway.
#[must_use = "a lost link expels its connection"]
struct Expulsion {
	connection: ConnectionId,
}

impl Expulsion {
	/// Expel the connection from `registry` with `EnhanceYourCalm`, the
	/// analog for a peer that cannot keep pace with delivery.
	///
	/// # Sources
	///
	/// - RFC 9113 § 7, Error Codes:
	///   <https://datatracker.ietf.org/doc/html/rfc9113#section-7>
	fn run(self, registry: &Inner) {
		let mut vacancies = Vacancies::default();
		registry.expel(self.connection, GoAwayReason::EnhanceYourCalm, &mut vacancies);
		vacancies.report(registry.backplane());
	}
}

/// The hold of a drain task on its subscriber. The drop retires the
/// subscription, whichever way the task ends.
///
/// A retirement after the subscription already left leaves the registry as
/// it is, because the registry matches the id of the subscription it removes.
struct Retirement(Arc<Subscriber>);

impl Drop for Retirement {
	fn drop(&mut self) {
		self.0.retire();
	}
}

/// Per-topic bookkeeping: the member set. The backplane owns the order
/// counter.
#[derive(Default)]
struct TopicState {
	members: HashSet<SubscriberId>,
}

/// Per-connection bookkeeping: the emitter of its link, the peer its
/// handshake proved, the byte budget its lanes share, the connection's live
/// subscriptions, and the signal that expels it.
struct ConnectionState {
	emitter: Emitter,
	session: SessionContext,
	budget: Arc<ConnectionBudget>,
	topics: HashMap<Topic, SubscriberId>,
	/// Resolves the [`Membership::expelled`] future of the connection.
	expulsion: Sender<GoAwayReason>,
	/// The audit trail of the connection, which its subscriptions share.
	audit: ConnectionAudit,
}

impl ConnectionState {
	/// The subscription this connection already holds for `topic`, or `None`
	/// when a new one fits under `cap` live subscriptions.
	///
	/// A held topic answers its id, so a repeated `sub/` stays idempotent and
	/// takes no second seat.
	///
	/// # Errors
	///
	/// - [`RegisterError::LimitReached`] -- `topic` is new, and the connection holds `cap`
	///   subscriptions.
	fn admit(&self, topic: &Topic, cap: NonZeroUsize) -> Result<Option<SubscriberId>, RegisterError> {
		if let Some(held) = self.topics.get(topic) {
			return Ok(Some(*held));
		}
		if self.topics.len() >= cap.get() {
			return Err(RegisterError::LimitReached);
		}

		Ok(None)
	}

	/// The subscription this connection holds for `topic`.
	fn held(&self, topic: &Topic) -> Option<SubscriberId> {
		self.topics.get(topic).copied()
	}

	/// Hold the new subscription `id` for `topic`, which
	/// [`admit`](Self::admit) answered `None` for.
	fn hold(&mut self, topic: Topic, id: SubscriberId) {
		self.topics.insert(topic, id);
	}

	/// Let go of the subscription `id` for `topic`, while this connection
	/// still holds `id` for `topic`. Returns whether it let go.
	///
	/// A later subscription to `topic` holds a new id, so the release of an
	/// old one leaves it in place.
	fn release(&mut self, topic: &Topic, id: SubscriberId) -> bool {
		let holds = self.held(topic) == Some(id);
		if !holds {
			return false;
		}

		self.topics.remove(topic);
		true
	}

	/// Let go of every subscription this connection holds, and answer them.
	fn take_topics(&mut self) -> HashMap<Topic, SubscriberId> {
		mem::take(&mut self.topics)
	}
}

/// A connection that left the registry, with the count of the subscriptions
/// it held. The holder runs it once it released the registry lock, so no
/// sink of the audit trail runs under the lock.
struct Departed {
	state: ConnectionState,
	departure: Departure,
}

impl Departed {
	/// Record the departure of a connection whose serve ended.
	fn left(self) {
		self.state.audit.left(&self.departure);
	}

	/// Expel the connection with `reason`, the reason its served connection
	/// drains with, and record the expulsion ahead of the departure it causes.
	///
	/// A membership that already left reads no reason, so its connection has
	/// nothing to drain.
	fn expel(self, reason: GoAwayReason) {
		self.state.audit.expelled(reason);
		self.state.audit.left(&self.departure);
		let _ = self.state.expulsion.send(reason);
	}
}

/// The topics that lost their last local member in one step of the
/// registry. The step reports them to the backplane once the registry lock
/// is released, or hands them back from a delivery as [`Delivered`].
#[derive(Default)]
#[must_use = "a vacancy reaches the backplane, or its counter waits for a sweep"]
struct Vacancies(Vec<Topic>);

impl Vacancies {
	fn record(&mut self, topic: Topic) {
		self.0.push(topic);
	}

	/// Report each vacated topic to `backplane`. The caller holds no registry
	/// lock and runs no delivery.
	fn report(self, backplane: &dyn Backplane) {
		for topic in &self.0 {
			backplane.vacated(topic);
		}
	}
}

#[derive(Default)]
struct State {
	topics: HashMap<Topic, TopicState>,
	connections: HashMap<ConnectionId, ConnectionState>,
	subscribers: HashMap<SubscriberId, Arc<Subscriber>>,
}

impl State {
	/// The connection `id` while the registry holds it.
	fn connection(&self, id: ConnectionId) -> Option<&ConnectionState> {
		self.connections.get(&id)
	}

	/// Subscribe `connection` to `topic` under the options of `registry`, or
	/// return the subscription the connection already holds.
	///
	/// - A new subscription enters the connection, the subscriber map, and the member set of its
	///   topic in one step.
	/// - [`unsubscribe`](Self::unsubscribe), [`retire`](Self::retire), and
	///   [`remove_connection`](Self::remove_connection) undo it.
	///
	/// # Errors
	///
	/// - [`RegisterError::UnknownConnection`] -- `connection` left.
	/// - [`RegisterError::LimitReached`] -- `topic` is new, and the connection holds its cap of
	///   subscriptions.
	fn attach(
		&mut self,
		connection: ConnectionId,
		topic: Topic,
		registry: &Arc<Inner>,
	) -> Result<SubscriberId, RegisterError> {
		let cap = registry.options.max_subscriptions_per_connection;
		let connected = self.connections.get_mut(&connection).ok_or(RegisterError::UnknownConnection)?;
		if let Some(held) = connected.admit(&topic, cap)? {
			return Ok(held);
		}

		let id = SubscriberId(registry.next_subscriber.fetch_add(1, Ordering::Relaxed));
		let subscriber = Subscriber::spawn(id, topic.clone(), connection, connected, registry);

		connected.hold(topic.clone(), id);

		self.subscribers.insert(id, subscriber);
		self.topics.entry(topic).or_default().members.insert(id);

		Ok(id)
	}

	/// End the subscription that `connection` holds for `topic`, through
	/// [`retire`](Self::retire). Returns its drain task, or `None` when the
	/// subscription did not exist.
	fn unsubscribe(&mut self, connection: ConnectionId, topic: &Topic, vacancies: &mut Vacancies) -> Option<DrainTask> {
		let held = self.connection(connection).and_then(|connected| connected.held(topic));
		let id = held?;

		self.retire(connection, topic, id, vacancies)
	}

	/// End the subscription `id` of `connection` to `topic`, undoing its
	/// [`attach`](Self::attach), while the connection still holds `id` for
	/// `topic` ([`ConnectionState::release`]). Returns the drain task of the
	/// subscription it ended, or `None` when it ended none.
	fn retire(
		&mut self,
		connection: ConnectionId,
		topic: &Topic,
		id: SubscriberId,
		vacancies: &mut Vacancies,
	) -> Option<DrainTask> {
		let connected = self.connections.get_mut(&connection)?;
		let released = connected.release(topic, id);
		if !released {
			return None;
		}

		self.detach(id, vacancies)
	}

	/// Forget `connection` and end every subscription it holds, undoing each
	/// [`attach`](Self::attach). Returns its [`Departed`], or `None` when the
	/// connection already left.
	fn remove_connection(&mut self, connection: ConnectionId, vacancies: &mut Vacancies) -> Option<Departed> {
		let mut connected = self.connections.remove(&connection)?;

		let topics = connected.take_topics();
		let subscriptions = u64::try_from(topics.len()).unwrap_or(u64::MAX);
		for id in topics.into_values() {
			self.detach(id, vacancies);
		}

		let departure = Departure { connection: connection.0, subscriptions };
		Some(Departed { state: connected, departure })
	}

	/// Forget every connection, as
	/// [`remove_connection`](Self::remove_connection) forgets one.
	fn depart_all(&mut self, vacancies: &mut Vacancies) -> Vec<Departed> {
		let connections: Vec<ConnectionId> = self.connections.keys().copied().collect();
		let departed = connections.into_iter().filter_map(|id| self.remove_connection(id, vacancies));
		departed.collect()
	}

	/// End every subscription and forget every connection, because the last
	/// handle of the registry let go.
	///
	/// - Each lane closes, which ends its drain task, and each topic with a member vacates.
	/// - A dropped expulsion leaves its membership pending, so no served connection drains for it.
	fn end_all(&mut self, vacancies: &mut Vacancies) {
		for subscriber in mem::take(&mut self.subscribers).into_values() {
			subscriber.close();
		}
		for topic in mem::take(&mut self.topics).into_keys() {
			vacancies.record(topic);
		}

		self.connections.clear();
	}

	/// The live subscribers of `topic`, for work that runs after the lock.
	fn members(&self, topic: &Topic) -> Vec<Arc<Subscriber>> {
		let Some(entry) = self.topics.get(topic) else {
			return Vec::new();
		};

		let live = entry.members.iter().filter_map(|id| self.subscribers.get(id));
		live.cloned().collect()
	}

	/// Remove one subscriber from the subscriber map and the member set of its
	/// topic, and end its delivery. Returns its drain task. The caller already
	/// removed it from its connection.
	///
	/// A topic that loses its last member here vacates.
	fn detach(&mut self, id: SubscriberId, vacancies: &mut Vacancies) -> Option<DrainTask> {
		let subscriber = self.subscribers.remove(&id)?;
		if let Some(entry) = self.topics.get_mut(&subscriber.topic) {
			entry.members.remove(&id);
			// Prune the emptied topic, so the map holds only topics with a
			// member. The backplane keeps the order counter.
			if entry.members.is_empty() {
				self.topics.remove(&subscriber.topic);
				vacancies.record(subscriber.topic.clone());
			}
		}

		subscriber.close()
	}
}

/// How far a registry has drained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum DrainPhase {
	/// The registry takes subscriptions and publishes.
	Live,
	/// A drain is in flight. Subscriptions and publishes refuse, so the topic
	/// set and every order hold still while the end frames build.
	Draining,
	/// Every topic of the drain queued its `end/<topic>`. The registry turns
	/// every new connection away.
	Ended,
}

impl DrainPhase {
	/// Whether the registry refuses subscriptions and publishes in this phase.
	fn refuses_work(self) -> bool {
		self != Self::Live
	}

	/// Whether a drain completed in this phase.
	fn has_ended(self) -> bool {
		self == Self::Ended
	}
}

/// The [`DrainPhase`] of a registry. Any reader loads it without a lock, and
/// only the holder of a [`DrainGuard`] stores it.
struct AtomicDrainPhase(AtomicU8);

impl AtomicDrainPhase {
	const LIVE: u8 = DrainPhase::Live as u8;
	const DRAINING: u8 = DrainPhase::Draining as u8;

	fn new() -> Self {
		Self(AtomicU8::new(Self::LIVE))
	}

	/// The phase now, read without a lock.
	fn load(&self) -> DrainPhase {
		let phase = self.0.load(Ordering::Acquire);
		match phase {
			Self::LIVE => DrainPhase::Live,
			Self::DRAINING => DrainPhase::Draining,
			_ => DrainPhase::Ended,
		}
	}

	/// Store `phase` under the drain guard `held`.
	fn store(&self, phase: DrainPhase, _held: &DrainGuard<'_>) {
		self.0.store(phase as u8, Ordering::Release);
	}
}

/// The hold of one drain on its turn, from
/// [`begin_drain`](TopicRegistry::begin_drain) until its completion finishes
/// or unwinds. A second drain waits on the same lock, so it reads the phase
/// that the first one left.
struct DrainGuard<'a> {
	phase: &'a AtomicDrainPhase,
	_turn: AsyncMutexGuard<'a, ()>,
}

impl<'a> DrainGuard<'a> {
	/// The hold of a drain that takes `turn` on `phase` and stores
	/// [`Draining`](DrainPhase::Draining), or `None` when an earlier drain
	/// ended.
	fn begin(phase: &'a AtomicDrainPhase, turn: AsyncMutexGuard<'a, ()>) -> Option<Self> {
		if phase.load().has_ended() {
			return None;
		}

		let guard = Self { phase, _turn: turn };
		guard.store(DrainPhase::Draining);
		Some(guard)
	}

	/// Store `phase` under this guard.
	fn store(&self, phase: DrainPhase) {
		self.phase.store(phase, self);
	}
}

/// The compensation of the first act: a completion that unwinds or drops
/// before it queues its end frames cancels, so the registry takes
/// subscriptions and publishes again and a later drain starts over.
impl Drop for DrainGuard<'_> {
	fn drop(&mut self) {
		let phase = self.phase.load();
		if phase == DrainPhase::Draining {
			self.store(DrainPhase::Live);
		}
	}
}

/// The first act of the drain saga: a drain in flight, which holds the drain
/// guard and the topic set it froze.
#[must_use = "a drain builds its end frames, or its drop cancels it"]
struct Draining<'a> {
	registry: &'a Inner,
	guard: DrainGuard<'a>,
	topics: Vec<Topic>,
}

impl<'a> Draining<'a> {
	/// Build the `end/<topic>` of every frozen topic at its last order.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of an end frame that failed to encode, the signature of upstream
	///   `FrameBuilder::build`. The guard drops with the error, which cancels the drain.
	async fn end_frames(self) -> Result<Completing<'a>, TightBeamError> {
		let Self { registry, guard, topics } = self;
		let backplane = registry.backplane();

		let mut ends = Vec::with_capacity(topics.len());
		for topic in topics {
			let order = backplane.last_order(&topic).await;
			let end = topic.end_frame(order)?;
			ends.push((topic, Arc::new(end)));
		}

		Ok(Completing { registry, guard, ends })
	}
}

/// The second act of the drain saga: a drain whose end frames all built,
/// which holds the drain guard until [`finish`](Self::finish) queues them.
#[must_use = "a completion queues its end frames, or its drop cancels the drain"]
struct Completing<'a> {
	registry: &'a Inner,
	guard: DrainGuard<'a>,
	ends: Vec<(Topic, Arc<Frame>)>,
}

impl Completing<'_> {
	/// Queue the end frame of each topic behind every update its members
	/// hold, and mark the registry ended. Returns how many subscriptions
	/// completed.
	///
	/// - The act has no compensation, so the saga only goes forward from here.
	/// - The phase is stored under the state lock, so each admission reads the phase it races.
	fn finish(self) -> usize {
		let state = self.registry.lock_state();

		let mut completed = 0;
		for (topic, end) in &self.ends {
			for subscriber in state.members(topic) {
				subscriber.finish(end);
				completed += 1;
			}
		}

		self.guard.store(DrainPhase::Ended);
		completed
	}
}

/// The shared state behind every clone of a [`TopicRegistry`].
///
/// Locks nest in one order on every path: the drain turn, the turn of a
/// topic in the backplane, the state of the backplane, the state of the
/// registry, then a lane.
struct Inner {
	options: RegistryOptions,
	/// The drain turn. One completion holds it for its acts, so a second
	/// drain waits for the outcome of the first.
	drain: AsyncMutex<()>,
	/// The drain phase, which every admission, registration, delivery, and
	/// publish reads.
	phase: AtomicDrainPhase,
	next_connection: AtomicU64,
	next_subscriber: AtomicU64,
	state: Mutex<State>,
	/// The count of lanes with work left. See [`TopicRegistry::drain`].
	backlog: Arc<Backlog>,
}

impl Inner {
	fn lock_state(&self) -> MutexGuard<'_, State> {
		self.state.lock().unwrap_or_else(PoisonError::into_inner)
	}

	fn backplane(&self) -> &dyn Backplane {
		self.options.backplane.as_ref()
	}

	/// Hold `connected` as the connection `id`, or answer it as departed when
	/// the registry already ended, so it is turned away.
	fn enter(&self, id: ConnectionId, connected: ConnectionState) -> Option<Departed> {
		let mut state = self.lock_state();
		let ended = self.phase.load().has_ended();
		if ended {
			let departure = Departure { connection: id.0, subscriptions: 0 };
			return Some(Departed { state: connected, departure });
		}

		state.connections.insert(id, connected);
		None
	}

	/// Subscribe `connection` to `topic`, spawning its delivery task, or
	/// answer the subscription it already holds.
	///
	/// # Errors
	///
	/// - [`RegisterError::Draining`] -- a drain is in flight or finished.
	/// - The errors of [`State::attach`].
	fn register(self: &Arc<Self>, connection: ConnectionId, topic: Topic) -> Result<SubscriberId, RegisterError> {
		let mut state = self.lock_state();
		/*
		 * Checked under the state lock: a drain stores its phase before it
		 * freezes the topic set under the same lock, so a subscriber that
		 * enters before the freeze is in the set, and every later one
		 * refuses.
		 */
		if RegistryView::of(self).is_draining() {
			return Err(RegisterError::Draining);
		}

		state.attach(connection, topic, self)
	}

	/// Drop the subscription of `connection` to `topic`, and report what it
	/// vacated once the lock is released. Returns its drain task, or `None`
	/// when none existed.
	fn unregister(&self, connection: ConnectionId, topic: &Topic) -> Option<DrainTask> {
		let mut vacancies = Vacancies::default();
		let ended = self.lock_state().unsubscribe(connection, topic, &mut vacancies);

		vacancies.report(self.backplane());
		ended
	}

	/// End the subscription `id` of `connection` to `topic`, unless a newer
	/// subscription already took its place. See [`State::retire`].
	fn retire(&self, connection: ConnectionId, topic: &Topic, id: SubscriberId) {
		let mut vacancies = Vacancies::default();
		self.lock_state().retire(connection, topic, id, &mut vacancies);
		vacancies.report(self.backplane());
	}

	/// Forget `connection`, drop every subscription it holds, and record its
	/// departure once the registry lock is released.
	fn leave(&self, connection: ConnectionId) {
		let mut vacancies = Vacancies::default();
		let departed = self.lock_state().remove_connection(connection, &mut vacancies);

		vacancies.report(self.backplane());
		if let Some(departed) = departed {
			departed.left();
		}
	}

	/// Dismiss every connection with a `Shutdown` GoAway: the last act of a
	/// drain. Returns how many it dismissed.
	///
	/// The act is safe to repeat, because a dismissed connection is gone.
	fn dismiss(&self) -> usize {
		let mut vacancies = Vacancies::default();
		let departed = self.lock_state().depart_all(&mut vacancies);

		vacancies.report(self.backplane());
		let dismissed = departed.len();
		for connection in departed {
			connection.expel(GoAwayReason::Shutdown);
		}

		dismissed
	}

	/// End every subscription and forget every connection, because the last
	/// handle of the registry let go. See [`State::end_all`].
	fn end_all(&self) {
		let mut vacancies = Vacancies::default();
		self.lock_state().end_all(&mut vacancies);
		vacancies.report(self.backplane());
	}

	/// Offer `update` of `len` payload octets to each member of a snapshot,
	/// with no registry lock held, and expel every connection the delivery
	/// policy votes off with `EnhanceYourCalm`.
	///
	/// - Each expulsion runs as its vote lands, so a policy that unwinds at a later member leaves
	///   every earlier vote acted on.
	/// - The fan-out runs inside a delivery of the backplane, so it answers the topics the
	///   expulsions vacated instead of reporting them.
	fn fan_out(&self, members: &[Arc<Subscriber>], update: &Arc<Frame>, len: usize) -> Vacancies {
		let mut vacancies = Vacancies::default();
		for subscriber in members {
			let admission = subscriber.admit(update, len, self);
			if admission == Admission::Disconnect {
				self.expel(subscriber.connection, GoAwayReason::EnhanceYourCalm, &mut vacancies);
			}
		}

		vacancies
	}

	/// Forget `connection`, end every subscription it holds into
	/// `vacancies`, and expel it with `reason` once the registry lock is
	/// released.
	fn expel(&self, connection: ConnectionId, reason: GoAwayReason, vacancies: &mut Vacancies) {
		let departed = self.lock_state().remove_connection(connection, vacancies);
		if let Some(departed) = departed {
			departed.expel(reason);
		}
	}

	/// One update that the backplane stamped lands on this node: build its
	/// frame at the assigned order and fan it out to the local members.
	///
	/// # Errors
	///
	/// - [`DeliverError::Draining`] -- a drain is in flight or finished.
	/// - [`DeliverError::Build`] -- the update frame failed to encode.
	fn deliver(&self, topic: &Topic, order: u64, payload: &[u8]) -> Result<Delivered, DeliverError> {
		/*
		 * A delivery that passes this check before a drain stores its phase
		 * offers to a lane that already took its end/ as Shut, so no update
		 * follows the completion of its subscription.
		 */
		if RegistryView::of(self).is_draining() {
			return Err(DeliverError::Draining);
		}

		let members = self.lock_state().members(topic);

		let update = Arc::new(topic.update_frame(order, payload)?);
		let vacancies = self.fan_out(&members, &update, payload.len());

		Ok(Delivered { vacated: vacancies.0 })
	}

	/// A topic is live while its member set holds a subscriber.
	fn has_members(&self, topic: &Topic) -> bool {
		let state = self.lock_state();
		let entry = state.topics.get(topic);
		entry.is_some_and(|entry| !entry.members.is_empty())
	}
}

/// One attached node, as a backplane holds it: a weak handle that reaches
/// one registry while the registry lives.
///
/// A dropped registry leaves distribution on its own, and each registry
/// attaches its own handle as it is built.
pub struct NodeSink(Weak<Inner>);

impl NodeSink {
	fn of(inner: &Arc<Inner>) -> Self {
		Self(Arc::downgrade(inner))
	}

	/// A second handle on the same node.
	pub(crate) fn share(&self) -> Self {
		Self(Weak::clone(&self.0))
	}

	/// Whether the registry still lives.
	#[must_use]
	pub fn is_attached(&self) -> bool {
		self.0.strong_count() > 0
	}

	/// Fan `payload` out to the subscribers of `topic` on this node at the
	/// backplane-assigned `order`, or `None` once the node is gone.
	///
	/// # Errors
	///
	/// - [`DeliverError::Draining`] -- the node is draining.
	/// - [`DeliverError::Build`] -- the update frame failed to encode.
	pub fn deliver(&self, topic: &Topic, order: u64, payload: &[u8]) -> Option<Result<Delivered, DeliverError>> {
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

/// What one node did with a delivered update: the topics that lost their
/// last local member while it fanned the update out, because the delivery
/// policy expelled a connection.
///
/// They reach the backplane here, in place of [`Backplane::vacated`].
#[derive(Debug, Default)]
#[must_use = "the vacated topics of a delivery reach the backplane, or their counters wait for a sweep"]
pub struct Delivered {
	vacated: Vec<Topic>,
}

impl Delivered {
	/// The topics the delivery vacated.
	#[must_use]
	pub fn into_vacated(self) -> Vec<Topic> {
		self.vacated
	}
}

/// What one [`TopicRegistry::drain`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Drained {
	/// The subscriptions that this drain completed with `end/<topic>`.
	pub completed: usize,
	/// The connections that this drain dismissed with a `Shutdown` GoAway.
	pub dismissed: usize,
}

/// The owning handle behind every clone of a [`TopicRegistry`].
///
/// Its drop ends every subscription and reports each held topic vacated, in
/// the context of the caller that let go of the last clone, outside every
/// delivery.
struct Owner {
	inner: Arc<Inner>,
}

impl Drop for Owner {
	fn drop(&mut self) {
		self.inner.end_all();
	}
}

/// Topic fan-out over multiplexed tightbeam connections.
///
/// Clone-cheap: clones share the same registry. When the last clone drops,
/// every subscription ends and its delivery task stops. The reads live on
/// the [`RegistryView`] of [`view`](Self::view).
#[derive(Clone)]
pub struct TopicRegistry {
	owner: Arc<Owner>,
}

impl Default for TopicRegistry {
	fn default() -> Self {
		Self::new(RegistryOptions::default())
	}
}

/// A borrowed view of a [`TopicRegistry`], for the reads a policy weighs.
///
/// The registry lends a view into each policy callback for that call alone,
/// so a policy holds no registry.
///
/// # Examples
///
/// ```
/// use tightbeam_pubsub::{Topic, TopicRegistry};
///
/// let registry = TopicRegistry::default();
/// let prices: Topic = "prices".parse()?;
/// let view = registry.view();
/// assert_eq!(view.subscriber_count(&prices), 0);
/// assert!(!view.is_draining());
/// # Ok::<(), tightbeam_pubsub::TopicError>(())
/// ```
#[derive(Clone, Copy)]
pub struct RegistryView<'a> {
	inner: &'a Inner,
}

impl<'a> RegistryView<'a> {
	fn of(inner: &'a Inner) -> Self {
		Self { inner }
	}

	/// Whether a [`drain`](TopicRegistry::drain) is in flight or finished, so
	/// the registry refuses subscriptions and publishes.
	#[must_use]
	pub fn is_draining(&self) -> bool {
		let phase = self.inner.phase.load();
		phase.refuses_work()
	}

	/// Live subscriber count for `topic`.
	#[must_use]
	pub fn subscriber_count(&self, topic: &Topic) -> usize {
		let state = self.inner.lock_state();
		state.topics.get(topic).map_or(0, |entry| entry.members.len())
	}
}

impl TopicRegistry {
	/// A registry with explicit queue, policy, and backplane options.
	pub fn new(options: RegistryOptions) -> Self {
		let inner = Arc::new(Inner {
			options,
			drain: AsyncMutex::new(()),
			phase: AtomicDrainPhase::new(),
			next_connection: AtomicU64::new(1),
			next_subscriber: AtomicU64::new(1),
			state: Mutex::new(State::default()),
			backlog: Backlog::new(),
		});

		let sink = NodeSink::of(&inner);
		inner.options.backplane.attach(sink);

		let owner = Arc::new(Owner { inner });
		Self { owner }
	}

	fn inner(&self) -> &Arc<Inner> {
		&self.owner.inner
	}

	/// The reads of this registry, as a [`RegistryView`].
	#[must_use]
	pub fn view(&self) -> RegistryView<'_> {
		RegistryView::of(self.inner())
	}

	/// Admit `served`, yielding the [`Membership`] its subscriptions hang off.
	///
	/// - The connection registers under the session of its link: the peer that
	///   its handshake proved, or the empty session of a cleartext link. The
	///   policies authorize that session.
	/// - Every emit of the connection runs under
	///   [`RegistryOptions::emit_deadline`] on the clock of its writer.
	/// - A registry that already completed its drain turns the connection away
	///   with a `Shutdown` GoAway.
	pub(crate) fn admit(&self, served: &ServedMux) -> Membership {
		let inner = self.inner();
		let id = ConnectionId(inner.next_connection.fetch_add(1, Ordering::Relaxed));
		let budget = ConnectionBudget::new(inner.options.connection_queue_bytes);
		let (expulsion, expelled) = oneshot::channel();

		let emitter = Emitter::served(served, inner.options.emit_deadline);
		let session = served.session().clone();
		let audit = ConnectionAudit::of(served);
		audit.admitted(id.0);

		let member = Member { registry: Arc::downgrade(inner), connection: id };
		let context = ConnectionContext::new(member, emitter.clone());
		let topics = HashMap::new();
		let connected = ConnectionState { emitter, session, budget, topics, expulsion, audit };

		let turned_away = inner.enter(id, connected);
		if let Some(departed) = turned_away {
			departed.expel(GoAwayReason::Shutdown);
		}

		Membership { context, expelled }
	}

	/// Publish `payload` to every subscriber of `topic` on every node of the
	/// backplane, and resolve once the backplane answered.
	///
	/// The stamp advances with no subscriber too, so a late subscriber reads
	/// a dense sequence.
	///
	/// # Errors
	///
	/// - [`PublishError::Draining`] -- the registry is draining, or every node drains.
	/// - [`PublishError::Build`] -- a node could not encode the update frame.
	/// - [`PublishError::TopicLimit`] -- `topic` is new, and the backplane has no room for its counter.
	/// - [`PublishError::Unavailable`] -- the distribution fabric of the backplane failed.
	pub async fn publish(&self, topic: &Topic, payload: impl AsRef<[u8]>) -> Result<(), PublishError> {
		// Each node reads the phase again as it delivers, so a racing drain
		// still refuses the update.
		if self.view().is_draining() {
			return Err(PublishError::Draining);
		}

		let payload = payload.as_ref();
		self.inner().backplane().publish(topic, payload).await
	}

	/// Publish the DER of `inner`, a full tightbeam frame, as the payload of
	/// one update of `topic`.
	///
	/// The page `docs/pubsub.md` (Registry) states what the relay keeps end
	/// to end.
	///
	/// # Errors
	///
	/// - The errors of [`publish`](Self::publish).
	/// - [`PublishError::Build`] -- `inner` failed to encode to DER.
	pub async fn publish_frame(&self, topic: &Topic, inner: &Frame) -> Result<(), PublishError> {
		let payload = inner.to_der().map_err(TightBeamError::from)?;
		self.publish(topic, payload).await
	}

	/// Drain the registry, as a saga of acts:
	///
	/// 1. Refuse new subscriptions and publishes, and freeze the topic set.
	/// 2. Build the `end/<topic>` of every topic at its [`Backplane::last_order`], so completion
	///    burns no order and every other node keeps a dense sequence.
	/// 3. Queue each `end/<topic>` behind every update its subscribers hold. From here the drain
	///    only goes forward.
	/// 4. Wait until every lane emptied, so every `end/<topic>` left. Each emit runs under the emit
	///    deadline, so the wait ends.
	/// 5. Dismiss every served connection with a `Shutdown` GoAway. A connection admitted after
	///    step 3 is dismissed at its admission.
	///
	/// A drain that meets another in flight waits for its outcome. A repeat,
	/// or a drain whose future dropped during step 4, completes nothing and
	/// runs steps 4 and 5 again.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of an `end/<topic>` frame that failed to encode, the signature of
	///   upstream `FrameBuilder::build`. The drain cancels, so the registry takes subscriptions
	///   and publishes again, and a later drain starts over.
	pub async fn drain(&self) -> Result<Drained, TightBeamError> {
		let completed = self.complete().await?;
		self.flushed().await;

		let dismissed = self.inner().dismiss();
		Ok(Drained { completed, dismissed })
	}

	/// Run the acts of a drain that can still refuse, and queue every end
	/// frame. Returns how many subscriptions completed, or `0` when an
	/// earlier drain already completed them.
	///
	/// # Errors
	///
	/// - The errors of [`drain`](Self::drain).
	pub(crate) async fn complete(&self) -> Result<usize, TightBeamError> {
		let Some(draining) = self.begin_drain().await else {
			return Ok(0);
		};

		let completing = draining.end_frames().await?;
		Ok(completing.finish())
	}

	/// Begin a drain: take the drain turn, refuse subscriptions and
	/// publishes from now on, and freeze the topic set. Answers `None` when an
	/// earlier drain ended.
	///
	/// - The call waits for the turn, so a drain in flight settles first.
	/// - A drain that unwound left the phase [`Live`](DrainPhase::Live) through its guard.
	async fn begin_drain(&self) -> Option<Draining<'_>> {
		let inner = &**self.inner();
		let turn = inner.drain.lock().await;

		let guard = DrainGuard::begin(&inner.phase, turn)?;
		let topics: Vec<Topic> = inner.lock_state().topics.keys().cloned().collect();

		let draining = Draining { registry: inner, guard, topics };
		Some(draining)
	}

	/// Resolve once no lane has anything left to emit. Every waiter wakes.
	async fn flushed(&self) {
		self.inner().backlog.idle().await;
	}
}

/// The standing of one served connection in the registry that admitted it:
/// that registry, and the id of the connection there.
///
/// Only [`TopicRegistry::admit`] builds one, so every command names a
/// connection of the registry it runs on.
#[derive(Clone)]
pub(crate) struct Member {
	/// Held weakly, so the registry drops while its connections serve.
	registry: Weak<Inner>,
	connection: ConnectionId,
}

impl Member {
	/// The peer that the handshake of the connection proved, while the
	/// connection is registered.
	///
	/// - A connection that left has no standing and answers `None`.
	/// - A registered anonymous connection answers a session with no peer certificate.
	pub(crate) fn session(&self) -> Option<SessionContext> {
		let registry = self.registry.upgrade()?;
		let state = registry.lock_state();
		let session = state.connection(self.connection).map(|connected| connected.session.clone());
		session
	}

	/// Subscribe the connection to `topic`. Idempotent per topic: a repeat
	/// answers the id it already holds.
	///
	/// # Errors
	///
	/// - [`RegisterError::UnknownConnection`] -- the connection left, or the registry is gone.
	/// - [`RegisterError::Draining`] -- the registry is draining.
	/// - [`RegisterError::LimitReached`] -- the connection holds its cap of subscriptions.
	pub(crate) fn subscribe(&self, topic: Topic) -> Result<SubscriberId, RegisterError> {
		let registry = self.registry.upgrade().ok_or(RegisterError::UnknownConnection)?;
		registry.register(self.connection, topic)
	}

	/// Drop the subscription of the connection to `topic`, and resolve once
	/// its drain task ended, so no update of the subscription leaves after
	/// the answer. Returns whether one existed, so a repeat answers `false`.
	pub(crate) async fn unsubscribe(&self, topic: &Topic) -> bool {
		let registry = self.registry.upgrade();
		let Some(task) = registry.and_then(|registry| registry.unregister(self.connection, topic)) else {
			return false;
		};

		task.ended().await;
		true
	}

	/// A share of the audit trail of the connection, which records nothing
	/// once the connection left.
	pub(crate) fn audit(&self) -> ConnectionAudit {
		let Some(registry) = self.registry.upgrade() else {
			return ConnectionAudit::default();
		};

		let state = registry.lock_state();
		let audit = state.connection(self.connection).map(|connected| connected.audit.share());
		audit.unwrap_or_default()
	}

	/// Leave the registry with every subscription.
	fn leave(&self) {
		if let Some(registry) = self.registry.upgrade() {
			registry.leave(self.connection);
		}
	}
}

/// The registration of one served connection.
///
/// - The drop leaves the registry and ends every subscription of the connection, so a serve
///   that completes or drops leaves no registration behind.
/// - [`expelled`](Self::expelled) is the one signal of a connection the registry expels.
pub(crate) struct Membership {
	context: ConnectionContext,
	expelled: Receiver<GoAwayReason>,
}

impl Membership {
	/// What the application handler of the connection works with.
	pub(crate) fn context(&self) -> &ConnectionContext {
		&self.context
	}

	/// Resolve with the reason the registry expels this connection for.
	/// [`CONNECTION_EXPELLED`] lists the causes of an expulsion.
	///
	/// A registry that drops or forgets the connection leaves the wait pending.
	///
	/// [`CONNECTION_EXPELLED`]: crate::events::CONNECTION_EXPELLED
	pub(crate) async fn expelled(&mut self) -> GoAwayReason {
		let signaled = (&mut self.expelled).await;
		match signaled {
			Ok(reason) => reason,
			Err(_) => pending().await,
		}
	}
}

impl Drop for Membership {
	fn drop(&mut self) {
		self.context.member().leave();
	}
}

#[cfg(test)]
mod tests {
	use core::pin::pin;
	use core::time::Duration;

	use tightbeam::clock::{Clock, ManualClock};
	use tightbeam::marker::MaybeSendFuture;
	use tightbeam::policy::TransitStatus;
	use tightbeam::transport::handshake::negotiation::MuxSettings;
	use tightbeam::transport::multiplex::{MuxDrivers, MuxHandle, SpawnedMux};
	use tightbeam::transport::ResponsePackage;
	use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
	use tokio::sync::Semaphore;
	use tokio::task::{AbortHandle, JoinSet};
	use tokio::time::timeout;

	use super::*;
	use crate::frame::OpaqueFrame;
	use crate::testing::nodes::{waits, Accepting, Admitted, SHORT};
	use crate::testing::{Dial, Loopback, PATIENCE};

	fn count(value: usize) -> NonZeroUsize {
		NonZeroUsize::new(value).expect("test counts should be above zero")
	}

	fn deadline(span: Duration) -> EmitDeadline {
		EmitDeadline::new(span).expect("test deadlines should be above zero")
	}

	/// Subscribe `member` to `name`, expecting acceptance.
	fn subscribed(member: &Member, name: &str) -> SubscriberId {
		let topic: Topic = name.parse().expect("the name should be a topic");
		member.subscribe(topic).expect("the registration should be accepted")
	}

	/// Publish `payload` to `name`, expecting acceptance.
	async fn published(registry: &TopicRegistry, name: &str, payload: &[u8]) {
		let topic: Topic = name.parse().expect("the name should be a topic");
		let outcome = registry.publish(&topic, payload).await;
		outcome.expect("the publish should be accepted");
	}

	/// Run the acts of a drain that can still refuse, expecting the count of
	/// completed subscriptions.
	async fn completed(registry: &TopicRegistry) -> usize {
		let completed = registry.complete().await;
		completed.expect("every end frame builds")
	}

	/// The last order the registry's backplane committed for `name`.
	async fn last_order(registry: &TopicRegistry, name: &str) -> u64 {
		registry
			.inner()
			.backplane()
			.last_order(&name.parse::<Topic>().expect("the name should be a topic"))
			.await
	}

	/// The subscriber `id` of `registry`, while the registry holds it.
	fn subscriber_of(registry: &TopicRegistry, id: SubscriberId) -> Option<Arc<Subscriber>> {
		registry.inner().lock_state().subscribers.get(&id).cloned()
	}

	/// Updates dropped so far for `subscriber`, or `None` once it is gone.
	fn dropped_of(registry: &TopicRegistry, subscriber: SubscriberId) -> Option<u64> {
		let held = subscriber_of(registry, subscriber)?;
		Some(held.dropped.load(Ordering::Relaxed))
	}

	/// The orders queued in the lane of `subscriber` behind the update in
	/// flight.
	fn queued_orders(registry: &TopicRegistry, subscriber: SubscriberId) -> Vec<u64> {
		let Some(held) = subscriber_of(registry, subscriber) else {
			return Vec::new();
		};

		let lane = held.lane();
		let Lane::Open(queue) = &*lane else {
			return Vec::new();
		};

		queue.entries.iter().map(|queued| queued.update.metadata().order()).collect()
	}

	/// A registry with one admitted loopback connection, whose client end
	/// answers nothing. The returned guard keeps the registration and the
	/// link alive.
	async fn registered(options: RegistryOptions) -> (TopicRegistry, Member, Admitted) {
		let registry = TopicRegistry::new(options);
		let admitted = Admitted::to(&registry).await;
		(registry, admitted.member().clone(), admitted)
	}

	/// One loopback connection that a registry admitted: its membership, its
	/// served end, and its client end.
	struct Connection {
		membership: Membership,
		served: ServedMux,
		client: SpawnedMux,
	}

	impl Connection {
		/// Admit one loopback connection under `dial` to `registry`.
		async fn to(registry: &TopicRegistry, dial: &Dial) -> Self {
			let opened = Loopback::open(dial).await;
			let Loopback { server, client } = opened.expect("a loopback link opens");
			let served = server.spawn();
			let membership = registry.admit(&served);
			Self { membership, served, client }
		}
	}

	/// A registry under `options` with one connection over a link under
	/// `settings`, whose client answers every update with `status`. The
	/// returned guard keeps the connection alive.
	async fn answering(
		options: RegistryOptions,
		settings: MuxSettings,
		status: TransitStatus,
	) -> (TopicRegistry, Member, impl Sized) {
		let registry = TopicRegistry::new(options);
		let dial = Dial { settings, ..Dial::default() };
		let Connection { membership, served, client } = Connection::to(&registry, &dial).await;
		let SpawnedMux { handle, responder, drivers } = client;

		let answer = move |_| async move { ResponsePackage::new(status, None) };
		let answering = tokio::spawn(responder.serve(answer));

		let member = membership.context().member().clone();
		let guard = (membership, served, handle, drivers, answering.abort_handle());
		(registry, member, guard)
	}

	/// The answer of one update at a [`Holding`] client: its drop before it
	/// answers reports the cancel of its stream.
	struct Answer(Option<UnboundedSender<()>>);

	impl Answer {
		/// The answer settled, so its drop reports nothing.
		fn settle(mut self) {
			self.0 = None;
		}
	}

	impl Drop for Answer {
		fn drop(&mut self) {
			if let Some(cancelled) = self.0.take() {
				// The test may hold no receiver.
				let _ = cancelled.send(());
			}
		}
	}

	/// The client end of a connection whose responder reports each update it
	/// takes, answers it once the semaphore grants a permit, and reports each
	/// stream whose answer the server cancelled.
	struct Holding {
		answers: Arc<Semaphore>,
		taken: UnboundedReceiver<()>,
		cancelled: UnboundedReceiver<()>,
		_client: (MuxHandle, MuxDrivers, AbortHandle),
	}

	impl Holding {
		/// Serve `client` as a holding client.
		fn serve(client: SpawnedMux) -> Self {
			let SpawnedMux { handle, responder, drivers } = client;
			let answers = Arc::new(Semaphore::new(0));
			let (took, taken) = unbounded_channel();
			let (cancel, cancelled) = unbounded_channel();

			let gate = Arc::clone(&answers);
			let answer = move |_| {
				let gate = Arc::clone(&gate);
				let took = took.clone();
				let pending = Answer(Some(cancel.clone()));
				async move {
					let _ = took.send(());
					let permit = gate.acquire().await.expect("the answer gate stays open");
					permit.forget();
					pending.settle();
					ResponsePackage::new(TransitStatus::Ok, None)
				}
			};

			let answering = tokio::spawn(responder.serve(answer));
			Self { answers, taken, cancelled, _client: (handle, drivers, answering.abort_handle()) }
		}

		/// Wait until the client took one more update, so its emit is in
		/// flight.
		async fn took(&mut self) {
			let taken = timeout(PATIENCE, self.taken.recv()).await;
			assert!(matches!(taken, Ok(Some(()))), "the client should take the update");
		}

		/// Wait until the server cancelled the stream of one update.
		async fn cancelled(&mut self) -> bool {
			let cancelled = timeout(PATIENCE, self.cancelled.recv()).await;
			matches!(cancelled, Ok(Some(())))
		}
	}

	/// A registry under `options` with one connection over a link under
	/// `dial`, whose client holds every answer. The returned guard keeps the
	/// membership and the served end alive.
	async fn holding_over(options: RegistryOptions, dial: &Dial) -> (TopicRegistry, Member, Holding, impl Sized) {
		let registry = TopicRegistry::new(options);
		let Connection { membership, served, client } = Connection::to(&registry, dial).await;
		let member = membership.context().member().clone();
		(registry, member, Holding::serve(client), (membership, served))
	}

	/// As [`holding_over`], under the default dial.
	async fn holding(options: RegistryOptions) -> (TopicRegistry, Member, Holding, impl Sized) {
		holding_over(options, &Dial::default()).await
	}

	/// Wait until every lane of `registry` is idle, expecting it within the
	/// deadline.
	async fn settled(registry: &TopicRegistry) {
		let flushed = timeout(PATIENCE, registry.flushed()).await;
		flushed.expect("every lane should go idle");
	}

	/// Wait until the backlog of `registry`, which the registry and every
	/// subscriber it ever held share, is gone, once the caller drops the
	/// registry. Answers whether it went within the deadline.
	async fn backlog_gone(backlog: Arc<Backlog>, registry: TopicRegistry) -> bool {
		let mut watched = backlog.0.subscribe();
		drop((backlog, registry));

		let gone = async { while watched.changed().await.is_ok() {} };
		timeout(PATIENCE, gone).await.is_ok()
	}

	/// A manual clock, and a dial whose server end runs on it.
	fn manual() -> (Arc<ManualClock>, Dial) {
		let clock = Arc::new(ManualClock::default());
		let dial = Dial { clock: Arc::clone(&clock) as Arc<dyn Clock>, ..Dial::default() };
		(clock, dial)
	}

	#[tokio::test]
	async fn every_concurrent_flush_waiter_returns_once_the_lanes_idle() {
		let (registry, member, mut client, _connection) = holding(RegistryOptions::default()).await;
		subscribed(&member, "prices");
		published(&registry, "prices", b"tick").await;
		client.took().await;

		let mut first = pin!(registry.flushed());
		let mut second = pin!(registry.flushed());
		let first_waits = waits(first.as_mut()).await;
		let second_waits = waits(second.as_mut()).await;
		client.answers.add_permits(1);

		let both = timeout(PATIENCE, async { tokio::join!(first, second) }).await;
		assert!(first_waits && second_waits);
		assert!(both.is_ok());
	}

	#[tokio::test]
	async fn register_is_idempotent_per_connection_and_topic() {
		let (registry, member, _peer) = registered(RegistryOptions::default()).await;

		let first = subscribed(&member, "prices");
		let second = subscribed(&member, "prices");
		assert_eq!(first, second);
		assert_eq!(
			registry
				.view()
				.subscriber_count(&"prices".parse::<Topic>().expect("the name should be a topic")),
			1
		);
	}

	#[tokio::test]
	async fn register_refuses_past_the_per_connection_subscription_cap() {
		let options = RegistryOptions { max_subscriptions_per_connection: count(2), ..RegistryOptions::default() };
		let (registry, member, _peer) = registered(options).await;

		let first = subscribed(&member, "a");
		subscribed(&member, "b");

		let refused = member.subscribe("c".parse::<Topic>().expect("the name should be a topic"));
		assert_eq!(refused, Err(RegisterError::LimitReached));
		assert_eq!(subscribed(&member, "a"), first);

		member
			.unsubscribe(&"a".parse::<Topic>().expect("the name should be a topic"))
			.await;

		subscribed(&member, "c");
		assert_eq!(
			registry
				.view()
				.subscriber_count(&"c".parse::<Topic>().expect("the name should be a topic")),
			1
		);
	}

	#[tokio::test]
	async fn register_requires_a_known_connection() {
		let (_registry, member, peer) = registered(RegistryOptions::default()).await;

		drop(peer);

		let outcome = member.subscribe("prices".parse::<Topic>().expect("the name should be a topic"));
		assert_eq!(outcome, Err(RegisterError::UnknownConnection));
	}

	#[tokio::test]
	async fn a_member_subscribes_in_the_registry_that_admitted_it() {
		let (admitting, member, _peer) = registered(RegistryOptions::default()).await;
		let (other, _other_member, _other_peer) = registered(RegistryOptions::default()).await;

		subscribed(&member, "prices");

		assert_eq!(
			admitting
				.view()
				.subscriber_count(&"prices".parse::<Topic>().expect("the name should be a topic")),
			1
		);
		assert_eq!(
			other
				.view()
				.subscriber_count(&"prices".parse::<Topic>().expect("the name should be a topic")),
			0
		);
	}

	#[tokio::test]
	async fn a_session_requires_a_live_registration() {
		let (_registry, member, peer) = registered(RegistryOptions::default()).await;
		let held = member.session();

		drop(peer);

		let left = member.session();
		assert!(held.is_some());
		assert!(left.is_none());
	}

	#[tokio::test]
	async fn unregister_prunes_the_emptied_topic() {
		let (registry, member, _peer) = registered(RegistryOptions::default()).await;
		subscribed(&member, "prices");

		member
			.unsubscribe(&"prices".parse::<Topic>().expect("the name should be a topic"))
			.await;

		let state = registry.inner().lock_state();
		assert!(!state
			.topics
			.contains_key(&"prices".parse::<Topic>().expect("the name should be a topic")));
	}

	#[tokio::test]
	async fn unregister_forgets_the_membership() {
		let (registry, member, _peer) = registered(RegistryOptions::default()).await;

		subscribed(&member, "prices");

		let removed = member
			.unsubscribe(&"prices".parse::<Topic>().expect("the name should be a topic"))
			.await;
		let repeat = member
			.unsubscribe(&"prices".parse::<Topic>().expect("the name should be a topic"))
			.await;
		assert!(removed);
		assert!(!repeat);
		assert_eq!(
			registry
				.view()
				.subscriber_count(&"prices".parse::<Topic>().expect("the name should be a topic")),
			0
		);
	}

	#[tokio::test]
	async fn a_dropped_membership_forgets_every_subscription() {
		let (registry, member, peer) = registered(RegistryOptions::default()).await;
		subscribed(&member, "prices");
		subscribed(&member, "chat");

		drop(peer);

		assert_eq!(
			registry
				.view()
				.subscriber_count(&"prices".parse::<Topic>().expect("the name should be a topic")),
			0
		);
		assert_eq!(
			registry
				.view()
				.subscriber_count(&"chat".parse::<Topic>().expect("the name should be a topic")),
			0
		);
	}

	#[tokio::test]
	async fn a_dropped_membership_ends_a_drain_task_parked_in_an_emit() {
		let registry = TopicRegistry::default();
		let Connection { membership, served, client } = Connection::to(&registry, &Dial::default()).await;
		let mut client = Holding::serve(client);

		subscribed(membership.context().member(), "prices");
		published(&registry, "prices", b"tick").await;
		client.took().await;

		drop(membership);

		let cancelled = client.cancelled().await;
		settled(&registry).await;
		assert!(cancelled, "the parked emit should end and cancel its stream");
		drop(served);
	}

	#[tokio::test]
	async fn an_unsubscribe_returns_once_its_drain_task_ended() {
		let (registry, member, mut client, _connection) = holding(RegistryOptions::default()).await;
		let id = subscribed(&member, "prices");
		published(&registry, "prices", b"tick").await;
		client.took().await;
		let held = subscriber_of(&registry, id).map(|subscriber| Arc::downgrade(&subscriber));

		let unsubscribed = member
			.unsubscribe(&"prices".parse::<Topic>().expect("the name should be a topic"))
			.await;

		assert!(unsubscribed);
		let ended = held.is_some_and(|subscriber| subscriber.upgrade().is_none());
		assert!(ended, "the drain task should hold its subscriber no more");
	}

	#[tokio::test]
	async fn a_dropped_registry_ends_every_drain_task() {
		let (registry, member, _peer) = registered(RegistryOptions::default()).await;
		subscribed(&member, "prices");
		let backlog = Arc::clone(&registry.inner().backlog);

		assert!(backlog_gone(backlog, registry).await);
	}

	#[tokio::test]
	async fn publish_to_a_memberless_topic_retains_no_state() {
		let (registry, member, _peer) = registered(RegistryOptions::default()).await;
		published(&registry, "silence", b"tick").await;
		published(&registry, "silence", b"tock").await;

		{
			let state = registry.inner().lock_state();
			assert!(!state
				.topics
				.contains_key(&"silence".parse::<Topic>().expect("the name should be a topic")));
		}

		// The backplane kept the counter, so a late subscriber still reads a
		// dense sequence.
		subscribed(&member, "silence");
		published(&registry, "silence", b"third").await;

		assert_eq!(last_order(&registry, "silence").await, 3);
	}

	/// Delivery policy returning one fixed verdict.
	struct FixedVerdict(DeliveryVerdict);

	impl DeliveryPolicy for FixedVerdict {
		fn on_full(&self, _registry: RegistryView<'_>, _topic: &Topic, _dropped_so_far: u64) -> DeliveryVerdict {
			self.0
		}
	}

	/// The saturation of a registry: `capacity` queue slots, `bytes` of
	/// connection budget, and one fixed `verdict`.
	struct Saturating {
		capacity: usize,
		bytes: usize,
		verdict: DeliveryVerdict,
	}

	impl Saturating {
		/// The registry options of this saturation.
		fn options(self) -> RegistryOptions {
			RegistryOptions {
				queue_capacity: count(self.capacity),
				connection_queue_bytes: count(self.bytes),
				delivery: Arc::new(FixedVerdict(self.verdict)),
				..RegistryOptions::default()
			}
		}
	}

	/// A holding connection under `options` subscribed to `prices`, whose
	/// first update `first` is in flight.
	async fn in_flight(
		options: RegistryOptions,
		first: &[u8],
	) -> (TopicRegistry, SubscriberId, Member, Holding, impl Sized) {
		let (registry, member, mut client, connection) = holding(options).await;
		let id = subscribed(&member, "prices");
		published(&registry, "prices", first).await;
		client.took().await;
		(registry, id, member, client, connection)
	}

	#[tokio::test]
	async fn drop_oldest_keeps_the_newest_updates() {
		let options = Saturating { capacity: 2, bytes: 1024, verdict: DeliveryVerdict::DropOldest }.options();
		let (registry, id, _member, _client, _connection) = in_flight(options, b"1").await;

		for payload in [b"2", b"3", b"4"] {
			published(&registry, "prices", payload).await;
		}

		assert_eq!(queued_orders(&registry, id), [3, 4]);
		assert_eq!(dropped_of(&registry, id), Some(1));
	}

	#[tokio::test]
	async fn drop_new_keeps_the_oldest_updates() {
		let options = Saturating { capacity: 2, bytes: 1024, verdict: DeliveryVerdict::DropNew }.options();
		let (registry, id, _member, _client, _connection) = in_flight(options, b"1").await;

		for payload in [b"2", b"3", b"4"] {
			published(&registry, "prices", payload).await;
		}

		assert_eq!(queued_orders(&registry, id), [2, 3]);
		assert_eq!(dropped_of(&registry, id), Some(1));
	}

	#[tokio::test]
	async fn disconnect_expels_the_connection_with_enhance_your_calm() {
		let options = Saturating { capacity: 1, bytes: 1024, verdict: DeliveryVerdict::Disconnect }.options();
		let registry = TopicRegistry::new(options);
		let Connection { mut membership, served, client } = Connection::to(&registry, &Dial::default()).await;
		let mut client = Holding::serve(client);
		subscribed(membership.context().member(), "prices");
		published(&registry, "prices", b"1").await;
		client.took().await;

		published(&registry, "prices", b"2").await;
		published(&registry, "prices", b"3").await;

		let reason = timeout(PATIENCE, membership.expelled()).await;
		assert_eq!(reason.ok(), Some(GoAwayReason::EnhanceYourCalm));
		assert_eq!(
			registry
				.view()
				.subscriber_count(&"prices".parse::<Topic>().expect("the name should be a topic")),
			0
		);
		drop(served);
	}

	#[tokio::test]
	async fn an_update_past_the_byte_budget_counts_as_a_full_queue() {
		let options = Saturating { capacity: 32, bytes: 8, verdict: DeliveryVerdict::DropNew }.options();
		let (registry, id, _member, _client, _connection) = in_flight(options, b"123456").await;

		published(&registry, "prices", b"abcdef").await;

		assert_eq!(queued_orders(&registry, id), Vec::<u64>::new());
		assert_eq!(dropped_of(&registry, id), Some(1));
	}

	#[tokio::test]
	async fn an_update_that_fills_the_byte_budget_exactly_is_delivered() {
		let options = Saturating { capacity: 32, bytes: 8, verdict: DeliveryVerdict::DropNew }.options();
		let (registry, id, _member, _client, _connection) = in_flight(options, b"12345678").await;
		assert_eq!(dropped_of(&registry, id), Some(0));
	}

	#[tokio::test]
	async fn drop_oldest_frees_the_byte_budget_for_the_new_update() {
		let options = Saturating { capacity: 32, bytes: 12, verdict: DeliveryVerdict::DropOldest }.options();
		let (registry, id, _member, _client, _connection) = in_flight(options, b"123456").await;

		published(&registry, "prices", b"abcd").await;
		published(&registry, "prices", b"5678").await;

		assert_eq!(queued_orders(&registry, id), [3]);
		assert_eq!(dropped_of(&registry, id), Some(1));
	}

	#[tokio::test]
	async fn drop_oldest_drops_the_new_update_when_eviction_frees_too_little() {
		let options = Saturating { capacity: 32, bytes: 8, verdict: DeliveryVerdict::DropOldest }.options();
		let (registry, _holder, member, client, _connection) = in_flight(options, b"123456").await;
		let starved = subscribed(&member, "chat");

		published(&registry, "chat", b"abcdef").await;

		assert_eq!(queued_orders(&registry, starved), Vec::<u64>::new());
		assert_eq!(dropped_of(&registry, starved), Some(1));
		drop(client);
	}

	#[tokio::test]
	async fn a_closed_lane_returns_its_octets_to_the_budget() {
		let options = Saturating { capacity: 32, bytes: 10, verdict: DeliveryVerdict::DropNew }.options();
		let (registry, _leaving, member, mut client, _connection) = in_flight(options, b"12").await;
		let staying = subscribed(&member, "chat");
		published(&registry, "prices", b"123456").await;

		member
			.unsubscribe(&"prices".parse::<Topic>().expect("the name should be a topic"))
			.await;
		published(&registry, "chat", b"abcdef").await;

		client.took().await;
		assert_eq!(dropped_of(&registry, staying), Some(0));
	}

	#[tokio::test]
	async fn an_emit_past_the_deadline_on_the_clock_of_the_link_ends_its_lane() {
		let (clock, dial) = manual();
		let options = RegistryOptions { emit_deadline: deadline(SHORT), ..RegistryOptions::default() };
		let (registry, member, mut client, _connection) = holding_over(options, &dial).await;
		let id = subscribed(&member, "prices");
		published(&registry, "prices", b"tick").await;
		client.took().await;
		let before = dropped_of(&registry, id);

		clock.advance(SHORT + Duration::from_secs(1));
		settled(&registry).await;

		assert_eq!(before, Some(0));
		assert_eq!(dropped_of(&registry, id), None);
	}

	#[tokio::test]
	async fn an_emit_past_the_deadline_expels_its_connection() {
		let (clock, dial) = manual();
		let options = RegistryOptions { emit_deadline: deadline(SHORT), ..RegistryOptions::default() };
		let registry = TopicRegistry::new(options);
		let Connection { mut membership, served, client } = Connection::to(&registry, &dial).await;
		let mut client = Holding::serve(client);
		let member = membership.context().member().clone();
		subscribed(&member, "prices");
		subscribed(&member, "chat");
		published(&registry, "prices", b"tick").await;
		client.took().await;

		clock.advance(SHORT + Duration::from_secs(1));

		let reason = timeout(PATIENCE, membership.expelled()).await;
		let renewed = member.subscribe("prices".parse::<Topic>().expect("the name should be a topic"));
		assert_eq!(reason.ok(), Some(GoAwayReason::EnhanceYourCalm));
		assert_eq!(renewed, Err(RegisterError::UnknownConnection));
		assert_eq!(
			registry
				.view()
				.subscriber_count(&"chat".parse::<Topic>().expect("the name should be a topic")),
			0
		);
		drop(served);
	}

	#[tokio::test]
	async fn an_emit_of_the_application_ends_at_the_emit_deadline() {
		let (clock, dial) = manual();
		let options = RegistryOptions { emit_deadline: deadline(SHORT), ..RegistryOptions::default() };
		let registry = TopicRegistry::new(options);
		let admitted = Admitted::over(&registry, &dial).await;
		let notice = OpaqueFrame { id: "notice", order: 1, payload: b"ping" }.build();
		let notice = notice.expect("the notice builds");

		let mut emitted = pin!(admitted.context().emitter().until_settled(&notice));
		let parked = waits(emitted.as_mut()).await;
		clock.advance(SHORT + Duration::from_secs(1));

		let settled = timeout(PATIENCE, emitted).await;
		assert!(parked);
		assert!(matches!(settled, Ok(Err(_))));
	}

	#[tokio::test]
	async fn a_stale_retirement_spares_a_newer_subscription() {
		let (registry, member, _peer) = registered(RegistryOptions::default()).await;
		let stale = subscribed(&member, "prices");
		member
			.unsubscribe(&"prices".parse::<Topic>().expect("the name should be a topic"))
			.await;

		let fresh = subscribed(&member, "prices");

		registry.inner().retire(
			member.connection,
			&"prices".parse::<Topic>().expect("the name should be a topic"),
			stale,
		);

		let held = subscribed(&member, "prices");
		assert_eq!(held, fresh);
		assert_eq!(
			registry
				.view()
				.subscriber_count(&"prices".parse::<Topic>().expect("the name should be a topic")),
			1
		);
	}

	#[tokio::test]
	async fn a_completed_subscription_leaves_the_registry() {
		let accepting = TransitStatus::Ok;
		let (registry, member, _peer) =
			answering(RegistryOptions::default(), MuxSettings::symmetric(4), accepting).await;
		let id = subscribed(&member, "prices");

		completed(&registry).await;
		settled(&registry).await;

		assert_eq!(dropped_of(&registry, id), None);
	}

	#[tokio::test]
	async fn a_peer_refusal_counts_the_update_and_the_lane_continues() {
		let refusing = TransitStatus::ResourceExhausted;
		let (registry, member, _peer) =
			answering(RegistryOptions::default(), MuxSettings::symmetric(4), refusing).await;
		let id = subscribed(&member, "prices");

		published(&registry, "prices", b"one").await;
		published(&registry, "prices", b"two").await;

		settled(&registry).await;
		assert_eq!(dropped_of(&registry, id), Some(2));
	}

	#[tokio::test]
	async fn an_update_past_the_session_budget_counts_and_the_lane_continues() {
		let unfunded = MuxSettings::symmetric(4).with_send_budget(Some(0));
		let (registry, member, _peer) = answering(RegistryOptions::default(), unfunded, TransitStatus::Ok).await;
		let id = subscribed(&member, "prices");

		published(&registry, "prices", b"one").await;
		published(&registry, "prices", b"two").await;

		settled(&registry).await;
		assert_eq!(dropped_of(&registry, id), Some(2));
	}

	#[tokio::test]
	async fn a_delivered_update_returns_its_octets_to_the_budget() {
		let options = Saturating { capacity: 32, bytes: 8, verdict: DeliveryVerdict::DropNew }.options();
		let (registry, member, _peer) = answering(options, MuxSettings::symmetric(4), TransitStatus::Ok).await;
		let id = subscribed(&member, "prices");

		published(&registry, "prices", b"123456").await;
		settled(&registry).await;
		published(&registry, "prices", b"abcdef").await;
		settled(&registry).await;

		assert_eq!(dropped_of(&registry, id), Some(0));
	}

	#[tokio::test]
	async fn a_counter_whose_last_member_left_makes_room_for_a_new_topic() {
		let backplane: Arc<dyn Backplane> = Arc::new(Local::default().with_max_topics(count(1)));
		let (registry, member, _peer) = registered(RegistryOptions { backplane, ..RegistryOptions::default() }).await;

		subscribed(&member, "prices");
		member
			.unsubscribe(&"prices".parse::<Topic>().expect("the name should be a topic"))
			.await;
		published(&registry, "prices", b"tick").await;

		let outcome = registry
			.publish(&"chat".parse::<Topic>().expect("the name should be a topic"), b"hello")
			.await;
		assert!(outcome.is_ok());
	}

	/// Subscribe `member` to each of `names` and publish once to each, so
	/// every counted topic of the backplane has a member.
	async fn crowded(registry: &TopicRegistry, member: &Member, names: &[&str]) {
		for name in names {
			subscribed(member, name);
			published(registry, name, b"tick").await;
		}
	}

	/// The three topics the topic-limit tests fill a backplane of three with.
	const FULL: [&str; 3] = ["prices", "chat", "news"];

	#[tokio::test]
	async fn a_topic_that_loses_its_last_member_after_a_refusal_makes_room() {
		let backplane: Arc<dyn Backplane> = Arc::new(Local::default().with_max_topics(count(3)));
		let (registry, member, _peer) = registered(RegistryOptions { backplane, ..RegistryOptions::default() }).await;

		crowded(&registry, &member, &FULL).await;

		let refused = registry
			.publish(&"sports".parse::<Topic>().expect("the name should be a topic"), b"hello")
			.await;

		member
			.unsubscribe(&"prices".parse::<Topic>().expect("the name should be a topic"))
			.await;

		let outcome = registry
			.publish(&"sports".parse::<Topic>().expect("the name should be a topic"), b"hello")
			.await;
		assert!(matches!(refused, Err(PublishError::TopicLimit)));
		assert!(outcome.is_ok());
	}

	#[tokio::test]
	async fn a_dropped_registry_reports_each_topic_it_held() {
		let backplane = Arc::new(Local::default().with_max_topics(count(3)));
		let shared = Arc::clone(&backplane) as Arc<dyn Backplane>;
		let options = RegistryOptions { backplane: shared, ..RegistryOptions::default() };
		let (registry, member, _peer) = registered(options).await;

		crowded(&registry, &member, &FULL).await;

		let refused = registry
			.publish(&"sports".parse::<Topic>().expect("the name should be a topic"), b"hello")
			.await;

		drop(registry);

		let outcome = backplane
			.publish(&"sports".parse::<Topic>().expect("the name should be a topic"), b"hello")
			.await;
		assert!(matches!(refused, Err(PublishError::TopicLimit)));
		assert!(outcome.is_ok());
	}

	#[tokio::test]
	async fn an_expulsion_during_a_delivery_frees_the_counters_it_vacates() {
		let backplane: Arc<dyn Backplane> = Arc::new(Local::default().with_max_topics(count(2)));
		let saturating = Saturating { capacity: 1, bytes: 1024, verdict: DeliveryVerdict::Disconnect }.options();
		let options = RegistryOptions { backplane, ..saturating };
		let (registry, member, mut client, _connection) = holding(options).await;

		subscribed(&member, "prices");
		subscribed(&member, "chat");
		published(&registry, "chat", b"one").await;
		client.took().await;
		published(&registry, "prices", b"one").await;
		client.took().await;

		let refused = registry
			.publish(&"sports".parse::<Topic>().expect("the name should be a topic"), b"hello")
			.await;

		published(&registry, "prices", b"two").await;
		published(&registry, "prices", b"three").await;

		let outcome = registry
			.publish(&"news".parse::<Topic>().expect("the name should be a topic"), b"hello")
			.await;
		assert!(matches!(refused, Err(PublishError::TopicLimit)));
		assert!(outcome.is_ok());
	}

	/// A backplane that wraps [`Local`] and lets every vacancy report go.
	struct Forgetful(Local);

	impl Backplane for Forgetful {
		fn attach(&self, sink: NodeSink) {
			self.0.attach(sink);
		}

		fn publish<'a>(&'a self, topic: &'a Topic, payload: &'a [u8]) -> MaybeSendFuture<'a, Result<(), PublishError>> {
			self.0.publish(topic, payload)
		}

		fn last_order<'a>(&'a self, topic: &'a Topic) -> MaybeSendFuture<'a, u64> {
			self.0.last_order(topic)
		}

		fn vacated(&self, _topic: &Topic) {}
	}

	#[tokio::test]
	async fn a_wrapper_that_drops_vacancy_reports_still_frees_counters() {
		let local = Local::default().with_max_topics(count(1));
		let backplane: Arc<dyn Backplane> = Arc::new(Forgetful(local));
		let (registry, member, _peer) = registered(RegistryOptions { backplane, ..RegistryOptions::default() }).await;

		crowded(&registry, &member, &["prices"]).await;

		let refused = registry
			.publish(&"chat".parse::<Topic>().expect("the name should be a topic"), b"hello")
			.await;

		member
			.unsubscribe(&"prices".parse::<Topic>().expect("the name should be a topic"))
			.await;

		let outcome = registry
			.publish(&"chat".parse::<Topic>().expect("the name should be a topic"), b"hello")
			.await;
		assert!(matches!(refused, Err(PublishError::TopicLimit)));
		assert!(outcome.is_ok());
	}

	#[tokio::test]
	async fn a_dropped_expulsion_sender_never_drains_the_connection() {
		let registry = TopicRegistry::default();
		let Connection { mut membership, served, client } = Connection::to(&registry, &Dial::default()).await;

		drop(registry);

		let mut serving = JoinSet::new();
		serving.spawn(async move { served.serve_dispatch(Accepting, membership.expelled()).await });

		let probe = OpaqueFrame { id: "probe", order: 1, payload: b"ping" }.build();
		let probe = probe.expect("the probe builds");

		let emitted = client.handle.emit_on_stream(&probe);
		let answered = timeout(PATIENCE, emitted).await;
		assert!(matches!(answered, Ok(Ok(None))));
		assert_eq!(client.handle.goaway_reason(), None);
	}

	/// Disconnects a connection whose topic has a subscriber, as the
	/// registry counts it from inside `on_full`, and drops the update
	/// otherwise.
	struct DisconnectWhileSubscribed;

	impl DeliveryPolicy for DisconnectWhileSubscribed {
		fn on_full(&self, registry: RegistryView<'_>, topic: &Topic, _dropped_so_far: u64) -> DeliveryVerdict {
			if registry.subscriber_count(topic) > 0 {
				return DeliveryVerdict::Disconnect;
			}

			DeliveryVerdict::DropNew
		}
	}

	#[tokio::test]
	async fn a_registry_drops_while_a_policy_and_a_backplane_are_attached() {
		let delivery: Arc<dyn DeliveryPolicy> = Arc::new(DisconnectWhileSubscribed);
		let backplane: Arc<dyn Backplane> = Arc::new(Forgetful(Local::default()));
		let options = RegistryOptions { delivery, backplane, ..RegistryOptions::default() };
		let (registry, member, _peer) = registered(options).await;
		subscribed(&member, "prices");

		let backlog = Arc::clone(&registry.inner().backlog);
		assert!(backlog_gone(backlog, registry).await);
	}

	#[tokio::test]
	async fn a_delivery_policy_may_call_back_into_the_registry() {
		let delivery: Arc<dyn DeliveryPolicy> = Arc::new(DisconnectWhileSubscribed);
		let options = RegistryOptions { queue_capacity: count(1), delivery, ..RegistryOptions::default() };
		let registry = TopicRegistry::new(options);
		let Connection { mut membership, served, client } = Connection::to(&registry, &Dial::default()).await;
		let mut client = Holding::serve(client);

		subscribed(membership.context().member(), "prices");
		published(&registry, "prices", b"one").await;

		client.took().await;

		published(&registry, "prices", b"two").await;
		published(&registry, "prices", b"three").await;

		let reason = timeout(PATIENCE, membership.expelled()).await;
		assert_eq!(reason.ok(), Some(GoAwayReason::EnhanceYourCalm));
		drop(served);
	}

	#[tokio::test]
	async fn publish_stamps_dense_per_topic_orders() {
		let (registry, member, _peer) = registered(RegistryOptions::default()).await;
		subscribed(&member, "prices");
		subscribed(&member, "chat");

		published(&registry, "prices", b"one").await;
		published(&registry, "prices", b"two").await;
		published(&registry, "chat", b"hello").await;

		assert_eq!(last_order(&registry, "prices").await, 2);
		assert_eq!(last_order(&registry, "chat").await, 1);
	}

	#[tokio::test]
	async fn a_completed_registry_refuses_further_registration_and_publish() {
		let (registry, member, _peer) = registered(RegistryOptions::default()).await;

		subscribed(&member, "prices");

		let signaled = completed(&registry).await;
		let again = completed(&registry).await;
		let refused = member.subscribe("chat".parse::<Topic>().expect("the name should be a topic"));
		let late = registry
			.publish(&"prices".parse::<Topic>().expect("the name should be a topic"), b"tick")
			.await;
		assert_eq!(signaled, 1);
		assert_eq!(again, 0);
		assert!(matches!(refused, Err(RegisterError::Draining)));
		assert!(matches!(late, Err(PublishError::Draining)));
	}

	#[tokio::test]
	async fn a_drain_dismisses_every_connection_with_shutdown() {
		let registry = TopicRegistry::default();
		let Connection { mut membership, served, client } = Connection::to(&registry, &Dial::default()).await;

		let drained = registry.drain().await;

		let reason = timeout(PATIENCE, membership.expelled()).await;
		assert!(matches!(drained, Ok(Drained { completed: 0, dismissed: 1 })));
		assert_eq!(reason.ok(), Some(GoAwayReason::Shutdown));
		drop((served, client));
	}

	#[tokio::test]
	async fn a_repeat_drain_completes_and_dismisses_nothing() {
		let (registry, _member, _peer) = registered(RegistryOptions::default()).await;
		registry.drain().await.expect("the first drain completes");

		let repeated = registry.drain().await;
		assert!(matches!(repeated, Ok(Drained { completed: 0, dismissed: 0 })));
	}

	#[tokio::test]
	async fn a_connection_admitted_after_a_drain_is_dismissed_at_once() {
		let registry = TopicRegistry::default();
		registry.drain().await.expect("a drain with no topic completes");

		let Connection { mut membership, served, client } = Connection::to(&registry, &Dial::default()).await;

		let reason = timeout(PATIENCE, membership.expelled()).await;
		assert_eq!(reason.ok(), Some(GoAwayReason::Shutdown));
		drop((served, client));
	}

	#[tokio::test]
	async fn a_drain_burns_no_order() {
		let (registry, member, _peer) = registered(RegistryOptions::default()).await;
		subscribed(&member, "prices");
		published(&registry, "prices", b"tick").await;
		assert_eq!(completed(&registry).await, 1);
		assert_eq!(last_order(&registry, "prices").await, 1);
	}

	#[tokio::test]
	async fn a_drain_leaves_sibling_orders_dense() {
		let backplane = Arc::new(Local::default());
		let options = || RegistryOptions {
			backplane: Arc::clone(&backplane) as Arc<dyn Backplane>,
			..RegistryOptions::default()
		};

		let (alpha, alpha_member, _alpha_peer) = registered(options()).await;
		let (beta, beta_member, _beta_peer) = registered(options()).await;
		subscribed(&alpha_member, "prices");
		subscribed(&beta_member, "prices");
		published(&alpha, "prices", b"tick").await;

		assert_eq!(completed(&alpha).await, 1);

		published(&beta, "prices", b"tock").await;

		assert_eq!(
			backplane
				.last_order(&"prices".parse::<Topic>().expect("the name should be a topic"))
				.await,
			2
		);
	}

	#[tokio::test]
	async fn a_drain_waits_for_a_publish_in_flight() {
		let (registry, member, mut client, _connection) = holding(RegistryOptions::default()).await;
		subscribed(&member, "prices");
		published(&registry, "prices", b"tick").await;
		client.took().await;

		let mut draining = pin!(registry.drain());
		let parked = waits(draining.as_mut()).await;
		client.answers.add_permits(2);

		let drained = timeout(PATIENCE, draining).await;
		assert!(parked, "the drain should wait for the update in flight");
		assert!(matches!(drained, Ok(Ok(Drained { completed: 1, dismissed: 1 }))));
	}

	/// Begin a drain of `registry`, expecting a live registry.
	async fn begun(registry: &TopicRegistry) -> Draining<'_> {
		let begun = registry.begin_drain().await;
		begun.expect("a live registry should begin its drain")
	}

	#[tokio::test]
	async fn a_subscribe_during_a_drain_is_refused() {
		let (registry, member, _peer) = registered(RegistryOptions::default()).await;
		let _draining = begun(&registry).await;

		let refused = member.subscribe("prices".parse::<Topic>().expect("the name should be a topic"));
		assert!(matches!(refused, Err(RegisterError::Draining)));
	}

	#[tokio::test]
	async fn a_drain_that_unwinds_before_it_completes_leaves_the_registry_live() {
		let (registry, member, _peer) = registered(RegistryOptions::default()).await;
		subscribed(&member, "prices");

		let draining = begun(&registry).await;
		drop(draining);

		let resubscribed = member.subscribe("chat".parse::<Topic>().expect("the name should be a topic"));
		let retried = registry.complete().await;
		assert!(resubscribed.is_ok());
		assert!(matches!(retried, Ok(2)));
	}
}
