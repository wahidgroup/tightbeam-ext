//! The topic registry: subscription bookkeeping, publish fan-out, and
//! per-subscriber delivery.
//!
//! One registry serves a whole process. Connections register with their
//! [`Emitter`], topics map to member subscribers, and every subscriber owns
//! one bounded queue drained by one task, so one slow client never stalls
//! another.
//!
//! Each connection also holds a byte budget that every queued update of its
//! subscriptions draws from ([`RegistryOptions::connection_queue_bytes`]),
//! and each update has a deadline to leave
//! ([`RegistryOptions::emit_deadline`]). A peer that never answers therefore
//! holds bounded memory for bounded time.

use core::error::Error;
use core::fmt;
use core::future::pending;
use core::mem;
use core::num::NonZeroUsize;
use core::pin::pin;
use core::time::Duration;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use der::Encode;
use tightbeam::clock::Timer;
use tightbeam::constants::{DEFAULT_OPERATION_TIMEOUT, MAX_MUX_CONNECTION_REASSEMBLY_BYTES};
use tightbeam::policy::SessionContext;
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::{Frame, TightBeamError};
use tightbeam_ws::serve::{RacingClock, ServedMux};
use tokio::sync::oneshot::{self, Receiver, Sender};
use tokio::sync::Notify;
use tokio::task::AbortHandle;

use crate::audit::ConnectionAudit;
use crate::backplane::{Backplane, BackplaneFault, DeliverError, Local, NodeSink, UpdateSink};
use crate::emit::{Emitter, LinkLost, Settled};
use crate::policy::{DeliveryPolicy, DeliveryVerdict, DropOldest};
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

/// One registered connection, allocated when
/// [`PubsubCommands::serve`](crate::PubsubCommands::serve) admits a served
/// connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(u64);

/// One live subscription, allocated by [`TopicRegistry::register`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubscriberId(u64);

/// How long one update may take to leave for its subscriber.
///
/// The span is above zero, because no emit finishes in zero time. The
/// default is [`DEFAULT_OPERATION_TIMEOUT`], the deadline of one write on an
/// established tightbeam session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmitDeadline(Duration);

impl EmitDeadline {
	/// A deadline of `span`, or `None` for a zero span.
	#[must_use]
	pub const fn new(span: Duration) -> Option<Self> {
		if span.is_zero() {
			return None;
		}

		Some(Self(span))
	}
}

impl Default for EmitDeadline {
	fn default() -> Self {
		Self(DEFAULT_OPERATION_TIMEOUT)
	}
}

/// Registry construction knobs.
pub struct RegistryOptions {
	/// Bounded queue length per subscriber.
	pub queue_capacity: NonZeroUsize,
	/// Cap on live subscriptions one connection may hold.
	///
	/// A new `sub/` for a topic the connection does not already hold is
	/// refused once this many subscriptions are live. Re-subscribe of an
	/// existing topic stays idempotent and does not count again.
	pub max_subscriptions_per_connection: NonZeroUsize,
	/// Payload octets one connection may hold queued or in flight, across
	/// every subscription it holds.
	///
	/// An update that does not fit counts as a full queue, so the delivery
	/// policy decides its fate. The default is
	/// [`MAX_MUX_CONNECTION_REASSEMBLY_BYTES`], the reassembly ceiling of one
	/// tightbeam connection.
	pub connection_queue_bytes: NonZeroUsize,
	/// How long one update may take to leave. An emit past the deadline ends
	/// the delivery of its subscription.
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
pub enum RegisterError {
	/// The connection id was never registered or already dropped.
	UnknownConnection,
	/// The registry is quiescing: no new subscriptions.
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

/// Why a publish produced no fan-out.
///
/// The registry and every [`Backplane`] answer a publish with this one set,
/// whichever node refused it.
#[derive(Debug)]
pub enum PublishError {
	/// The registry is quiescing, or every node that answered drains.
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

/// The updates one lane holds, and the drain task that serves them.
///
/// The drop aborts the task, so a lane that lets go of its queue has no
/// task left.
struct Queue {
	entries: VecDeque<Queued>,
	/// A popped update is being emitted right now.
	in_flight: bool,
	task: AbortHandle,
}

impl Queue {
	fn new(task: AbortHandle) -> Self {
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

impl Drop for Queue {
	fn drop(&mut self) {
		self.task.abort();
	}
}

/// What one offer of an update to a lane did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Offer {
	/// The update entered the queue.
	Queued,
	/// The queue or the connection byte budget has no room.
	Full,
	/// The lane takes no more updates.
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

	/// End delivery. The queue drops, which aborts the drain task and returns
	/// every reserved octet.
	fn close(&mut self) {
		*self = Self::Closed;
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
	/// Shared with the registry. See [`TopicRegistry::flushed`].
	flush: Arc<Notify>,
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
			flush: Arc::clone(&registry.flush),
			audit: connected.audit.share(),
		});

		let deadline = registry.options.emit_deadline;
		let timer = connected.clock.timer();
		let mut lane = subscriber.lock_lane();
		let drain = Arc::clone(&subscriber).drain(connected.emitter.clone(), timer, deadline);
		let task = tokio::spawn(drain);

		*lane = Lane::Open(Queue::new(task.abort_handle()));
		drop(lane);

		subscriber
	}

	fn lock_lane(&self) -> MutexGuard<'_, Lane> {
		self.lane.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// Whether updates are still queued or being emitted.
	fn pending(&self) -> bool {
		self.lock_lane().pending()
	}

	/// End delivery, whatever the drain task is doing.
	fn close(&self) {
		self.lock_lane().close();
		self.flush.notify_one();
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
		self.lock_lane().finish(end);
		self.notify.notify_one();
	}

	fn count_drop(&self) {
		let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
		self.audit.dropped(&self.topic, dropped);
	}

	/// Queue `update` of `len` payload octets, consulting the delivery policy
	/// when the lane or the connection budget is full.
	///
	/// The policy of `registry` runs with no registry lock held, on a
	/// [`RegistryView`] of it. `DropOldest` evicts one queued update and
	/// offers once more, and a second refusal drops the new update as
	/// `DropNew` does.
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
				let evicted = self.lock_lane().evict_oldest();
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
		let offered = self.lock_lane().offer(update, len, &self.budget, capacity);
		if offered == Offer::Queued {
			self.notify.notify_one();
		}

		offered
	}

	/// Count the update in flight as gone, and wake
	/// [`TopicRegistry::flushed`] once the lane is idle.
	fn settle(&self) {
		let mut lane = self.lock_lane();
		lane.settle();

		let idle = !lane.pending();
		drop(lane);

		if idle {
			self.flush.notify_one();
		}
	}

	/// Emit queued updates in order until the lane closes.
	///
	/// The lane counts the popped update in flight until its emit settles,
	/// so an idle lane at [`TopicRegistry::flushed`] means every update left.
	///
	/// Every emit runs under `deadline` on `timer`, which reads the clock of
	/// the link. The task holds a [`Retirement`], which retires the
	/// subscription on every exit.
	async fn drain(self: Arc<Self>, emitter: Emitter, mut timer: Timer, deadline: EmitDeadline) {
		let _retirement = Retirement(Arc::clone(&self));

		loop {
			let step = self.lock_lane().next_step();
			match step {
				Step::Emit(queued) => {
					let delivered = self.deliver(&emitter, &queued.update, deadline, &mut timer).await;
					drop(queued);

					let Ok(()) = delivered else {
						return;
					};

					self.settle();
				}
				Step::End(end) => {
					// Best effort: the topic completes either way.
					let _ = self.deliver(&emitter, &end, deadline, &mut timer).await;
					return;
				}
				Step::Wait => self.notify.notified().await,
				Step::Stop => return,
			}
		}
	}

	/// Emit one update before `deadline` passes on `timer`.
	///
	/// # Errors
	///
	/// - [`LinkLost`]: the deadline passed, or [`emit`](Self::emit) lost the link.
	async fn deliver(
		&self,
		emitter: &Emitter,
		update: &Frame,
		deadline: EmitDeadline,
		timer: &mut Timer,
	) -> Result<(), LinkLost> {
		let emitted = pin!(self.emit(emitter, update));
		let bounded = timer.within(deadline.0, emitted).await;
		bounded.unwrap_or_else(|lapse| Err(LinkLost::lapsed(lapse)))
	}

	/// Emit one update, and count it dropped when the emit settles as
	/// [`Settled::Refused`].
	///
	/// # Errors
	///
	/// - [`LinkLost`]: the emit counts as the end of the link, which ends the lane.
	async fn emit(&self, emitter: &Emitter, update: &Frame) -> Result<(), LinkLost> {
		let settled = emitter.until_settled(update).await?;
		if let Settled::Refused(_) = settled {
			self.count_drop();
		}

		Ok(())
	}
}

/// The hold of a drain task on its subscriber. The drop retires the
/// subscription, whichever way the task ends.
///
/// A retirement after the subscription already left does nothing, because
/// the registry matches the id of the subscription it removes.
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

/// Per-connection bookkeeping: the emitter and the clock of its link, the
/// peer its handshake proved, the byte budget its lanes share, the
/// connection's live subscriptions, and the signal that expels it.
struct ConnectionState {
	emitter: Emitter,
	/// The clock of the link under `emitter`, for the emit deadlines.
	clock: RacingClock,
	session: SessionContext,
	budget: Arc<ConnectionBudget>,
	topics: HashMap<Topic, SubscriberId>,
	/// Resolves the [`Membership::expelled`] future of the connection.
	expulsion: Sender<GoAwayReason>,
	/// The audit trail of the connection, which its subscriptions share.
	audit: ConnectionAudit,
}

/// A connection that left the registry, with the count of the subscriptions
/// it held. It records its departure on the audit trail of the connection,
/// which the holder runs once it released the registry lock, so no sink of
/// the trail runs under the lock.
struct Departed {
	connection: ConnectionId,
	state: ConnectionState,
	subscriptions: u64,
}

impl Departed {
	/// Record the departure of a connection whose serve ended.
	fn left(self) {
		self.state.audit.left(self.connection.0, self.subscriptions);
	}

	/// Expel the connection with `reason`, and record the expulsion ahead of
	/// the departure it causes.
	fn expel(self, reason: GoAwayReason) {
		self.state.audit.expelled(reason);
		self.state.audit.left(self.connection.0, self.subscriptions);
		self.state.expel(reason);
	}
}

impl ConnectionState {
	/// Expel this connection with `reason`, the reason its served connection
	/// drains with.
	///
	/// A membership that already left reads no reason, so its connection has
	/// nothing to drain.
	fn expel(self, reason: GoAwayReason) {
		let _ = self.expulsion.send(reason);
	}

	/// The subscription this connection already holds for `topic`, or `None`
	/// when a new one fits under `cap` live subscriptions.
	///
	/// A held topic answers its id, so a repeated `sub/` stays idempotent and
	/// takes no second seat.
	///
	/// # Errors
	///
	/// - [`RegisterError::LimitReached`]: `topic` is new, and the connection holds `cap`
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
}

#[derive(Default)]
struct State {
	topics: HashMap<Topic, TopicState>,
	connections: HashMap<ConnectionId, ConnectionState>,
	subscribers: HashMap<SubscriberId, Arc<Subscriber>>,
}

impl State {
	/// Subscribe `connection` to `topic` under the options of `registry`, or
	/// return the subscription the connection already holds.
	///
	/// A new subscription enters the connection, the subscriber map, and the
	/// member set of its topic in one step. [`unsubscribe`](Self::unsubscribe),
	/// [`retire`](Self::retire), and
	/// [`remove_connection`](Self::remove_connection) undo it.
	///
	/// # Errors
	///
	/// - [`RegisterError::UnknownConnection`]: `connection` was never admitted, or it dropped.
	/// - [`RegisterError::LimitReached`]: `topic` is new, and the connection holds its cap of
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

		connected.topics.insert(topic.clone(), id);

		self.subscribers.insert(id, subscriber);
		self.topics.entry(topic).or_default().members.insert(id);

		Ok(id)
	}

	/// End the subscription that `connection` holds for `topic`, through
	/// [`retire`](Self::retire). Returns whether the subscription existed.
	fn unsubscribe(&mut self, connection: ConnectionId, topic: &Topic, registry: &Inner) -> bool {
		let Some(connected) = self.connections.get(&connection) else {
			return false;
		};
		let Some(id) = connected.held(topic) else {
			return false;
		};

		self.retire(connection, topic, id, registry)
	}

	/// End the subscription `id` of `connection` to `topic`, undoing its
	/// [`attach`](Self::attach), while the connection still holds `id` for
	/// `topic` ([`ConnectionState::release`]). Returns whether it ended.
	fn retire(&mut self, connection: ConnectionId, topic: &Topic, id: SubscriberId, registry: &Inner) -> bool {
		let Some(connected) = self.connections.get_mut(&connection) else {
			return false;
		};

		let released = connected.release(topic, id);
		if !released {
			return false;
		}

		self.detach(id, registry);
		true
	}

	/// Forget `connection` and end every subscription it holds, undoing each
	/// [`attach`](Self::attach). Returns its [`Departed`], which records the
	/// departure once the caller releases the registry lock, or `None` when
	/// the connection already left.
	fn remove_connection(&mut self, connection: ConnectionId, registry: &Inner) -> Option<Departed> {
		let mut connected = self.connections.remove(&connection)?;

		let topics = mem::take(&mut connected.topics);
		let subscriptions = u64::try_from(topics.len()).unwrap_or(u64::MAX);
		for id in topics.into_values() {
			self.detach(id, registry);
		}

		Some(Departed { connection, state: connected, subscriptions })
	}

	/// End every subscription, because the registry is gone: close each lane,
	/// which ends its drain task, and report each topic with a member to
	/// `backplane` as vacated.
	fn end_all(&self, backplane: &dyn Backplane) {
		for subscriber in self.subscribers.values() {
			subscriber.close();
		}

		for topic in self.topics.keys() {
			backplane.vacated(topic);
		}
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
	/// topic, and end its delivery. The caller already removed it from its
	/// connection.
	///
	/// A topic that loses its last member here is reported to the backplane
	/// of `registry` as vacated.
	fn detach(&mut self, id: SubscriberId, registry: &Inner) {
		let Some(subscriber) = self.subscribers.remove(&id) else {
			return;
		};
		if let Some(entry) = self.topics.get_mut(&subscriber.topic) {
			entry.members.remove(&id);
			/*
			 * Prune the emptied topic so churn over unique names never grows
			 * the map without bound. The backplane keeps the order counter.
			 */
			if entry.members.is_empty() {
				self.topics.remove(&subscriber.topic);
				registry.options.backplane.vacated(&subscriber.topic);
			}
		}

		subscriber.close();
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
	/// Every topic of the drain queued its `end/<topic>`.
	Drained,
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
			_ => DrainPhase::Drained,
		}
	}

	/// Store `phase` under the drain guard `held`.
	fn store(&self, phase: DrainPhase, _held: &DrainGuard<'_>) {
		self.0.store(phase as u8, Ordering::Release);
	}
}

/// The hold of one quiesce on the drain, from
/// [`begin_drain`](TopicRegistry::begin_drain) until its saga finishes or
/// unwinds. A second quiesce waits on the same lock, so it reads the phase
/// that the first one left.
struct DrainGuard<'a> {
	phase: &'a AtomicDrainPhase,
	_turn: MutexGuard<'a, ()>,
}

impl DrainGuard<'_> {
	/// Store `phase` under this guard.
	fn store(&self, phase: DrainPhase) {
		self.phase.store(phase, self);
	}

	/// Cancel the drain, so the registry takes subscriptions and publishes
	/// again, and a later quiesce starts over.
	fn cancel(&self) {
		self.store(DrainPhase::Live);
	}
}

/// A drain that unwinds or drops before it finishes cancels, so a panic in
/// the saga leaves the registry live.
impl Drop for DrainGuard<'_> {
	fn drop(&mut self) {
		let phase = self.phase.load();
		if phase == DrainPhase::Draining {
			self.cancel();
		}
	}
}

/// The first step of the quiesce saga: a drain in flight, which holds the
/// drain guard and the topic set it froze.
#[must_use = "a drain builds its end frames, or its drop cancels it"]
struct Draining<'a> {
	registry: &'a Inner,
	guard: DrainGuard<'a>,
	topics: Vec<Topic>,
}

impl<'a> Draining<'a> {
	/// Build the `end/<topic>` of every frozen topic at its last order.
	///
	/// The orders are read with no registry lock held, because [`Local`]
	/// holds its lock while it delivers into the registry.
	///
	/// # Errors
	///
	/// - [`TightBeamError`]: an end frame failed to encode. The drain cancels before the error
	///   returns.
	fn end_frames(self) -> Result<Ended<'a>, TightBeamError> {
		self.end_frames_by(Topic::end_frame)
	}

	/// As [`end_frames`](Self::end_frames), with each end frame built by
	/// `encode`.
	///
	/// A test drives the cancel through `encode`, because every topic and
	/// order build an end frame.
	///
	/// # Errors
	///
	/// - The error of `encode`. The drain cancels before the error returns.
	fn end_frames_by<E>(self, encode: E) -> Result<Ended<'a>, TightBeamError>
	where
		E: Fn(&Topic, u64) -> Result<Frame, TightBeamError>,
	{
		let backplane = &self.registry.options.backplane;

		let mut ends = Vec::with_capacity(self.topics.len());
		for topic in self.topics {
			let order = backplane.last_order(&topic);
			let built = encode(&topic, order);
			let end = match built {
				Ok(end) => end,
				Err(cause) => {
					self.guard.cancel();
					return Err(cause);
				}
			};

			ends.push((topic, Arc::new(end)));
		}

		let ended = Ended { registry: self.registry, guard: self.guard, ends };
		Ok(ended)
	}
}

/// The last step of the quiesce saga: a drain whose end frames all built,
/// which holds the drain guard until [`finish`](Self::finish) queues them.
#[must_use = "an ended drain queues its end frames, or its drop cancels it"]
struct Ended<'a> {
	registry: &'a Inner,
	guard: DrainGuard<'a>,
	ends: Vec<(Topic, Arc<Frame>)>,
}

impl Ended<'_> {
	/// Queue the end frame of each topic behind every update its members
	/// hold, and mark the registry drained. Returns how many subscribers were
	/// signaled.
	fn finish(self) -> usize {
		let state = self.registry.lock_state();

		let mut signaled = 0;
		for (topic, end) in &self.ends {
			for subscriber in state.members(topic) {
				subscriber.finish(end);
				signaled += 1;
			}
		}

		self.guard.store(DrainPhase::Drained);
		signaled
	}
}

/// The shared state behind every clone of a [`TopicRegistry`].
///
/// Locks nest in one order on every path: `drain`, then the lock of the
/// backplane, then `state`.
struct Inner {
	options: RegistryOptions,
	/// The drain guard. One quiesce holds it for its whole saga, so a second
	/// quiesce waits for the outcome of the first.
	drain: Mutex<()>,
	/// The drain phase, which `register`, `deliver`, `publish`, and
	/// [`RegistryView::is_draining`] read without a lock.
	phase: AtomicDrainPhase,
	next_connection: AtomicU64,
	next_subscriber: AtomicU64,
	state: Mutex<State>,
	/// Signaled whenever a lane goes idle or closes. See
	/// [`TopicRegistry::flushed`].
	flush: Arc<Notify>,
}

/// Topic fan-out over multiplexed tightbeam connections.
///
/// Clone-cheap: clones share the same registry. When the last clone drops,
/// every subscription ends and its delivery task stops. The reads live on
/// the [`RegistryView`] of [`view`](Self::view).
#[derive(Clone)]
pub struct TopicRegistry {
	inner: Arc<Inner>,
}

impl Default for TopicRegistry {
	fn default() -> Self {
		Self::new(RegistryOptions::default())
	}
}

/// A borrowed view of a [`TopicRegistry`], for the reads a policy weighs.
///
/// The registry lends a view into each policy callback. A view lives only
/// as long as that call and offers no way to own the registry, so a policy
/// that the registry holds cannot keep the registry alive.
///
/// # Examples
///
/// ```
/// use tightbeam_pubsub::{Topic, TopicRegistry};
///
/// let registry = TopicRegistry::default();
/// let view = registry.view();
/// assert_eq!(view.subscriber_count(&Topic::fixture("prices")), 0);
/// assert!(!view.is_draining());
/// ```
#[derive(Clone, Copy)]
pub struct RegistryView<'a> {
	inner: &'a Inner,
}

impl<'a> RegistryView<'a> {
	fn of(inner: &'a Inner) -> Self {
		Self { inner }
	}

	/// Whether a [`quiesce`](TopicRegistry::quiesce) is in flight or finished,
	/// so the registry refuses subscriptions and publishes.
	#[must_use]
	pub fn is_draining(&self) -> bool {
		let phase = self.inner.phase.load();
		phase != DrainPhase::Live
	}

	/// The peer that the handshake of `connection` proved, while the
	/// connection is registered.
	///
	/// A connection that left, or that the registry never admitted, has no
	/// standing and answers `None`, so a revoked caller never reads as an
	/// anonymous one. An anonymous connection answers a session with no peer
	/// certificate.
	#[must_use]
	pub fn session(&self, connection: ConnectionId) -> Option<SessionContext> {
		let state = self.inner.lock_state();
		let connected = state.connections.get(&connection)?;
		Some(connected.session.clone())
	}

	/// Updates dropped so far for `subscriber`, or `None` once it is gone.
	#[must_use]
	pub fn dropped(&self, subscriber: SubscriberId) -> Option<u64> {
		let state = self.inner.lock_state();
		let counter = &state.subscribers.get(&subscriber)?.dropped;
		Some(counter.load(Ordering::Relaxed))
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
			drain: Mutex::new(()),
			phase: AtomicDrainPhase::new(),
			next_connection: AtomicU64::new(1),
			next_subscriber: AtomicU64::new(1),
			state: Mutex::new(State::default()),
			flush: Arc::new(Notify::new()),
		});

		let sink = NodeSink::from(&inner);
		inner.options.backplane.attach(sink);

		Self { inner }
	}

	fn lock_state(&self) -> MutexGuard<'_, State> {
		self.inner.lock_state()
	}

	/// A share of the audit trail of `connection`, which records nothing for
	/// a connection that left or was never admitted.
	pub(crate) fn audit_of(&self, connection: ConnectionId) -> ConnectionAudit {
		let state = self.lock_state();
		let connected = state.connections.get(&connection);
		connected.map(|connected| connected.audit.share()).unwrap_or_default()
	}

	/// The reads of this registry, as a [`RegistryView`].
	#[must_use]
	pub fn view(&self) -> RegistryView<'_> {
		RegistryView::of(&self.inner)
	}

	/// Admit `served`, yielding the [`Membership`] its subscriptions hang off.
	///
	/// The connection registers under the peer its handshake proved, so the
	/// policies authorize the authenticated caller. Every emit of its
	/// subscriptions runs its deadline on the clock of its writer.
	pub(crate) fn admit(&self, served: &ServedMux) -> Membership {
		let id = ConnectionId(self.inner.next_connection.fetch_add(1, Ordering::Relaxed));
		let budget = ConnectionBudget::new(self.inner.options.connection_queue_bytes);
		let (expulsion, expelled) = oneshot::channel();

		let emitter = Emitter::from(served.handle().clone());
		let clock = served.clock().clone();
		let session = served.session().clone();
		let audit = ConnectionAudit::of(served);
		audit.admitted(id.0);

		let topics = HashMap::new();
		let connection = ConnectionState { emitter, clock, session, budget, topics, expulsion, audit };

		self.lock_state().connections.insert(id, connection);

		let registry = Arc::downgrade(&self.inner);
		Membership { registry, connection: id, expelled }
	}

	/// Subscribe `connection` to `topic`, spawning its delivery task.
	///
	/// Idempotent per connection and topic: re-subscribing returns the
	/// existing id. MUST be called within a tokio runtime.
	///
	/// # Errors
	///
	/// - [`RegisterError::Draining`]: a [`quiesce`](Self::quiesce) is in flight or finished.
	/// - [`RegisterError::UnknownConnection`]: `connection` was never admitted.
	/// - [`RegisterError::LimitReached`]: the connection already holds
	///   [`RegistryOptions::max_subscriptions_per_connection`] subscriptions.
	pub fn register(&self, connection: ConnectionId, topic: Topic) -> Result<SubscriberId, RegisterError> {
		let mut state = self.lock_state();
		/*
		 * Checked under the state lock: a drain stores its phase before it
		 * freezes the topic set under the same lock, so a subscriber that
		 * enters before the freeze is in the set, and every later one
		 * refuses.
		 */
		if self.view().is_draining() {
			return Err(RegisterError::Draining);
		}

		state.attach(connection, topic, &self.inner)
	}

	/// Drop `connection`'s subscription to `topic`.
	///
	/// Returns whether a subscription existed. Idempotent: a repeat (or a
	/// never-subscribed topic) is `false`, not an error.
	pub fn unregister(&self, connection: ConnectionId, topic: &Topic) -> bool {
		let mut state = self.lock_state();
		state.unsubscribe(connection, topic, &self.inner)
	}

	/// Publish `payload` to every subscriber of `topic`, through the backplane.
	///
	/// The backplane assigns the dense per-topic stamp and distributes to
	/// every attached node. Each node builds the update frame (id =
	/// topic) and fans out locally. The stamp advances even with no
	/// subscribers, so late subscribers observe continuity.
	///
	/// # Errors
	///
	/// - [`PublishError::Draining`]: the registry is quiescing, or every node drains.
	/// - [`PublishError::Build`]: a node could not encode the update frame.
	/// - [`PublishError::TopicLimit`]: `topic` is new, and the backplane has no room for its counter.
	/// - [`PublishError::Unavailable`]: the distribution fabric of the backplane failed.
	pub fn publish(&self, topic: &Topic, payload: impl AsRef<[u8]>) -> Result<(), PublishError> {
		/*
		 * Fast-fail only: deliver reads the phase again for each node, so a
		 * racing quiesce still refuses the update.
		 */
		if self.view().is_draining() {
			return Err(PublishError::Draining);
		}

		let payload = payload.as_ref();
		self.inner.options.backplane.publish(topic, payload)
	}

	/// Publish a full tightbeam frame as `topic`'s payload: frame in
	/// frame, the transport-envelope pattern one level up.
	///
	/// The inner frame travels byte-for-byte inside the update wrapper
	/// the registry builds, so everything the publisher applied survives
	/// the relay end to end: signature, witness, message commitment,
	/// encrypted or compressed body, priority, lifetime, and the
	/// `previous_frame` chain. The registry stamps only its wrapper
	/// (`metadata.id` = topic, `metadata.order` = dense sequence) and
	/// never reads the inner frame. Subscribers lift the payload and
	/// decode it as a frame (the TypeScript client's `Framed` codec).
	///
	/// # Errors
	///
	/// Same set as [`publish`](Self::publish). Encoding `inner` to DER
	/// surfaces as [`PublishError::Build`].
	pub fn publish_frame(&self, topic: &Topic, inner: &Frame) -> Result<(), PublishError> {
		let payload = inner.to_der().map_err(TightBeamError::from)?;
		self.publish(topic, payload)
	}

	/// Complete every topic: push `end/<topic>` to every subscriber and
	/// refuse new subscriptions and publishes from now on.
	///
	/// Returns how many subscribers were signaled. Idempotent: a repeat
	/// signals nobody. The caller follows with the transport drain
	/// (`shutdown_with(GoAwayReason::Shutdown)` per connection).
	///
	/// A quiesce that meets another in flight waits for its outcome. It
	/// answers `Ok(0)` once that drain finished, and runs its own drain when
	/// that one cancelled, so `Ok` means every `end/<topic>` is queued.
	///
	/// Each `end/<topic>` carries the [`Backplane::last_order`] of its
	/// topic, the order of the last update the topic accepted. Completion
	/// therefore burns no order, and every other node on the backplane keeps
	/// a dense sequence. The orders are read with no registry lock held,
	/// because [`Local`] holds its lock while it delivers into the registry.
	///
	/// # Errors
	///
	/// - [`TightBeamError`]: an `end/<topic>` frame failed to encode. The drain cancels, so the
	///   registry takes subscriptions and publishes again, and a later quiesce starts over.
	pub fn quiesce(&self) -> Result<usize, TightBeamError> {
		let Some(draining) = self.begin_drain() else {
			return Ok(0);
		};

		let ended = draining.end_frames()?;
		let signaled = ended.finish();
		Ok(signaled)
	}

	/// Begin a drain: take the drain guard, refuse subscriptions and
	/// publishes from now on, and freeze the topic set. Answers `None` when an
	/// earlier drain finished.
	///
	/// The call waits for the guard, so a drain in flight settles first. A
	/// guard that a panic poisoned is recovered and its phase reset to
	/// [`Live`](DrainPhase::Live), so the drain starts over.
	fn begin_drain(&self) -> Option<Draining<'_>> {
		let inner = &*self.inner;
		let locked = inner.drain.lock();
		let poisoned = locked.is_err();
		let turn = locked.unwrap_or_else(PoisonError::into_inner);

		let guard = DrainGuard { phase: &inner.phase, _turn: turn };
		if poisoned {
			inner.drain.clear_poison();
			guard.cancel();
		}

		let phase = inner.phase.load();
		if phase == DrainPhase::Drained {
			return None;
		}

		guard.store(DrainPhase::Draining);
		let topics: Vec<Topic> = self.lock_state().topics.keys().cloned().collect();

		let draining = Draining { registry: inner, guard, topics };
		Some(draining)
	}

	/// Wait until every live subscriber queue has emptied.
	///
	/// After [`quiesce`](Self::quiesce) this means every `end/<topic>`
	/// push has left, so the caller can drain the transport without
	/// racing the completion signals.
	pub async fn flushed(&self) {
		loop {
			let pending = {
				let state = self.lock_state();
				state.subscribers.values().any(|subscriber| subscriber.pending())
			};
			if !pending {
				return;
			}

			self.inner.flush.notified().await;
		}
	}
}

impl Inner {
	fn lock_state(&self) -> MutexGuard<'_, State> {
		self.state.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// Forget `connection`, drop every subscription it holds, and record its
	/// departure once the registry lock is released.
	fn leave(&self, connection: ConnectionId) {
		let departed = self.lock_state().remove_connection(connection, self);
		if let Some(departed) = departed {
			departed.left();
		}
	}

	/// End the subscription `id` of `connection` to `topic`, unless a newer
	/// subscription already took its place. See [`State::retire`].
	fn retire(&self, connection: ConnectionId, topic: &Topic, id: SubscriberId) {
		let mut state = self.lock_state();
		state.retire(connection, topic, id, self);
	}

	/// Drop a connection the delivery policy voted off, and resolve its
	/// [`Membership::expelled`] future, so its served connection drains with
	/// an orderly GoAway instead of a silent stall.
	///
	/// The connection drains with `EnhanceYourCalm`, the analog for a
	/// load-generating peer that cannot keep pace with delivery.
	///
	/// # Sources
	///
	/// - RFC 9113 § 7, GOAWAY frame:
	///   <https://datatracker.ietf.org/doc/html/rfc9113#section-7>
	fn expel(&self, connection: ConnectionId) {
		let removed = self.lock_state().remove_connection(connection, self);
		let Some(expelled) = removed else {
			return;
		};

		expelled.expel(GoAwayReason::EnhanceYourCalm);
	}

	/// Offer `update` of `len` payload octets to each member of a snapshot,
	/// with no registry lock held, and expel every connection the delivery
	/// policy votes off.
	fn fan_out(&self, members: &[Arc<Subscriber>], update: &Arc<Frame>, len: usize) {
		let mut doomed = Vec::new();
		for subscriber in members {
			let admission = subscriber.admit(update, len, self);
			if admission == Admission::Disconnect {
				doomed.push(subscriber.connection);
			}
		}

		for connection in doomed {
			self.expel(connection);
		}
	}
}

impl UpdateSink for Inner {
	/// One backplane-sequenced update lands on this node: build the wire
	/// frame at the assigned order and fan out to the local members.
	fn deliver(&self, topic: &Topic, order: u64, payload: &[u8]) -> Result<(), DeliverError> {
		/*
		 * A drain stores its phase before it reads any last order, and the
		 * backplane answers a last order only after every delivery in flight
		 * returned. Every delivery the drain counts therefore lands before
		 * its end/, and every later one refuses here.
		 */
		if RegistryView::of(self).is_draining() {
			return Err(DeliverError::Draining);
		}

		let members = self.lock_state().members(topic);

		let update = Arc::new(topic.update_frame(order, payload)?);
		self.fan_out(&members, &update, payload.len());

		Ok(())
	}

	/// A topic is live while its member set holds a subscriber.
	fn has_members(&self, topic: &Topic) -> bool {
		let state = self.lock_state();
		let entry = state.topics.get(topic);
		entry.is_some_and(|entry| !entry.members.is_empty())
	}
}

impl Drop for Inner {
	/// The last registry handle is gone. A drain task holds only its
	/// subscriber, so every lane closes here to end its task.
	fn drop(&mut self) {
		let state = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
		state.end_all(self.options.backplane.as_ref());
	}
}

/// The registration of one served connection.
///
/// The drop leaves the registry and ends every subscription of the
/// connection, so a serve that completes or drops leaves no registration
/// behind. [`expelled`](Self::expelled) is the one signal of a connection the
/// delivery policy voted off.
pub(crate) struct Membership {
	/// Held weakly, so the registry drops while its connections serve.
	registry: Weak<Inner>,
	connection: ConnectionId,
	expelled: Receiver<GoAwayReason>,
}

impl Membership {
	/// The registry id this connection's subscriptions hang off.
	pub(crate) fn connection(&self) -> ConnectionId {
		self.connection
	}

	/// Resolve with the reason the registry expels this connection for.
	///
	/// The registry that drops, or that forgets the connection, drops the
	/// signal unsent. A dropped signal stays pending, so it never drains a
	/// served connection.
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
		if let Some(registry) = self.registry.upgrade() {
			registry.leave(self.connection);
		}
	}
}

#[cfg(test)]
mod tests {
	use std::panic::{catch_unwind, AssertUnwindSafe};
	use std::sync::atomic::AtomicBool;
	use std::sync::OnceLock;

	use der::{Error as DerError, ErrorKind};
	use tightbeam::clock::{Clock, ManualClock};
	use tightbeam::policy::TransitStatus;
	use tightbeam::transport::handshake::negotiation::MuxSettings;
	use tightbeam::transport::multiplex::{MuxDispatch, SpawnedMux};
	use tightbeam::transport::{ResponsePackage, TransportResult};
	use tokio::task::{spawn_blocking, yield_now};
	use tokio::time::{sleep, timeout};

	use super::*;
	use crate::testing::{MemoryLink, OpaqueFrame};

	/// Bound every wait on a live link, so a regression fails instead of
	/// hanging.
	const DEADLINE: Duration = Duration::from_secs(2);

	fn count(value: usize) -> NonZeroUsize {
		NonZeroUsize::new(value).expect("test counts should be above zero")
	}

	fn deadline(span: Duration) -> EmitDeadline {
		EmitDeadline::new(span).expect("test deadlines should be above zero")
	}

	/// Subscribe `connection` to `name`, expecting acceptance.
	fn subscribed(registry: &TopicRegistry, connection: ConnectionId, name: &str) -> SubscriberId {
		let topic = Topic::fixture(name);
		registry
			.register(connection, topic)
			.expect("the registration should be accepted")
	}

	/// Publish `payload` to `name`, expecting acceptance.
	fn published(registry: &TopicRegistry, name: &str, payload: &[u8]) {
		let topic = Topic::fixture(name);
		registry.publish(&topic, payload).expect("the publish should be accepted");
	}

	/// Quiesce the registry, expecting the signaled subscriber count.
	fn quiesced(registry: &TopicRegistry) -> usize {
		registry.quiesce().expect("quiesce should succeed")
	}

	/// The last order the registry's backplane committed for `name`.
	fn last_order(registry: &TopicRegistry, name: &str) -> u64 {
		registry.inner.options.backplane.last_order(&Topic::fixture(name))
	}

	/// One served end of an in-memory link under `settings`, and the client
	/// end beside it, spawned with its responder unserved.
	fn served_over(link: &MemoryLink, settings: MuxSettings) -> (ServedMux, SpawnedMux) {
		let linked = link.served(settings);
		let (client, server) = linked.expect("a test link races on a tokio thread");
		(server.spawn(), client.spawn())
	}

	/// A registry with one admitted in-memory connection, whose peer reads
	/// nothing. The returned guard keeps the registration and the peer alive.
	fn registered(options: RegistryOptions) -> (TopicRegistry, ConnectionId, impl Sized) {
		let link = MemoryLink::default();
		let linked = link.served(MuxSettings::symmetric(4));
		let (client, server) = linked.expect("a test link races on a tokio thread");
		let served = server.spawn();

		let registry = TopicRegistry::new(options);
		let membership = registry.admit(&served);
		let connection = membership.connection();
		(registry, connection, (membership, served, client))
	}

	/// A registry with one registered connection over a live link on the
	/// system clock whose peer takes each update and answers none. The
	/// returned guard keeps the peer alive.
	fn stalled(options: RegistryOptions) -> (TopicRegistry, ConnectionId, impl Sized) {
		stalled_on(options, MemoryLink::default())
	}

	/// As [`stalled`], over `link`.
	fn stalled_on(options: RegistryOptions, link: MemoryLink) -> (TopicRegistry, ConnectionId, impl Sized) {
		let (served, client) = served_over(&link, MuxSettings::symmetric(4));

		let registry = TopicRegistry::new(options);
		let membership = registry.admit(&served);
		let connection = membership.connection();
		(registry, connection, (membership, served, client))
	}

	/// A registry under `options` with one registered connection over a live
	/// link under `settings`, whose peer answers every update with `status`.
	/// The returned guard keeps the peer alive.
	fn answering(
		options: RegistryOptions,
		settings: MuxSettings,
		status: TransitStatus,
	) -> (TopicRegistry, ConnectionId, impl Sized) {
		let link = MemoryLink::default();
		let (served, client) = served_over(&link, settings);
		let SpawnedMux { handle, responder, drivers } = client;

		let answer = move |_| async move { ResponsePackage::new(status, None) };
		let answering = tokio::spawn(responder.serve(answer));

		let registry = TopicRegistry::new(options);
		let membership = registry.admit(&served);
		let connection = membership.connection();
		(
			registry,
			connection,
			(membership, served, handle, drivers, answering.abort_handle()),
		)
	}

	/// Wait until every lane of `registry` is idle, expecting it within the
	/// deadline.
	async fn settled(registry: &TopicRegistry) {
		let flushed = timeout(DEADLINE, registry.flushed()).await;
		flushed.expect("every lane should go idle");
	}

	#[tokio::test]
	async fn register_is_idempotent_per_connection_and_topic() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());

		let first = subscribed(&registry, connection, "prices");
		let second = subscribed(&registry, connection, "prices");
		assert_eq!(first, second);
		assert_eq!(registry.view().subscriber_count(&Topic::fixture("prices")), 1);
	}

	#[tokio::test]
	async fn register_refuses_past_the_per_connection_subscription_cap() {
		let options = RegistryOptions { max_subscriptions_per_connection: count(2), ..RegistryOptions::default() };
		let (registry, connection, _peer) = registered(options);

		let first = subscribed(&registry, connection, "a");
		subscribed(&registry, connection, "b");

		let refused = registry.register(connection, Topic::fixture("c"));
		assert_eq!(refused, Err(RegisterError::LimitReached));
		assert_eq!(subscribed(&registry, connection, "a"), first);

		registry.unregister(connection, &Topic::fixture("a"));

		subscribed(&registry, connection, "c");
		assert_eq!(registry.view().subscriber_count(&Topic::fixture("c")), 1);
	}

	#[tokio::test]
	async fn register_requires_a_known_connection() {
		let (registry, connection, peer) = registered(RegistryOptions::default());

		drop(peer);

		let outcome = registry.register(connection, Topic::fixture("prices"));
		assert_eq!(outcome, Err(RegisterError::UnknownConnection));
	}

	#[tokio::test]
	async fn a_session_requires_a_live_registration() {
		let (registry, connection, peer) = registered(RegistryOptions::default());
		let member = registry.view().session(connection);

		drop(peer);

		let left = registry.view().session(connection);
		assert!(member.is_some());
		assert!(left.is_none());
	}

	#[tokio::test]
	async fn unregister_prunes_the_emptied_topic() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());
		subscribed(&registry, connection, "prices");

		registry.unregister(connection, &Topic::fixture("prices"));

		let state = registry.lock_state();
		assert!(!state.topics.contains_key(&Topic::fixture("prices")));
	}

	#[tokio::test]
	async fn unregister_forgets_the_membership() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());

		subscribed(&registry, connection, "prices");

		let removed = registry.unregister(connection, &Topic::fixture("prices"));
		let repeat = registry.unregister(connection, &Topic::fixture("prices"));
		assert!(removed);
		assert!(!repeat);
		assert_eq!(registry.view().subscriber_count(&Topic::fixture("prices")), 0);
	}

	#[tokio::test]
	async fn a_dropped_membership_forgets_every_subscription() {
		let (registry, connection, peer) = registered(RegistryOptions::default());
		subscribed(&registry, connection, "prices");
		subscribed(&registry, connection, "chat");

		drop(peer);

		assert_eq!(registry.view().subscriber_count(&Topic::fixture("prices")), 0);
		assert_eq!(registry.view().subscriber_count(&Topic::fixture("chat")), 0);
	}

	/// Yield until the last strong reference behind `subscriber` is gone,
	/// or give up.
	async fn released(subscriber: &Weak<Subscriber>) -> bool {
		for _ in 0..64 {
			if subscriber.strong_count() == 0 {
				return true;
			}

			yield_now().await;
		}

		false
	}

	#[tokio::test]
	async fn a_dropped_membership_ends_a_drain_task_parked_in_an_emit() {
		let (registry, connection, peer) = stalled(RegistryOptions::default());
		let id = subscribed(&registry, connection, "prices");
		published(&registry, "prices", b"tick");
		yield_now().await;
		let subscriber = Arc::downgrade(&registry.lock_state().subscribers[&id]);

		drop(peer);

		assert!(released(&subscriber).await);
	}

	#[tokio::test]
	async fn a_dropped_registry_ends_every_drain_task() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());
		let id = subscribed(&registry, connection, "prices");
		let subscriber = Arc::downgrade(&registry.lock_state().subscribers[&id]);

		drop(registry);

		assert!(released(&subscriber).await);
	}

	#[tokio::test]
	async fn publish_to_a_memberless_topic_retains_no_state() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());
		published(&registry, "silence", b"tick");
		published(&registry, "silence", b"tock");

		{
			let state = registry.lock_state();
			assert!(!state.topics.contains_key(&Topic::fixture("silence")));
		}

		/*
		 * The backplane kept the counter: a late subscriber still
		 * observes the continued dense sequence.
		 */
		subscribed(&registry, connection, "silence");
		published(&registry, "silence", b"third");

		assert_eq!(last_order(&registry, "silence"), 3);
	}

	/// Delivery policy returning one fixed verdict.
	struct FixedVerdict(DeliveryVerdict);

	impl DeliveryPolicy for FixedVerdict {
		fn on_full(&self, _registry: RegistryView<'_>, _topic: &Topic, _dropped_so_far: u64) -> DeliveryVerdict {
			self.0
		}
	}

	/// Options of `capacity` queue slots, `bytes` of connection budget, and
	/// one fixed `verdict`.
	fn saturating(capacity: usize, bytes: usize, verdict: DeliveryVerdict) -> RegistryOptions {
		RegistryOptions {
			queue_capacity: count(capacity),
			connection_queue_bytes: count(bytes),
			delivery: Arc::new(FixedVerdict(verdict)),
			..RegistryOptions::default()
		}
	}

	/// A subscriber on `budget` whose lane takes offers and never drains.
	fn parked(budget: &Arc<ConnectionBudget>) -> Subscriber {
		let task = tokio::spawn(pending::<()>());
		let lane = Lane::Open(Queue::new(task.abort_handle()));

		Subscriber {
			id: SubscriberId(1),
			topic: Topic::fixture("prices"),
			connection: ConnectionId(1),
			registry: Weak::new(),
			budget: Arc::clone(budget),
			lane: Mutex::new(lane),
			notify: Notify::new(),
			dropped: AtomicU64::new(0),
			flush: Arc::new(Notify::new()),
			audit: ConnectionAudit::default(),
		}
	}

	/// A subscriber with its own budget under the options of `registry` that
	/// never drains.
	fn parked_under(registry: &TopicRegistry) -> Subscriber {
		let budget = ConnectionBudget::new(registry.inner.options.connection_queue_bytes);
		parked(&budget)
	}

	/// Admit one update per payload to `subscriber` under the options of
	/// `registry`, stamped `1, 2, ...`, returning the last admission.
	fn admitted(subscriber: &Subscriber, registry: &TopicRegistry, payloads: &[&[u8]]) -> Admission {
		let topic = Topic::fixture("prices");
		let mut last = Admission::Settled;
		for (order, payload) in (1..).zip(payloads) {
			let update = topic.update_frame(order, payload).expect("update frames should build");
			last = subscriber.admit(&Arc::new(update), payload.len(), &registry.inner);
		}

		last
	}

	fn queued_orders(subscriber: &Subscriber) -> Vec<u64> {
		let lane = subscriber.lock_lane();
		let Lane::Open(queue) = &*lane else {
			return Vec::new();
		};

		queue.entries.iter().map(|queued| queued.update.metadata().order()).collect()
	}

	fn dropped(subscriber: &Subscriber) -> u64 {
		subscriber.dropped.load(Ordering::Relaxed)
	}

	#[tokio::test]
	async fn admit_drop_oldest_keeps_the_newest_updates() {
		let registry = TopicRegistry::new(saturating(2, 1024, DeliveryVerdict::DropOldest));
		let subscriber = parked_under(&registry);

		admitted(&subscriber, &registry, &[b"tick", b"tick", b"tick"]);

		assert_eq!(queued_orders(&subscriber), [2, 3]);
		assert_eq!(dropped(&subscriber), 1);
	}

	#[tokio::test]
	async fn admit_drop_new_keeps_the_oldest_updates() {
		let registry = TopicRegistry::new(saturating(2, 1024, DeliveryVerdict::DropNew));
		let subscriber = parked_under(&registry);

		admitted(&subscriber, &registry, &[b"tick", b"tick", b"tick"]);

		assert_eq!(queued_orders(&subscriber), [1, 2]);
		assert_eq!(dropped(&subscriber), 1);
	}

	#[tokio::test]
	async fn admit_disconnect_names_the_connection() {
		let registry = TopicRegistry::new(saturating(1, 1024, DeliveryVerdict::Disconnect));
		let subscriber = parked_under(&registry);

		let outcome = admitted(&subscriber, &registry, &[b"tick", b"tick"]);

		assert_eq!(outcome, Admission::Disconnect);
		assert_eq!(queued_orders(&subscriber), [1]);
	}

	#[tokio::test]
	async fn an_update_past_the_byte_budget_counts_as_a_full_queue() {
		let registry = TopicRegistry::new(saturating(32, 8, DeliveryVerdict::DropNew));
		let subscriber = parked_under(&registry);

		admitted(&subscriber, &registry, &[b"123456", b"abcdef"]);

		assert_eq!(queued_orders(&subscriber), [1]);
		assert_eq!(dropped(&subscriber), 1);
	}

	#[tokio::test]
	async fn an_update_that_fills_the_byte_budget_exactly_is_queued() {
		let registry = TopicRegistry::new(saturating(32, 8, DeliveryVerdict::DropNew));
		let subscriber = parked_under(&registry);

		admitted(&subscriber, &registry, &[b"12345678"]);

		assert_eq!(queued_orders(&subscriber), [1]);
		assert_eq!(dropped(&subscriber), 0);
	}

	#[tokio::test]
	async fn drop_oldest_frees_the_byte_budget_for_the_new_update() {
		let registry = TopicRegistry::new(saturating(32, 8, DeliveryVerdict::DropOldest));
		let subscriber = parked_under(&registry);

		admitted(&subscriber, &registry, &[b"123456", b"abcdef"]);

		assert_eq!(queued_orders(&subscriber), [2]);
		assert_eq!(dropped(&subscriber), 1);
	}

	#[tokio::test]
	async fn drop_oldest_drops_the_new_update_when_eviction_frees_too_little() {
		let registry = TopicRegistry::new(saturating(32, 8, DeliveryVerdict::DropOldest));
		let budget = ConnectionBudget::new(registry.inner.options.connection_queue_bytes);
		let holder = parked(&budget);
		let starved = parked(&budget);

		admitted(&holder, &registry, &[b"123456"]);
		admitted(&starved, &registry, &[b"abcdef"]);

		assert_eq!(queued_orders(&starved), Vec::<u64>::new());
		assert_eq!(dropped(&starved), 1);
	}

	#[tokio::test]
	async fn a_closed_lane_returns_its_octets_to_the_budget() {
		let registry = TopicRegistry::new(saturating(32, 8, DeliveryVerdict::DropNew));
		let budget = ConnectionBudget::new(registry.inner.options.connection_queue_bytes);
		let leaving = parked(&budget);
		let staying = parked(&budget);

		admitted(&leaving, &registry, &[b"123456"]);
		leaving.close();
		admitted(&staying, &registry, &[b"abcdef"]);

		assert_eq!(queued_orders(&staying), [1]);
	}

	#[test]
	fn an_emit_deadline_is_above_zero() {
		assert_eq!(EmitDeadline::new(Duration::ZERO), None);
	}

	#[tokio::test(start_paused = true)]
	async fn an_emit_past_the_deadline_ends_its_lane() {
		let options = RegistryOptions { emit_deadline: deadline(Duration::from_secs(5)), ..RegistryOptions::default() };
		let (registry, connection, _peer) = stalled(options);
		let id = subscribed(&registry, connection, "prices");
		let subscriber = Arc::downgrade(&registry.lock_state().subscribers[&id]);

		published(&registry, "prices", b"tick");

		let flushed = timeout(Duration::from_secs(6), registry.flushed()).await;
		assert!(flushed.is_ok());
		assert!(released(&subscriber).await);
	}

	#[tokio::test(start_paused = true)]
	async fn the_emit_deadline_runs_on_the_clock_of_the_link() {
		let clock = Arc::new(ManualClock::default());
		let options = RegistryOptions { emit_deadline: deadline(Duration::from_secs(5)), ..RegistryOptions::default() };
		let (registry, connection, _peer) = stalled_on(options, MemoryLink::new(Arc::clone(&clock) as Arc<dyn Clock>));
		let id = subscribed(&registry, connection, "prices");

		published(&registry, "prices", b"tick");
		sleep(Duration::from_secs(60)).await;

		let before = registry.view().dropped(id);

		clock.advance(Duration::from_secs(6));
		settled(&registry).await;

		assert_eq!(before, Some(0));
		assert_eq!(registry.view().dropped(id), None);
	}

	#[tokio::test(start_paused = true)]
	async fn an_emit_past_the_deadline_unregisters_its_subscription() {
		let options = RegistryOptions { emit_deadline: deadline(Duration::from_secs(5)), ..RegistryOptions::default() };
		let (registry, connection, _peer) = stalled(options);
		let lapsed = subscribed(&registry, connection, "prices");

		published(&registry, "prices", b"tick");

		let flushed = timeout(Duration::from_secs(6), registry.flushed()).await;
		let renewed = subscribed(&registry, connection, "prices");
		assert!(flushed.is_ok());
		assert_eq!(registry.view().dropped(lapsed), None);
		assert_ne!(lapsed, renewed);
	}

	#[tokio::test]
	async fn a_stale_retirement_spares_a_newer_subscription() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());
		let stale = subscribed(&registry, connection, "prices");
		registry.unregister(connection, &Topic::fixture("prices"));

		let fresh = subscribed(&registry, connection, "prices");

		registry.inner.retire(connection, &Topic::fixture("prices"), stale);

		let held = subscribed(&registry, connection, "prices");
		assert_eq!(held, fresh);
		assert_eq!(registry.view().subscriber_count(&Topic::fixture("prices")), 1);
	}

	#[tokio::test]
	async fn a_completed_subscription_leaves_the_registry() {
		let accepting = TransitStatus::Ok;
		let (registry, connection, _peer) = answering(RegistryOptions::default(), MuxSettings::symmetric(4), accepting);
		let id = subscribed(&registry, connection, "prices");

		quiesced(&registry);
		settled(&registry).await;

		assert_eq!(registry.view().dropped(id), None);
	}

	#[tokio::test]
	async fn a_peer_refusal_counts_the_update_and_the_lane_continues() {
		let refusing = TransitStatus::ResourceExhausted;
		let (registry, connection, _peer) = answering(RegistryOptions::default(), MuxSettings::symmetric(4), refusing);
		let id = subscribed(&registry, connection, "prices");

		published(&registry, "prices", b"one");
		published(&registry, "prices", b"two");

		let flushed = timeout(DEADLINE, registry.flushed()).await;
		assert!(flushed.is_ok());
		assert_eq!(registry.view().dropped(id), Some(2));
	}

	#[tokio::test]
	async fn an_update_past_the_session_budget_counts_and_the_lane_continues() {
		let unfunded = MuxSettings::symmetric(4).with_send_budget(Some(0));
		let (registry, connection, _peer) = answering(RegistryOptions::default(), unfunded, TransitStatus::Ok);
		let id = subscribed(&registry, connection, "prices");

		published(&registry, "prices", b"one");
		published(&registry, "prices", b"two");

		let flushed = timeout(DEADLINE, registry.flushed()).await;
		assert!(flushed.is_ok());
		assert_eq!(registry.view().dropped(id), Some(2));
	}

	#[tokio::test]
	async fn a_delivered_update_returns_its_octets_to_the_budget() {
		let options = saturating(32, 8, DeliveryVerdict::DropNew);
		let (registry, connection, _peer) = answering(options, MuxSettings::symmetric(4), TransitStatus::Ok);
		let id = subscribed(&registry, connection, "prices");

		published(&registry, "prices", b"123456");
		settled(&registry).await;
		published(&registry, "prices", b"abcdef");
		settled(&registry).await;

		assert_eq!(registry.view().dropped(id), Some(0));
	}

	#[tokio::test]
	async fn a_counter_whose_last_member_left_makes_room_for_a_new_topic() {
		let backplane: Arc<dyn Backplane> = Arc::new(Local::default().with_max_topics(count(1)));
		let (registry, connection, _peer) = registered(RegistryOptions { backplane, ..RegistryOptions::default() });

		subscribed(&registry, connection, "prices");
		registry.unregister(connection, &Topic::fixture("prices"));
		published(&registry, "prices", b"tick");

		let outcome = registry.publish(&Topic::fixture("chat"), b"hello");
		assert!(outcome.is_ok());
	}

	/// Subscribe `connection` to each of `names` and publish once to each, so
	/// every counted topic of the backplane has a member.
	fn crowded(registry: &TopicRegistry, connection: ConnectionId, names: &[&str]) {
		for name in names {
			subscribed(registry, connection, name);
			published(registry, name, b"tick");
		}
	}

	/// The three topics the topic-limit tests fill a backplane of three with.
	const FULL: [&str; 3] = ["prices", "chat", "news"];

	#[tokio::test]
	async fn a_topic_that_loses_its_last_member_after_a_refusal_makes_room() {
		let backplane: Arc<dyn Backplane> = Arc::new(Local::default().with_max_topics(count(3)));
		let (registry, connection, _peer) = registered(RegistryOptions { backplane, ..RegistryOptions::default() });

		crowded(&registry, connection, &FULL);

		let refused = registry.publish(&Topic::fixture("sports"), b"hello");

		registry.unregister(connection, &Topic::fixture("prices"));

		let outcome = registry.publish(&Topic::fixture("sports"), b"hello");
		assert!(matches!(refused, Err(PublishError::TopicLimit)));
		assert!(outcome.is_ok());
	}

	#[tokio::test]
	async fn a_dropped_registry_reports_each_topic_it_held() {
		let backplane = Arc::new(Local::default().with_max_topics(count(3)));
		let shared = Arc::clone(&backplane) as Arc<dyn Backplane>;
		let options = RegistryOptions { backplane: shared, ..RegistryOptions::default() };
		let (registry, connection, _peer) = registered(options);

		crowded(&registry, connection, &FULL);

		let refused = registry.publish(&Topic::fixture("sports"), b"hello");

		drop(registry);

		let outcome = backplane.publish(&Topic::fixture("sports"), b"hello");
		assert!(matches!(refused, Err(PublishError::TopicLimit)));
		assert!(outcome.is_ok());
	}

	/// A backplane that wraps [`Local`] and lets every vacancy report go.
	struct Forgetful(Local);

	impl Backplane for Forgetful {
		fn attach(&self, sink: NodeSink) {
			self.0.attach(sink);
		}

		fn publish(&self, topic: &Topic, payload: &[u8]) -> Result<(), PublishError> {
			self.0.publish(topic, payload)
		}

		fn last_order(&self, topic: &Topic) -> u64 {
			self.0.last_order(topic)
		}

		fn vacated(&self, _topic: &Topic) {}
	}

	#[tokio::test]
	async fn a_wrapper_that_drops_vacancy_reports_still_frees_counters() {
		let local = Local::default().with_max_topics(count(1));
		let backplane: Arc<dyn Backplane> = Arc::new(Forgetful(local));
		let (registry, connection, _peer) = registered(RegistryOptions { backplane, ..RegistryOptions::default() });

		crowded(&registry, connection, &["prices"]);

		let refused = registry.publish(&Topic::fixture("chat"), b"hello");

		registry.unregister(connection, &Topic::fixture("prices"));

		let outcome = registry.publish(&Topic::fixture("chat"), b"hello");
		assert!(matches!(refused, Err(PublishError::TopicLimit)));
		assert!(outcome.is_ok());
	}

	/// Answers every unary stream with an empty `Ok`.
	struct Accepting;

	impl MuxDispatch for Accepting {
		async fn unary(&self, _frame: Arc<Frame>) -> TransportResult<ResponsePackage> {
			Ok(ResponsePackage::new(TransitStatus::Ok, None))
		}
	}

	#[tokio::test]
	async fn a_dropped_expulsion_sender_never_drains_the_connection() {
		let link = MemoryLink::default();
		let (served, client) = served_over(&link, MuxSettings::symmetric(4));
		let registry = TopicRegistry::default();
		let mut membership = registry.admit(&served);

		drop(registry);

		let serving = tokio::spawn(async move { served.serve(Accepting, membership.expelled()).await });
		let probe = OpaqueFrame { id: "probe", order: 1, payload: b"ping" }.build();
		let probe = probe.expect("the probe builds");
		let emitted = client.handle.emit_on_stream(&probe);
		let answered = timeout(DEADLINE, emitted).await;
		serving.abort();

		assert!(matches!(answered, Ok(Ok(None))));
		assert_eq!(client.handle.goaway_reason(), None);
	}

	/// Reads live membership from inside `on_full`, as a policy that
	/// weighs the audience of a topic does, then drops the new update.
	#[derive(Default)]
	struct Inspecting {
		seen: OnceLock<usize>,
	}

	impl DeliveryPolicy for Inspecting {
		fn on_full(&self, registry: RegistryView<'_>, topic: &Topic, _dropped_so_far: u64) -> DeliveryVerdict {
			let _ = self.seen.set(registry.subscriber_count(topic));
			DeliveryVerdict::DropNew
		}
	}

	/// A fresh [`Inspecting`] policy, and `options` under it.
	fn inspected(options: RegistryOptions) -> (Arc<Inspecting>, RegistryOptions) {
		let policy = Arc::new(Inspecting::default());
		let delivery = Arc::clone(&policy) as Arc<dyn DeliveryPolicy>;
		(policy, RegistryOptions { delivery, ..options })
	}

	#[tokio::test]
	async fn a_registry_drops_while_a_policy_and_a_backplane_are_attached() {
		let (_policy, options) = inspected(RegistryOptions::default());
		let backplane: Arc<dyn Backplane> = Arc::new(Forgetful(Local::default()));
		let (registry, connection, _peer) = registered(RegistryOptions { backplane, ..options });
		let id = subscribed(&registry, connection, "prices");
		let subscriber = Arc::downgrade(&registry.lock_state().subscribers[&id]);

		drop(registry);

		assert!(released(&subscriber).await);
	}

	#[tokio::test]
	async fn a_delivery_policy_may_call_back_into_the_registry() {
		let (policy, options) = inspected(RegistryOptions { queue_capacity: count(1), ..RegistryOptions::default() });
		let (registry, connection, _peer) = stalled(options);
		subscribed(&registry, connection, "prices");
		published(&registry, "prices", b"one");
		yield_now().await;
		published(&registry, "prices", b"two");

		let publisher = registry.clone();
		let full = spawn_blocking(move || publisher.publish(&Topic::fixture("prices"), b"three"));
		let joined = timeout(DEADLINE, full).await;
		assert!(joined.is_ok());
		assert_eq!(policy.seen.get(), Some(&1));
	}

	#[tokio::test]
	async fn publish_stamps_dense_per_topic_orders() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());
		subscribed(&registry, connection, "prices");
		subscribed(&registry, connection, "chat");

		published(&registry, "prices", b"one");
		published(&registry, "prices", b"two");
		published(&registry, "chat", b"hello");

		assert_eq!(last_order(&registry, "prices"), 2);
		assert_eq!(last_order(&registry, "chat"), 1);
	}

	#[tokio::test]
	async fn quiesce_refuses_further_registration_and_publish() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());

		subscribed(&registry, connection, "prices");

		let signaled = quiesced(&registry);
		let again = quiesced(&registry);
		let refused = registry.register(connection, Topic::fixture("chat"));
		let late = registry.publish(&Topic::fixture("prices"), b"tick");
		assert_eq!(signaled, 1);
		assert_eq!(again, 0);
		assert!(matches!(refused, Err(RegisterError::Draining)));
		assert!(matches!(late, Err(PublishError::Draining)));
	}

	#[tokio::test]
	async fn quiesce_burns_no_order() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());
		subscribed(&registry, connection, "prices");
		published(&registry, "prices", b"tick");
		assert_eq!(quiesced(&registry), 1);
		assert_eq!(last_order(&registry, "prices"), 1);
	}

	#[tokio::test]
	async fn quiesce_leaves_sibling_orders_dense() {
		let backplane = Arc::new(Local::default());
		let options = || RegistryOptions {
			backplane: Arc::clone(&backplane) as Arc<dyn Backplane>,
			..RegistryOptions::default()
		};

		let (alpha, alpha_connection, _alpha_peer) = registered(options());
		let (beta, beta_connection, _beta_peer) = registered(options());
		subscribed(&alpha, alpha_connection, "prices");
		subscribed(&beta, beta_connection, "prices");
		published(&alpha, "prices", b"tick");
		assert_eq!(quiesced(&alpha), 1);

		published(&beta, "prices", b"tock");

		assert_eq!(backplane.last_order(&Topic::fixture("prices")), 2);
	}

	#[tokio::test]
	async fn quiesce_and_publish_do_not_deadlock() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());
		subscribed(&registry, connection, "prices");

		let publisher = registry.clone();
		let publish = spawn_blocking(move || {
			for _ in 0..64 {
				let _ = publisher.publish(&Topic::fixture("prices"), b"x");
			}
		});

		yield_now().await;
		assert!(registry.quiesce().is_ok());

		timeout(Duration::from_secs(2), publish)
			.await
			.expect("quiesce and publish must not deadlock")
			.expect("the publisher task must join");
	}

	/// How long a case lets a second quiesce reach a drain in flight before
	/// that drain settles.
	const ARRIVAL: Duration = Duration::from_millis(50);

	/// Begin a drain of `registry`, expecting a live registry.
	fn begun(registry: &TopicRegistry) -> Draining<'_> {
		registry.begin_drain().expect("a live registry should begin its drain")
	}

	/// Refuse every end frame: the fault a case injects, because every topic
	/// and order build one.
	fn refusing(_topic: &Topic, _order: u64) -> Result<Frame, TightBeamError> {
		let encoding = DerError::from(ErrorKind::Failed);
		Err(encoding.into())
	}

	/// Begin a drain of `registry`, and cancel it with a refused end frame.
	fn cancelled(registry: &TopicRegistry) {
		let refused = begun(registry).end_frames_by(refusing);
		refused.err().expect("the refused end frame should cancel the drain");
	}

	/// A backplane that wraps [`Local`] and panics on its first read of a
	/// last order: a user backplane can fail inside a drain this way, and no
	/// shipped backplane does.
	struct PanicsOnce {
		local: Local,
		armed: AtomicBool,
	}

	impl Backplane for PanicsOnce {
		fn attach(&self, sink: NodeSink) {
			self.local.attach(sink);
		}

		fn publish(&self, topic: &Topic, payload: &[u8]) -> Result<(), PublishError> {
			self.local.publish(topic, payload)
		}

		fn last_order(&self, topic: &Topic) -> u64 {
			let armed = self.armed.swap(false, Ordering::Relaxed);
			if armed {
				panic!("the backplane fails inside the drain");
			}

			self.local.last_order(topic)
		}

		fn vacated(&self, topic: &Topic) {
			self.local.vacated(topic);
		}
	}

	/// A registry over a backplane that panics once, with one connection
	/// subscribed to `prices`.
	fn panicking() -> (TopicRegistry, ConnectionId, impl Sized) {
		let faulty = PanicsOnce { local: Local::default(), armed: AtomicBool::new(true) };
		let backplane: Arc<dyn Backplane> = Arc::new(faulty);
		let (registry, connection, peer) = registered(RegistryOptions { backplane, ..RegistryOptions::default() });
		subscribed(&registry, connection, "prices");

		(registry, connection, peer)
	}

	/// Quiesce `registry` through a drain that panics, expecting the panic.
	fn panicked(registry: &TopicRegistry) {
		let quiesce = AssertUnwindSafe(|| registry.quiesce());
		let unwound = catch_unwind(quiesce);
		unwound.expect_err("the drain should panic");
	}

	#[tokio::test]
	async fn a_subscribe_during_a_drain_is_refused() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());
		let _draining = begun(&registry);

		let refused = registry.register(connection, Topic::fixture("prices"));
		assert!(matches!(refused, Err(RegisterError::Draining)));
	}

	#[tokio::test]
	async fn a_quiesce_whose_end_frame_fails_cancels_its_drain() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());
		subscribed(&registry, connection, "prices");

		let refused = begun(&registry).end_frames_by(refusing);
		assert!(refused.is_err());
		assert!(!registry.view().is_draining());
	}

	#[tokio::test]
	async fn a_cancelled_drain_accepts_subscribes_again() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());
		subscribed(&registry, connection, "prices");
		cancelled(&registry);

		let resubscribed = registry.register(connection, Topic::fixture("chat"));
		assert!(resubscribed.is_ok());
	}

	#[tokio::test]
	async fn a_quiesce_during_a_cancelled_drain_reports_not_drained() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());
		subscribed(&registry, connection, "prices");
		let draining = begun(&registry);

		let waiting = registry.clone();
		let mut second = spawn_blocking(move || waiting.quiesce());
		let early = timeout(ARRIVAL, &mut second).await;
		let refused = draining.end_frames_by(refusing);
		let answered = timeout(DEADLINE, second).await;
		assert!(early.is_err());
		assert!(refused.is_err());
		assert!(matches!(answered, Ok(Ok(Ok(1)))));
	}

	#[tokio::test]
	async fn a_drain_dropped_by_a_panic_leaves_the_registry_live() {
		let (registry, connection, _peer) = panicking();
		panicked(&registry);

		let resubscribed = registry.register(connection, Topic::fixture("chat"));
		assert!(resubscribed.is_ok());
	}

	#[tokio::test]
	async fn a_retry_after_a_panicked_drain_completes_every_topic() {
		let (registry, connection, _peer) = panicking();
		subscribed(&registry, connection, "chat");
		panicked(&registry);

		let retried = registry.quiesce();
		assert!(matches!(retried, Ok(2)));
	}

	#[tokio::test]
	async fn a_repeat_after_a_recovered_drain_signals_nobody() {
		let (registry, _connection, _peer) = panicking();
		panicked(&registry);
		quiesced(&registry);

		let repeated = registry.quiesce();
		assert!(matches!(repeated, Ok(0)));
	}
}
