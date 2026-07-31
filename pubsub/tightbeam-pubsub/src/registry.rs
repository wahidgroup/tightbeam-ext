//! The topic registry: subscription bookkeeping, publish fan-out, and
//! per-subscriber delivery.
//!
//! One registry serves a whole process. Connections register with their
//! [`MuxHandle`], topics map to member subscribers, and every subscriber
//! owns one bounded queue drained by one task, so one slow client never
//! stalls another.

use core::fmt;
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use der::Encode;
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::transport::error::{TransportError, TransportFailure};
use tightbeam::transport::multiplex::MuxHandle;
use tightbeam::{Frame, TightBeamError};
use tokio::sync::Notify;

use crate::backplane::{Backplane, BackplaneError, DeliverError, Local, UpdateSink};
use crate::frame::{end_frame, update_frame};
use crate::policy::{DeliveryPolicy, DeliveryVerdict, DropOldest};
use crate::topic::Topic;

/// Updates one subscriber queue holds before the delivery policy decides.
const DEFAULT_QUEUE_CAPACITY: usize = 32;

/// One registered connection, allocated by
/// [`TopicRegistry::register_connection`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(u64);

/// One live subscription, allocated by [`TopicRegistry::register`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubscriberId(u64);

/// Registry construction knobs.
pub struct RegistryOptions {
	/// Bounded queue length per subscriber.
	pub queue_capacity: usize,
	/// Consulted when a subscriber queue is full.
	pub delivery: Arc<dyn DeliveryPolicy>,
	/// Sequencing and distribution: [`Local`] (single node) by default.
	pub backplane: Arc<dyn Backplane>,
}

impl Default for RegistryOptions {
	fn default() -> Self {
		Self {
			queue_capacity: DEFAULT_QUEUE_CAPACITY,
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
}

impl fmt::Display for RegisterError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::UnknownConnection => f.write_str("the connection is not registered"),
			Self::Draining => f.write_str("the registry is draining"),
		}
	}
}

impl Error for RegisterError {}

/// Why a publish produced no fan-out.
#[derive(Debug)]
pub enum PublishError {
	/// The registry is quiescing: new publishes are refused.
	Draining,
	/// The update frame failed to encode for delivery.
	Build(TightBeamError),
	/// The backplane rejected or lost the publish after local checks passed.
	Backplane(BackplaneError),
}

impl From<TightBeamError> for PublishError {
	fn from(cause: TightBeamError) -> Self {
		Self::Build(cause)
	}
}

impl From<BackplaneError> for PublishError {
	fn from(cause: BackplaneError) -> Self {
		/*
		 * Single-node refusals keep their pre-backplane shapes so callers
		 * match on Draining/Build regardless of the backplane behind them.
		 */
		match cause {
			BackplaneError::Refused(DeliverError::Draining) => Self::Draining,
			BackplaneError::Refused(DeliverError::Build(cause)) => Self::Build(cause),
			unavailable => Self::Backplane(unavailable),
		}
	}
}

impl fmt::Display for PublishError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Draining => f.write_str("the registry is draining"),
			Self::Build(cause) => write!(f, "the update frame failed to build: {cause}"),
			Self::Backplane(cause) => write!(f, "the backplane refused the publish: {cause}"),
		}
	}
}

impl Error for PublishError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Build(cause) => Some(cause),
			Self::Backplane(cause) => Some(cause),
			Self::Draining => None,
		}
	}
}

/// The queue and its emit state, guarded as one unit so eviction can
/// never touch the update currently in flight.
#[derive(Default)]
struct Lane {
	queue: VecDeque<Arc<Frame>>,
	/// A popped update is being emitted right now.
	in_flight: bool,
}

/// One subscriber's delivery lane: the bounded queue its drain task feeds
/// from, and the flags publish/unregister flip.
struct Subscriber {
	topic: Topic,
	connection: ConnectionId,
	lane: Mutex<Lane>,
	notify: Notify,
	dropped: AtomicU64,
	/// Stop immediately: the subscription or its connection is gone.
	closed: AtomicBool,
	/// Stop once the queue empties: the topic completed (quiesce).
	finished: AtomicBool,
}

impl Subscriber {
	fn new(topic: Topic, connection: ConnectionId) -> Self {
		Self {
			topic,
			connection,
			lane: Mutex::new(Lane::default()),
			notify: Notify::new(),
			dropped: AtomicU64::new(0),
			closed: AtomicBool::new(false),
			finished: AtomicBool::new(false),
		}
	}

	fn lock_lane(&self) -> MutexGuard<'_, Lane> {
		self.lane.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// Whether updates are still queued or being emitted.
	fn pending(&self) -> bool {
		let lane = self.lock_lane();
		lane.in_flight || !lane.queue.is_empty()
	}

	/// Stop the drain task at the next iteration and wake it.
	fn close(&self) {
		self.closed.store(true, Ordering::Release);
		self.notify.notify_one();
	}

	/// Queue the final update and stop the drain task once it flushes.
	fn finish(&self, end: &Arc<Frame>) {
		self.lock_lane().queue.push_back(Arc::clone(end));
		self.finished.store(true, Ordering::Release);
		self.notify.notify_one();
	}
}

/// What one enqueue attempt did.
enum PushOutcome {
	/// The update entered the queue.
	Delivered,
	/// The policy dropped an update (this one or the oldest).
	Dropped,
	/// The policy gave up on the whole connection.
	Disconnect,
}

/// Per-topic bookkeeping: the dense order counter and the member set.
#[derive(Default)]
struct TopicState {
	last_order: u64,
	members: HashSet<SubscriberId>,
}

/// Per-connection bookkeeping: the emit handle, the identity the
/// application attached, and the connection's live subscriptions.
struct ConnectionState {
	handle: MuxHandle,
	identity: Option<Arc<[u8]>>,
	topics: HashMap<Topic, SubscriberId>,
}

#[derive(Default)]
struct State {
	topics: HashMap<Topic, TopicState>,
	connections: HashMap<ConnectionId, ConnectionState>,
	subscribers: HashMap<SubscriberId, Arc<Subscriber>>,
}

struct Inner {
	options: RegistryOptions,
	draining: AtomicBool,
	next_connection: AtomicU64,
	next_subscriber: AtomicU64,
	state: Mutex<State>,
	/// Signaled by drain tasks whenever a queue empties; see
	/// [`TopicRegistry::flushed`].
	flush: Notify,
}

/// Topic fan-out over multiplexed tightbeam connections.
///
/// Clone-cheap: clones share the same registry.
#[derive(Clone)]
pub struct TopicRegistry {
	inner: Arc<Inner>,
}

impl Default for TopicRegistry {
	fn default() -> Self {
		Self::new(RegistryOptions::default())
	}
}

impl TopicRegistry {
	/// A registry with explicit queue, policy, and backplane options.
	pub fn new(options: RegistryOptions) -> Self {
		let inner = Arc::new(Inner {
			options,
			draining: AtomicBool::new(false),
			next_connection: AtomicU64::new(1),
			next_subscriber: AtomicU64::new(1),
			state: Mutex::new(State::default()),
			flush: Notify::new(),
		});

		/*
		 * Weak: a dropped registry falls out of the backplane's distribution
		 * on its own, and the backplane never keeps a dead node alive.
		 */
		let sink = Arc::downgrade(&inner) as Weak<dyn UpdateSink>;
		inner.options.backplane.attach(sink);

		Self { inner }
	}

	fn lock_state(&self) -> MutexGuard<'_, State> {
		self.inner.lock_state()
	}

	/// Whether [`quiesce`](Self::quiesce) already ran.
	pub fn is_draining(&self) -> bool {
		self.inner.draining.load(Ordering::Acquire)
	}

	/// Register an anonymous connection's emit handle, yielding the id
	/// its subscriptions hang off.
	pub fn register_connection(&self, handle: MuxHandle) -> ConnectionId {
		self.admit_connection(handle, None)
	}

	/// Register a connection's emit handle under an opaque identity, so the
	/// policies can authorize by caller.
	pub fn register_connection_as(&self, handle: MuxHandle, identity: impl Into<Vec<u8>>) -> ConnectionId {
		self.admit_connection(handle, Some(identity.into()))
	}

	fn admit_connection(&self, handle: MuxHandle, identity: Option<Vec<u8>>) -> ConnectionId {
		let id = ConnectionId(self.inner.next_connection.fetch_add(1, Ordering::Relaxed));
		let connection = ConnectionState { handle, identity: identity.map(Arc::from), topics: HashMap::new() };

		self.lock_state().connections.insert(id, connection);
		id
	}

	/// The identity attached at
	/// [`register_connection_as`](Self::register_connection_as); `None`
	/// for an anonymous connection.
	pub fn identity(&self, connection: ConnectionId) -> Option<Arc<[u8]>> {
		self.member_identity(connection).flatten()
	}

	/// The caller's identity while `connection` is registered: `None`
	/// once the connection was dropped (or never admitted), so a revoked
	/// caller never degrades to anonymous access, and `Some(None)` for a
	/// registered anonymous connection.
	pub fn member_identity(&self, connection: ConnectionId) -> Option<Option<Arc<[u8]>>> {
		let state = self.lock_state();
		let connected = state.connections.get(&connection)?;
		Some(connected.identity.clone())
	}

	/// Subscribe `connection` to `topic`, spawning its delivery task.
	///
	/// Idempotent per connection and topic: re-subscribing returns the
	/// existing id. MUST be called within a tokio runtime.
	///
	/// # Errors
	///
	/// - [`RegisterError::Draining`]: [`quiesce`](Self::quiesce) already ran.
	/// - [`RegisterError::UnknownConnection`]: `connection` was never admitted.
	pub fn register(&self, connection: ConnectionId, topic: Topic) -> Result<SubscriberId, RegisterError> {
		let mut state = self.lock_state();
		/*
		 * Checked under the state lock: quiesce flips the flag before it
		 * takes the lock, so no subscriber can slip in after its topic's
		 * end/ push and miss the completion.
		 */
		if self.is_draining() {
			return Err(RegisterError::Draining);
		}

		let connected = state.connections.get(&connection).ok_or(RegisterError::UnknownConnection)?;
		if let Some(existing) = connected.topics.get(&topic) {
			return Ok(*existing);
		}

		let id = SubscriberId(self.inner.next_subscriber.fetch_add(1, Ordering::Relaxed));
		let subscriber = Arc::new(Subscriber::new(topic.clone(), connection));
		let handle = connected.handle.clone();

		state.subscribers.insert(id, Arc::clone(&subscriber));
		state.topics.entry(topic.clone()).or_default().members.insert(id);

		if let Some(connected) = state.connections.get_mut(&connection) {
			connected.topics.insert(topic, id);
		}

		drop(state);

		tokio::spawn(drain(subscriber, handle, Arc::clone(&self.inner)));
		Ok(id)
	}

	/// Drop `connection`'s subscription to `topic`.
	///
	/// Returns whether a subscription existed. Idempotent: a repeat (or a
	/// never-subscribed topic) is `false`, not an error.
	pub fn unregister(&self, connection: ConnectionId, topic: &Topic) -> bool {
		let mut state = self.lock_state();
		let Some(connected) = state.connections.get_mut(&connection) else {
			return false;
		};
		let Some(id) = connected.topics.remove(topic) else {
			return false;
		};

		remove_subscriber(&mut state, id);
		true
	}

	/// Drop every subscription the connection holds.
	///
	/// The serve-side helper calls this when a connection's serve loop
	/// exits; delivery tasks stop and the topics forget the members.
	pub fn drop_connection(&self, connection: ConnectionId) {
		self.inner.drop_connection(connection);
	}

	/// Publish `payload` to every subscriber of `topic`, through the backplane.
	///
	/// The backplane assigns the dense per-topic stamp and distributes to
	/// every attached node; each node builds the update frame (id =
	/// topic) and fans out locally. The stamp advances even with no
	/// subscribers, so late subscribers observe continuity.
	///
	/// # Errors
	///
	/// - [`PublishError::Draining`]: the registry is quiescing.
	/// - [`PublishError::Build`]: a node could not encode the update frame.
	/// - [`PublishError::Backplane`]: the backplane rejected or lost the publish.
	pub fn publish(&self, topic: &Topic, payload: impl AsRef<[u8]>) -> Result<(), PublishError> {
		/*
		 * Fast-fail only: the authoritative draining check runs under the
		 * state lock in deliver, so a racing quiesce still refuses the
		 * update after its end/ push.
		 */
		if self.is_draining() {
			return Err(PublishError::Draining);
		}

		self.inner.options.backplane.publish(topic, payload.as_ref())?;
		Ok(())
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
	/// # Errors
	///
	/// - [`PublishError::Build`]: an `end/<topic>` frame failed to encode.
	pub fn quiesce(&self) -> Result<usize, PublishError> {
		if self.inner.draining.swap(true, Ordering::AcqRel) {
			return Ok(0);
		}

		let mut state = self.lock_state();
		let mut signaled = 0;

		let topics: Vec<Topic> = state.topics.keys().cloned().collect();
		for topic in topics {
			let Some(entry) = state.topics.get_mut(&topic) else {
				continue;
			};
			let order = entry.last_order.saturating_add(1);
			let end = Arc::new(end_frame(&topic, order)?);

			entry.last_order = order;

			let members: Vec<SubscriberId> = entry.members.iter().copied().collect();
			for id in members {
				if let Some(subscriber) = state.subscribers.get(&id) {
					subscriber.finish(&end);
					signaled += 1;
				}
			}
		}

		Ok(signaled)
	}

	/// Updates dropped so far for `subscriber`, or `None` once it is gone.
	pub fn dropped(&self, subscriber: SubscriberId) -> Option<u64> {
		let state = self.lock_state();
		let counter = &state.subscribers.get(&subscriber)?.dropped;
		Some(counter.load(Ordering::Relaxed))
	}

	/// Live subscriber count for `topic`.
	pub fn subscriber_count(&self, topic: &Topic) -> usize {
		let state = self.lock_state();
		state.topics.get(topic).map_or(0, |entry| entry.members.len())
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
				state.subscribers.values().any(|subscriber| {
					let live = !subscriber.closed.load(Ordering::Acquire);
					live && subscriber.pending()
				})
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

	/// Drop every subscription the connection holds.
	fn drop_connection(&self, connection: ConnectionId) {
		let mut state = self.lock_state();
		let Some(connected) = state.connections.remove(&connection) else {
			return;
		};

		for id in connected.topics.into_values() {
			remove_subscriber(&mut state, id);
		}
	}

	/// Drop a connection the delivery policy voted off and drain its
	/// link so the peer observes an orderly GoAway instead of a silent stall.
	///
	/// The registry sends `EnhanceYourCalm`, the analog for a load-generating
	/// peer that cannot keep pace with delivery.
	///
	/// # Sources
	///
	/// - RFC 9113 § 7, GOAWAY frame:
	///   <https://datatracker.ietf.org/doc/html/rfc9113#section-7>
	fn disconnect(&self, connection: ConnectionId) {
		let handle = {
			let state = self.lock_state();
			state.connections.get(&connection).map(|connected| connected.handle.clone())
		};

		self.drop_connection(connection);

		let Some(handle) = handle else {
			return;
		};

		tokio::spawn(async move {
			// Best effort: a link that already failed has nothing to drain.
			let _ = handle.shutdown_with(GoAwayReason::EnhanceYourCalm).await;
		});
	}

	/// Enqueue `update` to every member, collecting connections the
	/// delivery policy voted off.
	fn fan_out(&self, state: &State, topic: &Topic, update: &Arc<Frame>) -> Vec<ConnectionId> {
		let mut doomed = Vec::new();
		let Some(members) = state.topics.get(topic).map(|entry| &entry.members) else {
			return doomed;
		};

		for id in members {
			let Some(subscriber) = state.subscribers.get(id) else {
				continue;
			};

			match self.push(subscriber, update) {
				PushOutcome::Delivered | PushOutcome::Dropped => {}
				PushOutcome::Disconnect => doomed.push(subscriber.connection),
			}
		}

		doomed
	}

	/// Enqueue one update, consulting the delivery policy when full.
	///
	/// Eviction only ever touches queued updates: the update in flight
	/// already left the queue, so it is beyond the policy's reach.
	fn push(&self, subscriber: &Subscriber, update: &Arc<Frame>) -> PushOutcome {
		let mut lane = subscriber.lock_lane();
		if lane.queue.len() < self.options.queue_capacity {
			lane.queue.push_back(Arc::clone(update));

			drop(lane);
			subscriber.notify.notify_one();

			return PushOutcome::Delivered;
		}

		let dropped_so_far = subscriber.dropped.load(Ordering::Relaxed);
		match self.options.delivery.on_full(&subscriber.topic, dropped_so_far) {
			DeliveryVerdict::DropOldest => {
				lane.queue.pop_front();
				lane.queue.push_back(Arc::clone(update));

				drop(lane);

				subscriber.dropped.fetch_add(1, Ordering::Relaxed);
				subscriber.notify.notify_one();

				PushOutcome::Delivered
			}
			DeliveryVerdict::DropNew => {
				drop(lane);

				subscriber.dropped.fetch_add(1, Ordering::Relaxed);

				PushOutcome::Dropped
			}
			DeliveryVerdict::Disconnect => PushOutcome::Disconnect,
		}
	}
}

impl UpdateSink for Inner {
	/// One backplane-sequenced update lands on this node: build the wire
	/// frame at the assigned order and fan out to the local members.
	fn deliver(&self, topic: &Topic, order: u64, payload: &[u8]) -> Result<(), DeliverError> {
		let mut state = self.lock_state();
		/*
		 * Checked under the state lock: quiesce flips the flag before it
		 * takes the lock, so no update can ever land after a topic's
		 * end/ push.
		 */
		if self.draining.load(Ordering::Acquire) {
			return Err(DeliverError::Draining);
		}

		let update = Arc::new(update_frame(topic, order, payload)?);
		/*
		 * Only subscribed topics keep state: the backplane owns the order
		 * counter, so publishes to arbitrary names never grow the map.
		 */
		if let Some(entry) = state.topics.get_mut(topic) {
			entry.last_order = entry.last_order.max(order);
		}

		let doomed = self.fan_out(&state, topic, &update);
		drop(state);

		for connection in doomed {
			self.disconnect(connection);
		}

		Ok(())
	}
}

/// Detach one subscriber from every map and stop its delivery task.
fn remove_subscriber(state: &mut State, id: SubscriberId) {
	let Some(subscriber) = state.subscribers.remove(&id) else {
		return;
	};
	if let Some(entry) = state.topics.get_mut(&subscriber.topic) {
		entry.members.remove(&id);
		/*
		 * Prune the emptied topic so churn over unique names never grows
		 * the map without bound; the backplane keeps the order counter.
		 */
		if entry.members.is_empty() {
			state.topics.remove(&subscriber.topic);
		}
	}

	subscriber.close();
}

/// One subscriber's delivery loop: pop, emit, repeat.
///
/// Emits serialize per subscriber, preserving stamp order. The lane's
/// `in_flight` flag covers the popped update until its emit settles, so
/// [`TopicRegistry::flushed`] observing an idle empty lane means every
/// update actually left. A local stream-cap exhaustion waits for a slot.
async fn drain(subscriber: Arc<Subscriber>, handle: MuxHandle, registry: Arc<Inner>) {
	loop {
		if subscriber.closed.load(Ordering::Acquire) {
			return;
		}

		let next = {
			let mut lane = subscriber.lock_lane();
			let popped = lane.queue.pop_front();

			lane.in_flight = popped.is_some();

			popped
		};
		let Some(update) = next else {
			if subscriber.finished.load(Ordering::Acquire) {
				return;
			}

			subscriber.notify.notified().await;
			continue;
		};

		let delivery = deliver(&subscriber, &handle, &update).await;

		let idle = {
			let mut lane = subscriber.lock_lane();
			lane.in_flight = false;
			lane.queue.is_empty()
		};
		if idle {
			registry.flush.notify_one();
		}

		if delivery.is_err() {
			subscriber.close();
			return;
		}
	}
}

/// The delivery loop lost its link: stop draining.
struct LinkLost;

/// Emit one update, classifying the failure modes.
async fn deliver(subscriber: &Subscriber, handle: &MuxHandle, update: &Arc<Frame>) -> Result<(), LinkLost> {
	loop {
		match handle.emit_on_stream(update).await {
			Ok(_) => return Ok(()),
			Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted)) => {
				handle.wait_for_stream_slot().await.map_err(|_| LinkLost)?;
			}
			Err(TransportError::OperationFailed(_)) => {
				/*
				 * The peer refused this one update: saturation, an
				 * application answer, or the post-unsubscribe race where
				 * the topic is no longer routed.
				 */
				subscriber.dropped.fetch_add(1, Ordering::Relaxed);
				return Ok(());
			}
			Err(_) => return Err(LinkLost),
		}
	}
}

#[cfg(test)]
mod tests {
	use core::time::Duration;

	use super::*;
	use crate::testing::memory_mux_pair;

	fn topic(name: &str) -> Topic {
		name.parse().expect("test topics should parse")
	}

	/// Subscribe `connection` to `name`, expecting acceptance.
	fn subscribed(registry: &TopicRegistry, connection: ConnectionId, name: &str) -> SubscriberId {
		registry
			.register(connection, topic(name))
			.expect("the registration should be accepted")
	}

	/// Publish `payload` to `name`, expecting acceptance.
	fn published(registry: &TopicRegistry, name: &str, payload: &[u8]) {
		registry.publish(&topic(name), payload).expect("the publish should be accepted");
	}

	/// Quiesce the registry, expecting the signaled subscriber count.
	fn quiesced(registry: &TopicRegistry) -> usize {
		registry.quiesce().expect("quiesce should succeed")
	}

	/// A registry with one registered in-memory connection. The returned
	/// guard keeps the peer transport alive.
	fn registered(options: RegistryOptions) -> (TopicRegistry, ConnectionId, impl Sized) {
		let (client, server) = memory_mux_pair(4);
		let (handle, _reader, _writer, _responder) = server.into_parts();

		let registry = TopicRegistry::new(options);
		let connection = registry.register_connection_as(handle, b"cert".to_vec());
		(registry, connection, client)
	}

	#[tokio::test]
	async fn register_is_idempotent_per_connection_and_topic() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());

		let first = subscribed(&registry, connection, "prices");
		let second = subscribed(&registry, connection, "prices");
		assert_eq!(first, second);
		assert_eq!(registry.subscriber_count(&topic("prices")), 1);
	}

	#[tokio::test]
	async fn register_requires_a_known_connection() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());

		registry.drop_connection(connection);

		let outcome = registry.register(connection, topic("prices"));
		assert_eq!(outcome, Err(RegisterError::UnknownConnection));
	}

	#[tokio::test]
	async fn identity_surfaces_what_registration_attached() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());

		let identity = registry.identity(connection);
		assert_eq!(identity.as_deref(), Some(b"cert".as_slice()));
	}

	#[tokio::test]
	async fn member_identity_requires_a_live_registration() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());
		assert!(registry.member_identity(connection).is_some());

		registry.drop_connection(connection);
		assert!(registry.member_identity(connection).is_none());
	}

	#[tokio::test]
	async fn unregister_prunes_the_emptied_topic() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());
		subscribed(&registry, connection, "prices");

		registry.unregister(connection, &topic("prices"));

		let state = registry.lock_state();
		assert!(!state.topics.contains_key(&topic("prices")));
	}

	#[tokio::test]
	async fn unregister_forgets_the_membership() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());

		subscribed(&registry, connection, "prices");

		let removed = registry.unregister(connection, &topic("prices"));
		let repeat = registry.unregister(connection, &topic("prices"));
		assert!(removed);
		assert!(!repeat);
		assert_eq!(registry.subscriber_count(&topic("prices")), 0);
	}

	#[tokio::test]
	async fn drop_connection_forgets_every_membership() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());
		subscribed(&registry, connection, "prices");
		subscribed(&registry, connection, "chat");

		registry.drop_connection(connection);

		assert_eq!(registry.subscriber_count(&topic("prices")), 0);
		assert_eq!(registry.subscriber_count(&topic("chat")), 0);
	}

	#[tokio::test]
	async fn publish_to_a_memberless_topic_retains_no_state() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());
		published(&registry, "silence", b"tick");
		published(&registry, "silence", b"tock");

		{
			let state = registry.lock_state();
			assert!(!state.topics.contains_key(&topic("silence")));
		}

		/*
		 * The backplane kept the counter: a late subscriber still
		 * observes the continued dense sequence.
		 */
		subscribed(&registry, connection, "silence");
		published(&registry, "silence", b"third");

		let state = registry.lock_state();
		assert_eq!(state.topics[&topic("silence")].last_order, 3);
	}

	/// Delivery policy returning one fixed verdict.
	struct FixedVerdict(DeliveryVerdict);

	impl DeliveryPolicy for FixedVerdict {
		fn on_full(&self, _topic: &Topic, _dropped_so_far: u64) -> DeliveryVerdict {
			self.0
		}
	}

	/// A subscriber and `capacity + extra` stamped updates to push at it.
	fn saturated(capacity: usize, verdict: DeliveryVerdict) -> (TopicRegistry, Subscriber, Vec<Arc<Frame>>) {
		let options = RegistryOptions {
			queue_capacity: capacity,
			delivery: Arc::new(FixedVerdict(verdict)),
			..RegistryOptions::default()
		};

		let registry = TopicRegistry::new(options);
		let subscriber = Subscriber::new(topic("prices"), ConnectionId(1));
		let updates: Vec<Arc<Frame>> = (1..=(capacity as u64) + 1)
			.map(|order| {
				let update = update_frame(&topic("prices"), order, b"tick").expect("update frames should build");
				Arc::new(update)
			})
			.collect();

		(registry, subscriber, updates)
	}

	fn queued_orders(subscriber: &Subscriber) -> Vec<u64> {
		subscriber.lock_lane().queue.iter().map(|frame| frame.metadata.order).collect()
	}

	#[test]
	fn push_drop_oldest_keeps_the_newest_updates() {
		let (registry, subscriber, updates) = saturated(2, DeliveryVerdict::DropOldest);
		for update in &updates {
			registry.inner.push(&subscriber, update);
		}

		assert_eq!(queued_orders(&subscriber), [2, 3]);
		assert_eq!(subscriber.dropped.load(Ordering::Relaxed), 1);
	}

	#[test]
	fn push_drop_new_keeps_the_oldest_updates() {
		let (registry, subscriber, updates) = saturated(2, DeliveryVerdict::DropNew);
		for update in &updates {
			registry.inner.push(&subscriber, update);
		}

		assert_eq!(queued_orders(&subscriber), [1, 2]);
		assert_eq!(subscriber.dropped.load(Ordering::Relaxed), 1);
	}

	/// Poll until the peer observes a GoAway, or give up.
	async fn drained_reason(handle: &MuxHandle) -> Option<GoAwayReason> {
		for _ in 0..100 {
			if let Some(reason) = handle.goaway_reason() {
				return Some(reason);
			}

			tokio::time::sleep(Duration::from_millis(10)).await;
		}

		None
	}

	#[tokio::test]
	async fn a_disconnect_verdict_drains_the_connection() {
		let options = RegistryOptions {
			queue_capacity: 1,
			delivery: Arc::new(FixedVerdict(DeliveryVerdict::Disconnect)),
			..RegistryOptions::default()
		};
		let registry = TopicRegistry::new(options);

		let (client, server) = memory_mux_pair(4);
		let (server_handle, server_reader, server_writer, _server_responder) = server.into_parts();
		let (client_handle, client_reader, client_writer, _client_responder) = client.into_parts();
		tokio::spawn(server_reader.drive());
		tokio::spawn(server_writer.drive());
		tokio::spawn(client_reader.drive());
		tokio::spawn(client_writer.drive());

		let connection = registry.register_connection(server_handle);
		subscribed(&registry, connection, "prices");

		/*
		 * The client never answers update streams, so the first emit
		 * stays in flight, the second fills the capacity-1 queue, and
		 * the third makes the delivery policy vote the connection off.
		 */
		published(&registry, "prices", b"one");
		published(&registry, "prices", b"two");
		published(&registry, "prices", b"three");

		let reason = drained_reason(&client_handle).await;
		assert_eq!(reason, Some(GoAwayReason::EnhanceYourCalm));
		assert_eq!(registry.subscriber_count(&topic("prices")), 0);
	}

	#[test]
	fn push_disconnect_names_the_connection() {
		let (registry, subscriber, updates) = saturated(1, DeliveryVerdict::Disconnect);

		registry.inner.push(&subscriber, &updates[0]);

		let outcome = registry.inner.push(&subscriber, &updates[1]);
		assert!(matches!(outcome, PushOutcome::Disconnect));
		assert_eq!(queued_orders(&subscriber), [1]);
	}

	#[tokio::test]
	async fn publish_stamps_dense_per_topic_orders() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());
		subscribed(&registry, connection, "prices");
		subscribed(&registry, connection, "chat");

		published(&registry, "prices", b"one");
		published(&registry, "prices", b"two");
		published(&registry, "chat", b"hello");

		let state = registry.lock_state();
		assert_eq!(state.topics[&topic("prices")].last_order, 2);
		assert_eq!(state.topics[&topic("chat")].last_order, 1);
	}

	#[tokio::test]
	async fn quiesce_refuses_further_registration_and_publish() {
		let (registry, connection, _peer) = registered(RegistryOptions::default());

		subscribed(&registry, connection, "prices");

		let signaled = quiesced(&registry);
		let again = quiesced(&registry);
		assert_eq!(signaled, 1);
		assert_eq!(again, 0);
		assert!(matches!(
			registry.register(connection, topic("chat")),
			Err(RegisterError::Draining)
		));
		assert!(matches!(
			registry.publish(&topic("prices"), b"tick"),
			Err(PublishError::Draining)
		));
	}
}
