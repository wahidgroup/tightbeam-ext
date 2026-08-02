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
//!   refusal means that sink is leaving and does not fail the publish when
//!   another sink accepted. A hard refusal ([`DeliverError::Build`] or
//!   [`DeliverError::Rejected`]) fails the publish.
//! - The order stamp burns when at least one sink accepted. An all-refuse
//!   publish leaves the counter untouched so subscribers never see a gap
//!   for an update no node fanned out.
//! - Per-topic counters persist for the backplane's lifetime: dense
//!   ordering cannot forget a topic's last order. The subscribe and
//!   publish policies are the boundary that keeps the topic namespace
//!   (and so the counter set) application-controlled.
//! - Async fabrics MAY return [`Ok`] after durable enqueue when they
//!   document at-most-once delivery. [`Local`] is stamp-then-deliver.

use core::error::Error;
use core::fmt;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError, Weak};

use tightbeam::TightBeamError;

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
	/// The sink refused this update for an application reason.
	///
	/// Hard: the publish fails even when another sink accepted.
	Rejected,
}

impl fmt::Display for DeliverError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Draining => f.write_str("the node is draining"),
			Self::Build(cause) => write!(f, "the update frame failed to build: {cause}"),
			Self::Rejected => f.write_str("the sink rejected the update"),
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
			Self::Draining | Self::Rejected => None,
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

/// Why a publish never entered the backplane.
#[derive(Debug)]
pub enum BackplaneError {
	/// Every reachable node refused the update.
	Refused(DeliverError),
	/// The backplane transport rejected or lost the publish.
	Unavailable(Box<dyn Error + Send + Sync>),
}

impl fmt::Display for BackplaneError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Refused(cause) => write!(f, "every node refused the update: {cause}"),
			Self::Unavailable(cause) => write!(f, "the backplane is unavailable: {cause}"),
		}
	}
}

impl Error for BackplaneError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Refused(cause) => Some(cause),
			Self::Unavailable(cause) => Some(cause.as_ref()),
		}
	}
}

/// One node's local delivery hook. The registry attaches itself at
/// construction. The backplane calls back with every sequenced update.
pub trait UpdateSink: Send + Sync {
	/// Fan `payload` out to this node's subscribers of `topic` at the
	/// backplane-assigned `order`.
	///
	/// # Errors
	///
	/// - [`DeliverError::Draining`]: this node is quiescing.
	/// - [`DeliverError::Build`]: the update frame failed to encode.
	/// - [`DeliverError::Rejected`]: the sink refuses this update for an
	///   application reason.
	fn deliver(&self, topic: &Topic, order: u64, payload: &[u8]) -> Result<(), DeliverError>;
}

/// Per-topic sequencing and distribution behind the registry.
pub trait Backplane: Send + Sync {
	/// Attach one node's delivery hook. Weak: a dropped registry falls
	/// out of distribution on its own.
	fn attach(&self, sink: Weak<dyn UpdateSink>);

	/// Assign the next dense order for `topic` and distribute `payload`
	/// to every attached node.
	///
	/// For [`Local`], success means every non-draining live sink accepted.
	/// Async fabrics that only enqueue MUST document at-most-once ack.
	///
	/// # Errors
	///
	/// - [`BackplaneError::Refused`]: no sink accepted, or a hard refusal
	///   occurred after a partial accept. The stamp still burns when any
	///   sink accepted.
	/// - [`BackplaneError::Unavailable`]: the distribution fabric failed.
	fn publish(&self, topic: &Topic, payload: &[u8]) -> Result<(), BackplaneError>;

	/// Claim the next dense order for `topic` without fan-out.
	///
	/// [`TopicRegistry::quiesce`](crate::TopicRegistry::quiesce) uses this
	/// for `end/<topic>` stamps so completion shares the same counter as
	/// updates across every attached sink. Callers MUST NOT hold a
	/// registry lock across this call. [`Local::publish`] holds the
	/// backplane lock while it re-enters [`UpdateSink::deliver`].
	fn reserve_order(&self, topic: &Topic) -> u64;

	/// Last committed dense order for `topic`, or `0` when the topic has
	/// never accepted a publish.
	fn last_order(&self, topic: &Topic) -> u64;
}

#[derive(Default)]
struct LocalState {
	orders: HashMap<Topic, u64>,
	sinks: Vec<Weak<dyn UpdateSink>>,
}

/// The in-process backplane: one counter per topic, direct synchronous
/// delivery to every attached registry. The default.
///
/// The lock spans sequencing and delivery, so two racing publishes can
/// never reach a subscriber queue out of stamp order.
#[derive(Default)]
pub struct Local {
	state: Mutex<LocalState>,
}

impl Local {
	fn lock_state(&self) -> MutexGuard<'_, LocalState> {
		self.state.lock().unwrap_or_else(PoisonError::into_inner)
	}
}

impl Backplane for Local {
	fn attach(&self, sink: Weak<dyn UpdateSink>) {
		let mut state = self.lock_state();
		state.sinks.retain(|existing| existing.strong_count() > 0);
		state.sinks.push(sink);
	}

	fn publish(&self, topic: &Topic, payload: &[u8]) -> Result<(), BackplaneError> {
		let mut state = self.lock_state();
		let order = state.orders.get(topic).copied().unwrap_or(0).saturating_add(1);

		let mut delivered_any = false;
		let mut first_hard = None;
		let mut first_soft = None;
		state.sinks.retain(|entry| {
			let Some(sink) = entry.upgrade() else {
				return false;
			};

			match sink.deliver(topic, order, payload) {
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
			state.orders.insert(topic.clone(), order);
			if let Some(refusal) = first_hard {
				return Err(BackplaneError::Refused(refusal));
			}

			return Ok(());
		}

		match first_hard.or(first_soft) {
			Some(refusal) => Err(BackplaneError::Refused(refusal)),
			None => {
				// No live sinks: still advance the dense counter.
				state.orders.insert(topic.clone(), order);
				Ok(())
			}
		}
	}

	fn reserve_order(&self, topic: &Topic) -> u64 {
		let mut state = self.lock_state();
		let order = state.orders.get(topic).copied().unwrap_or(0).saturating_add(1);

		state.orders.insert(topic.clone(), order);

		order
	}

	fn last_order(&self, topic: &Topic) -> u64 {
		self.lock_state().orders.get(topic).copied().unwrap_or(0)
	}
}

#[cfg(test)]
mod tests {
	use std::sync::atomic::{AtomicU64, Ordering};
	use std::sync::Arc;

	use super::*;

	fn topic(name: &str) -> Topic {
		name.parse().expect("test topics should parse")
	}

	/// Publish `payload` to `name` through `backplane`, expecting acceptance.
	fn published(backplane: &Local, name: &str, payload: &[u8]) {
		backplane
			.publish(&topic(name), payload)
			.expect("the publish should be accepted");
	}

	#[test]
	fn reserve_order_claims_without_fan_out() {
		let backplane = Local::default();
		let recorder = Arc::new(Recorder::default());
		backplane.attach(Arc::downgrade(&(recorder.clone() as Arc<dyn UpdateSink>)));

		assert_eq!(backplane.reserve_order(&topic("prices")), 1);
		assert_eq!(backplane.last_order(&topic("prices")), 1);
		assert!(recorded(&recorder).is_empty());

		published(&backplane, "prices", b"tick");
		assert_eq!(recorded(&recorder), [(topic("prices"), 2)]);
	}

	/// Records every delivery. Refuses once `draining` flips.
	#[derive(Default)]
	struct Recorder {
		orders: Mutex<Vec<(Topic, u64)>>,
		refusals: AtomicU64,
		draining: bool,
	}

	impl UpdateSink for Recorder {
		fn deliver(&self, topic: &Topic, order: u64, _payload: &[u8]) -> Result<(), DeliverError> {
			if self.draining {
				self.refusals.fetch_add(1, Ordering::Relaxed);
				return Err(DeliverError::Draining);
			}

			self.orders
				.lock()
				.unwrap_or_else(PoisonError::into_inner)
				.push((topic.clone(), order));

			Ok(())
		}
	}

	fn recorded(recorder: &Recorder) -> Vec<(Topic, u64)> {
		recorder.orders.lock().unwrap_or_else(PoisonError::into_inner).clone()
	}

	/// Attach one fresh recorder node to `backplane`.
	fn attached(backplane: &Local, draining: bool) -> Arc<Recorder> {
		let node = Arc::new(Recorder { draining, ..Recorder::default() });
		backplane.attach(Arc::downgrade(&node) as Weak<dyn UpdateSink>);
		node
	}

	#[test]
	fn publish_assigns_dense_orders_per_topic() {
		let backplane = Local::default();
		let node = attached(&backplane, false);

		published(&backplane, "prices", b"one");
		published(&backplane, "prices", b"two");
		published(&backplane, "chat", b"hello");

		let expected = [(topic("prices"), 1), (topic("prices"), 2), (topic("chat"), 1)];
		assert_eq!(recorded(&node), expected);
	}

	#[test]
	fn publish_reaches_every_attached_node() {
		let backplane = Local::default();
		let first = attached(&backplane, false);
		let second = attached(&backplane, false);

		published(&backplane, "prices", b"tick");

		assert_eq!(recorded(&first), [(topic("prices"), 1)]);
		assert_eq!(recorded(&second), [(topic("prices"), 1)]);
	}

	#[test]
	fn publish_survives_a_dropped_node() {
		let backplane = Local::default();
		let live = attached(&backplane, false);
		let dead = attached(&backplane, false);
		drop(dead);

		let outcome = backplane.publish(&topic("prices"), b"tick");
		assert!(outcome.is_ok());
		assert_eq!(recorded(&live), [(topic("prices"), 1)]);
	}

	#[test]
	fn publish_with_no_nodes_still_sequences() {
		let backplane = Local::default();

		published(&backplane, "prices", b"one");
		published(&backplane, "prices", b"two");

		let node = attached(&backplane, false);
		published(&backplane, "prices", b"three");

		assert_eq!(recorded(&node), [(topic("prices"), 3)]);
	}

	#[test]
	fn publish_refused_everywhere_surfaces_the_refusal() {
		let backplane = Local::default();
		let _draining = attached(&backplane, true);

		let outcome = backplane.publish(&topic("prices"), b"tick");
		assert!(matches!(outcome, Err(BackplaneError::Refused(DeliverError::Draining))));
	}

	#[test]
	fn a_refused_publish_does_not_burn_the_order() {
		let backplane = Local::default();
		let draining = attached(&backplane, true);

		let refused = backplane.publish(&topic("prices"), b"tick");
		assert!(matches!(refused, Err(BackplaneError::Refused(_))));

		drop(draining);

		let node = attached(&backplane, false);
		published(&backplane, "prices", b"tick");

		assert_eq!(recorded(&node), [(topic("prices"), 1)]);
	}

	#[test]
	fn publish_accepted_with_draining_peer_is_ok() {
		let backplane = Local::default();
		let _draining = attached(&backplane, true);
		let live = attached(&backplane, false);

		let outcome = backplane.publish(&topic("prices"), b"tick");
		assert!(outcome.is_ok());
		assert_eq!(recorded(&live), [(topic("prices"), 1)]);
	}

	/// Hard-refusing sink used to prove multi-sink publish fails closed.
	struct Rejector;

	impl UpdateSink for Rejector {
		fn deliver(&self, _topic: &Topic, _order: u64, _payload: &[u8]) -> Result<(), DeliverError> {
			Err(DeliverError::Rejected)
		}
	}

	#[test]
	fn publish_hard_refusal_fails_even_when_a_peer_accepted() {
		let backplane = Local::default();
		let live = attached(&backplane, false);
		let rejector = Arc::new(Rejector);

		backplane.attach(Arc::downgrade(&rejector) as Weak<dyn UpdateSink>);

		let outcome = backplane.publish(&topic("prices"), b"tick");
		assert!(matches!(outcome, Err(BackplaneError::Refused(DeliverError::Rejected))));
		assert_eq!(recorded(&live), [(topic("prices"), 1)]);
		assert_eq!(backplane.last_order(&topic("prices")), 1);
	}
}
