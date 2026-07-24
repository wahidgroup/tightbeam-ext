//! The backplane: per-topic sequencing and update distribution.
//!
//! [`TopicRegistry`](crate::TopicRegistry) owns local fan-out (lanes,
//! queues, delivery policies) and delegates two decisions here: who
//! assigns the dense per-topic `order`, and how a publish reaches other
//! nodes. [`Local`] answers both in process and is the default; a
//! Redis/Postgres/NATS implementation swaps in through
//! [`RegistryOptions`](crate::RegistryOptions) without touching the wire
//! format or the TypeScript client.
//!
//! # Contract
//!
//! - Orders MUST be dense (`1, 2, 3, ...`) per topic across every node:
//!   the client `TopicGate` reads a hole as message loss and reports a
//!   gap. Redis `INCR`/`XADD` qualify; raw Postgres sequences do not
//!   (rollbacks leave holes) - use a locked counter row instead.
//! - Deliveries for one topic MUST NOT run concurrently: the registry
//!   relies on arrival order matching stamp order. [`Local`] holds its
//!   lock across delivery; a remote implementation gets this from a
//!   single consumer task.
//! - Every attached sink observes every update, including the publishing
//!   node's own.

use core::fmt;
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Mutex, MutexGuard, PoisonError, Weak};

use tightbeam::TightBeamError;

use crate::topic::Topic;

/// Why a node refused one sequenced update.
#[derive(Debug)]
pub enum DeliverError {
	/// The node is quiescing: its topics already completed.
	Draining,
	/// The update frame failed to build.
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
/// construction; the backplane calls back with every sequenced update.
pub trait UpdateSink: Send + Sync {
	/// Fan `payload` out to this node's subscribers of `topic` at the
	/// backplane-assigned `order`.
	fn deliver(&self, topic: &Topic, order: u64, payload: &[u8]) -> Result<(), DeliverError>;
}

/// Per-topic sequencing and distribution behind the registry.
pub trait Backplane: Send + Sync {
	/// Attach one node's delivery hook. Weak: a dropped registry falls
	/// out of distribution on its own.
	fn attach(&self, sink: Weak<dyn UpdateSink>);

	/// Assign the next dense order for `topic` and distribute `payload`
	/// to every attached node.
	fn publish(&self, topic: &Topic, payload: &[u8]) -> Result<(), BackplaneError>;
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

		/*
		 * Ok when any node accepted: the first refusal only surfaces when
		 * every node refused (single-node: exact publish semantics).
		 */
		let mut delivered_any = false;
		let mut first_refusal = None;
		state.sinks.retain(|entry| {
			let Some(sink) = entry.upgrade() else {
				return false;
			};
			match sink.deliver(topic, order, payload) {
				Ok(()) => delivered_any = true,
				Err(cause) => {
					if first_refusal.is_none() {
						first_refusal = Some(cause);
					}
				}
			}
			true
		});

		state.orders.insert(topic.clone(), order);

		match first_refusal {
			Some(refusal) if !delivered_any => Err(BackplaneError::Refused(refusal)),
			_ => Ok(()),
		}
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

	/// Records every delivery; refuses once `draining` flips.
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
	fn publish_accepted_anywhere_is_ok() {
		let backplane = Local::default();
		let _draining = attached(&backplane, true);
		let live = attached(&backplane, false);

		let outcome = backplane.publish(&topic("prices"), b"tick");
		assert!(outcome.is_ok());
		assert_eq!(recorded(&live), [(topic("prices"), 1)]);
	}
}
