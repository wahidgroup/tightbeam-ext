//! Behavioral seams for delivery saturation and topic access authorization.
//!
//! Every trait follows the core hook style: a small object the application
//! installs once, consulted at the relevant decision point.

use crate::topic::Topic;

/// What to do when a subscriber's bounded update queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryVerdict {
	/// Drop the oldest queued update to make room for the new one.
	DropOldest,
	/// Drop the new update and keep the queue as is.
	DropNew,
	/// Drop the subscriber's whole connection: it is beyond catching up.
	Disconnect,
}

/// Decides the fate of an update when a subscriber queue is full.
///
/// This crate has no per-subscription credit, so a full queue is the only
/// backpressure signal. Every drop is a guaranteed gap at the client's gate.
pub trait DeliveryPolicy: Send + Sync {
	/// One update does not fit `topic`'s queue for a subscriber that has
	/// already dropped `dropped_so_far` updates. Return the verdict.
	fn on_full(&self, topic: &Topic, dropped_so_far: u64) -> DeliveryVerdict;
}

/// The default policy: always drop the oldest queued update.
///
/// Bounded-queue drop-oldest matches common broker practice: the newest
/// state wins, and the client's gap detection reports what was lost.
///
/// # Sources
///
/// - MQTT 5.0, broker queueing practice (topic vocabulary and delivery):
///   <https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html>
///
#[derive(Debug, Default, Clone, Copy)]
pub struct DropOldest;

impl DeliveryPolicy for DropOldest {
	fn on_full(&self, _topic: &Topic, _dropped_so_far: u64) -> DeliveryVerdict {
		DeliveryVerdict::DropOldest
	}
}

/// Whether a connection may perform the guarded action on a topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessVerdict {
	/// Proceed.
	Allow,
	/// Refuse with `PermissionDenied`.
	Forbid,
}

/// Owns the `PermissionDenied` decision for `sub/` commands.
///
/// `identity` is whatever the application attached at connection
/// registration. A mutual-auth transport identity is the expected source.
/// Without this hook the wire's `PermissionDenied` answer has no author.
pub trait SubscribePolicy: Send + Sync {
	/// May the connection carrying `identity` subscribe to `topic`?
	fn authorize(&self, identity: Option<&[u8]>, topic: &Topic) -> AccessVerdict;
}

/// Owns the `PermissionDenied` decision for `pub/` commands.
///
/// Client publish is opt-in: [`PubsubCommands`](crate::PubsubCommands)
/// only answers `pub/` frames once a publish policy is installed with
/// [`with_publish`](crate::PubsubCommands::with_publish).
pub trait PublishPolicy: Send + Sync {
	/// May the connection carrying `identity` publish to `topic`?
	fn authorize(&self, identity: Option<&[u8]>, topic: &Topic) -> AccessVerdict;
}

/// The default policy: every subscription (and, when installed as a
/// [`PublishPolicy`], every publish) is allowed.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAll;

impl SubscribePolicy for AllowAll {
	fn authorize(&self, _identity: Option<&[u8]>, _topic: &Topic) -> AccessVerdict {
		AccessVerdict::Allow
	}
}

impl PublishPolicy for AllowAll {
	fn authorize(&self, _identity: Option<&[u8]>, _topic: &Topic) -> AccessVerdict {
		AccessVerdict::Allow
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn topic(name: &str) -> Topic {
		name.parse().expect("test topics should parse")
	}

	#[test]
	fn drop_oldest_always_drops_the_oldest() {
		let policy = DropOldest;

		let verdict = policy.on_full(&topic("prices"), 7);
		assert_eq!(verdict, DeliveryVerdict::DropOldest);
	}

	#[test]
	fn allow_all_allows_subscriptions_without_identity() {
		let policy = AllowAll;

		let verdict = SubscribePolicy::authorize(&policy, None, &topic("prices"));
		assert_eq!(verdict, AccessVerdict::Allow);
	}

	#[test]
	fn allow_all_allows_publishes_without_identity() {
		let policy = AllowAll;

		let verdict = PublishPolicy::authorize(&policy, None, &topic("prices"));
		assert_eq!(verdict, AccessVerdict::Allow);
	}
}
