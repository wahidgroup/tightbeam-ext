//! Behavioral seams for delivery saturation and topic access authorization.
//!
//! Every trait follows the core hook style: a small object the application
//! installs once, consulted at the relevant decision point.

use tightbeam::policy::SessionContext;

use crate::registry::RegistryView;
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
/// This crate has no per-subscription credit, so a full queue, or a full
/// byte budget of the connection, is the only backpressure signal. Every
/// drop is a guaranteed gap at the client's gate.
///
/// The registry asks with no registry lock held, and lends a
/// [`RegistryView`] for the reads a verdict weighs. The backplane may still
/// hold its own lock, as [`Local`](crate::Local) does while it delivers, so a
/// policy MUST NOT publish, quiesce, or make any other call that reaches the
/// backplane.
pub trait DeliveryPolicy: Send + Sync {
	/// One update does not fit `topic`'s queue for a subscriber that has
	/// already dropped `dropped_so_far` updates. Return the verdict.
	fn on_full(&self, registry: RegistryView<'_>, topic: &Topic, dropped_so_far: u64) -> DeliveryVerdict;
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
	fn on_full(&self, _registry: RegistryView<'_>, _topic: &Topic, _dropped_so_far: u64) -> DeliveryVerdict {
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
/// `session` names the peer that the handshake of the connection proved. A
/// mutual-auth peer carries its validated certificate
/// ([`SessionContext::peer_certificate`]), and an anonymous peer carries none.
/// Without this hook the wire's `PermissionDenied` answer has no author.
///
/// The dispatcher lends a [`RegistryView`] for the reads a verdict weighs.
pub trait SubscribePolicy: Send + Sync {
	/// May the peer of `session` subscribe to `topic`?
	fn authorize(&self, registry: RegistryView<'_>, session: &SessionContext, topic: &Topic) -> AccessVerdict;
}

/// Owns the `PermissionDenied` decision for `pub/` commands.
///
/// Client publish is opt-in: [`PubsubCommands`](crate::PubsubCommands)
/// only answers `pub/` frames once a publish policy is installed with
/// [`with_publish`](crate::PubsubCommands::with_publish). `session` names the
/// peer as it does for a [`SubscribePolicy`], and the dispatcher lends a
/// [`RegistryView`] for the reads a verdict weighs.
pub trait PublishPolicy: Send + Sync {
	/// May the peer of `session` publish to `topic`?
	fn authorize(&self, registry: RegistryView<'_>, session: &SessionContext, topic: &Topic) -> AccessVerdict;
}

/// The default policy: every subscription (and, when installed as a
/// [`PublishPolicy`], every publish) is allowed.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAll;

impl SubscribePolicy for AllowAll {
	fn authorize(&self, _registry: RegistryView<'_>, _session: &SessionContext, _topic: &Topic) -> AccessVerdict {
		AccessVerdict::Allow
	}
}

impl PublishPolicy for AllowAll {
	fn authorize(&self, _registry: RegistryView<'_>, _session: &SessionContext, _topic: &Topic) -> AccessVerdict {
		AccessVerdict::Allow
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::registry::TopicRegistry;

	#[test]
	fn drop_oldest_always_drops_the_oldest() {
		let policy = DropOldest;
		let registry = TopicRegistry::default();

		let verdict = policy.on_full(registry.view(), &Topic::fixture("prices"), 7);
		assert_eq!(verdict, DeliveryVerdict::DropOldest);
	}

	#[test]
	fn allow_all_allows_subscriptions_without_a_peer() {
		let policy = AllowAll;
		let registry = TopicRegistry::default();
		let anonymous = SessionContext::default();

		let verdict = SubscribePolicy::authorize(&policy, registry.view(), &anonymous, &Topic::fixture("prices"));
		assert_eq!(verdict, AccessVerdict::Allow);
	}

	#[test]
	fn allow_all_allows_publishes_without_a_peer() {
		let policy = AllowAll;
		let registry = TopicRegistry::default();
		let anonymous = SessionContext::default();

		let verdict = PublishPolicy::authorize(&policy, registry.view(), &anonymous, &Topic::fixture("prices"));
		assert_eq!(verdict, AccessVerdict::Allow);
	}
}
