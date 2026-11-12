//! The policies that a registry and its commands consult. The page
//! `docs/pubsub.md` (Delivery policy, Access policies) states each one.

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

/// Decides the fate of an update that finds the queue of its subscriber, or
/// the byte budget of its connection, full.
///
/// The registry asks with no registry lock held, during a delivery of its
/// backplane, and lends a [`RegistryView`] for the reads a verdict weighs.
pub trait DeliveryPolicy: Send + Sync {
	/// One update does not fit `topic`'s queue for a subscriber that has
	/// already dropped `dropped_so_far` updates. Return the verdict.
	fn on_full(&self, registry: RegistryView<'_>, topic: &Topic, dropped_so_far: u64) -> DeliveryVerdict;
}

/// The default policy: always drop the oldest queued update, so the newest
/// state wins and the gate of the client reports the loss.
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
/// - `session` names the peer that the handshake of the connection proved. A mutual-auth peer
///   carries its validated certificate ([`SessionContext::peer_certificate`]), and an anonymous
///   peer carries none.
/// - The dispatcher lends a [`RegistryView`] for the reads a verdict weighs.
pub trait SubscribePolicy: Send + Sync {
	/// May the peer of `session` subscribe to `topic`?
	fn authorize(&self, registry: RegistryView<'_>, session: &SessionContext, topic: &Topic) -> AccessVerdict;
}

/// Owns the `PermissionDenied` decision for `pub/` commands.
///
/// - [`PubsubCommands`](crate::PubsubCommands) answers `pub/` frames once
///   [`with_publish`](crate::PubsubCommands::with_publish) installs a publish policy.
/// - `session` and the [`RegistryView`] read as they do for a [`SubscribePolicy`].
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

		let verdict = policy.on_full(
			registry.view(),
			&"prices".parse::<Topic>().expect("the name should be a topic"),
			7,
		);
		assert_eq!(verdict, DeliveryVerdict::DropOldest);
	}

	#[test]
	fn allow_all_allows_subscriptions_without_a_peer() {
		let policy = AllowAll;
		let registry = TopicRegistry::default();
		let anonymous = SessionContext::default();

		let verdict = SubscribePolicy::authorize(
			&policy,
			registry.view(),
			&anonymous,
			&"prices".parse::<Topic>().expect("the name should be a topic"),
		);
		assert_eq!(verdict, AccessVerdict::Allow);
	}

	#[test]
	fn allow_all_allows_publishes_without_a_peer() {
		let policy = AllowAll;
		let registry = TopicRegistry::default();
		let anonymous = SessionContext::default();

		let verdict = PublishPolicy::authorize(
			&policy,
			registry.view(),
			&anonymous,
			&"prices".parse::<Topic>().expect("the name should be a topic"),
		);
		assert_eq!(verdict, AccessVerdict::Allow);
	}
}
