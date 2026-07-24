//! Serve-side command dispatch: the wire's `sub/`, `unsub/`, and
//! (opt-in) `pub/` prefixes.
//!
//! The helper answers command frames and leaves everything else to the
//! application's own serve handler, so pub/sub composes with existing
//! routes instead of replacing them:
//!
//! ```ignore
//! responder.serve(move |frame| {
//!     let commands = commands.clone();
//!     async move {
//!         if let Some(answer) = commands.answer(connection, &frame) {
//!             return answer;
//!         }
//!         application_routes(frame).await
//!     }
//! });
//! ```
//!
//! Client publish is opt-in: without [`PubsubCommands::with_publish`],
//! `pub/` frames fall through to the application like any other stream.

use std::sync::Arc;

use tightbeam::policy::TransitStatus;
use tightbeam::transport::ResponsePackage;
use tightbeam::Frame;

use crate::frame::opaque_payload;
use crate::policy::{AccessVerdict, PublishPolicy, SubscribePolicy};
use crate::registry::{ConnectionId, PublishError, RegisterError, TopicRegistry};
use crate::topic::{Topic, PUB_PREFIX, SUB_PREFIX, UNSUB_PREFIX};

/// Answers `sub/` and `unsub/` command frames against one registry,
/// consulting a [`SubscribePolicy`] before any registration. With a
/// [`PublishPolicy`] installed ([`with_publish`](Self::with_publish)),
/// also answers `pub/` command frames.
pub struct PubsubCommands<P> {
	registry: TopicRegistry,
	policy: Arc<P>,
	publish: Option<Arc<dyn PublishPolicy>>,
}

impl<P> Clone for PubsubCommands<P> {
	fn clone(&self) -> Self {
		Self {
			registry: self.registry.clone(),
			policy: Arc::clone(&self.policy),
			publish: self.publish.clone(),
		}
	}
}

impl<P: SubscribePolicy> PubsubCommands<P> {
	/// Bind `registry` and `policy` into one dispatcher. Client publish
	/// stays off until [`with_publish`](Self::with_publish) installs a
	/// policy for it.
	pub fn new(registry: TopicRegistry, policy: P) -> Self {
		Self { registry, policy: Arc::new(policy), publish: None }
	}

	/// Enable the `pub/<topic>` command, authorized by `policy`.
	#[must_use]
	pub fn with_publish(mut self, policy: impl PublishPolicy + 'static) -> Self {
		self.publish = Some(Arc::new(policy));
		self
	}

	/// The registry this dispatcher answers against.
	pub fn registry(&self) -> &TopicRegistry {
		&self.registry
	}

	/// Answer `frame` when it is a pub/sub command; `None` hands the
	/// frame to the application's own routes.
	pub fn answer(&self, connection: ConnectionId, frame: &Frame) -> Option<ResponsePackage> {
		let id = frame.metadata.id.as_slice();
		if let Some(name) = id.strip_prefix(SUB_PREFIX.as_bytes()) {
			return Some(self.subscribe(connection, name));
		}
		if let Some(name) = id.strip_prefix(UNSUB_PREFIX.as_bytes()) {
			return Some(self.unsubscribe(connection, name));
		}
		if let Some(name) = id.strip_prefix(PUB_PREFIX.as_bytes()) {
			let policy = self.publish.as_deref()?;
			return Some(self.publish(policy, connection, name, frame));
		}

		None
	}

	/// Validate the topic and consult `authorize` for the connection's
	/// identity: the shared preamble of every policy-guarded command.
	fn authorized_topic(
		&self,
		connection: ConnectionId,
		name: &[u8],
		authorize: impl Fn(Option<&[u8]>, &Topic) -> AccessVerdict,
	) -> Result<Topic, ResponsePackage> {
		let Ok(topic) = Topic::try_from(name) else {
			return Err(refusal(TransitStatus::InvalidArgument));
		};

		/*
		 * A dropped (or never-admitted) connection has no standing:
		 * refusing here keeps revocation authoritative instead of
		 * degrading the caller to anonymous access.
		 */
		let Some(identity) = self.registry.member_identity(connection) else {
			return Err(refusal(TransitStatus::PermissionDenied));
		};

		let verdict = authorize(identity.as_deref(), &topic);
		if verdict == AccessVerdict::Forbid {
			return Err(refusal(TransitStatus::PermissionDenied));
		}

		Ok(topic)
	}

	/// Answer one `sub/<topic>` command.
	fn subscribe(&self, connection: ConnectionId, name: &[u8]) -> ResponsePackage {
		let authorized =
			self.authorized_topic(connection, name, |identity, topic| self.policy.authorize(identity, topic));
		let topic = match authorized {
			Ok(topic) => topic,
			Err(refused) => return refused,
		};

		match self.registry.register(connection, topic) {
			Ok(_) => accepted(),
			Err(RegisterError::Draining) => refusal(TransitStatus::Unavailable),
			// The connection dropped between authorization and
			// registration: the same no-standing refusal as the preamble.
			Err(RegisterError::UnknownConnection) => refusal(TransitStatus::PermissionDenied),
		}
	}

	/// Answer one `unsub/<topic>` command.
	///
	/// Idempotent like
	/// [MQTT 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
	/// § 3.11 UNSUBACK: unsubscribing a topic that was never subscribed
	/// still succeeds.
	fn unsubscribe(&self, connection: ConnectionId, name: &[u8]) -> ResponsePackage {
		let Ok(topic) = Topic::try_from(name) else {
			return refusal(TransitStatus::InvalidArgument);
		};

		self.registry.unregister(connection, &topic);
		accepted()
	}

	/// Answer one `pub/<topic>` command: authorize, lift the payload,
	/// publish through the registry.
	fn publish(
		&self,
		policy: &dyn PublishPolicy,
		connection: ConnectionId,
		name: &[u8],
		frame: &Frame,
	) -> ResponsePackage {
		let authorized = self.authorized_topic(connection, name, |identity, topic| policy.authorize(identity, topic));
		let topic = match authorized {
			Ok(topic) => topic,
			Err(refused) => return refused,
		};

		let Ok(payload) = opaque_payload(frame) else {
			return refusal(TransitStatus::InvalidArgument);
		};

		match self.registry.publish(&topic, payload) {
			Ok(()) => accepted(),
			Err(PublishError::Draining) => refusal(TransitStatus::Unavailable),
			// The frame id and payload already validated: a build failure
			// is a server-side fault, not something the client caused.
			Err(PublishError::Build(_)) => refusal(TransitStatus::Internal),
			Err(PublishError::Backplane(_)) => refusal(TransitStatus::Unavailable),
		}
	}
}

fn accepted() -> ResponsePackage {
	ResponsePackage::new(TransitStatus::Ok, None)
}

fn refusal(status: TransitStatus) -> ResponsePackage {
	ResponsePackage::new(status, None)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::frame::build;
	use crate::policy::AllowAll;
	use crate::testing::memory_mux_pair;

	/// Forbid every topic under `secrets/`.
	struct DenySecrets;

	impl SubscribePolicy for DenySecrets {
		fn authorize(&self, _identity: Option<&[u8]>, topic: &Topic) -> AccessVerdict {
			if topic.as_str().starts_with("secrets/") {
				return AccessVerdict::Forbid;
			}

			AccessVerdict::Allow
		}
	}

	/// Forbid every publish.
	struct DenyPublish;

	impl PublishPolicy for DenyPublish {
		fn authorize(&self, _identity: Option<&[u8]>, _topic: &Topic) -> AccessVerdict {
			AccessVerdict::Forbid
		}
	}

	fn topic(name: &str) -> Topic {
		name.parse().expect("test topics should parse")
	}

	fn command(id: &str) -> Frame {
		payload_command(id, &[])
	}

	fn payload_command(id: &str, payload: &[u8]) -> Frame {
		build(id, 1, payload).expect("command frames should build")
	}

	/// Answer `frame`, expecting the dispatcher to claim it.
	fn answered<P: SubscribePolicy>(
		commands: &PubsubCommands<P>,
		connection: ConnectionId,
		frame: &Frame,
	) -> ResponsePackage {
		commands
			.answer(connection, frame)
			.expect("the dispatcher should claim the command")
	}

	/// Quiesce the registry, expecting the signal to succeed.
	fn drained(registry: &TopicRegistry) {
		registry.quiesce().expect("quiesce should succeed");
	}

	/// A dispatcher over one registered in-memory connection. The guard
	/// keeps the peer transport alive.
	fn dispatcher<P: SubscribePolicy>(policy: P) -> (PubsubCommands<P>, TopicRegistry, ConnectionId, impl Sized) {
		let (client, server) = memory_mux_pair(4);
		let (handle, _reader, _writer, _responder) = server.into_parts();

		let registry = TopicRegistry::default();
		let connection = registry.register_connection(handle);
		let commands = PubsubCommands::new(registry.clone(), policy);
		(commands, registry, connection, client)
	}

	/// A dispatcher with client publish enabled.
	fn publisher<S, P>(policy: S, publish: P) -> (PubsubCommands<S>, TopicRegistry, ConnectionId, impl Sized)
	where
		S: SubscribePolicy,
		P: PublishPolicy + 'static,
	{
		let (commands, registry, connection, peer) = dispatcher(policy);
		(commands.with_publish(publish), registry, connection, peer)
	}

	/// The publish command the publish tests emit.
	fn tick_publish() -> Frame {
		payload_command("pub/prices", b"tick")
	}

	#[tokio::test]
	async fn subscribe_command_registers_and_accepts() {
		let (commands, registry, connection, _peer) = dispatcher(AllowAll);

		let answer = answered(&commands, connection, &command("sub/prices"));

		assert_eq!(answer.status(), TransitStatus::Ok);
		assert_eq!(registry.subscriber_count(&topic("prices")), 1);
	}

	#[tokio::test]
	async fn unsubscribe_command_forgets_and_accepts() {
		let (commands, registry, connection, _peer) = dispatcher(AllowAll);
		answered(&commands, connection, &command("sub/prices"));

		let answer = answered(&commands, connection, &command("unsub/prices"));
		assert_eq!(answer.status(), TransitStatus::Ok);
		assert_eq!(registry.subscriber_count(&topic("prices")), 0);
	}

	#[tokio::test]
	async fn unsubscribe_of_a_never_subscribed_topic_still_accepts() {
		let (commands, _registry, connection, _peer) = dispatcher(AllowAll);

		let answer = answered(&commands, connection, &command("unsub/prices"));
		assert_eq!(answer.status(), TransitStatus::Ok);
	}

	#[tokio::test]
	async fn forbidden_topic_answers_permission_denied() {
		let (commands, registry, connection, _peer) = dispatcher(DenySecrets);

		let answer = answered(&commands, connection, &command("sub/secrets/keys"));
		assert_eq!(answer.status(), TransitStatus::PermissionDenied);
		assert_eq!(registry.subscriber_count(&topic("secrets/keys")), 0);
	}

	#[tokio::test]
	async fn malformed_topic_answers_invalid_argument() {
		let (commands, _registry, connection, _peer) = dispatcher(AllowAll);

		let answer = answered(&commands, connection, &command("sub/"));
		assert_eq!(answer.status(), TransitStatus::InvalidArgument);
	}

	#[tokio::test]
	async fn draining_registry_answers_unavailable() {
		let (commands, registry, connection, _peer) = dispatcher(AllowAll);
		drained(&registry);

		let answer = answered(&commands, connection, &command("sub/prices"));
		assert_eq!(answer.status(), TransitStatus::Unavailable);
	}

	#[tokio::test]
	async fn non_command_frames_pass_through() {
		let (commands, _registry, connection, _peer) = dispatcher(AllowAll);

		let answer = commands.answer(connection, &command("prices"));
		assert!(answer.is_none());
	}

	#[tokio::test]
	async fn pub_command_passes_through_until_publish_is_enabled() {
		let (commands, _registry, connection, _peer) = dispatcher(AllowAll);

		let answer = commands.answer(connection, &command("pub/prices"));
		assert!(answer.is_none());
	}

	#[tokio::test]
	async fn pub_command_publishes_when_the_policy_allows() {
		let (commands, _registry, connection, _peer) = publisher(AllowAll, AllowAll);

		let answer = answered(&commands, connection, &tick_publish());
		assert_eq!(answer.status(), TransitStatus::Ok);
	}

	#[tokio::test]
	async fn commands_from_a_dropped_connection_answer_permission_denied() {
		let (commands, registry, connection, _peer) = publisher(AllowAll, AllowAll);
		registry.drop_connection(connection);

		let publish = answered(&commands, connection, &tick_publish());
		let subscribe = answered(&commands, connection, &command("sub/prices"));
		assert_eq!(publish.status(), TransitStatus::PermissionDenied);
		assert_eq!(subscribe.status(), TransitStatus::PermissionDenied);
	}

	#[tokio::test]
	async fn forbidden_publish_answers_permission_denied() {
		let (commands, _registry, connection, _peer) = publisher(AllowAll, DenyPublish);

		let answer = answered(&commands, connection, &tick_publish());
		assert_eq!(answer.status(), TransitStatus::PermissionDenied);
	}

	#[tokio::test]
	async fn malformed_publish_topic_answers_invalid_argument() {
		let (commands, _registry, connection, _peer) = publisher(AllowAll, AllowAll);

		let answer = answered(&commands, connection, &command("pub/"));
		assert_eq!(answer.status(), TransitStatus::InvalidArgument);
	}

	#[tokio::test]
	async fn publish_to_a_draining_registry_answers_unavailable() {
		let (commands, registry, connection, _peer) = publisher(AllowAll, AllowAll);
		drained(&registry);

		let answer = answered(&commands, connection, &tick_publish());
		assert_eq!(answer.status(), TransitStatus::Unavailable);
	}
}
