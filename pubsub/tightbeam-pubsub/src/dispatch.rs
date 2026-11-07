//! Serve-side command dispatch: the wire's `sub/`, `unsub/`, and
//! (opt-in) `pub/` prefixes.
//!
//! [`PubsubCommands::answer`] answers command frames and leaves everything
//! else to the application, so pub/sub composes with existing routes instead
//! of replacing them. [`PubsubCommands::serve`] runs that composition for one
//! whole connection: the mux drivers, a keepalive, the transport gate,
//! registration, dispatch, and cleanup.
//!
//! Client publish is opt-in: without [`PubsubCommands::with_publish`],
//! `pub/` frames fall through to the application like any other stream.

use core::future::Future;
use core::marker::PhantomData;
use std::sync::Arc;

use tightbeam::marker::MaybeSend;
use tightbeam::policy::{SessionContext, TransitStatus};
use tightbeam::transport::io::{EnvelopeSink, EnvelopeSource};
use tightbeam::transport::multiplex::MuxDispatch;
use tightbeam::transport::{ResponsePackage, TransportResult};
use tightbeam::{Frame, Opaque};
use tightbeam_ws::serve::AcceptedLink;

use crate::policy::{AccessVerdict, PublishPolicy, SubscribePolicy};
use crate::registry::{ConnectionId, PublishError, RegisterError, RegistryView, TopicRegistry};
use crate::serve::{AppRoutes, ConnectionContext};
use crate::topic::{Topic, PUB_PREFIX, SUB_PREFIX, UNSUB_PREFIX};

/// Why one wire command took no effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandRefusal {
	/// The topic name or the publish body does not parse.
	Malformed,
	/// The caller has no standing, or a policy forbids the topic to it.
	Forbidden,
	/// The registry drains, or the distribution fabric of its backplane failed.
	Unavailable,
	/// The connection holds its cap of subscriptions, or the backplane holds
	/// its limit of topics.
	ResourceExhausted,
	/// The update frame of an authorized publish failed to build.
	Internal,
}

impl CommandRefusal {
	/// The status of the empty answer that carries this refusal.
	fn status(self) -> TransitStatus {
		match self {
			Self::Malformed => TransitStatus::InvalidArgument,
			Self::Forbidden => TransitStatus::PermissionDenied,
			Self::Unavailable => TransitStatus::Unavailable,
			Self::ResourceExhausted => TransitStatus::ResourceExhausted,
			Self::Internal => TransitStatus::Internal,
		}
	}
}

impl From<RegisterError> for CommandRefusal {
	/// The refusal a `sub/` meets for each registration failure.
	fn from(error: RegisterError) -> Self {
		match error {
			RegisterError::Draining => Self::Unavailable,
			RegisterError::LimitReached => Self::ResourceExhausted,
			// The connection dropped between authorization and registration:
			// the same no-standing refusal as an unknown caller.
			RegisterError::UnknownConnection => Self::Forbidden,
		}
	}
}

impl From<PublishError> for CommandRefusal {
	/// The refusal a `pub/` meets for each publish failure.
	fn from(error: PublishError) -> Self {
		match error {
			PublishError::Draining => Self::Unavailable,
			// The frame id and payload already validated: a build failure is a
			// server-side fault, not something the client caused.
			PublishError::Build(_) => Self::Internal,
			// The topic limit clears once a topic loses its last member.
			PublishError::TopicLimit => Self::ResourceExhausted,
			PublishError::Unavailable(_) => Self::Unavailable,
		}
	}
}

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

	/// Answer `frame` when it is a pub/sub command. `None` hands the
	/// frame to the application's own routes.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::policy::TransitStatus;
	/// use tightbeam::transport::ResponsePackage;
	/// use tightbeam::Frame;
	/// use tightbeam_pubsub::{AllowAll, ConnectionContext, PubsubCommands};
	///
	/// /// Answer the commands of `context` first, and every other stream
	/// /// with `NotFound`.
	/// fn route(
	///     commands: &PubsubCommands<AllowAll>,
	///     context: &ConnectionContext,
	///     frame: &Arc<Frame>,
	/// ) -> ResponsePackage {
	///     let answered = commands.answer(context.connection(), frame);
	///     answered.unwrap_or_else(|| ResponsePackage::new(TransitStatus::NotFound, None))
	/// }
	/// ```
	pub fn answer(&self, connection: ConnectionId, frame: &Frame) -> Option<ResponsePackage> {
		let outcome = self.command(connection, frame)?;
		let status = outcome.map_or_else(CommandRefusal::status, |()| TransitStatus::Ok);
		let answer = ResponsePackage::new(status, None);
		Some(answer)
	}

	/// Run `frame` when it is a pub/sub command, and return whether the
	/// command took effect. `None` leaves the frame to the application.
	fn command(&self, connection: ConnectionId, frame: &Frame) -> Option<Result<(), CommandRefusal>> {
		let id = frame.metadata().id();
		if let Some(name) = id.strip_prefix(SUB_PREFIX.as_bytes()) {
			let subscribed = self.subscribe(connection, name);
			return Some(subscribed);
		}
		if let Some(name) = id.strip_prefix(UNSUB_PREFIX.as_bytes()) {
			let unsubscribed = self.unsubscribe(connection, name);
			return Some(unsubscribed);
		}
		if let Some(name) = id.strip_prefix(PUB_PREFIX.as_bytes()) {
			let policy = self.publish.as_deref()?;
			let published = self.publish(policy, connection, name, frame);
			return Some(published);
		}

		None
	}

	/// Validate the topic and consult `authorize` for the connection's
	/// session: the shared preamble of every policy-guarded command.
	fn authorized_topic(
		&self,
		connection: ConnectionId,
		name: &[u8],
		authorize: impl Fn(RegistryView<'_>, &SessionContext, &Topic) -> AccessVerdict,
	) -> Result<Topic, CommandRefusal> {
		let Ok(topic) = Topic::try_from(name) else {
			return Err(CommandRefusal::Malformed);
		};

		/*
		 * A dropped (or never-admitted) connection has no standing:
		 * refusing here keeps revocation authoritative instead of
		 * degrading the caller to anonymous access.
		 */
		let view = self.registry.view();
		let Some(session) = view.session(connection) else {
			return Err(CommandRefusal::Forbidden);
		};

		let verdict = authorize(view, &session, &topic);
		if verdict == AccessVerdict::Forbid {
			return Err(CommandRefusal::Forbidden);
		}

		Ok(topic)
	}

	/// Run one `sub/<topic>` command.
	fn subscribe(&self, connection: ConnectionId, name: &[u8]) -> Result<(), CommandRefusal> {
		let authorized = self.authorized_topic(connection, name, |view, session, topic| {
			self.policy.authorize(view, session, topic)
		});
		let topic = authorized?;

		self.registry.register(connection, topic)?;
		Ok(())
	}

	/// Run one `unsub/<topic>` command.
	///
	/// Idempotent like MQTT UNSUBACK: unsubscribing a topic that was never
	/// subscribed still succeeds.
	///
	/// # Sources
	///
	/// - MQTT 5.0 § 3.11, UNSUBACK:
	///   <https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html>
	fn unsubscribe(&self, connection: ConnectionId, name: &[u8]) -> Result<(), CommandRefusal> {
		let Ok(topic) = Topic::try_from(name) else {
			return Err(CommandRefusal::Malformed);
		};

		self.registry.unregister(connection, &topic);
		Ok(())
	}

	/// Run one `pub/<topic>` command: authorize, lift the payload, publish
	/// through the registry.
	fn publish(
		&self,
		policy: &dyn PublishPolicy,
		connection: ConnectionId,
		name: &[u8],
		frame: &Frame,
	) -> Result<(), CommandRefusal> {
		let authorized =
			self.authorized_topic(connection, name, |view, session, topic| policy.authorize(view, session, topic));
		let topic = authorized?;

		let Ok(body) = frame.decode_message::<Opaque>() else {
			return Err(CommandRefusal::Malformed);
		};

		self.registry.publish(&topic, body.as_bytes())?;
		Ok(())
	}
}

impl<P: SubscribePolicy + 'static> PubsubCommands<P> {
	/// Serve one multiplexed connection over `link` until it ends.
	///
	/// - The mux of the link runs its drivers beside the serve loop, with a keepalive that paces
	///   its probes to the operation timeout of the link ([`MuxHandle::keep_alive`]).
	/// - Every stream passes the transport gate of the link first. Wire commands then answer
	///   through [`answer`](Self::answer), and every other stream goes to `app` with the
	///   [`ConnectionContext`] of the connection.
	/// - The connection registers on entry under the peer its handshake proved, so the policies
	///   authorize the authenticated caller. Every emit deadline of its subscriptions runs on the
	///   clock of the writer of the link.
	/// - A connection that the delivery policy votes off drains with an `EnhanceYourCalm` GoAway.
	/// - When the future completes or drops, the connection leaves the registry with all its
	///   subscriptions, and the drivers and the keepalive end.
	///
	/// # Errors
	///
	/// - [`TransportError`](tightbeam::transport::TransportError): the serve loop of the responder
	///   failed. The connection leaves the registry before the error returns.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::transport::multiplex::MuxAcceptor;
	/// use tightbeam_pubsub::{AllowAll, PubsubCommands, Unrouted};
	/// use tightbeam_ws::serve::AcceptedLink;
	///
	/// /// Serve `transport` until it ends, once its server handshake
	/// /// negotiated multiplexing.
	/// async fn serve<T>(
	///     commands: &PubsubCommands<AllowAll>,
	///     mut transport: T,
	/// ) -> Result<(), Box<dyn std::error::Error>>
	/// where
	///     T: MuxAcceptor,
	///     T::EnvelopeReader: Send,
	///     T::EnvelopeWriter: Send,
	/// {
	///     transport.negotiate_mux().await?;
	///     let link = AcceptedLink::accepted(transport)?;
	///     commands.serve(link, Unrouted).await?;
	///     Ok(())
	/// }
	/// ```
	///
	/// [`MuxHandle::keep_alive`]: tightbeam::transport::multiplex::MuxHandle::keep_alive
	pub async fn serve<R, W, A, F>(&self, link: AcceptedLink<R, W>, app: A) -> TransportResult<()>
	where
		R: EnvelopeSource + Send + 'static,
		W: EnvelopeSink + Send + 'static,
		A: AppRoutes<F>,
		F: Future<Output = ResponsePackage> + Send + 'static,
	{
		let served = link.spawn();
		let mut membership = self.registry.admit(&served);
		let context = ConnectionContext::of(&served, membership.connection());

		let routes = CommandRoutes { commands: self.clone(), app, context, routed: PhantomData };
		let expelled = membership.expelled();
		served.serve(routes, expelled).await
	}
}

/// The unary routes of one served connection: the wire commands first, then
/// the application.
///
/// The responder serves unary streams alone, so a streaming or duplex stream
/// answers `Unimplemented` through the defaults of [`MuxDispatch`].
struct CommandRoutes<P, A, F> {
	commands: PubsubCommands<P>,
	app: A,
	context: ConnectionContext,
	/// The future type of the routes of `app`.
	routed: PhantomData<fn() -> F>,
}

impl<P, A, F> MuxDispatch for CommandRoutes<P, A, F>
where
	P: SubscribePolicy + 'static,
	A: AppRoutes<F>,
	F: Future<Output = ResponsePackage> + Send + 'static,
{
	fn unary(&self, frame: Arc<Frame>) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		let commands = self.commands.clone();
		let app = self.app.clone();
		let context = self.context.clone();
		async move {
			let connection = context.connection();
			if let Some(answer) = commands.answer(connection, &frame) {
				return Ok(answer);
			}

			let routed = app.route(context, frame).await;
			Ok(routed)
		}
	}
}

#[cfg(test)]
mod tests {
	use core::num::NonZeroUsize;

	use tightbeam::transport::handshake::negotiation::MuxSettings;

	use super::*;
	use crate::backplane::{Backplane, Local, NodeSink};
	use crate::frame::OpaqueFrame;
	use crate::policy::AllowAll;
	use crate::registry::RegistryOptions;
	use crate::testing::faults::Rejector;
	use crate::testing::MemoryLink;

	/// Forbid every topic under `secrets/`.
	struct DenySecrets;

	impl SubscribePolicy for DenySecrets {
		fn authorize(&self, _registry: RegistryView<'_>, _session: &SessionContext, topic: &Topic) -> AccessVerdict {
			if topic.as_str().starts_with("secrets/") {
				return AccessVerdict::Forbid;
			}

			AccessVerdict::Allow
		}
	}

	/// Forbid every publish.
	struct DenyPublish;

	impl PublishPolicy for DenyPublish {
		fn authorize(&self, _registry: RegistryView<'_>, _session: &SessionContext, _topic: &Topic) -> AccessVerdict {
			AccessVerdict::Forbid
		}
	}

	fn command(id: &str) -> Frame {
		payload_command(id, &[])
	}

	fn payload_command(id: &str, payload: &[u8]) -> Frame {
		let frame = OpaqueFrame { id, order: 1, payload };
		frame.build().expect("command frames should build")
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

	/// A dispatcher over one admitted in-memory connection. The guard keeps
	/// the registration and the peer transport alive, and its drop leaves the
	/// registry.
	fn dispatcher<P: SubscribePolicy>(policy: P) -> (PubsubCommands<P>, TopicRegistry, ConnectionId, impl Sized) {
		dispatcher_with(policy, RegistryOptions::default())
	}

	/// As [`dispatcher`], with explicit registry options.
	fn dispatcher_with<P: SubscribePolicy>(
		policy: P,
		options: RegistryOptions,
	) -> (PubsubCommands<P>, TopicRegistry, ConnectionId, impl Sized) {
		let link = MemoryLink::default();
		let served = link.served(MuxSettings::symmetric(4));
		let (client, server) = served.expect("a link on the system clock races on a tokio thread");
		let served = server.spawn();

		let registry = TopicRegistry::new(options);
		let membership = registry.admit(&served);
		let connection = membership.connection();
		let commands = PubsubCommands::new(registry.clone(), policy);
		(commands, registry, connection, (membership, served, client))
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

	/// A publish command whose body is sealed to a key the server lacks, so
	/// it does not decode as an opaque payload.
	fn sealed_publish() -> Frame {
		let frame = OpaqueFrame { id: "pub/prices", order: 1, payload: b"tick" };
		frame.sealed(&[7; 32], b"absent").expect("sealed command frames should build")
	}

	#[tokio::test]
	async fn subscribe_command_registers_and_accepts() {
		let (commands, registry, connection, _peer) = dispatcher(AllowAll);
		let answer = answered(&commands, connection, &command("sub/prices"));
		assert_eq!(answer.status(), TransitStatus::Ok);
		assert_eq!(registry.view().subscriber_count(&Topic::fixture("prices")), 1);
	}

	#[tokio::test]
	async fn unsubscribe_command_forgets_and_accepts() {
		let (commands, registry, connection, _peer) = dispatcher(AllowAll);
		answered(&commands, connection, &command("sub/prices"));

		let answer = answered(&commands, connection, &command("unsub/prices"));
		assert_eq!(answer.status(), TransitStatus::Ok);
		assert_eq!(registry.view().subscriber_count(&Topic::fixture("prices")), 0);
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
		assert_eq!(registry.view().subscriber_count(&Topic::fixture("secrets/keys")), 0);
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
	async fn over_quota_subscribe_answers_resource_exhausted() {
		let options = RegistryOptions {
			max_subscriptions_per_connection: NonZeroUsize::MIN,
			..RegistryOptions::default()
		};
		let (commands, _registry, connection, _peer) = dispatcher_with(AllowAll, options);
		assert_eq!(
			answered(&commands, connection, &command("sub/prices")).status(),
			TransitStatus::Ok
		);
		assert_eq!(
			answered(&commands, connection, &command("sub/chat")).status(),
			TransitStatus::ResourceExhausted
		);
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
		let (commands, _registry, connection, peer) = publisher(AllowAll, AllowAll);
		drop(peer);

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
	async fn a_publish_body_that_does_not_decode_answers_invalid_argument() {
		let (commands, _registry, connection, _peer) = publisher(AllowAll, AllowAll);
		let answer = answered(&commands, connection, &sealed_publish());
		assert_eq!(answer.status(), TransitStatus::InvalidArgument);
	}

	#[tokio::test]
	async fn a_backplane_topic_limit_answers_resource_exhausted() {
		let backplane: Arc<dyn Backplane> = Arc::new(Local::default().with_max_topics(NonZeroUsize::MIN));
		let options = RegistryOptions { backplane, ..RegistryOptions::default() };
		let (commands, _registry, connection, _peer) = dispatcher_with(AllowAll, options);
		let commands = commands.with_publish(AllowAll);
		answered(&commands, connection, &command("sub/prices"));
		answered(&commands, connection, &tick_publish());

		let answer = answered(&commands, connection, &payload_command("pub/chat", b"tick"));
		assert_eq!(answer.status(), TransitStatus::ResourceExhausted);
	}

	#[tokio::test]
	async fn a_publish_whose_update_frame_fails_to_build_answers_internal() {
		let local = Local::default();
		let rejector = Arc::new(Rejector);
		local.attach(NodeSink::from(&rejector));

		let backplane: Arc<dyn Backplane> = Arc::new(local);
		let options = RegistryOptions { backplane, ..RegistryOptions::default() };
		let (commands, _registry, connection, _peer) = dispatcher_with(AllowAll, options);
		let commands = commands.with_publish(AllowAll);

		let answer = answered(&commands, connection, &tick_publish());
		assert_eq!(answer.status(), TransitStatus::Internal);
	}

	#[tokio::test]
	async fn publish_to_a_draining_registry_answers_unavailable() {
		let (commands, registry, connection, _peer) = publisher(AllowAll, AllowAll);
		drained(&registry);

		let answer = answered(&commands, connection, &tick_publish());
		assert_eq!(answer.status(), TransitStatus::Unavailable);
	}
}
