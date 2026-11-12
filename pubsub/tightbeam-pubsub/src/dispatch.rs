//! The client commands of a served connection, and its serve. The page
//! `docs/pubsub.md` (Connection serve) states each step.

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

use crate::backplane::PublishError;
use crate::policy::{AccessVerdict, PublishPolicy, SubscribePolicy};
use crate::registry::{Member, RegisterError, RegistryView, TopicRegistry};
use crate::serve::{AppRoutes, ConnectionContext};
use crate::topic::{Topic, TopicError, Verb};

/// The topic that a client command names, or the refusal of the name.
type Named = Result<Topic, TopicError>;

/// The constructor of one kind of client command.
type Kind = fn(Named) -> ClientCommand;

/// A client command, parsed once from the id of its frame: its kind, and
/// the topic it names or the refusal of the name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClientCommand {
	/// `sub/<topic>`: subscribe.
	Subscribe(Named),
	/// `unsub/<topic>`: unsubscribe. The page `docs/pubsub.md` (Command
	/// convention) states each answer.
	Unsubscribe(Named),
	/// `pub/<topic>`: publish the body of the frame.
	Publish(Named),
}

impl ClientCommand {
	/// Each kind of client command, with the verb whose prefix names it.
	const KINDS: [(Verb, Kind); 3] = [
		(Verb::Subscribe, Self::Subscribe),
		(Verb::Unsubscribe, Self::Unsubscribe),
		(Verb::Publish, Self::Publish),
	];

	/// The command that `id` names, with the verb whose audit record names
	/// it, or `None` for an id no client command claims.
	fn parse(id: &[u8]) -> Option<(Verb, Self)> {
		Self::KINDS.into_iter().find_map(|(verb, command)| {
			let name = id.strip_prefix(verb.prefix().as_bytes())?;
			Some((verb, command(Topic::try_from(name))))
		})
	}

	/// Run this command of `member`, which `frame` carries, through
	/// `commands`, and answer whether it took effect. `None` is the answer of
	/// [`PubsubCommands::publish`] for a `pub/` that it hands on.
	async fn run<P: SubscribePolicy>(
		self,
		commands: &PubsubCommands<P>,
		member: &Member,
		frame: &Frame,
	) -> Option<Result<(), CommandRefusal>> {
		match self {
			Self::Subscribe(named) => Some(commands.subscribe(member, named)),
			Self::Unsubscribe(named) => {
				let unsubscribed = match named {
					Ok(topic) => {
						member.unsubscribe(&topic).await;
						Ok(())
					}
					Err(refusal) => Err(CommandRefusal::from(refusal)),
				};
				Some(unsubscribed)
			}
			Self::Publish(named) => commands.publish(member, named, frame).await,
		}
	}
}

/// Why one command took no effect.
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

impl From<TopicError> for CommandRefusal {
	/// The refusal a command meets for a name that is no topic.
	fn from(_error: TopicError) -> Self {
		Self::Malformed
	}
}

impl From<RegisterError> for CommandRefusal {
	/// The refusal a `sub/` meets for each registration failure.
	fn from(error: RegisterError) -> Self {
		match error {
			RegisterError::Draining => Self::Unavailable,
			RegisterError::LimitReached => Self::ResourceExhausted,
			// The connection left between authorization and registration:
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
			// The command already validated, so a failed build is a fault of
			// the server.
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

	/// Answer `frame` of `member` when it is a pub/sub command, and record
	/// each refusal on the audit trail of the connection. `None` hands the
	/// frame to the application's own routes.
	pub(crate) async fn answer(&self, member: &Member, frame: &Frame) -> Option<ResponsePackage> {
		let (verb, command) = ClientCommand::parse(frame.metadata().id())?;
		let outcome = command.run(self, member, frame).await?;

		let status = match outcome {
			Ok(()) => TransitStatus::Ok,
			Err(refusal) => {
				let status = refusal.status();
				member.audit().refused(verb.tag(), status);
				status
			}
		};

		let answer = ResponsePackage::new(status, None);
		Some(answer)
	}

	/// Consult `authorize` on `topic` for the session of `member`: the shared
	/// preamble of every policy-guarded command.
	fn authorize(
		&self,
		member: &Member,
		topic: &Topic,
		authorize: impl Fn(RegistryView<'_>, &SessionContext, &Topic) -> AccessVerdict,
	) -> Result<(), CommandRefusal> {
		// The policy weighs only a caller whose connection the registry
		// still holds.
		let Some(session) = member.session() else {
			return Err(CommandRefusal::Forbidden);
		};

		let verdict = authorize(self.registry.view(), &session, topic);
		if verdict == AccessVerdict::Forbid {
			return Err(CommandRefusal::Forbidden);
		}

		Ok(())
	}

	fn subscribe(&self, member: &Member, named: Named) -> Result<(), CommandRefusal> {
		let topic = named?;
		self.authorize(member, &topic, |view, session, topic| {
			self.policy.authorize(view, session, topic)
		})?;

		member.subscribe(topic)?;
		Ok(())
	}

	/// Run one `pub/<topic>` command: authorize, lift the payload, publish
	/// through the registry. `None` hands the command to the application
	/// when these commands take no client publish.
	async fn publish(&self, member: &Member, named: Named, frame: &Frame) -> Option<Result<(), CommandRefusal>> {
		let policy = self.publish.as_deref()?;
		let published = async {
			let topic = named?;
			self.authorize(member, &topic, |view, session, topic| policy.authorize(view, session, topic))?;

			let Ok(body) = frame.decode_message::<Opaque>() else {
				return Err(CommandRefusal::Malformed);
			};

			self.registry.publish(&topic, body.as_bytes()).await?;
			Ok(())
		};

		Some(published.await)
	}
}

impl<P: SubscribePolicy + 'static> PubsubCommands<P> {
	/// Serve one multiplexed connection over `link` until it ends.
	///
	/// - The link spawns the drivers of its mux beside the serve loop, with a keepalive of its own
	///   that paces its probes to the operation timeout of the link ([`AcceptedLink::spawn`]).
	/// - Every stream passes the transport gate of the link first. The commands then answer, and
	///   every other unary stream goes to `app` with the [`ConnectionContext`] of the connection.
	///   A streaming or duplex stream answers `Unimplemented`.
	/// - The connection registers on entry under the session of the link: the peer that its
	///   handshake proved, or the empty session of a cleartext link. The policies authorize that
	///   session. Every emit of the connection runs under the emit deadline of the registry, on
	///   the clock of the writer of the link.
	/// - A connection that the delivery policy votes off drains with an `EnhanceYourCalm` GoAway,
	///   and one that a [`drain`](TopicRegistry::drain) dismisses drains with `Shutdown`.
	/// - When the future completes or drops, the connection leaves the registry with all its
	///   subscriptions, and the drivers and the keepalive end.
	///
	/// # Errors
	///
	/// - The [`TransportError`](tightbeam::transport::TransportError) of a failed serve loop of
	///   the responder. The connection leaves the registry before the error returns.
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
	/// 	commands: &PubsubCommands<AllowAll>,
	/// 	mut transport: T,
	/// ) -> Result<(), Box<dyn std::error::Error>>
	/// where
	/// 	T: MuxAcceptor,
	/// 	T::EnvelopeReader: Send,
	/// 	T::EnvelopeWriter: Send,
	/// {
	/// 	transport.negotiate_mux().await?;
	/// 	let link = AcceptedLink::accepted(transport)?;
	/// 	commands.serve(link, Unrouted).await?;
	/// 	Ok(())
	/// }
	/// ```
	pub async fn serve<R, W, A, F>(&self, link: AcceptedLink<R, W>, app: A) -> TransportResult<()>
	where
		R: EnvelopeSource + Send + 'static,
		W: EnvelopeSink + Send + 'static,
		A: AppRoutes<F>,
		F: Future<Output = ResponsePackage> + Send + 'static,
	{
		let served = link.spawn();
		let mut membership = self.registry.admit(&served);
		let context = membership.context().clone();

		let routes = CommandRoutes { commands: self.clone(), app, context, routed: PhantomData };
		let expelled = membership.expelled();
		served.serve_dispatch(routes, expelled).await
	}
}

/// The unary routes of one served connection: the commands first, then
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
			if let Some(answer) = commands.answer(context.member(), &frame).await {
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

	use tightbeam::builder::TypeBuilder;
	use tightbeam::crypto::key::Aes256GcmKeyProvider;
	use tightbeam::Version;

	use super::*;
	use crate::backplane::{Backplane, Local};
	use crate::frame::OpaqueFrame;
	use crate::policy::AllowAll;
	use crate::registry::RegistryOptions;
	use crate::testing::nodes::Admitted;

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
	async fn answered<P: SubscribePolicy>(
		commands: &PubsubCommands<P>,
		member: &Member,
		frame: &Frame,
	) -> ResponsePackage {
		let answer = commands.answer(member, frame).await;
		answer.expect("the dispatcher should claim the command")
	}

	/// A dispatcher over one admitted loopback connection. The guard keeps
	/// the registration and the link alive, and its drop leaves the
	/// registry.
	async fn dispatcher<P: SubscribePolicy>(policy: P) -> (PubsubCommands<P>, TopicRegistry, Member, Admitted) {
		dispatcher_with(policy, RegistryOptions::default()).await
	}

	/// As [`dispatcher`], with explicit registry options.
	async fn dispatcher_with<P: SubscribePolicy>(
		policy: P,
		options: RegistryOptions,
	) -> (PubsubCommands<P>, TopicRegistry, Member, Admitted) {
		let registry = TopicRegistry::new(options);
		let admitted = Admitted::to(&registry).await;
		let member = admitted.member().clone();
		let commands = PubsubCommands::new(registry.clone(), policy);
		(commands, registry, member, admitted)
	}

	/// A dispatcher with client publish enabled.
	async fn publisher<S, P>(policy: S, publish: P) -> (PubsubCommands<S>, TopicRegistry, Member, Admitted)
	where
		S: SubscribePolicy,
		P: PublishPolicy + 'static,
	{
		let (commands, registry, member, peer) = dispatcher(policy).await;
		(commands.with_publish(publish), registry, member, peer)
	}

	/// The publish command the publish tests emit.
	fn tick_publish() -> Frame {
		payload_command("pub/prices", b"tick")
	}

	/// A publish command whose body is sealed to a key the server lacks, so
	/// the publish refuses it as `CommandRefusal::Malformed`.
	fn sealed_publish() -> Frame {
		let frame = OpaqueFrame { id: "pub/prices", order: 1, payload: b"tick" };
		let framed = frame.framed(Version::V1).expect("the command body encodes");
		let sealer = Aes256GcmKeyProvider::new(vec![7; 32], b"absent".to_vec()).expect("the key wraps");
		framed
			.with_encryptor(sealer)
			.build()
			.expect("sealed command frames should build")
	}

	#[test]
	fn an_id_parses_as_the_command_of_its_prefix() {
		let prices = "prices".parse();
		let ids = [
			(
				b"sub/prices".as_slice(),
				Verb::Subscribe,
				ClientCommand::Subscribe(prices.clone()),
			),
			(b"unsub/prices", Verb::Unsubscribe, ClientCommand::Unsubscribe(prices.clone())),
			(b"pub/prices", Verb::Publish, ClientCommand::Publish(prices)),
		];
		for (id, verb, command) in ids {
			assert_eq!(ClientCommand::parse(id), Some((verb, command)));
		}
	}

	#[test]
	fn a_command_whose_name_is_no_topic_holds_the_refusal() {
		let parsed = ClientCommand::parse(b"sub/");
		assert_eq!(
			parsed,
			Some((Verb::Subscribe, ClientCommand::Subscribe(Err(TopicError::Empty))))
		);
	}

	#[test]
	fn an_end_id_is_no_client_command() {
		assert_eq!(ClientCommand::parse(b"end/prices"), None);
	}

	#[tokio::test]
	async fn subscribe_command_registers_and_accepts() {
		let (commands, registry, member, _peer) = dispatcher(AllowAll).await;
		let answer = answered(&commands, &member, &command("sub/prices")).await;
		assert_eq!(answer.status(), TransitStatus::Ok);
		assert_eq!(
			registry
				.view()
				.subscriber_count(&"prices".parse::<Topic>().expect("the name should be a topic")),
			1
		);
	}

	#[tokio::test]
	async fn unsubscribe_command_forgets_and_accepts() {
		let (commands, registry, member, _peer) = dispatcher(AllowAll).await;
		answered(&commands, &member, &command("sub/prices")).await;

		let answer = answered(&commands, &member, &command("unsub/prices")).await;
		assert_eq!(answer.status(), TransitStatus::Ok);
		assert_eq!(
			registry
				.view()
				.subscriber_count(&"prices".parse::<Topic>().expect("the name should be a topic")),
			0
		);
	}

	#[tokio::test]
	async fn unsubscribe_of_a_never_subscribed_topic_still_accepts() {
		let (commands, _registry, member, _peer) = dispatcher(AllowAll).await;
		let answer = answered(&commands, &member, &command("unsub/prices")).await;
		assert_eq!(answer.status(), TransitStatus::Ok);
	}

	#[tokio::test]
	async fn malformed_unsubscribe_topic_answers_invalid_argument() {
		let (commands, _registry, member, _peer) = dispatcher(AllowAll).await;
		let answer = answered(&commands, &member, &command("unsub/")).await;
		assert_eq!(answer.status(), TransitStatus::InvalidArgument);
	}

	#[tokio::test]
	async fn forbidden_topic_answers_permission_denied() {
		let (commands, registry, member, _peer) = dispatcher(DenySecrets).await;
		let answer = answered(&commands, &member, &command("sub/secrets/keys")).await;
		assert_eq!(answer.status(), TransitStatus::PermissionDenied);
		assert_eq!(
			registry
				.view()
				.subscriber_count(&"secrets/keys".parse::<Topic>().expect("the name should be a topic")),
			0
		);
	}

	#[tokio::test]
	async fn malformed_topic_answers_invalid_argument() {
		let (commands, _registry, member, _peer) = dispatcher(AllowAll).await;
		let answer = answered(&commands, &member, &command("sub/")).await;
		assert_eq!(answer.status(), TransitStatus::InvalidArgument);
	}

	#[tokio::test]
	async fn a_draining_registry_answers_unavailable() {
		let (commands, registry, member, _peer) = dispatcher(AllowAll).await;
		registry.complete().await.expect("every end frame builds");

		let answer = answered(&commands, &member, &command("sub/prices")).await;
		assert_eq!(answer.status(), TransitStatus::Unavailable);
	}

	#[tokio::test]
	async fn over_quota_subscribe_answers_resource_exhausted() {
		let options = RegistryOptions {
			max_subscriptions_per_connection: NonZeroUsize::MIN,
			..RegistryOptions::default()
		};
		let (commands, _registry, member, _peer) = dispatcher_with(AllowAll, options).await;
		let first = answered(&commands, &member, &command("sub/prices")).await;
		let second = answered(&commands, &member, &command("sub/chat")).await;
		assert_eq!(first.status(), TransitStatus::Ok);
		assert_eq!(second.status(), TransitStatus::ResourceExhausted);
	}

	#[tokio::test]
	async fn non_command_frames_pass_through() {
		let (commands, _registry, member, _peer) = dispatcher(AllowAll).await;
		let answer = commands.answer(&member, &command("prices")).await;
		assert!(answer.is_none());
	}

	#[tokio::test]
	async fn pub_command_passes_through_until_publish_is_enabled() {
		let (commands, _registry, member, _peer) = dispatcher(AllowAll).await;
		let answer = commands.answer(&member, &command("pub/prices")).await;
		assert!(answer.is_none());
	}

	#[tokio::test]
	async fn malformed_pub_command_passes_through_until_publish_is_enabled() {
		let (commands, _registry, member, _peer) = dispatcher(AllowAll).await;
		let answer = commands.answer(&member, &command("pub/")).await;
		assert!(answer.is_none());
	}

	#[tokio::test]
	async fn pub_command_publishes_when_the_policy_allows() {
		let (commands, _registry, member, _peer) = publisher(AllowAll, AllowAll).await;
		let answer = answered(&commands, &member, &tick_publish()).await;
		assert_eq!(answer.status(), TransitStatus::Ok);
	}

	#[tokio::test]
	async fn commands_from_a_departed_connection_answer_permission_denied() {
		let (commands, _registry, member, peer) = publisher(AllowAll, AllowAll).await;
		drop(peer);

		let publish = answered(&commands, &member, &tick_publish()).await;
		let subscribe = answered(&commands, &member, &command("sub/prices")).await;
		assert_eq!(publish.status(), TransitStatus::PermissionDenied);
		assert_eq!(subscribe.status(), TransitStatus::PermissionDenied);
	}

	#[tokio::test]
	async fn forbidden_publish_answers_permission_denied() {
		let (commands, _registry, member, _peer) = publisher(AllowAll, DenyPublish).await;
		let answer = answered(&commands, &member, &tick_publish()).await;
		assert_eq!(answer.status(), TransitStatus::PermissionDenied);
	}

	#[tokio::test]
	async fn malformed_publish_topic_answers_invalid_argument() {
		let (commands, _registry, member, _peer) = publisher(AllowAll, AllowAll).await;
		let answer = answered(&commands, &member, &command("pub/")).await;
		assert_eq!(answer.status(), TransitStatus::InvalidArgument);
	}

	#[tokio::test]
	async fn a_publish_body_that_does_not_decode_answers_invalid_argument() {
		let (commands, _registry, member, _peer) = publisher(AllowAll, AllowAll).await;
		let answer = answered(&commands, &member, &sealed_publish()).await;
		assert_eq!(answer.status(), TransitStatus::InvalidArgument);
	}

	#[tokio::test]
	async fn a_backplane_topic_limit_answers_resource_exhausted() {
		let backplane: Arc<dyn Backplane> = Arc::new(Local::default().with_max_topics(NonZeroUsize::MIN));
		let options = RegistryOptions { backplane, ..RegistryOptions::default() };
		let (commands, _registry, member, _peer) = dispatcher_with(AllowAll, options).await;
		let commands = commands.with_publish(AllowAll);
		answered(&commands, &member, &command("sub/prices")).await;
		answered(&commands, &member, &tick_publish()).await;

		let answer = answered(&commands, &member, &payload_command("pub/chat", b"tick")).await;
		assert_eq!(answer.status(), TransitStatus::ResourceExhausted);
	}

	#[tokio::test]
	async fn publish_to_a_draining_registry_answers_unavailable() {
		let (commands, registry, member, _peer) = publisher(AllowAll, AllowAll).await;
		registry.complete().await.expect("every end frame builds");

		let answer = answered(&commands, &member, &tick_publish()).await;
		assert_eq!(answer.status(), TransitStatus::Unavailable);
	}
}
