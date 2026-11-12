//! The clauses of the backplane contract that `docs/pubsub.md` (Backplane)
//! lists, which a driver checks in its tests against fresh fabrics of its own.

use core::error::Error;
use core::fmt;
use core::future::Future;
use core::num::NonZeroUsize;
use core::pin::pin;
use std::sync::Arc;

use tightbeam::clock::{Clock, Lapse, SystemClock, Timer};
use tightbeam::TightBeamError;
use tokio::task::{JoinError, JoinSet};

use crate::backplane::{Backplane, Local, PublishError};
use crate::dispatch::PubsubCommands;
use crate::policy::AllowAll;
use crate::registry::{RegistryOptions, TopicRegistry};
use crate::testing::{Dial, Peer, PATIENCE};
use crate::topic::{Topic, TopicError};

/// How many publishes race in the clause of serialized delivery.
const RACERS: u64 = 16;

/// The topic of the clause of racing publishes.
const RACING: &str = "conformance/racing";

/// One octet past the longest DER length, so no node builds an update frame
/// of a payload this long.
pub(crate) const PAST_DER_LIMIT: usize = 0x1000_0000;

/// The clause of the contract of [`Backplane`] that a driver breaks.
#[derive(Debug)]
pub enum BackplaneBreach {
	/// A subscriber read the order `delivered` where the contract places
	/// `expected`, or read none before its link closed (`None`).
	Order {
		/// The order the contract places next.
		expected: u64,
		/// The order the subscriber read.
		delivered: Option<u64>,
	},
	/// [`Backplane::last_order`] answered `answered` after a subscriber read
	/// the order `expected` last.
	LastOrder {
		/// The order the subscriber read last.
		expected: u64,
		/// The order the backplane answered.
		answered: u64,
	},
	/// A publish that the contract accepts was refused, with the refusal.
	Refused(PublishError),
	/// A publish answered `answered` where the contract places the refusal
	/// `expected`.
	Answered {
		/// The refusal that the contract places.
		expected: Refusal,
		/// What the backplane answered.
		answered: Result<(), PublishError>,
	},
	/// The check could not run, because a peer failed at a step, with its
	/// error.
	PeerFailed {
		/// The step that the peer failed.
		step: &'static str,
		/// The error of the peer.
		error: TightBeamError,
	},
	/// The check could not run, because the drain of the registry of a node
	/// failed, with its error.
	Drain(TightBeamError),
	/// The check could not run, because the task of a racing publish ended
	/// before it answered, with its error.
	Racer(JoinError),
	/// The check could not run, because a topic that a clause names failed
	/// validation, with the refusal.
	Topic(TopicError),
	/// A step of a clause did not happen within the patience of the check,
	/// or its thread had no timer to bound the wait.
	Lapsed {
		/// The clause that waited.
		clause: &'static str,
		/// The step that the clause waited for.
		step: &'static str,
		/// Why the bound ended the wait.
		lapse: Lapse,
	},
}

impl fmt::Display for BackplaneBreach {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Order { expected, delivered: Some(delivered) } => {
				write!(f, "a subscriber read order {delivered} where the contract places {expected}")
			}
			Self::Order { expected, delivered: None } => {
				write!(f, "the link of a subscriber closed where the contract places order {expected}")
			}
			Self::LastOrder { expected, answered } => {
				write!(f, "the last order answered {answered} after a subscriber read {expected}")
			}
			Self::Refused(refusal) => write!(f, "an accepted publish was refused: {refusal}"),
			Self::Answered { expected, answered: Ok(()) } => {
				write!(f, "a publish answered Ok where the contract places {expected}")
			}
			Self::Answered { expected, answered: Err(refusal) } => {
				write!(f, "a publish answered {refusal} where the contract places {expected}")
			}
			Self::PeerFailed { step, error } => write!(f, "a peer of the check failed at {step}: {error}"),
			Self::Drain(error) => write!(f, "the drain of a node failed: {error}"),
			Self::Racer(error) => write!(f, "the task of a racing publish ended: {error}"),
			Self::Topic(error) => write!(f, "a topic that the check names failed validation: {error}"),
			Self::Lapsed { clause, step, .. } => {
				write!(f, "the clause that {clause} gave up its wait for {step}")
			}
		}
	}
}

impl Error for BackplaneBreach {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Refused(refusal) | Self::Answered { answered: Err(refusal), .. } => Some(refusal),
			Self::PeerFailed { error, .. } | Self::Drain(error) => Some(error),
			Self::Racer(error) => Some(error),
			Self::Topic(error) => Some(error),
			Self::Lapsed { lapse, .. } => Some(lapse),
			Self::Order { .. } | Self::LastOrder { .. } | Self::Answered { answered: Ok(()), .. } => None,
		}
	}
}

/// A refusal of a publish that a clause of the contract places.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
	/// [`PublishError::Draining`].
	Draining,
	/// [`PublishError::Build`].
	Build,
	/// [`PublishError::TopicLimit`].
	TopicLimit,
}

impl Refusal {
	/// The refusal that `answered` is, or `None` for one that no clause
	/// places.
	fn of(answered: &PublishError) -> Option<Self> {
		match answered {
			PublishError::Draining => Some(Self::Draining),
			PublishError::Build(_) => Some(Self::Build),
			PublishError::TopicLimit => Some(Self::TopicLimit),
			PublishError::Unavailable(_) => None,
		}
	}

	/// Whether `answered` is this refusal.
	fn admits(self, answered: &PublishError) -> bool {
		Self::of(answered) == Some(self)
	}
}

impl fmt::Display for Refusal {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Draining => f.write_str("the draining refusal"),
			Self::Build => f.write_str("the build refusal"),
			Self::TopicLimit => f.write_str("the topic-limit refusal"),
		}
	}
}

/// One distribution fabric under check, which builds the backplane of each
/// node that joins it.
pub trait Fabric: Send + Sync {
	/// The backplane of one more node of this fabric.
	fn join(&self) -> impl Future<Output = Arc<dyn Backplane>> + Send;
}

/// One [`Local`] spans the registries of one process, so every node of its
/// fabric shares it.
impl Fabric for Arc<Local> {
	async fn join(&self) -> Arc<dyn Backplane> {
		Arc::clone(self) as Arc<dyn Backplane>
	}
}

/// The topic limit of every clause that evicts nothing.
const UNLIMITED: NonZeroUsize = NonZeroUsize::MAX;

/// The topic `name` of a clause.
///
/// # Errors
///
/// - [`BackplaneBreach::Topic`] -- `name` fails [`Topic`] validation, so the clause cannot run.
fn topic_named(name: &str) -> Result<Topic, BackplaneBreach> {
	name.parse::<Topic>().map_err(BackplaneBreach::Topic)
}

/// The clauses of the contract of [`Backplane`] that `docs/pubsub.md`
/// (Backplane) lists, as one check of one driver.
///
/// Each clause runs on a fresh fabric that `fresh` builds under a topic limit,
/// through real registries and the loopback [`Peer`] subscribers of each.
///
/// # Examples
///
/// ```
/// use std::num::NonZeroUsize;
/// use std::sync::Arc;
///
/// use tightbeam_pubsub::testing::{BackplaneBreach, BackplaneConformance};
/// use tightbeam_pubsub::Local;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), BackplaneBreach> {
/// let fresh = |limit: NonZeroUsize| Arc::new(Local::default().with_max_topics(limit));
/// BackplaneConformance::new(fresh).check().await
/// # }
/// ```
pub struct BackplaneConformance<F> {
	fresh: F,
	/// The clock that bounds each wait of a clause.
	clock: Arc<dyn Clock>,
}

impl<F, B> BackplaneConformance<F>
where
	F: Fn(NonZeroUsize) -> B,
	B: Fabric,
{
	/// The check of the fabrics that `fresh` builds, each of whose
	/// backplanes counts at most the topic limit it takes. Each wait of a
	/// clause runs on the system clock.
	pub fn new(fresh: F) -> Self {
		Self { fresh, clock: Arc::new(SystemClock) }
	}

	/// Check each clause of the contract that `docs/pubsub.md` (Backplane)
	/// lists for this kit, each on a fresh fabric.
	///
	/// # Errors
	///
	/// - The [`BackplaneBreach`] of the first clause that the backplane breaks.
	pub async fn check(&self) -> Result<(), BackplaneBreach> {
		self.orders_are_dense_across_nodes().await?;
		self.racing_publishes_reach_every_node_in_order().await?;
		self.a_draining_node_leaves_the_others_dense().await?;
		self.a_refusal_everywhere_burns_no_order().await?;
		self.an_update_no_node_builds_fails_and_burns_no_order().await?;
		self.a_counter_with_a_live_member_stays().await?;
		self.the_last_order_is_the_last_delivered().await
	}

	/// Two nodes whose publishes interleave, which both subscribers read as
	/// one dense sequence.
	async fn orders_are_dense_across_nodes(&self) -> Result<(), BackplaneBreach> {
		let clause = Clause::named("orders are dense across nodes", &self.clock);
		let fabric = (self.fresh)(UNLIMITED);
		let topic = topic_named("conformance/dense")?;
		let first = Node::join(&fabric, clause).await?;
		let second = Node::join(&fabric, clause).await?;
		let mut on_first = first.subscriber(&topic).await?;
		let mut on_second = second.subscriber(&topic).await?;

		for publisher in [&first, &second, &first] {
			publisher.publish(&topic).await?;
		}

		for order in 1..=3 {
			on_first.read(order).await?;
			on_second.read(order).await?;
		}

		Ok(())
	}

	/// [`RACERS`] publishes that race from as many tasks, which every node
	/// delivers in the order of their stamps.
	async fn racing_publishes_reach_every_node_in_order(&self) -> Result<(), BackplaneBreach> {
		let clause = Clause::named("racing publishes reach every node in order", &self.clock);
		let fabric = (self.fresh)(UNLIMITED);
		let topic = topic_named(RACING)?;
		let publisher = Node::join(&fabric, clause).await?;
		let other = Node::join(&fabric, clause).await?;
		let mut on_publisher = publisher.subscriber(&topic).await?;
		let mut on_other = other.subscriber(&topic).await?;

		let mut racers = JoinSet::new();
		for _ in 0..RACERS {
			let registry = publisher.registry.clone();
			let topic = topic.clone();
			racers.spawn(async move { registry.publish(&topic, b"race").await });
		}

		while let Some(raced) = clause.within("a racing publish", racers.join_next()).await? {
			let published = raced.map_err(BackplaneBreach::Racer)?;
			published.map_err(BackplaneBreach::Refused)?;
		}

		for order in 1..=RACERS {
			on_publisher.read(order).await?;
			on_other.read(order).await?;
		}

		Ok(())
	}

	/// A node that drains between two publishes of another, whose subscriber
	/// reads the second publish next in its sequence.
	async fn a_draining_node_leaves_the_others_dense(&self) -> Result<(), BackplaneBreach> {
		let clause = Clause::named("a draining node leaves the others dense", &self.clock);
		let fabric = (self.fresh)(UNLIMITED);
		let topic = topic_named("conformance/draining")?;
		let leaving = Node::join(&fabric, clause).await?;
		let staying = Node::join(&fabric, clause).await?;
		let mut on_leaving = leaving.subscriber(&topic).await?;
		let mut on_staying = staying.subscriber(&topic).await?;

		staying.publish(&topic).await?;
		on_leaving.read(1).await?;
		on_staying.read(1).await?;

		leaving.drain().await?;
		staying.publish(&topic).await?;

		on_staying.read(2).await
	}

	/// A publish that the one draining node refuses, after which a new node
	/// reads the first order of the topic.
	async fn a_refusal_everywhere_burns_no_order(&self) -> Result<(), BackplaneBreach> {
		let clause = Clause::named("a refusal everywhere burns no order", &self.clock);
		let fabric = (self.fresh)(UNLIMITED);
		let topic = topic_named("conformance/refused")?;
		let drained = Node::join(&fabric, clause).await?;
		drained.drain().await?;

		let answered = drained.answer(&topic, b"refused").await?;
		Self::refused(answered, Refusal::Draining)?;

		let live = Node::join(&fabric, clause).await?;
		let mut on_live = live.subscriber(&topic).await?;
		live.publish(&topic).await?;

		on_live.read(1).await
	}

	/// A publish whose update frame no node can build, which fails with
	/// [`PublishError::Build`], after which the topic reads its first order.
	async fn an_update_no_node_builds_fails_and_burns_no_order(&self) -> Result<(), BackplaneBreach> {
		let clause = Clause::named("an update no node builds fails and burns no order", &self.clock);
		let fabric = (self.fresh)(UNLIMITED);
		let topic = topic_named("conformance/oversized")?;
		let node = Node::join(&fabric, clause).await?;
		let mut subscriber = node.subscriber(&topic).await?;

		let oversized = vec![0_u8; PAST_DER_LIMIT];
		let answered = node.answer(&topic, &oversized).await?;
		Self::refused(answered, Refusal::Build)?;
		node.publish(&topic).await?;

		subscriber.read(1).await
	}

	/// A fabric of one counted topic, whose topic has a live member on one
	/// node: a publish of another node to a new topic answers
	/// [`PublishError::TopicLimit`], and the counted topic keeps its order.
	async fn a_counter_with_a_live_member_stays(&self) -> Result<(), BackplaneBreach> {
		let clause = Clause::named("a counter with a live member stays", &self.clock);
		let fabric = (self.fresh)(NonZeroUsize::MIN);
		let held = topic_named("conformance/held")?;
		let holder = Node::join(&fabric, clause).await?;
		let other = Node::join(&fabric, clause).await?;
		let mut member = holder.subscriber(&held).await?;
		holder.publish(&held).await?;
		member.read(1).await?;

		let answered = other.answer(&topic_named("conformance/new")?, b"conformance").await?;
		Self::refused(answered, Refusal::TopicLimit)?;
		other.publish(&held).await?;

		member.read(2).await
	}

	/// Expect `answered` to be the refusal `expected`.
	///
	/// # Errors
	///
	/// - [`BackplaneBreach::Answered`] -- the publish answered anything else.
	fn refused(answered: Result<(), PublishError>, expected: Refusal) -> Result<(), BackplaneBreach> {
		match &answered {
			Err(refusal) if expected.admits(refusal) => Ok(()),
			_ => Err(BackplaneBreach::Answered { expected, answered }),
		}
	}

	/// Three accepted publishes, after whose delivery the last order is the
	/// third.
	async fn the_last_order_is_the_last_delivered(&self) -> Result<(), BackplaneBreach> {
		let clause = Clause::named("the last order is the last delivered", &self.clock);
		let fabric = (self.fresh)(UNLIMITED);
		let topic = topic_named("conformance/last")?;
		let node = Node::join(&fabric, clause).await?;
		let mut subscriber = node.subscriber(&topic).await?;

		for order in 1..=3 {
			node.publish(&topic).await?;
			subscriber.read(order).await?;
		}

		let answered = clause
			.within("the last order of a topic", node.backplane.last_order(&topic))
			.await?;
		if answered != 3 {
			return Err(BackplaneBreach::LastOrder { expected: 3, answered });
		}

		Ok(())
	}
}

/// One clause of the check, by the name that its breaches carry, and the
/// clock of its waits. It owns each wait of the clause.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Clause<'c> {
	name: &'static str,
	clock: &'c Arc<dyn Clock>,
}

impl<'c> Clause<'c> {
	/// The clause of the name `name`, whose waits run on `clock`.
	pub(crate) const fn named(name: &'static str, clock: &'c Arc<dyn Clock>) -> Self {
		Self { name, clock }
	}

	/// The output of `future`, once it settles within [`PATIENCE`] on the
	/// clock of this clause.
	///
	/// # Errors
	///
	/// - [`BackplaneBreach::Lapsed`] -- `future` did not settle in time, at `step` of this clause.
	pub(crate) async fn within<T>(
		self,
		step: &'static str,
		future: impl Future<Output = T>,
	) -> Result<T, BackplaneBreach> {
		let Self { name: clause, clock } = self;
		let mut timer = Timer::new(Arc::clone(clock));
		let bounded = timer.within(PATIENCE, pin!(future)).await;
		bounded.map_err(|lapse| BackplaneBreach::Lapsed { clause, step, lapse })
	}
}

/// One node of the fabric under check: its backplane, the registry on it,
/// the commands its peers connect through, and the clause it runs in.
struct Node<'c> {
	clause: Clause<'c>,
	backplane: Arc<dyn Backplane>,
	registry: TopicRegistry,
	commands: PubsubCommands<AllowAll>,
}

impl<'c> Node<'c> {
	/// A registry on the backplane of one more node of `fabric`, in `clause`.
	///
	/// # Errors
	///
	/// - [`BackplaneBreach::Lapsed`] -- the fabric did not join the node in time.
	async fn join(fabric: &impl Fabric, clause: Clause<'c>) -> Result<Self, BackplaneBreach> {
		let backplane = clause.within("the join of a node", fabric.join()).await?;
		let options = RegistryOptions { backplane: Arc::clone(&backplane), ..RegistryOptions::default() };
		let registry = TopicRegistry::new(options);
		let commands = PubsubCommands::new(registry.clone(), AllowAll);
		Ok(Self { clause, backplane, registry, commands })
	}

	/// A peer of this node, subscribed to `topic`.
	///
	/// # Errors
	///
	/// - [`BackplaneBreach::PeerFailed`] -- the peer failed to connect or to subscribe.
	async fn subscriber(&self, topic: &Topic) -> Result<Subscriber<'c>, BackplaneBreach> {
		let connected = Peer::connect(&self.commands, &Dial::default()).await;
		let peer =
			connected.map_err(|error| BackplaneBreach::PeerFailed { step: "the link of a subscriber", error })?;
		let subscribed = peer.subscribe(topic).await;
		subscribed.map_err(|error| BackplaneBreach::PeerFailed { step: "the subscribe of a subscriber", error })?;
		Ok(Subscriber { peer, clause: self.clause })
	}

	/// Publish one update to `topic` through this node.
	///
	/// # Errors
	///
	/// - [`BackplaneBreach::Lapsed`] -- the publish did not answer in time.
	/// - [`BackplaneBreach::Refused`] -- the registry or its backplane refused the publish.
	async fn publish(&self, topic: &Topic) -> Result<(), BackplaneBreach> {
		let publishing = self.registry.publish(topic, b"conformance");
		let published = self.clause.within("a publish through a node", publishing).await?;
		published.map_err(BackplaneBreach::Refused)
	}

	/// The answer of the backplane of this node to one publish of `payload`
	/// to `topic`.
	///
	/// # Errors
	///
	/// - [`BackplaneBreach::Lapsed`] -- the backplane did not answer in time.
	async fn answer(&self, topic: &Topic, payload: &[u8]) -> Result<Result<(), PublishError>, BackplaneBreach> {
		let publishing = self.backplane.publish(topic, payload);
		self.clause.within("a publish on the backplane of a node", publishing).await
	}

	/// Drain the registry of this node.
	///
	/// # Errors
	///
	/// - [`BackplaneBreach::Lapsed`] -- the drain did not complete in time.
	/// - [`BackplaneBreach::Drain`] -- the drain failed.
	async fn drain(&self) -> Result<(), BackplaneBreach> {
		let drained = self.clause.within("the drain of a node", self.registry.drain()).await?;
		drained.map_err(BackplaneBreach::Drain)?;
		Ok(())
	}
}

/// A peer of one node of a clause, which reads each update in the patience
/// of the clause.
struct Subscriber<'c> {
	peer: Peer,
	clause: Clause<'c>,
}

impl Subscriber<'_> {
	/// Read the next update, expecting it at `expected`.
	///
	/// # Errors
	///
	/// - [`BackplaneBreach::Lapsed`] -- no update arrived in time.
	/// - [`BackplaneBreach::Order`] -- the update carries another order, or the link closed first.
	async fn read(&mut self, expected: u64) -> Result<(), BackplaneBreach> {
		let next = self.clause.within("the read of an update", self.peer.next_update()).await?;
		let delivered = next.map(|update| update.metadata().order());
		if delivered != Some(expected) {
			return Err(BackplaneBreach::Order { expected, delivered });
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use core::future::{pending, poll_fn};
	use core::task::Poll;
	use std::io;

	use tightbeam::clock::{ManualClock, SystemClock};
	use tightbeam::marker::MaybeSendFuture;
	use tightbeam::testing::SetupEnv;
	use tightbeam::transport::error::{TransportError, TransportFailure};
	use tightbeam::urn::Urn;
	use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn};
	use tokio::sync::Notify;

	use super::*;
	use crate::backplane::BackplaneFault;
	use crate::registry::NodeSink;

	/// The one step that a driver of the scenario never answers.
	#[derive(Clone, Copy, PartialEq, Eq)]
	enum Silence {
		Join,
		Publish,
		LastOrder,
	}

	impl Silence {
		/// Notify `parked` and wait forever at `step` when this silence holds
		/// it, and answer `answered` at every other step.
		async fn at<T>(self, step: Self, parked: &Notify, answered: impl Future<Output = T>) -> T {
			if self == step {
				parked.notify_one();
				pending::<()>().await;
			}

			answered.await
		}
	}

	/// A driver over a [`Local`] that never answers the step of its silence,
	/// and notifies `parked` when it parks there.
	struct Silent {
		local: Local,
		silence: Silence,
		parked: Arc<Notify>,
	}

	impl Backplane for Silent {
		fn attach(&self, sink: NodeSink) {
			self.local.attach(sink);
		}

		fn publish<'a>(&'a self, topic: &'a Topic, payload: &'a [u8]) -> MaybeSendFuture<'a, Result<(), PublishError>> {
			let published = self.local.publish(topic, payload);
			Box::pin(self.silence.at(Silence::Publish, &self.parked, published))
		}

		fn last_order<'a>(&'a self, topic: &'a Topic) -> MaybeSendFuture<'a, u64> {
			Box::pin(self.silence.at(Silence::LastOrder, &self.parked, self.local.last_order(topic)))
		}

		fn vacated(&self, topic: &Topic) {
			self.local.vacated(topic);
		}
	}

	impl Fabric for Arc<Silent> {
		async fn join(&self) -> Arc<dyn Backplane> {
			let joined = async { Arc::clone(self) as Arc<dyn Backplane> };
			self.silence.at(Silence::Join, &self.parked, joined).await
		}
	}

	/// The answer of the check of a driver that never answers `silence`, at
	/// its first poll once the clock of the check passed [`PATIENCE`] at the
	/// park of that step. A check that ends before the park answers at once.
	///
	/// # Errors
	///
	/// - [`BackplaneBreach::Lapsed`] -- the check neither parked nor ended within the patience of a
	///   clause on the system clock.
	async fn silenced(silence: Silence) -> Result<Poll<Result<(), BackplaneBreach>>, BackplaneBreach> {
		let clock = Arc::new(ManualClock::default());
		let parked = Arc::new(Notify::new());
		let fresh = |limit: NonZeroUsize| {
			let local = Local::default().with_max_topics(limit);
			Arc::new(Silent { local, silence, parked: Arc::clone(&parked) })
		};
		let conformance = BackplaneConformance { fresh, clock: Arc::clone(&clock) as Arc<dyn Clock> };

		let system: Arc<dyn Clock> = Arc::new(SystemClock);
		let scenario = Clause::named("the scenario of a silent driver", &system);
		let mut checking = pin!(conformance.check());
		tokio::select! {
			checked = &mut checking => return Ok(Poll::Ready(checked)),
			parking = scenario.within("the park of the silent step", parked.notified()) => parking?,
		}

		clock.advance(PATIENCE);
		Ok(poll_fn(|context| Poll::Ready(checking.as_mut().poll(context))).await)
	}

	/// Whether the check of a driver that never answers one step answered the
	/// lapse of the clause and the step that wait for it.
	const LAPSED: Urn<'static> = urn!("test", "event:pubsub-conformance/lapsed");

	tb_assert_spec! {
		pub SilentDriverSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(LAPSED, exactly!(3), equals!(true))
			]
		}
	}

	// A driver that never answers its join, a publish, or the last order of
	// a drain breaks the check with the lapse of that step, which names the
	// clause that waited for it. The clock of the check passes its patience
	// at the park of the step, so the lapse answers at the next poll.
	tb_scenario! {
		name: a_driver_that_never_answers_breaks_the_check_with_a_lapse,
		spec: SilentDriverSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let silences = [
					(Silence::Join, "orders are dense across nodes", "the join of a node"),
					(Silence::Publish, "orders are dense across nodes", "a publish through a node"),
					(Silence::LastOrder, "a draining node leaves the others dense", "the drain of a node"),
				];
				for (silence, waiting, held) in silences {
					let answered = silenced(silence).await.map_err(io::Error::other)?;
					let lapsed = matches!(
						answered,
						Poll::Ready(Err(BackplaneBreach::Lapsed { clause, step, lapse: Lapse::Passed }))
							if clause == waiting && step == held
					);
					trace.event_with(LAPSED, &[], lapsed)?;
				}

				Ok(())
			}
		}
	}

	/// The fault of the publishes of a [`Faulty`] driver.
	#[derive(Clone, Copy)]
	enum Fault {
		/// Each refusal of `Local` answers as a saturated fabric.
		Saturated,
		/// A publish to the topic of the racing clause panics.
		PanicsInRace,
	}

	impl Fault {
		/// The answer of `local` to one publish of `payload` to `topic` under
		/// this fault.
		fn publish<'a>(
			self,
			local: &'a Local,
			topic: &'a Topic,
			payload: &'a [u8],
		) -> MaybeSendFuture<'a, Result<(), PublishError>> {
			match self {
				Self::Saturated => Box::pin(async move {
					let published = local.publish(topic, payload).await;
					published.map_err(|_| PublishError::Unavailable(BackplaneFault::Saturated))
				}),
				Self::PanicsInRace => {
					if topic.as_str() == RACING {
						panic!("the driver panics at a racing publish");
					}

					local.publish(topic, payload)
				}
			}
		}
	}

	/// A driver over a [`Local`] whose publishes answer under `fault`.
	struct Faulty {
		local: Local,
		fault: Fault,
	}

	impl Faulty {
		/// The fabric of one driver under `fault`, whose backplane counts at
		/// most `limit` topics.
		fn fabric(fault: Fault, limit: NonZeroUsize) -> Arc<Self> {
			let local = Local::default().with_max_topics(limit);
			Arc::new(Self { local, fault })
		}
	}

	impl Backplane for Faulty {
		fn attach(&self, sink: NodeSink) {
			self.local.attach(sink);
		}

		fn publish<'a>(&'a self, topic: &'a Topic, payload: &'a [u8]) -> MaybeSendFuture<'a, Result<(), PublishError>> {
			self.fault.publish(&self.local, topic, payload)
		}

		fn last_order<'a>(&'a self, topic: &'a Topic) -> MaybeSendFuture<'a, u64> {
			self.local.last_order(topic)
		}

		fn vacated(&self, topic: &Topic) {
			self.local.vacated(topic);
		}
	}

	impl Fabric for Arc<Faulty> {
		async fn join(&self) -> Arc<dyn Backplane> {
			Arc::clone(self) as Arc<dyn Backplane>
		}
	}

	/// Whether the check of a driver that answers another refusal answered
	/// the refusal that the clause places, beside the one the driver answered.
	const ANSWERED: Urn<'static> = urn!("test", "event:pubsub-conformance/answered");

	tb_assert_spec! {
		pub SaturatedDriverSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(ANSWERED, exactly!(1), equals!(true))
			]
		}
	}

	// A driver that answers a saturated fabric where every node drains breaks
	// the check at the clause of a refusal everywhere, with the draining
	// refusal that the clause places.
	tb_scenario! {
		name: a_driver_that_answers_another_refusal_breaks_the_check_with_the_refusal_it_places,
		spec: SaturatedDriverSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let fresh = |limit: NonZeroUsize| Faulty::fabric(Fault::Saturated, limit);
				let checked = BackplaneConformance::new(fresh).check().await;
				let answered = matches!(
					checked,
					Err(BackplaneBreach::Answered {
						expected: Refusal::Draining,
						answered: Err(PublishError::Unavailable(BackplaneFault::Saturated)),
					})
				);
				trace.event_with(ANSWERED, &[], answered)?;
				Ok(())
			}
		}
	}

	/// Whether the check of a driver that panics at a racing publish answered
	/// the panic of the task of that publish.
	const RACER: Urn<'static> = urn!("test", "event:pubsub-conformance/racer");

	tb_assert_spec! {
		pub PanickingRacerSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(RACER, exactly!(1), equals!(true))
			]
		}
	}

	// A driver whose publish panics in the racing clause breaks the check
	// with the panic of the task that ran the publish.
	tb_scenario! {
		name: a_driver_that_panics_at_a_racing_publish_breaks_the_check_with_the_panic,
		spec: PanickingRacerSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let fresh = |limit: NonZeroUsize| Faulty::fabric(Fault::PanicsInRace, limit);
				let checked = BackplaneConformance::new(fresh).check().await;
				let panicked = matches!(checked, Err(BackplaneBreach::Racer(ref error)) if error.is_panic());
				trace.event_with(RACER, &[], panicked)?;
				Ok(())
			}
		}
	}

	/// Whether a command that the server never answers answered the lapse of
	/// the patience of its peer.
	const COMMAND_LAPSED: Urn<'static> = urn!("test", "event:pubsub-peer/command-lapsed");

	tb_assert_spec! {
		pub LapsedCommandSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(COMMAND_LAPSED, exactly!(1), equals!(true))
			]
		}
	}

	// A `pub/` whose publish the backplane never answers ends at the patience
	// of its peer. The clock of the peer passes the patience at the park of
	// the publish, so the lapse answers at the next poll.
	tb_scenario! {
		name: a_command_the_server_never_answers_lapses_at_the_patience_of_its_peer,
		spec: LapsedCommandSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let parked = Arc::new(Notify::new());
				let silent = Silent { local: Local::default(), silence: Silence::Publish, parked: Arc::clone(&parked) };
				let options = RegistryOptions { backplane: Arc::new(silent), ..RegistryOptions::default() };
				let commands = PubsubCommands::new(TopicRegistry::new(options), AllowAll).with_publish(AllowAll);
				let mut peer = Peer::connect(&commands, &Dial::default()).await?;
				let clock = Arc::new(ManualClock::default());
				peer.clock = Arc::clone(&clock) as Arc<dyn Clock>;

				let system: Arc<dyn Clock> = Arc::new(SystemClock);
				let scenario = Clause::named("the scenario of a command the server never answers", &system);
				let mut requesting = pin!(peer.request("pub/prices", b"tick"));
				let early = tokio::select! {
					requested = &mut requesting => Some(requested),
					parking = scenario.within("the park of the publish", parked.notified()) => {
						parking.map_err(io::Error::other)?;
						None
					}
				};

				clock.advance(PATIENCE);
				let requested = match early {
					Some(requested) => Poll::Ready(requested),
					None => poll_fn(|context| Poll::Ready(requesting.as_mut().poll(context))).await,
				};
				let lapsed = matches!(
					requested,
					Poll::Ready(Err(TightBeamError::TransportError(TransportError::OperationFailed(
						TransportFailure::DeadlineExceeded
					))))
				);
				trace.event_with(COMMAND_LAPSED, &[], lapsed)?;
				Ok(())
			}
		}
	}

	/// Whether the check of a peer of a drained node named the subscribe as
	/// the step that the peer failed.
	const SUBSCRIBE_FAILED: Urn<'static> = urn!("test", "event:pubsub-conformance/subscribe-failed");

	tb_assert_spec! {
		pub DrainedPeerSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(SUBSCRIBE_FAILED, exactly!(1), equals!(true))
			]
		}
	}

	// The registry of a drained node refuses the subscribe of a new peer, so
	// the check breaks with the failure of the peer at that step.
	tb_scenario! {
		name: a_peer_of_a_drained_node_breaks_the_check_at_its_subscribe,
		spec: DrainedPeerSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let clock: Arc<dyn Clock> = Arc::new(SystemClock);
				let clause = Clause::named("the scenario of a drained node", &clock);
				let fabric = Arc::new(Local::default());
				let node = Node::join(&fabric, clause).await.map_err(io::Error::other)?;
				node.drain().await.map_err(io::Error::other)?;

				let topic = topic_named("conformance/drained").map_err(io::Error::other)?;
				let subscribed = node.subscriber(&topic).await;
				let failed = matches!(
					subscribed,
					Err(BackplaneBreach::PeerFailed { step: "the subscribe of a subscriber", .. })
				);
				trace.event_with(SUBSCRIBE_FAILED, &[], failed)?;
				Ok(())
			}
		}
	}
}
