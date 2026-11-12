//! Test support over loopback WebSocket links, and the backplane contract
//! suite. The page `docs/pubsub.md` (Testing) lists each part.

pub(crate) mod conformance;

use core::future::Future;
use core::pin::pin;
use core::time::Duration;
use std::io;
use std::sync::Arc;

use tightbeam::clock::{Clock, SystemClock};
use tightbeam::policy::TransitStatus;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::transport::error::TransportError;
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::{
	MuxAcceptor, MuxConnector, MuxDrivers, MuxHandle, MuxRole, MuxTransport, SpawnedMux,
};
use tightbeam::transport::{ClientBuilder, Protocol, ResponsePackage};
use tightbeam::{Frame, TightBeamError};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::serve::AcceptedLink;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

pub use self::conformance::{BackplaneBreach, BackplaneConformance, Fabric, Refusal};
use crate::dispatch::PubsubCommands;
use crate::frame::OpaqueFrame;
use crate::policy::SubscribePolicy;
use crate::serve::Unrouted;
use crate::topic::{Topic, SUB_PREFIX, UNSUB_PREFIX};

/// How long the kit waits for each step before it reads the step as lost.
pub(crate) const PATIENCE: Duration = Duration::from_secs(5);

/// The output of `step`, a wait on the other end of a link, once it settles
/// within [`PATIENCE`] on `clock`.
///
/// # Errors
///
/// - [`TightBeamError::TransportError`] -- `step` did not settle in time, or the thread has no timer
///   for `clock`, as the `From<Lapse>` of [`TransportError`] maps each.
async fn patient<T>(clock: &dyn Clock, step: impl Future<Output = T>) -> Result<T, TightBeamError> {
	let bounded = clock.within(PATIENCE, pin!(step)).await;
	let settled = bounded.map_err(TransportError::from)?;
	Ok(settled)
}

/// The transport of each end of a [`Loopback`].
type LoopbackTransport = <WsListener as Protocol>::Transport;

/// The server end of a [`Loopback`], as the link that
/// [`PubsubCommands::serve`] takes.
pub type ServerEnd = AcceptedLink<
	<LoopbackTransport as MuxAcceptor>::EnvelopeReader,
	<LoopbackTransport as MuxAcceptor>::EnvelopeWriter,
>;

/// How a [`Loopback`] link dials.
///
/// A cleartext link negotiates nothing, so both ends take `settings`.
pub struct Dial {
	/// The multiplexing settings of both ends.
	pub settings: MuxSettings,
	/// The clock of the server end, which runs every deadline of the
	/// registry that serves it.
	pub clock: Arc<dyn Clock>,
	/// The trace that both transports record on, when the link has one.
	pub trace: Option<TraceCollector>,
}

impl Default for Dial {
	/// Four streams each way, the system clock, and no trace.
	fn default() -> Self {
		Self { settings: MuxSettings::symmetric(4), clock: Arc::new(SystemClock), trace: None }
	}
}

impl Dial {
	/// The default dial, recording on `trace`.
	#[must_use]
	pub fn traced(trace: &TraceCollector) -> Self {
		Self { trace: Some(trace.share()), ..Self::default() }
	}

	/// `transport`, recording on the trace of this dial.
	fn recording(&self, transport: LoopbackTransport) -> LoopbackTransport {
		match &self.trace {
			Some(trace) => transport.with_trace(trace.share()),
			None => transport,
		}
	}
}

/// One cleartext WebSocket connection on loopback, through the real
/// listener, dial, and [`AcceptedLink::cleartext`] of `tightbeam-ws`.
///
/// The server end dials, because a dial runs on the clock it names and an
/// accepted transport runs on the system clock.
pub struct Loopback {
	/// The server end, on the clock of the dial.
	pub server: ServerEnd,
	/// The client end, spawned, with its responder unserved.
	pub client: SpawnedMux,
}

impl Loopback {
	/// Open one link under `dial`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a listener that failed to bind, a dial or an
	///   accept that failed, or a clock of `dial` that cannot race a wait on
	///   the calling thread.
	/// - [`TightBeamError::TransportError`] -- the dial and the accept did not settle within the
	///   patience of the kit on the system clock.
	pub async fn open(dial: &Dial) -> Result<Self, TightBeamError> {
		let loopback = TightBeamSocketAddr("127.0.0.1:0".parse()?);
		let (listener, addr) = <WsListener as Protocol>::bind_cleartext(loopback).await?;
		let builder = ClientBuilder::<WsListener>::on_clock(Arc::clone(&dial.clock)).allow_cleartext();

		let linking = async { tokio::try_join!(listener.accept(), builder.connect(addr)) };
		let linked = patient(&SystemClock, linking).await?;
		let ((accepted, _peer), dialed) = linked?;
		let server_transport = dial.recording(dialed.into_transport());
		let server = AcceptedLink::cleartext(server_transport, dial.settings).map_err(io::Error::other)?;

		let client_transport = dial.recording(accepted);
		let (reader, writer) = MuxConnector::into_envelope_halves(client_transport)?;
		let client = MuxTransport::new(reader, writer, MuxRole::Client, dial.settings).spawn();
		Ok(Self { server, client })
	}
}

/// One client of a registry over a [`Loopback`] link. The server end serves
/// through [`PubsubCommands::serve`], and the client answers each update
/// with `Ok` once it holds an ack permit.
///
/// The drop ends the link, which leaves the registry.
///
/// # Examples
///
/// ```
/// use tightbeam_pubsub::testing::{Dial, Peer};
/// use tightbeam_pubsub::{AllowAll, PubsubCommands, Topic, TopicRegistry};
///
/// # async fn read() -> Result<(), Box<dyn std::error::Error>> {
/// let registry = TopicRegistry::default();
/// let commands = PubsubCommands::new(registry.clone(), AllowAll);
/// let topic: Topic = "prices".parse()?;
///
/// let mut peer = Peer::connect(&commands, &Dial::default()).await?;
/// peer.subscribe(&topic).await?;
/// registry.publish(&topic, b"tick").await?;
///
/// let update = peer.next_update().await;
/// assert_eq!(update.map(|update| update.metadata().order()), Some(1));
/// # Ok(())
/// # }
/// ```
pub struct Peer {
	handle: MuxHandle,
	updates: UnboundedReceiver<Arc<Frame>>,
	acks: Arc<Semaphore>,
	streams: u32,
	/// The clock of the patience of each command.
	clock: Arc<dyn Clock>,
	serving: JoinSet<()>,
	_responding: JoinSet<()>,
	_drivers: MuxDrivers,
}

impl Peer {
	/// Connect to the registry of `commands` under `dial`, acking each update
	/// as it arrives.
	///
	/// # Errors
	///
	/// - The errors of [`Loopback::open`].
	pub async fn connect<P>(commands: &PubsubCommands<P>, dial: &Dial) -> Result<Self, TightBeamError>
	where
		P: SubscribePolicy + 'static,
	{
		Self::open(commands, dial, 1).await
	}

	/// Connect as [`connect`](Self::connect) does, with every ack held until
	/// [`grant`](Self::grant) hands out a permit for it.
	///
	/// # Errors
	///
	/// - The errors of [`Loopback::open`].
	pub async fn stalled<P>(commands: &PubsubCommands<P>, dial: &Dial) -> Result<Self, TightBeamError>
	where
		P: SubscribePolicy + 'static,
	{
		Self::open(commands, dial, 0).await
	}

	/// Connect with `permits` acks free at once.
	async fn open<P>(commands: &PubsubCommands<P>, dial: &Dial, permits: usize) -> Result<Self, TightBeamError>
	where
		P: SubscribePolicy + 'static,
	{
		let Loopback { server, client } = Loopback::open(dial).await?;
		let SpawnedMux { handle, responder, drivers } = client;
		let (sender, updates) = unbounded_channel();
		let acks = Arc::new(Semaphore::new(permits));

		let gate = Arc::clone(&acks);
		let answer = move |update: Arc<Frame>| {
			let sender = sender.clone();
			let gate = Arc::clone(&gate);
			async move {
				// A peer that dropped its receiver reads nothing more.
				let _ = sender.send(update);
				// The semaphore closes only with the peer.
				if let Ok(permit) = gate.acquire().await {
					drop(permit);
				}

				ResponsePackage::new(TransitStatus::Ok, None)
			}
		};

		let commands = commands.clone();
		let mut serving = JoinSet::new();
		serving.spawn(async move {
			// The client reads the end of the serve as the end of its link.
			let _ = commands.serve(server, Unrouted).await;
		});

		let mut responding = JoinSet::new();
		responding.spawn(async move {
			// The responder ends with the link.
			let _ = responder.serve(answer).await;
		});

		let streams = dial.settings.local_initiated_cap();
		Ok(Self {
			handle,
			updates,
			acks,
			streams,
			clock: Arc::new(SystemClock),
			serving,
			_responding: responding,
			_drivers: drivers,
		})
	}

	/// Subscribe to `topic` with a `sub/` command.
	///
	/// # Errors
	///
	/// - The errors of [`request`](Self::request).
	pub async fn subscribe(&self, topic: &Topic) -> Result<(), TightBeamError> {
		let id = format!("{SUB_PREFIX}{topic}");
		self.request(&id, b"").await?;
		Ok(())
	}

	/// Unsubscribe from `topic` with an `unsub/` command.
	///
	/// # Errors
	///
	/// - The errors of [`request`](Self::request).
	pub async fn unsubscribe(&self, topic: &Topic) -> Result<(), TightBeamError> {
		let id = format!("{UNSUB_PREFIX}{topic}");
		self.request(&id, b"").await?;
		Ok(())
	}

	/// Emit one stream of the id `id` that carries `payload`, and answer the
	/// frame the server answered with.
	///
	/// # Errors
	///
	/// - The errors of [`OpaqueFrame::build`].
	/// - [`TightBeamError::TransportError`] -- the stream was refused, the link failed, the server
	///   did not answer within the patience of the kit on the system clock (`DeadlineExceeded`), or
	///   the polling thread has no timer for that clock (`FailedPrecondition`).
	pub async fn request(&self, id: &str, payload: &[u8]) -> Result<Option<Frame>, TightBeamError> {
		let frame = OpaqueFrame { id, order: 1, payload };
		let built = frame.build()?;
		let answered = patient(&*self.clock, self.handle.emit_on_stream(&built)).await?;
		Ok(answered?)
	}

	/// The next update that the registry pushed, or `None` once the link
	/// closed. The update arrives before its ack.
	pub async fn next_update(&mut self) -> Option<Arc<Frame>> {
		self.updates.recv().await
	}

	/// Free `acks` more acks of updates.
	pub fn grant(&self, acks: usize) {
		self.acks.add_permits(acks);
	}

	/// Wait for the GoAway of the server, and answer its reason.
	///
	/// The peer holds every local stream slot, so its wait for a free slot
	/// ends when a GoAway ends admission. A slot that will not open means
	/// admission already ended.
	pub async fn goaway(&self) -> Option<GoAwayReason> {
		let mut held = Vec::new();
		for _ in 0..self.streams {
			let Ok(stream) = self.handle.open_stream() else {
				break;
			};

			held.push(stream);
		}

		let admission = self.handle.wait_for_stream_slot().await;
		drop(held);

		admission.err()?;
		self.handle.goaway_reason()
	}

	/// Drop the serve of the server end, as an accept loop that aborts its
	/// handlers does, and wait until the serve is gone.
	pub async fn drop_serve(&mut self) {
		self.serving.abort_all();
		while self.serving.join_next().await.is_some() {}
	}
}

/// The fixtures of the unit tests of this crate.
#[cfg(test)]
pub(crate) mod nodes {
	use core::future::{poll_fn, Future};
	use core::pin::Pin;
	use core::task::Poll;
	use core::time::Duration;
	use std::sync::Arc;

	use tightbeam::policy::TransitStatus;
	use tightbeam::transport::multiplex::{MuxDispatch, SpawnedMux};
	use tightbeam::transport::{ResponsePackage, TransportResult};
	use tightbeam::Frame;
	use tightbeam_ws::serve::ServedMux;

	use super::{Dial, Loopback, PATIENCE};
	use crate::registry::{Member, Membership, TopicRegistry};
	use crate::serve::ConnectionContext;
	use crate::topic::Topic;

	/// The emit deadline of the tests that advance a manual clock past it,
	/// twice [`PATIENCE`], so only the advance ends an emit within the bound.
	pub(crate) const SHORT: Duration = Duration::from_secs(PATIENCE.as_secs() * 2);

	/// Answers every unary stream with an empty `Ok`.
	pub(crate) struct Accepting;

	impl MuxDispatch for Accepting {
		async fn unary(&self, _frame: Arc<Frame>) -> TransportResult<ResponsePackage> {
			Ok(ResponsePackage::new(TransitStatus::Ok, None))
		}
	}

	/// Whether `future` waits at its first poll.
	pub(crate) async fn waits<F: Future>(mut future: Pin<&mut F>) -> bool {
		poll_fn(|context| Poll::Ready(future.as_mut().poll(context).is_pending())).await
	}

	/// One loopback connection that a registry admitted, whose client end
	/// reads nothing. The drop leaves the registry.
	pub(crate) struct Admitted {
		membership: Membership,
		_link: (ServedMux, SpawnedMux),
	}

	impl Admitted {
		/// Admit one connection to `registry` under the default dial.
		pub(crate) async fn to(registry: &TopicRegistry) -> Self {
			Self::over(registry, &Dial::default()).await
		}

		/// Admit one connection to `registry` under `dial`.
		pub(crate) async fn over(registry: &TopicRegistry, dial: &Dial) -> Self {
			let opened = Loopback::open(dial).await;
			let Loopback { server, client } = opened.expect("a loopback link opens");
			let served = server.spawn();
			let membership = registry.admit(&served);
			Self { membership, _link: (served, client) }
		}

		/// The context of the connection.
		pub(crate) fn context(&self) -> &ConnectionContext {
			self.membership.context()
		}

		/// The standing of the connection in its registry.
		pub(crate) fn member(&self) -> &Member {
			self.context().member()
		}

		/// Subscribe the connection to `name`, expecting acceptance.
		pub(crate) fn subscribe(&self, name: &str) {
			let topic: Topic = name.parse().expect("the name should be a topic");
			self.member().subscribe(topic).expect("the registration should be accepted");
		}
	}
}

#[cfg(test)]
mod tests {
	use tightbeam::testing::SetupEnv;
	use tightbeam::urn::Urn;
	use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn};

	use super::*;
	use crate::policy::AllowAll;
	use crate::registry::TopicRegistry;
	use crate::testing::conformance::PAST_DER_LIMIT;

	/// Whether a request whose frame failed to build answered the encode
	/// error of the build.
	const BUILD_FAILED: Urn<'static> = urn!("test", "event:pubsub-peer/build-failed");

	tb_assert_spec! {
		pub FailedBuildSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(BUILD_FAILED, exactly!(1), equals!(true))
			]
		}
	}

	// A request whose payload passes the longest DER length answers the
	// encode error of its frame.
	tb_scenario! {
		name: a_request_whose_frame_fails_to_build_answers_the_encode_error,
		spec: FailedBuildSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let commands = PubsubCommands::new(TopicRegistry::default(), AllowAll);
				let peer = Peer::connect(&commands, &Dial::default()).await?;
				let oversized = vec![0_u8; PAST_DER_LIMIT];
				let requested = peer.request("pub/prices", &oversized).await;
				let failed = matches!(requested, Err(TightBeamError::SerializationError(_)));
				trace.event_with(BUILD_FAILED, &[], failed)?;
				Ok(())
			}
		}
	}
}
