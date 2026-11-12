//! The multiplexed encrypted pub/sub demo server that the e2e suite drives.
//! The page `docs/pubsub.md` (Testing) states what it serves.
//!
//! Environment:
//!   - `TBWS_SERVER_CERT`           path to the server certificate DER, beside its key
//!   - `PUBSUB_WS_PORT`             listen port, which the compose file of the stack sets
//!   - `MUX_STREAMS`                client-initiated concurrency cap (default `8`)
//!   - `PUBSUB_QUEUE_CAPACITY`      per-subscriber queue bound (default `32`)
//!   - `PUBSUB_MAX_SUBSCRIPTIONS`   live subscriptions per connection
//!     (default `64`)
//!   - `PUBSUB_PROCESSOR_ENDPOINT`  when set, publishes relay through the
//!     processor servlet at this ws:// URL ([`RelayBackplane`])
//!   - `PUBSUB_PROCESSOR_CERT`      path to the processor certificate DER the
//!     relay dial pins (required with the endpoint)
//!   - the variables of [`DemoConfig`], which decide the [`Security`] of every
//!     served connection and of the relay dial alike
//!
//! [`Security`]: tightbeam_ws::testing::Security

use core::fmt;
use core::future::Future;
use core::str::FromStr;
use core::time::Duration;
use std::error::Error;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::marker::MaybeSendFuture;
use tightbeam::policy::{SessionContext, TransitStatus};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::multiplex::{
	MuxAcceptor, MuxConnector, MuxDrivers, MuxHandle, MuxResponder, MuxRole, MuxTransport, SpawnedMux,
};
use tightbeam::transport::{EncryptedMessageIO, EncryptedProtocol, EnvelopeSink, GenericClient, ResponsePackage};
use tightbeam::{Frame, Opaque, TightBeamError};
use tightbeam_pubsub::{
	AccessVerdict, AppRoutes, Backplane, BackplaneFault, ConnectionContext, EmitDeadline, Emitter, LinkLost, Local,
	NodeSink, OpaqueFrame, PublishError, PublishPolicy, PubsubCommands, RegistryOptions, RegistryView, Settled,
	SubscribePolicy, Topic, TopicRegistry, Unrouted,
};
use tightbeam_ws::io::WsTransport;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::serve::{AcceptedLink, LinkError, RacingClock};
use tightbeam_ws::testing::{DemoConfig, EnvVar, Identity, Pinned, Security};
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio_tungstenite::tungstenite::http::uri::{Authority, InvalidUri, PathAndQuery};
use tokio_tungstenite::tungstenite::http::Uri;
use tokio_tungstenite::MaybeTlsStream;

type BoxError = Box<dyn Error + Send + Sync>;

/// The transport an accepted WebSocket connection follows.
type ServerTransport = WsTransport<MaybeTlsStream<TcpStream>>;

/// The frame id of the demo command that pushes one `notice` stream back to
/// the client, which reaches the fallback of its manager.
const POKE: &[u8] = b"poke";

/// The relay worker is gone: its channel closed.
#[derive(Debug)]
struct RelayClosed;

impl fmt::Display for RelayClosed {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("the relay worker is gone")
	}
}

impl Error for RelayClosed {}

/// The processor accepted a request and answered it with no frame.
#[derive(Debug)]
struct EmptyAnswer;

impl fmt::Display for EmptyAnswer {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("the processor answered with no frame")
	}
}

impl Error for EmptyAnswer {}

/// Why one relayed publish produced no fan-out.
enum RelayFault {
	/// The processor refused or spoiled one request, or the session budget
	/// could not carry it, and the link stays up.
	Refused(BoxError),
	/// An emit on the processor link counts as [`LinkLost`], one past its
	/// deadline included.
	LinkLost(BoxError),
	/// The local sequencer refused the processed payload.
	Sequencer(PublishError),
}

impl From<RelayFault> for PublishError {
	/// A fault of the processor link is a fault of the fabric, and the
	/// sequencer answers its own refusal.
	fn from(fault: RelayFault) -> Self {
		match fault {
			RelayFault::Refused(cause) | RelayFault::LinkLost(cause) => {
				Self::Unavailable(BackplaneFault::Failed(cause))
			}
			RelayFault::Sequencer(refusal) => refusal,
		}
	}
}

impl From<LinkLost> for RelayFault {
	fn from(lost: LinkLost) -> Self {
		Self::LinkLost(Box::new(lost))
	}
}

impl From<TightBeamError> for RelayFault {
	/// A frame that fails to build or decode spoils one request only.
	fn from(error: TightBeamError) -> Self {
		Self::Refused(Box::new(error))
	}
}

/// How many publishes may wait on the processor before the relay
/// refuses new ones: the bound that keeps a fast publisher from growing
/// the queue without limit.
const RELAY_DEPTH: usize = 64;

/// How many demo invoices the relay pays: the handshake and every renewal of
/// a long-lived processor link.
const RELAY_PAYMENTS: usize = 1024;

/// The port of a `ws://` URL that names none (RFC 6455 § 3).
const WS_DEFAULT_PORT: u16 = 80;

/// Why `PUBSUB_PROCESSOR_ENDPOINT` names no processor the relay can dial.
#[derive(Debug)]
enum EndpointError {
	/// The value is not a URI.
	Malformed(InvalidUri),
	/// The scheme is not `ws`.
	Scheme,
	/// The URL names no host.
	NoHost,
	/// The URL carries a path or a query, and the processor serves its root.
	Path,
	/// The URL declares a port that is not a number from 0 to 65535.
	Port,
	/// The host resolves to no socket address.
	Unresolved,
}

impl fmt::Display for EndpointError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Malformed(cause) => write!(f, "PUBSUB_PROCESSOR_ENDPOINT is not a URI: {cause}"),
			Self::Scheme => f.write_str("PUBSUB_PROCESSOR_ENDPOINT must be a ws:// URL"),
			Self::NoHost => f.write_str("PUBSUB_PROCESSOR_ENDPOINT must name a host"),
			Self::Path => f.write_str("PUBSUB_PROCESSOR_ENDPOINT must name the root path only"),
			Self::Port => f.write_str("PUBSUB_PROCESSOR_ENDPOINT must declare a port from 0 to 65535"),
			Self::Unresolved => f.write_str("PUBSUB_PROCESSOR_ENDPOINT names a host with no address"),
		}
	}
}

impl Error for EndpointError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Malformed(cause) => Some(cause),
			_ => None,
		}
	}
}

/// The `ws://host:port` URL of the processor servlet, from
/// `PUBSUB_PROCESSOR_ENDPOINT`.
///
/// The host may be a name, such as a compose service, or an IP address. An
/// IPv6 address drops its URL brackets here.
#[derive(Debug, PartialEq, Eq)]
struct ProcessorEndpoint {
	host: String,
	port: u16,
}

impl FromStr for ProcessorEndpoint {
	type Err = EndpointError;

	/// Parse a `ws://` URL with a host, an optional port, and no path.
	///
	/// # Errors
	///
	/// - [`EndpointError::Malformed`] -- `endpoint` is not a URI.
	/// - [`EndpointError::Scheme`] -- the scheme is not `ws`.
	/// - [`EndpointError::Path`] -- the URL carries a path or a query.
	/// - [`EndpointError::NoHost`] -- the URL names no host.
	/// - [`EndpointError::Port`] -- the URL declares a port past 65535, or one
	///   that is not a number.
	fn from_str(endpoint: &str) -> Result<Self, Self::Err> {
		let url: Uri = endpoint.parse().map_err(EndpointError::Malformed)?;
		if url.scheme_str() != Some("ws") {
			return Err(EndpointError::Scheme);
		}

		let target = url.path_and_query().map_or("/", PathAndQuery::as_str);
		if target != "/" {
			return Err(EndpointError::Path);
		}

		let named = url.host().filter(|host| !host.is_empty());
		let host = named.ok_or(EndpointError::NoHost)?;
		let bare = host.trim_start_matches('[').trim_end_matches(']');
		let authority = url.authority().map_or("", Authority::as_str);
		let port = Self::port_in(authority)?;
		Ok(Self { host: bare.to_owned(), port })
	}
}

impl ProcessorEndpoint {
	/// The port that `authority` declares, or [`WS_DEFAULT_PORT`] when it
	/// declares none.
	///
	/// The URI parser reads a port past 65535 as no port, so this reads the
	/// declared digits itself.
	///
	/// # Errors
	///
	/// - [`EndpointError::Port`] -- the declared port is past 65535, or it is
	///   not a number.
	fn port_in(authority: &str) -> Result<u16, EndpointError> {
		let after_host = authority.rsplit_once(']').map_or(authority, |(_, rest)| rest);
		let Some((_, declared)) = after_host.rsplit_once(':') else {
			return Ok(WS_DEFAULT_PORT);
		};

		declared.parse().map_err(|_| EndpointError::Port)
	}

	/// Every socket address the host resolves to.
	///
	/// # Errors
	///
	/// - The [`io::Error`](std::io::Error) of the lookup.
	/// - [`EndpointError::Unresolved`] -- the lookup found no address.
	async fn resolve(&self) -> Result<ProcessorAddresses, BoxError> {
		let target = (self.host.as_str(), self.port);
		let resolved = lookup_host(target).await?;
		let found: Vec<SocketAddr> = resolved.collect();
		let addresses = ProcessorAddresses::try_from(found)?;
		Ok(addresses)
	}
}

/// The socket addresses a processor host resolves to, one or more, in the
/// order of the lookup.
#[derive(Debug, PartialEq, Eq)]
struct ProcessorAddresses {
	first: TightBeamSocketAddr,
	rest: Vec<TightBeamSocketAddr>,
}

impl TryFrom<Vec<SocketAddr>> for ProcessorAddresses {
	type Error = EndpointError;

	/// # Errors
	///
	/// - [`EndpointError::Unresolved`] -- `addresses` is empty.
	fn try_from(addresses: Vec<SocketAddr>) -> Result<Self, Self::Error> {
		let mut wrapped = addresses.into_iter().map(TightBeamSocketAddr);
		let first = wrapped.next().ok_or(EndpointError::Unresolved)?;
		Ok(Self { first, rest: wrapped.collect() })
	}
}

impl ProcessorAddresses {
	/// Run `attempt` on each address in order, and return the first success,
	/// or the failure of the last address.
	async fn first_answer<T, E, F>(&self, mut attempt: impl FnMut(TightBeamSocketAddr) -> F) -> Result<T, E>
	where
		F: Future<Output = Result<T, E>>,
	{
		let mut outcome = attempt(self.first).await;
		for address in &self.rest {
			if outcome.is_ok() {
				break;
			}

			outcome = attempt(*address).await;
		}

		outcome
	}
}

/// What one dial of the processor presents: the pinned trust, and the client
/// identity that the security kind of the demo presents.
struct RelayDial<'a> {
	trust: Arc<dyn CertificateTrust>,
	security: &'a Security,
}

impl RelayDial<'_> {
	/// Dial the processor at `address` through `WsListener::connect_within`,
	/// so the socket admits the ceilings of the limits the transport reads
	/// under.
	async fn connect(&self, address: TightBeamSocketAddr) -> Result<GenericClient<WsListener>, BoxError> {
		let builder = self.security.client_builder::<WsListener>(Arc::clone(&self.trust));
		let dialed = builder.connect(address).await?;
		Ok(dialed)
	}
}

/// A [`Backplane`] that carries each publish to the processor servlet over a
/// mux connection of its own, and sequences the answer of the servlet
/// through a [`Local`].
///
/// - A publish resolves with the outcome of the local publish once the
///   processor answered, so each refusal reaches the publisher.
/// - The queue holds at most [`RELAY_DEPTH`] publishes, and a full queue
///   answers `Unavailable`.
/// - A failed processor link closes the relay, so every later publish
///   answers `Unavailable`.
struct RelayBackplane {
	/// Shared with the [`RelayWorker`], which publishes each processed payload
	/// into it.
	local: Arc<Local>,
	requests: Sender<Relayed>,
	/// The processor connection and every task that serves it, which end
	/// when the backplane drops.
	_link: RelayLink,
}

impl RelayBackplane {
	/// Dial the processor over HPKE, pin `cert_path`, and spawn the relay
	/// worker.
	///
	/// - The dial answers a processor of the same [`Security`] kind as `demo`.
	/// - It presents the client identity the processor pins.
	/// - Under the paywall it pays demo invoices, so renewals stay live.
	///
	/// [`Security`]: tightbeam_ws::testing::Security
	async fn connect(endpoint: &ProcessorEndpoint, cert_path: &Path, demo: &DemoConfig) -> Result<Arc<Self>, BoxError> {
		let trust = Pinned::read(cert_path)?.trust()?;
		let addresses = endpoint.resolve().await?;
		let security = demo.security();

		let dial = RelayDial { trust, security };
		let dialed = addresses.first_answer(|address| dial.connect(address)).await?;
		let transport: ServerTransport = dialed.into_transport();
		let mut transport = demo.meter_dial(transport, RELAY_PAYMENTS);
		transport.perform_client_handshake().await?;

		/*
		 * The client half of the upstream mux assembly, with the clock of
		 * the writer kept for the emit deadline of the relay.
		 */
		let settings = transport.negotiated_mux().ok_or(LinkError::NotMultiplexed)?;
		let rekey = MuxConnector::take_rekey(&mut transport)?;
		let (reader, writer) = MuxConnector::into_envelope_halves(transport)?;
		let clock = RacingClock::try_from(writer.clock())?;
		let mux = match rekey {
			Some(context) => MuxTransport::with_rekey(reader, writer, context, settings),
			None => MuxTransport::new(reader, writer, MuxRole::Client, settings),
		};

		Ok(Self::spawned(mux.spawn(), clock, Arc::new(Local::default())))
	}

	/// Run the relay worker over the processor connection `mux`, whose writer
	/// runs on `clock`, with `local` for sequencing.
	///
	/// One worker drains the queue, so deliveries stay serialized per
	/// topic: the backplane contract.
	fn spawned(mux: SpawnedMux, clock: RacingClock, local: Arc<Local>) -> Arc<Self> {
		let (requests, queue) = channel::<Relayed>(RELAY_DEPTH);
		let link = RelayLink::serve(mux, clock, Arc::clone(&local), queue);

		Arc::new(Self { local, requests, _link: link })
	}
}

/// The relay's mux connection to the processor, and every task that serves
/// it: the responder, the keepalive, and the [`RelayWorker`].
///
/// The drop ends the drivers and every task, so a relay that drops leaves no
/// task behind.
struct RelayLink {
	_drivers: MuxDrivers,
	_tasks: JoinSet<()>,
}

impl RelayLink {
	/// Serve the processor connection `mux`, and run a worker that relays the
	/// publishes of `queue` through it into `local`.
	///
	/// - The responder refuses every peer-initiated stream, so peer-initiated work such as a
	///   paywall renewal drains at once.
	/// - A keepalive holds a quiet link open through the read deadlines of both ends.
	/// - Each round trip ends within [`PROCESSOR_DEADLINE`] on `clock`, the clock of the writer.
	fn serve(mux: SpawnedMux, clock: RacingClock, local: Arc<Local>, queue: Receiver<Relayed>) -> Self {
		let SpawnedMux { handle, responder, drivers } = mux;
		let processor = Emitter::new(handle.clone(), clock, PROCESSOR_DEADLINE);
		let worker = RelayWorker { processor, local, queue };

		let mut tasks = JoinSet::new();
		tasks.spawn(Self::refuse_peer_streams(responder));
		tasks.spawn(Self::keep_alive(handle));
		tasks.spawn(worker.run());

		Self { _drivers: drivers, _tasks: tasks }
	}

	/// Answer every peer-initiated stream of `responder` with
	/// `Unimplemented`, until the connection ends.
	async fn refuse_peer_streams(responder: MuxResponder) {
		let refuse = |_| async { ResponsePackage::new(TransitStatus::Unimplemented, None) };
		// The worker observes a failed link on its next emit.
		let _ = responder.serve(refuse).await;
	}

	/// Probe the peer of `handle` until the link fails.
	async fn keep_alive(handle: MuxHandle) {
		// The worker observes a failed link on its next emit.
		let _ = handle.keep_alive().await;
	}
}

/// One publish that the relay worker carries to the processor: its topic,
/// its request frame, and the sender of its outcome.
struct Relayed {
	topic: Topic,
	request: Frame,
	outcome: oneshot::Sender<Result<(), PublishError>>,
}

/// The task that drains the queue of a [`RelayBackplane`].
///
/// The worker holds no [`Sender`] of its queue, so the queue closes once the
/// backplane drops, and the worker ends.
struct RelayWorker {
	/// The emitter of the processor link.
	processor: Emitter,
	local: Arc<Local>,
	queue: Receiver<Relayed>,
}

impl RelayWorker {
	/// Relay each queued publish through the processor and answer its
	/// outcome, until the queue closes or the processor link is lost.
	async fn run(mut self) {
		while let Some(Relayed { topic, request, outcome }) = self.queue.recv().await {
			let relayed = self.relay(&topic, &request).await;
			let lost = matches!(relayed, Err(RelayFault::LinkLost(_)));

			// A publisher that stopped waiting reads no outcome.
			let _ = outcome.send(relayed.map_err(PublishError::from));
			if lost {
				return;
			}
		}
	}

	/// Relay one publish in one bounded round trip to the processor, then
	/// publish the processed payload into the local sequencer.
	///
	/// # Errors
	///
	/// - [`RelayFault::Refused`] -- the processor refused or spoiled the request, or the session
	///   budget could not carry it.
	/// - [`RelayFault::LinkLost`] -- the emit counts as [`LinkLost`], one past its deadline included.
	/// - [`RelayFault::Sequencer`] -- the local sequencer refused the processed payload.
	async fn relay(&self, topic: &Topic, request: &Frame) -> Result<(), RelayFault> {
		let settled = self.processor.until_settled(request).await?;
		let answered = match settled {
			Settled::Answered(answered) => answered,
			Settled::Refused(cause) => return Err(RelayFault::Refused(Box::new(cause))),
		};
		let answer = answered.ok_or_else(|| RelayFault::Refused(Box::new(EmptyAnswer)))?;
		let body = answer.decode_message::<Opaque>()?;

		let sequenced = self.local.publish(topic, body.as_bytes()).await;
		sequenced.map_err(RelayFault::Sequencer)
	}
}

/// How long one processor round-trip may take before the relay reads its
/// link as lost. Sized for a cold dockerized servlet under parallel e2e load.
const PROCESSOR_DEADLINE: EmitDeadline = match EmitDeadline::new(Duration::from_secs(15)) {
	Some(deadline) => deadline,
	None => panic!("the processor deadline is above zero"),
};

impl Backplane for RelayBackplane {
	fn attach(&self, sink: NodeSink) {
		self.local.attach(sink);
	}

	fn publish<'a>(&'a self, topic: &'a Topic, payload: &'a [u8]) -> MaybeSendFuture<'a, Result<(), PublishError>> {
		Box::pin(async move {
			let request = OpaqueFrame { id: topic.as_str(), order: 1, payload }.build()?;
			let (outcome, answered) = oneshot::channel();
			let relayed = Relayed { topic: topic.clone(), request, outcome };
			self.requests.try_send(relayed).map_err(|refusal| {
				let fault = match refusal {
					TrySendError::Full(_) => BackplaneFault::Saturated,
					TrySendError::Closed(_) => BackplaneFault::Failed(Box::new(RelayClosed)),
				};

				PublishError::Unavailable(fault)
			})?;

			let closed = || PublishError::Unavailable(BackplaneFault::Failed(Box::new(RelayClosed)));
			answered.await.unwrap_or_else(|_| Err(closed()))
		})
	}

	fn last_order<'a>(&'a self, topic: &'a Topic) -> MaybeSendFuture<'a, u64> {
		self.local.last_order(topic)
	}

	fn vacated(&self, topic: &Topic) {
		self.local.vacated(topic);
	}
}

/// Forbid every topic under `forbidden/`, for a subscribe and for a publish,
/// so the e2e suite reads the `PermissionDenied` answer.
struct DenyForbidden;

impl DenyForbidden {
	/// The verdict on `topic`: forbidden under `forbidden/`, allowed otherwise.
	fn verdict(topic: &Topic) -> AccessVerdict {
		if topic.as_str().starts_with("forbidden/") {
			return AccessVerdict::Forbid;
		}

		AccessVerdict::Allow
	}
}

impl SubscribePolicy for DenyForbidden {
	fn authorize(&self, _registry: RegistryView<'_>, _session: &SessionContext, topic: &Topic) -> AccessVerdict {
		Self::verdict(topic)
	}
}

impl PublishPolicy for DenyForbidden {
	fn authorize(&self, _registry: RegistryView<'_>, _session: &SessionContext, topic: &Topic) -> AccessVerdict {
		Self::verdict(topic)
	}
}

/// Answer one non-command stream: the demo's `poke`.
async fn answer_stream(context: ConnectionContext, frame: Arc<Frame>) -> ResponsePackage {
	if frame.metadata().id() == POKE {
		let link = ClientLink(context.emitter());
		return link.poke().await;
	}

	Unrouted.route(context, frame).await
}

/// The mux link of one served client.
struct ClientLink<'a>(&'a Emitter);

impl ClientLink<'_> {
	/// Push one server-initiated stream with the non-topic id `notice`.
	async fn poke(&self) -> ResponsePackage {
		let frame = OpaqueFrame { id: "notice", order: 1, payload: b"ping" };
		let Ok(notice) = frame.build() else {
			return ResponsePackage::new(TransitStatus::Internal, None);
		};

		let settled = self.0.until_settled(&notice).await;
		match settled {
			Ok(Settled::Answered(_)) => ResponsePackage::new(TransitStatus::Ok, None),
			Ok(Settled::Refused(cause)) => {
				eprintln!("[pubsub-demo] the client refused the poke: {cause}");
				ResponsePackage::new(TransitStatus::Unavailable, None)
			}
			Err(lost) => {
				eprintln!("[pubsub-demo] poke failed: {lost}");
				ResponsePackage::new(TransitStatus::Unavailable, None)
			}
		}
	}
}

/// One accepted encrypted connection of the demo server, and the demo
/// configuration that meters it.
struct PubsubConnection {
	transport: ServerTransport,
	demo: Arc<DemoConfig>,
}

impl PubsubConnection {
	/// Serve the connection through `commands` until it ends.
	async fn serve(self, commands: PubsubCommands<DenyForbidden>) -> Result<(), BoxError> {
		let Self { transport, demo } = self;

		let mut transport = demo.meter(transport);
		transport.negotiate_mux().await?;

		let link = AcceptedLink::accepted(transport)?;
		commands.serve(link, answer_stream).await?;
		Ok(())
	}
}

/// The variable that sets the listen port.
const PORT: EnvVar = EnvVar::new("PUBSUB_WS_PORT");

/// The variable that bounds each subscriber queue.
const QUEUE_CAPACITY: EnvVar = EnvVar::new("PUBSUB_QUEUE_CAPACITY");

/// The variable that caps the live subscriptions of one connection.
const MAX_SUBSCRIPTIONS: EnvVar = EnvVar::new("PUBSUB_MAX_SUBSCRIPTIONS");

/// The variable naming the `ws://` URL of the processor servlet.
const PROCESSOR_ENDPOINT: EnvVar = EnvVar::new("PUBSUB_PROCESSOR_ENDPOINT");

/// The variable naming the processor certificate DER file the relay pins.
const PROCESSOR_CERT: EnvVar = EnvVar::new("PUBSUB_PROCESSOR_CERT");

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let defaults = RegistryOptions::default();
	let port: u16 = PORT.parsed()?;
	let queue_capacity = QUEUE_CAPACITY.parsed_or(defaults.queue_capacity)?;
	let max_subscriptions_per_connection = MAX_SUBSCRIPTIONS.parsed_or(defaults.max_subscriptions_per_connection)?;
	let bind_addr = TightBeamSocketAddr(format!("0.0.0.0:{port}").parse()?);
	let demo = Arc::new(DemoConfig::from_env()?);

	let mut options = RegistryOptions { queue_capacity, max_subscriptions_per_connection, ..defaults };
	if let Some(endpoint) = PROCESSOR_ENDPOINT.value()? {
		let processor: ProcessorEndpoint = endpoint.parse()?;
		let cert_path = PROCESSOR_CERT.required_path()?;
		options.backplane = RelayBackplane::connect(&processor, &cert_path, &demo).await?;
		println!("[pubsub-demo] publishing through the processor at {endpoint}");
	}

	let registry = TopicRegistry::new(options);
	let commands = PubsubCommands::new(registry, DenyForbidden).with_publish(DenyForbidden);

	let identity = Identity::from_env()?;
	let config = demo.security().server_config(&identity)?;
	let (listener, bound) = <WsListener as EncryptedProtocol>::bind_with(bind_addr, config).await?;
	println!(
		"[pubsub-demo] multiplexed encrypted ({}) tightbeam pub/sub demo listening on ws://{}",
		demo.security(),
		bound.0
	);

	loop {
		let (transport, peer) = listener.accept().await?;
		let commands = commands.clone();
		let connection = PubsubConnection { transport, demo: Arc::clone(&demo) };
		tokio::spawn(async move {
			if let Err(error) = connection.serve(commands).await {
				eprintln!("[pubsub-demo] connection from {peer} ended: {error}");
			}
		});
	}
}

#[cfg(test)]
mod tests {
	use core::future::{pending, poll_fn};
	use core::num::NonZeroUsize;
	use core::task::Poll;
	use core::time::Duration;

	use tightbeam::clock::{Clock, SystemClock};
	use tightbeam::transport::multiplex::MuxDispatch;
	use tightbeam::transport::TransportResult;
	use tightbeam_pubsub::testing::{BackplaneConformance, Dial, Fabric, Loopback, Peer};
	use tightbeam_pubsub::AllowAll;
	use tokio::net::TcpListener;
	use tokio::sync::OnceCell;
	use tokio::task::JoinHandle;
	use tokio::time::timeout;

	use super::*;

	/// Bound every wait on a live link, so a regression fails at the bound.
	const DEADLINE: Duration = Duration::from_secs(5);

	fn endpoint(url: &str) -> Result<ProcessorEndpoint, EndpointError> {
		url.parse()
	}

	fn named(host: &str, port: u16) -> ProcessorEndpoint {
		ProcessorEndpoint { host: host.to_owned(), port }
	}

	#[test]
	fn a_value_that_is_no_uri_is_refused() {
		let parsed = endpoint("ws://pubsub processor");
		assert!(matches!(parsed, Err(EndpointError::Malformed(_))));
	}

	#[test]
	fn an_endpoint_with_a_query_is_refused() {
		let parsed = endpoint("ws://pubsub-processor:9111?relay=1");
		assert!(matches!(parsed, Err(EndpointError::Path)));
	}

	#[test]
	fn a_port_past_the_u16_range_is_refused() {
		let parsed = endpoint("ws://pubsub-processor:99999");
		assert!(matches!(parsed, Err(EndpointError::Port)));
	}

	#[test]
	fn a_port_that_is_not_a_number_is_refused() {
		let parsed = endpoint("ws://pubsub-processor:abc");
		assert!(matches!(parsed, Err(EndpointError::Port)));
	}

	#[tokio::test]
	async fn an_address_literal_resolves_to_itself() {
		let parsed = endpoint("ws://127.0.0.1:9111").expect("a loopback URL parses");
		let resolved = parsed.resolve().await;

		let loopback = TightBeamSocketAddr(SocketAddr::from(([127, 0, 0, 1], 9111)));
		assert_eq!(resolved.ok(), Some(ProcessorAddresses { first: loopback, rest: Vec::new() }));
	}

	#[test]
	fn a_lookup_with_no_address_is_unresolved() {
		let addresses = ProcessorAddresses::try_from(Vec::new());
		assert!(matches!(addresses, Err(EndpointError::Unresolved)));
	}

	/// A loopback address that no listener holds: one a listener bound and
	/// let go.
	async fn closed_address() -> SocketAddr {
		let probe = TcpListener::bind("127.0.0.1:0").await.expect("loopback binds");
		probe.local_addr().expect("a bound listener has an address")
	}

	#[tokio::test]
	async fn a_dial_tries_each_address_until_one_answers() {
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("loopback binds");
		let open = listener.local_addr().expect("a bound listener has an address");
		let addresses = ProcessorAddresses::try_from(vec![closed_address().await, open]);
		let addresses = addresses.expect("two addresses make a set");

		let dial = |address: TightBeamSocketAddr| async move { TcpStream::connect(address.0).await.map(|_| address) };
		let answered = addresses.first_answer(dial).await;
		assert_eq!(answered.ok(), Some(TightBeamSocketAddr(open)));
	}

	/// A processor that refuses the payload `bad`, as a servlet refuses a
	/// malformed note, and echoes every other payload.
	struct RefusingBad;

	impl MuxDispatch for RefusingBad {
		async fn unary(&self, frame: Arc<Frame>) -> TransportResult<ResponsePackage> {
			let Ok(body) = frame.decode_message::<Opaque>() else {
				return Ok(ResponsePackage::new(TransitStatus::Internal, None));
			};
			if body.as_bytes() == b"bad" {
				return Ok(ResponsePackage::new(TransitStatus::InvalidArgument, None));
			}

			let frame = OpaqueFrame { id: "processed", order: 1, payload: body.as_bytes() };
			let answer = frame.build().ok();
			Ok(ResponsePackage::new(TransitStatus::Ok, answer))
		}
	}

	/// The relay end of one loopback link to a processor, and the processor
	/// end, accepted and not yet served.
	async fn processor_link() -> (SpawnedMux, tightbeam_pubsub::testing::ServerEnd) {
		let opened = Loopback::open(&Dial::default()).await;
		let Loopback { server, client } = opened.expect("a loopback link opens");
		(client, server)
	}

	/// A relay over the processor link `mux`, the client end of a loopback
	/// link, which runs on the system clock, with `local` for sequencing.
	fn relay_over(mux: SpawnedMux, local: Arc<Local>) -> Arc<RelayBackplane> {
		let system: Arc<dyn Clock> = Arc::new(SystemClock);
		let clock = RacingClock::try_from(system).expect("a test link races on a tokio thread");
		RelayBackplane::spawned(mux, clock, local)
	}

	/// A relay with `local` for sequencing over a link to [`RefusingBad`],
	/// and the serve of the processor, which ends with the link.
	async fn relay_to_processor(local: Arc<Local>) -> (Arc<RelayBackplane>, JoinHandle<TransportResult<()>>) {
		let (relay, processor) = processor_link().await;
		let serving = tokio::spawn(processor.spawn().serve_dispatch(RefusingBad, pending()));
		(relay_over(relay, local), serving)
	}

	/// The relays of one fabric: each node dials its own processor and
	/// sequences through the one shared [`Local`].
	struct Relays(Arc<Local>);

	impl Fabric for Relays {
		async fn join(&self) -> Arc<dyn Backplane> {
			let (relay, _serving) = relay_to_processor(Arc::clone(&self.0)).await;
			relay as Arc<dyn Backplane>
		}
	}

	#[tokio::test]
	async fn the_relay_keeps_the_backplane_contract() {
		let fresh = |limit: NonZeroUsize| Relays(Arc::new(Local::default().with_max_topics(limit)));
		let checked = BackplaneConformance::new(fresh).check().await;
		assert!(checked.is_ok(), "each relay should keep the backplane contract: {checked:?}");
	}

	/// The fabric of one relay, which every node publishes through.
	///
	/// The one worker of the relay carries the publishes of every topic, as
	/// the single consumer task of `docs/pubsub.md` (Backplane) does.
	struct SharedRelay {
		local: Arc<Local>,
		relay: OnceCell<Arc<RelayBackplane>>,
	}

	impl Fabric for SharedRelay {
		async fn join(&self) -> Arc<dyn Backplane> {
			let dialed = self.relay.get_or_init(|| async {
				let (relay, _serving) = relay_to_processor(Arc::clone(&self.local)).await;
				relay
			});
			Arc::clone(dialed.await) as Arc<dyn Backplane>
		}
	}

	#[tokio::test]
	async fn a_relay_that_every_node_shares_keeps_the_backplane_contract() {
		let fresh = |limit: NonZeroUsize| SharedRelay {
			local: Arc::new(Local::default().with_max_topics(limit)),
			relay: OnceCell::new(),
		};
		let checked = BackplaneConformance::new(fresh).check().await;
		assert!(checked.is_ok(), "the relay should keep the backplane contract: {checked:?}");
	}

	/// A registry on `backplane`, and the commands its peers connect through.
	fn served_on(backplane: &Arc<RelayBackplane>) -> (TopicRegistry, PubsubCommands<AllowAll>) {
		let shared = Arc::clone(backplane) as Arc<dyn Backplane>;
		let registry = TopicRegistry::new(RegistryOptions { backplane: shared, ..RegistryOptions::default() });
		let commands = PubsubCommands::new(registry.clone(), AllowAll);
		(registry, commands)
	}

	/// A peer of `commands` subscribed to each of `names`.
	async fn subscriber(commands: &PubsubCommands<AllowAll>, names: &[&str]) -> Peer {
		let peer = Peer::connect(commands, &Dial::default())
			.await
			.expect("a loopback peer connects");
		for name in names {
			peer.subscribe(&name.parse::<Topic>().expect("the name should be a topic"))
				.await
				.expect("the subscription is accepted");
		}

		peer
	}

	/// Publish to `name` through the [`Local`] of `backplane`.
	async fn sequenced(backplane: &RelayBackplane, name: &str) -> Result<(), PublishError> {
		let topic: Topic = name.parse().expect("the name should be a topic");
		backplane.local.publish(&topic, b"tick").await
	}

	#[tokio::test]
	async fn the_relay_passes_each_vacancy_report_to_its_local() {
		let two = NonZeroUsize::new(2).expect("two is above zero");
		let (backplane, _serving) = relay_to_processor(Arc::new(Local::default().with_max_topics(two))).await;
		let (_registry, commands) = served_on(&backplane);
		let peer = subscriber(&commands, &["prices", "chat"]).await;

		let filled = [sequenced(&backplane, "prices").await, sequenced(&backplane, "chat").await];
		let refused = sequenced(&backplane, "news").await;

		peer.unsubscribe(&"prices".parse::<Topic>().expect("the name should be a topic"))
			.await
			.expect("the unsubscribe is accepted");

		let outcome = sequenced(&backplane, "news").await;
		assert!(filled.iter().all(Result::is_ok));
		assert!(matches!(refused, Err(PublishError::TopicLimit)));
		assert!(outcome.is_ok());
	}

	#[tokio::test]
	async fn a_processor_refusal_leaves_the_relay_running() {
		let (backplane, _serving) = relay_to_processor(Arc::new(Local::default())).await;
		let (_registry, commands) = served_on(&backplane);
		let mut peer = subscriber(&commands, &["prices"]).await;

		let refused = backplane
			.publish(&"prices".parse::<Topic>().expect("the name should be a topic"), b"bad")
			.await;
		let accepted = backplane
			.publish(&"prices".parse::<Topic>().expect("the name should be a topic"), b"good")
			.await;

		let update = timeout(DEADLINE, peer.next_update()).await.ok().flatten();
		let update = update.expect("the processed publish arrives");
		let body = update.decode_message::<Opaque>().expect("an update carries an opaque body");
		assert!(matches!(refused, Err(PublishError::Unavailable(BackplaneFault::Failed(_)))));
		assert!(accepted.is_ok());
		assert_eq!(update.metadata().order(), 1);
		assert_eq!(body.as_bytes(), b"good");
	}

	#[tokio::test]
	async fn a_processor_failure_closes_the_relay() {
		let (relay, processor) = processor_link().await;

		// A processor that is gone closes the link, so the first request
		// fails and the relay closes.
		drop(processor);

		let backplane = relay_over(relay, Arc::new(Local::default()));
		let first = timeout(
			DEADLINE,
			backplane.publish(&"prices".parse::<Topic>().expect("the name should be a topic"), b"tick"),
		)
		.await;
		let closed = timeout(DEADLINE, backplane.requests.closed()).await;

		let after = backplane
			.publish(&"prices".parse::<Topic>().expect("the name should be a topic"), b"tick")
			.await;
		assert!(matches!(first, Ok(Err(PublishError::Unavailable(BackplaneFault::Failed(_))))));
		assert!(closed.is_ok());
		assert!(matches!(after, Err(PublishError::Unavailable(BackplaneFault::Failed(_)))));
	}

	/// Start `attempts` publishes, each polled once and held, and answer the
	/// outcome of the last, or `None` while it waits.
	async fn flooded(backplane: &RelayBackplane, attempts: usize, topic: &Topic) -> Option<Result<(), PublishError>> {
		let mut held = Vec::with_capacity(attempts);
		let mut last = None;
		for _ in 0..attempts {
			let mut publishing = backplane.publish(topic, b"tick");
			let polled = poll_fn(|context| Poll::Ready(publishing.as_mut().poll(context))).await;
			last = match polled {
				Poll::Ready(outcome) => Some(outcome),
				Poll::Pending => None,
			};
			held.push(publishing);
		}

		last
	}

	#[tokio::test]
	async fn a_saturated_relay_refuses_the_publish() {
		let (relay, processor) = processor_link().await;
		let backplane = relay_over(relay, Arc::new(Local::default()));

		// The processor end reads nothing, so the worker waits out its first
		// round trip and the queue only fills. One publish past the queue
		// depth, and the one the worker holds, is refused.
		let last = flooded(
			&backplane,
			RELAY_DEPTH + 2,
			&"prices".parse::<Topic>().expect("the name should be a topic"),
		)
		.await;
		assert!(matches!(last, Some(Err(PublishError::Unavailable(BackplaneFault::Saturated)))));

		drop(processor);
	}

	#[tokio::test]
	async fn a_dropped_relay_ends_its_processor_link() {
		let (backplane, serving) = relay_to_processor(Arc::new(Local::default())).await;

		drop(backplane);

		let ended = timeout(DEADLINE, serving).await;
		assert!(ended.is_ok(), "the processor should read the end of the link");
	}

	#[test]
	fn the_compose_endpoint_names_its_service_and_port() {
		let parsed = endpoint("ws://pubsub-processor:9111");
		assert_eq!(parsed.ok(), Some(named("pubsub-processor", 9111)));
	}

	#[test]
	fn an_endpoint_with_no_port_takes_the_ws_default() {
		let parsed = endpoint("ws://pubsub-processor/");
		assert_eq!(parsed.ok(), Some(named("pubsub-processor", WS_DEFAULT_PORT)));
	}

	#[test]
	fn an_ipv6_endpoint_drops_its_brackets() {
		let parsed = endpoint("ws://[::1]:9111");
		assert_eq!(parsed.ok(), Some(named("::1", 9111)));
	}

	#[test]
	fn an_endpoint_with_a_path_is_refused() {
		let parsed = endpoint("ws://pubsub-processor:9111/relay");
		assert!(matches!(parsed, Err(EndpointError::Path)));
	}

	#[test]
	fn an_endpoint_with_no_host_is_refused() {
		let parsed = endpoint("ws://:9111");
		assert!(matches!(parsed, Err(EndpointError::NoHost)));
	}

	#[test]
	fn an_endpoint_past_the_ws_scheme_is_refused() {
		let parsed = endpoint("wss://pubsub-processor:9111");
		assert!(matches!(parsed, Err(EndpointError::Scheme)));
	}
}
