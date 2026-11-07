//! Multiplexed encrypted pub/sub demo server for the e2e suite.
//!
//! Every connection completes the HPKE handshake (negotiating
//! multiplexing inside it) and shares one [`TopicRegistry`]. The wire
//! commands (`sub/`, `unsub/`, and client `pub/` publish) answer through
//! [`PubsubCommands::serve`], plus one demo command that lets a test
//! client drive the server side of the contract:
//!
//!   - `poke`  push one non-topic stream (id `notice`) back
//!
//! The subscribe and publish policies forbid every topic under
//! `forbidden/`, exercising the `PermissionDenied` answer. Every connection registers
//! under the peer its handshake proved, so a policy can tell callers apart
//! by the certificate of a mutual-auth peer.
//!
//! Environment:
//!   - `TBWS_SERVER_CERT`           path to the server certificate DER, beside its key
//!   - `PUBSUB_WS_PORT`             listen port (default `9110`)
//!   - `MUX_STREAMS`                client-initiated concurrency cap (default `8`)
//!   - `PUBSUB_QUEUE_CAPACITY`      per-subscriber queue bound (default `32`)
//!   - `PUBSUB_MAX_SUBSCRIPTIONS`   live subscriptions per connection
//!     (default `64`)
//!   - `PUBSUB_PROCESSOR_ENDPOINT`  when set, publishes relay through the
//!     processor servlet at this ws:// URL ([`RelayBackplane`])
//!   - `PUBSUB_PROCESSOR_CERT`      path to the processor certificate DER the
//!     relay dial pins (required with the endpoint)
//!   - the variables of [`DemoConfig`]
//!
//! The [`DemoConfig`] decides the [`Security`] of every served connection and
//! of the relay dial alike. Under mutual auth and under the paywall, the dial
//! presents the client identity that the processor pins, distinct from the
//! server identity this process presents to browsers.
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
use tightbeam::policy::{SessionContext, TransitStatus};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::multiplex::{MuxAcceptor, MuxDrivers, MuxHandle, MuxResponder, MuxRole, SpawnedMux};
use tightbeam::transport::{
	ClientBuilder, ConnectionBuilder, EncryptedMessageIO, EncryptedProtocol, GenericClient, ResponsePackage,
};
use tightbeam::{Frame, Opaque, TightBeamError};
use tightbeam_pubsub::testing::OpaqueFrame;
use tightbeam_pubsub::{
	AccessVerdict, AppRoutes, Backplane, BackplaneFault, ConnectionContext, Emitter, LinkLost, Local, NodeSink,
	PublishError, PublishPolicy, PubsubCommands, RegistryOptions, RegistryView, Settled, SubscribePolicy, Topic,
	TopicRegistry, Unrouted,
};
use tightbeam_ws::io::WsTransport;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::serve::AcceptedLink;
use tightbeam_ws::testing::{DemoConfig, EnvVar, Identity, Pinned};
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinSet;
use tokio::time::error::Elapsed;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::http::uri::{Authority, InvalidUri, PathAndQuery};
use tokio_tungstenite::tungstenite::http::Uri;
use tokio_tungstenite::MaybeTlsStream;

type BoxError = Box<dyn Error + Send + Sync>;

/// The transport an accepted WebSocket connection follows.
type ServerTransport = WsTransport<MaybeTlsStream<TcpStream>>;

/// Frame id that pushes one non-topic stream back at the client, so a
/// subscriber's fallback routing can be exercised end to end.
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

/// Why one relayed publish produced no processed payload.
enum RelayFault {
	/// The processor refused or spoiled one request, or the session budget
	/// could not carry it, and the link stays up.
	Refused(BoxError),
	/// The processor link stalled, or an emit on it counts as [`LinkLost`].
	LinkLost(BoxError),
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

impl From<Elapsed> for RelayFault {
	/// An emit on a lost mux link can hang rather than fail, so a stalled
	/// round-trip means the link is gone.
	fn from(elapsed: Elapsed) -> Self {
		Self::LinkLost(Box::new(elapsed))
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
	/// - [`EndpointError::Malformed`]: `endpoint` is not a URI.
	/// - [`EndpointError::Scheme`]: the scheme is not `ws`.
	/// - [`EndpointError::Path`]: the URL carries a path or a query.
	/// - [`EndpointError::NoHost`]: the URL names no host.
	/// - [`EndpointError::Port`]: the URL declares a port past 65535, or one
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
	/// - [`EndpointError::Port`]: the declared port is past 65535, or it is
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
	/// - The I/O error of the lookup.
	/// - [`EndpointError::Unresolved`]: the lookup found no address.
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
	/// - [`EndpointError::Unresolved`]: `addresses` is empty.
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
	client: Option<&'a Identity>,
}

impl RelayDial<'_> {
	/// Dial the processor at `address` through `WsListener::connect_within`,
	/// so the socket admits the ceilings of the limits the transport reads
	/// under.
	async fn connect(&self, address: TightBeamSocketAddr) -> Result<GenericClient<WsListener>, BoxError> {
		let mut builder = ClientBuilder::<WsListener>::builder().with_trust_store(Arc::clone(&self.trust));
		if let Some(client) = self.client {
			builder = builder.with_client_identity(client.signing_identity()?);
		}

		let dialed = builder.connect(address).await?;
		Ok(dialed)
	}
}

/// A custom [`Backplane`]: every publish crosses to the processor
/// servlet over the demo server's own tightbeam mux connection, and the
/// servlet's answer is what gets sequenced and fanned out. Composes the
/// stock [`Local`] for sequencing and sink management.
///
/// This fabric documents **at-most-once** acks. [`Backplane::publish`]
/// returns once the work is enqueued, not once [`Local`] has stamped and
/// delivered. The queue is bounded at [`RELAY_DEPTH`]. A saturated relay
/// answers `Unavailable` instead of growing without limit. A processor
/// refusal or a spent session budget ends one publish, and a failed processor
/// link closes the relay so every later publish answers `Unavailable` instead
/// of silently dropping.
struct RelayBackplane {
	/// Shared with the [`RelayWorker`], which publishes each processed payload
	/// into it.
	local: Arc<Local>,
	requests: Sender<(Topic, Vec<u8>)>,
	/// The processor connection and every task that serves it, which end
	/// when the backplane drops.
	_link: RelayLink,
}

impl RelayBackplane {
	/// Dial the processor over HPKE, pin `cert_path`, and spawn the relay
	/// worker.
	///
	/// The dial answers a processor of the same [`Security`] kind as `demo`.
	/// It presents the client identity the processor pins, and under the
	/// paywall it pays demo invoices so renewals stay live.
	///
	/// [`Security`]: tightbeam_ws::testing::Security
	async fn connect(endpoint: &ProcessorEndpoint, cert_path: &Path, demo: &DemoConfig) -> Result<Arc<Self>, BoxError> {
		let trust = Pinned::read(cert_path)?.trust()?;
		let addresses = endpoint.resolve().await?;
		let client = demo.security().client_identity();

		let dial = RelayDial { trust, client };
		let dialed = addresses.first_answer(|address| dial.connect(address)).await?;
		let transport: ServerTransport = dialed.into_transport();
		let mut transport = demo.meter_dial(transport, RELAY_PAYMENTS);
		transport.perform_client_handshake().await?;

		let mux = transport.into_mux(MuxRole::Client)?;
		Ok(Self::spawned(mux.spawn(), Local::default()))
	}

	/// Run the relay worker over the processor connection `mux`, with `local`
	/// for sequencing.
	///
	/// One worker drains the queue, so deliveries stay serialized per
	/// topic: the backplane contract.
	fn spawned(mux: SpawnedMux, local: Local) -> Arc<Self> {
		let (requests, queue) = channel::<(Topic, Vec<u8>)>(RELAY_DEPTH);
		let local = Arc::new(local);
		let link = RelayLink::serve(mux, Arc::clone(&local), queue);

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
	///   paywall renewal drains instead of filling the inbound queue and stalling every emit.
	/// - A keepalive holds a quiet link open through the read deadlines of both ends.
	fn serve(mux: SpawnedMux, local: Arc<Local>, queue: Receiver<(Topic, Vec<u8>)>) -> Self {
		let SpawnedMux { handle, responder, drivers } = mux;
		let processor = Emitter::from(handle.clone());
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

/// The task that drains the queue of a [`RelayBackplane`].
///
/// The worker holds no [`Sender`] of its queue, so the queue closes once the
/// backplane drops, and the worker ends.
struct RelayWorker {
	/// The emitter of the processor link.
	processor: Emitter,
	local: Arc<Local>,
	queue: Receiver<(Topic, Vec<u8>)>,
}

impl RelayWorker {
	/// Relay each queued publish through the processor until the queue
	/// closes or a [`RelayFault::LinkLost`].
	async fn run(mut self) {
		while let Some((topic, payload)) = self.queue.recv().await {
			let relayed = self.relay(&topic, &payload).await;
			match relayed {
				Ok(()) => {}
				Err(RelayFault::Refused(error)) => {
					eprintln!("[pubsub-demo] the processor refused one publish: {error}");
				}
				Err(RelayFault::LinkLost(error)) => {
					/*
					 * Stop the worker so the closed queue turns every later
					 * publish into an Unavailable answer instead of a silent
					 * drop.
					 */
					eprintln!("[pubsub-demo] the processor link failed, closing the relay: {error}");
					return;
				}
			}
		}
	}

	/// Relay one publish in one bounded round-trip to the processor, raw
	/// payload out and processed back, then publish the processed payload
	/// into the local sequencer.
	///
	/// # Errors
	///
	/// - [`RelayFault::Refused`]: the processor refused or spoiled the request, or the session
	///   budget could not carry it.
	/// - [`RelayFault::LinkLost`]: the round-trip stalled, or its emit counts as [`LinkLost`].
	async fn relay(&self, topic: &Topic, payload: &[u8]) -> Result<(), RelayFault> {
		let frame = OpaqueFrame { id: topic.as_str(), order: 1, payload };
		let request = frame.build()?;
		let round_trip = self.processor.until_settled(&request);
		let settled = timeout(PROCESSOR_TIMEOUT, round_trip).await??;
		let answered = match settled {
			Settled::Answered(answered) => answered,
			Settled::Refused(cause) => return Err(RelayFault::Refused(Box::new(cause))),
		};
		let answer = answered.ok_or_else(|| RelayFault::Refused(Box::new(EmptyAnswer)))?;
		let body = answer.decode_message::<Opaque>()?;

		/*
		 * A local refusal is the registry quiescing, an orderly end for
		 * an update enqueued before it, or the topic limit.
		 */
		if let Err(error) = self.local.publish(topic, body.as_bytes()) {
			eprintln!("[pubsub-demo] relay delivery refused: {error}");
		}

		Ok(())
	}
}

/// How long one processor round-trip may take: an emit on a lost mux
/// link can hang rather than error, so a timeout means the relay link
/// is dead. Sized for a cold dockerized servlet under parallel e2e load.
const PROCESSOR_TIMEOUT: Duration = Duration::from_secs(15);

impl Backplane for RelayBackplane {
	fn attach(&self, sink: NodeSink) {
		self.local.attach(sink);
	}

	fn publish(&self, topic: &Topic, payload: &[u8]) -> Result<(), PublishError> {
		let request = (topic.clone(), payload.to_vec());
		self.requests.try_send(request).map_err(|refusal| {
			let fault = match refusal {
				TrySendError::Full(_) => BackplaneFault::Saturated,
				TrySendError::Closed(_) => BackplaneFault::Failed(Box::new(RelayClosed)),
			};

			PublishError::Unavailable(fault)
		})
	}

	fn last_order(&self, topic: &Topic) -> u64 {
		self.local.last_order(topic)
	}

	fn vacated(&self, topic: &Topic) {
		self.local.vacated(topic);
	}
}

/// Forbid every topic under `forbidden/`, for a subscribe and for a publish,
/// exercising the `PermissionDenied` answer in the e2e suite.
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
	let port = PORT.parsed_or(9110u32)?;
	let queue_capacity = QUEUE_CAPACITY.parsed_or(defaults.queue_capacity)?;
	let max_subscriptions_per_connection = MAX_SUBSCRIPTIONS.parsed_or(defaults.max_subscriptions_per_connection)?;
	let bind_addr = TightBeamSocketAddr(format!("0.0.0.0:{port}").parse()?);
	let demo = Arc::new(DemoConfig::from_env()?);

	let mut options = RegistryOptions { queue_capacity, max_subscriptions_per_connection, ..defaults };
	if let Some(endpoint) = PROCESSOR_ENDPOINT.value()? {
		let processor: ProcessorEndpoint = endpoint.parse()?;
		let cert_path = PROCESSOR_CERT.path()?;
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
		// A failed accept is the listener's own fault, such as a descriptor
		// shortage, and it clears on retry.
		let (transport, peer) = match listener.accept().await {
			Ok(accepted) => accepted,
			Err(error) => {
				eprintln!("[pubsub-demo] accept failed: {error}");
				continue;
			}
		};

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
	use core::num::NonZeroUsize;
	use core::time::Duration;
	use std::collections::HashSet;
	use std::sync::{Mutex, MutexGuard, PoisonError, Weak};

	use tightbeam::clock::{Clock, SystemClock};
	use tightbeam::transport::handshake::negotiation::MuxSettings;
	use tightbeam_pubsub::testing::MemoryLink;
	use tightbeam_pubsub::{DeliverError, UpdateSink};
	use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
	use tokio::task::yield_now;

	use super::*;

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

	/// Three loopback addresses on the ports `1`, `2`, and `3`.
	fn three_addresses() -> ProcessorAddresses {
		let ports = [1, 2, 3].map(|port| SocketAddr::from(([127, 0, 0, 1], port)));
		ProcessorAddresses::try_from(ports.to_vec()).expect("three addresses make a set")
	}

	/// A dial that answers only on port 2 and records each port it tries. A
	/// processor dial needs a live servlet behind each address, and this test
	/// reads only the order of the attempts.
	#[derive(Default)]
	struct PortTwo(Mutex<Vec<u16>>);

	impl PortTwo {
		fn lock(&self) -> MutexGuard<'_, Vec<u16>> {
			self.0.lock().unwrap_or_else(PoisonError::into_inner)
		}

		async fn dial(&self, address: TightBeamSocketAddr) -> Result<u16, u16> {
			let port = address.0.port();
			self.lock().push(port);
			if port != 2 {
				return Err(port);
			}

			Ok(port)
		}
	}

	#[tokio::test]
	async fn a_dial_tries_each_address_until_one_answers() {
		let addresses = three_addresses();
		let dial = PortTwo::default();

		let answered = addresses.first_answer(|address| dial.dial(address)).await;
		assert_eq!(answered, Ok(2));
		assert_eq!(*dial.lock(), [1, 2]);
	}

	/// Holds a live member of each topic in its set, and lets one leave with no
	/// report. A registry would need a served connection behind each member,
	/// and this test reads only membership.
	struct Members(Mutex<HashSet<Topic>>);

	impl Members {
		fn of(names: &[&str]) -> Arc<Self> {
			let topics = names.iter().map(|name| Topic::fixture(name));
			Arc::new(Self(Mutex::new(topics.collect())))
		}

		fn leave(&self, name: &str) {
			let topic = Topic::fixture(name);
			self.0.lock().unwrap_or_else(PoisonError::into_inner).remove(&topic);
		}
	}

	impl UpdateSink for Members {
		fn deliver(&self, _topic: &Topic, _order: u64, _payload: &[u8]) -> Result<(), DeliverError> {
			Ok(())
		}

		fn has_members(&self, topic: &Topic) -> bool {
			self.0.lock().unwrap_or_else(PoisonError::into_inner).contains(topic)
		}
	}

	/// A relay over a link whose processor end runs no driver, whose [`Local`]
	/// counts two topics.
	fn relay_of_two() -> (Arc<RelayBackplane>, impl Sized) {
		let (client, server) = MemoryLink::default().mux_pair(MuxSettings::symmetric(4));
		let two = NonZeroUsize::new(2).expect("two is above zero");

		let backplane = RelayBackplane::spawned(server.spawn(), Local::default().with_max_topics(two));
		(backplane, client)
	}

	/// Publish `payload` to `name` through the [`Local`] of `backplane`.
	fn sequenced(backplane: &RelayBackplane, name: &str) -> Result<(), PublishError> {
		let topic = Topic::fixture(name);
		backplane.local.publish(&topic, b"tick")
	}

	#[tokio::test]
	async fn the_relay_passes_each_vacancy_report_to_its_local() {
		let (backplane, _peer) = relay_of_two();
		let members = Members::of(&["prices", "chat"]);

		backplane.attach(NodeSink::from(&members));

		let filled = [sequenced(&backplane, "prices"), sequenced(&backplane, "chat")];
		let refused = sequenced(&backplane, "news");

		members.leave("prices");
		backplane.vacated(&Topic::fixture("prices"));

		let outcome = sequenced(&backplane, "news");
		assert!(filled.iter().all(Result::is_ok));
		assert!(matches!(refused, Err(PublishError::TopicLimit)));
		assert!(outcome.is_ok());
	}

	/// Yield until the last strong reference behind `clock` is gone, or give
	/// up.
	async fn released(clock: &Weak<dyn Clock>) -> bool {
		for _ in 0..64 {
			if clock.strong_count() == 0 {
				return true;
			}

			yield_now().await;
		}

		false
	}

	/// How long the relay waits for the processor to answer its first
	/// keepalive probe, so the keepalive sleeps out its interval when the
	/// relay drops.
	const PROBED: Duration = Duration::from_millis(50);

	#[tokio::test]
	async fn a_dropped_relay_link_ends_its_tasks() {
		let clock: Arc<dyn Clock> = Arc::new(SystemClock);
		let witness = Arc::downgrade(&clock);
		let (processor, relay) = MemoryLink::new(clock).mux_pair(MuxSettings::symmetric(4));
		let processor = processor.spawn();
		let backplane = RelayBackplane::spawned(relay.spawn(), Local::default());
		tokio::time::sleep(PROBED).await;

		drop(backplane);
		drop(processor);

		assert!(released(&witness).await);
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

	/// Publish until the relay refuses with `Unavailable`, or give up:
	/// the worker observes the processor failure asynchronously, no
	/// sooner than [`PROCESSOR_TIMEOUT`] on a hung link.
	async fn relay_refused(backplane: &RelayBackplane, topic: &Topic) -> bool {
		let deadline = tokio::time::Instant::now() + PROCESSOR_TIMEOUT + Duration::from_secs(2);
		while tokio::time::Instant::now() < deadline {
			let outcome = backplane.publish(topic, b"tick");
			if matches!(outcome, Err(PublishError::Unavailable(_))) {
				return true;
			}

			tokio::time::sleep(Duration::from_millis(100)).await;
		}

		false
	}

	/// Publish `attempts` times without giving the worker room to
	/// drain, returning the last outcome.
	fn flooded(backplane: &RelayBackplane, attempts: usize, topic: &Topic) -> Result<(), PublishError> {
		let mut last = Ok(());
		for _ in 0..attempts {
			last = backplane.publish(topic, b"tick");
		}

		last
	}

	#[tokio::test]
	async fn a_saturated_relay_refuses_the_publish() {
		let (client, server) = MemoryLink::default().mux_pair(MuxSettings::symmetric(4));
		let backplane = RelayBackplane::spawned(server.spawn(), Local::default());

		/*
		 * The processor end runs no driver: the worker stalls inside its
		 * first round-trip's timeout window, so the queue can only fill.
		 * One publish past the queue depth (plus the item the worker
		 * holds) must refuse instead of growing without bound.
		 */
		let last = flooded(&backplane, RELAY_DEPTH + 2, &Topic::fixture("prices"));
		assert!(matches!(last, Err(PublishError::Unavailable(BackplaneFault::Saturated))));

		drop(client);
	}

	/// Hands every payload the relay delivers locally to the test.
	struct Delivered(UnboundedSender<Vec<u8>>);

	impl UpdateSink for Delivered {
		fn deliver(&self, _topic: &Topic, _order: u64, payload: &[u8]) -> Result<(), DeliverError> {
			let _ = self.0.send(payload.to_vec());
			Ok(())
		}

		fn has_members(&self, _topic: &Topic) -> bool {
			true
		}
	}

	/// A processor that refuses the payload `bad`, as a servlet refuses a
	/// malformed note, and echoes every other payload.
	async fn refusing_bad(frame: Arc<Frame>) -> ResponsePackage {
		let Ok(body) = frame.decode_message::<Opaque>() else {
			return ResponsePackage::new(TransitStatus::Internal, None);
		};
		if body.as_bytes() == b"bad" {
			return ResponsePackage::new(TransitStatus::InvalidArgument, None);
		}

		let frame = OpaqueFrame { id: "processed", order: 1, payload: body.as_bytes() };
		let answer = frame.build().ok();
		ResponsePackage::new(TransitStatus::Ok, answer)
	}

	/// A relay over a live link under `settings` to [`refusing_bad`], and the
	/// receiver of every payload it delivers. The returned guard keeps the
	/// sink alive.
	fn relaying(settings: MuxSettings) -> (Arc<RelayBackplane>, UnboundedReceiver<Vec<u8>>, impl Sized) {
		let (client, server) = MemoryLink::default().mux_pair(settings);
		let SpawnedMux { handle, responder, drivers } = client.spawn();
		let processor = tokio::spawn(responder.serve(refusing_bad));

		let backplane = RelayBackplane::spawned(server.spawn(), Local::default());
		let (sender, delivered) = unbounded_channel();
		let sink = Arc::new(Delivered(sender));
		backplane.attach(NodeSink::from(&sink));
		(backplane, delivered, (sink, handle, drivers, processor.abort_handle()))
	}

	#[tokio::test]
	async fn a_processor_refusal_leaves_the_relay_running() {
		let (backplane, mut delivered, _sink) = relaying(MuxSettings::symmetric(4));
		let refused = backplane.publish(&Topic::fixture("prices"), b"bad");
		let accepted = backplane.publish(&Topic::fixture("prices"), b"good");

		let processed = timeout(Duration::from_secs(5), delivered.recv()).await;
		assert!(refused.is_ok());
		assert!(accepted.is_ok());
		assert_eq!(processed.ok().flatten(), Some(b"good".to_vec()));
	}

	#[tokio::test(start_paused = true)]
	async fn a_budget_refusal_leaves_the_relay_running() {
		let unfunded = MuxSettings::symmetric(4).with_send_budget(Some(0));
		let (backplane, _delivered, _sink) = relaying(unfunded);

		let closed = relay_refused(&backplane, &Topic::fixture("prices")).await;
		assert!(!closed);
	}

	#[tokio::test]
	async fn a_processor_failure_closes_the_relay() {
		let (client, server) = MemoryLink::default().mux_pair(MuxSettings::symmetric(4));

		/*
		 * A dropped peer closes the link: every processor request fails,
		 * and the first failure the worker observes must close the
		 * relay instead of acking publishes into a void.
		 */
		drop(client);

		let backplane = RelayBackplane::spawned(server.spawn(), Local::default());
		assert!(relay_refused(&backplane, &Topic::fixture("prices")).await);
	}
}
