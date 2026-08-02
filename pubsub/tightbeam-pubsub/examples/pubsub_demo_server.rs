//! Multiplexed encrypted pub/sub demo server for the e2e suite.
//!
//! Every connection completes the ECIES handshake (negotiating
//! multiplexing inside it) and shares one [`TopicRegistry`]. The wire
//! commands (`sub/`, `unsub/`, and client `pub/` publish) answer through
//! [`PubsubCommands`] inside [`serve_connection`], plus two demo
//! commands that let a test client drive the server side of the
//! contract:
//!
//!   - `poke`     push one non-topic stream (id `notice`) back
//!   - `quiesce`  complete every topic, then drain this connection
//!
//! The subscribe policy forbids every topic under `forbidden/`,
//! exercising the `PermissionDenied` answer.
//!
//! Environment:
//!   - `TBWS_SERVER_CERT`           path to the server certificate DER
//!   - `TBWS_SERVER_KEY`            path to the raw 32-byte server signing key
//!   - `PUBSUB_WS_PORT`             listen port (default `9110`)
//!   - `MUX_STREAMS`                client-initiated concurrency cap (default `8`)
//!   - `PUBSUB_QUEUE_CAPACITY`      per-subscriber queue bound (default `32`)
//!   - `PUBSUB_MAX_SUBSCRIPTIONS`   live subscriptions per connection
//!     (default `64`)
//!   - `PUBSUB_PROCESSOR_ENDPOINT`  when set, publishes relay through the
//!     processor servlet at this ws:// URL ([`RelayBackplane`])
//!   - `PUBSUB_PROCESSOR_CERT`      path to the processor certificate DER the
//!     relay dial pins (required with the endpoint)
//!   - `TBWS_CLIENT_CERT`           required when `TBWS_PAYWALL=1`
//!   - `TBWS_CLIENT_KEY`            raw 32-byte client signing key. Required
//!     for the processor relay dial under paywall (distinct from the
//!     server identity this process presents to browsers)
//!   - `TBWS_PAYWALL`               enable demo session-budget paywall

use core::fmt;
use core::time::Duration;
use std::env::{self, var};
use std::error::Error;
use std::fs;
use std::sync::{Arc, Weak};

use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::x509::policy::{CertificateValidation, RuntimeCertificatePinning};
use tightbeam::der::Decode;
use tightbeam::policy::TransitStatus;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::transport::handshake::negotiation::{TransportAuthorizer, TransportOffer};
use tightbeam::transport::multiplex::{MuxHandle, MuxRole};
use tightbeam::transport::{EncryptedMessageIO, EncryptedProtocol, ResponsePackage, X509ClientConfig};
use tightbeam::x509::Certificate;
use tightbeam::Frame;
use tightbeam_pubsub::testing::command_frame;
use tightbeam_pubsub::{
	opaque_payload, serve_connection, AccessVerdict, AllowAll, Backplane, BackplaneError, ConnectionContext, Local,
	PubsubCommands, RegistryOptions, SubscribePolicy, Topic, TopicRegistry, UpdateSink,
};
use tightbeam_ws::io::{WsStream, WsTransport};
use tightbeam_ws::mux::assemble_mux;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{
	budget_ceiling, env_u32, paywall_enabled, pinned_trust, serve_handshake, DemoPaywall, FixedWallet, Identity,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{channel, Sender};
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, MaybeTlsStream};

type BoxError = Box<dyn Error + Send + Sync>;

/// The transport an accepted WebSocket connection follows.
type ServerTransport = WsTransport<MaybeTlsStream<TcpStream>>;

/// Frame id that pushes one non-topic stream back at the client, so a
/// subscriber's fallback routing can be exercised end to end.
const POKE: &[u8] = b"poke";

/// Frame id that quiesces the registry and drains the connection.
const QUIESCE: &[u8] = b"quiesce";

/// The relay worker is gone: its channel closed.
#[derive(Debug)]
struct RelayClosed;

impl fmt::Display for RelayClosed {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("the relay worker is gone")
	}
}

impl Error for RelayClosed {}

/// The relay queue is full: publishers outpace processor round-trips.
#[derive(Debug)]
struct RelaySaturated;

impl fmt::Display for RelaySaturated {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("the relay queue is full")
	}
}

impl Error for RelaySaturated {}

/// How many publishes may wait on the processor before the relay
/// refuses new ones: the bound that keeps a fast publisher from growing
/// the queue without limit.
const RELAY_DEPTH: usize = 64;

/// A custom [`Backplane`]: every publish crosses to the processor
/// servlet over the demo server's own tightbeam mux connection, and the
/// servlet's answer is what gets sequenced and fanned out. Composes the
/// stock [`Local`] for sequencing and sink management.
///
/// This fabric documents **at-most-once** acks. [`Backplane::publish`]
/// returns once the work is enqueued, not once [`Local`] has stamped and
/// delivered. The queue is bounded at [`RELAY_DEPTH`]. A saturated relay
/// answers `Unavailable` instead of growing without limit. A processor
/// failure closes the relay so every later publish answers `Unavailable`
/// instead of silently dropping.
struct RelayBackplane {
	local: Local,
	requests: Sender<(Topic, Vec<u8>)>,
}

impl RelayBackplane {
	/// Dial the processor over ECIES, pin `cert_path`, and spawn the relay
	/// worker.
	///
	/// When `paywall` is set, the dial presents `client` (the stack client
	/// fixture the processor pins) and pays demo invoices so renewals stay
	/// live.
	async fn connect(
		endpoint: &str,
		cert_path: &str,
		cap: u32,
		paywall: bool,
		client: &Identity,
	) -> Result<Arc<Self>, BoxError> {
		let trust = pinned_trust(&fs::read(cert_path)?)?;
		let (websocket, _response) = connect_async(endpoint).await?;
		let transport: ServerTransport = WsTransport::from(WsStream::new(websocket));

		let mut offer = TransportOffer::mux(cap);
		if paywall {
			offer = offer.with_budgets(budget_ceiling());
		}

		let mut transport = transport.with_trust_store(trust).with_mux_offer(Some(offer));
		if paywall {
			let (cert, keys) = client.client_identity();
			transport = transport
				.with_client_identity(cert, keys)
				.with_receipt_approver(FixedWallet::shared(1024)?);
		}

		transport.perform_client_handshake().await?;

		let mux = assemble_mux(transport, MuxRole::Client)?;
		let (handle, reader_driver, writer_driver, responder) = mux.into_parts();

		tokio::spawn(reader_driver.drive());
		tokio::spawn(writer_driver.drive());
		/*
		 * Serve the responder so peer-initiated work such as paywall
		 * renewals drains. Otherwise the inbound queue fills and emit
		 * stalls.
		 */
		tokio::spawn(async move {
			let _ = responder
				.serve(|_| async { ResponsePackage::new(TransitStatus::Unimplemented, None) })
				.await;
		});

		Ok(Self::spawned(handle))
	}

	/// Spawn the relay worker over an established processor `handle`.
	///
	/// One worker drains the queue, so deliveries stay serialized per
	/// topic: the backplane contract.
	fn spawned(handle: MuxHandle) -> Arc<Self> {
		let (requests, mut queue) = channel::<(Topic, Vec<u8>)>(RELAY_DEPTH);
		let backplane = Arc::new(Self { local: Local::default(), requests });

		let relay = Arc::clone(&backplane);
		tokio::spawn(async move {
			while let Some((topic, payload)) = queue.recv().await {
				match process(&handle, &topic, &payload).await {
					Ok(processed) => {
						/*
						 * A local refusal is the registry quiescing: an
						 * orderly end for an update enqueued before it.
						 */
						if let Err(error) = relay.local.publish(&topic, &processed) {
							eprintln!("[pubsub-demo] relay delivery refused: {error}");
						}
					}
					Err(error) => {
						/*
						 * The processor link is broken: stop the worker so
						 * the closed queue turns every later publish into
						 * an Unavailable answer instead of a silent drop.
						 */
						eprintln!("[pubsub-demo] processor request failed, closing the relay: {error}");
						return;
					}
				}
			}
		});

		backplane
	}
}

/// How long one processor round-trip may take: an emit on a lost mux
/// link can hang rather than error, so a timeout means the relay link
/// is dead. Sized for a cold dockerized servlet under parallel e2e load.
const PROCESSOR_TIMEOUT: Duration = Duration::from_secs(15);

/// One bounded round-trip to the processor: raw payload out, processed
/// back.
async fn process(handle: &MuxHandle, topic: &Topic, payload: &[u8]) -> Result<Vec<u8>, BoxError> {
	let request = command_frame(topic.as_str(), 1, payload)?;
	let emitted = timeout(PROCESSOR_TIMEOUT, handle.emit_on_stream(&request)).await?;
	let answer = emitted?.ok_or(RelayClosed)?;
	Ok(opaque_payload(&answer)?)
}

impl Backplane for RelayBackplane {
	fn attach(&self, sink: Weak<dyn UpdateSink>) {
		self.local.attach(sink);
	}

	fn publish(&self, topic: &Topic, payload: &[u8]) -> Result<(), BackplaneError> {
		let request = (topic.clone(), payload.to_vec());
		self.requests.try_send(request).map_err(|refusal| {
			let cause: Box<dyn Error + Send + Sync> = match refusal {
				TrySendError::Full(_) => Box::new(RelaySaturated),
				TrySendError::Closed(_) => Box::new(RelayClosed),
			};

			BackplaneError::Unavailable(cause)
		})
	}

	fn reserve_order(&self, topic: &Topic) -> u64 {
		self.local.reserve_order(topic)
	}

	fn last_order(&self, topic: &Topic) -> u64 {
		self.local.last_order(topic)
	}
}

/// Forbid every topic under `forbidden/`, exercising the
/// `PermissionDenied` answer in the e2e suite.
struct DenyForbidden;

impl SubscribePolicy for DenyForbidden {
	fn authorize(&self, _identity: Option<&[u8]>, topic: &Topic) -> AccessVerdict {
		if topic.as_str().starts_with("forbidden/") {
			return AccessVerdict::Forbid;
		}

		AccessVerdict::Allow
	}
}

/// Answer one non-command stream: the demo's `poke` and `quiesce`.
async fn answer_stream(registry: TopicRegistry, context: ConnectionContext, frame: Arc<Frame>) -> ResponsePackage {
	let id = frame.metadata.id.as_slice();
	if id == POKE {
		return answer_poke(&context.handle).await;
	}
	if id == QUIESCE {
		return answer_quiesce(&registry, &context.handle).await;
	}

	ResponsePackage::new(TransitStatus::Unimplemented, None)
}

/// Push one server-initiated stream with the non-topic id `notice`.
async fn answer_poke(handle: &MuxHandle) -> ResponsePackage {
	let Ok(notice) = command_frame("notice", 1, b"ping") else {
		return ResponsePackage::new(TransitStatus::Internal, None);
	};

	match handle.emit_on_stream(&notice).await {
		Ok(_) => ResponsePackage::new(TransitStatus::Ok, None),
		Err(error) => {
			eprintln!("[pubsub-demo] poke failed: {error}");
			ResponsePackage::new(TransitStatus::Unavailable, None)
		}
	}
}

/// Complete every topic, wait for the completion pushes to leave, then
/// drain this connection with an orderly `Shutdown` GoAway.
///
/// This demo path is open to any connected peer. A production surface
/// MUST authorize the caller before it exposes an equivalent command.
/// Use [`serve_connection_as`] with a policy check when identity matters.
async fn answer_quiesce(registry: &TopicRegistry, handle: &MuxHandle) -> ResponsePackage {
	if let Err(error) = registry.quiesce() {
		eprintln!("[pubsub-demo] quiesce failed: {error}");
		return ResponsePackage::new(TransitStatus::Internal, None);
	}

	registry.flushed().await;

	if let Err(error) = handle.shutdown_with(GoAwayReason::Shutdown).await {
		eprintln!("[pubsub-demo] drain failed: {error}");
	}

	ResponsePackage::new(TransitStatus::Ok, None)
}

/// Serve one multiplexed encrypted connection until it ends.
async fn serve_ws_connection(
	mut transport: ServerTransport,
	commands: PubsubCommands<DenyForbidden>,
	cap: u32,
	authorizer: Option<Arc<dyn TransportAuthorizer>>,
) -> Result<(), BoxError> {
	let mut offer = TransportOffer::mux(cap);
	if authorizer.is_some() {
		offer = offer.with_budgets(budget_ceiling());
	}

	transport = transport.with_mux_offer(Some(offer));
	if let Some(authorizer) = authorizer {
		transport = transport.with_transport_authorizer(authorizer);
	}

	serve_handshake(&mut transport).await?;

	let mux = assemble_mux(transport, MuxRole::Server)?;
	let registry = commands.registry().clone();
	serve_connection(mux, commands, move |context, frame| {
		answer_stream(registry.clone(), context, frame)
	})
	.await?;

	Ok(())
}

/// Pin the client certificate at `path` as the only accepted client identity.
fn client_validators(path: &str) -> Result<Vec<Arc<dyn CertificateValidation>>, BoxError> {
	let cert = Certificate::from_der(&fs::read(path)?)?;
	let pinning = RuntimeCertificatePinning::<Sha3_256>::from_certificates([cert])?;

	Ok(vec![Arc::new(pinning)])
}

/// Load the client fixture from `TBWS_CLIENT_CERT` and `TBWS_CLIENT_KEY`.
///
/// The processor pins that certificate on mutual-auth dials.
fn relay_client_identity() -> Result<Identity, BoxError> {
	let certificate_der = fs::read(var("TBWS_CLIENT_CERT")?)?;
	let key_bytes = fs::read(var("TBWS_CLIENT_KEY")?)?;
	let key: [u8; 32] = key_bytes
		.as_slice()
		.try_into()
		.map_err(|_| "TBWS_CLIENT_KEY must hold exactly 32 bytes")?;

	Ok(Identity::from_der(&certificate_der, &key)?)
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port = env_u32("PUBSUB_WS_PORT", 9110);
	let cap = env_u32("MUX_STREAMS", 8);
	let queue_capacity = env_u32("PUBSUB_QUEUE_CAPACITY", 32) as usize;
	let max_subscriptions_per_connection = env_u32("PUBSUB_MAX_SUBSCRIPTIONS", 64) as usize;
	let bind_addr = TightBeamSocketAddr(format!("0.0.0.0:{port}").parse()?);

	let paywall = paywall_enabled();
	let identity = Identity::from_env()?;

	let mut options =
		RegistryOptions { queue_capacity, max_subscriptions_per_connection, ..RegistryOptions::default() };
	if let Ok(endpoint) = var("PUBSUB_PROCESSOR_ENDPOINT") {
		let cert_path = var("PUBSUB_PROCESSOR_CERT")?;
		/*
		 * The processor pins `TBWS_CLIENT_CERT`. Present that client
		 * fixture on the relay dial, not this process's server identity.
		 */
		let client = relay_client_identity()?;
		options.backplane = RelayBackplane::connect(&endpoint, &cert_path, cap, paywall, &client).await?;
		println!("[pubsub-demo] publishing through the processor at {endpoint}");
	}

	let registry = TopicRegistry::new(options);
	let commands = PubsubCommands::new(registry, DenyForbidden).with_publish(AllowAll);

	let mut config = identity.server_config();
	if paywall {
		let client_cert =
			env::var("TBWS_CLIENT_CERT").map_err(|_| "TBWS_PAYWALL requires TBWS_CLIENT_CERT (mutual auth)")?;
		config = config.with_client_validators(client_validators(&client_cert)?);
	}

	let authorizer = if paywall {
		Some(DemoPaywall::shared()?)
	} else {
		None
	};

	let (listener, bound) = <WsListener as EncryptedProtocol>::bind_with(bind_addr, config).await?;
	println!(
		"[pubsub-demo] multiplexed encrypted tightbeam pub/sub demo listening on ws://{}",
		bound.0
	);

	loop {
		// A failed WebSocket upgrade is a per-connection fault (bad
		// handshake, probe, abrupt teardown), never server-fatal.
		let (transport, peer) = match listener.accept().await {
			Ok(accepted) => accepted,
			Err(error) => {
				eprintln!("[pubsub-demo] accept failed: {error}");
				continue;
			}
		};

		let commands = commands.clone();
		let authorizer = authorizer.clone();
		tokio::spawn(async move {
			if let Err(error) = serve_ws_connection(transport, commands, cap, authorizer).await {
				eprintln!("[pubsub-demo] connection from {peer} ended: {error}");
			}
		});
	}
}

#[cfg(test)]
mod tests {
	use core::time::Duration;

	use tightbeam_pubsub::testing::memory_mux_pair;

	use super::*;

	fn topic(name: &str) -> Topic {
		name.parse().expect("test topics should parse")
	}

	/// Publish until the relay refuses with `Unavailable`, or give up:
	/// the worker observes the processor failure asynchronously, no
	/// sooner than [`PROCESSOR_TIMEOUT`] on a hung link.
	async fn relay_refused(backplane: &RelayBackplane, topic: &Topic) -> bool {
		let deadline = tokio::time::Instant::now() + PROCESSOR_TIMEOUT + Duration::from_secs(2);
		while tokio::time::Instant::now() < deadline {
			let outcome = backplane.publish(topic, b"tick");
			if matches!(outcome, Err(BackplaneError::Unavailable(_))) {
				return true;
			}

			tokio::time::sleep(Duration::from_millis(100)).await;
		}

		false
	}

	/// Publish `attempts` times without giving the worker room to
	/// drain, returning the last outcome.
	fn flooded(backplane: &RelayBackplane, attempts: usize, topic: &Topic) -> Result<(), BackplaneError> {
		let mut last = Ok(());
		for _ in 0..attempts {
			last = backplane.publish(topic, b"tick");
		}

		last
	}

	#[tokio::test]
	async fn a_saturated_relay_refuses_the_publish() {
		let (client, server) = memory_mux_pair(4);
		let (handle, _reader, _writer, _responder) = server.into_parts();
		let backplane = RelayBackplane::spawned(handle);

		/*
		 * No drivers: the worker stalls inside its first round-trip's
		 * timeout window, so the queue can only fill. One publish past
		 * the queue depth (plus the item the worker holds) must refuse
		 * instead of growing without bound.
		 */
		let last = flooded(&backplane, RELAY_DEPTH + 2, &topic("prices"));
		assert!(matches!(last, Err(BackplaneError::Unavailable(_))));

		drop(client);
	}

	#[tokio::test]
	async fn a_processor_failure_closes_the_relay() {
		let (client, server) = memory_mux_pair(4);
		let (handle, reader_driver, writer_driver, _responder) = server.into_parts();

		tokio::spawn(reader_driver.drive());
		tokio::spawn(writer_driver.drive());

		/*
		 * A dropped peer closes the link: every processor request fails,
		 * and the first failure the worker observes must close the
		 * relay instead of acking publishes into a void.
		 */
		drop(client);

		let backplane = RelayBackplane::spawned(handle);
		assert!(relay_refused(&backplane, &topic("prices")).await);
	}
}
