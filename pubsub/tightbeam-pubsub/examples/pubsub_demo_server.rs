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
//!   - `PUBSUB_PROCESSOR_ENDPOINT`  when set, publishes relay through the
//!     processor servlet at this ws:// URL ([`RelayBackplane`])
//!   - `PUBSUB_PROCESSOR_CERT`      path to the processor certificate DER the
//!     relay dial pins (required with the endpoint)

use core::fmt;
use std::env::var;
use std::error::Error;
use std::fs;
use std::sync::{Arc, Weak};

use tightbeam::policy::TransitStatus;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::multiplex::{GoAwayReason, MuxHandle, MuxRole, MuxTransport};
use tightbeam::transport::{EncryptedMessageIO, EncryptedProtocol, ResponsePackage, X509ClientConfig};
use tightbeam::Frame;
use tightbeam_pubsub::testing::command_frame;
use tightbeam_pubsub::{
	opaque_payload, serve_connection, AccessVerdict, AllowAll, Backplane, BackplaneError, ConnectionContext, Local,
	PubsubCommands, RegistryOptions, SubscribePolicy, Topic, TopicRegistry, UpdateSink,
};
use tightbeam_ws::io::{WsStream, WsTransport};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{env_u32, pinned_trust, serve_handshake, Identity};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio_tungstenite::{connect_async, MaybeTlsStream};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

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

/// A custom [`Backplane`]: every publish crosses to the processor
/// servlet over the demo server's own tightbeam mux connection, and the
/// servlet's answer is what gets sequenced and fanned out. Composes the
/// stock [`Local`] for sequencing and sink management.
struct RelayBackplane {
	local: Local,
	requests: UnboundedSender<(Topic, Vec<u8>)>,
}

impl RelayBackplane {
	/// Dial the processor over ECIES (pinning `cert_path`) and spawn the
	/// relay worker.
	async fn connect(endpoint: &str, cert_path: &str, cap: u32) -> Result<Arc<Self>, BoxError> {
		let trust = pinned_trust(&fs::read(cert_path)?)?;
		let (websocket, _response) = connect_async(endpoint).await?;
		let transport: ServerTransport = WsTransport::from(WsStream::new(websocket));
		let mut transport = transport.with_trust_store(trust).with_mux_offer(Some(TransportOffer::mux(cap)));

		transport.perform_client_handshake().await?;

		let settings = transport
			.negotiated_mux()
			.ok_or("the processor did not negotiate multiplexing")?;
		let (reader, writer) = transport.into_split()?;

		let mux = MuxTransport::new(reader, writer, MuxRole::Client, settings);
		let (handle, reader_driver, writer_driver, _responder) = mux.into_parts();
		tokio::spawn(reader_driver.drive());
		tokio::spawn(writer_driver.drive());

		let (requests, mut queue) = unbounded_channel::<(Topic, Vec<u8>)>();
		let backplane = Arc::new(Self { local: Local::default(), requests });

		/*
		 * One worker drains the queue, so deliveries stay serialized per
		 * topic: the backplane contract.
		 */
		let relay = Arc::clone(&backplane);
		tokio::spawn(async move {
			while let Some((topic, payload)) = queue.recv().await {
				match process(&handle, &topic, &payload).await {
					Ok(processed) => {
						if let Err(error) = relay.local.publish(&topic, &processed) {
							eprintln!("[pubsub-demo] relay delivery failed: {error}");
						}
					}
					Err(error) => eprintln!("[pubsub-demo] processor request failed: {error}"),
				}
			}
		});

		Ok(backplane)
	}
}

/// One round-trip to the processor: raw payload out, processed back.
async fn process(handle: &MuxHandle, topic: &Topic, payload: &[u8]) -> Result<Vec<u8>, BoxError> {
	let request = command_frame(topic.as_str(), 1, payload)?;
	let answer = handle.emit_on_stream(&request).await?.ok_or(RelayClosed)?;
	Ok(opaque_payload(&answer)?)
}

impl Backplane for RelayBackplane {
	fn attach(&self, sink: Weak<dyn UpdateSink>) {
		self.local.attach(sink);
	}

	fn publish(&self, topic: &Topic, payload: &[u8]) -> Result<(), BackplaneError> {
		let request = (topic.clone(), payload.to_vec());
		if self.requests.send(request).is_err() {
			return Err(BackplaneError::Unavailable(Box::new(RelayClosed)));
		}

		Ok(())
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
	transport: ServerTransport,
	commands: PubsubCommands<DenyForbidden>,
	cap: u32,
) -> Result<(), BoxError> {
	let mut transport = transport.with_mux_offer(Some(TransportOffer::mux(cap)));
	serve_handshake(&mut transport).await?;

	let settings = transport.negotiated_mux().ok_or("the client did not negotiate multiplexing")?;
	let (reader, writer) = transport.into_split()?;
	let mux = MuxTransport::new(reader, writer, MuxRole::Server, settings);

	let registry = commands.registry().clone();
	serve_connection(mux, commands, move |context, frame| {
		answer_stream(registry.clone(), context, frame)
	})
	.await?;

	Ok(())
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port = env_u32("PUBSUB_WS_PORT", 9110);
	let cap = env_u32("MUX_STREAMS", 8);
	let queue_capacity = env_u32("PUBSUB_QUEUE_CAPACITY", 32) as usize;
	let bind_addr = TightBeamSocketAddr(format!("0.0.0.0:{port}").parse()?);

	let mut options = RegistryOptions { queue_capacity, ..RegistryOptions::default() };
	if let Ok(endpoint) = var("PUBSUB_PROCESSOR_ENDPOINT") {
		let cert_path = var("PUBSUB_PROCESSOR_CERT")?;
		options.backplane = RelayBackplane::connect(&endpoint, &cert_path, cap).await?;
		println!("[pubsub-demo] publishing through the processor at {endpoint}");
	}

	let registry = TopicRegistry::new(options);
	let commands = PubsubCommands::new(registry, DenyForbidden).with_publish(AllowAll);

	let identity = Identity::from_env()?;
	let (listener, bound) = <WsListener as EncryptedProtocol>::bind_with(bind_addr, identity.server_config()).await?;
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
		tokio::spawn(async move {
			if let Err(error) = serve_ws_connection(transport, commands, cap).await {
				eprintln!("[pubsub-demo] connection from {peer} ended: {error}");
			}
		});
	}
}
