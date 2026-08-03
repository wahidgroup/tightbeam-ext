//! The full mesh: one mutually-authenticated, multiplexed tightbeam
//! link per party pair, plus inbound links from authorized consumers.
//!
//! Party `i` binds a listener and dials every `j > i`, so exactly one
//! TCP connection exists per pair; multiplexing makes that single link
//! serve both directions concurrently. Identity is the handshake:
//! dialers pin the target's roster certificate, acceptors validate the
//! presented certificate against the roster (direct trust) and map it
//! back to the party or client id, so a frame's sender attribution is
//! exactly the link it arrived on.
//!
//! Consumers (MPC clients) never listen: they dial every party, and the
//! server-to-client direction (`send_to_client`) rides the same mux
//! link back.
//!
//! Session lifetime: when flow-control budgets or AEAD record limits
//! drain a link (GoAway), the dialing side re-dials (parties on the
//! next send, consumers likewise); the acceptor side simply accepts the
//! replacement connection.

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use stoffelnet::network_utils::{ClientId, PartyId};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::x509::policy::{CertificateValidation, DirectTrustValidator};
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
use tightbeam::der::{Decode, Encode};
use tightbeam::policy::TransitStatus;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::handshake::{HandshakeKeyManager, TcpHandshakeState};
use tightbeam::transport::multiplex::{MuxHandle, MuxRole, MuxTransport};
use tightbeam::transport::state::EncryptedProtocolState;
use tightbeam::transport::tcp::r#async::{TokioListener, TokioStream};
use tightbeam::transport::{
	EncryptedMessageIO, EncryptedProtocol, MessageIO, ResponsePackage, TcpTransport, TransportEncryptionConfig,
	TransportError, TransportFailure, WireEnvelope, X509ClientConfig,
};
use tightbeam::x509::Certificate;
use tightbeam::{Frame, TightBeamError};
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::{timeout_at, Instant};

use crate::error::{Error, Result};
use crate::frame;
use crate::frame::Lane;
use crate::roster::{LocalIdentity, PartyEntry, Roster};
use crate::trace::{events, TraceHandle};

/// Handshake message ceiling: ECIES completes in two client messages,
/// so anything beyond a small bound is a protocol violation.
const MAX_HANDSHAKE_MESSAGES: usize = 4;

/// Terminal fate of one backpressured emit.
pub(crate) enum EmitOutcome {
	/// The frame is on the wire.
	Sent,
	/// The link is dead or stayed saturated past the deadline.
	LinkDead,
}

/// Emit with backpressure: concurrent protocol rounds can transiently
/// exhaust a link's stream budget, which is congestion, not death, so
/// those failures wait for in-flight streams to drain instead of
/// tearing the link down.
///
/// The wait rides the mux's own slot waiter, so a retry wakes the
/// moment an in-flight stream completes. Admission is advisory (a
/// concurrent emit can take the freed slot first), hence the loop;
/// `saturated_send_deadline` bounds the total wait.
///
/// Saturation is traced once per emit; a fault injected at that label
/// surfaces as a dead link, the same failure class a saturated link
/// that never drains produces.
pub(crate) async fn emit_backpressured(
	handle: &MuxHandle,
	frame: &Frame,
	deadline: Duration,
	trace: &TraceHandle,
) -> EmitOutcome {
	let give_up_at = Instant::now() + deadline;
	let mut saturation_traced = false;
	loop {
		match handle.emit_on_stream(frame).await {
			Ok(_) => return EmitOutcome::Sent,
			Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted)) => {
				if !saturation_traced {
					saturation_traced = true;
					if trace.event(&events::SEND_SATURATED).is_err() {
						return EmitOutcome::LinkDead;
					}
				}

				if Instant::now() >= give_up_at {
					return EmitOutcome::LinkDead;
				}

				let woken = timeout_at(give_up_at, handle.wait_for_stream_slot()).await;
				if !matches!(woken, Ok(Ok(()))) {
					return EmitOutcome::LinkDead;
				}
			}
			Err(_) => return EmitOutcome::LinkDead,
		}
	}
}

/// A message delivered to the local endpoint: who sent it and its bytes.
/// The sender is a party id on party-to-party links and a client id on
/// consumer links.
pub type Delivery = (PartyId, Vec<u8>);

/// The per-lane delivery channels every link serves into.
#[derive(Clone)]
pub(crate) struct Inboxes {
	/// Engine traffic: `WrappedMessage` bytes for the MPC node.
	pub(crate) engine: Sender<Delivery>,
	/// Control traffic: program submission, digest exchange, reveals.
	pub(crate) control: Sender<Delivery>,
}

impl Inboxes {
	fn for_lane(&self, lane: Lane) -> &Sender<Delivery> {
		match lane {
			Lane::Engine => &self.engine,
			Lane::Control => &self.control,
		}
	}
}

/// Tunables for mesh establishment and delivery.
#[derive(Clone, Debug)]
pub struct MeshConfig {
	/// Concurrent streams each endpoint lets its peer open per link.
	/// Bounds the number of in-flight MPC messages per direction.
	pub stream_cap: u32,
	/// Deadline for the full mesh to form.
	pub establish_timeout: Duration,
	/// Pause between dial attempts while peers are still booting.
	pub dial_retry_interval: Duration,
	/// Bound on locally queued inbound messages before backpressure
	/// propagates to the sending peers.
	pub inbox_capacity: usize,
	/// How long one send waits on a saturated link (stream budget
	/// exhausted by concurrent protocol rounds) before the link is
	/// declared dead. Saturation drains in link round-trip time, so
	/// the default is generous.
	pub saturated_send_deadline: Duration,
	/// Where link-lifecycle events (`link_up`, `link_dead`, `redial`,
	/// `send_saturated`, and their `client_` twins) are recorded. The
	/// default is an isolated collector nobody observes; verification
	/// runs inject a shared handle and check the live stream.
	pub trace: TraceHandle,
}

impl Default for MeshConfig {
	fn default() -> Self {
		Self {
			stream_cap: 64,
			establish_timeout: Duration::from_secs(30),
			dial_retry_interval: Duration::from_millis(200),
			inbox_capacity: 1024,
			saturated_send_deadline: Duration::from_secs(5),
			trace: TraceHandle::default(),
		}
	}
}

/// Pin one roster certificate as the only trust anchor for a dial.
pub(crate) fn pinned_trust(certificate: &Certificate) -> Result<Arc<dyn CertificateTrust>> {
	let store = CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
		.with_certificate(certificate.clone())
		.map_err(TightBeamError::from)?
		.build();

	Ok(Arc::new(store))
}

/// Attach a handshaken transport to the mux plane: split, spawn the two
/// drivers, and serve inbound frames into the lane-matching inbox,
/// attributed to `sender` - the id the completed handshake proved.
pub(crate) fn attach(
	transport: TcpTransport<TokioStream>,
	sender: PartyId,
	role: MuxRole,
	inboxes: Inboxes,
) -> Result<MuxHandle> {
	let settings = transport
		.negotiated_mux()
		.ok_or(Error::MuxNotNegotiated { peer: Some(sender) })?;
	let (reader, writer) = transport.into_split().map_err(TightBeamError::from)?;

	let mux = MuxTransport::new(reader, writer, role, settings);
	let (handle, reader_driver, writer_driver, responder) = mux.into_parts();

	tokio::spawn(async move {
		let _ = reader_driver.drive().await;
	});
	tokio::spawn(async move {
		let _ = writer_driver.drive().await;
	});

	tokio::spawn(async move {
		let _ = responder
			.serve(move |frame: Arc<Frame>| {
				let inboxes = inboxes.clone();
				async move { deliver(&inboxes, sender, &frame).await }
			})
			.await;
	});

	Ok(handle)
}

/// One dial attempt against a roster party: TCP connect, pinned
/// mutually-authenticated ECIES handshake, mux negotiation, link
/// attachment. Used by both party dialers and consumer dialers; the
/// two differ only in the identity they present.
pub(crate) async fn dial_link(
	entry: &PartyEntry,
	identity: &LocalIdentity,
	stream_cap: u32,
	inboxes: Inboxes,
) -> Result<MuxHandle> {
	let peer = entry.id();
	let stream = TcpStream::connect(entry.address()).await.map_err(TightBeamError::from)?;

	let key_manager = HandshakeKeyManager::new(identity.signing_key());
	let mut transport = TcpTransport::from(TokioStream::from(stream))
		.with_trust_store(pinned_trust(entry.certificate())?)
		.with_client_identity(Arc::new(identity.certificate().clone()), Arc::new(key_manager))
		.with_mux_offer(Some(TransportOffer::mux(stream_cap)));

	transport.perform_client_handshake().await.map_err(TightBeamError::from)?;
	if transport.to_handshake_state() != TcpHandshakeState::Complete {
		return Err(Error::HandshakeIncomplete { peer: Some(peer) });
	}

	let handle = attach(transport, peer, MuxRole::Client, inboxes)?;
	Ok(handle)
}

/// State shared between the send paths, the accept loop, and the dial
/// tasks.
struct MeshShared {
	local: PartyId,
	roster: Arc<Roster>,
	identity: LocalIdentity,
	config: MeshConfig,
	links: StdMutex<HashMap<PartyId, MuxHandle>>,
	client_links: StdMutex<HashMap<ClientId, MuxHandle>>,
	link_change: Notify,
	inboxes: Inboxes,
	order: AtomicU64,
	/// Serializes re-dials so concurrent failing sends rebuild one link.
	redial: AsyncMutex<()>,
}

impl MeshShared {
	fn lock_links(&self) -> std::sync::MutexGuard<'_, HashMap<PartyId, MuxHandle>> {
		self.links.lock().unwrap_or_else(PoisonError::into_inner)
	}

	fn lock_client_links(&self) -> std::sync::MutexGuard<'_, HashMap<ClientId, MuxHandle>> {
		self.client_links.lock().unwrap_or_else(PoisonError::into_inner)
	}

	fn link(&self, peer: PartyId) -> Option<MuxHandle> {
		self.lock_links().get(&peer).cloned()
	}

	fn install_link(&self, peer: PartyId, handle: MuxHandle) {
		self.lock_links().insert(peer, handle);
		self.link_change.notify_one();
	}

	fn drop_link(&self, peer: PartyId) {
		self.lock_links().remove(&peer);
	}

	fn link_count(&self) -> usize {
		self.lock_links().len()
	}

	fn next_order(&self) -> u64 {
		self.order.fetch_add(1, Ordering::Relaxed)
	}

	fn mux_offer(&self) -> TransportOffer {
		TransportOffer::mux(self.config.stream_cap)
	}

	/// The accept-side validator chain: the presented certificate must
	/// itself be a roster certificate - party or authorized client
	/// (direct trust plus expiry).
	fn roster_validators(&self) -> Vec<Arc<dyn CertificateValidation>> {
		let validator = DirectTrustValidator::default().with_trust_chain(self.roster.certificates());
		vec![Arc::new(validator)]
	}

	/// One dial attempt from this party toward a higher-id peer.
	async fn dial_once(&self, entry: &PartyEntry) -> Result<MuxHandle> {
		let handle = dial_link(entry, &self.identity, self.config.stream_cap, self.inboxes.clone()).await?;
		self.config.trace.event(&events::LINK_UP)?;
		self.install_link(entry.id(), handle.clone());
		Ok(handle)
	}

	/// Serve one accepted connection: drive the server-side handshake,
	/// map the authenticated certificate to its roster party or
	/// authorized client, enforce the dial rule, attach the link.
	async fn accept_once(&self, transport: TcpTransport<TokioStream>) -> Result<()> {
		let mut transport = transport.with_mux_offer(Some(self.mux_offer()));

		for _ in 0..MAX_HANDSHAKE_MESSAGES {
			if transport.to_handshake_state() == TcpHandshakeState::Complete {
				break;
			}

			let wire_bytes = transport.read_envelope_bytes().await.map_err(TightBeamError::from)?;
			let wire_envelope = WireEnvelope::from_der(&wire_bytes).map_err(TightBeamError::from)?;
			let WireEnvelope::Cleartext(envelope) = wire_envelope else {
				return Err(Error::HandshakeIncomplete { peer: None });
			};

			let handshake_bytes = envelope.to_der().map_err(TightBeamError::from)?;
			transport
				.perform_server_handshake(&handshake_bytes)
				.await
				.map_err(TightBeamError::from)?;
		}

		if transport.to_handshake_state() != TcpHandshakeState::Complete {
			return Err(Error::HandshakeIncomplete { peer: None });
		}

		let peer_der = transport
			.peer_certificate()
			.ok_or(Error::UnknownPeerCertificate)?
			.to_der()
			.map_err(TightBeamError::from)?;

		if let Some(peer) = self.roster.party_by_certificate_der(&peer_der) {
			// The dial rule says lower ids dial higher ones, so only lower
			// ids may arrive here; anything else is a misbehaving member.
			if peer >= self.local {
				return Err(Error::UnexpectedDialer { peer });
			}

			let handle = attach(transport, peer, MuxRole::Server, self.inboxes.clone())?;
			self.config.trace.event(&events::LINK_UP)?;
			self.install_link(peer, handle);
			return Ok(());
		}

		let client = self
			.roster
			.client_by_certificate_der(&peer_der)
			.ok_or(Error::UnknownPeerCertificate)?;

		// A reconnecting consumer replaces its old link; the stale
		// handle just drops.
		let handle = attach(transport, client, MuxRole::Server, self.inboxes.clone())?;
		self.config.trace.event(&events::CLIENT_LINK_UP)?;
		self.lock_client_links().insert(client, handle);
		Ok(())
	}

	/// Restore the link to a higher-id peer after a drain or failure.
	/// Acceptor-side links (lower-id peers and consumers) are restored
	/// by the peer's own re-dial, never from here.
	async fn redial(&self, peer: PartyId) -> Result<MuxHandle> {
		if peer <= self.local {
			return Err(Error::LinkUnavailable { peer });
		}

		let entry = self.roster.entry(peer).ok_or(Error::PartyNotFound { peer })?;
		let _guard = self.redial.lock().await;
		if let Some(handle) = self.link(peer) {
			return Ok(handle);
		}

		self.config.trace.event(&events::REDIAL)?;
		self.dial_once(entry).await
	}
}

/// Decode one inbound frame and hand it to its lane's processing loop.
async fn deliver(inboxes: &Inboxes, peer: PartyId, frame: &Frame) -> ResponsePackage {
	let Ok((lane, payload)) = frame::open(frame) else {
		return ResponsePackage::new(TransitStatus::InvalidArgument, None);
	};

	if inboxes.for_lane(lane).send((peer, payload)).await.is_err() {
		return ResponsePackage::new(TransitStatus::Unavailable, None);
	}

	ResponsePackage::new(TransitStatus::Ok, None)
}

/// The established mesh: a live link table plus the background tasks
/// keeping it populated.
pub(crate) struct Mesh {
	shared: Arc<MeshShared>,
	background: Vec<JoinHandle<()>>,
}

impl Mesh {
	/// Bind, dial, and wait until every pairwise link exists.
	///
	/// `inboxes` receive every inbound message as `(sender, bytes)`,
	/// split by lane; self-delivery is the caller's concern (the
	/// network layer routes local sends straight to the same channels).
	pub(crate) async fn establish(
		roster: Arc<Roster>,
		identity: LocalIdentity,
		config: MeshConfig,
		inboxes: Inboxes,
	) -> Result<Self> {
		roster.verify_identity(&identity)?;

		let local = identity.id();
		let expected = roster.party_count() - 1;
		let deadline = Instant::now() + config.establish_timeout;

		let shared = Arc::new(MeshShared {
			local,
			roster: Arc::clone(&roster),
			identity,
			config,
			links: StdMutex::new(HashMap::new()),
			client_links: StdMutex::new(HashMap::new()),
			link_change: Notify::new(),
			inboxes,
			order: AtomicU64::new(0),
			redial: AsyncMutex::new(()),
		});

		let listen_entry = roster.entry(local).ok_or(Error::PartyNotFound { peer: local })?;
		let key_manager = HandshakeKeyManager::new(shared.identity.signing_key());
		let encryption = TransportEncryptionConfig::new(shared.identity.certificate().clone(), key_manager)
			.with_client_validators(shared.roster_validators());
		let (listener, _bound) =
			TokioListener::bind_with(TightBeamSocketAddr::from(listen_entry.address()), encryption)
				.await
				.map_err(TightBeamError::from)?;

		let mut background = Vec::new();
		background.push(spawn_accept_loop(Arc::clone(&shared), listener));

		for entry in roster.dial_targets(local) {
			background.push(spawn_dial(Arc::clone(&shared), entry.clone(), deadline));
		}

		let mesh = Self { shared, background };
		mesh.await_full_mesh(expected, deadline).await?;
		Ok(mesh)
	}

	async fn await_full_mesh(&self, expected: usize, deadline: Instant) -> Result<()> {
		loop {
			let connected = self.shared.link_count();
			if connected == expected {
				return Ok(());
			}

			let now = Instant::now();
			if now >= deadline {
				return Err(Error::MeshIncomplete { connected, expected });
			}

			let notified = self.shared.link_change.notified();
			if tokio::time::timeout(deadline - now, notified).await.is_err() {
				let connected = self.shared.link_count();
				return Err(Error::MeshIncomplete { connected, expected });
			}
		}
	}

	/// The local party id.
	pub(crate) fn local(&self) -> PartyId {
		self.shared.local
	}

	/// Deliver `payload` to `peer` on `lane`, re-dialing dialer-side
	/// links that drained or failed since the last send.
	pub(crate) async fn send(&self, peer: PartyId, lane: Lane, payload: &[u8]) -> Result<usize> {
		if self.shared.roster.entry(peer).is_none() {
			return Err(Error::PartyNotFound { peer });
		}

		let built = frame::build(self.shared.next_order(), lane, payload)?;
		let deadline = self.shared.config.saturated_send_deadline;
		let trace = &self.shared.config.trace;
		let handle = match self.shared.link(peer) {
			Some(handle) => handle,
			None => self.shared.redial(peer).await?,
		};

		if matches!(emit_backpressured(&handle, &built, deadline, trace).await, EmitOutcome::Sent) {
			return Ok(payload.len());
		}

		// The link drained (GoAway) or died. Rebuild if this side dials
		// that peer, then retry the emit exactly once.
		trace.event(&events::LINK_DEAD)?;
		self.shared.drop_link(peer);
		let handle = self.shared.redial(peer).await?;
		if matches!(
			emit_backpressured(&handle, &built, deadline, trace).await,
			EmitOutcome::LinkDead
		) {
			return Err(Error::LinkUnavailable { peer });
		}

		Ok(payload.len())
	}

	/// Deliver `payload` to a connected consumer on `lane`. Consumers
	/// dial in, so a dead link is dropped and only the consumer's own
	/// re-dial can restore it.
	pub(crate) async fn send_to_client(&self, client: ClientId, lane: Lane, payload: &[u8]) -> Result<usize> {
		let built = frame::build(self.shared.next_order(), lane, payload)?;
		let handle = self
			.shared
			.lock_client_links()
			.get(&client)
			.cloned()
			.ok_or(Error::ClientNotConnected { client })?;

		let deadline = self.shared.config.saturated_send_deadline;
		let trace = &self.shared.config.trace;
		if matches!(
			emit_backpressured(&handle, &built, deadline, trace).await,
			EmitOutcome::LinkDead
		) {
			trace.event(&events::CLIENT_LINK_DEAD)?;
			self.shared.lock_client_links().remove(&client);
			return Err(Error::ClientNotConnected { client });
		}

		Ok(payload.len())
	}

	/// Consumers with a live link right now.
	pub(crate) fn connected_clients(&self) -> Vec<ClientId> {
		let mut clients: Vec<ClientId> = self.shared.lock_client_links().keys().copied().collect();
		clients.sort_unstable();
		clients
	}

	/// Whether a consumer currently holds a live link.
	pub(crate) fn is_client_connected(&self, client: ClientId) -> bool {
		self.shared.lock_client_links().contains_key(&client)
	}
}

impl Drop for Mesh {
	fn drop(&mut self) {
		for task in &self.background {
			task.abort();
		}
	}
}

/// Accept connections for the mesh's lifetime; each is authenticated
/// and attached on its own task so one slow handshake never blocks the
/// listener. Failed or foreign connections are dropped.
fn spawn_accept_loop(shared: Arc<MeshShared>, listener: TokioListener) -> JoinHandle<()> {
	tokio::spawn(async move {
		loop {
			let Ok((transport, _addr)) = listener.accept().await else {
				return;
			};

			let shared = Arc::clone(&shared);
			tokio::spawn(async move {
				let _ = shared.accept_once(transport).await;
			});
		}
	})
}

/// Dial one peer until it answers or the establishment deadline passes.
/// Peers boot in any order, so refused connections are expected early.
fn spawn_dial(shared: Arc<MeshShared>, entry: PartyEntry, deadline: Instant) -> JoinHandle<()> {
	tokio::spawn(async move {
		loop {
			if shared.dial_once(&entry).await.is_ok() {
				return;
			}
			if Instant::now() >= deadline {
				return;
			}
			tokio::time::sleep(shared.config.dial_retry_interval).await;
		}
	})
}
