//! The consumer-side [`Network`]: an MPC client that provides inputs
//! and receives outputs without holding a share of the computation.

use core::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use async_trait::async_trait;
use futures_util::future::try_join_all;
use stoffelnet::network_utils::{ClientId, Network, NetworkError, PartyId, VerifiedOrdering};
use tightbeam::transport::multiplex::MuxHandle;
use tokio::sync::mpsc::{channel, Receiver};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::Instant;

use crate::error::{Error, Result};
use crate::frame;
use crate::frame::Lane;
use crate::mesh::{dial_link, emit_backpressured, Delivery, EmitOutcome, Inboxes, MeshConfig};
use crate::roster::{LocalIdentity, Roster, TbNode};
use crate::trace::{events, TraceHandle};

/// State shared between the send paths and re-dials.
struct ClientShared {
	roster: Arc<Roster>,
	identity: LocalIdentity,
	config: MeshConfig,
	links: StdMutex<HashMap<PartyId, MuxHandle>>,
	inboxes: Inboxes,
	order: AtomicU64,
	/// Serializes re-dials so concurrent failing sends rebuild one link.
	redial: AsyncMutex<()>,
}

impl ClientShared {
	fn lock_links(&self) -> std::sync::MutexGuard<'_, HashMap<PartyId, MuxHandle>> {
		self.links.lock().unwrap_or_else(PoisonError::into_inner)
	}

	fn link(&self, peer: PartyId) -> Option<MuxHandle> {
		self.lock_links().get(&peer).cloned()
	}

	async fn dial_once(&self, peer: PartyId) -> Result<MuxHandle> {
		let entry = self.roster.entry(peer).ok_or(Error::PartyNotFound { peer })?;
		let handle = dial_link(entry, &self.identity, self.config.stream_cap, self.inboxes.clone()).await?;

		self.config.trace.event(&events::LINK_UP)?;
		self.lock_links().insert(peer, handle.clone());

		Ok(handle)
	}

	async fn redial(&self, peer: PartyId) -> Result<MuxHandle> {
		let _guard = self.redial.lock().await;
		if let Some(handle) = self.link(peer) {
			return Ok(handle);
		}

		self.config.trace.event(&events::REDIAL)?;
		self.dial_once(peer).await
	}
}

/// A consumer's network: one dialed, mutually-authenticated tightbeam
/// link per party.
pub struct TightbeamClient {
	shared: Arc<ClientShared>,
	nodes: Vec<TbNode>,
	inbox: StdMutex<Option<Receiver<Delivery>>>,
	control_inbox: StdMutex<Option<Receiver<Delivery>>>,
}

impl TightbeamClient {
	/// Dial every party and attach the local inboxes.
	///
	/// Parties boot in any order, so each dial retries until it lands
	/// or the establishment deadline passes. Resolves once every party
	/// link exists.
	pub async fn establish(roster: Roster, identity: LocalIdentity, config: MeshConfig) -> Result<Self> {
		roster.verify_client_identity(&identity)?;

		let roster = Arc::new(roster);
		let (inbox_sender, inbox_receiver) = channel(config.inbox_capacity);
		let (control_sender, control_receiver) = channel(config.inbox_capacity);
		let deadline = Instant::now() + config.establish_timeout;

		let nodes: Vec<TbNode> = roster.entries().iter().map(|entry| TbNode::new(entry.id())).collect();
		let shared = Arc::new(ClientShared {
			roster: Arc::clone(&roster),
			identity,
			config,
			links: StdMutex::new(HashMap::new()),
			inboxes: Inboxes { engine: inbox_sender, control: control_sender },
			order: AtomicU64::new(0),
			redial: AsyncMutex::new(()),
		});

		let dials = roster
			.entries()
			.iter()
			.map(|entry| dial_until(Arc::clone(&shared), entry.id(), deadline));
		try_join_all(dials).await?;

		Ok(Self {
			shared,
			nodes,
			inbox: StdMutex::new(Some(inbox_receiver)),
			control_inbox: StdMutex::new(Some(control_receiver)),
		})
	}

	/// The consumer's client id.
	pub fn client_id(&self) -> ClientId {
		self.shared.identity.id()
	}

	/// A handle onto the consumer's trace collector, for layers that
	/// want their events in the same stream as the link lifecycle.
	pub fn trace(&self) -> TraceHandle {
		self.shared.config.trace.clone()
	}

	/// Take the engine delivery stream: every party-to-client engine
	/// message as `(party, bytes)`, in per-link arrival order. Yields
	/// `None` on second call; there is exactly one message loop per
	/// consumer.
	pub fn take_inbox(&self) -> Option<Receiver<Delivery>> {
		self.inbox.lock().unwrap_or_else(PoisonError::into_inner).take()
	}

	/// Take the control delivery stream: digest echoes and other
	/// control-plane replies as `(party, bytes)`. Yields `None` on
	/// second call.
	pub fn take_control_inbox(&self) -> Option<Receiver<Delivery>> {
		self.control_inbox.lock().unwrap_or_else(PoisonError::into_inner).take()
	}

	/// Deliver a control payload to `peer` (program submission and
	/// other control-plane requests).
	pub async fn send_control(&self, peer: PartyId, payload: &[u8]) -> Result<usize> {
		let sent = self.deliver(peer, Lane::Control, payload).await?;
		Ok(sent)
	}

	/// Deliver `payload` to `peer` on `lane`, rebuilding the link if it
	/// drained or died since the last send.
	async fn deliver(&self, peer: PartyId, lane: Lane, payload: &[u8]) -> Result<usize> {
		if self.shared.roster.entry(peer).is_none() {
			return Err(Error::PartyNotFound { peer });
		}

		let built = frame::build(self.shared.order.fetch_add(1, Ordering::Relaxed), lane, payload)?;
		let deadline = self.shared.config.saturated_send_deadline;
		let trace = &self.shared.config.trace;
		let handle = match self.shared.link(peer) {
			Some(handle) => handle,
			None => self.shared.redial(peer).await?,
		};

		if matches!(emit_backpressured(&handle, &built, deadline, trace).await, EmitOutcome::Sent) {
			return Ok(payload.len());
		}

		trace.event(&events::LINK_DEAD)?;
		self.shared.lock_links().remove(&peer);

		let handle = self.shared.redial(peer).await?;
		if matches!(
			emit_backpressured(&handle, &built, deadline, trace).await,
			EmitOutcome::LinkDead
		) {
			return Err(Error::LinkUnavailable { peer });
		}

		Ok(payload.len())
	}
}

/// Dial one party until it answers or the establishment deadline
/// passes. Refused connections are expected while parties boot.
async fn dial_until(shared: Arc<ClientShared>, peer: PartyId, deadline: Instant) -> Result<()> {
	loop {
		let outcome = shared.dial_once(peer).await;
		if outcome.is_ok() {
			return Ok(());
		}

		if Instant::now() >= deadline {
			return outcome.map(|_| ());
		}

		tokio::time::sleep(shared.config.dial_retry_interval).await;
	}
}

#[async_trait]
impl Network for TightbeamClient {
	type NodeType = TbNode;
	type NetworkConfig = MeshConfig;

	async fn send(&self, recipient: PartyId, message: &[u8]) -> core::result::Result<usize, NetworkError> {
		let sent = self.deliver(recipient, Lane::Engine, message).await?;
		Ok(sent)
	}

	async fn broadcast(&self, message: &[u8]) -> core::result::Result<usize, NetworkError> {
		let mut total = 0;
		for id in 0..self.nodes.len() {
			let delivered = self.deliver(id, Lane::Engine, message).await?;
			total += delivered;
		}

		Ok(total)
	}

	fn parties(&self) -> Vec<&Self::NodeType> {
		self.nodes.iter().collect()
	}

	fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
		self.nodes.iter_mut().collect()
	}

	fn config(&self) -> &Self::NetworkConfig {
		&self.shared.config
	}

	fn node(&self, id: PartyId) -> Option<&Self::NodeType> {
		self.nodes.get(id)
	}

	fn node_mut(&mut self, id: PartyId) -> Option<&mut Self::NodeType> {
		self.nodes.get_mut(id)
	}

	async fn send_to_client(&self, client: ClientId, _message: &[u8]) -> core::result::Result<usize, NetworkError> {
		// Consumers talk to parties only; client-to-client delivery
		// does not exist in the protocol.
		Err(NetworkError::ClientNotFound(client))
	}

	fn clients(&self) -> Vec<ClientId> {
		vec![self.client_id()]
	}

	fn is_client_connected(&self, client: ClientId) -> bool {
		client == self.client_id()
	}

	fn local_party_id(&self) -> PartyId {
		// The engine treats client ids and party ids as one id space;
		// a consumer's "party id" is its client id.
		self.client_id()
	}

	fn party_count(&self) -> usize {
		self.nodes.len()
	}

	fn verified_ordering(&self) -> Option<VerifiedOrdering> {
		None
	}
}
