//! The [`Network`] implementation the HoneyBadgerMPC engine drives.
//!
//! [`TightbeamNetwork`] owns the mesh and a local inbox. Sends to remote
//! parties cross their pairwise tightbeam link; sends to the local party
//! loop straight into the inbox, because the reference semantics (and
//! the engine's all-to-all rounds) include self-delivery. Broadcast is
//! send-to-everyone, self included. `send_to_client` rides the inbound
//! link an authorized consumer established by dialing this party.
//!
//! The engine inbox is taken once by the caller's message loop, which
//! feeds each `(sender, bytes)` delivery into the engine's `process`;
//! sender ids above the party space are consumer messages. The control
//! inbox carries the control lane (program submission, digest exchange,
//! reveal shares) and is taken by whichever layer runs that plane.

use core::time::Duration;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use async_trait::async_trait;
use stoffelnet::network_utils::{ClientId, Network, NetworkError, PartyId, VerifiedOrdering};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time::Instant;

use crate::error::{Error, Result};
use crate::frame::Lane;
use crate::mesh::{Delivery, Inboxes, Mesh, MeshConfig};
use crate::roster::{LocalIdentity, Roster, TbNode};
use crate::trace::TraceHandle;

/// A HoneyBadgerMPC network over a tightbeam full mesh.
pub struct TightbeamNetwork {
	mesh: Mesh,
	nodes: Vec<TbNode>,
	config: MeshConfig,
	inbox_sender: Sender<Delivery>,
	inbox: StdMutex<Option<Receiver<Delivery>>>,
	control_sender: Sender<Delivery>,
	control_inbox: StdMutex<Option<Receiver<Delivery>>>,
}

impl TightbeamNetwork {
	/// Establish the mesh and attach the local inboxes.
	///
	/// Resolves once every pairwise link exists, so a returned network
	/// is immediately usable for protocol rounds.
	pub async fn establish(roster: Roster, identity: LocalIdentity, config: MeshConfig) -> Result<Self> {
		let roster = Arc::new(roster);
		let (inbox_sender, inbox_receiver) = channel(config.inbox_capacity);
		let (control_sender, control_receiver) = channel(config.inbox_capacity);
		let inboxes = Inboxes { engine: inbox_sender.clone(), control: control_sender.clone() };

		let nodes = roster.entries().iter().map(|entry| TbNode::new(entry.id())).collect();
		let mesh = Mesh::establish(Arc::clone(&roster), identity, config.clone(), inboxes).await?;

		Ok(Self {
			mesh,
			nodes,
			config,
			inbox_sender,
			inbox: StdMutex::new(Some(inbox_receiver)),
			control_sender,
			control_inbox: StdMutex::new(Some(control_receiver)),
		})
	}

	/// A handle onto the mesh's trace collector, for layers that want
	/// their events in the same stream as the link lifecycle.
	pub fn trace(&self) -> TraceHandle {
		self.config.trace.clone()
	}

	/// Take the engine delivery stream: every inbound engine message as
	/// `(sender, bytes)`, in per-link arrival order. Yields `None` on
	/// second call; there is exactly one message loop per network.
	pub fn take_inbox(&self) -> Option<Receiver<Delivery>> {
		self.inbox.lock().unwrap_or_else(PoisonError::into_inner).take()
	}

	/// Take the control delivery stream: program submissions, digest
	/// exchanges, and reveal shares as `(sender, bytes)`. Yields `None`
	/// on second call.
	pub fn take_control_inbox(&self) -> Option<Receiver<Delivery>> {
		self.control_inbox.lock().unwrap_or_else(PoisonError::into_inner).take()
	}

	/// Deliver a control payload to one party, looping local sends into
	/// the local control inbox.
	pub async fn send_control(&self, recipient: PartyId, message: &[u8]) -> Result<usize> {
		if recipient == self.mesh.local() {
			self.control_sender
				.send((recipient, message.to_vec()))
				.await
				.map_err(|_| Error::InboxClosed)?;
			return Ok(message.len());
		}

		self.mesh.send(recipient, Lane::Control, message).await
	}

	/// Deliver a control payload to a connected consumer.
	pub async fn send_control_to_client(&self, client: ClientId, message: &[u8]) -> Result<usize> {
		let sent = self.mesh.send_to_client(client, Lane::Control, message).await?;
		Ok(sent)
	}

	/// Wait until every listed consumer holds a live link, or the
	/// deadline elapses.
	///
	/// A consumer's handshake completes on its dial side before this
	/// party's accept task installs the link, so callers that need to
	/// `send_to_client` must wait here first.
	pub async fn await_clients(&self, clients: &[ClientId], deadline: Duration) -> Result<()> {
		let expected = clients.len();
		if expected == 0 {
			return Ok(());
		}

		let deadline_at = Instant::now() + deadline;
		loop {
			let connected = clients.iter().filter(|client| self.mesh.is_client_connected(**client)).count();
			if connected == expected {
				return Ok(());
			}

			let now = Instant::now();
			if now >= deadline_at {
				return Err(Error::ClientsNotReady { connected, expected });
			}

			let remaining = deadline_at - now;
			let pause = self.config.dial_retry_interval.min(remaining);
			tokio::time::sleep(pause).await;
		}
	}

	/// Route an engine payload to one party, looping local sends into
	/// the local engine inbox.
	async fn route(&self, recipient: PartyId, message: &[u8]) -> Result<usize> {
		if recipient == self.mesh.local() {
			self.inbox_sender
				.send((recipient, message.to_vec()))
				.await
				.map_err(|_| Error::InboxClosed)?;
			return Ok(message.len());
		}

		self.mesh.send(recipient, Lane::Engine, message).await
	}
}

#[async_trait]
impl Network for TightbeamNetwork {
	type NodeType = TbNode;
	type NetworkConfig = MeshConfig;

	async fn send(&self, recipient: PartyId, message: &[u8]) -> core::result::Result<usize, NetworkError> {
		let sent = self.route(recipient, message).await?;
		Ok(sent)
	}

	async fn broadcast(&self, message: &[u8]) -> core::result::Result<usize, NetworkError> {
		let mut total = 0;
		for id in 0..self.nodes.len() {
			total += self.route(id, message).await?;
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
		&self.config
	}

	fn node(&self, id: PartyId) -> Option<&Self::NodeType> {
		self.nodes.get(id)
	}

	fn node_mut(&mut self, id: PartyId) -> Option<&mut Self::NodeType> {
		self.nodes.get_mut(id)
	}

	async fn send_to_client(&self, client: ClientId, message: &[u8]) -> core::result::Result<usize, NetworkError> {
		let sent = self.mesh.send_to_client(client, Lane::Engine, message).await?;
		Ok(sent)
	}

	fn clients(&self) -> Vec<ClientId> {
		self.mesh.connected_clients()
	}

	fn is_client_connected(&self, client: ClientId) -> bool {
		self.mesh.is_client_connected(client)
	}

	fn local_party_id(&self) -> PartyId {
		self.mesh.local()
	}

	fn party_count(&self) -> usize {
		self.nodes.len()
	}

	fn verified_ordering(&self) -> Option<VerifiedOrdering> {
		// Party identity is fixed by the certificate roster before the
		// mesh forms, so no post-hoc consensus ordering exists.
		None
	}
}
