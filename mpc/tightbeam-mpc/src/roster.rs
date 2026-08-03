//! The party directory: who participates, where they listen, and which
//! certificate authenticates them.
//!
//! Party ids double as share-evaluation indices in HoneyBadgerMPC, so
//! the roster enforces dense `0..n` ids at construction. Certificates
//! are the identity anchor: the ECIES handshake proves possession of a
//! roster certificate's key, and the mesh maps that certificate back to
//! the party id, so no separate identity exchange exists to spoof.

use core::net::SocketAddr;
use std::sync::Arc;

use ark_ff::Field;
use stoffelnet::network_utils::{ClientId, Node, PartyId};
use tightbeam::crypto::key::SigningKeyProvider;
use tightbeam::der::Encode;
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;

use crate::error::{Result, RosterError};

/// One roster line: a party id, its listen address, and its certificate.
#[derive(Clone)]
pub struct PartyEntry {
	id: PartyId,
	address: SocketAddr,
	certificate: Certificate,
}

impl PartyEntry {
	/// Describe one party.
	pub fn new(id: PartyId, address: SocketAddr, certificate: Certificate) -> Self {
		Self { id, address, certificate }
	}

	/// The party id.
	pub fn id(&self) -> PartyId {
		self.id
	}

	/// The address the party's listener binds.
	pub fn address(&self) -> SocketAddr {
		self.address
	}

	/// The certificate that authenticates the party.
	pub fn certificate(&self) -> &Certificate {
		&self.certificate
	}
}

/// One authorized consumer: a client id and the certificate it
/// authenticates with. Clients hold no listen address because they
/// always dial in; the mux plane carries the server-to-client
/// direction back over the same link.
#[derive(Clone)]
pub struct ClientEntry {
	id: ClientId,
	certificate: Certificate,
}

impl ClientEntry {
	/// Describe one authorized client.
	pub fn new(id: ClientId, certificate: Certificate) -> Self {
		Self { id, certificate }
	}

	/// The client id.
	pub fn id(&self) -> ClientId {
		self.id
	}

	/// The certificate that authenticates the client.
	pub fn certificate(&self) -> &Certificate {
		&self.certificate
	}
}

/// The ordered set of protocol participants.
pub struct Roster {
	entries: Vec<PartyEntry>,
	/// DER of each entry's certificate, index-aligned with `entries`,
	/// precomputed so accept-path identity lookups never re-encode.
	certificate_ders: Vec<Vec<u8>>,
	/// Authorized consumers, with their certificate DERs index-aligned.
	clients: Vec<ClientEntry>,
	client_ders: Vec<Vec<u8>>,
}

impl Roster {
	/// Assemble a roster, sorting by party id and requiring dense
	/// `0..n` ids.
	pub fn new(mut entries: Vec<PartyEntry>) -> Result<Self> {
		if entries.is_empty() {
			return Err(RosterError::Empty.into());
		}

		entries.sort_by_key(PartyEntry::id);
		for (position, entry) in entries.iter().enumerate() {
			if entry.id() != position {
				return Err(RosterError::NonContiguousIds { expected: position, found: entry.id() }.into());
			}
		}

		let certificate_ders = entries
			.iter()
			.map(|entry| entry.certificate().to_der())
			.collect::<core::result::Result<Vec<_>, _>>()
			.map_err(TightBeamError::from)?;

		Ok(Self { entries, certificate_ders, clients: Vec::new(), client_ders: Vec::new() })
	}

	/// Authorize consumers. Client ids must sit outside the party id
	/// space and repeat neither each other nor any certificate already
	/// in the roster, because both are attribution keys.
	pub fn with_clients(mut self, clients: Vec<ClientEntry>) -> Result<Self> {
		let party_count = self.entries.len();

		for client in clients {
			// Accepted clients are pushed as we go, so this single check
			// also catches duplicates inside the incoming batch.
			let id_taken = client.id() < party_count || self.clients.iter().any(|known| known.id() == client.id());
			if id_taken {
				return Err(RosterError::ClientIdTaken { id: client.id() }.into());
			}

			let der = client.certificate().to_der().map_err(TightBeamError::from)?;
			if self.certificate_ders.contains(&der) || self.client_ders.contains(&der) {
				return Err(RosterError::AmbiguousCertificate { id: client.id() }.into());
			}

			self.client_ders.push(der);
			self.clients.push(client);
		}

		Ok(self)
	}

	/// Number of parties, including the local one.
	pub fn party_count(&self) -> usize {
		self.entries.len()
	}

	/// The entry for `id`.
	pub fn entry(&self, id: PartyId) -> Option<&PartyEntry> {
		self.entries.get(id)
	}

	/// Every entry in id order.
	pub fn entries(&self) -> &[PartyEntry] {
		&self.entries
	}

	/// The parties `local` dials: the deterministic rule is that each
	/// party dials every higher id, so exactly one link exists per pair.
	pub fn dial_targets(&self, local: PartyId) -> impl Iterator<Item = &PartyEntry> {
		self.entries.iter().filter(move |entry| entry.id() > local)
	}

	/// Every authorized client.
	pub fn clients(&self) -> &[ClientEntry] {
		&self.clients
	}

	/// Map an authenticated certificate back to its party.
	pub(crate) fn party_by_certificate_der(&self, der: &[u8]) -> Option<PartyId> {
		self.certificate_ders.iter().position(|known| known == der)
	}

	/// Map an authenticated certificate back to its client.
	pub(crate) fn client_by_certificate_der(&self, der: &[u8]) -> Option<ClientId> {
		self.client_ders
			.iter()
			.position(|known| known == der)
			.map(|index| self.clients[index].id())
	}

	/// Certificates of every party and authorized client, for the
	/// accept-side validator chain.
	pub(crate) fn certificates(&self) -> Vec<Certificate> {
		self.entries
			.iter()
			.map(PartyEntry::certificate)
			.chain(self.clients.iter().map(ClientEntry::certificate))
			.cloned()
			.collect()
	}

	/// Confirm the identity belongs to this roster: the id exists and
	/// the certificate matches the roster entry byte for byte.
	pub(crate) fn verify_identity(&self, identity: &LocalIdentity) -> Result<()> {
		let known = self
			.certificate_ders
			.get(identity.id())
			.ok_or(RosterError::LocalPartyMissing { id: identity.id() })?;

		let presented = identity.certificate().to_der().map_err(TightBeamError::from)?;

		if *known != presented {
			return Err(RosterError::CertificateMismatch { id: identity.id() }.into());
		}

		Ok(())
	}

	/// Confirm the identity names an authorized client and that its
	/// certificate matches the directory entry byte for byte.
	pub(crate) fn verify_client_identity(&self, identity: &LocalIdentity) -> Result<()> {
		let position = self
			.clients
			.iter()
			.position(|client| client.id() == identity.id())
			.ok_or(RosterError::UnknownClient { id: identity.id() })?;

		let presented = identity.certificate().to_der().map_err(TightBeamError::from)?;
		if self.client_ders[position] != presented {
			return Err(RosterError::CertificateMismatch { id: identity.id() }.into());
		}

		Ok(())
	}
}

/// The local party's credentials: its roster id, the certificate it
/// presents, and the signing key that proves possession.
#[derive(Clone)]
pub struct LocalIdentity {
	id: PartyId,
	certificate: Certificate,
	signing_key: Arc<dyn SigningKeyProvider>,
}

impl LocalIdentity {
	/// Bundle the local credentials.
	pub fn new(id: PartyId, certificate: Certificate, signing_key: Arc<dyn SigningKeyProvider>) -> Self {
		Self { id, certificate, signing_key }
	}

	/// The local party id.
	pub fn id(&self) -> PartyId {
		self.id
	}

	/// The certificate presented during handshakes.
	pub fn certificate(&self) -> &Certificate {
		&self.certificate
	}

	/// The signing key provider backing the handshakes.
	pub(crate) fn signing_key(&self) -> Arc<dyn SigningKeyProvider> {
		Arc::clone(&self.signing_key)
	}
}

/// A roster participant as the MPC engine sees it.
///
/// Follows the reference `FakeNode` semantics: `scalar_id` is the raw
/// id lifted into the field, because HoneyBadger uses it as the share
/// evaluation index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TbNode {
	id: PartyId,
}

impl TbNode {
	/// Wrap a party id.
	pub fn new(id: PartyId) -> Self {
		Self { id }
	}
}

impl Node for TbNode {
	fn id(&self) -> PartyId {
		self.id
	}

	fn scalar_id<F: Field>(&self) -> F {
		F::from(self.id as u64)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::error::Error;
	use crate::testing::PartyMaterials;

	fn roster_of(count: usize) -> (Roster, Vec<PartyMaterials>) {
		let materials = PartyMaterials::mint(count).expect("test identities should mint");
		let entries = materials
			.iter()
			.map(|party| party.entry("127.0.0.1:0".parse().expect("the literal address should parse")))
			.collect();
		let roster = Roster::new(entries).expect("the dense roster should assemble");
		(roster, materials)
	}

	#[test]
	fn dial_rule_targets_every_higher_id() {
		let (roster, _materials) = roster_of(4);

		let targets: Vec<_> = roster.dial_targets(1).map(PartyEntry::id).collect();

		assert_eq!(targets, [2, 3]);
	}

	#[test]
	fn highest_party_dials_nobody() {
		let (roster, _materials) = roster_of(3);

		let targets: Vec<_> = roster.dial_targets(2).map(PartyEntry::id).collect();

		assert!(targets.is_empty());
	}

	#[test]
	fn gapped_ids_are_rejected() {
		let materials = PartyMaterials::mint(2).expect("test identities should mint");
		let address = "127.0.0.1:0".parse().expect("the literal address should parse");
		let entries = vec![
			PartyEntry::new(0, address, materials[0].certificate().clone()),
			PartyEntry::new(2, address, materials[1].certificate().clone()),
		];

		let outcome = Roster::new(entries);

		assert!(matches!(
			outcome,
			Err(Error::Roster(RosterError::NonContiguousIds { expected: 1, found: 2 }))
		));
	}

	#[test]
	fn empty_roster_is_rejected() {
		let outcome = Roster::new(Vec::new());
		assert!(matches!(outcome, Err(Error::Roster(RosterError::Empty))));
	}

	#[test]
	fn certificates_map_back_to_their_party() {
		let (roster, materials) = roster_of(3);
		let der = materials[1].certificate().to_der().expect("the certificate should encode");

		assert_eq!(roster.party_by_certificate_der(&der), Some(1));
	}

	#[test]
	fn foreign_certificates_map_to_nobody() {
		let (roster, _materials) = roster_of(2);
		let stranger = PartyMaterials::mint(1).expect("test identities should mint");
		let der = stranger[0].certificate().to_der().expect("the certificate should encode");

		assert_eq!(roster.party_by_certificate_der(&der), None);
	}

	#[test]
	fn identity_with_foreign_certificate_is_rejected() {
		let (roster, _materials) = roster_of(2);
		let stranger = PartyMaterials::mint(1).expect("test identities should mint");
		let identity = LocalIdentity::new(0, stranger[0].certificate().clone(), stranger[0].signing_key());

		let outcome = roster.verify_identity(&identity);

		assert!(matches!(
			outcome,
			Err(Error::Roster(RosterError::CertificateMismatch { id: 0 }))
		));
	}

	#[test]
	fn scalar_id_lifts_the_raw_party_id() {
		use ark_bls12_381::Fr;

		let node = TbNode::new(3);

		assert_eq!(node.scalar_id::<Fr>(), Fr::from(3u64));
	}

	#[test]
	fn client_certificates_map_back_to_their_client() {
		let (roster, _materials) = roster_of(2);
		let consumer = PartyMaterials::mint_client(100).expect("the client identity should mint");
		let roster = roster
			.with_clients(vec![consumer.client_entry()])
			.expect("the client should be authorized");
		let der = consumer.certificate().to_der().expect("the certificate should encode");

		assert_eq!(roster.client_by_certificate_der(&der), Some(100));
		assert_eq!(roster.party_by_certificate_der(&der), None);
	}

	#[test]
	fn client_ids_inside_the_party_space_are_rejected() {
		let (roster, _materials) = roster_of(3);
		let consumer = PartyMaterials::mint_client(2).expect("the client identity should mint");

		let outcome = roster.with_clients(vec![consumer.client_entry()]);

		assert!(matches!(outcome, Err(Error::Roster(RosterError::ClientIdTaken { id: 2 }))));
	}

	#[test]
	fn duplicate_client_ids_are_rejected() {
		let (roster, _materials) = roster_of(2);
		let first = PartyMaterials::mint_client(100).expect("the client identity should mint");
		let second = PartyMaterials::mint_client(100).expect("the client identity should mint");

		let outcome = roster.with_clients(vec![first.client_entry(), second.client_entry()]);

		assert!(matches!(outcome, Err(Error::Roster(RosterError::ClientIdTaken { id: 100 }))));
	}

	#[test]
	fn client_reusing_a_party_certificate_is_rejected() {
		let (roster, materials) = roster_of(2);
		let masquerade = ClientEntry::new(100, materials[0].certificate().clone());

		let outcome = roster.with_clients(vec![masquerade]);

		assert!(matches!(
			outcome,
			Err(Error::Roster(RosterError::AmbiguousCertificate { id: 100 }))
		));
	}

	#[test]
	fn validator_chain_covers_parties_and_clients() {
		let (roster, _materials) = roster_of(2);
		let consumer = PartyMaterials::mint_client(100).expect("the client identity should mint");
		let roster = roster
			.with_clients(vec![consumer.client_entry()])
			.expect("the client should be authorized");

		assert_eq!(roster.certificates().len(), 3);
	}
}
