//! Test-support identities for multi-party fixtures.
//!
//! Real deployments provision party certificates through their PKI;
//! tests mint self-signed roots here so a whole roster exists in one
//! call. Compiled only under the `testing` feature.

use core::net::SocketAddr;
use core::time::Duration;
use std::net::TcpListener;
use std::sync::Arc;

use futures_util::future::join_all;
use stoffelnet::network_utils::{ClientId, PartyId};
use tightbeam::cert;
use tightbeam::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
use tightbeam::crypto::sign::ecdsa::{Secp256k1SigningKey, Secp256k1VerifyingKey};
use tightbeam::crypto::sign::Sha3Signer;
use tightbeam::random::OsRng;
use tightbeam::spki::SubjectPublicKeyInfoOwned;
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;

use crate::error::Result;
use crate::mesh::MeshConfig;
use crate::network::TightbeamNetwork;
use crate::roster::{ClientEntry, LocalIdentity, PartyEntry, Roster};
use crate::TightbeamClient;

/// Certificate validity horizon for minted test identities.
const TEST_VALIDITY: Duration = Duration::from_secs(60 * 60);

/// One minted party: id, self-signed certificate, and signing key.
pub struct PartyMaterials {
	id: PartyId,
	certificate: Certificate,
	signing_key: Secp256k1SigningKey,
}

impl PartyMaterials {
	/// Mint identities for parties `0..count`.
	pub fn mint(count: usize) -> Result<Vec<Self>> {
		(0..count).map(Self::mint_one).collect()
	}

	/// Mint a consumer identity under `id`, which must sit outside the
	/// party id space.
	pub fn mint_client(id: ClientId) -> Result<Self> {
		Self::mint_one(id)
	}

	fn mint_one(id: PartyId) -> Result<Self> {
		Ok(mint(id)?)
	}

	/// The party id this identity was minted for.
	pub fn id(&self) -> PartyId {
		self.id
	}

	/// The self-signed certificate.
	pub fn certificate(&self) -> &Certificate {
		&self.certificate
	}

	/// The signing key wrapped as a handshake key provider.
	pub fn signing_key(&self) -> Arc<dyn SigningKeyProvider> {
		Arc::new(Secp256k1KeyProvider::from(self.signing_key.clone()))
	}

	/// The roster line for this party at `address`.
	pub fn entry(&self, address: SocketAddr) -> PartyEntry {
		PartyEntry::new(self.id, address, self.certificate.clone())
	}

	/// The client directory line for this identity.
	pub fn client_entry(&self) -> ClientEntry {
		ClientEntry::new(self.id, self.certificate.clone())
	}

	/// The local credentials for running this party.
	pub fn identity(&self) -> LocalIdentity {
		LocalIdentity::new(self.id, self.certificate.clone(), self.signing_key())
	}
}

/// A full localhost fixture: every party meshed, one consumer linked
/// to all of them.
///
/// [`MeshConfig::establish_timeout`] bounds the whole formation, so a
/// stalled mesh surfaces as [`Error::MeshIncomplete`](crate::Error::MeshIncomplete)
/// rather than a hung test.
pub struct TestTopology {
	/// One established mesh endpoint per party, in id order.
	pub networks: Vec<Arc<TightbeamNetwork>>,
	/// The consumer's network, linked to every party.
	pub client: Arc<TightbeamClient>,
}

impl TestTopology {
	/// Establish `parties` meshed parties plus one authorized consumer
	/// under `client_id`, all over ephemeral localhost ports.
	pub async fn establish(parties: usize, client_id: ClientId) -> Result<Self> {
		Self::establish_with(parties, client_id, |_| MeshConfig::default()).await
	}

	/// [`TestTopology::establish`] with a per-party [`MeshConfig`], so
	/// scenarios can inject a shared [`TraceHandle`](crate::TraceHandle)
	/// on the observed host or tune deadlines.
	pub async fn establish_with(
		parties: usize,
		client_id: ClientId,
		mut party_config: impl FnMut(PartyId) -> MeshConfig,
	) -> Result<Self> {
		let materials = PartyMaterials::mint(parties)?;
		let consumer = PartyMaterials::mint_client(client_id)?;
		let addresses = reserve_addresses(parties)?;

		let roster_for = || -> Result<Roster> {
			let entries = materials
				.iter()
				.zip(&addresses)
				.map(|(member, address)| member.entry(*address))
				.collect();
			let roster = Roster::new(entries)?.with_clients(vec![consumer.client_entry()])?;
			Ok(roster)
		};

		let mut establishments = Vec::with_capacity(parties);
		for party in &materials {
			let config = party_config(party.id());
			establishments.push(TightbeamNetwork::establish(roster_for()?, party.identity(), config));
		}

		let mut networks = Vec::with_capacity(parties);
		for outcome in join_all(establishments).await {
			networks.push(Arc::new(outcome?));
		}

		let client_config = party_config(client_id);
		let client = TightbeamClient::establish(roster_for()?, consumer.identity(), client_config).await?;

		Ok(Self { networks, client: Arc::new(client) })
	}
}

/// Establish a party-only mesh (no consumers) over ephemeral localhost ports.
pub async fn establish_mesh(parties: usize) -> Result<Vec<Arc<TightbeamNetwork>>> {
	establish_mesh_with(parties, None, |_| MeshConfig::default()).await
}

/// Meshed parties with `client_id` authorized in every roster, but no
/// consumer dialed. The readiness gates can time out on purpose.
pub async fn establish_parties(parties: usize, client_id: ClientId) -> Result<Vec<Arc<TightbeamNetwork>>> {
	establish_mesh_with(parties, Some(client_id), |_| MeshConfig::default()).await
}

/// [`establish_mesh`] with optional authorized clients and a per-party
/// [`MeshConfig`].
pub async fn establish_mesh_with(
	parties: usize,
	client_id: Option<ClientId>,
	mut party_config: impl FnMut(PartyId) -> MeshConfig,
) -> Result<Vec<Arc<TightbeamNetwork>>> {
	let materials = PartyMaterials::mint(parties)?;
	let consumer = match client_id {
		Some(id) => Some(PartyMaterials::mint_client(id)?),
		None => None,
	};
	let addresses = reserve_addresses(parties)?;

	let roster_for = || -> Result<Roster> {
		let entries = materials
			.iter()
			.zip(&addresses)
			.map(|(member, address)| member.entry(*address))
			.collect();
		let roster = Roster::new(entries)?;
		match &consumer {
			Some(client) => roster.with_clients(vec![client.client_entry()]),
			None => Ok(roster),
		}
	};

	let mut establishments = Vec::with_capacity(parties);
	for party in &materials {
		let config = party_config(party.id());
		establishments.push(TightbeamNetwork::establish(roster_for()?, party.identity(), config));
	}

	let mut networks = Vec::with_capacity(parties);
	for outcome in join_all(establishments).await {
		networks.push(Arc::new(outcome?));
	}

	Ok(networks)
}

/// Reserve distinct localhost ports by binding ephemeral listeners,
/// releasing them just before the parties bind for real. Every
/// listener stays alive until all addresses resolve, so the OS cannot
/// hand the same port out twice.
fn reserve_addresses(count: usize) -> Result<Vec<SocketAddr>> {
	let mut listeners = Vec::with_capacity(count);
	for _ in 0..count {
		let listener = TcpListener::bind("127.0.0.1:0").map_err(TightBeamError::IoError)?;
		listeners.push(listener);
	}

	let mut addresses = Vec::with_capacity(count);
	for listener in &listeners {
		let address = listener.local_addr().map_err(TightBeamError::IoError)?;
		addresses.push(address);
	}

	Ok(addresses)
}

/// Mint one self-signed root identity. The `cert!` macro applies `?`
/// internally, so this runs under the tightbeam error type.
fn mint(id: PartyId) -> core::result::Result<PartyMaterials, TightBeamError> {
	let signing_key = Secp256k1SigningKey::random(&mut OsRng);
	let verifying_key = Secp256k1VerifyingKey::from(&signing_key);
	let spki = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;
	let signer = Sha3Signer::from(&signing_key);
	let subject = format!("CN=mpc-party-{id},O=tightbeam-mpc");

	let certificate = cert!(
		profile: Root,
		subject: subject.as_str(),
		serial: (id as u32) + 1,
		duration: TEST_VALIDITY,
		signer: &signer,
		subject_public_key: spki
	)?;

	Ok(PartyMaterials { id, certificate, signing_key })
}
