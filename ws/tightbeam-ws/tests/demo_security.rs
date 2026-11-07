//! Both halves of each demo [`Security`] kind, over a loopback handshake.
//!
//! Each case accepts one dial on a server of a kind and dials it under the same
//! kind, as the pubsub demo relay dials its processor. The server reports the
//! client certificate it authenticated, and the dial reports the receipt it
//! countersigned. A dial that does not pay a paywalled server fails the
//! handshake, so a case that returns `Ok` paid what it was asked.

#![cfg(feature = "testing")]

use std::sync::Arc;
use std::time::Duration;

use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::handshake::negotiation::MuxBudgets;
use tightbeam::transport::handshake::receipt::{SessionReceipt, StoredReceipt};
use tightbeam::transport::multiplex::MuxAcceptor;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, EncryptedMessageIO, EncryptedProtocol};
use tightbeam::x509::Certificate;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{DemoPaywall, Identity, Security};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The stream cap that both ends offer.
const STREAMS: u32 = 4;

/// How many invoices a dial pays.
const PAYMENTS: usize = 4;

/// The invoice of the paywalled kind.
const INVOICE: &[u8] = b"security-test-invoice";

/// The payment that settles [`INVOICE`].
const PAYMENT: &[u8] = b"security-test-payment";

/// The ceiling of the paywalled kind, above any budget that a dial could
/// request in place of the ceiling.
const CEILING: MuxBudgets = MuxBudgets { client_to_server: 50_000, server_to_client: 70_000 };

/// How long each identity stays valid.
const VALIDITY: Duration = Duration::from_secs(3600);

/// The identity of the server, which every dial pins.
fn server() -> Identity {
	let minted = Identity::mint("CN=security server,O=tightbeam-ws,C=US", 1, VALIDITY);
	minted.expect("the server identity mints")
}

/// The client identity that a mutual kind pins.
fn client() -> Identity {
	let minted = Identity::mint("CN=security client,O=tightbeam-ws,C=US", 2, VALIDITY);
	minted.expect("the client identity mints")
}

/// The paywalled kind over `client`, which invoices [`INVOICE`] under
/// [`CEILING`].
fn paywalled(client: Identity) -> Security {
	let paywall = DemoPaywall::new(INVOICE, PAYMENT, CEILING).expect("the invoice and the payment encode");
	Security::Paywalled { pinned: client, paywall: Arc::new(paywall) }
}

/// What each end observes after one handshake.
struct Handshake {
	/// The client certificate that the server authenticated, or `None` when
	/// the dial presented none.
	peer: Option<Certificate>,
	/// The receipt that the dial countersigned, or `None` for an unmetered
	/// session.
	receipt: Option<SessionReceipt>,
}

impl Handshake {
	/// The budgets that the receipt attests, or `None` for an unmetered
	/// session.
	fn budgets(&self) -> Option<MuxBudgets> {
		let receipt = self.receipt.as_ref()?;
		Some(receipt.budgets)
	}

	/// The settlement challenge that the dial paid, or `None` when the session
	/// raised none.
	fn challenge(&self) -> Option<&[u8]> {
		let receipt = self.receipt.as_ref()?;
		let challenge = receipt.ancillary.as_ref()?;
		Some(challenge.as_bytes())
	}
}

/// Accept one dial on a server of `security` that presents `server`, dial it
/// under the same kind, and report what each end observed.
async fn handshake(server: &Identity, security: &Security) -> Result<Handshake, BoxError> {
	let config = security.server_config(server).expect("the server config builds");
	let loopback = TightBeamSocketAddr("127.0.0.1:0".parse().expect("the loopback address parses"));
	let bound = <WsListener as EncryptedProtocol>::bind_with(loopback, config).await;
	let (listener, addr) = bound.expect("the server binds loopback");

	let served = accept(&listener, security);
	let dialed = dial(addr, server, security);
	let (peer, receipt) = tokio::join!(served, dialed);

	let handshake = Handshake { peer: peer?, receipt: receipt? };
	Ok(handshake)
}

/// Accept one dial on `listener` under `security`, and return the client
/// certificate that the handshake authenticated.
async fn accept(listener: &WsListener, security: &Security) -> Result<Option<Certificate>, BoxError> {
	let (transport, _peer) = listener.accept().await?;
	let mut metered = security.meter(transport, STREAMS);
	metered.negotiate_mux().await?;

	let peer = metered.peer_certificate().cloned();
	Ok(peer)
}

/// Dial `addr` under `security`, pinning `server` as the relay pins its
/// processor, and return the receipt that the session holds.
async fn dial(
	addr: TightBeamSocketAddr,
	server: &Identity,
	security: &Security,
) -> Result<Option<SessionReceipt>, BoxError> {
	let trust = server.trust_anchor().expect("the server certificate pins");
	let mut builder = ClientBuilder::<WsListener>::builder().with_trust_store(trust);
	if let Some(client) = security.client_identity() {
		builder = builder.with_client_identity(client.signing_identity()?);
	}

	let dialed = builder.connect(addr).await?;
	let mut transport = security.meter_dial(dialed.into_transport(), STREAMS, PAYMENTS);
	transport.perform_client_handshake().await?;

	let receipt = transport.session_receipt().map(StoredReceipt::receipt).cloned();
	Ok(receipt)
}

#[tokio::test]
async fn security_meters_the_offer_from_its_own_paywall() -> Result<(), BoxError> {
	let server = server();
	let security = paywalled(client());

	let handshake = handshake(&server, &security).await?;
	assert_eq!(
		handshake.budgets(),
		Some(CEILING),
		"the session grants the ceiling of the paywall"
	);
	Ok(())
}

#[tokio::test]
async fn a_paywalled_dial_presents_the_client_cert_and_pays() -> Result<(), BoxError> {
	let server = server();
	let client = client();
	let certificate = client.certificate().clone();
	let security = paywalled(client);

	let handshake = handshake(&server, &security).await?;
	assert_eq!(
		handshake.peer,
		Some(certificate),
		"the server authenticates the client certificate"
	);
	assert_eq!(handshake.challenge(), Some(INVOICE), "the dial pays the invoice of the paywall");
	Ok(())
}

#[tokio::test]
async fn a_server_auth_dial_presents_no_cert() -> Result<(), BoxError> {
	let server = server();
	let handshake = handshake(&server, &Security::ServerAuth).await?;
	assert_eq!(handshake.peer, None, "the server authenticates no client");
	assert_eq!(handshake.budgets(), None, "the session is unmetered");
	Ok(())
}

#[tokio::test]
async fn a_mutual_dial_presents_the_client_cert_and_pays_nothing() -> Result<(), BoxError> {
	let server = server();
	let client = client();
	let certificate = client.certificate().clone();
	let security = Security::Mutual { pinned: client };

	let handshake = handshake(&server, &security).await?;
	assert_eq!(
		handshake.peer,
		Some(certificate),
		"the server authenticates the client certificate"
	);
	assert_eq!(handshake.budgets(), None, "the session is unmetered, so the dial pays nothing");
	Ok(())
}
