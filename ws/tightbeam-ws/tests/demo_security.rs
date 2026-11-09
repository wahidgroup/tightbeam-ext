//! Both halves of each demo [`Security`] kind, over a loopback handshake, as
//! tightbeam scenarios.
//!
//! Each case accepts one dial on a server of a kind and dials it under the same
//! kind, as the pubsub demo relay dials its processor. Both transports record
//! on the trace, so the spec grades the handshake and the receipt each end
//! files. The server records whether the client certificate it authenticated
//! is the whole pinned identity, and the dial records the budgets and the
//! settlement challenge of the receipt it countersigned. A dial that does not
//! pay a paywalled server fails the handshake, so a case whose spec holds paid
//! what it was asked.

#![cfg(feature = "testing")]

use std::sync::Arc;
use std::time::Duration;

use tightbeam::instrumentation::events;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::{ClientEnv, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::MuxBudgets;
use tightbeam::transport::handshake::receipt::StoredReceipt;
use tightbeam::transport::multiplex::MuxAcceptor;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, EncryptedMessageIO, EncryptedProtocol};
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn, TightBeamError};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{DemoPaywall, Identity, Security};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// Which identity of the kind the client certificate that the server
/// authenticated is, as [`Security::peer_identity`] names it.
const PEER: Urn<'static> = urn!("test", "event:demo-security/peer");

/// The budgets that the receipt of the dial attests, client to server first.
const BUDGETS: Urn<'static> = urn!("test", "event:demo-security/budgets");

/// The settlement challenge that the dial paid.
const CHALLENGE: Urn<'static> = urn!("test", "event:demo-security/challenge");

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

/// How long a loopback handshake may take.
const PROMPT: Duration = Duration::from_secs(5);

/// The server of a scenario, and the socket address it bound.
type Served = Result<(JoinHandle<Result<(), TightBeamError>>, TightBeamSocketAddr), TightBeamError>;

/// A deadline that passed, as the failure of the exchange it bounded.
fn late(elapsed: tokio::time::error::Elapsed) -> TightBeamError {
	TightBeamError::IoError(elapsed.into())
}

/// One handshake of a demo kind: the identity of its server, the kind, and the
/// signal that the server recorded what it authenticated.
struct Case {
	server: Identity,
	security: Security,
	served: Notify,
}

impl Case {
	/// A case of `security` against the one server identity of this file.
	fn of(security: Security) -> Self {
		let minted = Identity::mint("CN=security server,O=tightbeam-ws,C=US", 1, VALIDITY);
		let server = minted.expect("the server identity mints");
		Self { server, security, served: Notify::new() }
	}

	/// The client identity that a mutual kind pins.
	fn client() -> Identity {
		let minted = Identity::mint("CN=security client,O=tightbeam-ws,C=US", 2, VALIDITY);
		minted.expect("the client identity mints")
	}

	/// The paywalled kind, which invoices [`INVOICE`] under [`CEILING`].
	fn paywalled() -> Self {
		let paywall = DemoPaywall::new(INVOICE, PAYMENT, CEILING).expect("the invoice and the payment encode");
		Self::of(Security::Paywalled { pinned: Self::client(), paywall: Arc::new(paywall) })
	}

	/// The kind that pins the client and meters nothing.
	fn mutual() -> Self {
		Self::of(Security::Mutual { pinned: Self::client() })
	}

	/// Bind a server of this kind on loopback, and accept one dial on it on
	/// a task, which records the client certificate it authenticated.
	async fn serve(case: Arc<Self>, trace: TraceCollector) -> Served {
		let config = case.security.server_config(&case.server)?;
		let loopback = TightBeamSocketAddr("127.0.0.1:0".parse()?);
		let (listener, addr) = <WsListener as EncryptedProtocol>::bind_with(loopback, config).await?;

		let accepting = tokio::spawn(async move {
			let (transport, _peer) = listener.accept().await?;
			let mut metered = case.security.meter(transport.with_trace(trace.share()), STREAMS);
			metered.negotiate_mux().await?;

			let peer = case.security.peer_identity(metered.peer_certificate());
			trace.event_with(PEER, &[], peer.as_str())?;
			case.served.notify_one();
			Ok(())
		});

		Ok((accepting, addr))
	}

	/// Dial `addr` under this kind, pinning the server as the relay pins its
	/// processor, record the receipt that the session holds, and wait for the
	/// server to record its side.
	async fn dial(&self, addr: TightBeamSocketAddr, trace: &TraceCollector) -> Result<(), TightBeamError> {
		let trust = self.server.trust_anchor()?;
		let mut builder = ClientBuilder::<WsListener>::builder().with_trust_store(trust);
		if let Some(client) = self.security.client_identity() {
			builder = builder.with_client_identity(client.signing_identity()?);
		}

		let dialed = builder.connect(addr).await?;
		let traced = dialed.into_transport().with_trace(trace.share());
		let mut transport = self.security.meter_dial(traced, STREAMS, PAYMENTS);
		transport.perform_client_handshake().await?;

		if let Some(receipt) = transport.session_receipt().map(StoredReceipt::receipt) {
			let budgets = (receipt.budgets.client_to_server, receipt.budgets.server_to_client);
			trace.event_with(BUDGETS, &[], budgets)?;
			if let Some(challenge) = receipt.ancillary.as_ref() {
				trace.event_with(CHALLENGE, &[], String::from_utf8_lossy(challenge.as_bytes()).into_owned())?;
			}
		}

		timeout(PROMPT, self.served.notified()).await.map_err(late)
	}
}

tb_assert_spec! {
	pub MeteredOfferSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(2)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(2)),
			(BUDGETS, exactly!(1), equals!((50_000u64, 70_000u64)))
		]
	}
}

// The paywalled kind meters the offer from its own paywall: the session
// grants the ceiling of the paywall, and both ends settle the receipt.
tb_scenario! {
	name: security_meters_the_offer_from_its_own_paywall,
	spec: MeteredOfferSpec,
	environment ServiceClient {
		context: Case::paywalled(),
		server: |SetupEnv { trace, context }| Case::serve(context, trace),
		client: |ClientEnv { trace, context, addr }| async move { context.dial(addr, &trace).await }
	}
}

tb_assert_spec! {
	pub PaywalledDialSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER, exactly!(1), equals!("pinned")),
			(CHALLENGE, exactly!(1), equals!("security-test-invoice")),
			(events::SESSION_RECEIPT_SETTLED, exactly!(2))
		]
	}
}

// A paywalled dial presents the client certificate, which the server
// authenticates, and pays the invoice of the paywall.
tb_scenario! {
	name: a_paywalled_dial_presents_the_client_cert_and_pays,
	spec: PaywalledDialSpec,
	environment ServiceClient {
		context: Case::paywalled(),
		server: |SetupEnv { trace, context }| Case::serve(context, trace),
		client: |ClientEnv { trace, context, addr }| async move { context.dial(addr, &trace).await }
	}
}

tb_assert_spec! {
	pub ServerAuthSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(2)),
			(PEER, exactly!(1), equals!("none")),
			(events::SESSION_RECEIPT_SETTLED, exactly!(0)),
			(BUDGETS, exactly!(0))
		]
	}
}

// A server-auth dial presents no certificate, so the server authenticates no
// client, and the session is unmetered.
tb_scenario! {
	name: a_server_auth_dial_presents_no_cert,
	spec: ServerAuthSpec,
	environment ServiceClient {
		context: Case::of(Security::ServerAuth),
		server: |SetupEnv { trace, context }| Case::serve(context, trace),
		client: |ClientEnv { trace, context, addr }| async move { context.dial(addr, &trace).await }
	}
}

tb_assert_spec! {
	pub MutualSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(2)),
			(PEER, exactly!(1), equals!("pinned")),
			(events::SESSION_RECEIPT_SETTLED, exactly!(0)),
			(BUDGETS, exactly!(0))
		]
	}
}

// A mutual dial presents the client certificate, which the server
// authenticates, and the session is unmetered, so the dial pays nothing.
tb_scenario! {
	name: a_mutual_dial_presents_the_client_cert_and_pays_nothing,
	spec: MutualSpec,
	environment ServiceClient {
		context: Case::mutual(),
		server: |SetupEnv { trace, context }| Case::serve(context, trace),
		client: |ClientEnv { trace, context, addr }| async move { context.dial(addr, &trace).await }
	}
}
