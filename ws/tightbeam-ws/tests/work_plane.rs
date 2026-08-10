//! Cluster work-plane round trips through the WebSocket edge plane.
//!
//! The colony (gateway, hive, servlet) runs its internal traffic over
//! TCP. The gateway additionally binds a WebSocket edge accept plane for
//! external clients. Proves the upstream `SubmitWork` blanket impl
//! reaches `GenericClient<WsListener>` with zero library changes in this
//! crate. A signed end-to-end work frame travels from the WebSocket edge
//! through the TCP colony to a hive-registered servlet, and the
//! servlet's complete signed response frame returns to the client with
//! its signature verifiable. An unserved servlet type resolves to a
//! typed `WorkRefused` refusal.
//!
//! [`SubmitWork`]: tightbeam::colony::SubmitWork

#![cfg(feature = "testing")]
// The colony runtime macros expand `cfg(feature = ...)` probes against the
// invoking crate's feature namespace. Those upstream feature names do not
// exist in this crate, so the leaked cfg warnings carry no signal here.
#![allow(unexpected_cfgs)]

use std::sync::Arc;
use std::time::Duration;

use tightbeam::builder::TypeBuilder;
use tightbeam::colony::cluster::{Cluster, ClusterConfig, ClusterTlsConfig};
use tightbeam::colony::common::{current_timestamp_ms, ColonyNamespace};
use tightbeam::colony::hive::{Hive, HiveConfig, HiveTlsConfig};
use tightbeam::colony::servlet::ServletConfig;
use tightbeam::colony::SubmitWork;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
use tightbeam::crypto::x509::CertificateSpec;
use tightbeam::policy::TransitStatus;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::{create_test_signing_key, TestMessage};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder};
use tightbeam::utils::compose as frame_compose;
use tightbeam::utils::urn::Urn;
use tightbeam::{cluster, compose, decode, hive, servlet, Frame, TightBeamError, Version};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::Identity;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

servlet! {
	/// Answers the typed work input with a signed `pong` echo carrying a
	/// witness of whether the client's end-to-end signature verified on
	/// the bytes the servlet received, proving byte-for-byte forwarding
	/// through the gateway.
	pub WorkProbeServlet<TestMessage, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |req, frame, _ctx| async move {
		let signature_valid = frame
			.verify::<Secp256k1Signature, Sha3_256>(probe_signing_key().verifying_key())
			.is_ok();

		let unsigned = compose! {
			V0: id: &frame.metadata.id,
				message: TestMessage { content: format!("pong:{}:{signature_valid}", req.content) }
		}?;

		let provider = Secp256k1KeyProvider::from(probe_signing_key());
		Ok(Some(unsigned.sign_with_provider::<Sha3_256, _>(&provider).await?))
	}
}

hive! {
	pub WorkProbeHive,
	protocol: TokioListener
}

cluster! {
	/// TCP colony gateway with a WebSocket edge accept plane. Hives
	/// register over TCP; external clients submit work over WebSocket.
	pub WorkPlaneGateway,
	protocol: TokioListener,
	edge: WsListener
}

/// Deterministic end-to-end signing key shared by the client and the
/// probe servlet, so each side verifies the other's frame signature
/// without key distribution.
fn probe_signing_key() -> Secp256k1SigningKey {
	Secp256k1SigningKey::from(create_test_signing_key())
}

/// Servlet type URN under the default colony namespace.
fn servlet_urn(name: &str) -> Urn<'static> {
	ColonyNamespace::default()
		.servlet(name)
		.expect("static servlet names satisfy the servlet URN grammar")
}

/// One transport identity shared by the gateway, the hive, the servlet,
/// and the client trust anchor, matching the shared-identity fixture
/// layout of the upstream cluster tests.
fn stack_identity() -> Result<Identity, BoxError> {
	Ok(Identity::mint_root(
		"CN=work plane,O=tightbeam-ws,C=US",
		1,
		Duration::from_secs(3600),
	)?)
}

// The five config builders below have a twin in
// examples/work_gateway_server.rs. The colony feature is dev-only, so no
// shared module can host these colony-typed helpers. Mirror any edit here
// in the example twin.

/// The identity's signing key as a key provider for TLS configs.
fn key_provider(identity: &Identity) -> Result<Arc<Secp256k1KeyProvider>, BoxError> {
	let key = Secp256k1SigningKey::from_bytes(&identity.signing_key_bytes().into())?;
	Ok(Arc::new(Secp256k1KeyProvider::from(key)))
}

/// The identity's certificate as a built certificate spec.
fn certificate_spec(identity: &Identity) -> CertificateSpec {
	CertificateSpec::Built(Box::new(identity.certificate().clone()))
}

/// Gateway config: the shared identity for TLS, the shared trust anchor
/// on the hive plane, and an eight-stream mux offer for pooled dials.
fn cluster_conf(identity: &Identity) -> Result<ClusterConfig, BoxError> {
	let tls = ClusterTlsConfig {
		certificate: certificate_spec(identity),
		key: key_provider(identity)?,
		validators: vec![],
		client_validators: vec![],
		hive_trust: Some(identity.trust_anchor()?),
		peer_trust: None,
	};

	let mut conf = ClusterConfig::new(tls);
	conf.pool_config.mux_offer = Some(Arc::new(TransportOffer::mux(8)));
	conf.edge_bind_addr = Some("127.0.0.1:0".into());
	Ok(conf)
}

/// Hive config: control-plane TLS from the shared identity plus the trust
/// anchor for dialing the gateway and the servlet.
fn hive_conf(identity: &Identity) -> Result<HiveConfig, BoxError> {
	let hive_tls = Arc::new(HiveTlsConfig {
		certificate: certificate_spec(identity),
		key: key_provider(identity)?,
		validators: vec![],
	});

	let mut conf = HiveConfig {
		trust_store: Some(identity.trust_anchor()?),
		hive_tls: Some(hive_tls),
		..Default::default()
	};
	conf.pool.mux_offer = Some(Arc::new(TransportOffer::mux(8)));
	Ok(conf)
}

/// Servlet config: encrypted TCP listener under the shared identity with
/// a mux offer matching the hive pool.
fn servlet_conf(
	identity: &Identity,
) -> Result<ServletConfig<TokioListener, TestMessage, DefaultCryptoProvider>, BoxError> {
	Ok(ServletConfig::<TokioListener, TestMessage, DefaultCryptoProvider>::builder()
		.with_certificate(certificate_spec(identity), key_provider(identity)?, vec![])?
		.with_mux_offer(Some(TransportOffer::mux(8)))
		.with_config(Arc::new(()))
		.build())
}

/// Compose and sign the end-to-end client work frame the gateway must
/// deliver to the servlet byte-for-byte.
async fn signed_work_frame(id: &[u8]) -> Result<Frame, TightBeamError> {
	let unsigned = frame_compose(Version::V0)
		.with_id(id)
		.with_order(current_timestamp_ms())
		.with_message(TestMessage { content: "21".into() })
		.build()?;

	let provider = Secp256k1KeyProvider::from(probe_signing_key());
	unsigned.sign_with_provider::<Sha3_256, _>(&provider).await
}

/// Start gateway, servlet, and hive over the TCP colony transport and
/// register the servlet under `type_name`. The gateway also binds its
/// WebSocket edge plane for the external client.
async fn start_stack(
	trace: &TraceCollector,
	identity: &Identity,
	type_name: &str,
) -> Result<(WorkPlaneGateway, WorkProbeHive), BoxError> {
	let gateway = WorkPlaneGateway::start(Arc::new(trace.share()), cluster_conf(identity)?).await?;

	let servlet = WorkProbeServlet::start(Arc::new(trace.share()), Some(servlet_conf(identity)?)).await?;
	let mut hive = WorkProbeHive::new(Some(hive_conf(identity)?))?;
	hive.register(servlet_urn(type_name), servlet, |t| WorkProbeServlet::start(t, None))?;
	hive.establish(Arc::new(trace.share())).await?;

	let registered = hive.register_with_cluster(gateway.addr()).await?;
	assert_eq!(
		registered.status,
		TransitStatus::Ok,
		"hive registration must succeed over the TCP colony plane"
	);

	Ok((gateway, hive))
}

/// The gateway's WebSocket edge address for external client dials.
fn edge_addr(gateway: &WorkPlaneGateway) -> Result<TightBeamSocketAddr, BoxError> {
	Ok(gateway.edge_addr().ok_or("edge plane did not bind")?.clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submit_work_round_trips_through_ws_gateway() -> Result<(), BoxError> {
	let trace = TraceCollector::default();
	let identity = stack_identity()?;
	let (gateway, hive) = start_stack(&trace, &identity, "work-probe").await?;

	let mut client = ClientBuilder::<WsListener>::builder()
		.with_trust_store(identity.trust_anchor()?)
		.build()
		.connect(&edge_addr(&gateway)?)
		.await?;

	let work = signed_work_frame(b"ws-work-1").await?;
	let served = client.submit_work_to(servlet_urn("work-probe"), &work).await?;
	assert!(
		served
			.verify::<Secp256k1Signature, Sha3_256>(probe_signing_key().verifying_key())
			.is_ok(),
		"servlet response signature must verify end to end at the client"
	);

	let reply: TestMessage = decode(&served.message)?;
	assert_eq!(
		reply.content, "pong:21:true",
		"servlet must answer the typed echo with the client signature verified on received bytes"
	);
	assert_eq!(
		served.metadata.id, b"ws-work-1",
		"servlet response must correlate with the work frame id"
	);

	hive.stop();
	gateway.stop();
	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unserved_type_resolves_to_typed_work_refusal() -> Result<(), BoxError> {
	let trace = TraceCollector::default();
	let identity = stack_identity()?;
	let (gateway, hive) = start_stack(&trace, &identity, "work-probe").await?;

	let mut client = ClientBuilder::<WsListener>::builder()
		.with_trust_store(identity.trust_anchor()?)
		.build()
		.connect(&edge_addr(&gateway)?)
		.await?;

	let work = signed_work_frame(b"ws-work-refused").await?;
	let refused = client.submit_work_to(servlet_urn("unserved"), &work).await;
	assert!(
		matches!(refused, Err(TightBeamError::WorkRefused(_))),
		"an unserved servlet type must resolve to a typed WorkRefused refusal, got {refused:?}"
	);

	hive.stop();
	gateway.stop();
	Ok(())
}
