//! Cluster work-plane round trips through the WebSocket edge plane.
//!
//! The colony (gateway, hive, servlet) runs its internal traffic over
//! TCP. The gateway also binds a WebSocket edge accept plane for external
//! clients. Proves the upstream `SubmitWork` blanket impl
//! reaches `GenericClient<WsListener>` with zero library changes in this
//! crate. A signed end-to-end work frame travels from the WebSocket edge
//! through the TCP colony to a hive-registered servlet, and the
//! servlet's complete signed response frame returns to the client with
//! its signature verifiable. An unserved servlet type resolves to a
//! typed `WorkRefused` refusal.
//!
//! [`SubmitWork`]: tightbeam::colony::SubmitWork

#![cfg(feature = "colony")]
// The colony runtime macros expand `cfg(feature = ...)` probes against the
// invoking crate's feature namespace. Those upstream feature names do not
// exist in this crate, so the leaked cfg warnings carry no signal here.
#![allow(unexpected_cfgs)]

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use tightbeam::builder::TypeBuilder;
use tightbeam::clock::UnixMillis;
use tightbeam::colony::cluster::Cluster;
use tightbeam::colony::hive::Hive;
use tightbeam::colony::servlet::ServletConfig;
use tightbeam::colony::urn::ColonyNamespace;
use tightbeam::colony::SubmitWork;
use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
use tightbeam::policy::TransitStatus;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::{TestIdentity, TestKey, TestMessage};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder};
use tightbeam::urn::Urn;
use tightbeam::{cluster, compose, hive, servlet, Frame, TightBeamError, Version};
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
		let signature_valid = PROBE.verifies(&frame);

		let mut reply = compose! {
			V1: id: frame.metadata().id(),
				message: TestMessage { content: format!("pong:{}:{signature_valid}", req.content) }
		}?;

		reply.sign_with_provider(&TestIdentity::of(&probe_signing_key())).await?;
		Ok(Some(reply))
	}
}

hive! {
	pub WorkProbeHive,
	protocol: TokioListener
}

cluster! {
	/// TCP colony gateway with a WebSocket edge accept plane. Hives
	/// register over TCP, and external clients submit work over WebSocket.
	pub WorkPlaneGateway,
	protocol: TokioListener,
	edge: WsListener
}

/// Deterministic end-to-end signing key shared by the client and the
/// probe servlet, so each side verifies the other's frame signature
/// without key distribution.
fn probe_signing_key() -> Secp256k1SigningKey {
	TestKey::insecure_fixed_signing()
}

/// The identity of the probe key, which verifies the end-to-end signature of
/// each frame either side signs with that key.
static PROBE: LazyLock<Identity> = LazyLock::new(|| {
	let probe = Identity::from_key(
		probe_signing_key(),
		"CN=work probe,O=tightbeam-ws,C=US",
		2,
		Duration::from_secs(3600),
	);
	probe.expect("the probe identity issues over the fixed test key")
});

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
	Ok(Identity::mint(
		"CN=work plane,O=tightbeam-ws,C=US",
		1,
		Duration::from_secs(3600),
	)?)
}

/// Compose and sign the end-to-end client work frame the gateway must
/// deliver to the servlet byte-for-byte.
async fn signed_work_frame(id: &[u8]) -> Result<Frame, TightBeamError> {
	let mut frame = Version::V1
		.compose()
		.with_id(id)
		.with_order(UnixMillis::now().get())
		.with_message(TestMessage { content: "21".into() })
		.build()?;

	frame.sign_with_provider(&TestIdentity::of(&probe_signing_key())).await?;
	Ok(frame)
}

/// Start gateway, servlet, and hive over the TCP colony transport and
/// register the servlet under `type_name`. The gateway also binds its
/// WebSocket edge plane for the external client.
async fn start_stack(
	trace: &TraceCollector,
	identity: &Identity,
	type_name: &str,
) -> Result<(WorkPlaneGateway, WorkProbeHive), BoxError> {
	let cluster_config = identity.cluster_config("127.0.0.1:0")?;
	let gateway = WorkPlaneGateway::start(Arc::new(trace.share()), cluster_config).await?;

	let servlet = WorkProbeServlet::start(Arc::new(trace.share()), identity.servlet_config()?).await?;
	let mut hive = WorkProbeHive::new(Some(identity.hive_config()?))?;
	hive.register(servlet_urn(type_name), servlet, |t| {
		WorkProbeServlet::start(t, ServletConfig::cleartext())
	})?;
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
	Ok(*gateway.edge_addr().ok_or("edge plane did not bind")?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submit_work_round_trips_through_ws_gateway() -> Result<(), BoxError> {
	let trace = TraceCollector::default();
	let identity = stack_identity()?;
	let (gateway, hive) = start_stack(&trace, &identity, "work-probe").await?;

	let mut client = ClientBuilder::<WsListener>::builder()
		.with_trust_store(identity.trust_anchor()?)
		.build()
		.connect(edge_addr(&gateway)?)
		.await?;

	let work = signed_work_frame(b"ws-work-1").await?;
	let served = client.submit_work_to(servlet_urn("work-probe"), &work).await?;
	assert!(
		PROBE.verifies(&served),
		"servlet response signature must verify end to end at the client"
	);

	let reply: TestMessage = served.decode_message()?;
	assert_eq!(
		reply.content, "pong:21:true",
		"servlet must answer the typed echo with the client signature verified on received bytes"
	);
	assert_eq!(
		served.metadata().id(),
		b"ws-work-1",
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
		.connect(edge_addr(&gateway)?)
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
