//! Cluster work-plane gateway for the e2e stack.
//!
//! This process runs a cluster gateway, a hive, and a `work-probe` servlet,
//! which speak encrypted TCP to each other. The gateway accepts clients on an
//! encrypted WebSocket edge at the public port, so the e2e suite exercises real
//! admission, routing, and refusal.
//!
//! [`WorkProbeServlet`] reports whether the client's signature verified after
//! the gateway forwarded the frame. The gateway refuses an unregistered servlet
//! type with a typed transit status.
//!
//! Environment:
//!   - `TBWS_SERVER_CERT`  path to the gateway certificate DER
//!   - `TBWS_SERVER_KEY`   path to the raw 32-byte gateway signing key
//!   - `TBWS_WORK_CERT`    path to the shared work certificate DER
//!   - `TBWS_WORK_KEY`     path to the raw 32-byte shared work signing key
//!   - `ECHO_WS_PORT`      listen port (default `9104`)

// The colony runtime macros expand `cfg(feature = ...)` probes against the
// invoking crate's feature namespace. Those upstream feature names do not
// exist in this crate, so the leaked cfg warnings carry no signal here.
#![allow(unexpected_cfgs)]

use core::fmt::Write;
use core::future::pending;
use std::env;
use std::fs;
use std::sync::{Arc, OnceLock};

use der::asn1::OctetString;
use der::Sequence;
use tightbeam::colony::cluster::{Cluster, ClusterConfig, ClusterTlsConfig};
use tightbeam::colony::hive::{Hive, HiveConfig, HiveTlsConfig};
use tightbeam::colony::servlet::ServletConfig;
use tightbeam::colony::urn::ColonyNamespace;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::x509::{KeyPurposes, PeerCertificate, Signing};
use tightbeam::policy::TransitStatus;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::handshake::PeerAuthentication;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::urn::Urn;
use tightbeam::{cluster, compose, hive, servlet, Beamable, Frame, TightBeamError};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{env_u32, Identity, SIGNING_KEY_LEN};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The profile opaque body the browser builds with `frame(bytes)`.
#[derive(Beamable, Clone, Debug, Eq, PartialEq, Sequence)]
#[beam(min_version = "V0")]
struct WorkBody {
	body: OctetString,
}

/// End-to-end work identity, installed by `main` before the servlet starts
/// so the handler never observes an empty slot.
static WORK_IDENTITY: OnceLock<Identity> = OnceLock::new();

/// Whether `frame` carries a signature that `identity`'s certificate verifies
/// over the bytes this end received.
fn signature_verifies(identity: &Identity, frame: &Frame) -> bool {
	let certificate = identity.certificate().clone();
	let signer = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(certificate, KeyPurposes::HOUSE.signer);
	signer.is_ok_and(|signer| frame.verify(&signer).is_ok())
}

servlet! {
	/// Answers the opaque work payload with a signed
	/// `pong:<payload-hex>:<signature-valid>` echo. The verdict witnesses
	/// whether the client's end-to-end signature verified on the bytes
	/// the servlet received.
	pub WorkProbeServlet<WorkBody, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |req, frame, _ctx| async move {
		// Main installs the identity before the topology starts, so an empty
		// slot is unreachable here. The early return keeps the handler
		// panic-free if that startup ordering ever breaks.
		let Some(identity) = WORK_IDENTITY.get() else {
			return Err(TightBeamError::MissingConfiguration);
		};

		let signature_valid = signature_verifies(identity, &frame);
		let payload_hex = hex_string(req.body.as_bytes());
		let reply = WorkBody {
			body: OctetString::new(format!("pong:{payload_hex}:{signature_valid}").into_bytes())?,
		};

		let mut signed = compose! {
			V1: id: frame.metadata().id(),
				message: reply
		}?;

		let signer = identity.signing_identity().map_err(|_| TightBeamError::MissingConfiguration)?;
		signed.sign_with_provider(&signer).await?;
		Ok(Some(signed))
	}
}

hive! {
	pub WorkProbeHive,
	protocol: TokioListener
}

cluster! {
	/// TCP colony gateway with a WebSocket edge accept plane. Hives
	/// register over TCP; the browser submits work over WebSocket.
	pub WorkPlaneGateway,
	protocol: TokioListener,
	edge: WsListener
}

/// Lowercase hex rendering of `bytes` for the echo payload.
fn hex_string(bytes: &[u8]) -> String {
	let mut hex = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		// Writing into a String cannot fail, so the fmt result carries
		// no signal.
		let _ = write!(hex, "{byte:02x}");
	}

	hex
}

/// Servlet type URN under the default colony namespace.
fn servlet_urn(name: &str) -> Result<Urn<'static>, BoxError> {
	Ok(ColonyNamespace::default().servlet(name)?)
}

// The four config builders below have a twin in tests/work_plane.rs. The
// colony feature is dev-only, so no shared module can host these
// colony-typed helpers. Mirror any edit here in the test twin.

/// Gateway config: the provisioned identity for TLS, the same identity as
/// the hive-plane trust anchor, a loopback TCP colony bind, the public
/// WebSocket edge on the fixed port, and an eight-stream mux offer shared
/// with every accepted connection (including the browser).
fn cluster_conf(identity: &Identity, port: u32) -> Result<ClusterConfig, BoxError> {
	let tls = ClusterTlsConfig::from_identity(identity.signing_identity()?, KeyPurposes::HOUSE)?;
	let tls = tls.with_hive_trust(Some(identity.trust_anchor()?));

	let mut conf = ClusterConfig::new(tls);
	conf.bind_addr = Some("127.0.0.1:0".into());
	conf.edge_bind_addr = Some(format!("0.0.0.0:{port}"));
	conf.pool_config.mux_offer = Some(Arc::new(TransportOffer::mux(8)));
	Ok(conf)
}

/// Hive config: control-plane TLS from the provisioned identity plus the
/// trust anchor for dialing the gateway and the servlet.
fn hive_conf(identity: &Identity) -> Result<HiveConfig, BoxError> {
	let authentication = PeerAuthentication::Anonymous;
	let hive_tls = HiveTlsConfig::from_identity(identity.signing_identity()?, authentication, KeyPurposes::HOUSE)?;

	let mut conf = HiveConfig {
		trust_store: Some(identity.trust_anchor()?),
		hive_tls: Some(Arc::new(hive_tls)),
		..Default::default()
	};
	conf.pool.mux_offer = Some(Arc::new(TransportOffer::mux(8)));
	Ok(conf)
}

/// Servlet config: encrypted TCP listener under the provisioned identity
/// with a mux offer matching the hive pool.
fn servlet_conf(
	identity: &Identity,
) -> Result<ServletConfig<TokioListener, WorkBody, DefaultCryptoProvider>, BoxError> {
	Ok(ServletConfig::<TokioListener, WorkBody, DefaultCryptoProvider>::builder()
		.with_identity(identity.signing_identity()?, vec![])
		.with_mux_offer(Some(TransportOffer::mux(8)))
		.with_config(Arc::new(()))
		.build())
}

/// Load the end-to-end work identity named by `TBWS_WORK_CERT` and
/// `TBWS_WORK_KEY`.
fn load_work_identity() -> Result<Identity, BoxError> {
	let cert_path = env::var("TBWS_WORK_CERT").map_err(|_| "TBWS_WORK_CERT is not set")?;
	let key_path = env::var("TBWS_WORK_KEY").map_err(|_| "TBWS_WORK_KEY is not set")?;

	let certificate = fs::read(&cert_path)?;
	let bytes = fs::read(&key_path)?;
	let scalar: [u8; SIGNING_KEY_LEN] = bytes
		.as_slice()
		.try_into()
		.map_err(|_| "work key file must hold exactly 32 bytes")?;

	Ok(Identity::from_der(&certificate, &scalar)?)
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port = env_u32("ECHO_WS_PORT", 9104);
	let identity = Identity::from_env()?;

	// The handler reads the slot on every work item, so it must be full
	// before the topology starts serving.
	let _ = WORK_IDENTITY.set(load_work_identity()?);

	let trace = TraceCollector::default();
	let gateway = WorkPlaneGateway::start(Arc::new(trace.share()), cluster_conf(&identity, port)?).await?;

	let servlet = WorkProbeServlet::start(Arc::new(trace.share()), servlet_conf(&identity)?).await?;
	let mut hive = WorkProbeHive::new(Some(hive_conf(&identity)?))?;
	hive.register(servlet_urn("work-probe")?, servlet, |t| {
		WorkProbeServlet::start(t, ServletConfig::cleartext())
	})?;
	hive.establish(Arc::new(trace.share())).await?;

	// The colony plane binds loopback with an ephemeral port, so the hive
	// dials the bound address directly.
	let registered = hive.register_with_cluster(gateway.addr()).await?;
	if registered.status != TransitStatus::Ok {
		return Err(format!("hive registration failed with status {:?}", registered.status).into());
	}

	let edge = gateway.edge_addr().ok_or("edge plane did not bind")?;
	println!(
		"[work-gateway] cluster work-plane gateway: colony tcp://{} edge ws://{} (servlet: work-probe)",
		gateway.addr().0,
		edge.0
	);

	// The topology serves from background tasks. Main only keeps the
	// process alive for the container runtime.
	pending::<()>().await;
	Ok(())
}
