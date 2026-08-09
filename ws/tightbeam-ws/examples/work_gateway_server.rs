//! Cluster work-plane gateway for the e2e stack.
//!
//! Assembles a real cluster gateway, a hive, and a `work-probe` servlet in
//! one process over the encrypted WebSocket transport, so the browser suite
//! exercises the genuine admission, routing, and refusal logic rather than
//! an emulation.
//!
//! The servlet answers the opaque work payload with a signed
//! `pong:<payload-hex>:<signature-valid>` echo. The verdict witnesses
//! whether the client's end-to-end signature verified on the bytes the
//! servlet received, proving byte-for-byte forwarding through the gateway.
//! An unregistered servlet type is refused by the gateway with a typed
//! transit status.
//!
//! Environment:
//!   - `TBWS_SERVER_CERT`  path to the gateway certificate DER
//!   - `TBWS_SERVER_KEY`   path to the raw 32-byte gateway signing key
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
use tightbeam::colony::common::ColonyNamespace;
use tightbeam::colony::hive::{Hive, HiveConfig, HiveTlsConfig};
use tightbeam::colony::servlet::ServletConfig;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
use tightbeam::crypto::x509::CertificateSpec;
use tightbeam::policy::TransitStatus;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::utils::urn::Urn;
use tightbeam::{cluster, compose, hive, servlet, Beamable, TightBeamError};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{env_u32, Identity, SIGNING_KEY_LEN};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The profile opaque body the browser builds with `frame(bytes)`.
#[derive(Beamable, Clone, Debug, Eq, PartialEq, Sequence)]
#[beam(min_version = "V0")]
struct WorkBody {
	body: OctetString,
}

/// End-to-end work signing key, installed by `main` before the servlet
/// starts so the handler never observes an empty slot.
static WORK_KEY: OnceLock<Secp256k1SigningKey> = OnceLock::new();

servlet! {
	/// Answers the opaque work payload with a signed
	/// `pong:<payload-hex>:<signature-valid>` echo. The verdict witnesses
	/// whether the client's end-to-end signature verified on the bytes
	/// the servlet received.
	pub WorkProbeServlet<WorkBody, EnvConfig = ()>,
	protocol: WsListener,
	handle: |req, frame, _ctx| async move {
		// Main installs the key before the topology starts, so an empty
		// slot is unreachable here. The early return keeps the handler
		// panic-free if that startup ordering ever breaks.
		let Some(key) = WORK_KEY.get() else {
			return Err(TightBeamError::MissingConfiguration);
		};
		let signature_valid = frame
			.verify::<Secp256k1Signature, Sha3_256>(key.verifying_key())
			.is_ok();

		let payload_hex = hex_string(req.body.as_bytes());
		let reply = WorkBody {
			body: OctetString::new(format!("pong:{payload_hex}:{signature_valid}").into_bytes())?,
		};

		let unsigned = compose! {
			V0: id: &frame.metadata.id,
				message: reply
		}?;

		let provider = Secp256k1KeyProvider::from(key.clone());
		Ok(Some(unsigned.sign_with_provider::<Sha3_256, _>(&provider).await?))
	}
}

hive! {
	pub WorkProbeHive,
	protocol: WsListener
}

cluster! {
	pub WorkPlaneGateway,
	protocol: WsListener
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

// The five config builders below have a twin in tests/work_plane.rs. The
// colony feature is dev-only, so no shared module can host these
// colony-typed helpers. Mirror any edit here in the test twin.

/// The identity's signing key as a key provider for TLS configs.
fn key_provider(identity: &Identity) -> Result<Arc<Secp256k1KeyProvider>, BoxError> {
	let key = Secp256k1SigningKey::from_bytes(&identity.signing_key_bytes().into())?;
	Ok(Arc::new(Secp256k1KeyProvider::from(key)))
}

/// The identity's certificate as a built certificate spec.
fn certificate_spec(identity: &Identity) -> CertificateSpec {
	CertificateSpec::Built(Box::new(identity.certificate().clone()))
}

/// Gateway config: the provisioned identity for TLS, the same identity as
/// the hive-plane trust anchor, a fixed bind port, and an eight-stream mux
/// offer shared with every accepted connection (including the browser).
fn cluster_conf(identity: &Identity, port: u32) -> Result<ClusterConfig, BoxError> {
	let tls = ClusterTlsConfig {
		certificate: certificate_spec(identity),
		key: key_provider(identity)?,
		validators: vec![],
		client_validators: vec![],
		hive_trust: Some(identity.trust_anchor()?),
		peer_trust: None,
	};

	let mut conf = ClusterConfig::new(tls);
	conf.bind_addr = Some(format!("0.0.0.0:{port}"));
	conf.pool_config.mux_offer = Some(Arc::new(TransportOffer::mux(8)));
	Ok(conf)
}

/// Hive config: control-plane TLS from the provisioned identity plus the
/// trust anchor for dialing the gateway and the servlet.
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

/// Servlet config: encrypted ws listener under the provisioned identity
/// with a mux offer matching the hive pool.
fn servlet_conf(identity: &Identity) -> Result<ServletConfig<WsListener, WorkBody, DefaultCryptoProvider>, BoxError> {
	Ok(ServletConfig::<WsListener, WorkBody, DefaultCryptoProvider>::builder()
		.with_certificate(certificate_spec(identity), key_provider(identity)?, vec![])?
		.with_mux_offer(Some(TransportOffer::mux(8)))
		.with_config(Arc::new(()))
		.build())
}

/// Load the raw 32-byte end-to-end work signing key named by
/// `TBWS_WORK_KEY`.
fn load_work_key() -> Result<Secp256k1SigningKey, BoxError> {
	let path = env::var("TBWS_WORK_KEY").map_err(|_| "TBWS_WORK_KEY is not set")?;
	let bytes = fs::read(&path)?;

	let scalar: [u8; SIGNING_KEY_LEN] = bytes
		.as_slice()
		.try_into()
		.map_err(|_| "work key file must hold exactly 32 bytes")?;

	Ok(Secp256k1SigningKey::from_bytes(&scalar.into())?)
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port = env_u32("ECHO_WS_PORT", 9104);
	let identity = Identity::from_env()?;

	// The handler reads the slot on every work item, so it must be full
	// before the topology starts serving.
	let _ = WORK_KEY.set(load_work_key()?);

	let trace = TraceCollector::default();
	let gateway = WorkPlaneGateway::start(Arc::new(trace.share()), cluster_conf(&identity, port)?).await?;

	let servlet = WorkProbeServlet::start(Arc::new(trace.share()), Some(servlet_conf(&identity)?)).await?;
	let mut hive = WorkProbeHive::new(Some(hive_conf(&identity)?))?;
	hive.register(servlet_urn("work-probe")?, servlet, |t| WorkProbeServlet::start(t, None))?;
	hive.establish(Arc::new(trace.share())).await?;

	// The gateway binds 0.0.0.0. Registration dials loopback explicitly so
	// the hive reaches the same process without a wildcard-address dial.
	let gateway_addr = TightBeamSocketAddr(format!("127.0.0.1:{port}").parse()?);
	let registered = hive.register_with_cluster(&gateway_addr).await?;
	if registered.status != TransitStatus::Ok {
		return Err(format!("hive registration failed with status {:?}", registered.status).into());
	}

	println!(
		"[work-gateway] cluster work-plane gateway listening on ws://{} (servlet: work-probe)",
		gateway.addr().0
	);

	// The topology serves from background tasks. Main only keeps the
	// process alive for the container runtime.
	pending::<()>().await;
	Ok(())
}
