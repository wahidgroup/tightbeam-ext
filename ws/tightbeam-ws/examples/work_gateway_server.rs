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
//!   - `TBWS_SERVER_CERT`  path to the gateway certificate DER, beside its key
//!   - `TBWS_WORK_CERT`    path to the shared work certificate DER, beside its key
//!   - `ECHO_WS_PORT`      listen port (default `9104`)

// The colony runtime macros expand `cfg(feature = ...)` probes against the
// invoking crate's feature namespace. Those upstream feature names do not
// exist in this crate, so the leaked cfg warnings carry no signal here.
#![allow(unexpected_cfgs)]

use core::fmt::Write;
use core::future::pending;
use std::sync::{Arc, OnceLock};

use der::asn1::OctetString;
use der::Sequence;
use tightbeam::colony::cluster::Cluster;
use tightbeam::colony::hive::Hive;
use tightbeam::colony::servlet::ServletConfig;
use tightbeam::colony::urn::ColonyNamespace;
use tightbeam::policy::TransitStatus;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::urn::Urn;
use tightbeam::{cluster, compose, hive, servlet, Beamable, TightBeamError};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{EnvVar, Identity, IdentityFiles};

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

/// The variable that sets the listen port of the edge.
const PORT: EnvVar = EnvVar::new("ECHO_WS_PORT");

/// The variable naming the end-to-end work certificate DER file, which sits
/// beside its signing key.
const WORK_CERT: EnvVar = EnvVar::new("TBWS_WORK_CERT");

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

		let signature_valid = identity.verifies(&frame);
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
	/// register over TCP, and the browser submits work over WebSocket.
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

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port = PORT.parsed_or(9104u32)?;
	let identity = Identity::from_env()?;

	// The handler reads the slot on every work item, so it must be full
	// before the topology starts serving.
	let work_identity = IdentityFiles::from_env(WORK_CERT)?.load()?;
	let _ = WORK_IDENTITY.set(work_identity);

	let trace = TraceCollector::default();
	let cluster_config = identity.cluster_config(format!("0.0.0.0:{port}"))?;
	let gateway = WorkPlaneGateway::start(Arc::new(trace.share()), cluster_config).await?;

	let servlet = WorkProbeServlet::start(Arc::new(trace.share()), identity.servlet_config()?).await?;
	let mut hive = WorkProbeHive::new(Some(identity.hive_config()?))?;
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
