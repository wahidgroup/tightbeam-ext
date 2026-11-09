//! Cluster work-plane gateway with a gRPC edge, for the e2e stack.
//!
//! This process runs a cluster gateway, a hive, and the work probe of
//! `tightbeam_ws::testing`, which speak encrypted TCP to each other. The
//! gateway accepts clients on an encrypted gRPC edge, and the stack puts an
//! Envoy hop in front of it, so the e2e suite crosses a real h2c proxy.
//!
//! Environment:
//!   - `TBWS_SERVER_CERT`  path to the gateway certificate DER, beside its key
//!   - `TBWS_WORK_CERT`    path to the shared work certificate DER, beside its key
//!   - `GRPC_EDGE_PORT`    listen port of the edge

// The colony runtime macros expand `cfg(feature = ...)` probes against the
// invoking crate's feature namespace. Those upstream feature names do not
// exist in this crate, so the leaked cfg warnings carry no signal here.
#![allow(unexpected_cfgs)]

use core::future::pending;
use std::sync::Arc;

use tightbeam::cluster;
use tightbeam::colony::cluster::Cluster;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam_grpc::protocol::GrpcListener;
use tightbeam_ws::testing::{EnvVar, Identity, IdentityFiles, WorkClient, WorkPlane, WorkStack};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The variable that sets the listen port of the edge, which the stack sets.
const PORT: EnvVar = EnvVar::new("GRPC_EDGE_PORT");

/// The variable naming the end-to-end work certificate DER file, which sits
/// beside its signing key.
const WORK_CERT: EnvVar = EnvVar::new("TBWS_WORK_CERT");

cluster! {
	/// TCP colony gateway with a gRPC edge accept plane. Hives register over
	/// TCP, and clients submit work over the tunnel.
	pub WorkPlaneGateway,
	protocol: TokioListener,
	edge: GrpcListener
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port: u16 = PORT.parsed()?;
	let transport = Identity::from_env()?;
	let work = Arc::new(IdentityFiles::from_env(WORK_CERT)?.load()?);
	let plane = WorkPlane::new(transport, work)?;

	let trace = TraceCollector::default();
	let edge = format!("0.0.0.0:{port}");
	let stack = WorkStack::<WorkPlaneGateway>::start(&trace, &plane, edge).await?;

	let gateway = stack.gateway();
	let edge = gateway.edge_addr().ok_or("edge plane did not bind")?;
	let probe = WorkClient::probe()?;
	println!(
		"[grpc-work-gateway] cluster work-plane gateway: colony tcp://{} edge h2c://{edge} (servlet: {probe})",
		gateway.addr().0
	);

	// The topology serves from background tasks. Main only keeps the
	// process alive for the container runtime.
	pending::<()>().await;
	Ok(())
}
