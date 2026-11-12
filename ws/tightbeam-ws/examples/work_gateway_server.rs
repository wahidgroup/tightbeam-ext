//! The cluster work-plane gateway of the e2e stack, as `docs/ws.md` (Demo
//! servers) states it.

use core::future::pending;
use std::sync::Arc;

use tightbeam::colony::cluster::Cluster;
use tightbeam::trace::TraceCollector;
use tightbeam::urn::Urn;
use tightbeam_ws::testing::{EnvVar, Identity, IdentityFiles, WorkClient, WorkGateway, WorkPlane, WorkStack};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The variable that sets the listen port of the edge.
const PORT: EnvVar = EnvVar::new("ECHO_WS_PORT");

/// The variable naming the end-to-end work certificate DER file, which sits
/// beside its signing key.
const WORK_CERT: EnvVar = EnvVar::new("TBWS_WORK_CERT");

/// The variable naming the servlet type that the hive serves the work probe
/// under.
const SERVLET: EnvVar = EnvVar::new("TBWS_WORK_SERVLET");

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port: u16 = PORT.parsed()?;
	let transport = Identity::from_env()?;
	let work = Arc::new(IdentityFiles::from_env(WORK_CERT)?.load()?);
	let probe: Urn<'static> = SERVLET.parsed()?;
	let plane = WorkPlane::new(transport, work)?.serving(probe.clone());

	let trace = TraceCollector::default();
	let edge = format!("0.0.0.0:{port}");
	let stack = WorkStack::<WorkGateway>::start(&trace, &plane, edge).await?;

	let gateway = stack.gateway();
	let edge = WorkClient::edge_of(gateway)?;
	println!(
		"[work-gateway] cluster work-plane gateway: colony ws://{} edge ws://{} (servlet: {probe})",
		gateway.addr().0,
		edge.0
	);

	// The topology serves from tasks of its own, so main holds the process.
	pending::<()>().await;
	Ok(())
}
