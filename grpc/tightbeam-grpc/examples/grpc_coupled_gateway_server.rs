//! Cluster gateway with a coupled gRPC edge, for the e2e stack.
//!
//! Environment: `TBWS_SERVER_CERT`, `COUPLED_CERT_DIR`, and `GRPC_COUPLED_PORT`.

// The colony runtime macros expand `cfg(feature = ...)` probes against the
// invoking crate's feature namespace. Those upstream feature names do not
// exist in this crate, so the leaked cfg warnings carry no signal here.
#![allow(unexpected_cfgs)]

use core::future::pending;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tightbeam::colony::cluster::Cluster;
use tightbeam::colony::hive::Hive;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::policy::TransitStatus;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::{cluster, hive, servlet, TightBeamError};
use tightbeam_grpc::couple::{
	AdmissionTrust, AdmittedCall, Assurance, CallerTrust, Code, CoupledCall, Coupler, Grants, Principal, Routes,
	Servlet, Voucher,
};
use tightbeam_grpc::edge::{Dial, DialTls, Edge, EdgeTls};
use tightbeam_grpc::protocol::GrpcListener;
use tightbeam_grpc::staged_profile;
use tightbeam_ws::testing::{EnvVar, Identity, WorkClient};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The variable that sets the listen port of the coupled edge.
const PORT: EnvVar = EnvVar::new("GRPC_COUPLED_PORT");

/// The variable that names the directory of the coupled TLS material.
const CERT_DIR: EnvVar = EnvVar::new("COUPLED_CERT_DIR");

/// The method that the edge routes, which a stock caller calls.
const GET: &str = "/orders.v1.Orders/Get";

/// The method that the edge routes as `Signed`.
const PLACE: &str = "/orders.v1.Orders/Place";

/// The stock caller that `gen_coupled_certs` issues.
const CALLER: &str = "spiffe://acme/grpcurl";

/// The signing caller that `gen_coupled_certs` issues, whose claim identity
/// names the same subject.
const SIGNER: &str = "CN=coupled claims,O=acme,C=US";

/// How long the minted colony identities stay valid.
const ONE_DAY: Duration = Duration::from_secs(24 * 60 * 60);

staged_profile! {
	/// The coupled edge of the stack, staged from the files of
	/// `COUPLED_CERT_DIR` and the identities that this process mints.
	CoupledStackEdge
}

cluster! {
	/// TCP colony gateway with a coupled gRPC edge.
	pub CoupledGateway,
	protocol: TokioListener,
	edge: GrpcListener<DefaultCryptoProvider, CoupledStackEdge>
}

/// What the orders servlet admits and signs with.
struct OrdersEnv {
	admission: AdmissionTrust,
	signer: SigningIdentity,
}

servlet! {
	/// Answers each coupled call that it admits with its own request body, so
	/// a stock caller reads back the message it sent.
	pub OrdersServlet<CoupledCall, EnvConfig = OrdersEnv>,
	protocol: TokioListener,
	handle: |_call, frame, ctx| async move {
		let env = ctx.env_config();
		let admitted = AdmittedCall::admit(&frame, &env.admission)?;
		let body = admitted.body().to_vec();
		admitted.reply(Code::Ok, body, &env.signer).await
	}
}

hive! {
	/// The hive that hosts the orders servlet over the TCP colony.
	pub OrdersHive,
	protocol: TokioListener
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
	let port: u16 = PORT.parsed()?;
	let dir: PathBuf = CERT_DIR.parsed()?;
	let transport = Identity::from_env()?;
	let session = Identity::mint("CN=coupler session,O=acme,C=US", 2, ONE_DAY)?;
	let vouching = Identity::mint("CN=coupler,O=acme,C=US", 3, ONE_DAY)?;
	let answers = Identity::mint("CN=orders servlet,O=acme,C=US", 4, ONE_DAY)?;
	let servlet = WorkClient::servlet("orders")?;

	let callers = CallerTrust::from_pem(dir.join("root.pem"), dir.join("claims.pem"))?;
	let claims = callers.claim_store();
	let voucher = Voucher::new(session.signing_identity()?, vouching.signing_identity()?);
	let orders = Servlet::new(servlet.clone(), answers.certificate().clone())?;
	let routes = Routes::new().unary(GET, orders.clone(), Assurance::Vouched)?;
	let routes = routes.unary(PLACE, orders, Assurance::Signed)?;
	let grants = Grants::deny_all().grant(Principal::spiffe(CALLER)?, GET);
	let grants = grants.grant(Principal::subject(SIGNER)?, PLACE);
	let coupler = Coupler::new(callers, voucher, routes, grants)?;

	let tls = EdgeTls::from_pem(dir.join("edge.crt"), dir.join("edge.key"))?;
	let dial = DialTls::from_pem(dir.join("root.pem"))?;
	CoupledStackEdge::stage(Edge::Coupled(tls, coupler), Dial::Tls(dial));

	let trace = Arc::new(TraceCollector::default());
	let config = transport.cluster_config(format!("0.0.0.0:{port}"))?;
	let gateway = CoupledGateway::start(Arc::clone(&trace), config).await?;

	let admission = AdmissionTrust::new(vouching.trust_anchor()?, Arc::clone(&claims), claims);
	let env = Arc::new(OrdersEnv { admission, signer: answers.signing_identity()? });
	let served = OrdersServlet::start(Arc::clone(&trace), transport.servlet_config(env)?).await?;
	let mut hive = OrdersHive::new(Some(transport.hive_config()?))?;
	let restart = |_trace| async { Err(TightBeamError::MissingConfiguration) };
	hive.register(servlet.clone(), served, restart)?;
	hive.establish(Arc::clone(&trace)).await?;

	let registered = hive.register_with_cluster(gateway.addr()).await?;
	if registered.status != TransitStatus::Ok {
		return Err(format!("the gateway refused the hive: {:?}", registered.status).into());
	}

	let edge = gateway.edge_addr().ok_or("edge plane did not bind")?;
	println!("[grpc-coupled-gateway] coupled edge https://{edge} routes {GET} and {PLACE} to {servlet}");

	// The topology serves from background tasks. Main only keeps the
	// process alive for the container runtime.
	let _keep = (gateway, hive);
	pending::<()>().await;
	Ok(())
}
