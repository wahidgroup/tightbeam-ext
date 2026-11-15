//! Cluster gateway with a coupled gRPC edge, for the e2e stack.
//!
//! Environment: `TBWS_SERVER_CERT`, `CERT_DIR`, and `GRPC_COUPLED_PORT`.

use core::future::pending;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tightbeam::colony::cluster::{Cluster, EdgePlane};
use tightbeam::colony::hive::Hive;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::policy::TransitStatus;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::{cluster, hive, servlet, TightBeamError};
use tightbeam_grpc::couple::{
	AdmissionTrust, AdmittedCall, Assurance, CallerTrust, CallerTrustFiles, CoupledCall, Coupler, Grants, Identities,
	Principal, Routes, Servlet, Voucher,
};
use tightbeam_grpc::edge::{Dial, DialTls, Edge, EdgeTls, EdgeTlsFiles};
use tightbeam_grpc::protocol::GrpcListener;
use tightbeam_grpc::staged_profile;
use tightbeam_grpc::testing::CoupledStack;
use tightbeam_ws::testing::{EnvVar, Identity, WorkClient};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The variable that sets the listen port of the coupled edge.
const PORT: EnvVar = EnvVar::new("GRPC_COUPLED_PORT");

/// The variable that names the certificate directory of the stack, which
/// holds the coupled TLS material.
const CERT_DIR: EnvVar = EnvVar::new("CERT_DIR");

/// How long the colony identities that this process creates stay valid.
const ONE_DAY: Duration = Duration::from_secs(24 * 60 * 60);

staged_profile! {
	/// The coupled edge of the stack, staged from the coupled files of
	/// `CERT_DIR` and the identities that this process creates.
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
		admitted.reply(body, &env.signer).await
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
	let certs: PathBuf = CERT_DIR.parsed()?;
	let files = CoupledStack::under(certs);
	let transport = Identity::from_env()?;
	let session = Identity::mint("CN=coupler session,O=acme,C=US", 2, ONE_DAY)?;
	let vouching = Identity::mint("CN=coupler,O=acme,C=US", 3, ONE_DAY)?;
	let answers = Identity::mint("CN=orders servlet,O=acme,C=US", 4, ONE_DAY)?;
	let servlet = WorkClient::servlet("orders")?;

	let callers = CallerTrust::from_pem(CallerTrustFiles { tls_roots: files.root(), claim_roots: files.claims() })?;
	let claims = callers.claim_store();
	let voucher =
		Voucher::new(Identities { handshake: session.signing_identity(), signer: vouching.signing_identity() });
	let orders = Servlet::new(servlet.clone(), answers.certificate().clone())?;
	let (get, place) = (CoupledStack::GET, CoupledStack::PLACE);
	let routes = Routes::new().unary(get, orders.clone(), Assurance::Vouched)?;
	let routes = routes.unary(place, orders, Assurance::Signed)?;
	let grants = Grants::deny_all().grant(Principal::spiffe(CoupledStack::CALLER)?, get)?;
	let grants = grants.grant(Principal::subject(CoupledStack::SIGNER)?, place)?;
	let coupler = Coupler::new(callers, voucher, routes, grants)?;

	let tls = EdgeTls::from_pem(EdgeTlsFiles { chain: files.edge_chain(), key: files.edge_key() })?;
	let dial = DialTls::from_pem(files.root())?;
	CoupledStackEdge::stage(Edge::coupled(tls, coupler), Dial::Tls(dial));

	let trace = Arc::new(TraceCollector::default());
	let config = transport.cluster_config(EdgePlane::new(format!("0.0.0.0:{port}")))?;
	let gateway = CoupledGateway::start(Arc::clone(&trace), config).await?;

	let admission = AdmissionTrust::new()
		.with_vouchers(vouching.trust_anchor()?)
		.with_direct_callers(Arc::clone(&claims))
		.with_claim_signers(claims);
	let env = Arc::new(OrdersEnv { admission, signer: answers.signing_identity() });
	let served = OrdersServlet::start(Arc::clone(&trace), transport.servlet_config(env)).await?;
	let mut hive = OrdersHive::new(Some(transport.hive_config()?))?;
	let restart = |_trace| async { Err(TightBeamError::MissingConfiguration) };
	hive.register(servlet.clone(), served, restart)?;
	hive.establish(Arc::clone(&trace)).await?;

	let registered = hive.register_with_cluster(gateway.addr()).await?;
	if registered.status != TransitStatus::Ok {
		return Err(format!("the gateway refused the hive: {:?}", registered.status).into());
	}

	let edge = WorkClient::edge_of(&gateway)?;
	println!("[grpc-coupled-gateway] coupled edge https://{edge} routes {get} and {place} to {servlet}");

	// The topology serves from background tasks. Main only keeps the
	// process alive for the container runtime.
	let _keep = (gateway, hive);
	pending::<()>().await;
	Ok(())
}
