//! Tightbeam work out to a stock gRPC backend, as tightbeam scenarios.
//!
//! Each scenario starts a colony gateway, a hive whose servlet is a
//! [`Backend`] adapter, and a stock tonic server with its own TLS that
//! authenticates its clients, as the orders backend. The adapter relays each
//! coupled call it admits to the backend under its own TLS client certificate,
//! with the principal of the call and its forwarded claim in the metadata, and
//! the backend records what it read as events of the scenario:
//!
//! - A native tightbeam client signs a direct call under its own identity.
//! - A stock caller calls through a coupled edge, whose coupler vouches for
//!   it, so one call crosses both directions of the coupling.

// The colony runtime macros expand `cfg(feature = ...)` probes against the
// invoking crate's feature namespace. Those upstream feature names do not
// exist in this crate, so the leaked cfg warnings carry no signal here.
#![allow(unexpected_cfgs)]

mod support;

use core::convert::Infallible;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;

use tightbeam::builder::TypeBuilder;
use tightbeam::clock::UnixMillis;
use tightbeam::colony::hive::Hive;
use tightbeam::colony::SubmitWork;
use tightbeam::instrumentation::events;
use tightbeam::testing::macros::BuiltAssertSpec;
use tightbeam::testing::{ClusterEnv, ScenarioConfig, ScenarioConfigError, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder};
use tightbeam::urn::Urn;
use tightbeam::{
	cluster, exactly, hive, servlet, tb_assert_spec, tb_process_spec, tb_scenario, urn, Frame, TightBeamError, Version,
};
use tightbeam_grpc::couple::{
	AdmissionTrust, Assurance, Backend, BackendChannel, CallClaim, Code, CoupledCall, CoupledReply, Grants, Principal,
	Routes, Servlet,
};
use tightbeam_grpc::edge::DialTls;
use tightbeam_grpc::events::{
	BACKEND_CALL_REFUSED, BACKEND_CALL_RELAYED, COUPLED_CALL_ADMITTED, COUPLED_CALL_ANSWERED,
};
use tightbeam_grpc::protocol::{GrpcAddr, GrpcListener};
use tightbeam_ws::testing::{Identity, WorkClient};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::body::Body;
use tonic::metadata::MetadataMap;
use tonic::server::{Grpc, UnaryService};
use tonic::transport::{Certificate as TonicCertificate, Identity as TonicIdentity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tower_service::Service;

use support::{call, code_of, edge_error, mint_error, rejected_by, unexpected, Coupled, RawCodec, WEB};

/// The method that requires `Signed` at the backend.
const PLACE: &str = "/orders.v1.Orders/Place";

/// A method that the coupler routes as `Vouched`, and the backend requires
/// `Signed` for.
const LIST: &str = "/orders.v1.Orders/List";

/// The principal that the backend read from the metadata of a call.
const BACKEND_PRINCIPAL: Urn<'static> = urn!("test", "event:backend/principal");

/// Whether the call that the backend served forwarded a claim.
const BACKEND_CLAIM: Urn<'static> = urn!("test", "event:backend/claim");

/// The stock orders backend: a raw service on every path, which records the
/// principal and the claim of each call, and answers `ledger:` and the body of
/// the call.
#[derive(Clone)]
struct Ledger {
	trace: Arc<TraceCollector>,
}

impl Service<http::Request<Body>> for Ledger {
	type Response = http::Response<Body>;
	type Error = Infallible;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

	fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
		Poll::Ready(Ok(()))
	}

	fn call(&mut self, request: http::Request<Body>) -> Self::Future {
		let trace = Arc::clone(&self.trace);
		Box::pin(async move {
			let metadata = MetadataMap::from_headers(request.headers().clone());
			let principal = metadata.get_bin(Backend::PRINCIPAL_KEY).and_then(|value| value.to_bytes().ok());
			if let Some(principal) = principal {
				let _ = trace.event_with(BACKEND_PRINCIPAL, &[], String::from_utf8_lossy(&principal).into_owned());
			}
			let claim = if metadata.get_bin(CallClaim::METADATA_KEY).is_some() {
				"present"
			} else {
				"absent"
			};
			let _ = trace.event_with(BACKEND_CLAIM, &[], claim);

			let mut grpc = Grpc::new(RawCodec);
			Ok(grpc.unary(LedgerCall, request).await)
		})
	}
}

/// One unary call of the backend.
struct LedgerCall;

impl UnaryService<Vec<u8>> for LedgerCall {
	type Response = Vec<u8>;
	type Future = core::future::Ready<Result<Response<Vec<u8>>, Status>>;

	fn call(&mut self, request: Request<Vec<u8>>) -> Self::Future {
		let body = [b"ledger:".as_slice(), request.get_ref()].concat();
		core::future::ready(Ok(Response::new(body)))
	}
}

servlet! {
	/// The adapter servlet, which relays each coupled call it admits to the
	/// orders backend.
	pub LedgerAdapter<CoupledCall, EnvConfig = Backend>,
	protocol: TokioListener,
	handle: |_call, frame, ctx| async move { ctx.env_config().relay(&frame).await }
}

hive! {
	/// The hive that hosts the adapter over the TCP colony.
	pub LedgerHive,
	protocol: TokioListener
}

cluster! {
	/// A gateway with an h2c edge, which a native client submits to.
	pub DirectGateway,
	protocol: TokioListener,
	edge: GrpcListener
}

/// The servlet type of the adapter.
fn ledger() -> Result<Urn<'static>, TightBeamError> {
	Ok(WorkClient::servlet("ledger")?)
}

/// Start the stock orders backend on loopback, under a TLS certificate of the
/// root of the scenario, which authenticates its clients under the same root.
async fn backend(context: &Coupled, trace: &TraceCollector) -> Result<(JoinHandle<()>, GrpcAddr), TightBeamError> {
	let server = context.tls.server("CN=ledger,O=acme,C=US").map_err(mint_error)?;
	let root = TonicCertificate::from_pem(context.tls.root_pem().map_err(mint_error)?);
	let identity = TonicIdentity::from_pem(server.certificate_pem(), server.key_pem());
	let tls = ServerTlsConfig::new().identity(identity).client_ca_root(root);

	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let addr = GrpcAddr::from(listener.local_addr()?);
	let builder = Server::builder().tls_config(tls).map_err(unexpected)?;
	let ledger = Ledger { trace: Arc::new(trace.share()) };
	let served = tokio::spawn(async move {
		let _ = builder.serve_with_incoming(ledger, TcpListenerStream::new(listener)).await;
	});

	Ok((served, addr))
}

/// The adapter of the backend at `addr`: it routes `Place` and `List` as
/// `Signed`, grants both to the web principal, admits the vouchers of the
/// scenario and the direct caller `direct`, and signs under the answer
/// identity.
fn adapter(
	context: &Coupled,
	trace: &TraceCollector,
	addr: &GrpcAddr,
	direct: &Identity,
) -> Result<Backend, TightBeamError> {
	let client = context.caller("CN=ledger adapter,O=acme,C=US", Some("spiffe://acme/ledger-adapter"));
	let tls = DialTls::new([context.tls.root()]).map_err(edge_error)?;
	let tls = tls.with_identity([client.leaf().clone()], client.key()).map_err(edge_error)?;
	let channel = BackendChannel::new(addr, &tls)?;

	let routes = Routes::new().unary(PLACE, (), Assurance::Signed).map_err(edge_error)?;
	let routes = routes.unary(LIST, (), Assurance::Signed).map_err(edge_error)?;
	let web = Principal::subject(WEB).map_err(edge_error)?;
	let grants = Grants::deny_all().grant(web.clone(), PLACE).grant(web, LIST);
	let admission = AdmissionTrust::new(
		context.vouching.trust_anchor()?,
		direct.trust_anchor()?,
		context.claims.trust_anchor()?,
	);

	let signer = context.answers.signing_identity()?;
	let backend = Backend::new(channel, routes, grants, admission, signer).map_err(edge_error)?;
	Ok(backend.with_trace(trace.share()))
}

/// Start the hive that hosts the adapter of the backend at `addr`, which
/// admits the direct caller `direct`.
async fn hive(
	context: &Coupled,
	trace: &TraceCollector,
	addr: &GrpcAddr,
	direct: &Identity,
) -> Result<LedgerHive, TightBeamError> {
	let backend = Arc::new(adapter(context, trace, addr, direct)?);
	let config = context.transport.servlet_config(backend)?;
	let served = LedgerAdapter::start(Arc::new(trace.share()), config).await?;

	let mut hive = LedgerHive::new(Some(context.transport.hive_config()?))?;
	let restart = |_trace| async { Err(TightBeamError::MissingConfiguration) };
	hive.register(ledger()?, served, restart)?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// A direct call of `method` with `body`, signed under `signer` as its own
/// principal, as a native tightbeam client submits it.
async fn direct(signer: &Identity, method: &str, body: &[u8]) -> Result<Frame, TightBeamError> {
	let call = CoupledCall::direct(method, body.to_vec())?;
	let order = UnixMillis::now().get();
	let draft = Version::V1
		.compose()
		.with_id(b"ledger-call")
		.with_order(order)
		.with_message(call);

	let mut frame = draft.build()?;
	frame.sign_with_provider(&signer.signing_identity()?).await?;
	Ok(frame)
}

/// The answer of the adapter in `reply`, once its signature verifies under the
/// answer identity of the scenario.
fn answer_of(context: &Coupled, reply: &Frame) -> Result<CoupledReply, TightBeamError> {
	assert!(context.answers.verifies(reply), "the adapter MUST sign its answer");
	reply.decode_message()
}

/// The address of the edge of `gateway`.
fn direct_edge(gateway: &DirectGateway) -> Result<GrpcAddr, TightBeamError> {
	let bound = gateway.edge_addr().cloned();
	bound.ok_or(TightBeamError::MissingConfiguration)
}

/// Start the backend and the hive of the adapter, which admits `direct`.
macro_rules! with_backend {
	($context:expr, $trace:expr, $direct:expr) => {{
		// The drop of the handle detaches the backend, which serves until the
		// runtime of the scenario ends.
		let (_served, addr) = backend($context, $trace).await?;
		hive($context, $trace, &addr, $direct).await
	}};
}

tb_assert_spec! {
	/// One direct call relayed: the gateway routes it, the backend reads the
	/// principal of the caller and no claim, and the adapter relays the
	/// answer of status 0.
	pub DirectRelaySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(BACKEND_PRINCIPAL, exactly!(1), equals!(WEB)),
			(BACKEND_CLAIM, exactly!(1), equals!("absent")),
			(BACKEND_CALL_RELAYED, exactly!(1), equals!(0u32)),
			(BACKEND_CALL_REFUSED, exactly!(0))
		]
	}
}

// A native tightbeam client signs a direct call under its own identity, and
// the adapter relays it to the stock backend in the name of that identity.
tb_scenario! {
	name: a_direct_call_reaches_a_stock_backend,
	spec: DirectRelaySpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move { context.gateway::<DirectGateway>(&trace).await },
		hives: |SetupEnv { trace, context }| vec![async move { with_backend!(&context, &trace, &context.claims) }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let builder = ClientBuilder::<GrpcListener>::builder().with_trust_store(context.transport.trust_anchor()?);
			let mut client = builder.build().connect(direct_edge(&cluster)?).await?;

			let frame = direct(&context.claims, PLACE, b"order-9").await?;
			let reply = client.submit_work_to(ledger()?, &frame).await?;
			let answer = answer_of(&context, &reply)?;
			assert_eq!(answer.code(), Code::Ok, "the backend MUST serve the call");
			assert_eq!(answer.body(), b"ledger:order-9", "the adapter MUST relay the answer of the backend");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	/// A direct call that the adapter denies: it answers 7, and the backend
	/// reads nothing.
	pub DeniedRelaySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(BACKEND_CALL_REFUSED, exactly!(1), equals!("denied")),
			(BACKEND_PRINCIPAL, exactly!(0)),
			(BACKEND_CALL_RELAYED, exactly!(0))
		]
	}
}

/// An identity that the adapter admits as a direct caller and grants nothing.
fn intruder() -> Identity {
	let minted = Identity::mint("CN=intruder,O=acme,C=US", 9, support::LIFETIME);
	minted.expect("an identity mints")
}

// The adapter admits the signer of a direct call that no grant names, and
// answers it 7 before it calls the backend.
tb_scenario! {
	name: a_principal_without_a_grant_never_reaches_the_backend,
	spec: DeniedRelaySpec,
	environment Cluster {
		context: (Coupled::mint(), intruder()),
		start: |SetupEnv { trace, context }| async move { context.0.gateway::<DirectGateway>(&trace).await },
		hives: |SetupEnv { trace, context }| vec![async move { with_backend!(&context.0, &trace, &context.1) }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (context, intruder) = (&context.0, &context.1);
			let builder = ClientBuilder::<GrpcListener>::builder().with_trust_store(context.transport.trust_anchor()?);
			let mut client = builder.build().connect(direct_edge(&cluster)?).await?;

			let frame = direct(intruder, PLACE, b"order").await?;
			let reply = client.submit_work_to(ledger()?, &frame).await?;
			let answer = answer_of(context, &reply)?;
			assert_eq!(answer.code(), Code::PermissionDenied, "the adapter MUST deny a principal with no grant");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	/// A direct call under a signer that the adapter does not trust: the
	/// adapter admits nothing, so it neither refuses nor relays, and the
	/// backend reads nothing.
	pub UntrustedDirectSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(BACKEND_CALL_REFUSED, exactly!(0)),
			(BACKEND_CALL_RELAYED, exactly!(0)),
			(BACKEND_PRINCIPAL, exactly!(0))
		]
	}
}

// The intruder signs a direct call, but the adapter trusts the web identity
// alone as a direct caller, so the call never admits.
tb_scenario! {
	name: a_direct_call_under_an_untrusted_signer_never_admits,
	spec: UntrustedDirectSpec,
	environment Cluster {
		context: (Coupled::mint(), intruder()),
		start: |SetupEnv { trace, context }| async move { context.0.gateway::<DirectGateway>(&trace).await },
		hives: |SetupEnv { trace, context }| vec![async move { with_backend!(&context.0, &trace, &context.0.claims) }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (context, intruder) = (&context.0, &context.1);
			let builder = ClientBuilder::<GrpcListener>::builder().with_trust_store(context.transport.trust_anchor()?);
			let mut client = builder.build().connect(direct_edge(&cluster)?).await?;

			let frame = direct(intruder, PLACE, b"order").await?;
			let refused = client.submit_work_to(ledger()?, &frame).await;
			assert!(refused.is_err(), "a call under an untrusted signer MUST fail, got {refused:?}");

			cluster.stop();
			Ok(())
		}
	}
}

// The relay spec rejects a run whose call the adapter denies.
tb_scenario! {
	name: the_direct_relay_spec_rejects_a_denied_call,
	config: rejected_by(DirectRelaySpec::latest()),
	environment Cluster {
		context: (Coupled::mint(), intruder()),
		start: |SetupEnv { trace, context }| async move { context.0.gateway::<DirectGateway>(&trace).await },
		hives: |SetupEnv { trace, context }| vec![async move { with_backend!(&context.0, &trace, &context.1) }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (context, intruder) = (&context.0, &context.1);
			let builder = ClientBuilder::<GrpcListener>::builder().with_trust_store(context.transport.trust_anchor()?);
			let mut client = builder.build().connect(direct_edge(&cluster)?).await?;

			let frame = direct(intruder, PLACE, b"order").await?;
			let reply = client.submit_work_to(ledger()?, &frame).await?;
			let answer = answer_of(context, &reply)?;
			assert_eq!(answer.code(), Code::PermissionDenied);

			cluster.stop();
			Ok(())
		}
	}
}

/// Stage the coupled edge that routes `Place` as `Signed` and `List` as
/// `Vouched` to the adapter, grants both to the web principal, and pins the
/// answer identity, which the adapter signs under.
fn stage_chain(
	context: &Coupled,
	trace: &TraceCollector,
	stage: fn(tightbeam_grpc::edge::Edge, tightbeam_grpc::edge::Dial),
) -> Result<(), TightBeamError> {
	let adapter = Servlet::new(ledger()?, context.answers.certificate().clone()).map_err(edge_error)?;
	let routes = Routes::new()
		.unary(PLACE, adapter.clone(), Assurance::Signed)
		.map_err(edge_error)?;

	let routes = routes.unary(LIST, adapter, Assurance::Vouched).map_err(edge_error)?;
	let web = Principal::subject(WEB).map_err(edge_error)?;
	let grants = Grants::deny_all().grant(web.clone(), PLACE).grant(web, LIST);
	let coupler = context.coupler(trace, routes, grants)?;

	context.stage_coupler(stage, coupler)
}

tb_process_spec! {
	/// One call through both directions, in order: the coupler admits it, the
	/// backend reads its principal, the adapter relays the answer, and the
	/// coupler answers the caller.
	pub ChainProcess,
	events {
		observable { COUPLED_CALL_ADMITTED, BACKEND_PRINCIPAL, BACKEND_CALL_RELAYED, COUPLED_CALL_ANSWERED }
		hidden { }
	}
	states {
		Arrived => { COUPLED_CALL_ADMITTED => Admitted },
		Admitted => { BACKEND_PRINCIPAL => Read },
		Read => { BACKEND_CALL_RELAYED => Relayed },
		Relayed => { COUPLED_CALL_ANSWERED => Answered },
		Answered => { }
	}
	terminal { Answered }
}

tb_assert_spec! {
	/// One signed call through both directions: the coupler admits it as
	/// signed, the backend reads the web principal and the forwarded claim,
	/// and both ends answer status 0.
	pub ChainSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(1), equals!("signed")),
			(BACKEND_PRINCIPAL, exactly!(1), equals!(WEB)),
			(BACKEND_CLAIM, exactly!(1), equals!("present")),
			(BACKEND_CALL_RELAYED, exactly!(1), equals!(0u32)),
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32))
		]
	}
}

/// The config that grades a run with `spec` and the order of a chained call.
fn chained(spec: &'static BuiltAssertSpec) -> Result<ScenarioConfig, ScenarioConfigError> {
	ScenarioConfig::builder().with_spec(spec).with_csp(ChainProcess).build()
}

coupled!(ChainEdge, ChainGateway);

// A stock caller signs a claim and calls the coupled edge, the coupler vouches
// for it, the adapter relays it to the stock backend with the principal and
// the claim of the caller, and the answer of the backend returns the same way.
tb_scenario! {
	name: a_stock_caller_reaches_a_stock_backend_through_the_colony,
	config: chained(ChainSpec::latest()),
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			stage_chain(&context, &trace, ChainEdge::stage)?;
			context.gateway::<ChainGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { with_backend!(&context, &trace, &context.claims) }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (web, channel) = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order-10").await?;
			let answer = call(&channel, PLACE, b"order-10", Some(&claim)).await.map_err(|status| status.code());
			assert_eq!(answer.as_deref(), Ok(&b"ledger:order-10"[..]), "the answer of the backend MUST reach the caller");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	/// A vouched call on a route that the backend requires signed for: the
	/// coupler admits it as vouched, the adapter denies it, and the backend
	/// reads nothing.
	pub VouchedDeniedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(1), equals!("vouched")),
			(BACKEND_CALL_REFUSED, exactly!(1), equals!("denied")),
			(BACKEND_PRINCIPAL, exactly!(0)),
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(7u32))
		]
	}
}

coupled!(VouchedDeniedEdge, VouchedDeniedGateway);

// The coupler accepts a vouched call of `List`, but the backend requires it
// signed, so the adapter denies the call with 7, which the caller reads.
tb_scenario! {
	name: a_backend_requires_its_own_assurance_floor,
	spec: VouchedDeniedSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			stage_chain(&context, &trace, VouchedDeniedEdge::stage)?;
			context.gateway::<VouchedDeniedGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { with_backend!(&context, &trace, &context.claims) }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (_web, channel) = context.web(&cluster).await?;
			let answer = call(&channel, LIST, b"order", None).await;
			assert_eq!(code_of(answer), Some(tonic::Code::PermissionDenied));

			cluster.stop();
			Ok(())
		}
	}
}
