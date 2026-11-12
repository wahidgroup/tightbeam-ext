//! Colony work relayed to a stock gRPC server by a `Backend` servlet.

// The colony runtime macros expand `cfg(feature = ...)` probes against the
// invoking crate's feature namespace, which holds the features of this crate
// alone, so the leaked cfg warnings carry no signal here.
#![allow(unexpected_cfgs)]

mod support;

use core::convert::Infallible;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;
use std::time::Duration;

use tightbeam::builder::TypeBuilder;
use tightbeam::clock::UnixMillis;
use tightbeam::colony::cluster::{Cluster, EdgePlane};
use tightbeam::colony::hive::Hive;
use tightbeam::colony::SubmitWork;
use tightbeam::constants::MIN_MUX_CHUNK_SIZE;
use tightbeam::instrumentation::events;
use tightbeam::policy::TransitStatus;
use tightbeam::runtime::rt;
use tightbeam::testing::macros::BuiltAssertSpec;
use tightbeam::testing::{ClusterEnv, ScenarioConfig, ScenarioConfigError, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder};
use tightbeam::urn::Urn;
use tightbeam::{
	cluster, exactly, hive, servlet, tb_assert_spec, tb_process_spec, tb_scenario, urn, Frame, TightBeamError, Version,
};
use tightbeam_grpc::couple::{
	AdmissionTrust, Assurance, Backend, BackendChannel, CallClaim, Code, CoupledCall, CoupledReply, Grants, Origin,
	Principal, Routes, Servlet,
};
use tightbeam_grpc::edge::DialTls;
use tightbeam_grpc::events::{
	BACKEND_CALL_REFUSED, BACKEND_CALL_RELAYED, COUPLED_CALL_ADMITTED, COUPLED_CALL_ANSWERED, COUPLED_CALL_REFUSED,
};
use tightbeam_grpc::protocol::{GrpcAddr, GrpcListener};
use tightbeam_grpc::testing::StreamSigners;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{EventWatch, Identity, WorkClient};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::{Stream, StreamExt};
use tonic::body::Body;
use tonic::codec::CompressionEncoding;
use tonic::codec::Streaming;
use tonic::metadata::MetadataMap;
use tonic::server::{Grpc, StreamingService, UnaryService};
use tonic::transport::{Certificate as TonicCertificate, Identity as TonicIdentity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tower_service::Service;

use support::{
	bounded, code_of, edge_error, mint_error, unexpected, AnswerRead, Coupled, DirectRoute, Graded, RawCodec,
	WebCaller, WEB,
};

/// The method that requires `Signed` at the backend.
const PLACE: &str = "/orders.v1.Orders/Place";

/// A method that the coupler routes as `Vouched`, and the backend requires
/// `Signed` for.
const LIST: &str = "/orders.v1.Orders/List";

/// A bidirectional streaming method, which the backend answers with `ledger:`
/// and each request as it reads it.
const TAIL: &str = "/orders.v1.Orders/Tail";

/// A method that the coupler routes as a stream, and the backend as unary.
const AUDIT: &str = "/orders.v1.Orders/Audit";

/// A method that the coupler routes as unary, and the backend as a stream.
const FEED: &str = "/orders.v1.Orders/Feed";

/// A bidirectional streaming method whose backend never answers.
const HANG: &str = "/orders.v1.Orders/Hang";

/// A client-streaming method whose backend answers once for each request.
const COUNT: &str = "/orders.v1.Orders/Count";

/// A bidirectional streaming method whose backend answers one message past
/// the part ceiling of the adapter.
const BULK: &str = "/orders.v1.Orders/Bulk";

/// The size of the answer of [`BULK`], past the default part ceiling.
const BULK_ANSWER: usize = 300 * 1024;

/// A bidirectional streaming method whose backend answers with one message
/// of [`CHUNKED_ANSWER`] bytes, which a link of [`trickle`] terms carries in
/// many chunks.
const CHUNKED: &str = "/orders.v1.Orders/Chunked";

/// The size of the answer of [`CHUNKED`], within the part ceiling of a direct
/// stream.
const CHUNKED_ANSWER: usize = 8 * 1024;

/// A bidirectional streaming method whose backend answers each request with
/// [`FLOOD_ANSWERS`] messages of [`CHUNKED_ANSWER`] bytes.
const FLOOD: &str = "/orders.v1.Orders/Flood";

/// The count of the answers of [`FLOOD`]: more records than the TCP buffers
/// of a loopback link hold at the default credit.
const FLOOD_ANSWERS: usize = 64;

/// How one end of the chain routes a method, and the assurance it requires.
#[derive(Clone, Copy)]
enum Leg {
	Unary(Assurance),
	ClientStream(Assurance),
	Bidi(Assurance),
}

impl Leg {
	/// `routes` with `method` routed by this leg to `target`.
	fn route<T: Clone>(self, routes: Routes<T>, method: &'static str, target: T) -> Result<Routes<T>, TightBeamError> {
		let routed = match self {
			Self::Unary(assurance) => routes.unary(method, target, assurance),
			Self::ClientStream(assurance) => routes.client_stream(method, target, assurance),
			Self::Bidi(assurance) => routes.bidi_stream(method, target, assurance),
		};
		routed.map_err(edge_error)
	}
}

/// Each method of the chain, how the coupler routes it, and how the adapter
/// routes it. The ends differ where a scenario sends a call that the adapter
/// does not take.
const CHAIN: [(&str, Leg, Leg); 10] = [
	(PLACE, Leg::Unary(Assurance::Signed), Leg::Unary(Assurance::Signed)),
	(LIST, Leg::Unary(Assurance::Vouched), Leg::Unary(Assurance::Signed)),
	(TAIL, Leg::Bidi(Assurance::Vouched), Leg::Bidi(Assurance::Vouched)),
	(AUDIT, Leg::Bidi(Assurance::Vouched), Leg::Unary(Assurance::Vouched)),
	(FEED, Leg::Unary(Assurance::Vouched), Leg::Bidi(Assurance::Vouched)),
	(HANG, Leg::Bidi(Assurance::Vouched), Leg::Bidi(Assurance::Vouched)),
	(
		COUNT,
		Leg::ClientStream(Assurance::Vouched),
		Leg::ClientStream(Assurance::Vouched),
	),
	(BULK, Leg::Bidi(Assurance::Vouched), Leg::Bidi(Assurance::Vouched)),
	(CHUNKED, Leg::Bidi(Assurance::Vouched), Leg::Bidi(Assurance::Vouched)),
	(FLOOD, Leg::Bidi(Assurance::Vouched), Leg::Bidi(Assurance::Vouched)),
];

/// The grant of each method of [`CHAIN`] to the web principal.
fn chain_grants() -> Result<Grants, TightBeamError> {
	let web = Principal::subject(WEB).map_err(edge_error)?;
	let grants = CHAIN
		.into_iter()
		.try_fold(Grants::deny_all(), |grants, (method, ..)| grants.grant(web.clone(), method));
	grants.map_err(edge_error)
}

/// The principal that the backend read from the metadata of a call.
const BACKEND_PRINCIPAL: Urn<'static> = urn!("test", "event:backend/principal");

/// Whether the call that the backend served forwarded a claim.
const BACKEND_CLAIM: Urn<'static> = urn!("test", "event:backend/claim");

/// How long the adapter waits for its backend, connect included: past the
/// opening of a scenario and the patience of `EventWatch::recorded`, so only
/// an advance of a clock that the scenario moves ends a relay within either
/// wait.
const RELAY_TIMEOUT: Duration = EventWatch::PATIENCE.saturating_add(Duration::from_secs(2));

/// The trace context that a direct caller sends, which the backend reads.
const TRACEPARENT: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

/// The deadline that a direct caller sends, well short of [`RELAY_TIMEOUT`].
const CALL_TIMEOUT: Duration = Duration::from_secs(1);

/// The body of a call that the backend fails with [`DETAILS`].
const FAILING: &[u8] = b"fail";

/// The details that the backend fails a call with.
const DETAILS: &[u8] = b"ledger-details";

/// The trace context that the backend read.
const BACKEND_TRACE: Urn<'static> = urn!("test", "event:backend/trace");

/// A connection that the hung backend accepted.
const HUNG_ACCEPTED: Urn<'static> = urn!("test", "event:backend/hung-accepted");

/// Whether the `grpc-timeout` that the backend read fits the deadline of the
/// caller: `bounded` or `unbounded`.
const BACKEND_TIMEOUT: Urn<'static> = urn!("test", "event:backend/timeout");

/// Whether the call that the backend read accepts gzip answers: `gzip` or
/// `identity`.
const BACKEND_ACCEPTS: Urn<'static> = urn!("test", "event:backend/accepts");

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
			let principal = metadata.get_bin(Origin::PRINCIPAL_KEY).and_then(|value| value.to_bytes().ok());
			if let Some(principal) = principal {
				let _ = trace.event_with(BACKEND_PRINCIPAL, &[], String::from_utf8_lossy(&principal).into_owned());
			}

			let claim = if metadata.get_bin(CallClaim::METADATA_KEY).is_some() {
				"present"
			} else {
				"absent"
			};

			let _ = trace.event_with(BACKEND_CLAIM, &[], claim);

			if let Some(context) = metadata.get("traceparent").and_then(|value| value.to_str().ok()) {
				let _ = trace.event_with(BACKEND_TRACE, &[], context.to_owned());
			}

			let timeout = request.headers().get("grpc-timeout").and_then(|value| value.to_str().ok());
			let millis = timeout.and_then(millis_of);
			let bounded = millis.is_some_and(|millis| millis <= CALL_TIMEOUT.as_millis());
			let timeout = if bounded {
				"bounded"
			} else {
				"unbounded"
			};

			let _ = trace.event_with(BACKEND_TIMEOUT, &[], timeout);

			let accepted = request
				.headers()
				.get("grpc-accept-encoding")
				.and_then(|value| value.to_str().ok());
			let gzip = accepted.is_some_and(|encodings| encodings.split(',').any(|encoding| encoding.trim() == "gzip"));
			let accepts = if gzip {
				"gzip"
			} else {
				"identity"
			};

			let _ = trace.event_with(BACKEND_ACCEPTS, &[], accepts);

			let gzip = CompressionEncoding::Gzip;
			let mut grpc = Grpc::new(RawCodec).accept_compressed(gzip).send_compressed(gzip);
			match request.uri().path() {
				TAIL | FEED | COUNT => return Ok(grpc.streaming(LedgerTail, request).await),
				BULK => return Ok(grpc.streaming(LedgerBulk, request).await),
				CHUNKED => return Ok(grpc.streaming(LedgerChunked, request).await),
				FLOOD => return Ok(grpc.streaming(LedgerFlood, request).await),
				HANG => return Ok(grpc.streaming(LedgerHang, request).await),
				_ => {}
			}

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
		if request.get_ref() == FAILING {
			let status = Status::with_details(tonic::Code::FailedPrecondition, "held", DETAILS.into());
			return core::future::ready(Err(status));
		}

		let body = [b"ledger:".as_slice(), request.get_ref()].concat();
		core::future::ready(Ok(Response::new(body)))
	}
}

/// One bidirectional stream of the backend.
struct LedgerTail;

impl StreamingService<Vec<u8>> for LedgerTail {
	type Response = Vec<u8>;
	type ResponseStream = Pin<Box<dyn Stream<Item = Result<Vec<u8>, Status>> + Send>>;
	type Future = core::future::Ready<Result<Response<Self::ResponseStream>, Status>>;

	fn call(&mut self, request: Request<Streaming<Vec<u8>>>) -> Self::Future {
		let requests = request.into_inner();
		let answers = requests.map(|message| {
			let body = message?;
			if body == FAILING {
				return Err(Status::with_details(tonic::Code::FailedPrecondition, "held", DETAILS.into()));
			}

			Ok([b"ledger:".as_slice(), &body].concat())
		});

		let answers: Self::ResponseStream = Box::pin(answers);
		core::future::ready(Ok(Response::new(answers)))
	}
}

/// One bidirectional stream of the backend that answers each request with
/// [`BULK_ANSWER`] bytes.
struct LedgerBulk;

impl StreamingService<Vec<u8>> for LedgerBulk {
	type Response = Vec<u8>;
	type ResponseStream = Pin<Box<dyn Stream<Item = Result<Vec<u8>, Status>> + Send>>;
	type Future = core::future::Ready<Result<Response<Self::ResponseStream>, Status>>;

	fn call(&mut self, request: Request<Streaming<Vec<u8>>>) -> Self::Future {
		let answers = request.into_inner().map(|message| message.map(|_| vec![0x5a; BULK_ANSWER]));
		let answers: Self::ResponseStream = Box::pin(answers);
		core::future::ready(Ok(Response::new(answers)))
	}
}

/// One bidirectional stream of the backend that answers each request with
/// [`CHUNKED_ANSWER`] bytes.
struct LedgerChunked;

impl StreamingService<Vec<u8>> for LedgerChunked {
	type Response = Vec<u8>;
	type ResponseStream = Pin<Box<dyn Stream<Item = Result<Vec<u8>, Status>> + Send>>;
	type Future = core::future::Ready<Result<Response<Self::ResponseStream>, Status>>;

	fn call(&mut self, request: Request<Streaming<Vec<u8>>>) -> Self::Future {
		let answers = request.into_inner().map(|message| message.map(|_| vec![0x5a; CHUNKED_ANSWER]));
		let answers: Self::ResponseStream = Box::pin(answers);
		core::future::ready(Ok(Response::new(answers)))
	}
}

/// One bidirectional stream of the backend that answers each request with
/// [`FLOOD_ANSWERS`] messages of [`CHUNKED_ANSWER`] bytes.
struct LedgerFlood;

impl StreamingService<Vec<u8>> for LedgerFlood {
	type Response = Vec<u8>;
	type ResponseStream = Pin<Box<dyn Stream<Item = Result<Vec<u8>, Status>> + Send>>;
	type Future = core::future::Ready<Result<Response<Self::ResponseStream>, Status>>;

	fn call(&mut self, request: Request<Streaming<Vec<u8>>>) -> Self::Future {
		let answers = futures_util::StreamExt::flat_map(request.into_inner(), |message| {
			let answers = match message {
				Ok(_) => vec![Ok(vec![0x5a; CHUNKED_ANSWER]); FLOOD_ANSWERS],
				Err(status) => vec![Err(status)],
			};
			futures_util::stream::iter(answers)
		});

		let answers: Self::ResponseStream = Box::pin(answers);
		core::future::ready(Ok(Response::new(answers)))
	}
}

/// One bidirectional stream of the backend that never answers.
struct LedgerHang;

impl StreamingService<Vec<u8>> for LedgerHang {
	type Response = Vec<u8>;
	type ResponseStream = Pin<Box<dyn Stream<Item = Result<Vec<u8>, Status>> + Send>>;
	type Future = core::future::Ready<Result<Response<Self::ResponseStream>, Status>>;

	fn call(&mut self, _request: Request<Streaming<Vec<u8>>>) -> Self::Future {
		let held: Self::ResponseStream = Box::pin(tokio_stream::pending());
		core::future::ready(Ok(Response::new(held)))
	}
}

/// The milliseconds of a `grpc-timeout` value, rounded down.
fn millis_of(value: &str) -> Option<u128> {
	let (digits, unit) = value.split_at(value.len().checked_sub(1)?);
	let amount: u128 = digits.parse().ok()?;
	match unit {
		"H" => Some(amount * 3_600_000),
		"M" => Some(amount * 60_000),
		"S" => Some(amount * 1000),
		"m" => Some(amount),
		"u" => Some(amount / 1000),
		"n" => Some(amount / 1_000_000),
		_ => None,
	}
}

servlet! {
	/// The adapter servlet, which relays each coupled call and stream it
	/// admits to the orders backend.
	pub LedgerAdapter<CoupledCall, EnvConfig = Backend>,
	protocol: WsListener,
	handle: |_call, frame, ctx| async move { ctx.env_config().relay(&frame).await },
	duplex: |body, reply, ctx| async move { ctx.env_config().relay_stream(body, reply).await }
}

hive! {
	/// The hive that hosts the adapter over the WebSocket colony.
	pub LedgerHive,
	protocol: WsListener
}

cluster! {
	/// A gateway with an h2c edge, which a native client submits to.
	pub DirectGateway,
	protocol: WsListener,
	edge: GrpcListener
}

/// The servlet type of the adapter.
fn ledger() -> Result<Urn<'static>, TightBeamError> {
	Ok(WorkClient::servlet("ledger")?)
}

impl Coupled {
	/// Start the stock orders backend on loopback, under a TLS certificate of
	/// the root of the scenario, which authenticates its clients under the same
	/// root.
	async fn backend(&self, trace: &TraceCollector) -> Result<(JoinHandle<()>, GrpcAddr), TightBeamError> {
		let server = self.tls.server("CN=ledger,O=acme,C=US").map_err(mint_error)?;
		let root = TonicCertificate::from_pem(self.tls.root_pem().map_err(mint_error)?);
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
}

/// Start a backend that accepts each connection, records [`HUNG_ACCEPTED`] on
/// `trace`, and never answers its TLS handshake.
async fn hung_backend(trace: &TraceCollector) -> Result<(JoinHandle<()>, GrpcAddr), TightBeamError> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let addr = GrpcAddr::from(listener.local_addr()?);
	let trace = trace.share();
	let held = tokio::spawn(async move {
		let mut open = Vec::new();
		while let Ok((tcp, _)) = listener.accept().await {
			let _ = trace.event(HUNG_ACCEPTED);
			open.push(tcp);
		}
	});

	Ok((held, addr))
}

impl Coupled {
	/// The adapter of the backend at `addr`, which routes each method of
	/// [`CHAIN`] by its adapter leg, grants it to the web principal, and
	/// admits the direct caller `direct`.
	fn adapter(&self, trace: &TraceCollector, addr: &GrpcAddr, direct: &Identity) -> Result<Backend, TightBeamError> {
		let client = self.caller("CN=ledger adapter,O=acme,C=US", Some("spiffe://acme/ledger-adapter"));
		let tls = DialTls::new([self.tls.root()]).map_err(edge_error)?;
		let tls = tls.with_identity([client.leaf().clone()], client.key()).map_err(edge_error)?;
		let channel = BackendChannel::new(addr, &tls)?;

		let routes = CHAIN
			.into_iter()
			.try_fold(Routes::new(), |routes, (method, _, adapted)| adapted.route(routes, method, ()))?;

		let grants = chain_grants()?;
		let admission = AdmissionTrust::new()
			.with_vouchers(self.vouching.trust_anchor()?)
			.with_direct_callers(direct.trust_anchor()?)
			.with_claim_signers(self.claims.trust_anchor()?);

		let signer = self.answers.signing_identity();
		let backend = Backend::new(channel, routes, grants, admission, signer).map_err(edge_error)?;
		let backend = backend.with_timeout(RELAY_TIMEOUT).with_clock(self.clock.edge());
		Ok(backend.with_trace(trace.share()))
	}

	/// Start the hive that hosts the adapter of the backend at `addr`, which
	/// admits the direct caller `direct`.
	async fn hive(
		&self,
		trace: &TraceCollector,
		addr: &GrpcAddr,
		direct: &Identity,
	) -> Result<LedgerHive, TightBeamError> {
		let backend = Arc::new(self.adapter(trace, addr, direct)?);
		let config = self.transport.servlet_config(backend);
		let served = LedgerAdapter::start(Arc::new(trace.share()), config).await?;

		let mut hive = LedgerHive::new(Some(self.transport.hive_config()?))?;
		let restart = |_trace| async { Err(TightBeamError::MissingConfiguration) };
		hive.register(ledger()?, served, restart)?;
		hive.establish(Arc::new(trace.share())).await?;
		Ok(hive)
	}
}

/// A direct call of `method` with `body`, signed under `signer` as its own
/// principal, as a native tightbeam client submits it.
async fn direct(signer: &Identity, method: &str, body: &[u8]) -> Result<Frame, TightBeamError> {
	let call = CoupledCall::direct(method, body.to_vec()).map_err(edge_error)?;
	let order = UnixMillis::now().get();
	let draft = Version::V1
		.compose()
		.with_id(b"ledger-call")
		.with_order(order)
		.with_message(call);

	let mut frame = draft.build()?;
	frame.sign_with_provider(&signer.signing_identity()).await?;
	Ok(frame)
}

/// A direct call of `method` with `body`, the trace context [`TRACEPARENT`],
/// and the deadline [`CALL_TIMEOUT`], signed under `signer`.
async fn traced(signer: &Identity, method: &str, body: &[u8]) -> Result<Frame, TightBeamError> {
	let call = CoupledCall::direct(method, body.to_vec())
		.map_err(edge_error)?
		.with_timeout(CALL_TIMEOUT);

	let call = call.with_metadata("traceparent", TRACEPARENT).map_err(edge_error)?;
	let draft = Version::V1
		.compose()
		.with_id(b"traced-call")
		.with_order(UnixMillis::now().get());

	let mut frame = draft.with_message(call).build()?;
	frame.sign_with_provider(&signer.signing_identity()).await?;
	Ok(frame)
}

impl Coupled {
	/// The answer of the adapter in `reply`, once its signature verifies under
	/// the answer identity of the scenario.
	fn answer_of(&self, reply: &Frame) -> Result<CoupledReply, TightBeamError> {
		assert!(self.answers.verifies(reply), "the adapter MUST sign its answer");
		reply.decode_message()
	}
}

/// Start the backend and the hive of the adapter, which admits `direct`.
macro_rules! with_backend {
	($context:expr, $trace:expr, $direct:expr) => {{
		// The drop of the handle detaches the backend, which serves until the
		// runtime of the scenario ends.
		let (_served, addr) = $context.backend($trace).await?;
		$context.hive($trace, &addr, $direct).await
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
			let mut client = builder.build().connect(WorkClient::edge_of(&cluster)?).await?;

			let frame = direct(&context.claims, PLACE, b"order-9").await?;
			let reply = client.submit_work_to(ledger()?, &frame).await?;
			let answer = context.answer_of(&reply)?;
			assert_eq!(answer.code(), Code::Ok, "the backend MUST serve the call");
			assert_eq!(answer.body(), b"ledger:order-9", "the adapter MUST relay the answer of the backend");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	/// A direct call to a backend that never connects: the adapter answers 4.
	pub HungRelaySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(BACKEND_CALL_RELAYED, exactly!(1), equals!(4u32)),
			(BACKEND_PRINCIPAL, exactly!(0))
		]
	}
}

/// The events of the scenario of a hung backend.
static HUNG_RELAY_EVENTS: EventWatch = EventWatch::new();

// The adapter bounds the connect of a hung backend by its own timeout.
tb_scenario! {
	name: a_hung_backend_answers_deadline_exceeded,
	config: HungRelaySpec::latest().watched(&HUNG_RELAY_EVENTS),
	environment Cluster {
		context: Coupled::clocked(&HUNG_RELAY_EVENTS),
		start: |SetupEnv { trace, context }| async move { context.gateway::<DirectGateway>(&trace).await },
		hives: |SetupEnv { trace, context }| vec![async move {
			let (_held, addr) = hung_backend(&trace).await?;
			context.hive(&trace, &addr, &context.claims).await
		}],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let builder = ClientBuilder::<GrpcListener>::builder().with_trust_store(context.transport.trust_anchor()?);
			let mut client = builder.build().connect(WorkClient::edge_of(&cluster)?).await?;

			// The adapter dials its backend within the timeout of the relay.
			let frame = direct(&context.claims, PLACE, b"order-12").await?;
			let advancing = async {
				HUNG_RELAY_EVENTS.recorded(HUNG_ACCEPTED, 1).await?;
				context.clock.advance(RELAY_TIMEOUT)
			};
			let (reply, advanced) = tokio::join!(bounded(client.submit_work_to(ledger()?, &frame)), advancing);
			advanced?;
			let answer = context.answer_of(&reply??)?;
			assert_eq!(answer.code(), Code::DeadlineExceeded, "a hung backend MUST answer 4");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	/// A direct call that the adapter relays on a thread with no timer for
	/// the clock of the adapter: the adapter answers 13.
	pub NoTimerRelaySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(BACKEND_CALL_RELAYED, exactly!(1), equals!(13u32)),
			(BACKEND_PRINCIPAL, exactly!(0))
		]
	}
}

// The adapter bounds each call on its clock. A thread outside any tokio
// runtime has no timer for `SystemClock`, so a relay that waits there ends at
// once with 13.
tb_scenario! {
	name: a_relay_whose_clock_gives_no_timer_answers_internal,
	spec: NoTimerRelaySpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let context = Coupled::mint();
			let (_held, addr) = hung_backend(&trace).await?;
			let backend = context.adapter(&trace, &addr, &context.claims)?;
			let frame = direct(&context.claims, PLACE, b"order-13").await?;

			let relayed = std::thread::scope(|scope| scope.spawn(|| rt::block_on(backend.relay(&frame))).join());
			let reply = relayed.map_err(|_| unexpected("the relay thread panicked"))??;
			let reply = reply.ok_or_else(|| unexpected("the adapter answered no frame"))?;
			assert_eq!(context.answer_of(&reply)?.code(), Code::Internal, "a relay with no timer MUST answer 13");
			Ok(())
		}
	}
}

tb_assert_spec! {
	/// Two traced direct calls: for each, the backend reads the trace context,
	/// a deadline within the one of the caller, and an offer of gzip answers,
	/// which it answers in.
	pub TracedRelaySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(BACKEND_TRACE, exactly!(2), equals!(TRACEPARENT)),
			(BACKEND_TIMEOUT, exactly!(2), equals!("bounded")),
			(BACKEND_ACCEPTS, exactly!(2), equals!("gzip")),
			(BACKEND_CALL_RELAYED, exactly!(2))
		]
	}
}

// The adapter forwards the metadata and the deadline of a call, and relays
// the details of a failure.
tb_scenario! {
	name: a_backend_reads_the_trace_and_deadline_and_relays_its_details,
	spec: TracedRelaySpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move { context.gateway::<DirectGateway>(&trace).await },
		hives: |SetupEnv { trace, context }| vec![async move { with_backend!(&context, &trace, &context.claims) }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let builder = ClientBuilder::<GrpcListener>::builder().with_trust_store(context.transport.trust_anchor()?);
			let mut client = builder.build().connect(WorkClient::edge_of(&cluster)?).await?;

			let frame = traced(&context.claims, PLACE, b"order-15").await?;
			let reply = client.submit_work_to(ledger()?, &frame).await?;
			let answer = context.answer_of(&reply)?;
			assert_eq!(answer.body(), b"ledger:order-15");

			let frame = traced(&context.claims, PLACE, FAILING).await?;
			let reply = client.submit_work_to(ledger()?, &frame).await?;
			let answer = context.answer_of(&reply)?;
			assert_eq!(answer.code(), Code::FailedPrecondition);
			assert_eq!(answer.details(), Some(DETAILS), "the details of the backend MUST reach the caller");

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
	let created = Identity::mint("CN=intruder,O=acme,C=US", 9, support::LIFETIME);
	created.expect("an identity is created")
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
			let mut client = builder.build().connect(WorkClient::edge_of(&cluster)?).await?;

			let frame = direct(intruder, PLACE, b"order").await?;
			let reply = client.submit_work_to(ledger()?, &frame).await?;
			let answer = context.answer_of(&reply)?;
			assert_eq!(answer.code(), Code::PermissionDenied, "the adapter MUST deny a principal with no grant");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	/// A direct call under a signer that the adapter does not trust: the
	/// adapter refuses it at its admission, before its policy, so its trail
	/// records no refusal and no relay, and the backend reads nothing.
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
// alone as a direct caller, so the adapter refuses the call at its admission.
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
			let mut client = builder.build().connect(WorkClient::edge_of(&cluster)?).await?;

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
	config: DirectRelaySpec::latest().rejected(),
	environment Cluster {
		context: (Coupled::mint(), intruder()),
		start: |SetupEnv { trace, context }| async move { context.0.gateway::<DirectGateway>(&trace).await },
		hives: |SetupEnv { trace, context }| vec![async move { with_backend!(&context.0, &trace, &context.1) }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (context, intruder) = (&context.0, &context.1);
			let builder = ClientBuilder::<GrpcListener>::builder().with_trust_store(context.transport.trust_anchor()?);
			let mut client = builder.build().connect(WorkClient::edge_of(&cluster)?).await?;

			let frame = direct(intruder, PLACE, b"order").await?;
			let reply = client.submit_work_to(ledger()?, &frame).await?;
			let answer = context.answer_of(&reply)?;
			assert_eq!(answer.code(), Code::PermissionDenied);

			cluster.stop();
			Ok(())
		}
	}
}

impl Coupled {
	/// Stage the coupled edge that routes each method of [`CHAIN`] by its
	/// coupler leg to the adapter, grants it to the web principal, and pins the
	/// answer identity, which the adapter signs under.
	fn stage_chain(
		&self,
		trace: &TraceCollector,
		stage: fn(tightbeam_grpc::edge::Edge, tightbeam_grpc::edge::Dial),
	) -> Result<(), TightBeamError> {
		let adapter = Servlet::new(ledger()?, self.answers.certificate().clone()).map_err(edge_error)?;
		let routes = CHAIN.into_iter().try_fold(Routes::new(), |routes, (method, coupled, _)| {
			coupled.route(routes, method, adapter.clone())
		})?;

		let coupler = self.coupler(routes, chain_grants()?)?;

		self.stage_coupler(trace, stage, coupler)
	}
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

// A stock caller reaches a stock backend through the coupler and the adapter.
tb_scenario! {
	name: a_stock_caller_reaches_a_stock_backend_through_the_colony,
	config: chained(ChainSpec::latest()),
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage_chain(&trace, ChainEdge::stage)?;
			context.gateway::<ChainGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { with_backend!(&context, &trace, &context.claims) }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order-10").await?;
			let answer = channel.call(PLACE, b"order-10", Some(&claim)).await?.map_err(|status| status.code());
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
			context.stage_chain(&trace, VouchedDeniedEdge::stage)?;
			context.gateway::<VouchedDeniedGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { with_backend!(&context, &trace, &context.claims) }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let answer = channel.call(LIST, b"order", None).await?;
			assert_eq!(code_of(answer), Some(tonic::Code::PermissionDenied));

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	/// Streams through both directions: the backend reads the web principal
	/// on each, the adapter relays its answers and its status, 0 and then 9,
	/// and it refuses a stream of a method that the backend routes unary, and
	/// a unary call of a method that it routes as a stream.
	pub StreamChainSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(BACKEND_PRINCIPAL, exactly!(2), equals!(WEB)),
			(BACKEND_CALL_RELAYED, exactly!(2)),
			(BACKEND_CALL_REFUSED, exactly!(2), equals!("unrouted")),
			(COUPLED_CALL_ANSWERED, exactly!(4))
		]
	}
}

coupled!(StreamChainEdge, StreamChainGateway);

// A stock caller streams to a stock backend through the coupler and the
// adapter, and each request reaches the backend before its answer returns.
tb_scenario! {
	name: a_stock_stream_reaches_a_stock_backend_through_the_colony,
	spec: StreamChainSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage_chain(&trace, StreamChainEdge::stage)?;
			context.gateway::<StreamChainGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { with_backend!(&context, &trace, &context.claims) }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let answers = channel.stream(TAIL, &[b"a", b"b"], None).await?.map_err(|status| status.code());
			let expected = vec![b"ledger:a".to_vec(), b"ledger:b".to_vec()];
			assert_eq!(answers, Ok(expected), "each answer of the backend MUST reach the caller");

			let refused = channel.stream(AUDIT, &[b"a"], None).await?;
			assert_eq!(refused.map_err(|status| status.code()), Err(tonic::Code::Unimplemented));

			let failed = channel.stream(TAIL, &[FAILING], None).await?;
			let failed = failed.err().ok_or_else(|| unexpected("the backend answered a failing stream"))?;
			assert_eq!((failed.code(), failed.details()), (tonic::Code::FailedPrecondition, DETAILS));

			let fed = channel.call(FEED, b"a", None).await?;
			assert_eq!(code_of(fed), Some(tonic::Code::Unimplemented), "a unary call of a stream route MUST read 12");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	/// A stream to a backend that never answers: the adapter ends it at its
	/// own timeout with 4.
	pub HungStreamSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(BACKEND_CALL_RELAYED, exactly!(1), equals!(4u32)),
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(4u32))
		]
	}
}

coupled!(HungStreamEdge, HungStreamGateway);

/// The events of the scenario of a backend stream that never answers.
static HUNG_STREAM_EVENTS: EventWatch = EventWatch::new();

// A backend stream that never answers ends at the timeout of the adapter,
// and the caller reads 4.
tb_scenario! {
	name: a_hung_backend_stream_answers_deadline_exceeded,
	config: HungStreamSpec::latest().watched(&HUNG_STREAM_EVENTS),
	environment Cluster {
		context: Coupled::clocked(&HUNG_STREAM_EVENTS),
		start: |SetupEnv { trace, context }| async move {
			context.stage_chain(&trace, HungStreamEdge::stage)?;
			context.gateway::<HungStreamGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { with_backend!(&context, &trace, &context.claims) }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;

			// The backend reads the call of the adapter, which the timeout of
			// the relay bounds, and never answers it.
			let advancing = async {
				HUNG_STREAM_EVENTS.recorded(BACKEND_PRINCIPAL, 1).await?;
				context.clock.advance(RELAY_TIMEOUT)
			};
			let (hung, advanced) = tokio::join!(channel.stream(HANG, &[b"a"], None), advancing);
			advanced?;
			assert_eq!(hung?.map_err(|status| status.code()), Err(tonic::Code::DeadlineExceeded));

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	/// Two backend answers that the adapter cannot relay: one past the count
	/// of its method, and one past the part ceiling. The adapter ends each
	/// stream with the status of its own refusal, which the coupler relays.
	pub UnsentAnswerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(BACKEND_CALL_REFUSED, exactly!(2), equals!("part")),
			(COUPLED_CALL_REFUSED, exactly!(2), equals!("transit"))
		]
	}
}

coupled!(UnsentAnswerEdge, UnsentAnswerGateway);

// A backend that answers a client stream twice reads 12 at the caller, and one
// that answers past the part ceiling reads 8: the status of the part that did
// not send, at either end.
tb_scenario! {
	name: a_backend_answer_that_does_not_send_ends_with_its_own_status,
	spec: UnsentAnswerSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage_chain(&trace, UnsentAnswerEdge::stage)?;
			context.gateway::<UnsentAnswerGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { with_backend!(&context, &trace, &context.claims) }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let counted = channel.stream(COUNT, &[b"a", b"b"], None).await?;
			assert_eq!(code_of(counted), Some(tonic::Code::Unimplemented), "a second answer MUST read 12");

			let bulk = channel.stream(BULK, &[b"a"], None).await?;
			assert_eq!(code_of(bulk), Some(tonic::Code::ResourceExhausted), "an answer past the ceiling MUST read 8");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	/// A direct stream to the adapter whose part another key signs: the
	/// adapter refuses the part, ends the call of the backend, and relays
	/// nothing.
	pub ForgedPartSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(BACKEND_CALL_REFUSED, exactly!(1), equals!("part")),
			(BACKEND_CALL_RELAYED, exactly!(0))
		]
	}
}

// A peer that holds the key of a direct caller opens a stream to the adapter,
// and signs its part under another key. The adapter ends the stream and the
// call of the backend.
tb_scenario! {
	name: a_backend_stream_part_under_another_key_ends_the_call,
	spec: ForgedPartSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move { context.gateway::<DirectGateway>(&trace).await },
		hives: |SetupEnv { trace, context }| vec![async move { with_backend!(&context, &trace, &context.claims) }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let caller = context.claims.signing_identity();
			let other = context.session.signing_identity();
			let forging = StreamSigners { head: &caller, parts: &other };
			let route = DirectRoute { servlet: ledger()?, method: TAIL };
			let forged = context.direct_stream(cluster.addr(), route, forging).await?;
			let refused = forged.err().and_then(|error| error.transit_status());
			assert_eq!(refused, Some(TransitStatus::Unauthenticated));

			cluster.stop();
			Ok(())
		}
	}
}

/// The terms of a link that carries one chunk of [`MIN_MUX_CHUNK_SIZE`] bytes
/// of each stream at a time, until its reader takes the chunk.
fn trickle() -> TransportOffer {
	TransportOffer::mux(4)
		.with_initial_stream_credit(1)
		.with_chunk_payload_size(MIN_MUX_CHUNK_SIZE)
}

impl Coupled {
	/// Start the gateway `G`, whose links take [`trickle`] terms.
	async fn trickle_gateway<G: Cluster>(&self, trace: &TraceCollector) -> Result<G, TightBeamError> {
		let mut config = self.transport.cluster_config(EdgePlane::new("127.0.0.1:0"))?;
		config.pool_config.mux_offer = Some(Arc::new(trickle()));
		G::start(Arc::new(trace.share()), config).await
	}
}

tb_assert_spec! {
	/// A direct stream whose reader holds its reads until the timeout of the
	/// adapter cuts the push of its answer part: the adapter refuses to end
	/// the stream on the sink that the cut left, and relays no end.
	pub CutAnswerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(BACKEND_CALL_REFUSED, exactly!(1), equals!("part")),
			(BACKEND_CALL_RELAYED, exactly!(0))
		]
	}
}

/// The events of the scenario of an answer part that the timeout cuts.
static CUT_ANSWER_EVENTS: EventWatch = EventWatch::new();

// The timeout of the adapter cuts the push of an answer part that a held
// reader parks, so the stream fails with 4 and no part follows the cut.
tb_scenario! {
	name: an_answer_part_that_the_timeout_cuts_ends_the_stream_with_its_deadline,
	config: CutAnswerSpec::latest().watched(&CUT_ANSWER_EVENTS),
	environment Cluster {
		context: Coupled::clocked(&CUT_ANSWER_EVENTS),
		start: |SetupEnv { trace, context }| async move { context.trickle_gateway::<DirectGateway>(&trace).await },
		hives: |SetupEnv { trace, context }| vec![async move { with_backend!(&context, &trace, &context.claims) }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let caller = context.claims.signing_identity();
			let route = DirectRoute { servlet: ledger()?, method: CHUNKED };
			let signers = StreamSigners { head: &caller, parts: &caller };
			let mut answer = context.direct_answer(cluster.addr(), route, signers, trickle()).await?;
			answer.arrived().await?;
			context.clock.advance(RELAY_TIMEOUT)?;
			CUT_ANSWER_EVENTS.recorded(BACKEND_CALL_REFUSED, 1).await?;

			let AnswerRead { failure, .. } = answer.messages().await?;
			let failure = failure.and_then(|error| error.transit_status());
			assert_eq!(failure, Some(TransitStatus::DeadlineExceeded), "a cut answer part MUST end the stream with 4");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	/// A direct stream whose backend floods its answer, which the caller reads
	/// as it arrives: each link of the colony carries every record whole, so
	/// no link refuses an envelope, and the adapter relays the answer with 0.
	pub FloodedAnswerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(BACKEND_CALL_RELAYED, exactly!(1), equals!(0u32)),
			(events::TRANSPORT_ENVELOPE_REFUSED, exactly!(0))
		]
	}
}

/// The events of the scenario of a flooded answer.
static FLOODED_ANSWER_EVENTS: EventWatch = EventWatch::new();

// The backend answers one request with more records than the TCP buffers of
// a link hold at the default credit, and the direct caller reads each part as
// it arrives. Every answer reaches the caller, and the stream ends with 0.
tb_scenario! {
	name: a_flooded_answer_reaches_a_direct_caller_whole,
	config: FloodedAnswerSpec::latest().watched(&FLOODED_ANSWER_EVENTS),
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move { context.gateway::<DirectGateway>(&trace).await },
		hives: |SetupEnv { trace, context }| vec![async move { with_backend!(&context, &trace, &context.claims) }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let caller = context.claims.signing_identity();
			let route = DirectRoute { servlet: ledger()?, method: FLOOD };
			let signers = StreamSigners { head: &caller, parts: &caller };
			let answer = context.direct_answer(cluster.addr(), route, signers, TransportOffer::mux(4)).await?;
			let AnswerRead { messages, failure } = answer.messages().await?;
			let ended = failure.map(|error| error.to_string());
			assert_eq!((messages.len(), ended), (FLOOD_ANSWERS, None), "a flooded answer MUST reach the caller whole");
			FLOODED_ANSWER_EVENTS.recorded(BACKEND_CALL_RELAYED, 1).await?;

			cluster.stop();
			Ok(())
		}
	}
}
