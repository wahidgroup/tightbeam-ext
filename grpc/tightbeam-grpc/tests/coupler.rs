//! Stock gRPC callers through a coupled edge to a colony servlet.
//!
//! `Get` and `List` require `Vouched`, and `Place` requires `Signed`. The
//! billing caller holds `Get`, and the web caller holds all three.

// The colony runtime macros expand `cfg(feature = ...)` probes against the
// invoking crate's feature namespace, which holds the features of this crate
// alone, so the leaked cfg warnings carry no signal here.
#![allow(unexpected_cfgs)]

mod support;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use futures_util::stream;
use http::uri::PathAndQuery;
use rustls::AlertDescription;
use rustls_pki_types::CertificateRevocationListDer;
use tightbeam::builder::TypeBuilder;
use tightbeam::clock::UnixMillis;
use tightbeam::colony::hive::Hive;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::KeyCurves;
use tightbeam::der::asn1::OctetString;
use tightbeam::der::{Encode, Sequence};
use tightbeam::instrumentation::events;
use tightbeam::policy::TransitStatus;
use tightbeam::testing::macros::BuiltAssertSpec;
use tightbeam::testing::{ClusterEnv, ScenarioConfig, ScenarioConfigError, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::TransportLimits;
use tightbeam::urn::Urn;
use tightbeam::{
	exactly, hive, servlet, tb_assert_spec, tb_process_spec, tb_scenario, urn, Beamable, TightBeamError, Version,
};
use tightbeam_grpc::couple::{
	AdmissionTrust, AdmittedCall, AdmittedStream, AdmittedStreamParts, Assurance, BearerTrust, CallClaim, CallLimits,
	CallerTrust, ClaimLedger, ClaimSpend, Code, CoupleError, CoupledCall, Coupler, Grants, LedgerError, LedgerFuture,
	MemoryLedger, Metadata, Origin, Principal, Routes, Servlet,
};
use tightbeam_grpc::edge::{Dial, Edge};
use tightbeam_grpc::events::{
	COUPLED_CALL_ADMITTED, COUPLED_CALL_ANSWERED, COUPLED_CALL_OPENED, COUPLED_CALL_REFUSED, COUPLED_CLAIM_FORGOTTEN,
	COUPLED_CLAIM_SPENT, COUPLED_SESSION_OPENED, EDGE_REFUSED,
};
use tightbeam_grpc::protocol::{GrpcAddr, HEALTH_CHECK_PATH};
use tightbeam_grpc::testing::{PartFrames, StreamParts, StreamSigners, TlsAuthority, TlsLeaf};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{EventWatch, Identity, WorkClient};
use tokio::sync::Semaphore;
use tokio_stream::wrappers::ReceiverStream;
use tonic::codec::CompressionEncoding;
use tonic::metadata::MetadataValue;
use tonic::{Request, Status};

use support::{
	bounded, code_of, edge_error, mint_error, unexpected, Coupled, DirectRoute, Field, Graded, H2Tunnel, PageCall,
	PageRead, RawCodec, ScenarioClock, StockChannel, WebAnswer, WebCaller, BILLING, NOT_SERVING, SERVING, WEB,
};

/// The method that requires `Vouched`.
const GET: &str = "/orders.v1.Orders/Get";

/// The method that requires `Signed`.
const PLACE: &str = "/orders.v1.Orders/Place";

/// A method that requires `Vouched`, granted to the web caller alone.
const LIST: &str = "/orders.v1.Orders/List";

/// A server-streaming method that requires `Vouched`, granted to the web
/// caller alone.
const WATCH: &str = "/orders.v1.Orders/Watch";

/// A client-streaming method that requires `Vouched`, granted to the web
/// caller alone.
const BATCH: &str = "/orders.v1.Orders/Batch";

/// A bidirectional streaming method that requires `Signed`, granted to the web
/// caller alone.
const CHAT: &str = "/orders.v1.Orders/Chat";

/// A server-streaming method whose servlet answers one message, then holds
/// the stream open, granted to the web caller alone.
const HOLD: &str = "/orders.v1.Orders/Hold";

/// A client-streaming method whose servlet answers twice to `twice` and not at
/// all otherwise, granted to the web caller alone.
const BROKEN: &str = "/orders.v1.Orders/Broken";

/// A client-streaming method whose servlet answers outside the stream
/// library: twice to `twice`, and not at all otherwise, granted to the web
/// caller alone.
const TWICE: &str = "/orders.v1.Orders/Twice";

/// A bidirectional streaming method whose servlet answers until a push of the
/// answer fails, then sends once more, and records what that send answered.
const SEVERED: &str = "/orders.v1.Orders/Severed";

/// What a send of the servlet answered after a push of its answer failed, by
/// the status of its refusal.
const LATE_SEND: Urn<'static> = urn!("test", "event:servlet/late-send");

/// A method that requires `Bearer`, granted to the mobile caller alone.
const BROWSE: &str = "/orders.v1.Orders/Browse";

/// A server-streaming method that requires `Bearer`, granted to the mobile
/// caller alone. The servlet answers [`FAILING`] with one message, then fails.
const FEED: &str = "/orders.v1.Orders/Feed";

/// The metadata key of the client chain that a proxy forwards.
const XFCC: &str = "x-forwarded-client-cert";

/// The SPIFFE ID that the bearer tokens of the mobile caller name.
const MOBILE: &str = "spiffe://acme/mobile";

/// The SPIFFE ID of the proxy that forwards client chains.
const PROXY: &str = "spiffe://acme/proxy";

/// The body of a call that the servlet fails with [`DETAILS`].
const FAILING: &[u8] = b"fail";

/// The deadline that a traced caller sends.
const CALLER_TIMEOUT: Duration = Duration::from_secs(2);

/// The binary metadata that a caller sends, which the coupler forwards.
const TENANT: [u8; 2] = [0x00, 0xff];

/// The details that the servlet fails a call with.
const DETAILS: &[u8] = b"order-details";

/// The trace context that a caller sends, which the coupler forwards.
const TRACEPARENT: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

/// The trace context that the servlet read.
const SERVED_TRACE: Urn<'static> = urn!("test", "event:servlet/trace");

/// The deadline that the servlet read: `bounded` within [`CALLER_TIMEOUT`],
/// `default` past it, or `absent`.
const SERVED_DEADLINE: Urn<'static> = urn!("test", "event:servlet/deadline");

/// How many metadata entries the servlet read.
const SERVED_METADATA: Urn<'static> = urn!("test", "event:servlet/metadata");

/// The binary metadata that the servlet read, in hex.
const SERVED_TENANT: Urn<'static> = urn!("test", "event:servlet/tenant");

/// The part ceiling that the servlet that breaks the shape of its methods
/// reads and answers under.
const OUT_OF_SHAPE_CEILING: usize = 256 * 1024;

/// What the servlet waits for before it answers a call or a stream that
/// holds: a count of one event on the trace, which its body names as
/// `<event>:<count>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hold {
	/// The coupler refused this many calls, such as the one that waited on
	/// the session that the held call holds.
	Refused(usize),
	/// The servlet admitted this many calls, so they all ran at once.
	Served(usize),
	/// The coupler admitted this many calls, so the calls past the one that
	/// holds the session wait for it.
	Admitted(usize),
}

impl Hold {
	/// The hold that `body` names, or `None` for a body that holds nothing.
	fn of(body: &[u8]) -> Option<Self> {
		let text = core::str::from_utf8(body).ok()?;
		let (event, count) = text.split_once(':')?;
		let count = count.parse().ok()?;
		match event {
			"refused" => Some(Self::Refused(count)),
			"served" => Some(Self::Served(count)),
			"admitted" => Some(Self::Admitted(count)),
			_ => None,
		}
	}

	/// The body that names the hold.
	fn body(self) -> Vec<u8> {
		let (event, count) = match self {
			Self::Refused(count) => ("refused", count),
			Self::Served(count) => ("served", count),
			Self::Admitted(count) => ("admitted", count),
		};
		format!("{event}:{count}").into_bytes()
	}

	/// Wait until a trace of `events` holds the count of the event of the
	/// hold.
	async fn release(self, events: &EventWatch) -> Result<(), TightBeamError> {
		match self {
			Self::Refused(count) => Ok(events.recorded(COUPLED_CALL_REFUSED, count).await?),
			Self::Served(count) => Ok(events.recorded(SERVED_ASSURANCE, count).await?),
			Self::Admitted(count) => Ok(events.recorded(COUPLED_CALL_ADMITTED, count).await?),
		}
	}
}

/// The assurance that the servlet admitted a call with, which the servlet
/// records itself.
const SERVED_ASSURANCE: Urn<'static> = urn!("test", "event:servlet/assurance");

/// What the servlet of the orders service admits and signs with, the trace
/// it records the assurance of each call on, and the events that a held call
/// waits on.
struct OrdersEnv {
	admission: AdmissionTrust,
	signer: SigningIdentity,
	trace: TraceCollector,
	events: &'static EventWatch,
}

impl OrdersEnv {
	/// Record what the servlet read of the origin of a call or a stream: its
	/// assurance, its metadata, and its deadline.
	fn record(&self, origin: &Origin) -> Result<(), TightBeamError> {
		let assurance = match origin.assurance() {
			Assurance::Bearer => "bearer",
			Assurance::Vouched => "vouched",
			Assurance::Signed => "signed",
		};
		self.trace.event_with(SERVED_ASSURANCE, &[], assurance)?;

		let entries = u32::try_from(origin.metadata().count()).unwrap_or(u32::MAX);
		self.trace.event_with(SERVED_METADATA, &[], entries)?;
		for Metadata { key, value } in origin.metadata() {
			match key {
				"traceparent" => {
					self.trace
						.event_with(SERVED_TRACE, &[], String::from_utf8_lossy(value).into_owned())?;
				}
				"x-tenant-bin" => {
					self.trace.event_with(SERVED_TENANT, &[], hex(value))?;
				}
				_ => {}
			}
		}

		let deadline = match origin.remaining() {
			Some(remaining) if remaining <= CALLER_TIMEOUT => "bounded",
			Some(_) => "default",
			None => "absent",
		};
		self.trace.event_with(SERVED_DEADLINE, &[], deadline)?;
		Ok(())
	}
}

/// The lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

servlet! {
	/// Serves each coupled call that it admits with `served:` and the body of
	/// the call, signed under the answer identity of the scenario, and each
	/// coupled stream by its method.
	pub OrdersServlet<CoupledCall, EnvConfig = OrdersEnv>,
	protocol: WsListener,
	handle: |_call, frame, ctx| async move {
		let env = ctx.env_config();
		let admitted = AdmittedCall::admit(&frame, &env.admission)?;
		env.record(admitted.origin())?;
		if let Some(hold) = Hold::of(admitted.body()) {
			hold.release(env.events).await?;
		}

		if admitted.body() == FAILING {
			let status = Status::with_details(Code::FailedPrecondition, "held", DETAILS.into());
			return admitted.fail(&status, &env.signer).await;
		}

		let body = [b"served:".as_slice(), admitted.body()].concat();
		admitted.reply(body, &env.signer).await
	},
	duplex: |body, reply, ctx| async move {
		let env = ctx.env_config();
		let stream = AdmittedStream::admit(body, reply, &env.admission, env.signer.clone()).await?;
		let origin = stream.origin();
		env.record(origin)?;

		let method = origin.method().as_str().to_owned();
		let AdmittedStreamParts { mut requests, mut answers, .. } = stream.split();
		if method == SEVERED {
			while answers.send(vec![0x5a; 1024]).await.is_ok() {}
			let late = match answers.send(b"late".to_vec()).await {
				Err(TightBeamError::TransportError(refused)) => refused.transit_status(),
				_ => None,
			};

			env.trace.event_with(LATE_SEND, &[], format!("{late:?}"))?;

			return Ok(());
		}

		if method == HOLD {
			let request = requests.next().await?.unwrap_or_default();
			answers.send(b"held".to_vec()).await?;
			if let Some(hold) = Hold::of(&request) {
				hold.release(env.events).await?;
			}

			return answers.finish(requests).await;
		}

		let mut batch = Vec::new();
		while let Some(message) = requests.next().await? {
			match method.as_str() {
				FEED if message == FAILING => {
					answers.send(b"partial".to_vec()).await?;
					let status = Status::with_details(Code::FailedPrecondition, "held", DETAILS.into());
					return answers.end(requests, &status).await;
				}
				WATCH | FEED => {
					for index in [b"0", b"1", b"2"] {
						let watched = [b"watch:".as_slice(), &message, b":", index].concat();
						answers.send(watched).await?;
					}
				}
				BATCH | BROKEN => batch.extend_from_slice(&message),
				_ if message == FAILING => {
					let status = Status::with_details(Code::FailedPrecondition, "held", DETAILS.into());
					return answers.end(requests, &status).await;
				}
				_ => answers.send([b"chat:".as_slice(), &message].concat()).await?,
			}
		}

		match method.as_str() {
			BATCH => answers.send([b"batch:".as_slice(), &batch].concat()).await?,
			BROKEN if batch == b"twice" => {
				answers.send(b"first".to_vec()).await?;
				answers.send(b"second".to_vec()).await?;
			}
			_ => {}
		}

		answers.finish(requests).await
	}
}

servlet! {
	/// Answers each coupled stream outside the stream library, as a servlet
	/// that breaks the shape of its method does: a request of `twice` answers
	/// two messages, and any other none, before an end with status 0.
	pub OutOfShapeServlet<CoupledCall, EnvConfig = OrdersEnv>,
	protocol: WsListener,
	handle: |_call, _frame, _ctx| async move { Ok(None) },
	duplex: |body, reply, ctx| async move {
		out_of_shape(body, reply, ctx.env_config().signer.clone()).await
	}
}

/// Answer the stream of `body` on `reply` as a servlet that breaks the shape
/// of its method, outside the stream library: its parts sign under `signer`,
/// and a request of `twice` answers two messages, and any other request
/// none, before an end with status 0.
async fn out_of_shape(
	mut body: tightbeam::transport::multiplex::StreamBody,
	mut reply: tightbeam::transport::multiplex::ReplySink,
	signer: tightbeam::crypto::sign::SigningIdentity,
) -> Result<(), TightBeamError> {
	let mut read = PartFrames::new(OUT_OF_SHAPE_CEILING);
	let mut parts = Vec::new();
	while let Some(chunk) = body.chunk().await? {
		read.extend(&chunk);
		while let Some(part) = read.next_frame()? {
			parts.push(part);
		}
	}

	let (head, requests) = parts.split_first().ok_or_else(|| unexpected("the stream carried no head"))?;
	let mut twice = false;
	for request in requests {
		twice |= StreamParts::message_of(request)?.as_deref() == Some(b"twice".as_slice());
	}

	let mut answers = StreamParts::after(head, signer, OUT_OF_SHAPE_CEILING);
	if twice {
		reply.push(&answers.message(b"first").await?).await?;
		reply.push(&answers.message(b"second").await?).await?;
	}

	reply.push(&answers.end(&Status::new(Code::Ok, "")).await?).await?;
	Ok(())
}

hive! {
	/// The hive that hosts the orders servlet over the WebSocket colony.
	pub OrdersHive,
	protocol: WsListener
}

/// What a hive of the orders servlet trusts: the identity of its vouchers,
/// and the identity of its direct callers and claim signers.
#[derive(Clone, Copy)]
struct HiveTrust<'a> {
	vouchers: &'a Identity,
	claims: &'a Identity,
}

/// The orders service of a scenario: its routes, its grants, and its hive.
trait Orders {
	/// The servlet type of the orders service.
	fn servlet() -> Result<Urn<'static>, TightBeamError> {
		Ok(WorkClient::servlet("orders")?)
	}

	/// The servlet type of the orders servlet that breaks the shape of its
	/// methods.
	fn out_of_shape() -> Result<Urn<'static>, TightBeamError> {
		Ok(WorkClient::servlet("orders-out-of-shape")?)
	}

	/// The coupler of the orders service, which trusts `callers` and pins the
	/// certificate of `answers` as the signer of each answer.
	fn orders(&self, answers: &Identity, callers: CallerTrust) -> Result<Coupler, TightBeamError>;

	/// Stage the coupled edge through `stage`, which records on `trace` and
	/// pins the answer identity of the scenario.
	fn stage(&self, trace: &TraceCollector, stage: fn(Edge, Dial)) -> Result<(), TightBeamError>;

	/// Stage the coupled edge through `stage`, which records on `trace` and
	/// pins the certificate of `answers` as the signer of each answer.
	fn stage_pinned(
		&self,
		trace: &TraceCollector,
		stage: fn(Edge, Dial),
		answers: &Identity,
	) -> Result<(), TightBeamError>;

	/// Start the hive that hosts the orders servlet, which trusts the vouchers
	/// of `trust` as its vouchers and its claims as its direct callers and
	/// claim signers.
	async fn hive_trusting(&self, trace: &TraceCollector, trust: HiveTrust<'_>) -> Result<OrdersHive, TightBeamError>;

	/// Start the hive that hosts the orders servlet, which admits its calls
	/// under `admission`.
	async fn hive_admitting(
		&self,
		trace: &TraceCollector,
		admission: AdmissionTrust,
	) -> Result<OrdersHive, TightBeamError>;

	/// Start the hive that hosts the orders servlet, which trusts the voucher
	/// and the claim identity of the scenario.
	async fn hive(&self, trace: &TraceCollector) -> Result<OrdersHive, TightBeamError>;
}

impl Orders for Coupled {
	fn orders(&self, answers: &Identity, callers: CallerTrust) -> Result<Coupler, TightBeamError> {
		let orders = Servlet::new(Self::servlet()?, answers.certificate().clone()).map_err(edge_error)?;
		let routes = Routes::new()
			.unary(GET, orders.clone(), Assurance::Vouched)
			.map_err(edge_error)?;
		let routes = routes.unary(LIST, orders.clone(), Assurance::Vouched).map_err(edge_error)?;
		let routes = routes.unary(PLACE, orders.clone(), Assurance::Signed).map_err(edge_error)?;
		let routes = routes
			.server_stream(WATCH, orders.clone(), Assurance::Vouched)
			.map_err(edge_error)?;
		let routes = routes
			.client_stream(BATCH, orders.clone(), Assurance::Vouched)
			.map_err(edge_error)?;
		let routes = routes
			.bidi_stream(CHAT, orders.clone(), Assurance::Signed)
			.map_err(edge_error)?;
		let routes = routes
			.server_stream(HOLD, orders.clone(), Assurance::Vouched)
			.map_err(edge_error)?;
		let routes = routes
			.client_stream(BROKEN, orders.clone(), Assurance::Vouched)
			.map_err(edge_error)?;
		let routes = routes
			.server_stream(FEED, orders.clone(), Assurance::Bearer)
			.map_err(edge_error)?;
		let routes = routes
			.bidi_stream(SEVERED, orders.clone(), Assurance::Vouched)
			.map_err(edge_error)?;
		let routes = routes.unary(BROWSE, orders, Assurance::Bearer).map_err(edge_error)?;
		let out_of_shape = Servlet::new(Self::out_of_shape()?, answers.certificate().clone()).map_err(edge_error)?;
		let routes = routes
			.client_stream(TWICE, out_of_shape, Assurance::Vouched)
			.map_err(edge_error)?;

		let billing = Principal::spiffe(BILLING).map_err(edge_error)?;
		let web = Principal::subject(WEB).map_err(edge_error)?;
		let mobile = Principal::spiffe(MOBILE).map_err(edge_error)?;
		let granted = [
			(&billing, GET),
			(&web, GET),
			(&web, LIST),
			(&web, PLACE),
			(&web, WATCH),
			(&web, BATCH),
			(&web, CHAT),
			(&web, HOLD),
			(&web, BROKEN),
			(&web, TWICE),
			(&web, SEVERED),
			(&mobile, BROWSE),
			(&mobile, FEED),
			(&mobile, GET),
		];
		let grants = granted.into_iter().try_fold(Grants::deny_all(), |grants, (principal, method)| {
			grants.grant(principal.clone(), method)
		});
		let grants = grants.map_err(edge_error)?;

		let coupler = self.coupler_trusting(callers, routes, grants)?;
		coupler
			.with_forwarded_metadata(["traceparent", "x-tenant-bin"])
			.map_err(edge_error)
	}

	fn stage(&self, trace: &TraceCollector, stage: fn(Edge, Dial)) -> Result<(), TightBeamError> {
		self.stage_pinned(trace, stage, &self.answers)
	}

	fn stage_pinned(
		&self,
		trace: &TraceCollector,
		stage: fn(Edge, Dial),
		answers: &Identity,
	) -> Result<(), TightBeamError> {
		let coupler = self.orders(answers, self.callers()?)?;
		self.stage_coupler(trace, stage, coupler)
	}

	async fn hive_trusting(&self, trace: &TraceCollector, trust: HiveTrust<'_>) -> Result<OrdersHive, TightBeamError> {
		let HiveTrust { vouchers, claims } = trust;
		let admission = AdmissionTrust::new()
			.with_vouchers(vouchers.trust_anchor()?)
			.with_direct_callers(claims.trust_anchor()?)
			.with_claim_signers(claims.trust_anchor()?);
		self.hive_admitting(trace, admission).await
	}

	async fn hive_admitting(
		&self,
		trace: &TraceCollector,
		admission: AdmissionTrust,
	) -> Result<OrdersHive, TightBeamError> {
		let signer = self.answers.signing_identity();
		let env = Arc::new(OrdersEnv { admission, signer, trace: trace.share(), events: self.events });
		let config = self.transport.servlet_config(Arc::clone(&env));
		let served = OrdersServlet::start(Arc::new(trace.share()), config).await?;
		let config = self.transport.servlet_config(env);
		let out_of_shape = OutOfShapeServlet::start(Arc::new(trace.share()), config).await?;

		let mut hive = OrdersHive::new(Some(self.transport.hive_config()?))?;
		let restart = |_trace| async { Err(TightBeamError::MissingConfiguration) };
		hive.register(Self::servlet()?, served, restart)?;

		let restart = |_trace| async { Err(TightBeamError::MissingConfiguration) };
		hive.register(Self::out_of_shape()?, out_of_shape, restart)?;
		hive.establish(Arc::new(trace.share())).await?;
		Ok(hive)
	}

	async fn hive(&self, trace: &TraceCollector) -> Result<OrdersHive, TightBeamError> {
		self.hive_trusting(trace, HiveTrust { vouchers: &self.vouching, claims: &self.claims })
			.await
	}
}

/// The config that grades a run with `spec` and the order of one coupled
/// call.
fn ordered_by(spec: &'static BuiltAssertSpec) -> Result<ScenarioConfig, ScenarioConfigError> {
	ScenarioConfig::builder().with_spec(spec).with_csp(CoupledCallProcess).build()
}

tb_process_spec! {
	/// One coupled call, in order: the coupler admits it, the gateway routes
	/// it, and the coupler relays its answer.
	pub CoupledCallProcess,
	events {
		observable { COUPLED_CALL_ADMITTED, events::CLUSTER_WORK_ROUTED, COUPLED_CALL_ANSWERED }
		hidden { }
	}
	states {
		Arrived => { COUPLED_CALL_ADMITTED => Admitted },
		Admitted => { events::CLUSTER_WORK_ROUTED => Routed },
		Routed => { COUPLED_CALL_ANSWERED => Answered },
		Answered => { }
	}
	terminal { Answered }
}

coupled!(VouchedEdge, VouchedGateway);

tb_assert_spec! {
	/// One vouched call: the coupler admits it as vouched, the gateway routes
	/// it, the servlet admits it as vouched, and the coupler relays the
	/// verified answer with status 0.
	pub VouchedCallSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(1), equals!("vouched")),
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(SERVED_ASSURANCE, exactly!(1), equals!("vouched")),
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32)),
			(COUPLED_CALL_REFUSED, exactly!(0))
		]
	}
}

// A stock caller with a SPIFFE certificate calls the vouched method, and reads
// the answer that the servlet signed and the coupler verified.
tb_scenario! {
	name: a_stock_caller_reaches_a_servlet_through_the_coupled_edge,
	config: ordered_by(VouchedCallSpec::latest()),
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, VouchedEdge::stage)?;
			context.gateway::<VouchedGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.billing(&cluster).await?;
			let answer = channel.call(GET, b"order-7", None).await?;
			let answer = answer.map_err(|status| (status.code(), status.message().to_owned()));
			assert_eq!(answer.as_deref(), Ok(&b"served:order-7"[..]), "the coupler MUST relay the verified answer");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(SignedEdge, SignedGateway);

tb_assert_spec! {
	/// One signed call: the coupler admits it as signed, the gateway routes
	/// it, the servlet admits it as signed after it verifies the claim the
	/// call forwards, and the coupler relays the verified answer.
	pub SignedCallSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(1), equals!("signed")),
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(SERVED_ASSURANCE, exactly!(1), equals!("signed")),
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32)),
			(COUPLED_CALL_REFUSED, exactly!(0))
		]
	}
}

// The web caller signs a claim over its call to the signed method, bound to
// its TLS certificate, and the servlet admits the call as signed.
tb_scenario! {
	name: a_signed_claim_reaches_the_servlet_as_signed,
	config: ordered_by(SignedCallSpec::latest()),
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, SignedEdge::stage)?;
			context.gateway::<SignedGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order-8").await?;

			let answer = channel.call(PLACE, b"order-8", Some(&claim)).await?.map_err(|status| status.code());
			assert_eq!(answer.as_deref(), Ok(&b"served:order-8"[..]), "a signed call MUST reach the servlet");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(WideWindowEdge, WideWindowGateway);

// A replay window past the range of the clock counts as the longest window,
// so the coupler serves a signed call under it.
tb_scenario! {
	name: a_replay_window_past_the_clock_serves_a_signed_call,
	config: ordered_by(SignedCallSpec::latest()),
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			let coupler = context.orders(&context.answers, context.callers()?)?;
			context.stage_coupler(&trace, WideWindowEdge::stage, coupler.with_replay_window(Duration::MAX))?;
			context.gateway::<WideWindowGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order-9").await?;

			let answer = channel.call(PLACE, b"order-9", Some(&claim)).await?.map_err(|status| status.code());
			assert_eq!(answer.as_deref(), Ok(&b"served:order-9"[..]), "a wide window MUST serve a signed call");

			cluster.stop();
			Ok(())
		}
	}
}

/// Declare the spec `$spec` of a call that the coupler refuses as `$label`
/// before the gateway routes it.
macro_rules! refused_spec {
	($spec:ident, $label:literal, $admitted:literal) => {
		tb_assert_spec! {
			/// A call that the coupler refuses before the gateway routes it.
			pub $spec,
			V(1,0,0): {
				mode: Accept,
				assertions: [
					(COUPLED_CALL_REFUSED, exactly!(1), equals!($label)),
					(COUPLED_CALL_ADMITTED, exactly!($admitted)),
					(events::CLUSTER_WORK_ROUTED, exactly!(0)),
					(COUPLED_CALL_ANSWERED, exactly!(0))
				]
			}
		}
	};
}

coupled!(NoCertificateEdge, NoCertificateGateway);
refused_spec!(UnauthenticatedSpec, "unauthenticated", 0);

// A caller with no client certificate connects, but its coupled call refuses
// with 16.
tb_scenario! {
	name: a_call_with_no_client_certificate_is_unauthenticated,
	spec: UnauthenticatedSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, NoCertificateEdge::stage)?;
			context.gateway::<NoCertificateGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.channel(&WorkClient::edge_of(&cluster)?, None).await?;
			channel.serving(&context.clock).await?;

			let answer = channel.call("/orders.v1.Orders/Unrouted", b"order", None).await?;
			assert_eq!(code_of(answer), Some(tonic::Code::Unauthenticated));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(NoGrantEdge, NoGrantGateway);
refused_spec!(NoGrantSpec, "denied", 0);

// The billing caller holds no grant of a vouched method, whose assurance its
// call meets, so the grants alone deny it.
tb_scenario! {
	name: a_principal_without_a_grant_is_denied,
	spec: NoGrantSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, NoGrantEdge::stage)?;
			context.gateway::<NoGrantGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.billing(&cluster).await?;
			let answer = channel.call(LIST, b"order", None).await?;
			assert_eq!(code_of(answer), Some(tonic::Code::PermissionDenied));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(UnsignedEdge, UnsignedGateway);
refused_spec!(UnsignedSpec, "denied", 0);

// The web caller holds the grant of the signed method, but its call carries
// no claim, so it proves less than the route requires.
tb_scenario! {
	name: a_vouched_call_on_a_signed_route_is_denied,
	spec: UnsignedSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, UnsignedEdge::stage)?;
			context.gateway::<UnsignedGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let answer = channel.call(PLACE, b"order", None).await?;
			assert_eq!(code_of(answer), Some(tonic::Code::PermissionDenied));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(ForeignClaimEdge, ForeignClaimGateway);
refused_spec!(ForeignClaimSpec, "claim-refused", 0);

// The billing caller forwards a claim that the web identity signed.
tb_scenario! {
	name: a_claim_of_another_principal_is_refused,
	spec: ForeignClaimSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, ForeignClaimEdge::stage)?;
			context.gateway::<ForeignClaimGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let billing = context.billing_caller();
			let channel = context.channel(&WorkClient::edge_of(&cluster)?, Some(&billing)).await?;
			channel.serving(&context.clock).await?;

			let claim = context.claim(&billing, GET, b"order").await?;
			let answer = channel.call(GET, b"order", Some(&claim)).await?;
			assert_eq!(code_of(answer), Some(tonic::Code::Unauthenticated));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(OtherBodyEdge, OtherBodyGateway);
refused_spec!(OtherBodySpec, "claim-refused", 0);

// The web caller signs its claim over one body and sends another.
tb_scenario! {
	name: a_claim_over_another_body_is_refused,
	spec: OtherBodySpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, OtherBodyEdge::stage)?;
			context.gateway::<OtherBodyGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order-1").await?;
			let answer = channel.call(PLACE, b"order-2", Some(&claim)).await?;
			assert_eq!(code_of(answer), Some(tonic::Code::Unauthenticated));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(OtherLeafEdge, OtherLeafGateway);
refused_spec!(OtherLeafSpec, "claim-refused", 0);

// The web caller signs its claim bound to another TLS certificate of its own,
// so the claim stays bound to the connection of that certificate.
tb_scenario! {
	name: a_claim_bound_to_another_certificate_is_refused,
	spec: OtherLeafSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, OtherLeafEdge::stage)?;
			context.gateway::<OtherLeafGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let elsewhere = context.caller(WEB, None);
			let claim = context.claim(&elsewhere, PLACE, b"order").await?;

			let answer = channel.call(PLACE, b"order", Some(&claim)).await?;
			assert_eq!(code_of(answer), Some(tonic::Code::Unauthenticated));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(ReplayEdge, ReplayGateway);

tb_assert_spec! {
	/// A claim sent twice: the coupler admits both calls, serves the first,
	/// and refuses the second as a replay before the gateway routes it.
	pub ReplaySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(2)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32)),
			(COUPLED_CALL_REFUSED, exactly!(1), equals!("replayed"))
		]
	}
}

// The web caller sends one signed call twice, so the second spends a claim
// that the first spent.
tb_scenario! {
	name: a_replayed_claim_is_refused,
	spec: ReplaySpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, ReplayEdge::stage)?;
			context.gateway::<ReplayGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order").await?;

			let first = channel.call(PLACE, b"order", Some(&claim)).await?;
			assert!(first.is_ok(), "the first spend of a claim MUST serve, got {first:?}");

			let replayed = channel.call(PLACE, b"order", Some(&claim)).await?;
			assert_eq!(code_of(replayed), Some(tonic::Code::Unauthenticated));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(UnroutedEdge, UnroutedGateway);
refused_spec!(UnroutedSpec, "unrouted", 0);

// An authenticated caller calls a method that the edge routes no servlet for.
tb_scenario! {
	name: an_unrouted_method_is_unimplemented,
	spec: UnroutedSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, UnroutedEdge::stage)?;
			context.gateway::<UnroutedGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.billing(&cluster).await?;
			let answer = channel.call("/orders.v1.Orders/Cancel", b"order", None).await?;
			assert_eq!(code_of(answer), Some(tonic::Code::Unimplemented));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(UnpinnedEdge, UnpinnedGateway);

tb_assert_spec! {
	/// A call whose answer the servlet signs under a key that the route does
	/// not pin: the gateway routes it, and the coupler refuses the answer.
	pub UnpinnedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(1), equals!("vouched")),
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(COUPLED_CALL_ANSWERED, exactly!(0)),
			(COUPLED_CALL_REFUSED, exactly!(1), equals!("answer-refused"))
		]
	}
}

// The route pins another signer than the one the servlet answers under.
tb_scenario! {
	name: an_answer_under_an_unpinned_signer_is_refused,
	spec: UnpinnedSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage_pinned(&trace, UnpinnedEdge::stage, &context.session)?;
			context.gateway::<UnpinnedGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.billing(&cluster).await?;
			let answer = channel.call(GET, b"order", None).await?;
			assert_eq!(code_of(answer), Some(tonic::Code::Internal));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(ConcurrentEdge, ConcurrentGateway);

tb_assert_spec! {
	/// Eight calls at once on one connection: each one is admitted, routed,
	/// served, and answered.
	pub ConcurrentSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(8)),
			(events::CLUSTER_WORK_ROUTED, exactly!(8)),
			(SERVED_ASSURANCE, exactly!(8)),
			(COUPLED_CALL_ANSWERED, exactly!(8)),
			(COUPLED_CALL_REFUSED, exactly!(0))
		]
	}
}

/// The events of the scenario of concurrent coupled calls.
static CONCURRENT_EVENTS: EventWatch = EventWatch::new();

// One connection of the billing caller carries eight calls at once, which
// the gateway multiplexes on the loopback session. The servlet holds each
// answer until it serves all eight, so every call overlaps every other.
tb_scenario! {
	name: one_connection_carries_concurrent_coupled_calls,
	config: ConcurrentSpec::latest().watched(&CONCURRENT_EVENTS),
	environment Cluster {
		context: Coupled::watched(&CONCURRENT_EVENTS),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, ConcurrentEdge::stage)?;
			context.gateway::<ConcurrentGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.billing(&cluster).await?;
			let gathered = Hold::Served(8).body();
			let calls = (0..8).map(|_| {
				let (channel, gathered) = (channel.clone(), gathered.clone());
				async move { channel.call(GET, &gathered, None).await }
			});

			let answers = futures_util::future::join_all(calls).await;
			let answers = answers.into_iter().collect::<Result<Vec<_>, _>>()?;
			assert!(answers.iter().all(Result::is_ok), "every concurrent call MUST answer, got {answers:?}");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(LaneKindEdge, LaneKindGateway);
refused_spec!(LaneKindSpec, "other-kind", 0);

// A connection whose first call opens a tunnel is a tunnel lane, so a coupled
// call on it refuses with 14.
tb_scenario! {
	name: a_coupled_call_on_a_tunnel_lane_is_unavailable,
	spec: LaneKindSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, LaneKindEdge::stage)?;
			context.gateway::<LaneKindGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let billing = context.billing_caller();
			let channel = context.channel(&WorkClient::edge_of(&cluster)?, Some(&billing)).await?;
			let mut tunnel = channel.client().await?;

			// The head of the answer of the tunnel arrives once the tunnel
			// holds the lane of the connection.
			let (_hold, waiting) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
			let requests = Request::new(tokio_stream::wrappers::ReceiverStream::new(waiting));
			let path = PathAndQuery::from_static(tightbeam_grpc::protocol::TUNNEL_PATH);
			let _tunnel = bounded(tunnel.streaming(requests, path, RawCodec)).await?.map_err(unexpected)?;

			let answer = channel.call(GET, b"order", None).await?;
			assert_eq!(code_of(answer), Some(tonic::Code::Unavailable));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(RejectedEdge, RejectedGateway);

// The vouched-call spec rejects a run whose call the coupler refuses, so the
// spec of the round trip proves the round trip.
tb_scenario! {
	name: the_vouched_call_spec_rejects_a_refused_call,
	config: VouchedCallSpec::latest().rejected(),
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, RejectedEdge::stage)?;
			context.gateway::<RejectedGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.billing(&cluster).await?;
			let answer = channel.call(PLACE, b"order", None).await?;
			assert_eq!(code_of(answer), Some(tonic::Code::PermissionDenied));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(UntrustedVoucherEdge, UntrustedVoucherGateway);

tb_assert_spec! {
	/// A call that the servlet refuses at its own admission: the coupler
	/// admits it, the servlet admits nothing, so the gateway records no
	/// served route, and the coupler answers the refusal of the gateway.
	pub ServletRefusalSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(1)),
			(events::CLUSTER_WORK_ROUTED, exactly!(0)),
			(SERVED_ASSURANCE, exactly!(0)),
			(COUPLED_CALL_ANSWERED, exactly!(0)),
			(COUPLED_CALL_REFUSED, exactly!(1), equals!("transit"))
		]
	}
}

// The servlet trusts another voucher than the coupler of the edge, so it
// admits no call that the coupler vouches for.
tb_scenario! {
	name: a_servlet_refuses_a_voucher_it_does_not_trust,
	spec: ServletRefusalSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, UntrustedVoucherEdge::stage)?;
			context.gateway::<UntrustedVoucherGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move {
			let trust = HiveTrust { vouchers: &context.session, claims: &context.claims };
			context.hive_trusting(&trace, trust).await
		}],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.billing(&cluster).await?;
			let answer = channel.call(GET, b"order", None).await?;
			assert!(answer.is_err(), "a call that the servlet refuses MUST fail, got {answer:?}");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(UntrustedClaimEdge, UntrustedClaimGateway);

// The servlet trusts another claim store than the coupler, so it refuses the
// claim that a signed call forwards, though the coupler verified it.
tb_scenario! {
	name: a_servlet_refuses_a_forwarded_claim_it_does_not_trust,
	spec: ServletRefusalSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, UntrustedClaimEdge::stage)?;
			context.gateway::<UntrustedClaimGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move {
			let trust = HiveTrust { vouchers: &context.vouching, claims: &context.session };
			context.hive_trusting(&trace, trust).await
		}],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order").await?;
			let answer = channel.call(PLACE, b"order", Some(&claim)).await?;
			assert!(answer.is_err(), "a claim that the servlet refuses MUST fail, got {answer:?}");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(CoupledLaneEdge, CoupledLaneGateway);

tb_assert_spec! {
	/// A tunnel call on a connection that carries coupled calls: the coupler
	/// answers the coupled call, and the edge refuses the tunnel because a
	/// call of the other kind holds the connection.
	pub CoupledLaneSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32)),
			(EDGE_REFUSED, exactly!(1), equals!("other-kind"))
		]
	}
}

// A tunnel call on a connection that carries coupled calls refuses with 14.
tb_scenario! {
	name: a_tunnel_call_on_a_coupled_lane_is_unavailable,
	spec: CoupledLaneSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, CoupledLaneEdge::stage)?;
			context.gateway::<CoupledLaneGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.billing(&cluster).await?;
			let answer = channel.call(GET, b"order", None).await?;
			assert!(answer.is_ok(), "the coupled call MUST answer, got {answer:?}");

			let mut tunnel = channel.client().await?;

			let (_hold, waiting) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
			let requests = Request::new(tokio_stream::wrappers::ReceiverStream::new(waiting));
			let path = PathAndQuery::from_static(tightbeam_grpc::protocol::TUNNEL_PATH);
			let refused = bounded(tunnel.streaming(requests, path, RawCodec)).await?.map(|_| ());
			assert_eq!(refused.map_err(|status| status.code()), Err(tonic::Code::Unavailable));

			cluster.stop();
			Ok(())
		}
	}
}

/// What the health check of the edge answered, which the scenario records.
const HEALTH: Urn<'static> = urn!("test", "event:edge/health");

coupled!(MutualEdge, MutualGateway);

// A mutual edge that trusts the voucher opens the loopback session and serves.
tb_scenario! {
	name: a_mutual_edge_that_trusts_the_voucher_serves,
	config: ordered_by(VouchedCallSpec::latest()),
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, MutualEdge::stage)?;
			context.mutual_gateway::<MutualGateway>(&trace, &[&context.transport, &context.session]).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.billing(&cluster).await?;
			let answer = channel.call(GET, b"order-7", None).await?.map_err(|status| status.code());
			assert_eq!(answer.as_deref(), Ok(&b"served:order-7"[..]), "the coupler MUST serve under mutual authentication");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(UntrustedSessionEdge, UntrustedSessionGateway);

tb_assert_spec! {
	/// An edge that does not trust the voucher: the gateway refuses its one
	/// loopback session, its health reads `NOT_SERVING` once the clock passed
	/// the probe of that session, and its coupled call, which the coupler
	/// admits, refuses as unavailable before the coupler sends it.
	pub NotServingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(HEALTH, exactly!(1), equals!("not-serving")),
			(COUPLED_CALL_REFUSED, exactly!(1), equals!("unavailable")),
			(COUPLED_CALL_ADMITTED, exactly!(1), equals!("vouched")),
			(events::CLUSTER_WORK_ROUTED, exactly!(0)),
			(COUPLED_SESSION_OPENED, exactly!(1)),
			(events::SESSION_CERT_REJECTED, exactly!(1))
		]
	}
}

/// The events of the scenario of an edge that refuses the voucher.
static NOT_SERVING_EVENTS: EventWatch = EventWatch::new();

// A mutual edge that refuses the voucher never serves, and its calls answer 14.
tb_scenario! {
	name: an_edge_that_refuses_the_voucher_reads_not_serving,
	config: NotServingSpec::latest().watched(&NOT_SERVING_EVENTS),
	environment Cluster {
		context: Coupled::clocked(&NOT_SERVING_EVENTS),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, UntrustedSessionEdge::stage)?;
			context.mutual_gateway::<UntrustedSessionGateway>(&trace, &[&context.transport]).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { trace, context, cluster }| async move {
			let billing = context.billing_caller();
			let channel = context.channel(&WorkClient::edge_of(&cluster)?, Some(&billing)).await?;
			let mut watched = channel.watch(&[]).await?.map_err(unexpected)?;
			let first = watched.next().await?.map_err(unexpected)?;
			assert_eq!(first, Some(NOT_SERVING.to_vec()), "a watch MUST read NOT_SERVING");

			// The probe of the session that the gateway refused passes on the
			// clock of the edge once the trail recorded that refusal.
			NOT_SERVING_EVENTS.recorded(COUPLED_SESSION_OPENED, 1).await?;
			NOT_SERVING_EVENTS.recorded(events::SESSION_CERT_REJECTED, 1).await?;
			context.clock.advance(Coupler::LIVENESS_PROBE)?;

			let health = channel.call(HEALTH_CHECK_PATH, &[], None).await?.ok();
			let read = if health.as_deref() == Some(&NOT_SERVING[..]) { "not-serving" } else { "other" };
			trace.event_with(HEALTH, &[], read)?;

			let answer = channel.call(GET, b"order", None).await?;
			assert_eq!(code_of(answer), Some(tonic::Code::Unavailable));

			cluster.stop();
			Ok(())
		}
	}
}

/// The health watches that the scenarios read.
impl StockChannel {
	/// Wait until the health watch of the edge reads `NOT_SERVING`, then
	/// `SERVING`: the loopback session ended, and a fresh one opened.
	///
	/// - On `clock`, which the scenario moves, a `SERVING` before the end moves
	///   it one [`Coupler::LIVENESS_PROBE`], so the session reads its liveness.
	///   `NOT_SERVING` moves it one [`Coupler::SESSION_BACKOFF`], and then past
	///   the first probe of the session that opens after it.
	async fn reopened(&self, clock: &ScenarioClock) -> Result<(), TightBeamError> {
		let mut answers = self.watch(&[]).await?.map_err(unexpected)?;
		let mut ended = false;
		while let Some(answer) = answers.next().await?.map_err(unexpected)? {
			match (ended, answer == SERVING) {
				(true, true) => return Ok(()),
				(false, true) => clock.advance(Coupler::LIVENESS_PROBE)?,
				(_, false) => {
					ended = true;
					clock.advance(Coupler::SESSION_BACKOFF)?;
					clock.opened().await?;
				}
			}
		}

		Err(unexpected("the watch ended before the session reopened"))
	}

	/// Every answer of a health watch of `service`, each recorded on `trace`
	/// as it comes, until the edge ends it: the answers, or the status that
	/// ended the watch. The first answer moves `clock`, the clock of the
	/// edge, by [`CLOCKED_LIMIT`].
	async fn watched(
		&self,
		service: &[u8],
		trace: &TraceCollector,
		clock: &ScenarioClock,
	) -> Result<Result<Vec<Vec<u8>>, Status>, TightBeamError> {
		let mut answers = match self.watch(service).await? {
			Ok(answers) => answers,
			Err(status) => return Ok(Err(status)),
		};

		let mut collected = Vec::new();
		loop {
			match answers.next().await? {
				Ok(Some(answer)) => {
					trace.event_with(WATCH_ANSWER, &[], hex(&answer))?;
					if collected.is_empty() {
						clock.advance(CLOCKED_LIMIT)?;
					}

					collected.push(answer);
				}
				Ok(None) => return Ok(Ok(collected)),
				Err(status) => return Ok(Err(status)),
			}
		}
	}
}

/// The call limit of the scenarios whose edge runs on a clock that they move,
/// and of each edge whose watches it bounds: past [`OPENING`] and the
/// patience of `EventWatch::recorded`, so only an advance of that clock ends
/// a call within either wait.
const CLOCKED_LIMIT: Duration = EventWatch::PATIENCE.saturating_add(Duration::from_secs(2));

coupled!(HealthWatchEdge, HealthWatchGateway);

/// A health answer that a watcher read, by its `ServingStatus`.
const WATCH_ANSWER: Urn<'static> = urn!("test", "event:caller/watch-answer");

tb_assert_spec! {
	/// Two health watches: one reads SERVING, and one of a named service
	/// reads SERVICE_UNKNOWN, and the coupler admits neither as a call.
	pub WatchSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(WATCH_ANSWER, exactly!(2)),
			(COUPLED_CALL_ADMITTED, exactly!(0)),
			(COUPLED_CALL_REFUSED, exactly!(0))
		]
	}
}

// An identified caller watches the health of a serving edge, which answers
// once, then ends the watch. A watch of a named service reads
// SERVICE_UNKNOWN.
/// The events of the scenario of a health watch that the call limit ends.
static WATCH_EVENTS: EventWatch = EventWatch::new();

tb_scenario! {
	name: a_health_watch_reads_serving_until_the_call_limit,
	config: WatchSpec::latest().watched(&WATCH_EVENTS),
	environment Cluster {
		context: Coupled::clocked(&WATCH_EVENTS),
		start: |SetupEnv { trace, context }| async move {
			context.stage_limited(&trace, HealthWatchEdge::stage, CLOCKED_LIMIT, 4, 8)?;
			context.gateway::<HealthWatchGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { trace, context, cluster }| async move {
			let channel = context.billing(&cluster).await?;
			let clock = &context.clock;
			let serving = channel.watched(&[], &trace, clock).await?.map_err(|status| status.code());
			assert_eq!(serving, Ok(vec![SERVING.to_vec()]), "a watch MUST read SERVING once");

			let unknown = channel.watched(b"\x0a\x03abc", &trace, clock).await?.map_err(|status| status.code());
			assert_eq!(unknown, Ok(vec![vec![0x08, 0x03]]), "a named service MUST read SERVICE_UNKNOWN");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(SingleSessionEdge, SingleSessionGateway);

tb_assert_spec! {
	/// A signed call that waits out its deadline for a single session, which
	/// the coupler refuses with 4 and whose claim it keeps unspent, so the
	/// slow call and the retry of the same claim both serve.
	pub QueuedClaimSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_REFUSED, exactly!(1), equals!("deadline")),
			(COUPLED_CALL_ANSWERED, exactly!(2), equals!(0u32)),
			(events::CLUSTER_WORK_ROUTED, exactly!(2))
		]
	}
}

/// The events of the scenario of a call that waits out its deadline.
static QUEUED_CLAIM_EVENTS: EventWatch = EventWatch::new();

// A signed call that times out waiting for a single session keeps its claim.
tb_scenario! {
	name: a_call_that_waits_out_its_deadline_for_the_session_keeps_its_claim,
	config: QueuedClaimSpec::latest().watched(&QUEUED_CLAIM_EVENTS),
	environment Cluster {
		context: Coupled::clocked(&QUEUED_CLAIM_EVENTS),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, SingleSessionEdge::stage)?;
			context.single_gateway::<SingleSessionGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let billing = context.billing(&cluster).await?;
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order-11").await?;

			// The servlet admits the held call while it holds the one session,
			// and answers it once the coupler refuses the queued call.
			let held = Hold::Refused(1).body();
			let slow = tokio::spawn(async move { billing.call(GET, &held, None).await });
			QUEUED_CLAIM_EVENTS.recorded(SERVED_ASSURANCE, 1).await?;

			// The queued call asks for a deadline short of the call limit of
			// the held one, and the coupler admits it before it waits for the
			// session.
			let (queued, queued_claim) = (channel.clone(), claim.clone());
			let queued = tokio::spawn(async move {
				queued.call_within(PLACE, b"order-11", &queued_claim, CLOCKED_LIMIT).await
			});
			QUEUED_CLAIM_EVENTS.recorded(COUPLED_CALL_ADMITTED, 2).await?;
			context.clock.advance(CLOCKED_LIMIT)?;
			let queued = queued.await.map_err(unexpected)??;
			assert_eq!(code_of(queued), Some(tonic::Code::DeadlineExceeded), "the queued call MUST pass its deadline");

			let slow = slow.await.map_err(unexpected)??;
			assert!(slow.is_ok(), "the held call MUST serve, got {slow:?}");

			let retried = channel.call(PLACE, b"order-11", Some(&claim)).await?;
			let retried = retried.map_err(|status| status.code());
			assert_eq!(retried.as_deref(), Ok(&b"served:order-11"[..]), "the unspent claim MUST serve on retry");

			cluster.stop();
			Ok(())
		}
	}
}

impl StockChannel {
	/// A call of `method` whose request message never arrives: the code that
	/// the edge ends it with, or `None` for an answer.
	///
	/// # Errors
	///
	/// - The errors of [`StockChannel::client`] and of [`bounded`].
	async fn withheld(&self, method: &'static str) -> Result<Option<tonic::Code>, TightBeamError> {
		let mut grpc = self.client().await?;
		let body = Request::new(stream::pending::<Vec<u8>>());
		let call = grpc.client_streaming(body, PathAndQuery::from_static(method), RawCodec);
		let answered = bounded(call).await?;
		Ok(answered.err().map(|status| status.code()))
	}
}

impl Coupled {
	/// Stage the orders edge with calls of at most `limit`, `lanes` coupled
	/// lanes, and `streams` streams on each connection and on the loopback
	/// session.
	fn stage_limited(
		&self,
		trace: &TraceCollector,
		stage: fn(Edge, Dial),
		limit: Duration,
		lanes: usize,
		streams: u32,
	) -> Result<(), TightBeamError> {
		let lanes = core::num::NonZeroUsize::new(lanes).ok_or_else(|| unexpected("no lane"))?;
		let streams = core::num::NonZeroU32::new(streams).ok_or_else(|| unexpected("no stream"))?;
		let limits = CallLimits::default()
			.with_timeout(limit)
			.with_lanes(lanes)
			.with_streams(streams);
		let coupler = self.orders(&self.answers, self.callers()?)?.with_call_limits(limits);
		self.stage_coupler(trace, stage, coupler.map_err(edge_error)?)
	}

	/// Stage the orders edge with one coupled lane and calls of at most
	/// [`CLOCKED_LIMIT`].
	fn stage_withheld(&self, trace: &TraceCollector, stage: fn(Edge, Dial)) -> Result<(), TightBeamError> {
		self.stage_limited(trace, stage, CLOCKED_LIMIT, 1, 2)
	}
}

coupled!(WithheldEdge, WithheldGateway);

tb_assert_spec! {
	/// A granted call that withholds its body: its head opens it, and it ends
	/// at its deadline, before the coupler admits it.
	pub WithheldBodySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_OPENED, exactly!(1), equals!(GET)),
			(COUPLED_CALL_REFUSED, exactly!(1), equals!("deadline")),
			(COUPLED_CALL_ADMITTED, exactly!(0))
		]
	}
}

/// The events of the scenario of a call that withholds its body.
static WITHHELD_BODY_EVENTS: EventWatch = EventWatch::new();

// A granted caller that never sends its body holds its lane until its deadline.
tb_scenario! {
	name: a_call_that_withholds_its_body_ends_at_its_deadline,
	config: WithheldBodySpec::latest().watched(&WITHHELD_BODY_EVENTS),
	environment Cluster {
		context: Coupled::clocked(&WITHHELD_BODY_EVENTS),
		start: |SetupEnv { trace, context }| async move {
			context.stage_withheld(&trace, WithheldEdge::stage)?;
			context.gateway::<WithheldGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let billing = context.billing(&cluster).await?;
			let withheld = tokio::spawn(async move { billing.withheld(GET).await });
			WITHHELD_BODY_EVENTS.recorded(COUPLED_CALL_OPENED, 1).await?;
			context.clock.advance(CLOCKED_LIMIT)?;
			let ended = withheld.await.map_err(unexpected)??;
			assert_eq!(ended, Some(tonic::Code::DeadlineExceeded), "the edge MUST end the call at its deadline");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(DeniedHeadEdge, DeniedHeadGateway);

tb_assert_spec! {
	/// A call that no grant names refuses on its head, before its body.
	pub DeniedHeadSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_REFUSED, exactly!(1), equals!("denied")),
			(COUPLED_CALL_ADMITTED, exactly!(0))
		]
	}
}

// The billing caller holds no grant for `List`, so its call takes no lane.
tb_scenario! {
	name: a_call_that_no_grant_names_refuses_before_its_body,
	spec: DeniedHeadSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage_withheld(&trace, DeniedHeadEdge::stage)?;
			context.gateway::<DeniedHeadGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let billing = context.billing(&cluster).await?;
			let ended = billing.withheld(LIST).await?;
			assert_eq!(ended, Some(tonic::Code::PermissionDenied), "the edge MUST refuse the head");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(MidExchangeEdge, MidExchangeGateway);

tb_assert_spec! {
	/// A call that ends at its deadline mid-exchange on a single session
	/// leaves no reply for the next call to read, so the next call reads its
	/// own answer.
	pub MidExchangeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_REFUSED, exactly!(1), equals!("deadline")),
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32))
		]
	}
}

/// The events of the scenario of a call that ends mid-exchange.
static MID_EXCHANGE_EVENTS: EventWatch = EventWatch::new();

// A call that passes its deadline while it holds a single session.
tb_scenario! {
	name: a_call_that_ends_mid_exchange_leaves_no_stale_reply,
	config: MidExchangeSpec::latest().watched(&MID_EXCHANGE_EVENTS),
	environment Cluster {
		context: Coupled::clocked(&MID_EXCHANGE_EVENTS),
		start: |SetupEnv { trace, context }| async move {
			context.stage_limited(&trace, MidExchangeEdge::stage, CLOCKED_LIMIT, 4, 8)?;
			context.single_gateway::<MidExchangeGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let billing = context.billing(&cluster).await?;
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let held = Hold::Refused(1).body();
			let claim = context.claim(&web, PLACE, &held).await?;

			// The servlet admits the held call, so its frame left the session,
			// and holds the answer past the deadline of the call.
			let expiring = (channel.clone(), held.clone(), claim.clone());
			let expired = tokio::spawn(async move {
				let (channel, held, claim) = expiring;
				channel.call(PLACE, &held, Some(&claim)).await
			});
			MID_EXCHANGE_EVENTS.recorded(SERVED_ASSURANCE, 1).await?;
			context.clock.advance(CLOCKED_LIMIT)?;
			let expired = expired.await.map_err(unexpected)??;
			assert_eq!(code_of(expired), Some(tonic::Code::DeadlineExceeded), "the held call MUST pass its deadline");

			// The session that the expired call left mid-exchange ends, so the
			// health of the edge reads NOT_SERVING, then SERVING once a fresh
			// session opens.
			let clock = &context.clock;
			billing.reopened(clock).await?;

			let answer = billing.call(GET, b"order-13", None).await?;
			let answer = answer.map_err(|status| status.code());
			assert_eq!(answer.as_deref(), Ok(&b"served:order-13"[..]), "the next call MUST read its own answer");

			cluster.stop();
			Ok(())
		}
	}
}

/// The messages that `answer` read, as text, or its status code.
fn read(answer: Result<Vec<Vec<u8>>, Status>) -> Result<Vec<String>, tonic::Code> {
	let answer = answer.map_err(|status| status.code())?;
	let text = answer.iter().map(|message| String::from_utf8_lossy(message).into_owned());
	Ok(text.collect())
}

tb_assert_spec! {
	/// One stream that the coupler admits, the gateway routes, and the coupler
	/// answers with status 0.
	pub StreamSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(1)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(SERVED_DEADLINE, exactly!(1), equals!("default")),
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32)),
			(COUPLED_CALL_REFUSED, exactly!(0))
		]
	}
}

coupled!(WatchEdge, WatchGateway);

/// The events of the scenario of a server stream.
static SERVER_STREAM_EVENTS: EventWatch = EventWatch::new();

// A server stream: one request, and each message that the servlet answers.
tb_scenario! {
	name: a_server_stream_relays_each_message_of_the_servlet,
	config: StreamSpec::latest().watched(&SERVER_STREAM_EVENTS),
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, WatchEdge::stage)?;
			context.gateway::<WatchGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let answer = read(channel.stream(WATCH, &[b"order-1"], None).await?);
			let watched = ["watch:order-1:0", "watch:order-1:1", "watch:order-1:2"].map(String::from);
			assert_eq!(answer, Ok(watched.to_vec()), "each message of the servlet MUST reach the caller in order");

			SERVER_STREAM_EVENTS.recorded(events::CLUSTER_WORK_ROUTED, 1).await?;
			cluster.stop();
			Ok(())
		}
	}
}

coupled!(BatchEdge, BatchGateway);

/// The events of the scenario of a client stream.
static CLIENT_STREAM_EVENTS: EventWatch = EventWatch::new();

// A client stream: each request reaches the servlet, which answers once.
tb_scenario! {
	name: a_client_stream_answers_once,
	config: StreamSpec::latest().watched(&CLIENT_STREAM_EVENTS),
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, BatchEdge::stage)?;
			context.gateway::<BatchGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let answer = read(channel.stream(BATCH, &[b"a", b"b", b"c"], None).await?);
			assert_eq!(answer, Ok(vec!["batch:abc".to_owned()]), "the servlet MUST read every request");

			CLIENT_STREAM_EVENTS.recorded(events::CLUSTER_WORK_ROUTED, 1).await?;
			cluster.stop();
			Ok(())
		}
	}
}

coupled!(ChatEdge, ChatGateway);

tb_assert_spec! {
	/// One signed bidirectional stream: the coupler and the servlet both admit
	/// it as signed.
	pub SignedStreamSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(1), equals!("signed")),
			(SERVED_ASSURANCE, exactly!(1), equals!("signed")),
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32))
		]
	}
}

/// A message larger than one chunk of a mux stream.
const LARGE: usize = 100 * 1024;

/// The events of the scenario of a signed bidi stream.
static SIGNED_STREAM_EVENTS: EventWatch = EventWatch::new();

// A bidirectional stream under a claim over an empty body: each echo arrives
// before the next request leaves, and a message larger than a chunk of the
// mux stream crosses whole.
tb_scenario! {
	name: a_signed_bidi_stream_echoes_each_message_before_the_next,
	config: SignedStreamSpec::latest().watched(&SIGNED_STREAM_EVENTS),
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, ChatEdge::stage)?;
			context.gateway::<ChatGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = context.claim(&web, CHAT, b"").await?;
			let mut grpc = channel.client().await?;

			let (requests, queued) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
			let mut request = Request::new(ReceiverStream::new(queued));

			claim.attach(request.metadata_mut());

			let response = bounded(grpc.streaming(request, PathAndQuery::from_static(CHAT), RawCodec)).await?;
			let mut answers = response.map_err(unexpected)?.into_inner();

			requests.send(b"x".to_vec()).await.map_err(unexpected)?;

			let first = bounded(answers.message()).await?.map_err(unexpected)?;
			assert_eq!(first.as_deref(), Some(&b"chat:x"[..]), "the first echo MUST arrive before the next request");

			requests.send(vec![7; LARGE]).await.map_err(unexpected)?;

			let large = bounded(answers.message()).await?.map_err(unexpected)?;
			assert_eq!(large.map(|message| message.len()), Some(LARGE + 5), "a large message MUST cross whole");

			drop(requests);

			let end = bounded(answers.message()).await?.map_err(unexpected)?;
			assert!(end.is_none(), "the answer MUST end once the requests end");

			SIGNED_STREAM_EVENTS.recorded(events::CLUSTER_WORK_ROUTED, 1).await?;
			cluster.stop();
			Ok(())
		}
	}
}

coupled!(FailedStreamEdge, FailedStreamGateway);

tb_assert_spec! {
	/// A stream that the servlet fails: the coupler answers its status.
	pub FailedStreamSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(9u32)),
			(COUPLED_CALL_REFUSED, exactly!(0))
		]
	}
}

// The servlet fails a stream, and the caller reads its details.
tb_scenario! {
	name: a_failed_stream_carries_its_details_to_the_caller,
	spec: FailedStreamSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, FailedStreamEdge::stage)?;
			context.gateway::<FailedStreamGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = context.claim(&web, CHAT, b"").await?;
			let failed = channel.stream(CHAT, &[FAILING], Some(&claim)).await?;
			let status = failed.err().ok_or_else(|| unexpected("the servlet answered a failing stream"))?;
			assert_eq!(status.code(), tonic::Code::FailedPrecondition);
			assert_eq!(status.details(), DETAILS, "the details MUST reach the caller");

			cluster.stop();
			Ok(())
		}
	}
}

/// A spec of `count` streams that the coupler refuses with `label`.
macro_rules! refused_streams {
	($spec:ident, $label:literal, $count:literal) => {
		tb_assert_spec! {
			/// Streams that the coupler refuses with one fault.
			pub $spec,
			V(1,0,0): {
				mode: Accept,
				assertions: [
					(COUPLED_CALL_REFUSED, exactly!($count), equals!($label)),
					(COUPLED_CALL_ANSWERED, exactly!(0))
				]
			}
		}
	};
}

coupled!(SingleStreamEdge, SingleStreamGateway);
refused_streams!(SingleStreamSpec, "unavailable", 1);

// A session that runs one call at a time carries no stream.
tb_scenario! {
	name: a_stream_on_a_single_session_is_unavailable,
	spec: SingleStreamSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, SingleStreamEdge::stage)?;
			context.single_gateway::<SingleStreamGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let answer = read(channel.stream(WATCH, &[b"order-1"], None).await?);
			assert_eq!(answer, Err(tonic::Code::Unavailable));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(UnaryEdgeStreamEdge, UnaryEdgeStreamGateway);

tb_assert_spec! {
	/// A stream on a gateway whose edge plane refuses stream opens: the
	/// gateway refuses the open, and the coupler answers its status.
	pub UnaryEdgeStreamSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_EDGE_REFUSED, exactly!(1)),
			(COUPLED_CALL_REFUSED, exactly!(1), equals!("transit")),
			(COUPLED_CALL_ANSWERED, exactly!(0))
		]
	}
}

// A coupler with stream routes needs an edge plane that opens streams. On one
// that does not, a stream ends with the refusal of the gateway.
tb_scenario! {
	name: a_stream_on_an_edge_plane_without_streams_is_refused,
	spec: UnaryEdgeStreamSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, UnaryEdgeStreamEdge::stage)?;
			context.unary_gateway::<UnaryEdgeStreamGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let answer = read(channel.stream(WATCH, &[b"order-1"], None).await?);
			assert_eq!(answer, Err(tonic::Code::PermissionDenied));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(UnpinnedStreamEdge, UnpinnedStreamGateway);
refused_streams!(UnpinnedStreamSpec, "answer-refused", 1);

// The route pins another signer than the one the servlet answers parts under.
tb_scenario! {
	name: a_stream_answer_under_an_unpinned_signer_is_refused,
	spec: UnpinnedStreamSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage_pinned(&trace, UnpinnedStreamEdge::stage, &context.session)?;
			context.gateway::<UnpinnedStreamGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let answer = read(channel.stream(WATCH, &[b"order-1"], None).await?);
			assert_eq!(answer, Err(tonic::Code::Internal));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(ShapeEdge, ShapeGateway);
refused_streams!(ShapeSpec, "shape", 2);

// A server stream takes exactly one request, so a second one, or none, ends
// the call.
tb_scenario! {
	name: a_server_stream_with_two_requests_or_none_is_refused,
	spec: ShapeSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, ShapeEdge::stage)?;
			context.gateway::<ShapeGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let twice = read(channel.stream(WATCH, &[b"a", b"b"], None).await?);
			assert_eq!(twice.map(|_| ()), Err(tonic::Code::Unimplemented));

			let none = read(channel.stream(WATCH, &[], None).await?);
			assert_eq!(none.map(|_| ()), Err(tonic::Code::Unimplemented));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(AnswerShapeEdge, AnswerShapeGateway);
refused_streams!(AnswerShapeSpec, "transit", 2);

// A client stream answers exactly one message. The head tells the stream
// library of the servlet so, and it refuses a second answer, or an end with
// none, which ends the stream with 12.
tb_scenario! {
	name: a_servlet_cannot_answer_a_client_stream_twice_or_never,
	spec: AnswerShapeSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, AnswerShapeEdge::stage)?;
			context.gateway::<AnswerShapeGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let twice = read(channel.stream(BROKEN, &[b"twice"], None).await?);
			assert_eq!(twice.map(|_| ()), Err(tonic::Code::Unimplemented));

			let never = read(channel.stream(BROKEN, &[b"never"], None).await?);
			assert_eq!(never.map(|_| ()), Err(tonic::Code::Unimplemented));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(OutOfShapeEdge, OutOfShapeGateway);
refused_streams!(OutOfShapeSpec, "answer-shape", 2);

// A servlet outside the stream library answers a client stream twice, or ends
// it with no answer. The coupler counts the answers itself, and ends each
// stream with 12.
tb_scenario! {
	name: the_coupler_refuses_an_answer_out_of_the_shape_of_its_method,
	spec: OutOfShapeSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, OutOfShapeEdge::stage)?;
			context.gateway::<OutOfShapeGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let twice = read(channel.stream(TWICE, &[b"twice"], None).await?);
			assert_eq!(twice.map(|_| ()), Err(tonic::Code::Unimplemented), "a second answer MUST end the stream");

			let never = read(channel.stream(TWICE, &[b"never"], None).await?);
			assert_eq!(never.map(|_| ()), Err(tonic::Code::Unimplemented), "an end with no answer MUST end the stream");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(StalledEdge, StalledGateway);

tb_assert_spec! {
	/// A stream that stalls: it ends at its deadline, a second stream refuses
	/// while the first holds the one relay permit, and a third one serves
	/// after the deadline.
	pub StalledSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_REFUSED, exactly!(2)),
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32))
		]
	}
}

/// The events of the scenario of a stalled stream.
static STALLED_EVENTS: EventWatch = EventWatch::new();

// A stream whose servlet stalls, and whose caller never reads, holds its relay
// until its deadline and no longer.
tb_scenario! {
	name: a_stalled_stream_frees_its_relay_at_its_deadline,
	config: StalledSpec::latest().watched(&STALLED_EVENTS),
	environment Cluster {
		context: Coupled::clocked(&STALLED_EVENTS),
		start: |SetupEnv { trace, context }| async move {
			context.stage_limited(&trace, StalledEdge::stage, CLOCKED_LIMIT, 4, 2)?;
			context.gateway::<StalledGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel: stalled, .. } = context.web(&cluster).await?;
			let mut grpc = stalled.client().await?;
			let request = Request::new(stream::iter([Hold::Refused(2).body()]));
			let holding = bounded(grpc.streaming(request, PathAndQuery::from_static(HOLD), RawCodec)).await?;
			let _unread = holding.map_err(unexpected)?;

			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let held = read(channel.stream(WATCH, &[b"order-1"], None).await?);
			assert_eq!(held, Err(tonic::Code::ResourceExhausted), "the stalled stream MUST hold the one relay permit");

			context.clock.advance(CLOCKED_LIMIT)?;
			STALLED_EVENTS.recorded(COUPLED_CALL_REFUSED, 2).await?;

			// The advance passes the idle deadline of each connection too, so
			// the freed call opens a connection of its own.
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let freed = read(channel.stream(WATCH, &[b"order-2"], None).await?);
			assert_eq!(freed.map(|answers| answers.len()), Ok(3), "the deadline MUST free the stalled stream");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	/// A coupler of one stream is refused for its stream routes, and serves
	/// once it routes unary methods alone.
	pub OneStreamSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32))
		]
	}
}

coupled!(OneStreamEdge, OneStreamGateway);

impl Coupled {
	/// The coupler that routes `Get` alone to the orders servlet, and grants
	/// it to the billing caller.
	fn unary_orders(&self) -> Result<Coupler, TightBeamError> {
		let orders = Servlet::new(Self::servlet()?, self.answers.certificate().clone()).map_err(edge_error)?;
		let routes = Routes::new().unary(GET, orders, Assurance::Vouched).map_err(edge_error)?;
		let billing = Principal::spiffe(BILLING).map_err(edge_error)?;
		let grants = Grants::deny_all().grant(billing, GET).map_err(edge_error)?;
		self.coupler(routes, grants)
	}
}

// An open stream would hold the one stream of a session of one stream, so
// unary calls would starve: a coupler with stream routes refuses those
// limits, and one that routes unary methods alone takes them.
tb_scenario! {
	name: a_coupler_of_one_stream_routes_no_stream,
	spec: OneStreamSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			let one = CallLimits::default().with_streams(core::num::NonZeroU32::MIN);
			let streamed = context.orders(&context.answers, context.callers()?)?.with_call_limits(one);
			assert!(matches!(streamed, Err(CoupleError::Streams)), "a stream route MUST refuse one stream");

			let unary = context.unary_orders()?.with_call_limits(one).map_err(edge_error)?;
			context.stage_coupler(&trace, OneStreamEdge::stage, unary)?;
			context.gateway::<OneStreamGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.billing(&cluster).await?;
			let answer = channel.call(GET, b"order-70", None).await?.map_err(|status| status.code());
			assert_eq!(answer, Ok(b"served:order-70".to_vec()), "a unary coupler MUST serve under one stream");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(WithheldStreamEdge, WithheldStreamGateway);
refused_streams!(WithheldStreamSpec, "deadline", 1);

/// The events of the scenario of a stream that withholds its requests.
static WITHHELD_STREAM_EVENTS: EventWatch = EventWatch::new();

// A caller that opens a client stream and never sends ends at its deadline.
tb_scenario! {
	name: a_stream_that_withholds_its_requests_ends_at_its_deadline,
	config: WithheldStreamSpec::latest().watched(&WITHHELD_STREAM_EVENTS),
	environment Cluster {
		context: Coupled::clocked(&WITHHELD_STREAM_EVENTS),
		start: |SetupEnv { trace, context }| async move {
			context.stage_withheld(&trace, WithheldStreamEdge::stage)?;
			context.gateway::<WithheldStreamGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let withheld = tokio::spawn(async move { channel.withheld(BATCH).await });
			WITHHELD_STREAM_EVENTS.recorded(COUPLED_CALL_ADMITTED, 1).await?;
			context.clock.advance(CLOCKED_LIMIT)?;
			let ended = withheld.await.map_err(unexpected)??;
			assert_eq!(ended, Some(tonic::Code::DeadlineExceeded), "the relay MUST end the stream at its deadline");

			cluster.stop();
			Ok(())
		}
	}
}

impl StockChannel {
	/// A unary call of `method` with `body`, the deadline [`CALLER_TIMEOUT`],
	/// the metadata `traceparent`, `x-tenant-bin`, and `x-secret`, sent and
	/// accepted in gzip when `gzip` is set: the body of the answer and its
	/// `grpc-encoding`, or its status.
	async fn traced_call(
		&self,
		method: &'static str,
		body: &[u8],
		gzip: bool,
	) -> Result<Result<(Vec<u8>, Option<String>), Status>, TightBeamError> {
		let mut grpc = self.client().await?;
		if gzip {
			grpc = grpc
				.send_compressed(CompressionEncoding::Gzip)
				.accept_compressed(CompressionEncoding::Gzip);
		}

		let mut request = Request::new(body.to_vec());
		request.set_timeout(CALLER_TIMEOUT);

		let metadata = request.metadata_mut();
		metadata.insert("traceparent", MetadataValue::from_static(TRACEPARENT));
		metadata.insert_bin("x-tenant-bin", MetadataValue::from_bytes(&TENANT));
		metadata.insert("x-secret", MetadataValue::from_static("not-forwarded"));

		let path = PathAndQuery::from_static(method);
		let answered = bounded(grpc.unary(request, path, RawCodec)).await?;
		Ok(answered.map(|answer| {
			let encoding = answer.metadata().get("grpc-encoding").and_then(|value| value.to_str().ok());
			let encoding = encoding.map(str::to_owned);
			(answer.into_inner(), encoding)
		}))
	}
}

tb_assert_spec! {
	/// A traced call: the servlet reads the trace context, the binary tenant,
	/// two entries and no third, and a deadline within the one of the caller.
	pub TracedCallSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(SERVED_TRACE, exactly!(1), equals!(TRACEPARENT)),
			(SERVED_TENANT, exactly!(1), equals!("00ff")),
			(SERVED_METADATA, exactly!(1), equals!(2u32)),
			(SERVED_DEADLINE, exactly!(1), equals!("bounded")),
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32))
		]
	}
}

coupled!(TracedEdge, TracedGateway);

// A call reaches the servlet with its forwarded metadata alone, and with its
// own deadline.
tb_scenario! {
	name: a_call_carries_its_forwarded_metadata_and_deadline_to_the_servlet,
	spec: TracedCallSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, TracedEdge::stage)?;
			context.gateway::<TracedGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.billing(&cluster).await?;
			let answer = channel.traced_call(GET, b"order-14", false).await?.map_err(|status| status.code());
			assert_eq!(answer.map(|(body, _)| body).as_deref(), Ok(&b"served:order-14"[..]));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(GzipEdge, GzipGateway);

tb_assert_spec! {
	/// A compressed call that the coupler answers, and a compressed bomb that
	/// tonic refuses before the coupler admits it.
	pub GzipSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(1)),
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32)),
			(COUPLED_CALL_REFUSED, exactly!(1), equals!("refused"))
		]
	}
}

/// A body that gzip shrinks to a few kilobytes, past the envelope ceiling of
/// the edge.
const BOMB: usize = 4 * 1024 * 1024;

// The edge answers gzip in gzip, and refuses a body that decompresses past
// its ceiling with 8.
tb_scenario! {
	name: a_compressed_call_is_answered_compressed_and_a_bomb_is_refused,
	spec: GzipSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, GzipEdge::stage)?;
			context.gateway::<GzipGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.billing(&cluster).await?;
			let answer = channel.traced_call(GET, b"order-16", true).await?.map_err(|status| status.code());
			assert_eq!(answer.map(|(_, encoding)| encoding), Ok(Some("gzip".to_owned())), "the answer MUST be gzip");

			let bomb = channel.traced_call(GET, &vec![0; BOMB], true).await?;
			assert_eq!(bomb.map(|_| ()).map_err(|status| status.code()), Err(tonic::Code::ResourceExhausted));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(CeilingStreamEdge, CeilingStreamGateway);
refused_streams!(CeilingStreamSpec, "refused", 1);

// A stream message one byte past the envelope ceiling of the edge ends the
// stream with the code that tonic refuses it with.
tb_scenario! {
	name: a_stream_message_past_the_ceiling_reads_the_code_of_tonic,
	spec: CeilingStreamSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, CeilingStreamEdge::stage)?;
			context.gateway::<CeilingStreamGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let past = vec![0; TransportLimits::default().max_envelope() + 1];
			let answer = read(channel.stream(BATCH, &[&past], None).await?);
			assert_eq!(answer, Err(tonic::Code::OutOfRange), "the caller MUST read the code of tonic");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(ResetCallEdge, ResetCallGateway);

tb_assert_spec! {
	/// A unary call that its caller resets before its message: the coupler
	/// opens it, and the trail records its end as cancelled.
	pub ResetCallSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_OPENED, exactly!(1)),
			(COUPLED_CALL_REFUSED, exactly!(1), equals!("cancelled")),
			(COUPLED_CALL_ANSWERED, exactly!(0))
		]
	}
}

/// The events of the scenario of a unary call that its caller resets.
static RESET_CALL_EVENTS: EventWatch = EventWatch::new();

// A caller that resets its unary call once the coupler opened it, before its
// message, ends the call as cancelled.
tb_scenario! {
	name: a_unary_call_that_its_caller_resets_before_its_message_ends_as_cancelled,
	config: ResetCallSpec::latest().watched(&RESET_CALL_EVENTS),
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, ResetCallEdge::stage)?;
			context.gateway::<ResetCallGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			context.billing(&cluster).await?;
			let edge = WorkClient::edge_of(&cluster)?;
			let billing = context.billing_caller();
			let mut caller = H2Tunnel::connect_tls(edge.to_string(), &[], &context.tls, Some(&billing)).await?;

			let head = caller.head(http::Method::POST, &PathAndQuery::from_static(GET), "application/grpc")?;
			let (_response, mut requests) = caller.open(head)?;
			RESET_CALL_EVENTS.recorded(COUPLED_CALL_OPENED, 1).await?;
			requests.send_reset(h2::Reason::CANCEL);

			RESET_CALL_EVENTS.recorded(COUPLED_CALL_REFUSED, 1).await?;
			cluster.stop();
			Ok(())
		}
	}
}

coupled!(DetailsEdge, DetailsGateway);

tb_assert_spec! {
	/// A call that the servlet fails: the coupler answers its status.
	pub FailedCallSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(9u32))
		]
	}
}

// The servlet fails a call, and the caller reads its details.
tb_scenario! {
	name: a_failed_call_carries_its_details_to_the_caller,
	spec: FailedCallSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, DetailsEdge::stage)?;
			context.gateway::<DetailsGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.billing(&cluster).await?;
			let failed = channel.traced_call(GET, FAILING, false).await?;
			let status = failed.err().ok_or_else(|| unexpected("the servlet answered a failing call"))?;
			assert_eq!(status.code(), tonic::Code::FailedPrecondition);
			assert_eq!(status.details(), DETAILS, "the details MUST reach the caller");

			cluster.stop();
			Ok(())
		}
	}
}

impl Coupled {
	/// The direct callers of a hive that trusts two identities: the claim
	/// identity, which signs each head, and the session identity.
	fn two_direct_callers(&self) -> Result<AdmissionTrust, TightBeamError> {
		let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
		let builder = builder.with_certificate(self.claims.certificate().clone())?;
		let builder = builder.with_certificate(self.session.certificate().clone())?;
		let direct: Arc<dyn CertificateTrust> = Arc::new(builder.build());
		let admission = AdmissionTrust::new().with_vouchers(self.vouching.trust_anchor()?);
		Ok(admission
			.with_direct_callers(direct)
			.with_claim_signers(self.claims.trust_anchor()?))
	}
}

coupled!(DirectStreamEdge, DirectStreamGateway);

tb_assert_spec! {
	/// Two direct streams whose heads the servlet admits from its direct
	/// caller.
	pub DirectStreamSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(SERVED_ASSURANCE, exactly!(2), equals!("signed"))
		]
	}
}

// A peer that holds a trusted head key signs a later part under another key
// that the servlet also trusts. The servlet answers the part under the key of
// its head, and refuses the part under the other key.
tb_scenario! {
	name: a_stream_part_under_another_key_than_its_head_is_refused,
	spec: DirectStreamSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, DirectStreamEdge::stage)?;
			context.gateway::<DirectStreamGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive_admitting(&trace, context.two_direct_callers()?).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let caller = context.claims.signing_identity();
			let chat = DirectRoute { servlet: Coupled::servlet()?, method: CHAT };
			let signers = StreamSigners { head: &caller, parts: &caller };
			let answered = context.direct_stream(cluster.addr(), chat.clone(), signers).await?;
			let answered = answered.map_err(|error| error.transit_status());
			assert_eq!(answered, Ok(Some(b"chat:hello".to_vec())), "a part under the key of its head MUST be answered");

			let other = context.session.signing_identity();
			let forging = StreamSigners { head: &caller, parts: &other };
			let forged = context.direct_stream(cluster.addr(), chat, forging).await?;
			let refused = forged.err().and_then(|error| error.transit_status());
			assert_eq!(refused, Some(TransitStatus::Unauthenticated), "a part under another key MUST be refused");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(SeveredEdge, SeveredGateway);

tb_assert_spec! {
	/// A direct stream whose caller leaves while the servlet answers: a push
	/// of the answer fails, and the send after it refuses as unavailable.
	pub SeveredSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(LATE_SEND, exactly!(1), equals!("Some(Unavailable)"))
		]
	}
}

/// The events of the scenario of an answer whose caller leaves.
static SEVERED_EVENTS: EventWatch = EventWatch::new();

// The caller reads the first chunk of the answer and leaves, so a push of the
// answer of the servlet fails, and its next send refuses with 14.
tb_scenario! {
	name: a_send_after_a_failed_push_of_an_answer_refuses_as_unavailable,
	config: SeveredSpec::latest().watched(&SEVERED_EVENTS),
	environment Cluster {
		context: Coupled::watched(&SEVERED_EVENTS),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, SeveredEdge::stage)?;
			context.gateway::<SeveredGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let caller = context.claims.signing_identity();
			let route = DirectRoute { servlet: Coupled::servlet()?, method: SEVERED };
			let offer = tightbeam::transport::handshake::negotiation::TransportOffer::mux(4);
			let signers = StreamSigners { head: &caller, parts: &caller };
			let mut answer = context.direct_answer(cluster.addr(), route, signers, offer).await?;
			answer.arrived().await?;
			drop(answer);

			SEVERED_EVENTS.recorded(LATE_SEND, 1).await?;
			cluster.stop();
			Ok(())
		}
	}
}

coupled!(DroppedStreamEdge, DroppedStreamGateway);

tb_assert_spec! {
	/// Coupled streams whose caller drops each response while the relay holds
	/// an answer for it, each before a stream that the servlet serves: the
	/// trail records the end of each dropped one as cancelled.
	pub DroppedStreamSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_REFUSED, exactly!(16), equals!("cancelled")),
			(COUPLED_CALL_ANSWERED, exactly!(16), equals!(0u32))
		]
	}
}

/// The flow-control window of an HTTP/2 stream and of its connection, which a
/// raw caller never widens (RFC 9113 section 6.9.2).
const H2_WINDOW: usize = 65_535;

/// The events of the scenario of streams whose caller drops each response.
static DROPPED_STREAM_EVENTS: EventWatch = EventWatch::new();

// Each of 16 callers reads its answer until it fills the window of its
// connection, then drops the response. A served stream after each one keeps
// the route of the servlet live, because the gateway abandons a route after
// five failed streams in a row.
tb_scenario! {
	name: a_stream_whose_caller_drops_its_response_ends_as_cancelled,
	config: DroppedStreamSpec::latest().watched(&DROPPED_STREAM_EVENTS),
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, DroppedStreamEdge::stage)?;
			context.gateway::<DroppedStreamGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { leaf, channel } = context.web(&cluster).await?;
			let edge = WorkClient::edge_of(&cluster)?;
			for _ in 0..16 {
				let mut caller = H2Tunnel::connect_tls(edge.to_string(), &[], &context.tls, Some(&leaf)).await?;
				let head = caller.head(http::Method::POST, &PathAndQuery::from_static(SEVERED), "application/grpc")?;
				let mut answer = caller.call(head, None).await?.into_body();
				let filled = async {
					let mut read = 0;
					while read < H2_WINDOW {
						let chunk = answer.data().await.ok_or_else(|| unexpected("the answer ended"))?;
						read += chunk.map_err(unexpected)?.len();
					}

					Ok::<_, TightBeamError>(())
				};

				bounded(filled).await??;
				drop((answer, caller));

				let served = read(channel.stream(WATCH, &[b"order-1"], None).await?);
				assert_eq!(served.map(|watched| watched.len()), Ok(3), "the servlet MUST serve the next stream");
			}

			DROPPED_STREAM_EVENTS.recorded(COUPLED_CALL_REFUSED, 16).await?;
			cluster.stop();
			Ok(())
		}
	}
}

impl Coupled {
	/// Stage the orders edge, which trusts `callers`, through `stage`.
	fn stage_trusting(
		&self,
		trace: &TraceCollector,
		stage: fn(Edge, Dial),
		callers: CallerTrust,
	) -> Result<(), TightBeamError> {
		let coupler = self.orders(&self.answers, callers)?;
		self.stage_coupler(trace, stage, coupler)
	}
}

/// `pem`, percent-encoded as Envoy forwards it.
fn percent(pem: &str) -> String {
	pem.bytes()
		.map(|byte| match byte {
			b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => char::from(byte).to_string(),
			byte => format!("%{byte:02X}"),
		})
		.collect()
}

/// The XFCC value of a proxy that forwards the certificate of `caller`, as
/// Envoy writes it.
fn xfcc(caller: &TlsLeaf) -> String {
	let encoded = percent(caller.certificate_pem());
	format!("By=spiffe://acme/edge;Hash=00;Cert=\"{encoded}\";Subject=\"CN=web,O=acme\"")
}

/// The XFCC value of a proxy that forwards the certificate and the chain of
/// `caller`, as Envoy writes it.
fn xfcc_chain(caller: &TlsLeaf) -> String {
	let (cert, chain) = (percent(caller.certificate_pem()), percent(caller.chain_pem()));
	format!("By=spiffe://acme/edge;Hash=00;Cert=\"{cert}\";Chain=\"{chain}\";Subject=\"CN=web,O=acme\"")
}

coupled!(ForwardedEdge, ForwardedGateway);

tb_assert_spec! {
	/// Calls through a pinned proxy.
	///
	/// - The servlet admits the forwarded web caller twice and a bearer caller
	///   once.
	/// - The coupler refuses five calls: one with no forwarded chain and no
	///   token, a chain of another root, an injected quote, two fields, and a
	///   chain that a caller other than the proxy forwards.
	pub ForwardedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(3)),
			(SERVED_ASSURANCE, exactly!(3)),
			(COUPLED_CALL_REFUSED, exactly!(5))
		]
	}
}

// A TLS-terminating proxy forwards the client chain of the web caller. The
// edge takes the caller from the chain, verifies it under its own roots, and
// binds a claim to the forwarded leaf. Another caller's header changes
// nothing.
tb_scenario! {
	name: a_pinned_proxy_forwards_the_chain_of_its_caller,
	spec: ForwardedSpec,
	environment Cluster {
		context: (Coupled::mint(), issuer()),
		start: |SetupEnv { trace, context }| async move {
			let proxy = Principal::spiffe(PROXY).map_err(edge_error)?;
			let bearer = BearerTrust::from_jwks("acme", AUDIENCE, &jwks(&context.1)).map_err(edge_error)?;
			let callers = context.0.callers()?.with_forwarding_proxy(proxy).with_bearer(bearer);
			context.0.stage_trusting(&trace, ForwardedEdge::stage, callers)?;
			context.0.gateway::<ForwardedGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.0.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (context, issuer) = (&context.0, &context.1);
			let edge = WorkClient::edge_of(&cluster)?;
			let proxy = context.caller("CN=proxy,O=acme,C=US", Some(PROXY));
			let through = context.channel(&edge, Some(&proxy)).await?;
			through.serving(&context.clock).await?;

			let web = context.caller(WEB, None);
			let forwarded = [Field { key: XFCC, value: xfcc(&web) }];
			let listed = through.call_with(LIST, b"order-20", &forwarded, None).await?;
			assert_eq!(listed.map_err(|status| status.code()), Ok(b"served:order-20".to_vec()), "the forwarded web caller MUST hold LIST");

			let claim = context.claim(&web, PLACE, b"order-21").await?;
			let placed = through.call_with(PLACE, b"order-21", &forwarded, Some(&claim)).await?;
			assert_eq!(placed.map_err(|status| status.code()), Ok(b"served:order-21".to_vec()), "a claim MUST bind to the forwarded leaf");

			let bare = through.call_with(LIST, b"order", &[], None).await?;
			assert_eq!(code_of(bare), Some(tonic::Code::Unauthenticated), "a proxy call with no chain MUST be refused");

			let bearer = format!("Bearer {}", mobile_token(issuer, TOKEN_LIFETIME)?);
			let token = [Field { key: "authorization", value: bearer }];
			let tokened = through.call_with(BROWSE, b"order-23", &token, None).await?;
			let tokened = tokened.map_err(|status| status.code());
			assert_eq!(tokened, Ok(b"served:order-23".to_vec()), "a proxy call with no chain MUST fall back to its token");

			let rogue = TlsAuthority::mint("CN=rogue root,O=acme,C=US", support::LIFETIME);
			let rogue = rogue.map_err(support::mint_error)?.caller(WEB, None).map_err(support::mint_error)?;
			let foreign = [Field { key: XFCC, value: xfcc(&rogue) }];
			let forged = through.call_with(LIST, b"order", &foreign, None).await?;
			assert_eq!(code_of(forged), Some(tonic::Code::Unauthenticated), "a chain of another root MUST be refused");

			let billing = context.billing(&cluster).await?;
			let spoofed = billing.call_with(LIST, b"order", &forwarded, None).await?;
			assert_eq!(code_of(spoofed), Some(tonic::Code::PermissionDenied), "only the proxy MUST forward a chain");

			let injected = format!("Cert=\"{}\";Subject=\",{}", percent(web.certificate_pem()), xfcc(&proxy));
			let injected = [Field { key: XFCC, value: injected }];
			let injected = through.call_with(LIST, b"order", &injected, None).await?;
			assert_eq!(code_of(injected), Some(tonic::Code::Unauthenticated), "an injected quote MUST be refused");

			let twice = [Field { key: XFCC, value: xfcc(&web) }, Field { key: XFCC, value: xfcc(&proxy) }];
			let twice = through.call_appending(LIST, b"order", &twice).await?;
			assert_eq!(code_of(twice), Some(tonic::Code::Unauthenticated), "two XFCC fields MUST be refused");

			cluster.stop();
			Ok(())
		}
	}
}

impl Coupled {
	/// The trust of the orders edge in its callers and in the chains that the
	/// pinned proxy forwards, under `crls`.
	fn proxied(&self, crls: Vec<CertificateRevocationListDer<'static>>) -> Result<CallerTrust, TightBeamError> {
		let proxy = Principal::spiffe(PROXY).map_err(edge_error)?;
		Ok(self.callers()?.with_forwarding_proxy(proxy).with_crls(crls))
	}

	/// A channel to the edge at `edge` under the pinned proxy, once the coupler
	/// serves.
	async fn proxy_channel(&self, edge: &GrpcAddr) -> Result<StockChannel, TightBeamError> {
		let proxy = self.caller("CN=proxy,O=acme,C=US", Some(PROXY));
		let through = self.channel(edge, Some(&proxy)).await?;
		through.serving(&self.clock).await?;
		Ok(through)
	}
}

coupled!(IntermediateEdge, IntermediateGateway);

tb_assert_spec! {
	/// Calls of a web caller under an intermediate authority: the servlet
	/// admits two direct calls and one forwarded chain, and the coupler
	/// refuses a forwarded leaf without its intermediate.
	pub IntermediateSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(3)),
			(SERVED_ASSURANCE, exactly!(3)),
			(COUPLED_CALL_REFUSED, exactly!(1))
		]
	}
}

// The web caller holds a certificate of an intermediate authority under the
// TLS root. The edge builds its chain to the root, whether the caller presents
// it or the pinned proxy forwards it.
tb_scenario! {
	name: a_caller_under_an_intermediate_authority_chains_to_the_root,
	spec: IntermediateSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage_trusting(&trace, IntermediateEdge::stage, context.proxied(Vec::new())?)?;
			context.gateway::<IntermediateGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let edge = WorkClient::edge_of(&cluster)?;
			let issuing = context.tls.intermediate("CN=web issuing,O=acme,C=US").map_err(mint_error)?;
			let web = issuing.caller(WEB, None).map_err(mint_error)?;
			let direct = context.channel(&edge, Some(&web)).await?;
			direct.serving(&context.clock).await?;

			let listed = direct.call(LIST, b"order-40", None).await?;
			assert_eq!(listed.map_err(|status| status.code()), Ok(b"served:order-40".to_vec()), "a presented chain MUST reach the root");

			let claim = context.claim(&web, PLACE, b"order-41").await?;
			let placed = direct.call(PLACE, b"order-41", Some(&claim)).await?;
			assert_eq!(placed.map_err(|status| status.code()), Ok(b"served:order-41".to_vec()), "a claim MUST bind to a leaf under an intermediate");

			let through = context.proxy_channel(&edge).await?;
			let chain = [Field { key: XFCC, value: xfcc_chain(&web) }];
			let chained = through.call_with(LIST, b"order-42", &chain, None).await?;
			assert_eq!(chained.map_err(|status| status.code()), Ok(b"served:order-42".to_vec()), "a forwarded chain MUST reach the root");

			let leaf = [Field { key: XFCC, value: xfcc(&web) }];
			let bare = through.call_with(LIST, b"order", &leaf, None).await?;
			assert_eq!(code_of(bare), Some(tonic::Code::Unauthenticated), "a leaf without its intermediate MUST be refused");

			cluster.stop();
			Ok(())
		}
	}
}

/// The PKI of the revocation scenario, under the TLS root of its context.
struct Revocations {
	context: Coupled,
	/// An intermediate whose CRL revokes nothing.
	kept: TlsAuthority,
	/// An intermediate that the CRL of the root revokes, whose own CRL revokes
	/// nothing.
	revoked: TlsAuthority,
	/// An intermediate that issues no CRL.
	unlisted: TlsAuthority,
	/// A web leaf of the root, which the CRL of the root revokes.
	revoked_web: TlsLeaf,
}

impl Revocations {
	/// Create the PKI of the scenario.
	fn mint() -> Self {
		let context = Coupled::mint();
		let intermediate = |subject| context.tls.intermediate(subject).expect("an intermediate is created");
		let kept = intermediate("CN=kept issuing,O=acme,C=US");
		let revoked = intermediate("CN=revoked issuing,O=acme,C=US");
		let unlisted = intermediate("CN=unlisted issuing,O=acme,C=US");
		let revoked_web = context.caller(WEB, None);
		Self { context, kept, revoked, unlisted, revoked_web }
	}

	/// The CRLs of the edge, fresh while the scenario runs: the root revokes
	/// the revoked web leaf and the revoked intermediate, and the kept and the
	/// revoked intermediates revoke nothing.
	fn crls(&self) -> Result<Vec<CertificateRevocationListDer<'static>>, TightBeamError> {
		let fresh = SystemTime::now() + support::LIFETIME;
		let root = self
			.context
			.tls
			.crl(&[self.revoked_web.leaf(), self.revoked.certificate()], fresh);
		let crls = [root, self.kept.crl(&[], fresh), self.revoked.crl(&[], fresh)];
		crls.into_iter().collect::<Result<_, _>>().map_err(mint_error)
	}

	/// A web leaf of `authority`.
	fn web(authority: &TlsAuthority) -> Result<TlsLeaf, TightBeamError> {
		authority.caller(WEB, None).map_err(mint_error)
	}
}

coupled!(RevokedEdge, RevokedGateway);

tb_assert_spec! {
	/// Calls under CRLs: the servlet admits the billing caller, and a web
	/// caller of the kept intermediate both directly and forwarded. The
	/// coupler refuses a forwarded revoked leaf, a forwarded chain through the
	/// revoked intermediate, and one through the unlisted intermediate.
	pub RevokedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(3)),
			(SERVED_ASSURANCE, exactly!(3)),
			(COUPLED_CALL_REFUSED, exactly!(3))
		]
	}
}

// The edge checks every certificate of a chain against the CRL of its issuer,
// at the handshake of a caller and on each chain that the pinned proxy
// forwards. A revoked certificate and one whose issuer lists no CRL are
// refused.
tb_scenario! {
	name: a_revoked_chain_is_refused_at_its_handshake_and_when_forwarded,
	spec: RevokedSpec,
	environment Cluster {
		context: Revocations::mint(),
		start: |SetupEnv { trace, context }| async move {
			let callers = context.context.proxied(context.crls()?)?;
			context.context.stage_trusting(&trace, RevokedEdge::stage, callers)?;
			context.context.gateway::<RevokedGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (revocations, context) = (&context, &context.context);
			let edge = WorkClient::edge_of(&cluster)?;
			let billing = context.billing(&cluster).await?;
			let got = billing.call(GET, b"order-60", None).await?;
			assert_eq!(got.map_err(|status| status.code()), Ok(b"served:order-60".to_vec()), "a leaf that no CRL revokes MUST be admitted");

			let kept = Revocations::web(&revocations.kept)?;
			let direct = context.channel(&edge, Some(&kept)).await?;
			let listed = direct.call(LIST, b"order-61", None).await?;
			assert_eq!(listed.map_err(|status| status.code()), Ok(b"served:order-61".to_vec()), "a chain that each issuer lists MUST be admitted");

			let alert = context.alert_of(&edge, &revocations.revoked_web).await?;
			assert_eq!(alert, AlertDescription::CertificateRevoked, "a revoked leaf MUST fail its handshake");

			let under_revoked = Revocations::web(&revocations.revoked)?;
			let alert = context.alert_of(&edge, &under_revoked).await?;
			assert_eq!(alert, AlertDescription::CertificateRevoked, "a leaf under a revoked intermediate MUST fail its handshake");

			let unlisted = Revocations::web(&revocations.unlisted)?;
			let alert = context.alert_of(&edge, &unlisted).await?;
			assert_eq!(alert, AlertDescription::UnknownCA, "a leaf whose issuer lists no CRL MUST fail its handshake");

			let through = context.proxy_channel(&edge).await?;
			let listed = [Field { key: XFCC, value: xfcc_chain(&kept) }];
			let forwarded = through.call_with(LIST, b"order-62", &listed, None).await?;
			assert_eq!(forwarded.map_err(|status| status.code()), Ok(b"served:order-62".to_vec()), "a forwarded chain that each issuer lists MUST be admitted");

			let refused = [
				(xfcc(&revocations.revoked_web), "a forwarded revoked leaf MUST be refused"),
				(xfcc_chain(&under_revoked), "a forwarded chain through a revoked intermediate MUST be refused"),
				(xfcc_chain(&unlisted), "a forwarded chain whose issuer lists no CRL MUST be refused"),
			];
			for (field, reason) in refused {
				let field = [Field { key: XFCC, value: field }];
				let answer = through.call_with(LIST, b"order", &field, None).await?;
				assert_eq!(code_of(answer), Some(tonic::Code::Unauthenticated), "{reason}");
			}

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(StaleEdge, StaleGateway);

tb_assert_spec! {
	/// No coupled call: a CRL past its `nextUpdate` refuses each caller that
	/// presents a chain at its handshake.
	pub StaleSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(0)),
			(COUPLED_CALL_REFUSED, exactly!(0))
		]
	}
}

// The root issued its CRL a minute stale. The edge holds no status for any
// chain the CRL covers, so it refuses a caller that the CRL does not revoke.
tb_scenario! {
	name: a_crl_past_its_next_update_refuses_each_chain_it_covers,
	spec: StaleSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			let stale = SystemTime::now() - Duration::from_secs(60);
			let stale = context.tls.crl(&[], stale).map_err(mint_error)?;
			context.stage_trusting(&trace, StaleEdge::stage, context.callers()?.with_crls([stale]))?;
			context.gateway::<StaleGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let edge = WorkClient::edge_of(&cluster)?;
			context.channel(&edge, None).await?.serving(&context.clock).await?;

			let billing = context.billing_caller();
			let alert = context.alert_of(&edge, &billing).await?;
			assert_eq!(alert, AlertDescription::UnknownCA, "a stale CRL MUST refuse a chain it does not revoke");

			cluster.stop();
			Ok(())
		}
	}
}

/// The audience of the bearer tokens of the edge.
const AUDIENCE: &str = "spiffe://acme/orders-edge";

/// The key ID of the issuer of the bearer tokens.
const KID: &str = "issuer-1";

/// The key set of the issuer key `key` under [`KID`].
fn jwks(key: &p256::ecdsa::SigningKey) -> String {
	let point = key.verifying_key().to_encoded_point(false);
	let coordinate =
		|bytes: Option<&p256::FieldBytes>| bytes.map(|bytes| URL_SAFE_NO_PAD.encode(bytes)).unwrap_or_default();
	let (x, y) = (coordinate(point.x()), coordinate(point.y()));
	format!(r#"{{"keys":[{{"kty":"EC","crv":"P-256","use":"sig","kid":"{KID}","x":"{x}","y":"{y}"}}]}}"#)
}

/// How long a bearer token of the mobile caller stays valid, unless a
/// scenario names its own lifetime.
const TOKEN_LIFETIME: Duration = Duration::from_secs(300);

/// A JWT-SVID of the mobile caller for [`AUDIENCE`], signed under `key`,
/// which expires `lifetime` from now on the clock of the caller.
fn mobile_token(key: &p256::ecdsa::SigningKey, lifetime: Duration) -> Result<String, TightBeamError> {
	use p256::ecdsa::signature::Signer;

	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map_err(unexpected)?;
	let header = format!(r#"{{"alg":"ES256","kid":"{KID}","typ":"JWT"}}"#);
	let expires = (now + lifetime).as_secs();
	let claims = format!(r#"{{"sub":"{MOBILE}","aud":"{AUDIENCE}","exp":{expires}}}"#);

	let signed = format!("{}.{}", URL_SAFE_NO_PAD.encode(header), URL_SAFE_NO_PAD.encode(claims));
	let signature: p256::ecdsa::Signature = key.sign(signed.as_bytes());
	Ok(format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())))
}

/// The issuer key of the bearer scenario.
fn issuer() -> p256::ecdsa::SigningKey {
	p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)
}

/// The replay window and the token lifetime of the edge whose clock the
/// scenario moves past both.
const EXPIRY_WINDOW: Duration = Duration::from_secs(4);

coupled!(ExpiryEdge, ExpiryGateway);

tb_assert_spec! {
	/// A claim and a bearer token, each fresh on the clock of its caller,
	/// which the edge refuses with 16 once its own clock passes the replay
	/// window and the expiry of the token. The edge refuses the claim before
	/// its ledger.
	pub ExpirySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_REFUSED, exactly!(2)),
			(COUPLED_CALL_ANSWERED, exactly!(0)),
			(SERVED_ASSURANCE, exactly!(0)),
			(STORE_HELD, exactly!(0))
		]
	}
}

/// The events of the scenario of a stale claim and an expired token.
static EXPIRY_EVENTS: EventWatch = EventWatch::new();

// The edge judges the freshness of a claim and the expiry of a bearer token
// at the unix time of its own clock, which the scenario moves past both.
tb_scenario! {
	name: an_edge_judges_claims_and_tokens_at_the_time_of_its_clock,
	config: ExpirySpec::latest().watched(&EXPIRY_EVENTS),
	environment Cluster {
		context: (Coupled::clocked(&EXPIRY_EVENTS), issuer()),
		start: |SetupEnv { trace, context }| async move {
			let bearer = BearerTrust::from_jwks("acme", AUDIENCE, &jwks(&context.1)).map_err(edge_error)?;
			let callers = context.0.callers()?.with_bearer(bearer.with_leeway(Duration::ZERO));
			let coupler = context.0.orders(&context.0.answers, callers)?.with_replay_window(EXPIRY_WINDOW);
			let coupler = coupler.with_claim_ledger(HeldStoreLedger::on(&EXPIRY_EVENTS));
			context.0.stage_coupler(&trace, ExpiryEdge::stage, coupler)?;
			context.0.gateway::<ExpiryGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.0.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (context, issuer) = (&context.0, &context.1);
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order-90").await?;
			let mobile = context.channel(&WorkClient::edge_of(&cluster)?, None).await?;
			let bearer = format!("Bearer {}", mobile_token(issuer, EXPIRY_WINDOW)?);
			let token = [Field { key: "authorization", value: bearer }];

			context.clock.catch_up()?;
			context.clock.advance(EXPIRY_WINDOW + EXPIRY_WINDOW)?;

			let placed = channel.call(PLACE, b"order-90", Some(&claim)).await?;
			assert_eq!(code_of(placed), Some(tonic::Code::Unauthenticated), "a claim past the window of the edge MUST be refused");

			let browsed = mobile.call_with(BROWSE, b"order-91", &token, None).await?;
			assert_eq!(code_of(browsed), Some(tonic::Code::Unauthenticated), "a token past its expiry on the edge MUST be refused");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(BearerEdge, BearerGateway);

tb_assert_spec! {
	/// Calls of a bearer caller: the servlet admits one as bearer, and the
	/// coupler refuses one on a route that requires vouched, one under a
	/// token of another key, one with no token, and one that joins a claim.
	pub BearerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(1), equals!("bearer")),
			(SERVED_ASSURANCE, exactly!(1), equals!("bearer")),
			(COUPLED_CALL_REFUSED, exactly!(4))
		]
	}
}

// A caller with no client certificate presents a JWT-SVID. Its calls prove
// bearer, which a route must admit, and no claim can bind to it.
tb_scenario! {
	name: a_bearer_caller_reaches_only_a_route_that_admits_bearer,
	spec: BearerSpec,
	environment Cluster {
		context: (Coupled::mint(), issuer()),
		start: |SetupEnv { trace, context }| async move {
			let bearer = BearerTrust::from_jwks("acme", AUDIENCE, &jwks(&context.1)).map_err(edge_error)?;
			let callers = context.0.callers()?.with_bearer(bearer);
			context.0.stage_trusting(&trace, BearerEdge::stage, callers)?;
			context.0.gateway::<BearerGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.0.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (context, issuer) = (&context.0, &context.1);
			let channel = context.channel(&WorkClient::edge_of(&cluster)?, None).await?;
			channel.serving(&context.clock).await?;

			let bearer = format!("Bearer {}", mobile_token(issuer, TOKEN_LIFETIME)?);
			let token = [Field { key: "authorization", value: bearer }];
			let browsed = channel.call_with(BROWSE, b"order-22", &token, None).await?;
			assert_eq!(browsed.map_err(|status| status.code()), Ok(b"served:order-22".to_vec()));

			let vouched = channel.call_with(GET, b"order", &token, None).await?;
			assert_eq!(code_of(vouched), Some(tonic::Code::PermissionDenied), "a bearer call MUST NOT pass a vouched route");

			let other = format!("Bearer {}", mobile_token(&self::issuer(), TOKEN_LIFETIME)?);
			let forged = [Field { key: "authorization", value: other }];
			let forged = channel.call_with(BROWSE, b"order", &forged, None).await?;
			assert_eq!(code_of(forged), Some(tonic::Code::Unauthenticated), "a token of another key MUST be refused");

			let bare = channel.call_with(BROWSE, b"order", &[], None).await?;
			assert_eq!(code_of(bare), Some(tonic::Code::Unauthenticated), "a call with no token MUST be refused");

			let web = context.caller(WEB, None);
			let claim = context.claim(&web, BROWSE, b"order").await?;
			let claimed = channel.call_with(BROWSE, b"order", &token, Some(&claim)).await?;
			assert_eq!(code_of(claimed), Some(tonic::Code::Unauthenticated), "no claim MUST bind to a bearer caller");

			cluster.stop();
			Ok(())
		}
	}
}

/// The origin of the shop pages that the web edge serves.
const SHOP: &str = "https://shop.example";

coupled!(WebEdge, WebGateway);

tb_assert_spec! {
	/// Two gRPC-Web calls under a bearer token, binary from a page of the
	/// shop and text from no page, which the servlet admits as bearer.
	pub WebSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(2), equals!("bearer")),
			(SERVED_ASSURANCE, exactly!(2), equals!("bearer"))
		]
	}
}

// A page of the shop asks the edge first, then calls in gRPC-Web under a
// bearer token. A page of another origin is refused at each step.
tb_scenario! {
	name: a_page_of_an_allowed_origin_calls_in_grpc_web,
	spec: WebSpec,
	environment Cluster {
		context: (Coupled::mint(), issuer()),
		start: |SetupEnv { trace, context }| async move {
			let bearer = BearerTrust::from_jwks("acme", AUDIENCE, &jwks(&context.1)).map_err(edge_error)?;
			let callers = context.0.callers()?.with_bearer(bearer);
			let coupler = context.0.orders(&context.0.answers, callers)?;
			let coupler = coupler.with_grpc_web([SHOP]).map_err(edge_error)?;
			context.0.stage_coupler(&trace, WebEdge::stage, coupler)?;
			context.0.gateway::<WebGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.0.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (context, issuer) = (&context.0, &context.1);
			let edge = WorkClient::edge_of(&cluster)?;
			context.channel(&edge, None).await?.serving(&context.clock).await?;

			let mut page = H2Tunnel::connect_tls(edge.to_string(), &[], &context.tls, None).await?;

			let shop = PageCall { method: BROWSE, origin: SHOP };
			let evil = PageCall { method: BROWSE, origin: "https://evil.example" };
			let PageRead { status, allowed, .. } = page.preflight(shop).await?;
			assert_eq!((status.as_u16(), allowed.as_deref()), (204, Some(SHOP)), "the shop MUST pass its preflight");

			let PageRead { status, allowed, .. } = page.preflight(evil).await?;
			assert_eq!((status.as_u16(), allowed), (403, None), "another origin MUST fail its preflight");

			let token = mobile_token(issuer, TOKEN_LIFETIME)?;
			let PageRead { status, allowed, exposed, body } = page.web_call(shop, b"order-30", &token).await?;
			let exposed = exposed.unwrap_or_default();
			assert!(exposed.contains("grpc-status") && exposed.contains("grpc-status-details-bin"), "a page MUST read the status, got {exposed:?}");

			let WebAnswer { messages, trailers } = H2Tunnel::web_frames(&body);
			assert_eq!((status.as_u16(), allowed.as_deref()), (200, Some(SHOP)));
			assert_eq!(messages, [b"served:order-30".to_vec()], "the page MUST read the answer");
			assert!(trailers.contains("grpc-status:0"), "the page MUST read status 0, got {trailers:?}");

			let PageRead { status, .. } = page.web_call(evil, b"order", &token).await?;
			assert_eq!(status.as_u16(), 403, "a page of another origin MUST be refused");

			let WebAnswer { messages, .. } = page.web_text_call(BROWSE, b"order-31", &token).await?;
			assert_eq!(messages, [b"served:order-31".to_vec()], "a page MUST read a text answer");

			let browse = PathAndQuery::from_static(BROWSE);
			let request = page.head(http::Method::POST, &browse, "application/grpc-web+json")?;
			let framed = [&[0, 0, 0, 0, 1][..], b"x"].concat();
			let odd = page.call(request, Some(bytes::Bytes::from(framed))).await?;
			assert_eq!(odd.status().as_u16(), 415);

			cluster.stop();
			Ok(())
		}
	}
}

/// The messages that the servlet streams for `message` on [`FEED`].
fn fed(message: &[u8]) -> Vec<Vec<u8>> {
	let watched = |index: &[u8]| [b"watch:".as_slice(), message, b":", index].concat();
	vec![watched(b"0"), watched(b"1"), watched(b"2")]
}

/// The details of the status that the gRPC-Web `trailers` carry.
fn details_of(trailers: &str) -> Option<Vec<u8>> {
	use base64::engine::general_purpose::STANDARD_NO_PAD;

	let line = trailers
		.split("\r\n")
		.find_map(|line| line.strip_prefix("grpc-status-details-bin:"))?;
	STANDARD_NO_PAD.decode(line.trim().trim_end_matches('=')).ok()
}

coupled!(WebStreamEdge, WebStreamGateway);

tb_assert_spec! {
	/// Three server streams in gRPC-Web under a bearer token, which the
	/// servlet admits as bearer: binary and text streams that end with status
	/// 0, and one that fails after its first message.
	pub WebStreamSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(3), equals!("bearer")),
			(SERVED_ASSURANCE, exactly!(3), equals!("bearer"))
		]
	}
}

// A page of the shop reads a server stream in gRPC-Web: each message in
// order, then the status in the trailer frame, in binary and in text. A
// stream that fails carries its status and details after the messages
// before it.
tb_scenario! {
	name: a_page_reads_a_server_stream_in_grpc_web,
	spec: WebStreamSpec,
	environment Cluster {
		context: (Coupled::mint(), issuer()),
		start: |SetupEnv { trace, context }| async move {
			let bearer = BearerTrust::from_jwks("acme", AUDIENCE, &jwks(&context.1)).map_err(edge_error)?;
			let callers = context.0.callers()?.with_bearer(bearer);
			let coupler = context.0.orders(&context.0.answers, callers)?;
			let coupler = coupler.with_grpc_web([SHOP]).map_err(edge_error)?;
			context.0.stage_coupler(&trace, WebStreamEdge::stage, coupler)?;
			context.0.gateway::<WebStreamGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.0.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (context, issuer) = (&context.0, &context.1);
			let edge = WorkClient::edge_of(&cluster)?;
			context.channel(&edge, None).await?.serving(&context.clock).await?;
			let mut page = H2Tunnel::connect_tls(edge.to_string(), &[], &context.tls, None).await?;
			let token = mobile_token(issuer, TOKEN_LIFETIME)?;

			let feed = PageCall { method: FEED, origin: SHOP };
			let PageRead { status, allowed, body, .. } = page.web_call(feed, b"order-50", &token).await?;
			let WebAnswer { messages, trailers } = H2Tunnel::web_frames(&body);
			assert_eq!((status.as_u16(), allowed.as_deref()), (200, Some(SHOP)));
			assert_eq!(messages, fed(b"order-50"), "a page MUST read each message of the stream in order");
			assert!(trailers.contains("grpc-status:0"), "a page MUST read status 0, got {trailers:?}");

			let WebAnswer { messages, trailers } = page.web_text_call(FEED, b"order-51", &token).await?;
			assert_eq!(messages, fed(b"order-51"), "a page MUST read each message of a text stream in order");
			assert!(trailers.contains("grpc-status:0"), "a page MUST read status 0 of a text stream, got {trailers:?}");

			let PageRead { body, .. } = page.web_call(feed, FAILING, &token).await?;
			let WebAnswer { messages, trailers } = H2Tunnel::web_frames(&body);
			assert_eq!(messages, [b"partial".to_vec()], "a page MUST read the messages before the failure");
			assert!(trailers.contains("grpc-status:9"), "a page MUST read the status of the failure, got {trailers:?}");
			assert_eq!(details_of(&trailers), Some(DETAILS.to_vec()), "a page MUST read the details of the failure");

			cluster.stop();
			Ok(())
		}
	}
}

/// The encoded descriptors of the orders service, which reflection serves.
fn orders_descriptors() -> Vec<u8> {
	use prost::Message;
	use prost_types::{
		DescriptorProto, FileDescriptorProto, FileDescriptorSet, MethodDescriptorProto, ServiceDescriptorProto,
	};

	let method = |name: &str| MethodDescriptorProto {
		name: Some(name.to_owned()),
		input_type: Some(".orders.v1.Order".to_owned()),
		output_type: Some(".orders.v1.Order".to_owned()),
		..MethodDescriptorProto::default()
	};
	let orders = ServiceDescriptorProto {
		name: Some("Orders".to_owned()),
		method: vec![method("Get"), method("Place"), method("Purge")],
		..ServiceDescriptorProto::default()
	};
	let admin = ServiceDescriptorProto {
		name: Some("Admin".to_owned()),
		method: vec![method("Purge")],
		..ServiceDescriptorProto::default()
	};
	let file = FileDescriptorProto {
		name: Some("orders.proto".to_owned()),
		package: Some("orders.v1".to_owned()),
		message_type: vec![DescriptorProto { name: Some("Order".to_owned()), ..DescriptorProto::default() }],
		service: vec![orders, admin],
		syntax: Some("proto3".to_owned()),
		..FileDescriptorProto::default()
	};
	let secrets = FileDescriptorProto {
		name: Some("secrets.proto".to_owned()),
		package: Some("admin.v1".to_owned()),
		message_type: vec![DescriptorProto { name: Some("Order".to_owned()), ..DescriptorProto::default() }],
		service: vec![ServiceDescriptorProto {
			name: Some("Secrets".to_owned()),
			method: vec![method("Dump")],
			..ServiceDescriptorProto::default()
		}],
		syntax: Some("proto3".to_owned()),
		..FileDescriptorProto::default()
	};
	FileDescriptorSet { file: vec![file, secrets] }.encode_to_vec()
}

/// The reflection clients that the scenarios run.
impl StockChannel {
	/// The services that the reflection of the channel lists.
	async fn listed_services(&self) -> Result<Vec<String>, Status> {
		use tonic_reflection::pb::v1::server_reflection_client::ServerReflectionClient;
		use tonic_reflection::pb::v1::server_reflection_request::MessageRequest;
		use tonic_reflection::pb::v1::server_reflection_response::MessageResponse;
		use tonic_reflection::pb::v1::ServerReflectionRequest;

		let request = ServerReflectionRequest {
			host: String::new(),
			message_request: Some(MessageRequest::ListServices(String::new())),
		};

		let mut client = ServerReflectionClient::new(self.channel());
		let mut answers = client.server_reflection_info(stream::iter([request])).await?.into_inner();
		let answer = answers
			.message()
			.await?
			.ok_or_else(|| Status::internal("reflection answered nothing"))?;
		match answer.message_response {
			Some(MessageResponse::ListServicesResponse(listed)) => {
				Ok(listed.service.into_iter().map(|service| service.name).collect())
			}
			_ => Err(Status::internal("reflection answered no list")),
		}
	}

	/// The methods of `service` in the file that the reflection of the channel
	/// serves for the symbol `service`, or `None` when it serves no file.
	async fn reflected_methods(&self, service: &str) -> Result<Option<Vec<String>>, Status> {
		use prost::Message;
		use tonic_reflection::pb::v1::server_reflection_client::ServerReflectionClient;
		use tonic_reflection::pb::v1::server_reflection_request::MessageRequest;
		use tonic_reflection::pb::v1::server_reflection_response::MessageResponse;
		use tonic_reflection::pb::v1::ServerReflectionRequest;

		let request = ServerReflectionRequest {
			host: String::new(),
			message_request: Some(MessageRequest::FileContainingSymbol(service.to_owned())),
		};

		let mut client = ServerReflectionClient::new(self.channel());
		let mut answers = client.server_reflection_info(stream::iter([request])).await?.into_inner();
		let answer = answers
			.message()
			.await?
			.ok_or_else(|| Status::internal("reflection answered nothing"))?;
		let Some(MessageResponse::FileDescriptorResponse(files)) = answer.message_response else {
			return Ok(None);
		};

		let (package, name) = service
			.rsplit_once('.')
			.ok_or_else(|| Status::internal("a service names its package"))?;
		let decoded = files
			.file_descriptor_proto
			.iter()
			.map(|file| prost_types::FileDescriptorProto::decode(file.as_slice()));
		let decoded = decoded
			.collect::<Result<Vec<_>, _>>()
			.map_err(|error| Status::internal(error.to_string()))?;

		let file = decoded.into_iter().find(|file| file.package() == package);
		let service = file.and_then(|file| file.service.into_iter().find(|candidate| candidate.name() == name));
		Ok(Some(
			service
				.map(|service| service.method.iter().map(|method| method.name().to_owned()).collect())
				.unwrap_or_default(),
		))
	}

	/// The services that the v1alpha reflection of the channel lists.
	async fn listed_services_alpha(&self) -> Result<Vec<String>, Status> {
		use tonic_reflection::pb::v1alpha::server_reflection_client::ServerReflectionClient;
		use tonic_reflection::pb::v1alpha::server_reflection_request::MessageRequest;
		use tonic_reflection::pb::v1alpha::server_reflection_response::MessageResponse;
		use tonic_reflection::pb::v1alpha::ServerReflectionRequest;

		let request = ServerReflectionRequest {
			host: String::new(),
			message_request: Some(MessageRequest::ListServices(String::new())),
		};

		let mut client = ServerReflectionClient::new(self.channel());
		let mut answers = client.server_reflection_info(stream::iter([request])).await?.into_inner();
		let answer = answers
			.message()
			.await?
			.ok_or_else(|| Status::internal("reflection answered nothing"))?;
		match answer.message_response {
			Some(MessageResponse::ListServicesResponse(listed)) => {
				Ok(listed.service.into_iter().map(|service| service.name).collect())
			}
			_ => Err(Status::internal("reflection answered no list")),
		}
	}
}

coupled!(ReflectedEdge, ReflectedGateway);

tb_assert_spec! {
	/// Reflection, which the coupler admits as no call.
	pub ReflectedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(0)),
			(COUPLED_CALL_REFUSED, exactly!(1), equals!("unauthenticated"))
		]
	}
}

// A stock reflection client lists the routed services of the edge, and a
// caller that the edge does not identify is refused.
tb_scenario! {
	name: reflection_lists_the_routed_services_to_an_identified_caller,
	spec: ReflectedSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			let coupler = context.orders(&context.answers, context.callers()?)?;
			let coupler = coupler.with_reflection(&orders_descriptors()).map_err(edge_error)?;
			context.stage_coupler(&trace, ReflectedEdge::stage, coupler)?;
			context.gateway::<ReflectedGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let billing = context.billing(&cluster).await?;
			let listed = bounded(billing.listed_services()).await?.map_err(|status| status.code());
			assert_eq!(listed, Ok(vec!["orders.v1.Orders".to_owned()]), "reflection MUST list the routed services");

			let alpha = bounded(billing.listed_services_alpha()).await?.map_err(|status| status.code());
			assert_eq!(alpha, Ok(vec!["orders.v1.Orders".to_owned()]), "v1alpha MUST list the routed services");

			let routed = bounded(billing.reflected_methods("orders.v1.Orders")).await?.map_err(|status| status.code());
			let expected = vec!["Get".to_owned(), "Place".to_owned()];
			assert_eq!(routed, Ok(Some(expected)), "reflection MUST describe the routed methods alone");

			let beside = bounded(billing.reflected_methods("orders.v1.Admin")).await?.map_err(|status| status.code());
			assert_eq!(beside, Err(tonic::Code::NotFound), "an unrouted service of a routed file MUST NOT resolve");

			let apart = bounded(billing.reflected_methods("admin.v1.Secrets")).await?.map_err(|status| status.code());
			assert_eq!(apart, Err(tonic::Code::NotFound), "a service of an unrouted file MUST NOT resolve");

			let anonymous = context.channel(&WorkClient::edge_of(&cluster)?, None).await?;
			let refused = bounded(anonymous.listed_services()).await?.map_err(|status| status.code());
			assert_eq!(refused, Err(tonic::Code::Unauthenticated), "reflection MUST refuse an unidentified caller");

			cluster.stop();
			Ok(())
		}
	}
}

/// What a claim covers, as a signer in another language encodes the
/// `ClaimBody` of `docs/grpc.md`.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
#[beam(min_version = "V1")]
struct DocumentedClaimBody {
	method: String,
	body_digest: OctetString,
	leaf_digest: OctetString,
}

/// The `ClaimEnvelope` of `docs/grpc.md`.
#[derive(Sequence, Clone, Debug, PartialEq, Eq)]
struct DocumentedClaimEnvelope {
	frame: OctetString,
	signer: tightbeam::crypto::x509::Certificate,
	issuers: Vec<tightbeam::crypto::x509::Certificate>,
}

/// The DER of a claim of `method` and `body`, bound to `leaf`, built from the
/// claim encoding alone and signed under `claims`.
async fn documented_claim(
	claims: &Identity,
	leaf: &[u8],
	method: &str,
	body: &[u8],
) -> Result<Vec<u8>, TightBeamError> {
	use sha2::{Digest, Sha256};

	let claimed = DocumentedClaimBody {
		method: method.to_owned(),
		body_digest: OctetString::new(Sha256::digest(body).to_vec())?,
		leaf_digest: OctetString::new(Sha256::digest(leaf).to_vec())?,
	};

	let order = UnixMillis::now().get();
	let draft = Version::V1.compose().with_id(order.to_be_bytes()).with_order(order);
	let mut frame = draft.with_message(claimed).build()?;
	frame.sign_with_provider(&claims.signing_identity()).await?;

	let frame = OctetString::new(frame.to_der()?)?;
	let envelope = DocumentedClaimEnvelope { frame, signer: claims.certificate().clone(), issuers: Vec::new() };
	Ok(envelope.to_der()?)
}

coupled!(DocumentedClaimEdge, DocumentedClaimGateway);

tb_assert_spec! {
	/// One call under a claim that the claim encoding alone built, which the
	/// coupler and the servlet admit as signed.
	pub DocumentedClaimSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(1), equals!("signed")),
			(SERVED_ASSURANCE, exactly!(1), equals!("signed"))
		]
	}
}

// A signer in another language builds its claim from `docs/grpc.md` alone,
// with no `ClaimSigner`, and the edge admits the call as signed.
tb_scenario! {
	name: a_claim_built_from_the_claim_encoding_is_admitted,
	spec: DocumentedClaimSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, DocumentedClaimEdge::stage)?;
			context.gateway::<DocumentedClaimGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = documented_claim(&context.claims, web.leaf().as_ref(), PLACE, b"order-40").await?;

			let mut grpc = channel.client().await?;
			let mut request = Request::new(b"order-40".to_vec());
			request.metadata_mut().insert_bin(CallClaim::METADATA_KEY, MetadataValue::from_bytes(&claim));

			let placed = bounded(grpc.unary(request, PathAndQuery::from_static(PLACE), RawCodec)).await?;
			let placed = placed.map(tonic::Response::into_inner).map_err(|status| status.code());
			assert_eq!(placed, Ok(b"served:order-40".to_vec()), "a claim of the documented encoding alone MUST admit");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(ReplicaAEdge, ReplicaAGateway);
coupled!(ReplicaBEdge, ReplicaBGateway);

impl Coupled {
	/// The orders edge of one replica, which spends its claims in `ledger`,
	/// staged through `stage`.
	fn stage_replica(
		&self,
		trace: &TraceCollector,
		stage: fn(Edge, Dial),
		ledger: &Arc<MemoryLedger>,
	) -> Result<(), TightBeamError> {
		let shared: Arc<dyn ClaimLedger> = Arc::clone(ledger) as Arc<dyn ClaimLedger>;
		let coupler = self.orders(&self.answers, self.callers()?)?.with_claim_ledger(shared);
		self.stage_coupler(trace, stage, coupler)
	}
}

tb_assert_spec! {
	/// Two replicas that share one ledger: replica A serves a signed call,
	/// replica B admits its replay and refuses it at the spend, and serves a
	/// fresh claim.
	pub ReplicaSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(3), equals!("signed")),
			(COUPLED_CALL_REFUSED, exactly!(1), equals!("replayed")),
			(SERVED_ASSURANCE, exactly!(2), equals!("signed"))
		]
	}
}

// Two replicas of one edge share a claim ledger, so a claim that one spends
// is spent on the other.
tb_scenario! {
	name: replicas_that_share_a_ledger_spend_a_claim_once,
	spec: ReplicaSpec,
	environment Cluster {
		context: (Coupled::mint(), Arc::new(MemoryLedger::new())),
		start: |SetupEnv { trace, context }| async move {
			context.0.stage_replica(&trace, ReplicaAEdge::stage, &context.1)?;
			context.0.gateway::<ReplicaAGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.0.hive(&trace).await }],
		client: |ClusterEnv { trace, context, cluster }| async move {
			let (context, ledger) = (&context.0, &context.1);
			context.stage_replica(&trace, ReplicaBEdge::stage, ledger)?;

			let replica = context.gateway::<ReplicaBGateway>(&trace).await?;
			let hive = context.hive(&trace).await?;
			hive.register_with_cluster(replica.addr()).await?;

			let WebCaller { leaf: web, channel: first } = context.web(&cluster).await?;
			let second = context.channel(&WorkClient::edge_of(&replica)?, Some(&web)).await?;
			second.serving(&context.clock).await?;

			let claim = context.claim(&web, PLACE, b"order-50").await?;
			let placed = first.call(PLACE, b"order-50", Some(&claim)).await?.map_err(|status| status.code());
			assert_eq!(placed, Ok(b"served:order-50".to_vec()));

			let replayed = second.call(PLACE, b"order-50", Some(&claim)).await?;
			assert_eq!(code_of(replayed), Some(tonic::Code::Unauthenticated), "a claim spent on one replica MUST be spent on the other");

			let fresh = context.claim(&web, PLACE, b"order-51").await?;
			let placed = second.call(PLACE, b"order-51", Some(&fresh)).await?.map_err(|status| status.code());
			assert_eq!(placed, Ok(b"served:order-51".to_vec()));

			replica.stop();
			hive.stop();
			cluster.stop();
			Ok(())
		}
	}
}

coupled!(StrangerWatchEdge, StrangerWatchGateway);

tb_assert_spec! {
	/// A watch of a caller that no grant names, beside a call of the billing
	/// caller on the one coupled lane of the edge, which the coupler serves.
	pub StrangerWatchSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32))
		]
	}
}

// A caller that no grant names holds no coupled lane with its watch, so the
// one lane of the edge stays free for a granted call. The watch of the
// stranger opens first and stays open through the call.
tb_scenario! {
	name: a_watch_of_a_caller_with_no_grant_holds_no_lane,
	spec: StrangerWatchSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage_limited(&trace, StrangerWatchEdge::stage, CLOCKED_LIMIT, 1, 8)?;
			context.gateway::<StrangerWatchGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let stranger = context.caller("CN=stranger,O=acme,C=US", None);
			let watcher = context.channel(&WorkClient::edge_of(&cluster)?, Some(&stranger)).await?;
			let mut answers = watcher.watch(&[]).await?.map_err(unexpected)?;
			answers.serving(&context.clock).await?;

			let billing = context.billing(&cluster).await?;
			let served = billing.call(GET, b"order-60", None).await?.map_err(|status| status.code());
			assert_eq!(served, Ok(b"served:order-60".to_vec()), "the one lane MUST stay free for a granted call");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(NoTrustDomainEdge, NoTrustDomainGateway);
refused_spec!(NoTrustDomainSpec, "unauthenticated", 0);

// A caller whose SPIFFE ID names no trust domain names no principal, so the
// edge refuses its call as the servlet would refuse its origin.
tb_scenario! {
	name: a_caller_whose_spiffe_id_names_no_trust_domain_is_unauthenticated,
	spec: NoTrustDomainSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, NoTrustDomainEdge::stage)?;
			context.gateway::<NoTrustDomainGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let nameless = context.caller("CN=nameless,O=acme,C=US", Some("spiffe:///orders"));
			let channel = context.channel(&WorkClient::edge_of(&cluster)?, Some(&nameless)).await?;
			channel.serving(&context.clock).await?;

			let answer = channel.call(GET, b"order", None).await?;
			assert_eq!(code_of(answer), Some(tonic::Code::Unauthenticated));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(TrustDomainOnlyEdge, TrustDomainOnlyGateway);

tb_assert_spec! {
	/// Two callers whose SPIFFE IDs name a trust domain and no workload: the
	/// coupler refuses each as unauthenticated, before any grant is read.
	pub TrustDomainOnlySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_REFUSED, exactly!(2), equals!("unauthenticated")),
			(COUPLED_CALL_ADMITTED, exactly!(0)),
			(events::CLUSTER_WORK_ROUTED, exactly!(0))
		]
	}
}

// A SPIFFE ID of a trust domain alone, with or without a slash, names no
// workload, so the TLS path refuses it as the bearer path does.
tb_scenario! {
	name: a_caller_whose_spiffe_id_names_only_a_trust_domain_is_unauthenticated,
	spec: TrustDomainOnlySpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, TrustDomainOnlyEdge::stage)?;
			context.gateway::<TrustDomainOnlyGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			for id in ["spiffe://acme", "spiffe://acme/"] {
				let domain = context.caller("CN=domain,O=acme,C=US", Some(id));
				let channel = context.channel(&WorkClient::edge_of(&cluster)?, Some(&domain)).await?;
				channel.serving(&context.clock).await?;

				let answer = channel.call(GET, b"order", None).await?;
				assert_eq!(code_of(answer), Some(tonic::Code::Unauthenticated), "{id} MUST name no principal");
			}

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(NarrowSessionEdge, NarrowSessionGateway);

tb_assert_spec! {
	/// Three slow signed calls at once on a loopback session of one stream:
	/// each one waits for the stream within its deadline, and each one is
	/// answered.
	pub NarrowSessionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(3), equals!("signed")),
			(COUPLED_CALL_ANSWERED, exactly!(3), equals!(0u32)),
			(COUPLED_CALL_REFUSED, exactly!(0))
		]
	}
}

/// The events of the scenario of calls past the streams of the session.
static NARROW_SESSION_EVENTS: EventWatch = EventWatch::new();

// The gateway admits one stream of the loopback session at a time, and the
// servlet holds the first answer until the coupler admits all three calls,
// so the calls past the one stream wait for it rather than fail at their
// send.
tb_scenario! {
	name: calls_past_the_streams_of_the_session_wait_for_a_stream,
	config: NarrowSessionSpec::latest().watched(&NARROW_SESSION_EVENTS),
	environment Cluster {
		context: Coupled::watched(&NARROW_SESSION_EVENTS),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, NarrowSessionEdge::stage)?;
			context.narrow_gateway::<NarrowSessionGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let signer = context.signer(&web);
			let place = PLACE.parse().map_err(edge_error)?;
			let held = Hold::Admitted(3).body();
			let mut calls = Vec::new();
			for _ in 0..3 {
				let claim = signer.sign(&place, &held).await?;
				let (channel, held) = (channel.clone(), held.clone());
				calls.push(async move { channel.call(PLACE, &held, Some(&claim)).await });
			}

			let answers = futures_util::future::join_all(calls).await;
			let answers = answers.into_iter().collect::<Result<Vec<_>, _>>()?;
			assert!(answers.iter().all(Result::is_ok), "every call MUST wait for the stream, got {answers:?}");

			cluster.stop();
			Ok(())
		}
	}
}

/// A spend or a forget that the store of a [`HeldStoreLedger`] committed,
/// whose answer it holds.
const STORE_HELD: Urn<'static> = urn!("test", "event:store/held");

/// A claim ledger whose store commits each spend and each forget, records
/// [`STORE_HELD`], and holds the answer until the scenario lets it answer, as
/// the client of a slow store that the replicas of an edge share does.
struct HeldStoreLedger {
	ledger: MemoryLedger,
	answers: Semaphore,
	trace: TraceCollector,
}

impl HeldStoreLedger {
	/// A store that holds every answer, and records on a trace of `events`.
	fn on(events: &'static EventWatch) -> Arc<Self> {
		Arc::new(Self { ledger: MemoryLedger::new(), answers: Semaphore::new(0), trace: events.trace() })
	}

	/// Let the store give the answer that it holds, or else its next answer.
	fn answer(&self) {
		self.answers.add_permits(1);
	}

	/// Record [`STORE_HELD`], then hold the answer until the scenario lets
	/// the store answer.
	async fn held(&self) -> Result<(), LedgerError> {
		self.trace.event(STORE_HELD).map_err(LedgerError::new)?;
		let answer = self.answers.acquire().await.map_err(LedgerError::new)?;
		answer.forget();
		Ok(())
	}
}

impl ClaimLedger for HeldStoreLedger {
	fn spend<'a>(&'a self, spend: &'a ClaimSpend, now: SystemTime) -> LedgerFuture<'a, bool> {
		Box::pin(async move {
			let taken = self.ledger.spend(spend, now).await?;
			self.held().await?;
			Ok(taken)
		})
	}

	fn forget<'a>(&'a self, spend: &'a ClaimSpend) -> LedgerFuture<'a, ()> {
		Box::pin(async move {
			self.ledger.forget(spend).await?;
			self.held().await
		})
	}
}

impl Coupled {
	/// Stage the orders edge through `stage`, with calls of at most
	/// [`CLOCKED_LIMIT`], which spends its claims in `ledger`.
	fn stage_expiring(
		&self,
		trace: &TraceCollector,
		stage: fn(Edge, Dial),
		ledger: Arc<dyn ClaimLedger>,
	) -> Result<(), TightBeamError> {
		let limits = CallLimits::default().with_timeout(CLOCKED_LIMIT);
		let coupler = self.orders(&self.answers, self.callers()?)?.with_claim_ledger(ledger);
		let coupler = coupler.with_call_limits(limits).map_err(edge_error)?;
		self.stage_coupler(trace, stage, coupler)
	}
}

coupled!(LateStoreEdge, LateStoreGateway);

tb_assert_spec! {
	/// A signed call whose ledger commits its spend and answers past the
	/// deadline of the call: the coupler forgets the spend at the deadline and
	/// refuses the call with 4, and the claim then serves the retry.
	pub LateStoreSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(2), equals!("signed")),
			(COUPLED_CLAIM_FORGOTTEN, exactly!(1), equals!("deadline")),
			(COUPLED_CALL_REFUSED, exactly!(1), equals!("deadline")),
			(COUPLED_CLAIM_SPENT, exactly!(1)),
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32))
		]
	}
}

/// The events of the scenario of a ledger that answers past the deadline.
static LATE_STORE_EVENTS: EventWatch = EventWatch::new();

// The ledger commits the spend of the signed call and holds its answer past
// the deadline of the call, which the spend then holds itself.
tb_scenario! {
	name: a_spend_whose_ledger_answers_past_the_deadline_forgets_its_claim,
	config: LateStoreSpec::latest().watched(&LATE_STORE_EVENTS),
	environment Cluster {
		context: (Coupled::clocked(&LATE_STORE_EVENTS), HeldStoreLedger::on(&LATE_STORE_EVENTS)),
		start: |SetupEnv { trace, context }| async move {
			context.0.stage_expiring(&trace, LateStoreEdge::stage, context.1.clone())?;
			context.0.gateway::<LateStoreGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.0.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (context, store) = (&context.0, &context.1);
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order-82").await?;
			let (signed, signed_claim) = (channel.clone(), claim.clone());
			let placed = tokio::spawn(async move { signed.call(PLACE, b"order-82", Some(&signed_claim)).await });

			// The store holds the spend past the deadline of the call, then
			// the forget that undoes it as well.
			LATE_STORE_EVENTS.recorded(STORE_HELD, 1).await?;
			context.clock.advance(CLOCKED_LIMIT)?;
			LATE_STORE_EVENTS.recorded(STORE_HELD, 2).await?;
			store.answer();

			let placed = placed.await.map_err(unexpected)??;
			assert_eq!(code_of(placed), Some(tonic::Code::DeadlineExceeded), "the held spend MUST pass the deadline");

			store.answer();

			let retried = channel.call(PLACE, b"order-82", Some(&claim)).await?;
			let retried = retried.map_err(|status| status.code());
			assert_eq!(retried.as_deref(), Ok(&b"served:order-82"[..]), "the claim of a spend past the deadline MUST serve the retry");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(StalledForgetEdge, StalledForgetGateway);

tb_assert_spec! {
	/// A signed call whose ledger holds its spend past the deadline of the
	/// call, and then holds the forget that undoes it past the call limit:
	/// the coupler refuses the call with 4 at the call limit of the forget,
	/// and records no forget.
	pub StalledForgetSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(1), equals!("signed")),
			(COUPLED_CLAIM_SPENT, exactly!(0)),
			(COUPLED_CLAIM_FORGOTTEN, exactly!(0)),
			(COUPLED_CALL_REFUSED, exactly!(1), equals!("deadline")),
			(COUPLED_CALL_ANSWERED, exactly!(0))
		]
	}
}

/// The events of the scenario of a forget that the store holds.
static STALLED_FORGET_EVENTS: EventWatch = EventWatch::new();

// The ledger holds the spend of the signed call past its deadline, then holds
// the forget that undoes the spend and never answers it.
tb_scenario! {
	name: a_forget_that_its_ledger_holds_past_the_call_limit_ends_its_call,
	config: StalledForgetSpec::latest().watched(&STALLED_FORGET_EVENTS),
	environment Cluster {
		context: (Coupled::clocked(&STALLED_FORGET_EVENTS), HeldStoreLedger::on(&STALLED_FORGET_EVENTS)),
		start: |SetupEnv { trace, context }| async move {
			context.0.stage_expiring(&trace, StalledForgetEdge::stage, context.1.clone())?;
			context.0.gateway::<StalledForgetGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.0.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let context = &context.0;
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order-84").await?;
			let placed = tokio::spawn(async move { channel.call(PLACE, b"order-84", Some(&claim)).await });

			// The deadline of the call passes while the store holds the spend,
			// and the call limit passes while it holds the forget.
			STALLED_FORGET_EVENTS.recorded(STORE_HELD, 1).await?;
			context.clock.advance(CLOCKED_LIMIT)?;
			STALLED_FORGET_EVENTS.recorded(STORE_HELD, 2).await?;
			context.clock.advance(CLOCKED_LIMIT)?;

			let placed = placed.await.map_err(unexpected)??;
			assert_eq!(code_of(placed), Some(tonic::Code::DeadlineExceeded), "a forget past the call limit MUST end its call");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(EndedSpendEdge, EndedSpendGateway);

tb_assert_spec! {
	/// A signed call that its caller ends while the ledger holds its spend:
	/// the coupler records it as cancelled, keeps the claim that the ledger
	/// took, and refuses the retry as a replay.
	pub EndedSpendSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(2), equals!("signed")),
			(COUPLED_CLAIM_SPENT, exactly!(0)),
			(COUPLED_CLAIM_FORGOTTEN, exactly!(0)),
			(COUPLED_CALL_REFUSED, exactly!(2)),
			(COUPLED_CALL_ANSWERED, exactly!(0))
		]
	}
}

/// The events of the scenario of a spend that its caller ends.
static ENDED_SPEND_EVENTS: EventWatch = EventWatch::new();

// The caller ends the signed call while the ledger holds the answer of its
// spend, which the ledger already took.
tb_scenario! {
	name: a_spend_that_its_caller_ends_in_the_ledger_keeps_its_claim,
	config: EndedSpendSpec::latest().watched(&ENDED_SPEND_EVENTS),
	environment Cluster {
		context: (Coupled::clocked(&ENDED_SPEND_EVENTS), HeldStoreLedger::on(&ENDED_SPEND_EVENTS)),
		start: |SetupEnv { trace, context }| async move {
			context.0.stage_expiring(&trace, EndedSpendEdge::stage, context.1.clone())?;
			context.0.gateway::<EndedSpendGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.0.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (context, store) = (&context.0, &context.1);
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order-83").await?;
			let (signed, signed_claim) = (channel.clone(), claim.clone());
			let placed = tokio::spawn(async move { signed.call(PLACE, b"order-83", Some(&signed_claim)).await });

			ENDED_SPEND_EVENTS.recorded(STORE_HELD, 1).await?;
			placed.abort();
			ENDED_SPEND_EVENTS.recorded(COUPLED_CALL_REFUSED, 1).await?;
			store.answer();

			let retried = channel.call(PLACE, b"order-83", Some(&claim)).await?;
			assert_eq!(code_of(retried), Some(tonic::Code::Unauthenticated), "the claim that the ledger took MUST stay spent");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(ExpiredSendEdge, ExpiredSendGateway);

tb_assert_spec! {
	/// A signed call and a held stream on a loopback session of one stream,
	/// which the stream takes while the ledger holds the spend of the call.
	/// The coupler refuses both at their deadlines, forgets the claim, and
	/// serves its retry.
	pub ExpiredSendSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(3)),
			(COUPLED_CLAIM_SPENT, exactly!(2)),
			(COUPLED_CLAIM_FORGOTTEN, exactly!(1), equals!("unsent")),
			(COUPLED_CALL_REFUSED, exactly!(2), equals!("deadline")),
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32))
		]
	}
}

/// The events of the scenario of a send that waits out its deadline.
static EXPIRED_SEND_EVENTS: EventWatch = EventWatch::new();

// On a loopback session of one stream, a held stream takes the one stream
// while the ledger holds the spend of the signed call. Once the ledger
// answers, the signed call waits for the stream past its deadline.
tb_scenario! {
	name: a_send_whose_deadline_passes_while_it_waits_for_a_stream_forgets_its_claim,
	config: ExpiredSendSpec::latest().watched(&EXPIRED_SEND_EVENTS),
	environment Cluster {
		context: (Coupled::clocked(&EXPIRED_SEND_EVENTS), HeldStoreLedger::on(&EXPIRED_SEND_EVENTS)),
		start: |SetupEnv { trace, context }| async move {
			context.0.stage_expiring(&trace, ExpiredSendEdge::stage, context.1.clone())?;
			context.0.narrow_gateway::<ExpiredSendGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.0.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (context, store) = (&context.0, &context.1);
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order-80").await?;
			let (signed, signed_claim) = (channel.clone(), claim.clone());
			let placed = tokio::spawn(async move { signed.call(PLACE, b"order-80", Some(&signed_claim)).await });
			EXPIRED_SEND_EVENTS.recorded(STORE_HELD, 1).await?;

			let streamed = channel.clone();
			let stream = tokio::spawn(async move {
				let held = Hold::Refused(2).body();
				streamed.stream(HOLD, &[held.as_slice()], None).await
			});

			// The servlet admits the head of the stream, which holds the one
			// stream of the session from then on.
			EXPIRED_SEND_EVENTS.recorded(SERVED_ASSURANCE, 1).await?;
			store.answer();

			// The send of the signed call waits for the stream past its spend
			// and its deadline, and the store holds the forget that undoes the
			// spend.
			EXPIRED_SEND_EVENTS.recorded(COUPLED_CLAIM_SPENT, 1).await?;
			context.clock.advance(CLOCKED_LIMIT)?;
			EXPIRED_SEND_EVENTS.recorded(STORE_HELD, 2).await?;
			store.answer();

			let placed = placed.await.map_err(unexpected)??;
			assert_eq!(code_of(placed), Some(tonic::Code::DeadlineExceeded), "the signed call MUST pass its deadline");

			let stream = stream.await.map_err(unexpected)??;
			assert_eq!(code_of(stream), Some(tonic::Code::DeadlineExceeded), "the held stream MUST pass its deadline");

			store.answer();

			let retried = channel.call(PLACE, b"order-80", Some(&claim)).await?;
			let retried = retried.map_err(|status| status.code());
			assert_eq!(retried.as_deref(), Ok(&b"served:order-80"[..]), "the claim of a send that never left MUST serve the retry");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(StalledReleaseEdge, StalledReleaseGateway);

tb_assert_spec! {
	/// As the scenario of a send that waits out its deadline, where the
	/// ledger then holds the forget of the release past the call limit: the
	/// coupler refuses both calls with 4, the signed call at the call limit of
	/// the forget, and records no forget.
	pub StalledReleaseSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(2)),
			(COUPLED_CLAIM_SPENT, exactly!(1)),
			(COUPLED_CLAIM_FORGOTTEN, exactly!(0)),
			(COUPLED_CALL_REFUSED, exactly!(2), equals!("deadline")),
			(COUPLED_CALL_ANSWERED, exactly!(0))
		]
	}
}

/// The events of the scenario of a release whose forget the store holds.
static STALLED_RELEASE_EVENTS: EventWatch = EventWatch::new();

// On a loopback session of one stream, a held stream takes the one stream
// while the ledger holds the spend of the signed call. The send then waits
// out its deadline, and the ledger holds the forget of its release and never
// answers it.
tb_scenario! {
	name: a_release_whose_forget_its_ledger_holds_past_the_call_limit_ends_its_call,
	config: StalledReleaseSpec::latest().watched(&STALLED_RELEASE_EVENTS),
	environment Cluster {
		context: (Coupled::clocked(&STALLED_RELEASE_EVENTS), HeldStoreLedger::on(&STALLED_RELEASE_EVENTS)),
		start: |SetupEnv { trace, context }| async move {
			context.0.stage_expiring(&trace, StalledReleaseEdge::stage, context.1.clone())?;
			context.0.narrow_gateway::<StalledReleaseGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.0.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (context, store) = (&context.0, &context.1);
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order-85").await?;
			let signed = channel.clone();
			let placed = tokio::spawn(async move { signed.call(PLACE, b"order-85", Some(&claim)).await });
			STALLED_RELEASE_EVENTS.recorded(STORE_HELD, 1).await?;

			let stream = tokio::spawn(async move {
				let held = Hold::Refused(2).body();
				channel.stream(HOLD, &[held.as_slice()], None).await
			});

			// The servlet admits the head of the stream, which holds the one
			// stream of the session from then on.
			STALLED_RELEASE_EVENTS.recorded(SERVED_ASSURANCE, 1).await?;
			store.answer();

			// The send waits for the stream past its deadline, and the call
			// limit passes while the store holds the forget of its release.
			STALLED_RELEASE_EVENTS.recorded(COUPLED_CLAIM_SPENT, 1).await?;
			context.clock.advance(CLOCKED_LIMIT)?;
			STALLED_RELEASE_EVENTS.recorded(STORE_HELD, 2).await?;
			context.clock.advance(CLOCKED_LIMIT)?;

			let placed = placed.await.map_err(unexpected)??;
			assert_eq!(code_of(placed), Some(tonic::Code::DeadlineExceeded), "a release past the call limit MUST end its call");

			let stream = stream.await.map_err(unexpected)??;
			assert_eq!(code_of(stream), Some(tonic::Code::DeadlineExceeded), "the held stream MUST pass its deadline");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(CancelledSendEdge, CancelledSendGateway);

tb_assert_spec! {
	/// The scenario of a send that waits for a stream past its spend, where
	/// the caller ends the signed call first: the coupler records it as
	/// cancelled, keeps its claim spent, and refuses the retry as a replay.
	pub CancelledSendSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(3)),
			(COUPLED_CLAIM_SPENT, exactly!(1)),
			(COUPLED_CLAIM_FORGOTTEN, exactly!(0)),
			(COUPLED_CALL_REFUSED, exactly!(3)),
			(COUPLED_CALL_ANSWERED, exactly!(0))
		]
	}
}

/// The events of the scenario of a send that its caller ends past its spend.
static CANCELLED_SEND_EVENTS: EventWatch = EventWatch::new();

// As in the scenario of a send that waits out its deadline, the signed call
// waits for the one stream past its spend. Its caller ends it there, so the
// claim stays spent.
tb_scenario! {
	name: a_send_that_its_caller_ends_past_its_spend_keeps_its_claim,
	config: CancelledSendSpec::latest().watched(&CANCELLED_SEND_EVENTS),
	environment Cluster {
		context: (Coupled::clocked(&CANCELLED_SEND_EVENTS), HeldStoreLedger::on(&CANCELLED_SEND_EVENTS)),
		start: |SetupEnv { trace, context }| async move {
			context.0.stage_expiring(&trace, CancelledSendEdge::stage, context.1.clone())?;
			context.0.narrow_gateway::<CancelledSendGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.0.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (context, store) = (&context.0, &context.1);
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order-81").await?;
			let (signed, signed_claim) = (channel.clone(), claim.clone());
			let placed = tokio::spawn(async move { signed.call(PLACE, b"order-81", Some(&signed_claim)).await });
			CANCELLED_SEND_EVENTS.recorded(STORE_HELD, 1).await?;

			let streamed = channel.clone();
			let stream = tokio::spawn(async move {
				let held = Hold::Refused(2).body();
				streamed.stream(HOLD, &[held.as_slice()], None).await
			});

			// The stream holds the one stream of the session once the servlet
			// admits its head, so the signed call waits for it past its spend.
			CANCELLED_SEND_EVENTS.recorded(SERVED_ASSURANCE, 1).await?;
			store.answer();
			CANCELLED_SEND_EVENTS.recorded(COUPLED_CLAIM_SPENT, 1).await?;
			placed.abort();
			CANCELLED_SEND_EVENTS.recorded(COUPLED_CALL_REFUSED, 1).await?;
			context.clock.advance(CLOCKED_LIMIT)?;

			let stream = stream.await.map_err(unexpected)??;
			assert_eq!(code_of(stream), Some(tonic::Code::DeadlineExceeded), "the held stream MUST pass its deadline");

			store.answer();
			let retried = channel.call(PLACE, b"order-81", Some(&claim)).await?;
			assert_eq!(code_of(retried), Some(tonic::Code::Unauthenticated), "the claim of a send that its caller ended MUST stay spent");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(UnansweredEdge, UnansweredGateway);

tb_assert_spec! {
	/// A signed call whose servlet admits it and holds its answer past the
	/// deadline: the coupler refuses it with 4 and keeps its claim spent, so
	/// it refuses the retry of the claim as a replay.
	pub UnansweredSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(2)),
			(SERVED_ASSURANCE, exactly!(1), equals!("signed")),
			(COUPLED_CALL_REFUSED, exactly!(2)),
			(COUPLED_CALL_ANSWERED, exactly!(0))
		]
	}
}

/// The events of the scenario of a send whose reply passes its deadline.
static UNANSWERED_EVENTS: EventWatch = EventWatch::new();

// The servlet admits the signed call, so its frame left, and holds the answer
// until the coupler refuses the call at its deadline.
tb_scenario! {
	name: a_send_whose_reply_passes_its_deadline_keeps_its_claim,
	config: UnansweredSpec::latest().watched(&UNANSWERED_EVENTS),
	environment Cluster {
		context: Coupled::clocked(&UNANSWERED_EVENTS),
		start: |SetupEnv { trace, context }| async move {
			context.stage_expiring(&trace, UnansweredEdge::stage, Arc::new(MemoryLedger::new()))?;
			context.gateway::<UnansweredGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let held = Hold::Refused(1).body();
			let claim = context.claim(&web, PLACE, &held).await?;

			let placing = (channel.clone(), held.clone(), claim.clone());
			let placed = tokio::spawn(async move {
				let (channel, held, claim) = placing;
				channel.call(PLACE, &held, Some(&claim)).await
			});
			UNANSWERED_EVENTS.recorded(SERVED_ASSURANCE, 1).await?;
			context.clock.advance(CLOCKED_LIMIT)?;
			let placed = placed.await.map_err(unexpected)??;
			assert_eq!(code_of(placed), Some(tonic::Code::DeadlineExceeded), "the held call MUST pass its deadline");

			let retried = channel.call(PLACE, &held, Some(&claim)).await?;
			assert_eq!(code_of(retried), Some(tonic::Code::Unauthenticated), "the claim of a send that left MUST stay spent");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(NamelessChainEdge, NamelessChainGateway);

tb_assert_spec! {
	/// Calls under a bearer token that the edge trusts, each on a client chain
	/// that names no principal: the coupler refuses each as unauthenticated,
	/// before any grant is read.
	pub NamelessChainSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_REFUSED, exactly!(3), equals!("unauthenticated")),
			(COUPLED_CALL_ADMITTED, exactly!(0)),
			(events::CLUSTER_WORK_ROUTED, exactly!(0))
		]
	}
}

// A verified client chain that names no principal refuses its call with 16,
// though the call carries a bearer token that the edge trusts.
tb_scenario! {
	name: a_client_chain_that_names_no_principal_refuses_beside_a_trusted_token,
	spec: NamelessChainSpec,
	environment Cluster {
		context: (Coupled::mint(), issuer()),
		start: |SetupEnv { trace, context }| async move {
			let bearer = BearerTrust::from_jwks("acme", AUDIENCE, &jwks(&context.1)).map_err(edge_error)?;
			let callers = context.0.callers()?.with_bearer(bearer);
			context.0.stage_trusting(&trace, NamelessChainEdge::stage, callers)?;
			context.0.gateway::<NamelessChainGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.0.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (context, issuer) = (&context.0, &context.1);
			let bearer = format!("Bearer {}", mobile_token(issuer, TOKEN_LIFETIME)?);
			let token = [Field { key: "authorization", value: bearer }];
			for id in ["spiffe:///orders", "spiffe://acme", "spiffe://acme/"] {
				let nameless = context.caller("CN=nameless,O=acme,C=US", Some(id));
				let channel = context.channel(&WorkClient::edge_of(&cluster)?, Some(&nameless)).await?;
				channel.serving(&context.clock).await?;

				let browsed = channel.call_with(BROWSE, b"order", &token, None).await?;
				assert_eq!(code_of(browsed), Some(tonic::Code::Unauthenticated), "{id} MUST name no caller");
			}

			cluster.stop();
			Ok(())
		}
	}
}
/// The streams that one scenario of a servlet that ends its stream early
/// opens.
const EARLY_ENDS: u32 = 16;

/// The requests that follow the first request of a stream that floods: more
/// than the credit of the stream carries.
const LATE_REQUESTS: usize = 512;

/// A bidirectional streaming method whose servlet answers outside the stream
/// library: it fails the stream once its head arrives, then fails its handler
/// while its caller may still send.
const ABRUPT: &str = "/orders.v1.Orders/Abrupt";

/// A bidirectional streaming method whose servlet answers outside the stream
/// library: it fails the stream once its head arrives, reads the requests to
/// their end, then keeps its handler until its caller read the status.
const LINGER: &str = "/orders.v1.Orders/Linger";

/// A servlet of [`LINGER`] whose requests ended after its last answer part.
const SERVLET_RELEASED: Urn<'static> = urn!("test", "event:servlet/released");

/// A caller that read the status of a stream of [`LINGER`].
const CALLER_READ: Urn<'static> = urn!("test", "event:caller/read");

servlet! {
	/// Fails each coupled stream with [`DETAILS`] once its head arrives,
	/// outside the stream library, then fails its handler with 10, so the
	/// stream fails after its last answer part.
	pub AbruptServlet<CoupledCall, EnvConfig = OrdersEnv>,
	protocol: WsListener,
	handle: |_call, _frame, _ctx| async move { Ok(None) },
	duplex: |body, reply, ctx| async move {
		let (mut body, mut reply) = (body, reply);
		end_at_head(&mut body, &mut reply, ctx.env_config().signer.clone()).await?;
		Err(tightbeam::transport::TransportError::from(TransitStatus::Aborted).into())
	}
}

servlet! {
	/// Fails each coupled stream with [`DETAILS`] once its head arrives,
	/// outside the stream library, reads the requests to their end, then
	/// keeps its handler until its caller read the status, so the stream
	/// ends after the deadline of the coupler.
	pub LingerServlet<CoupledCall, EnvConfig = OrdersEnv>,
	protocol: WsListener,
	handle: |_call, _frame, _ctx| async move { Ok(None) },
	duplex: |body, reply, ctx| async move {
		let env = ctx.env_config();
		let (mut body, mut reply) = (body, reply);
		end_at_head(&mut body, &mut reply, env.signer.clone()).await?;
		while body.chunk().await?.is_some() {}
		env.trace.event(SERVLET_RELEASED)?;
		Ok(env.events.recorded(CALLER_READ, 1).await?)
	}
}

/// Answer the stream of `body` on `reply` with an end part signed under
/// `signer`, which fails it with [`DETAILS`], once its head arrives.
async fn end_at_head(
	body: &mut tightbeam::transport::multiplex::StreamBody,
	reply: &mut tightbeam::transport::multiplex::ReplySink,
	signer: SigningIdentity,
) -> Result<(), TightBeamError> {
	let mut read = PartFrames::new(OUT_OF_SHAPE_CEILING);
	let head = loop {
		if let Some(head) = read.next_frame()? {
			break head;
		}

		let chunk = body
			.chunk()
			.await?
			.ok_or_else(|| unexpected("the stream ended before its head"))?;
		read.extend(&chunk);
	};

	let status = Status::with_details(Code::FailedPrecondition, "ended", DETAILS.into());
	let mut answers = StreamParts::after(&head, signer, OUT_OF_SHAPE_CEILING);
	reply.push(&answers.end(&status).await?).await?;
	Ok(())
}

impl Coupled {
	/// The coupler under `limits` that routes [`ABRUPT`] and [`LINGER`] to
	/// their servlets for the web caller.
	fn raw_coupler(&self, limits: CallLimits) -> Result<Coupler, TightBeamError> {
		let web = Principal::subject(WEB).map_err(edge_error)?;
		let (mut routes, mut grants) = (Routes::new(), Grants::deny_all());
		for (method, servlet) in [(ABRUPT, "orders-abrupt"), (LINGER, "orders-linger")] {
			let servlet = Servlet::new(WorkClient::servlet(servlet)?, self.answers.certificate().clone());
			routes = routes
				.bidi_stream(method, servlet.map_err(edge_error)?, Assurance::Vouched)
				.map_err(edge_error)?;
			grants = grants.grant(web.clone(), method).map_err(edge_error)?;
		}

		self.coupler(routes, grants)?.with_call_limits(limits).map_err(edge_error)
	}

	/// The hive that hosts [`AbruptServlet`] and [`LingerServlet`], which
	/// record on `trace`.
	async fn raw_hive(&self, trace: &TraceCollector) -> Result<OrdersHive, TightBeamError> {
		let admission = AdmissionTrust::new().with_vouchers(self.vouching.trust_anchor()?);
		let signer = self.answers.signing_identity();
		let env = Arc::new(OrdersEnv { admission, signer, trace: trace.share(), events: self.events });
		let abrupt =
			AbruptServlet::start(Arc::new(trace.share()), self.transport.servlet_config(Arc::clone(&env))).await?;
		let linger = LingerServlet::start(Arc::new(trace.share()), self.transport.servlet_config(env)).await?;

		let mut hive = OrdersHive::new(Some(self.transport.hive_config()?))?;
		let restart = |_trace| async { Err(TightBeamError::MissingConfiguration) };
		hive.register(WorkClient::servlet("orders-abrupt")?, abrupt, restart)?;
		let restart = |_trace| async { Err(TightBeamError::MissingConfiguration) };
		hive.register(WorkClient::servlet("orders-linger")?, linger, restart)?;
		hive.establish(Arc::new(trace.share())).await?;
		Ok(hive)
	}
}

/// Open a bidi stream of `method` on `channel`, under `claim` when it is
/// `Some`, that sends `requests` and then holds its requests open, and read
/// the status that ends its answer.
async fn held_open(
	channel: &StockChannel,
	method: &'static str,
	requests: &[&[u8]],
	claim: Option<&CallClaim>,
) -> Result<Status, TightBeamError> {
	let mut grpc = channel.client().await?;
	let (sender, queued) = tokio::sync::mpsc::channel::<Vec<u8>>(requests.len().max(1));
	for message in requests {
		sender.send(message.to_vec()).await.map_err(unexpected)?;
	}

	let mut request = Request::new(ReceiverStream::new(queued));
	if let Some(claim) = claim {
		claim.attach(request.metadata_mut());
	}

	let response = bounded(grpc.streaming(request, PathAndQuery::from_static(method), RawCodec)).await?;
	let mut answers = response.map_err(unexpected)?.into_inner();
	let ended = bounded(answers.message()).await?.err();
	drop(sender);
	ended.ok_or_else(|| unexpected("the servlet answered a stream it failed"))
}

coupled!(HeldOpenEdge, HeldOpenGateway);

tb_assert_spec! {
	/// Bidi streams that the servlet fails at their first request while their
	/// callers hold their requests open: the coupler answers each with the
	/// status of the servlet, and none of them fails on the gateway.
	pub HeldOpenSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ANSWERED, exactly!(EARLY_ENDS), equals!(9u32)),
			(COUPLED_CALL_REFUSED, exactly!(0))
		]
	}
}

// The servlet fails each bidi stream at its first request while the caller
// holds its requests open. The servlet holds the stream until the coupler
// ends the requests, so the caller reads the status of the servlet each time,
// and the gateway keeps routing the servlet.
tb_scenario! {
	name: a_stream_that_its_caller_holds_open_answers_the_status_of_its_servlet,
	spec: HeldOpenSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, HeldOpenEdge::stage)?;
			context.gateway::<HeldOpenGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			for _ in 0..EARLY_ENDS {
				let claim = context.claim(&web, CHAT, b"").await?;
				let status = held_open(&channel, CHAT, &[FAILING], Some(&claim)).await?;
				assert_eq!(status.code(), tonic::Code::FailedPrecondition, "the caller MUST read the status of the servlet");
				assert_eq!(status.details(), DETAILS, "the details MUST reach the caller");
			}

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(FloodedEdge, FloodedGateway);

// The servlet fails each bidi stream at its first request while the caller
// still streams. The servlet holds the stream until the coupler ends the
// requests, so no request lands on a stream that the servlet ended: the
// caller reads the status of the servlet each time, and the gateway keeps
// routing the servlet.
tb_scenario! {
	name: a_stream_that_its_caller_floods_answers_the_status_of_its_servlet,
	spec: HeldOpenSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, FloodedEdge::stage)?;
			context.gateway::<FloodedGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { leaf: web, channel } = context.web(&cluster).await?;
			let late = vec![b"late".as_slice(); LATE_REQUESTS];
			let requests = [&[FAILING][..], &late].concat();
			for _ in 0..EARLY_ENDS {
				let claim = context.claim(&web, CHAT, b"").await?;
				let ended = channel.stream(CHAT, &requests, Some(&claim)).await?;
				let status = ended.err().ok_or_else(|| unexpected("the servlet answered a stream it failed"))?;
				assert_eq!(status.code(), tonic::Code::FailedPrecondition, "the caller MUST read the status of the servlet");
				assert_eq!(status.details(), DETAILS, "the details MUST reach the caller");
			}

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(AbruptHeldEdge, AbruptHeldGateway);

tb_assert_spec! {
	/// A stream that a servlet outside the stream library fails while its
	/// caller holds its requests open: the coupler answers it with the status
	/// of its last answer part.
	pub AbruptHeldSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(9u32)),
			(COUPLED_CALL_REFUSED, exactly!(0))
		]
	}
}

// The servlet fails the stream once its head arrives, then fails its handler,
// while the caller holds its requests open, so the stream fails with 10 after
// its last answer part. The caller reads the status of that part.
tb_scenario! {
	name: a_failure_of_a_stream_after_its_last_answer_part_leaves_the_status_to_that_part,
	spec: AbruptHeldSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage_coupler(&trace, AbruptHeldEdge::stage, context.raw_coupler(CallLimits::default())?)?;
			context.gateway::<AbruptHeldGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.raw_hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let status = held_open(&channel, ABRUPT, &[], None).await?;
			assert_eq!(status.code(), tonic::Code::FailedPrecondition, "the caller MUST read the status of the last part");
			assert_eq!(status.details(), DETAILS, "the details MUST reach the caller");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(AbruptFloodEdge, AbruptFloodGateway);

tb_assert_spec! {
	/// Streams that a servlet outside the stream library fails while their
	/// callers still send: the coupler answers or refuses each with a status
	/// that its stream carried, and refuses none as unavailable.
	pub AbruptFloodSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ANSWERED, tightbeam::at_most!(EARLY_ENDS), equals!(9u32)),
			(COUPLED_CALL_REFUSED, tightbeam::at_most!(EARLY_ENDS), equals!("transit"))
		]
	}
}

// The servlet fails each stream once its head arrives, then fails its
// handler, while the caller still streams, so the requests that follow meet a
// stream that the servlet ended. The status of each call is the one that its stream carried:
// the last answer part, or the status that the gateway ended the stream with.
tb_scenario! {
	name: requests_that_meet_a_stream_its_servlet_ended_leave_the_status_to_the_stream,
	spec: AbruptFloodSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage_coupler(&trace, AbruptFloodEdge::stage, context.raw_coupler(CallLimits::default())?)?;
			context.gateway::<AbruptFloodGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.raw_hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let requests = vec![b"late".as_slice(); LATE_REQUESTS];
			for _ in 0..EARLY_ENDS {
				let ended = channel.stream(ABRUPT, &requests, None).await?;
				let status = ended.err().ok_or_else(|| unexpected("the servlet answered a stream it failed"))?;
				assert_ne!(status.code(), tonic::Code::Unavailable, "a severed request MUST leave the status to its stream");
			}

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(LingerEdge, LingerGateway);

tb_assert_spec! {
	/// A stream whose deadline passes after its last answer part, while its
	/// servlet keeps its handler: the coupler answers it with the status of
	/// that part.
	pub LingerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(SERVLET_RELEASED, exactly!(1)),
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(9u32)),
			(COUPLED_CALL_REFUSED, exactly!(0))
		]
	}
}

/// The events of the scenario of a deadline that passes after the last
/// answer part.
static LINGER_EVENTS: EventWatch = EventWatch::new();

// The servlet fails the stream once its head arrives and keeps its handler
// after the coupler ends the requests, so the stream does not end. The clock
// of the edge then passes the deadline of the call, after the last answer
// part decided it. The caller reads the status of that part.
tb_scenario! {
	name: a_deadline_that_passes_after_the_last_answer_part_leaves_the_status_to_that_part,
	config: LingerSpec::latest().watched(&LINGER_EVENTS),
	environment Cluster {
		context: Coupled::clocked(&LINGER_EVENTS),
		start: |SetupEnv { trace, context }| async move {
			let limits = CallLimits::default().with_timeout(CLOCKED_LIMIT);
			context.stage_coupler(&trace, LingerEdge::stage, context.raw_coupler(limits)?)?;
			context.gateway::<LingerGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.raw_hive(&trace).await }],
		client: |ClusterEnv { trace, context, cluster }| async move {
			let WebCaller { channel, .. } = context.web(&cluster).await?;
			let reading = tokio::spawn(async move { held_open(&channel, LINGER, &[], None).await });
			LINGER_EVENTS.recorded(SERVLET_RELEASED, 1).await?;
			context.clock.advance(CLOCKED_LIMIT)?;

			let status = reading.await.map_err(unexpected)??;
			trace.event(CALLER_READ)?;
			assert_eq!(status.code(), tonic::Code::FailedPrecondition, "the caller MUST read the status of the last part");
			assert_eq!(status.details(), DETAILS, "the details MUST reach the caller");

			cluster.stop();
			Ok(())
		}
	}
}
