//! Stock gRPC callers through a coupled edge to a colony servlet.
//!
//! `Get` and `List` require `Vouched`, and `Place` requires `Signed`. The
//! billing caller holds `Get`, and the web caller holds all three.

// The colony runtime macros expand `cfg(feature = ...)` probes against the
// invoking crate's feature namespace. Those upstream feature names do not
// exist in this crate, so the leaked cfg warnings carry no signal here.
#![allow(unexpected_cfgs)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use http::uri::PathAndQuery;
use tightbeam::colony::hive::Hive;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::instrumentation::events;
use tightbeam::testing::macros::BuiltAssertSpec;
use tightbeam::testing::{ClusterEnv, ScenarioConfig, ScenarioConfigError, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::urn::Urn;
use tightbeam::{exactly, hive, servlet, tb_assert_spec, tb_process_spec, tb_scenario, urn, TightBeamError};
use tightbeam_grpc::couple::{
	AdmissionTrust, AdmittedCall, Assurance, Code, CoupledCall, Coupler, Grants, Principal, Routes, Servlet,
};
use tightbeam_grpc::edge::{Dial, Edge};
use tightbeam_grpc::events::{COUPLED_CALL_ADMITTED, COUPLED_CALL_ANSWERED, COUPLED_CALL_REFUSED, TUNNEL_REFUSED};
use tightbeam_grpc::protocol::HEALTH_CHECK_PATH;
use tightbeam_ws::testing::{Identity, WorkClient};
use tonic::Request;

use support::{
	call, call_within, code_of, edge_error, edge_of, rejected_by, serving, unexpected, Coupled, RawCodec, BILLING, WEB,
};

/// The method that requires `Vouched`.
const GET: &str = "/orders.v1.Orders/Get";

/// The method that requires `Signed`.
const PLACE: &str = "/orders.v1.Orders/Place";

/// A method that requires `Vouched`, granted to the web caller alone.
const LIST: &str = "/orders.v1.Orders/List";

/// The body of a call that the servlet serves slowly, so it holds the
/// loopback session of a gateway that offers no mux.
const SLOW: &[u8] = b"slow";

/// How long the servlet takes to serve a slow call.
const SLOW_SERVICE: Duration = Duration::from_millis(1000);

/// The assurance that the servlet admitted a call with, which the servlet
/// records itself.
const SERVED_ASSURANCE: Urn<'static> = urn!("test", "event:servlet/assurance");

/// What the servlet of the orders service admits and signs with, and the
/// trace it records the assurance of each call on.
struct OrdersEnv {
	admission: AdmissionTrust,
	signer: SigningIdentity,
	trace: TraceCollector,
}

servlet! {
	/// Serves each coupled call that it admits with `served:` and the body of
	/// the call, signed under the answer identity of the scenario.
	pub OrdersServlet<CoupledCall, EnvConfig = OrdersEnv>,
	protocol: TokioListener,
	handle: |_call, frame, ctx| async move {
		let env = ctx.env_config();
		let admitted = AdmittedCall::admit(&frame, &env.admission)?;
		let assurance = match admitted.assurance() {
			Assurance::Vouched => "vouched",
			Assurance::Signed => "signed",
		};

		env.trace.event_with(SERVED_ASSURANCE, &[], assurance)?;
		if admitted.body() == SLOW {
			tokio::time::sleep(SLOW_SERVICE).await;
		}

		let body = [b"served:".as_slice(), admitted.body()].concat();
		admitted.reply(Code::Ok, body, &env.signer).await
	}
}

hive! {
	/// The hive that hosts the orders servlet over the TCP colony.
	pub OrdersHive,
	protocol: TokioListener
}

/// The orders service of a scenario: its routes, its grants, and its hive.
trait Orders {
	/// The servlet type of the orders service.
	fn servlet() -> Result<Urn<'static>, TightBeamError> {
		Ok(WorkClient::servlet("orders")?)
	}

	/// The coupler of the orders service, which pins the certificate of
	/// `answers` as the signer of each answer, and records on `trace`.
	fn orders(&self, trace: &TraceCollector, answers: &Identity) -> Result<Coupler, TightBeamError>;

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

	/// Start the hive that hosts the orders servlet, which trusts `vouchers`
	/// as its vouchers and `claims` as its direct callers and claim signers.
	async fn hive_trusting(
		&self,
		trace: &TraceCollector,
		vouchers: &Identity,
		claims: &Identity,
	) -> Result<OrdersHive, TightBeamError>;

	/// Start the hive that hosts the orders servlet, which trusts the voucher
	/// and the claim identity of the scenario.
	async fn hive(&self, trace: &TraceCollector) -> Result<OrdersHive, TightBeamError>;
}

impl Orders for Coupled {
	fn orders(&self, trace: &TraceCollector, answers: &Identity) -> Result<Coupler, TightBeamError> {
		let orders = Servlet::new(Self::servlet()?, answers.certificate().clone()).map_err(edge_error)?;
		let routes = Routes::new()
			.unary(GET, orders.clone(), Assurance::Vouched)
			.map_err(edge_error)?;
		let routes = routes.unary(LIST, orders.clone(), Assurance::Vouched).map_err(edge_error)?;
		let routes = routes.unary(PLACE, orders, Assurance::Signed).map_err(edge_error)?;

		let billing = Principal::spiffe(BILLING).map_err(edge_error)?;
		let web = Principal::subject(WEB).map_err(edge_error)?;
		let grants = Grants::deny_all()
			.grant(billing, GET)
			.grant(web.clone(), GET)
			.grant(web.clone(), LIST);
		let grants = grants.grant(web, PLACE);

		self.coupler(trace, routes, grants)
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
		let coupler = self.orders(trace, answers)?;
		self.stage_coupler(stage, coupler)
	}

	async fn hive_trusting(
		&self,
		trace: &TraceCollector,
		vouchers: &Identity,
		claims: &Identity,
	) -> Result<OrdersHive, TightBeamError> {
		let admission = AdmissionTrust::new(vouchers.trust_anchor()?, claims.trust_anchor()?, claims.trust_anchor()?);
		let env = Arc::new(OrdersEnv { admission, signer: self.answers.signing_identity()?, trace: trace.share() });
		let config = self.transport.servlet_config(env)?;
		let served = OrdersServlet::start(Arc::new(trace.share()), config).await?;

		let mut hive = OrdersHive::new(Some(self.transport.hive_config()?))?;
		let restart = |_trace| async { Err(TightBeamError::MissingConfiguration) };
		hive.register(Self::servlet()?, served, restart)?;
		hive.establish(Arc::new(trace.share())).await?;
		Ok(hive)
	}

	async fn hive(&self, trace: &TraceCollector) -> Result<OrdersHive, TightBeamError> {
		self.hive_trusting(trace, &self.vouching, &self.claims).await
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
			let answer = call(&channel, GET, b"order-7", None).await;
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
			let (web, channel) = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order-8").await?;

			let answer = call(&channel, PLACE, b"order-8", Some(&claim)).await.map_err(|status| status.code());
			assert_eq!(answer.as_deref(), Ok(&b"served:order-8"[..]), "a signed call MUST reach the servlet");

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

// A caller with no client certificate connects, but its coupled call refuses with 16.
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
			let channel = context.channel(&edge_of(&cluster)?, None).await?;
			serving(&channel).await?;

			let answer = call(&channel, "/orders.v1.Orders/Unrouted", b"order", None).await;
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
			let answer = call(&channel, LIST, b"order", None).await;
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
			let (_web, channel) = context.web(&cluster).await?;
			let answer = call(&channel, PLACE, b"order", None).await;
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
			let billing = context.caller("CN=billing,O=acme,C=US", Some(BILLING));
			let channel = context.channel(&edge_of(&cluster)?, Some(&billing)).await?;
			serving(&channel).await?;

			let claim = context.claim(&billing, GET, b"order").await?;
			let answer = call(&channel, GET, b"order", Some(&claim)).await;
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
			let (web, channel) = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order-1").await?;
			let answer = call(&channel, PLACE, b"order-2", Some(&claim)).await;
			assert_eq!(code_of(answer), Some(tonic::Code::Unauthenticated));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(OtherLeafEdge, OtherLeafGateway);
refused_spec!(OtherLeafSpec, "claim-refused", 0);

// The web caller signs its claim bound to another TLS certificate of its own,
// so the claim cannot move to the connection it arrives on.
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
			let (_web, channel) = context.web(&cluster).await?;
			let elsewhere = context.caller(WEB, None);
			let claim = context.claim(&elsewhere, PLACE, b"order").await?;

			let answer = call(&channel, PLACE, b"order", Some(&claim)).await;
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
			let (web, channel) = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order").await?;

			let first = call(&channel, PLACE, b"order", Some(&claim)).await;
			assert!(first.is_ok(), "the first spend of a claim MUST serve, got {first:?}");

			let replayed = call(&channel, PLACE, b"order", Some(&claim)).await;
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
			let answer = call(&channel, "/orders.v1.Orders/Cancel", b"order", None).await;
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
			let answer = call(&channel, GET, b"order", None).await;
			assert_eq!(code_of(answer), Some(tonic::Code::Internal));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(ConcurrentEdge, ConcurrentGateway);

tb_assert_spec! {
	/// Eight calls at once on one connection: each one is admitted, routed,
	/// and answered.
	pub ConcurrentSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(8)),
			(events::CLUSTER_WORK_ROUTED, exactly!(8)),
			(COUPLED_CALL_ANSWERED, exactly!(8)),
			(COUPLED_CALL_REFUSED, exactly!(0))
		]
	}
}

// One connection of the billing caller carries eight calls at once, which
// the gateway multiplexes on the loopback session.
tb_scenario! {
	name: one_connection_carries_concurrent_coupled_calls,
	spec: ConcurrentSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, ConcurrentEdge::stage)?;
			context.gateway::<ConcurrentGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.billing(&cluster).await?;
			let calls = (0..8).map(|index| {
				let channel = channel.clone();
				async move { call(&channel, GET, format!("order-{index}").as_bytes(), None).await }
			});

			let answers = futures_util::future::join_all(calls).await;
			assert!(answers.iter().all(Result::is_ok), "every concurrent call MUST answer, got {answers:?}");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(LaneKindEdge, LaneKindGateway);
refused_spec!(LaneKindSpec, "unavailable", 0);

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
			let billing = context.caller("CN=billing,O=acme,C=US", Some(BILLING));
			let channel = context.channel(&edge_of(&cluster)?, Some(&billing)).await?;
			let mut tunnel = tonic::client::Grpc::new(channel.clone());
			tunnel.ready().await.map_err(unexpected)?;

			let (_hold, waiting) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
			let requests = Request::new(tokio_stream::wrappers::ReceiverStream::new(waiting));
			let path = PathAndQuery::from_static(tightbeam_grpc::protocol::TUNNEL_PATH);
			let _tunnel = tokio::spawn(async move { tunnel.streaming(requests, path, RawCodec).await });

			tokio::time::sleep(Duration::from_millis(100)).await;

			let answer = call(&channel, GET, b"order", None).await;
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
	config: rejected_by(VouchedCallSpec::latest()),
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, RejectedEdge::stage)?;
			context.gateway::<RejectedGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.billing(&cluster).await?;
			let answer = call(&channel, PLACE, b"order", None).await;
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
		hives: |SetupEnv { trace, context }| vec![async move { context.hive_trusting(&trace, &context.session, &context.claims).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let channel = context.billing(&cluster).await?;
			let answer = call(&channel, GET, b"order", None).await;
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
		hives: |SetupEnv { trace, context }| vec![async move { context.hive_trusting(&trace, &context.vouching, &context.session).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let (web, channel) = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order").await?;
			let answer = call(&channel, PLACE, b"order", Some(&claim)).await;
			assert!(answer.is_err(), "a claim that the servlet refuses MUST fail, got {answer:?}");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(CoupledLaneEdge, CoupledLaneGateway);

tb_assert_spec! {
	/// A tunnel call on a connection that carries coupled calls: the coupler
	/// answers the coupled call, and the listener refuses the tunnel as busy.
	pub CoupledLaneSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32)),
			(TUNNEL_REFUSED, exactly!(1), equals!("busy"))
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
			let answer = call(&channel, GET, b"order", None).await;
			assert!(answer.is_ok(), "the coupled call MUST answer, got {answer:?}");

			let mut tunnel = tonic::client::Grpc::new(channel.clone());
			tunnel.ready().await.map_err(unexpected)?;

			let (_hold, waiting) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
			let requests = Request::new(tokio_stream::wrappers::ReceiverStream::new(waiting));
			let path = PathAndQuery::from_static(tightbeam_grpc::protocol::TUNNEL_PATH);
			let refused = tunnel.streaming(requests, path, RawCodec).await.map(|_| ());
			assert_eq!(refused.map_err(|status| status.code()), Err(tonic::Code::Unavailable));

			cluster.stop();
			Ok(())
		}
	}
}

/// What the health check of the edge answered, which the scenario records.
const HEALTH: Urn<'static> = urn!("test", "event:edge/health");

/// How long a scenario watches a health check that MUST NOT turn `SERVING`.
const WATCHED: Duration = Duration::from_millis(1500);

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
			let answer = call(&channel, GET, b"order-7", None).await.map_err(|status| status.code());
			assert_eq!(answer.as_deref(), Ok(&b"served:order-7"[..]), "the coupler MUST serve under mutual authentication");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(UntrustedSessionEdge, UntrustedSessionGateway);

tb_assert_spec! {
	/// An edge that does not trust the voucher: its health reads
	/// `NOT_SERVING`, and its coupled call, which the coupler admits, refuses
	/// as unavailable before the coupler sends it.
	pub NotServingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(HEALTH, exactly!(1), equals!("not-serving")),
			(COUPLED_CALL_REFUSED, exactly!(1), equals!("unavailable")),
			(COUPLED_CALL_ADMITTED, exactly!(1), equals!("vouched")),
			(events::CLUSTER_WORK_ROUTED, exactly!(0))
		]
	}
}

// A mutual edge that refuses the voucher never serves, and its calls answer 14.
tb_scenario! {
	name: an_edge_that_refuses_the_voucher_reads_not_serving,
	spec: NotServingSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, UntrustedSessionEdge::stage)?;
			context.mutual_gateway::<UntrustedSessionGateway>(&trace, &[&context.transport]).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { trace, context, cluster }| async move {
			let billing = context.caller("CN=billing,O=acme,C=US", Some(BILLING));
			let channel = context.channel(&edge_of(&cluster)?, Some(&billing)).await?;

			let watching = tokio::time::Instant::now() + WATCHED;
			let mut health = None;
			while tokio::time::Instant::now() < watching {
				health = call(&channel, HEALTH_CHECK_PATH, &[], None).await.ok();
				assert_ne!(health.as_deref(), Some(&[0x08, 0x01][..]), "the edge MUST NOT serve a voucher it refuses");
				tokio::time::sleep(Duration::from_millis(100)).await;
			}

			let read = if health.as_deref() == Some(&[0x08, 0x02][..]) { "not-serving" } else { "other" };
			trace.event_with(HEALTH, &[], read)?;

			let answer = call(&channel, GET, b"order", None).await;
			assert_eq!(code_of(answer), Some(tonic::Code::Unavailable));

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(SingleSessionEdge, SingleSessionGateway);

tb_assert_spec! {
	/// A signed call that waits out its deadline for a single session never
	/// spends its claim, so the slow call and the retry of the same claim
	/// both serve. A spent claim would refuse the retry as a replay.
	pub QueuedClaimSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ANSWERED, exactly!(2), equals!(0u32)),
			(events::CLUSTER_WORK_ROUTED, exactly!(2))
		]
	}
}

// A signed call that times out waiting for a single session keeps its claim.
tb_scenario! {
	name: a_call_that_waits_out_its_deadline_for_the_session_keeps_its_claim,
	spec: QueuedClaimSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, SingleSessionEdge::stage)?;
			context.single_gateway::<SingleSessionGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let billing = context.billing(&cluster).await?;
			let (web, channel) = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, b"order-11").await?;

			let slow = tokio::spawn(async move { call(&billing, GET, SLOW, None).await });
			tokio::time::sleep(Duration::from_millis(200)).await;

			// tonic ends the call at the deadline it sends, as CANCELLED, so
			// the edge drops the call while it waits for the session, or
			// refuses it with 4 when its own deadline fires first.
			let queued = call_within(&channel, PLACE, b"order-11", &claim, Duration::from_millis(300)).await;
			let queued = code_of(queued);
			assert!(matches!(queued, Some(tonic::Code::Cancelled | tonic::Code::DeadlineExceeded)), "got {queued:?}");

			let slow = slow.await.map_err(|_| unexpected(()))?;
			assert!(slow.is_ok(), "the slow call MUST serve, got {slow:?}");

			let retried = call(&channel, PLACE, b"order-11", Some(&claim)).await;
			let retried = retried.map_err(|status| status.code());
			assert_eq!(retried.as_deref(), Ok(&b"served:order-11"[..]), "the unspent claim MUST serve on retry");

			cluster.stop();
			Ok(())
		}
	}
}

coupled!(MidExchangeEdge, MidExchangeGateway);

tb_assert_spec! {
	/// A call that ends mid-exchange on a single session leaves no reply for
	/// the next call to read, so the next call reads its own answer.
	pub MidExchangeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ANSWERED, exactly!(1), equals!(0u32))
		]
	}
}

// A call that passes its deadline while it holds a single session.
tb_scenario! {
	name: a_call_that_ends_mid_exchange_leaves_no_stale_reply,
	spec: MidExchangeSpec,
	environment Cluster {
		context: Coupled::mint(),
		start: |SetupEnv { trace, context }| async move {
			context.stage(&trace, MidExchangeEdge::stage)?;
			context.single_gateway::<MidExchangeGateway>(&trace).await
		},
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let billing = context.billing(&cluster).await?;
			let (web, channel) = context.web(&cluster).await?;
			let claim = context.claim(&web, PLACE, SLOW).await?;

			let expired = call_within(&channel, PLACE, SLOW, &claim, Duration::from_millis(300)).await;
			assert!(expired.is_err(), "the slow call MUST pass its deadline");

			// The slow reply lands on the session that the expired call held.
			tokio::time::sleep(SLOW_SERVICE).await;
			let reopened = tokio::time::Instant::now() + Duration::from_secs(5);
			let answer = loop {
				let answer = call(&billing, GET, b"order-13", None).await;
				let opening = matches!(&answer, Err(status) if status.code() == tonic::Code::Unavailable);
				if !opening || tokio::time::Instant::now() >= reopened {
					break answer;
				}
				tokio::time::sleep(Duration::from_millis(100)).await;
			};

			let answer = answer.map_err(|status| status.code());
			assert_eq!(answer.as_deref(), Ok(&b"served:order-13"[..]), "the next call MUST read its own answer");

			cluster.stop();
			Ok(())
		}
	}
}
