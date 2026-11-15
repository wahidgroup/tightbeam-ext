//! Tunnels over a TLS 1.3 edge.

mod support;

use std::time::Duration;

use tightbeam::colony::SubmitWork;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::instrumentation::events;
use tightbeam::testing::{ClientEnv, ClusterEnv, SetupEnv, TestFrame};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::policy::RestartLinearBackoff;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::TransportLimits;
use tightbeam::{client, cluster, exactly, tb_assert_spec, tb_scenario};
use tightbeam_grpc::edge::{Dial, Edge};
use tightbeam_grpc::events::EDGE_REFUSED;
use tightbeam_grpc::protocol::{GrpcAddr, GrpcListener, HEALTH_CHECK_PATH};
use tightbeam_grpc::staged_profile;
use tightbeam_grpc::testing::TlsAuthority;
use tightbeam_ws::testing::specs::{CleartextRoundTripSpec, EdgeWorkSpec, EncryptedRoundTripSpec};
use tightbeam_ws::testing::{EchoService, EventWatch, Identity, WorkClient, WorkPlane};
use tokio::net::TcpStream;

use support::{
	bounded, edge_error, mint_error, server_identity, Coupled, EchoServer, Graded, TcpWorkProbe, LIFETIME, SERVING,
};

/// The subject of the identity of each encrypted echo.
const ECHO: &str = "CN=tunnel echo,O=tightbeam-grpc,C=US";

/// How long a connection of the edge of the late scenario waits for its TLS
/// handshake, on a clock that the scenario moves: past the patience of
/// `EventWatch::recorded`, so only an advance of that clock ends the wait
/// within the wait of the scenario.
const SECURING: Duration = EventWatch::PATIENCE.saturating_add(Duration::from_secs(2));

staged_profile! {
	/// The profile of the cleartext round trip.
	CleartextEcho
}

staged_profile! {
	/// The profile of the encrypted round trip.
	EncryptedEcho
}

staged_profile! {
	/// A TLS edge whose dial trusts another root.
	UntrustedEcho
}

staged_profile! {
	/// A TLS edge that an h2c listener dials.
	TlsOnlyEcho
}

staged_profile! {
	/// The profile that the refused-dial spec grades a trusted dial under.
	TrustedEcho
}

staged_profile! {
	/// The edge of the colony gateway.
	TlsGatewayEdge
}

type CleartextEchoListener = GrpcListener<DefaultCryptoProvider, CleartextEcho>;
type EncryptedEchoListener = GrpcListener<DefaultCryptoProvider, EncryptedEcho>;
type UntrustedEchoListener = GrpcListener<DefaultCryptoProvider, UntrustedEcho>;
type TrustedEchoListener = GrpcListener<DefaultCryptoProvider, TrustedEcho>;
type TlsGatewayListener = GrpcListener<DefaultCryptoProvider, TlsGatewayEdge>;

cluster! {
	/// TCP colony gateway with a gRPC edge accept plane over TLS.
	pub TlsGateway,
	protocol: TokioListener,
	edge: TlsGatewayListener
}

staged_profile! {
	/// A TLS edge whose connection never starts its handshake.
	LateEcho
}

tb_assert_spec! {
	/// A dial that TLS refuses: the server accepts no connection, no end
	/// completes a handshake, and the edge records its refusal.
	pub RefusedDialSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CONNECTION_ACCEPTED, exactly!(0)),
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(0)),
			(EDGE_REFUSED, exactly!(1), equals!("tls"))
		]
	}
}

tb_assert_spec! {
	/// A connection that never starts its TLS handshake: the edge closes it
	/// at its deadline, records it as late, and accepts no connection.
	pub LateSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CONNECTION_ACCEPTED, exactly!(0)),
			(EDGE_REFUSED, exactly!(1), equals!("late"))
		]
	}
}

/// A root, which issues the edge certificate of a scenario.
fn authority() -> TlsAuthority {
	let created = TlsAuthority::mint("CN=tunnel root,O=tightbeam-grpc,C=US", LIFETIME);
	created.expect("a test root is created")
}

/// The TLS edge of `authority`, and the dial that trusts it.
fn trusted(authority: &TlsAuthority) -> (Edge, Dial) {
	let created = authority.edge("CN=tunnel edge,O=tightbeam-grpc,C=US");
	let edge = created.expect("an edge certificate is created");
	let dial = authority.dial().expect("a dial trusts the root");
	(Edge::tls(edge), Dial::Tls(dial))
}

/// The identity of an encrypted server whose profile `stage` stages a
/// trusted TLS edge and dial.
fn staged_identity(stage: fn(Edge, Dial)) -> Identity {
	let (edge, dial) = trusted(&authority());
	stage(edge, dial);
	server_identity(ECHO)
}

/// Stage a trusted TLS edge through `stage`, which records on `trace`.
fn stage_traced(stage: fn(Edge, Dial), trace: &TraceCollector) {
	let (edge, dial) = trusted(&authority());
	stage(edge.with_trace(trace.share()), dial);
}

// `server!` and `client!` drive a cleartext tunnel inside TLS.
tb_scenario! {
	name: cleartext_round_trip_over_tls,
	spec: CleartextRoundTripSpec,
	environment ServiceClient {
		context: {
			let (edge, dial) = trusted(&authority());
			CleartextEcho::stage(edge, dial);
		},
		server: |SetupEnv { trace, .. }| async move {
			EchoServer::cleartext::<CleartextEcho>(&trace).await
		},
		client: |ClientEnv { addr, .. }| async move {
			let mut client = client! {
				connect CleartextEchoListener: GrpcAddr::from(addr.0),
				cleartext,
				policies: {
					restart_policy: RestartLinearBackoff::default(),
				}
			};

			let message = TestFrame::v0(None, None);
			let reply = client.emit(message.clone(), None).await?;
			assert_eq!(reply, Some(message), "the server MUST echo the frame sent through the TLS edge");
			Ok(())
		}
	}
}

// One HPKE handshake completes at each end inside TLS, and the gate admits
// the one encrypted request.
tb_scenario! {
	name: encrypted_round_trip_over_tls,
	spec: EncryptedRoundTripSpec,
	environment ServiceClient {
		context: staged_identity(EncryptedEcho::stage),
		server: |SetupEnv { trace, context }| async move { EchoServer::encrypted::<EncryptedEcho>(context.server_config(), None, &trace).await },
		client: |ClientEnv { trace, addr, context }| async move {
			let expected = TestFrame::v0(None, None);
			let exchanged = EchoService::exchange::<EncryptedEchoListener, _, _>(GrpcAddr::from(addr.0), context.trust_anchor()?, expected.clone(), &trace);
			let reply = exchanged.await?;
			assert_eq!(reply, Some(expected), "the encrypted server MUST echo the frame back through the TLS edge");
			Ok(())
		}
	}
}

/// The events of the scenario of a dial that trusts another root.
static UNTRUSTED_DIAL_EVENTS: EventWatch = EventWatch::new();

// A dial that trusts another root fails its TLS handshake, so the server
// accepts no connection and no tightbeam handshake starts.
tb_scenario! {
	name: a_dial_that_trusts_another_root_reaches_no_tunnel,
	config: RefusedDialSpec::latest().watched(&UNTRUSTED_DIAL_EVENTS),
	environment ServiceClient {
		context: server_identity(ECHO),
		server: |SetupEnv { trace, context }| async move {
			let (edge, _dial) = trusted(&authority());
			let (_edge, other) = trusted(&authority());
			UntrustedEcho::stage(edge.with_trace(trace.share()), other);
			EchoServer::encrypted::<UntrustedEcho>(context.server_config(), None, &trace).await
		},
		client: |ClientEnv { trace, addr, context }| async move {
			let frame = TestFrame::v0(None, None);
			let exchanged = EchoService::exchange::<UntrustedEchoListener, _, _>(GrpcAddr::from(addr.0), context.trust_anchor()?, frame, &trace);
			assert!(exchanged.await.is_err(), "a dial that trusts another root MUST fail");
			Ok(UNTRUSTED_DIAL_EVENTS.recorded(EDGE_REFUSED, 1).await?)
		}
	}
}

/// The events of the scenario of an h2c dial to a TLS edge.
static H2C_DIAL_EVENTS: EventWatch = EventWatch::new();

// An h2c dial to a TLS edge reaches no tunnel.
tb_scenario! {
	name: an_h2c_dial_to_a_tls_edge_reaches_no_tunnel,
	config: RefusedDialSpec::latest().watched(&H2C_DIAL_EVENTS),
	environment ServiceClient {
		context: server_identity(ECHO),
		server: |SetupEnv { trace, context }| async move {
			stage_traced(TlsOnlyEcho::stage, &trace);
			EchoServer::encrypted::<TlsOnlyEcho>(context.server_config(), None, &trace).await
		},
		client: |ClientEnv { trace, addr, context }| async move {
			let frame = TestFrame::v0(None, None);
			let exchanged = EchoService::exchange::<GrpcListener, _, _>(GrpcAddr::from(addr.0), context.trust_anchor()?, frame, &trace);
			assert!(exchanged.await.is_err(), "an h2c dial to a TLS edge MUST fail");
			Ok(H2C_DIAL_EVENTS.recorded(EDGE_REFUSED, 1).await?)
		}
	}
}

// The refused-dial spec rejects a run whose dial trusts the root of the edge,
// so the tunnel opens and the echo answers.
tb_scenario! {
	name: the_refused_dial_spec_rejects_a_trusted_dial,
	config: RefusedDialSpec::latest().rejected(),
	environment ServiceClient {
		context: server_identity(ECHO),
		server: |SetupEnv { trace, context }| async move {
			stage_traced(TrustedEcho::stage, &trace);
			EchoServer::encrypted::<TrustedEcho>(context.server_config(), None, &trace).await
		},
		client: |ClientEnv { trace, addr, context }| async move {
			let frame = TestFrame::v0(None, None);
			let exchanged = EchoService::exchange::<TrustedEchoListener, _, _>(GrpcAddr::from(addr.0), context.trust_anchor()?, frame, &trace);
			exchanged.await?;
			Ok(())
		}
	}
}

/// The events of the scenario of a connection that never secures.
static LATE_EVENTS: EventWatch = EventWatch::new();

// A connection that opens TCP and never starts its TLS handshake holds its
// slot until the securing deadline of the edge, which then records it late.
// The edge answers the health check of a connection that secures after it
// once it read the deadline of the silent one.
tb_scenario! {
	name: a_connection_that_never_secures_is_refused_late,
	config: LateSpec::latest().watched(&LATE_EVENTS),
	environment ServiceClient {
		context: Coupled::clocked(&LATE_EVENTS),
		server: |SetupEnv { trace, context }| async move {
			let edge = context.tls.edge("CN=tunnel edge,O=tightbeam-grpc,C=US").map_err(mint_error)?;
			let dial = context.tls.dial().map_err(edge_error)?;
			let edge = Edge::tls(edge).with_trace(trace.share()).with_clock(context.clock.edge());
			LateEcho::stage(edge, Dial::Tls(dial));
			let limits = TransportLimits { handshake_timeout: SECURING, ..TransportLimits::default() };
			let config = context.transport.server_config().with_limits(limits)?;
			EchoServer::encrypted::<LateEcho>(config, None, &trace).await
		},
		client: |ClientEnv { addr, context, .. }| async move {
			let _silent = bounded(TcpStream::connect(addr.0)).await??;
			let secured = context.channel(&GrpcAddr::from(addr.0), None).await?;
			let checked = secured.call(HEALTH_CHECK_PATH, &[], None).await?;
			assert_eq!(checked.ok(), Some(SERVING.to_vec()), "the secured connection MUST read SERVING");

			context.clock.advance(SECURING)?;
			Ok(LATE_EVENTS.recorded(EDGE_REFUSED, 1).await?)
		}
	}
}

/// The identities of the work plane, after the TLS edge of the gateway is
/// staged.
fn tls_work_plane() -> WorkPlane {
	let (edge, dial) = trusted(&authority());
	TlsGatewayEdge::stage(edge, dial);

	let created = WorkPlane::mint("tightbeam-grpc");
	created.expect("the work plane identities are created")
}

// A native client submits work through a TLS edge to the colony.
tb_scenario! {
	name: submit_work_round_trips_through_a_tls_edge,
	spec: EdgeWorkSpec,
	environment Cluster {
		context: tls_work_plane(),
		start: |SetupEnv { trace, context }| async move { context.gateway::<TlsGateway>(&trace, "127.0.0.1:0").await },
		hives: |SetupEnv { trace, context }| vec![async move { context.hive::<TcpWorkProbe>(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let probe = context.client();
			let mut client = probe.connect::<TlsGatewayListener>(WorkClient::edge_of(&cluster)?).await?;

			let work = probe.work(b"tls-work-1").await?;
			let served = client.submit_work_to(WorkClient::probe()?, &work).await?;
			let answer = probe.answer(&served)?;
			assert_eq!(answer.as_deref(), Some(&b"pong:3231:true"[..]), "the probe MUST verify the work end to end, both ways");

			cluster.stop();
			Ok(())
		}
	}
}
