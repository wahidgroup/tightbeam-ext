//! Tunnels over a TLS 1.3 edge, as tightbeam scenarios.
//!
//! Each scenario declares a staged profile of its own, mints a TLS PKI with
//! [`TlsAuthority`] in its context, and stages the edge and the dial of that
//! profile before the server binds:
//!
//! - The round trips run the shared suites over TLS and grade their traces
//!   with the shared specs, so a tunnel inside TLS behaves as an h2c tunnel.
//! - A dial that trusts another root, and an h2c dial to a TLS edge, never
//!   reach a tunnel: the server accepts no connection, and the dial records
//!   its refusal on the trace as an event of the scenario.
//! - A colony gateway binds its edge through `EncryptedProtocol::bind_with`
//!   under a TLS profile, and a native client submits work through it.

// The colony runtime macros expand `cfg(feature = ...)` probes against the
// invoking crate's feature namespace. Those upstream feature names do not
// exist in this crate, so the leaked cfg warnings carry no signal here.
#![allow(unexpected_cfgs)]

use std::time::Duration;

use tightbeam::colony::SubmitWork;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::instrumentation::events;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::error::TestingError;
use tightbeam::testing::macros::BuiltAssertSpec;
use tightbeam::testing::{
	ClientEnv, ClusterEnv, Expect, Layer, ScenarioConfig, ScenarioConfigError, SetupEnv, TestFrame,
};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::policy::RestartLinearBackoff;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::EncryptedProtocol;
use tightbeam::urn::Urn;
use tightbeam::{client, cluster, exactly, tb_assert_spec, tb_scenario, urn, TightBeamError};
use tightbeam_grpc::edge::{Dial, Edge};
use tightbeam_grpc::protocol::{GrpcAddr, GrpcListener};
use tightbeam_grpc::staged_profile;
use tightbeam_grpc::testing::TlsAuthority;
use tightbeam_ws::testing::specs::{CleartextRoundTripSpec, EdgeWorkSpec, EncryptedRoundTripSpec};
use tightbeam_ws::testing::{EchoService, Identity, WorkClient, WorkPlane};
use tokio::task::JoinHandle;

/// The server of a scenario, and the socket address it bound.
type Served = Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError>;

/// How long every certificate of a scenario stays valid.
const LIFETIME: Duration = Duration::from_secs(3600);

/// How a dial of a scenario ended, which the scenario records itself: no code
/// under test records a dial that TLS refuses before any session exists.
const DIAL: Urn<'static> = urn!("test", "event:tls/dial");

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

tb_assert_spec! {
	/// A dial that TLS refuses: the server accepts no connection, no end
	/// completes a handshake, and the dial records its refusal.
	pub RefusedDialSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CONNECTION_ACCEPTED, exactly!(0)),
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(0)),
			(DIAL, exactly!(1), equals!("refused"))
		]
	}
}

/// A root, which issues the edge certificate of a scenario.
fn authority() -> TlsAuthority {
	let minted = TlsAuthority::mint("CN=tunnel root,O=tightbeam-grpc,C=US", LIFETIME);
	minted.expect("a test root mints")
}

/// The TLS edge of `authority`, and the dial that trusts it.
fn trusted(authority: &TlsAuthority) -> (Edge, Dial) {
	let minted = authority.edge("CN=tunnel edge,O=tightbeam-grpc,C=US");
	let edge = minted.expect("an edge certificate mints");
	let dial = authority.dial().expect("a dial trusts the root");
	(Edge::Tls(edge), Dial::Tls(dial))
}

/// The identity of an encrypted server, which its client pins.
fn server_identity() -> Identity {
	let minted = Identity::mint("CN=tunnel echo,O=tightbeam-grpc,C=US", 1, Duration::from_secs(3600));
	minted.expect("a test identity mints")
}

/// The identity of an encrypted server whose profile `stage` stages a
/// trusted TLS edge and dial.
fn staged_identity(stage: fn(Edge, Dial)) -> Identity {
	let (edge, dial) = trusted(&authority());
	stage(edge, dial);
	server_identity()
}

/// The shared echo on `listener`, which records each session on `trace`.
fn echo<C>(listener: GrpcListener<DefaultCryptoProvider, C>, trace: &TraceCollector) -> Served
where
	C: tightbeam_grpc::edge::EdgeProfile,
{
	let addr = TightBeamSocketAddr(listener.local_addr());
	Ok((EchoService::serve(listener, None, trace), addr))
}

/// Bind the shared echo of profile `C` on loopback under the encrypted
/// config of `identity`.
async fn encrypted_echo<C>(identity: &Identity, trace: &TraceCollector) -> Served
where
	C: tightbeam_grpc::edge::EdgeProfile,
{
	let bind: GrpcAddr = "127.0.0.1:0".parse()?;
	let config = identity.server_config()?;
	let bound = <GrpcListener<DefaultCryptoProvider, C> as EncryptedProtocol>::bind_with(bind, config);
	let (listener, _addr) = bound.await?;

	echo(listener, trace)
}

/// Record how `dialed` ended on `trace` as [`DIAL`]: `connected` or
/// `refused`.
fn record_dial<T>(dialed: &Result<T, TightBeamError>, trace: &TraceCollector) -> Result<(), TightBeamError> {
	let outcome = match dialed {
		Ok(_) => "connected",
		Err(_) => "refused",
	};
	trace.event_with(DIAL, &[], outcome)?;
	Ok(())
}

/// The config that grades a run with `spec`, and expects the spec to reject
/// it.
fn rejected_by(spec: &'static BuiltAssertSpec) -> Result<ScenarioConfig, ScenarioConfigError> {
	let config = ScenarioConfig::builder().with_spec(spec);
	config.with_expect(Expect::Violation(Layer::Assertion)).build()
}

// tightbeam's `server!` and `client!` macros drive a cleartext tunnel inside
// TLS: the server accepts the one connection, and its gate admits the one
// request.
tb_scenario! {
	name: cleartext_round_trip_over_tls,
	spec: CleartextRoundTripSpec,
	environment ServiceClient {
		context: {
			let (edge, dial) = trusted(&authority());
			CleartextEcho::stage(edge, dial);
		},
		server: |SetupEnv { trace, .. }| async move {
			let listener = CleartextEchoListener::bind_cleartext("127.0.0.1:0").await?;
			echo(listener, &trace)
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
		server: |SetupEnv { trace, context }| async move { encrypted_echo::<EncryptedEcho>(&context, &trace).await },
		client: |ClientEnv { trace, addr, context }| async move {
			let expected = TestFrame::v0(None, None);
			let exchanged = EchoService::exchange::<EncryptedEchoListener, _, _>(GrpcAddr::from(addr.0), context.trust_anchor()?, expected.clone(), &trace);
			let reply = exchanged.await?;
			assert_eq!(reply, Some(expected), "the encrypted server MUST echo the frame back through the TLS edge");
			Ok(())
		}
	}
}

// A dial that trusts another root fails its TLS handshake, so the server
// accepts no connection and no tightbeam handshake starts.
tb_scenario! {
	name: a_dial_that_trusts_another_root_reaches_no_tunnel,
	spec: RefusedDialSpec,
	environment ServiceClient {
		context: {
			let (edge, _dial) = trusted(&authority());
			let (_edge, other) = trusted(&authority());
			UntrustedEcho::stage(edge, other);
			server_identity()
		},
		server: |SetupEnv { trace, context }| async move { encrypted_echo::<UntrustedEcho>(&context, &trace).await },
		client: |ClientEnv { trace, addr, context }| async move {
			let frame = TestFrame::v0(None, None);
			let exchanged = EchoService::exchange::<UntrustedEchoListener, _, _>(GrpcAddr::from(addr.0), context.trust_anchor()?, frame, &trace);
			let dialed = exchanged.await.map_err(TightBeamError::from);
			record_dial(&dialed, &trace)
		}
	}
}

// An h2c dial to a TLS edge sends an HTTP/2 preface where the edge waits for
// a TLS ClientHello, so the edge closes the connection before any server
// sees it.
tb_scenario! {
	name: an_h2c_dial_to_a_tls_edge_reaches_no_tunnel,
	spec: RefusedDialSpec,
	environment ServiceClient {
		context: staged_identity(TlsOnlyEcho::stage),
		server: |SetupEnv { trace, context }| async move { encrypted_echo::<TlsOnlyEcho>(&context, &trace).await },
		client: |ClientEnv { trace, addr, context }| async move {
			let frame = TestFrame::v0(None, None);
			let exchanged = EchoService::exchange::<GrpcListener, _, _>(GrpcAddr::from(addr.0), context.trust_anchor()?, frame, &trace);
			let dialed = exchanged.await.map_err(TightBeamError::from);
			record_dial(&dialed, &trace)
		}
	}
}

// The refused-dial spec rejects a run whose dial trusts the root of the edge,
// so the tunnel opens and the echo answers.
tb_scenario! {
	name: the_refused_dial_spec_rejects_a_trusted_dial,
	config: rejected_by(RefusedDialSpec::latest()),
	environment ServiceClient {
		context: staged_identity(TrustedEcho::stage),
		server: |SetupEnv { trace, context }| async move { encrypted_echo::<TrustedEcho>(&context, &trace).await },
		client: |ClientEnv { trace, addr, context }| async move {
			let frame = TestFrame::v0(None, None);
			let exchanged = EchoService::exchange::<TrustedEchoListener, _, _>(GrpcAddr::from(addr.0), context.trust_anchor()?, frame, &trace);
			let dialed = exchanged.await.map_err(TightBeamError::from);
			record_dial(&dialed, &trace)
		}
	}
}

/// The identities of the work plane, after the TLS edge of the gateway is
/// staged.
fn tls_work_plane() -> WorkPlane {
	let (edge, dial) = trusted(&authority());
	TlsGatewayEdge::stage(edge, dial);

	let minted = WorkPlane::mint("tightbeam-grpc");
	minted.expect("the work plane identities mint")
}

/// The address of the edge plane of `gateway`.
fn edge_of(gateway: &TlsGateway) -> Result<GrpcAddr, TightBeamError> {
	let bound = gateway.edge_addr().cloned();
	let unbound = TightBeamError::TestingError(TestingError::UnexpectedOutcome("the edge plane did not bind"));
	bound.ok_or(unbound)
}

// A signed work frame travels from a native client through the TLS edge and
// the TCP colony to the work probe, and the signed answer of the probe
// verifies end to end.
tb_scenario! {
	name: submit_work_round_trips_through_a_tls_edge,
	spec: EdgeWorkSpec,
	environment Cluster {
		context: tls_work_plane(),
		start: |SetupEnv { trace, context }| async move { context.gateway::<TlsGateway>(&trace, "127.0.0.1:0").await },
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let probe = context.client();
			let mut client = probe.connect::<TlsGatewayListener>(edge_of(&cluster)?).await?;

			let work = probe.work(b"tls-work-1").await?;
			let served = client.submit_work_to(WorkClient::probe()?, &work).await?;
			let answer = probe.answer(&served)?;
			assert_eq!(answer.as_deref(), Some(&b"pong:3231:true"[..]), "the probe MUST verify the work end to end, both ways");

			cluster.stop();
			Ok(())
		}
	}
}
