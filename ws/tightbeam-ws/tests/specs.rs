//! The shared specs of `tightbeam_ws::testing::specs` reject a run that
//! breaks the behavior they grade, as tightbeam scenarios.
//!
//! Each transport of the repository grades its suites with these specs, so a
//! spec that held for any run would prove nothing for any of them. Each
//! scenario here breaks one behavior on purpose, completes its run, and
//! expects the assertion layer to reject it: the violation is the spec at
//! work.

#![cfg(feature = "testing")]
// The colony runtime macros expand `cfg(feature = ...)` probes against the
// invoking crate's feature namespace. Those upstream feature names do not
// exist in this crate, so the leaked cfg warnings carry no signal here.
#![allow(unexpected_cfgs)]

use core::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::macros::BuiltAssertSpec;
use tightbeam::testing::{ClientEnv, Expect, Layer, ScenarioConfig, ScenarioConfigError, SetupEnv, TestFrame};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::policy::{CollectorGateConfig, RestartLinearBackoff};
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, ConnectionPool, EncryptedProtocol, PoolConfig};
use tightbeam::{client, server, tb_scenario, Frame, TightBeamError};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::specs::{CleartextRoundTripSpec, DialCeilingSpec, EncryptedRoundTripSpec, PooledMuxSpec};
use tightbeam_ws::testing::{EchoService, Identity, ReadOutcome};
use tokio::task::JoinHandle;

/// The server of a scenario, and the socket address it bound.
type Served = Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError>;

/// The config that grades a run with `spec`, and expects the spec to reject
/// it.
fn rejected_by(spec: &'static BuiltAssertSpec) -> Result<ScenarioConfig, ScenarioConfigError> {
	let config = ScenarioConfig::builder().with_spec(spec);
	config.with_expect(Expect::Violation(Layer::Assertion)).build()
}

/// The shared echo on a cleartext listener on loopback, which records each
/// session on `trace`.
async fn cleartext_echo(trace: &TraceCollector) -> Served {
	let listener = WsListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await?;
	let addr = TightBeamSocketAddr(listener.local_addr()?);
	Ok((EchoService::serve(listener, None, trace), addr))
}

/// One cleartext exchange through `client!` with the server at `addr`, which
/// returns how it ended.
async fn cleartext_exchange(addr: TightBeamSocketAddr) -> Result<Option<Frame>, TightBeamError> {
	let mut client = client! {
		connect WsListener: addr,
		cleartext,
		policies: {
			restart_policy: RestartLinearBackoff::default(),
		}
	};

	Ok(client.emit(TestFrame::v0(None, None), None).await?)
}

/// The identity of an encrypted server, which its client pins.
fn server_identity() -> Identity {
	let minted = Identity::mint("CN=spec probe,O=tightbeam-ws,C=US", 1, Duration::from_secs(3600));
	minted.expect("a test identity mints")
}

/// A gate that refuses every call.
#[derive(Clone)]
struct RefuseAll;

impl GatePolicy for RefuseAll {
	fn evaluate(&self, _message: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		TransitStatus::PermissionDenied
	}
}

// The cleartext spec rejects a run whose gate refuses the one request, though
// the server accepts the connection.
tb_scenario! {
	name: the_cleartext_spec_rejects_a_refused_request,
	config: rejected_by(CleartextRoundTripSpec::latest()),
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move {
			let listener = WsListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await?;
			let addr = TightBeamSocketAddr(listener.local_addr()?);
			let handle = server! {
				protocol WsListener: listener,
				policies: {
					with_trace: [ trace.share() ],
					with_collector_gate: [ RefuseAll ]
				},
				handle: move |frame: Frame| async move { Ok(Some(frame)) }
			};
			Ok((handle, addr))
		},
		client: |ClientEnv { addr, .. }| async move {
			// A client with no restart policy sends the refused request once.
			let builder = ClientBuilder::<WsListener>::builder().allow_cleartext();
			let mut client = builder.build().connect(addr).await?;

			let refused = client.emit(TestFrame::v0(None, None), None).await;
			assert!(refused.is_err(), "the gate MUST refuse the request, got {refused:?}");
			Ok(())
		}
	}
}

// The encrypted spec rejects a run whose exchange runs in the clear, so no end
// completes a handshake.
tb_scenario! {
	name: the_encrypted_spec_rejects_a_cleartext_exchange,
	config: rejected_by(EncryptedRoundTripSpec::latest()),
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move { cleartext_echo(&trace).await },
		client: |ClientEnv { addr, .. }| async move {
			let reply = cleartext_exchange(addr).await?;
			assert!(reply.is_some(), "the cleartext echo MUST answer");
			Ok(())
		}
	}
}

// The pooled spec rejects a run whose server declines the multiplexing that
// the pool offers, though one exclusive lease still echoes.
tb_scenario! {
	name: the_pooled_spec_rejects_a_declined_offer,
	config: rejected_by(PooledMuxSpec::latest()),
	environment ServiceClient {
		context: server_identity(),
		server: |SetupEnv { trace, context }| async move {
			let loopback = TightBeamSocketAddr::from_str("127.0.0.1:0")?;
			let (listener, addr) = <WsListener as EncryptedProtocol>::bind_with(loopback, context.server_config()?).await?;
			Ok((EchoService::serve(listener, None, &trace), addr))
		},
		client: |ClientEnv { trace, context, addr }| async move {
			let offer = Some(Arc::new(TransportOffer::mux(8)));
			let config = PoolConfig { idle_timeout: None, max_connections: NonZeroUsize::MIN, mux_offer: offer };
			let builder = ConnectionPool::<WsListener>::builder().with_config(config);
			let pool = Arc::new(builder.with_trust_store(context.trust_anchor()?).with_trace(trace.share()).build());

			let mut lease = pool.connect(addr).await?;
			let reply = lease.emit(TestFrame::v0(None, None), None).await?;
			assert!(reply.is_some(), "the exclusive lease MUST echo");
			Ok(())
		}
	}
}

// The ceiling spec rejects a run whose dial reads a frame within its ceiling,
// which the read delivers.
tb_scenario! {
	name: the_ceiling_spec_rejects_a_delivered_frame,
	config: rejected_by(DialCeilingSpec::latest()),
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move { cleartext_echo(&trace).await },
		client: |ClientEnv { trace, addr, .. }| async move {
			let builder = ClientBuilder::<WsListener>::builder().allow_cleartext();
			let mut client = builder.build().connect(addr).await?;

			let emitted = client.emit(TestFrame::v0(None, None), None).await;
			ReadOutcome::record(&emitted, &trace)
		}
	}
}

#[cfg(feature = "colony")]
mod colony {
	use tightbeam::colony::SubmitWork;
	use tightbeam::testing::error::TestingError;
	use tightbeam::testing::{ClusterEnv, SetupEnv};
	use tightbeam::transport::tcp::r#async::TokioListener;
	use tightbeam::{cluster, tb_scenario, TightBeamError};
	use tightbeam_ws::protocol::WsListener;
	use tightbeam_ws::testing::specs::{EdgeWorkSpec, UnservedWorkSpec};
	use tightbeam_ws::testing::{WorkClient, WorkPlane};

	use super::rejected_by;

	cluster! {
		/// TCP colony gateway with a WebSocket edge accept plane.
		pub ProbeGateway,
		protocol: TokioListener,
		edge: WsListener
	}

	/// The identities of the work plane of every scenario.
	fn work_plane() -> WorkPlane {
		let minted = WorkPlane::mint("tightbeam-ws");
		minted.expect("the work plane identities mint")
	}

	/// Submit one probe work frame through the edge of `gateway` to the
	/// servlet type `servlet`, and return how the submission ended.
	async fn submit(
		plane: &WorkPlane,
		gateway: &ProbeGateway,
		servlet: tightbeam::urn::Urn<'static>,
	) -> Result<Result<tightbeam::Frame, TightBeamError>, TightBeamError> {
		let unbound = TightBeamError::TestingError(TestingError::UnexpectedOutcome("the edge plane did not bind"));
		let edge = gateway.edge_addr().copied().ok_or(unbound)?;
		let mut client = plane.client().connect::<WsListener>(edge).await?;

		let work = plane.client().work(b"spec-probe").await?;
		Ok(client.submit_work_to(servlet, &work).await)
	}

	// The spec of served work rejects a run whose work names a servlet type
	// that no hive serves, so the gateway routes nothing.
	tb_scenario! {
		name: the_edge_work_spec_rejects_unserved_work,
		config: rejected_by(EdgeWorkSpec::latest()),
		environment Cluster {
			context: work_plane(),
			start: |SetupEnv { trace, context }| async move { context.gateway::<ProbeGateway>(&trace, "127.0.0.1:0").await },
			hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
			client: |ClusterEnv { context, cluster, .. }| async move {
				let refused = submit(&context, &cluster, WorkClient::servlet("unserved")?).await?;
				assert!(refused.is_err(), "unserved work MUST be refused, got {refused:?}");
				cluster.stop();
				Ok(())
			}
		}
	}

	// The spec of unserved work rejects a run whose work reaches the work
	// probe, which the gateway routes.
	tb_scenario! {
		name: the_unserved_work_spec_rejects_served_work,
		config: rejected_by(UnservedWorkSpec::latest()),
		environment Cluster {
			context: work_plane(),
			start: |SetupEnv { trace, context }| async move { context.gateway::<ProbeGateway>(&trace, "127.0.0.1:0").await },
			hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
			client: |ClusterEnv { context, cluster, .. }| async move {
				let served = submit(&context, &cluster, WorkClient::probe()?).await?;
				assert!(served.is_ok(), "served work MUST reach the probe, got {served:?}");
				cluster.stop();
				Ok(())
			}
		}
	}
}
