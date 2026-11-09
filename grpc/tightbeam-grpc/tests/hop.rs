//! Work submission through an h2c proxy hop, as tightbeam scenarios.
//!
//! The docker stack runs the grpc work gateway behind a pinned Envoy that
//! routes by `:authority`. Each case dials Envoy by host name through a pool
//! that records on the trace, so its tunnel crosses the hop to the gateway's
//! gRPC edge, and the gateway routes the work through its TCP colony to the
//! work probe. The spec of each case counts the dials and the handshakes of
//! its pool, which tell a reused session from a fresh one.
//!
//! The cases compile under the `e2e` feature alone, and run in the grpc e2e
//! lane, `grpc/scripts/test-e2e.sh`, which reads the port of Envoy and the
//! stack identities from the stack environment.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tightbeam::colony::SubmitWork;
use tightbeam::instrumentation::events;
use tightbeam::testing::SetupEnv;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::PooledClient;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, Frame, TightBeamError};
use tightbeam_grpc::protocol::{GrpcAddr, GrpcListener};
use tightbeam_ws::testing::{EnvVar, IdentityFiles, WorkClient};
use tokio::time::sleep;

/// The host port of Envoy, which the stack allocates.
const ENVOY_PORT: EnvVar = EnvVar::new("GRPC_ENVOY_HOST_PORT");

/// The directory of the stack identities.
const CERT_DIR: EnvVar = EnvVar::new("CERT_DIR");

/// Envoy's default route timeout, which the hop of the stack disables.
const DEFAULT_ROUTE_TIMEOUT: Duration = Duration::from_secs(15);

/// The stack: the address of Envoy by host name, and the client side of its
/// work probe.
struct Stack {
	envoy: GrpcAddr,
	probe: WorkClient,
}

impl Stack {
	/// The stack that the e2e lane exports.
	fn from_env() -> Result<Self, TightBeamError> {
		let port: u16 = ENVOY_PORT.parsed().map_err(|_| TightBeamError::MissingConfiguration)?;
		let envoy = format!("localhost:{port}").parse()?;

		let certs: PathBuf = CERT_DIR.parsed().map_err(|_| TightBeamError::MissingConfiguration)?;
		let gateway = IdentityFiles::new(&certs, "server")?.load()?;
		let work = Arc::new(IdentityFiles::new(&certs, "client")?.load()?);
		let probe = WorkClient::new(&gateway, work)?;
		Ok(Self { envoy, probe })
	}

	/// The stack of the e2e lane, which every case of this file needs.
	fn exported() -> Self {
		let exported = Self::from_env();
		exported.expect("the grpc e2e lane exports the Envoy port and the stack identities")
	}

	/// A lease on a fresh pool to Envoy that pins the gateway identity and
	/// records on `trace`, so its first use dials a fresh tunnel.
	async fn lease(&self, trace: &TraceCollector) -> Result<PooledClient<GrpcListener>, TightBeamError> {
		let pool = self.probe.pool::<GrpcListener>(trace);
		pool.connect(self.envoy.clone()).await.map_err(TightBeamError::from)
	}

	/// Submit a probe work frame under `id` to the servlet type `servlet`.
	async fn submit(
		&self,
		lease: &mut PooledClient<GrpcListener>,
		servlet: tightbeam::urn::Urn<'static>,
		id: &[u8],
	) -> Result<Result<Frame, TightBeamError>, TightBeamError> {
		let work = self.probe.work(id).await?;
		Ok(lease.submit_work_to(servlet, &work).await)
	}

	/// Submit a probe work frame under `id` to the work probe, and require
	/// its verified answer.
	async fn round_trip(&self, lease: &mut PooledClient<GrpcListener>, id: &[u8]) -> Result<(), TightBeamError> {
		let served = self.submit(lease, WorkClient::probe()?, id).await??;
		let answer = self.probe.answer(&served)?;
		assert_eq!(
			answer.as_deref(),
			Some(&b"pong:3231:true"[..]),
			"the probe MUST verify the work end to end, both ways"
		);
		assert_eq!(served.metadata().id(), id, "the probe response MUST correlate with the work id");
		Ok(())
	}
}

tb_assert_spec! {
	pub OneTunnelSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(1))
		]
	}
}

// One tunnel crosses the hop: the pool dials Envoy once, the handshake with
// the gateway completes through it, and the work round-trips.
tb_scenario! {
	name: submit_work_round_trips_through_envoy,
	spec: OneTunnelSpec,
	environment Bare {
		context: Stack::exported(),
		exec: |SetupEnv { trace, context }| async move {
			let mut lease = context.lease(&trace).await?;
			context.round_trip(&mut lease, b"grpc-hop-1").await
		}
	}
}

// An unserved type resolves to a typed refusal through the hop, on the one
// tunnel that the pool dialed.
tb_scenario! {
	name: an_unserved_type_resolves_to_a_work_refusal_through_envoy,
	spec: OneTunnelSpec,
	environment Bare {
		context: Stack::exported(),
		exec: |SetupEnv { trace, context }| async move {
			let mut lease = context.lease(&trace).await?;
			let refused = context.submit(&mut lease, WorkClient::servlet("unserved")?, b"grpc-hop-refused").await?;
			assert!(
				matches!(refused, Err(TightBeamError::WorkRefused(_))),
				"an unserved servlet type MUST resolve to a typed WorkRefused through the hop, got {refused:?}"
			);
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub TunnelsInARowSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(3)),
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(3))
		]
	}
}

// Three fresh tunnels in a row cross the pooled upstream of Envoy, and each
// completes its own handshake with the gateway.
tb_scenario! {
	name: tunnels_in_a_row_cross_the_pooled_upstream_of_envoy,
	spec: TunnelsInARowSpec,
	environment Bare {
		context: Stack::exported(),
		exec: |SetupEnv { trace, context }| async move {
			for id in [&b"grpc-hop-row-1"[..], b"grpc-hop-row-2", b"grpc-hop-row-3"] {
				let mut lease = context.lease(&trace).await?;
				context.round_trip(&mut lease, id).await?;
			}
			Ok(())
		}
	}
}

// One tunnel outlives the default route timeout of Envoy: the lease holds its
// session across the wait, so the late exchange runs on the one dial and the
// one handshake. The first exchange opens the session, because the gateway
// closes a connection whose handshake it does not finish by its handshake
// timeout.
tb_scenario! {
	name: a_tunnel_outlives_the_default_route_timeout_of_envoy,
	spec: OneTunnelSpec,
	environment Bare {
		context: Stack::exported(),
		exec: |SetupEnv { trace, context }| async move {
			let mut lease = context.lease(&trace).await?;
			context.round_trip(&mut lease, b"grpc-hop-early").await?;

			sleep(DEFAULT_ROUTE_TIMEOUT + Duration::from_secs(1)).await;
			context.round_trip(&mut lease, b"grpc-hop-late").await
		}
	}
}
