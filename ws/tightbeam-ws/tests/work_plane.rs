//! Cluster work-plane round trips through the WebSocket edge plane, as
//! tightbeam scenarios.
//!
//! The colony (gateway, hive, servlet) runs its internal traffic over TCP, and
//! the gateway binds a WebSocket edge accept plane for external clients. The
//! upstream `SubmitWork` blanket implementation reaches
//! `GenericClient<WsListener>` with no library change in this crate. Each
//! scenario starts the gateway and the hive of one [`WorkPlane`] through the
//! Cluster environment, which registers the hive, and its spec grades the
//! registration and the routing that the gateway records on the trace.

#![cfg(feature = "colony")]
// The colony runtime macros expand `cfg(feature = ...)` probes against the
// invoking crate's feature namespace. Those upstream feature names do not
// exist in this crate, so the leaked cfg warnings carry no signal here.
#![allow(unexpected_cfgs)]

use tightbeam::colony::SubmitWork;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::error::TestingError;
use tightbeam::testing::{ClusterEnv, SetupEnv};
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::{cluster, tb_scenario, TightBeamError};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::specs::{EdgeWorkSpec, UnservedWorkSpec};
use tightbeam_ws::testing::{WorkClient, WorkPlane};

cluster! {
	/// TCP colony gateway with a WebSocket edge accept plane.
	pub WorkPlaneGateway,
	protocol: TokioListener,
	edge: WsListener
}

/// The identities of the work plane of every scenario.
fn work_plane() -> WorkPlane {
	let minted = WorkPlane::mint("tightbeam-ws");
	minted.expect("the work plane identities mint")
}

/// The address of the edge plane of `gateway`, which a gateway with an edge
/// bind address binds as it starts.
fn edge_of(gateway: &WorkPlaneGateway) -> Result<TightBeamSocketAddr, TightBeamError> {
	let bound = gateway.edge_addr().copied();
	bound.ok_or(TightBeamError::TestingError(TestingError::UnexpectedOutcome(
		"the edge plane did not bind",
	)))
}

// A signed work frame travels from the WebSocket edge through the TCP colony
// to the work probe, and the signed answer of the probe verifies end to end.
tb_scenario! {
	name: submit_work_round_trips_through_ws_gateway,
	spec: EdgeWorkSpec,
	environment Cluster {
		context: work_plane(),
		start: |SetupEnv { trace, context }| async move { context.gateway::<WorkPlaneGateway>(&trace, "127.0.0.1:0").await },
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let probe = context.client();
			let mut client = probe.connect::<WsListener>(edge_of(&cluster)?).await?;

			let work = probe.work(b"ws-work-1").await?;
			let served = client.submit_work_to(WorkClient::probe()?, &work).await?;
			let answer = probe.answer(&served)?;
			assert_eq!(answer.as_deref(), Some(&b"pong:3231:true"[..]), "the probe MUST verify the work end to end, both ways");
			assert_eq!(served.metadata().id(), b"ws-work-1", "the probe response MUST correlate with the work id");

			cluster.stop();
			Ok(())
		}
	}
}

// An unserved servlet type has no live trail, so the gateway routes no work,
// and the client reads its refusal as a typed `WorkRefused`.
tb_scenario! {
	name: unserved_type_resolves_to_typed_work_refusal,
	spec: UnservedWorkSpec,
	environment Cluster {
		context: work_plane(),
		start: |SetupEnv { trace, context }| async move { context.gateway::<WorkPlaneGateway>(&trace, "127.0.0.1:0").await },
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let probe = context.client();
			let mut client = probe.connect::<WsListener>(edge_of(&cluster)?).await?;

			let work = probe.work(b"ws-work-refused").await?;
			let refused = client.submit_work_to(WorkClient::servlet("unserved")?, &work).await;
			assert!(
				matches!(refused, Err(TightBeamError::WorkRefused(_))),
				"an unserved servlet type MUST resolve to a typed WorkRefused refusal, got {refused:?}"
			);

			cluster.stop();
			Ok(())
		}
	}
}
