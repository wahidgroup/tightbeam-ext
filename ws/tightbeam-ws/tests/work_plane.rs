//! Cluster work-plane round trips through the WebSocket edge plane, as
//! tightbeam scenarios.

#![cfg(feature = "colony")]

use tightbeam::testing::{ClusterEnv, SetupEnv};
use tightbeam::{tb_scenario, TightBeamError};
use tightbeam_ws::testing::specs::{EdgeWorkSpec, UnservedWorkSpec};
use tightbeam_ws::testing::{WorkClient, WorkGateway, WorkPlane};

/// The identities of the work plane of every scenario.
fn work_plane() -> WorkPlane {
	let issued = WorkPlane::mint("tightbeam-ws");
	issued.expect("the work plane identities issue")
}

// A signed work frame travels from the WebSocket edge through the WebSocket
// colony to the work probe, and the signed answer of the probe verifies end to
// end.
tb_scenario! {
	name: submit_work_round_trips_through_ws_gateway,
	spec: EdgeWorkSpec,
	environment Cluster {
		context: work_plane(),
		start: |SetupEnv { trace, context }| async move { context.gateway::<WorkGateway>(&trace, "127.0.0.1:0").await },
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let probe = context.client();
			let served = probe.submit(&cluster, WorkClient::probe()?, b"ws-work-1").await??;
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
		start: |SetupEnv { trace, context }| async move { context.gateway::<WorkGateway>(&trace, "127.0.0.1:0").await },
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let probe = context.client();
			let refused = probe.submit(&cluster, WorkClient::servlet("unserved")?, b"ws-work-refused").await?;
			assert!(
				matches!(refused, Err(TightBeamError::WorkRefused(_))),
				"an unserved servlet type MUST resolve to a typed WorkRefused refusal, got {refused:?}"
			);

			cluster.stop();
			Ok(())
		}
	}
}
