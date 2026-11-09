//! Cluster work-plane round trips through the gRPC edge plane, as tightbeam
//! scenarios.
//!
//! The colony (gateway, hive, servlet) runs its internal traffic over TCP, and
//! the gateway binds a gRPC edge accept plane for external clients. The
//! upstream `SubmitWork` blanket implementation reaches
//! `GenericClient<GrpcListener>` and `PooledClient<GrpcListener>` with no
//! library change in this crate. Each scenario starts the gateway and the hive
//! of one [`WorkPlane`] through the Cluster environment, which registers the
//! hive, and its spec grades the registration, the routing, and the refusals
//! that the gateway records on the trace.

// The colony runtime macros expand `cfg(feature = ...)` probes against the
// invoking crate's feature namespace. Those upstream feature names do not
// exist in this crate, so the leaked cfg warnings carry no signal here.
#![allow(unexpected_cfgs)]

use tightbeam::builder::TypeBuilder;
use tightbeam::clock::UnixMillis;
use tightbeam::colony::protocol::{ClusterRequest, RegisterHiveRequest};
use tightbeam::colony::work::ClusterWorkResponse;
use tightbeam::colony::SubmitWork;
use tightbeam::instrumentation::events;
use tightbeam::policy::TransitStatus;
use tightbeam::testing::error::TestingError;
use tightbeam::testing::{ClusterEnv, SetupEnv};
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::{cluster, exactly, tb_assert_spec, tb_scenario, Frame, TightBeamError, Version};
use tightbeam_grpc::protocol::{GrpcAddr, GrpcListener};
use tightbeam_ws::testing::specs::{EdgeWorkSpec, UnservedWorkSpec};
use tightbeam_ws::testing::{WorkClient, WorkPlane};

cluster! {
	/// TCP colony gateway with a gRPC edge accept plane.
	pub WorkPlaneGateway,
	protocol: TokioListener,
	edge: GrpcListener
}

/// The identities of the work plane of every scenario.
fn work_plane() -> WorkPlane {
	let minted = WorkPlane::mint("tightbeam-grpc");
	minted.expect("the work plane identities mint")
}

/// The address of the edge plane of `gateway`, which a gateway with an edge
/// bind address binds as it starts.
fn edge_of(gateway: &WorkPlaneGateway) -> Result<GrpcAddr, TightBeamError> {
	let bound = gateway.edge_addr().cloned();
	bound.ok_or(TightBeamError::TestingError(TestingError::UnexpectedOutcome(
		"the edge plane did not bind",
	)))
}

/// A hive registration signed under the transport identity of `plane`, which
/// the edge plane refuses.
async fn registration(plane: &WorkPlane) -> Result<Frame, TightBeamError> {
	let request = ClusterRequest::RegisterHive(RegisterHiveRequest {
		hive_addr: b"127.0.0.1:65001".to_vec(),
		servlet_addresses: Vec::new(),
		metadata: None,
	});

	let order = UnixMillis::now().get();
	let unsigned = Version::V1.compose().with_id(b"grpc-edge-registration").with_order(order);
	let mut frame = unsigned.with_message(request).build()?;

	let signer = plane.transport().signing_identity()?;
	frame.sign_with_provider(&signer).await?;
	Ok(frame)
}

// A signed work frame travels from the gRPC edge through the TCP colony to
// the work probe, and the signed answer of the probe verifies end to end.
tb_scenario! {
	name: submit_work_round_trips_through_grpc_gateway,
	spec: EdgeWorkSpec,
	environment Cluster {
		context: work_plane(),
		start: |SetupEnv { trace, context }| async move { context.gateway::<WorkPlaneGateway>(&trace, "127.0.0.1:0").await },
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let probe = context.client();
			let mut client = probe.connect::<GrpcListener>(edge_of(&cluster)?).await?;

			let work = probe.work(b"grpc-work-1").await?;
			let served = client.submit_work_to(WorkClient::probe()?, &work).await?;
			let answer = probe.answer(&served)?;
			assert_eq!(answer.as_deref(), Some(&b"pong:3231:true"[..]), "the probe MUST verify the work end to end, both ways");
			assert_eq!(served.metadata().id(), b"grpc-work-1", "the probe response MUST correlate with the work id");

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
			let mut client = probe.connect::<GrpcListener>(edge_of(&cluster)?).await?;

			let work = probe.work(b"grpc-work-refused").await?;
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

tb_assert_spec! {
	pub EdgeRegistrationSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_EDGE_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64))
		]
	}
}

// The edge plane admits work alone: it refuses a validly signed hive
// registration, and the hive of the scenario registers through the colony
// plane alone.
tb_scenario! {
	name: the_edge_refuses_a_hive_registration,
	spec: EdgeRegistrationSpec,
	environment Cluster {
		context: work_plane(),
		start: |SetupEnv { trace, context }| async move { context.gateway::<WorkPlaneGateway>(&trace, "127.0.0.1:0").await },
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { context, cluster, .. }| async move {
			let mut client = context.client().connect::<GrpcListener>(edge_of(&cluster)?).await?;

			let request = registration(&context).await?;
			let response = client.emit(request, None).await?.ok_or(TightBeamError::MissingResponse)?;
			let refusal: ClusterWorkResponse = response.decode_message()?;
			assert_eq!(refusal.status, TransitStatus::PermissionDenied, "the edge MUST refuse a hive registration");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PooledEdgeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_REUSE_READY, exactly!(1)),
			(events::CLUSTER_WORK_ROUTED, exactly!(2))
		]
	}
}

// One pooled edge connection serves work across two leases: the second lease
// reuses the connection that the first released, as ready, and the gateway
// routes both works.
//
// The colony pools record on the same trace as the edge pool, and the beat of
// the gateway dials its hive on a schedule of its own, so the spec counts no
// dial. The edge pool alone holds exclusive connections, so a ready reuse is
// the reuse of the edge.
tb_scenario! {
	name: a_pooled_edge_connection_serves_work_across_leases,
	spec: PooledEdgeSpec,
	environment Cluster {
		context: work_plane(),
		start: |SetupEnv { trace, context }| async move { context.gateway::<WorkPlaneGateway>(&trace, "127.0.0.1:0").await },
		hives: |SetupEnv { trace, context }| vec![async move { context.hive(&trace).await }],
		client: |ClusterEnv { trace, context, cluster }| async move {
			let probe = context.client();
			let pool = probe.pool::<GrpcListener>(&trace);
			let edge = edge_of(&cluster)?;

			for id in [&b"grpc-pooled-1"[..], b"grpc-pooled-2"] {
				let mut lease = pool.connect(edge.clone()).await?;
				let work = probe.work(id).await?;
				let served = lease.submit_work_to(WorkClient::probe()?, &work).await?;
				assert_eq!(served.metadata().id(), id, "each lease MUST serve its own work");
			}

			cluster.stop();
			Ok(())
		}
	}
}
