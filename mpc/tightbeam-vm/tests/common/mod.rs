//! Shared fixture for the VM integration suites: localhost topology,
//! party-host spawning, and the tunables every scenario runs under.
//!
//! Each integration target compiles this module separately and uses
//! its own subset, so items unused by one target are still live in
//! another.
#![allow(dead_code)]

use core::error::Error;
use core::time::Duration;
use std::io;
use std::sync::Arc;

use ark_bls12_381::Fr;
use ark_std::rand::rngs::{OsRng, StdRng};
use ark_std::rand::SeedableRng;
use futures_util::future::join_all;
use stoffelcrypto::common::rbc::rbc::Avid;
use stoffelcrypto::honeybadger::SessionId;
use stoffelnet::network_utils::ClientId;
use tightbeam::TightBeamError;
use tightbeam_mpc::testing::TestTopology;
use tightbeam_mpc::{TightbeamClient, TightbeamNetwork};
use tightbeam_vm::{TraceHandle, ValidProgram, VmConsumer, VmParty, VmPartyConfig};
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// What every fixture helper and scenario body returns, so exec
/// closures propagate failures with `?` instead of unwrapping.
pub type Outcome<T> = Result<T, TightBeamError>;

/// The engine instantiation every suite drives.
pub type Party = VmParty<Fr, Avid<SessionId>>;

/// The consumer id every suite authorizes.
pub const CONSUMER: ClientId = 100;

/// How long the consumer waits for unanimous digest echoes.
pub const SUBMIT_DEADLINE: Duration = Duration::from_secs(30);

/// How long the consumer waits for the reconstructed output.
pub const OUTPUT_DEADLINE: Duration = Duration::from_secs(60);

/// How long party runs may take end to end.
pub const RUN_DEADLINE: Duration = Duration::from_secs(120);

/// Adapt any failure into the scenario error space, so `?` carries it
/// out of an exec closure and fails the test with its cause chain.
pub fn scenario_error(cause: impl Into<Box<dyn Error + Send + Sync>>) -> TightBeamError {
	TightBeamError::IoError(io::Error::other(cause))
}

/// Establish `parties` meshed parties plus the consumer over
/// ephemeral localhost ports. Session/party traces stay off the mesh
/// config so assertion specs count host lifecycle events only.
pub async fn topology(parties: usize) -> Outcome<(Vec<Arc<TightbeamNetwork>>, Arc<TightbeamClient>)> {
	let formed = TestTopology::establish(parties, CONSUMER).await.map_err(scenario_error)?;
	Ok((formed.networks, formed.client))
}

/// Receive on every party (party 0 traced), submit from a traced
/// consumer, then wait for hosts. Scenario bodies stay one call.
pub async fn agree_submission(
	parties: usize,
	threshold: usize,
	program: &ValidProgram,
	trace: TraceHandle,
) -> Outcome<()> {
	let (networks, client_net) = topology(parties).await?;
	let receives = spawn_receives(networks, threshold, trace.clone());

	let mut consumer = VmConsumer::new(client_net).map_err(scenario_error)?.with_trace(trace);
	consumer.submit(program, SUBMIT_DEADLINE).await.map_err(scenario_error)?;

	await_hosts(receives, SUBMIT_DEADLINE).await?;
	Ok(())
}

/// The tunables every suite runs parties under.
pub fn party_config(threshold: usize, trace: TraceHandle) -> VmPartyConfig {
	VmPartyConfig {
		threshold,
		submission_deadline: SUBMIT_DEADLINE,
		client_ready_deadline: Duration::from_secs(10),
		input_wait: Duration::from_secs(10),
		reveal_deadline: Duration::from_secs(30),
		engine_timeout: Duration::from_secs(60),
		trace,
	}
}

/// One handle per party: the first records into `trace` so assertion
/// specs count a single host's events, the rest stay isolated.
fn per_party_traces(count: usize, trace: TraceHandle) -> Vec<TraceHandle> {
	let mut traces = vec![trace];
	traces.resize_with(count, TraceHandle::default);
	traces
}

/// Spawn one full receive-and-run per party. Party 0 records into
/// `trace`.
pub fn spawn_runs(
	networks: Vec<Arc<TightbeamNetwork>>,
	threshold: usize,
	trace: TraceHandle,
) -> Vec<JoinHandle<Outcome<Party>>> {
	let traces = per_party_traces(networks.len(), trace);
	networks
		.into_iter()
		.zip(traces)
		.map(|(network, trace)| {
			tokio::spawn(async move {
				let mut party: Party = Party::receive(network, party_config(threshold, trace))
					.await
					.map_err(scenario_error)?;
				let mut rng = StdRng::from_rng(OsRng).map_err(scenario_error)?;
				party.run(&mut rng).await.map_err(scenario_error)?;
				Ok(party)
			})
		})
		.collect()
}

/// Spawn one submission receive (no run) per party. Party 0 records
/// into `trace`.
pub fn spawn_receives(
	networks: Vec<Arc<TightbeamNetwork>>,
	threshold: usize,
	trace: TraceHandle,
) -> Vec<JoinHandle<Outcome<Party>>> {
	let traces = per_party_traces(networks.len(), trace);
	networks
		.into_iter()
		.zip(traces)
		.map(|(network, trace)| {
			tokio::spawn(async move {
				Party::receive(network, party_config(threshold, trace))
					.await
					.map_err(scenario_error)
			})
		})
		.collect()
}

/// Wait for every party task and hand the hosts back alive: dropping
/// a host tears down its mesh while slower peers still depend on the
/// links.
pub async fn await_hosts(runs: Vec<JoinHandle<Outcome<Party>>>, deadline: Duration) -> Outcome<Vec<Party>> {
	let outcomes = timeout(deadline, join_all(runs)).await.map_err(scenario_error)?;

	let mut hosts = Vec::with_capacity(outcomes.len());
	for outcome in outcomes {
		hosts.push(outcome.map_err(scenario_error)??);
	}
	Ok(hosts)
}
