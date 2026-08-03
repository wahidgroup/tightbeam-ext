//! Shared fixture for MPC integration suites: topology, engine setup,
//! and one traced square-round used by scenario bodies.
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
use stoffelcrypto::common::MPCProtocol;
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelcrypto::honeybadger::{HoneyBadgerMPCClient, HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts, SessionId};
use stoffelnet::network_utils::ClientId;
use tightbeam::TightBeamError;
use tightbeam_mpc::testing::{establish_mesh, TestTopology};
use tightbeam_mpc::{ClientSession, PartySession, TightbeamClient, TightbeamNetwork, TraceHandle};

/// What every fixture helper and scenario body returns, so exec
/// closures propagate failures with `?` instead of unwrapping.
pub type Outcome<T> = Result<T, TightBeamError>;

pub type Engine = HoneyBadgerMPCNode<Fr, Avid<SessionId>>;
pub type Party = PartySession<Fr, Avid<SessionId>>;
pub type Client = ClientSession<Fr, Avid<SessionId>>;

/// Adapt any failure into the scenario error space, so `?` carries it
/// out of an exec closure and fails the test with its cause chain.
pub fn scenario_error(cause: impl Into<Box<dyn Error + Send + Sync>>) -> TightBeamError {
	TightBeamError::IoError(io::Error::other(cause))
}

/// Establish meshed parties plus an authorized consumer.
pub async fn topology(parties: usize, client_id: ClientId) -> Outcome<TestTopology> {
	TestTopology::establish(parties, client_id).await.map_err(scenario_error)
}

/// Establish a party-only mesh.
pub async fn mesh(parties: usize) -> Outcome<Vec<Arc<TightbeamNetwork>>> {
	establish_mesh(parties).await.map_err(scenario_error)
}

/// Tunables for one [`party_engine`] setup call.
pub struct EngineSpec {
	pub parties: usize,
	pub threshold: usize,
	pub triples: usize,
	pub inputs: usize,
	pub instance: u32,
	pub consumers: Vec<ClientId>,
	pub timeout: Duration,
}

/// Build one engine node from `spec`.
pub fn party_engine(id: usize, spec: &EngineSpec) -> Outcome<Engine> {
	let opts = HoneyBadgerMPCNodeOpts::new(
		spec.parties,
		spec.threshold,
		spec.triples,
		spec.inputs,
		spec.instance,
		0,
		0,
		0,
		0,
		spec.timeout,
	)
	.map_err(scenario_error)?;

	let node = <Engine as MPCProtocol<Fr, RobustShare<Fr>, TightbeamNetwork>>::setup(id, opts, spec.consumers.clone())
		.map_err(scenario_error)?;
	Ok(node)
}

/// Open sessions for every party. Party 0 records into `trace`; the
/// rest stay on isolated collectors so assertion specs stay lean.
pub fn open_parties(
	nodes: Vec<Engine>,
	networks: Vec<Arc<TightbeamNetwork>>,
	trace: TraceHandle,
) -> Outcome<Vec<Party>> {
	let mut sessions = Vec::with_capacity(nodes.len());
	let mut pairs = nodes.into_iter().zip(networks);
	let Some((observed_node, observed_net)) = pairs.next() else {
		return Err(scenario_error("the roster names at least one party"));
	};

	let observed = Party::open(observed_node, observed_net)
		.map_err(scenario_error)?
		.with_trace(trace);
	sessions.push(observed);

	for (node, network) in pairs {
		let session = Party::open(node, network).map_err(scenario_error)?;
		sessions.push(session);
	}

	Ok(sessions)
}

/// Open a consumer session that records into `trace`.
pub fn open_client(
	engine: HoneyBadgerMPCClient<Fr, Avid<SessionId>>,
	network: Arc<TightbeamClient>,
	trace: TraceHandle,
) -> Outcome<Client> {
	let opened = Client::open(engine, network).map_err(scenario_error)?;
	let client = opened.with_trace(trace);
	Ok(client)
}

/// Parameters for [`square_round`].
pub struct SquareRound {
	pub parties: usize,
	pub threshold: usize,
	pub consumer: ClientId,
	pub inputs: &'static [u64],
	pub instance: u32,
	pub stage_deadline: Duration,
	pub preprocess_deadline: Duration,
	pub client_ready: Duration,
	pub input_wait: Duration,
	pub engine_timeout: Duration,
}

/// One traced round: preprocess, collect, square multiply, deliver.
/// Party 0 and the consumer share `trace` so the scenario collector
/// sees the live phase sequence without mesh link noise.
pub async fn square_round(params: SquareRound, trace: TraceHandle) -> Outcome<Vec<Fr>> {
	let formed = topology(params.parties, params.consumer).await?;
	let triples = params.inputs.len().max(2 * params.threshold + 1);
	let spec = EngineSpec {
		parties: params.parties,
		threshold: params.threshold,
		triples,
		inputs: params.inputs.len(),
		instance: params.instance,
		consumers: vec![params.consumer],
		timeout: params.engine_timeout,
	};

	let mut nodes = Vec::with_capacity(params.parties);
	for id in 0..params.parties {
		let node = party_engine(id, &spec)?;
		nodes.push(node);
	}

	let sessions = open_parties(nodes, formed.networks, trace.clone())?;
	let values: Vec<Fr> = params.inputs.iter().map(|value| Fr::from(*value)).collect();
	let consumer_engine = HoneyBadgerMPCClient::new(
		params.consumer,
		params.parties,
		params.threshold,
		params.instance,
		values,
		params.inputs.len(),
	)
	.map_err(scenario_error)?;
	let mut consumer = open_client(consumer_engine, formed.client, trace)?;

	for session in &sessions {
		session
			.await_clients(&[params.consumer], params.client_ready)
			.await
			.map_err(scenario_error)?;
	}

	let preprocessing = sessions.into_iter().map(|mut session| {
		tokio::spawn(async move {
			let mut rng = StdRng::from_rng(OsRng).map_err(scenario_error)?;
			session.preprocess(&mut rng).await.map_err(scenario_error)?;
			Outcome::Ok(session)
		})
	});
	let sessions = await_sessions(join_all(preprocessing), params.preprocess_deadline).await?;

	let input_phase = sessions.into_iter().map(|mut session| {
		let consumer_id = params.consumer;
		let input_len = params.inputs.len();
		let wait = params.input_wait;
		tokio::spawn(async move {
			let shares = session
				.collect_input(consumer_id, input_len, wait)
				.await
				.map_err(scenario_error)?;
			Outcome::Ok((session, shares))
		})
	});
	let collected = await_sessions(join_all(input_phase), params.stage_deadline).await?;

	let multiplications = collected.into_iter().map(|(mut session, shares)| {
		tokio::spawn(async move {
			let left = shares.clone();
			let products = session.multiply(left, shares).await.map_err(scenario_error)?;
			Outcome::Ok((session, products))
		})
	});
	let products = await_sessions(join_all(multiplications), params.stage_deadline).await?;

	for (mut session, shares) in products {
		session.send_output(params.consumer, shares).await.map_err(scenario_error)?;
	}

	let recovered = consumer.wait_output(params.stage_deadline).await.map_err(scenario_error)?;
	Ok(recovered)
}

async fn await_sessions<T>(
	work: impl core::future::Future<Output = Vec<Result<Outcome<T>, tokio::task::JoinError>>>,
	deadline: Duration,
) -> Outcome<Vec<T>> {
	let outcomes = tokio::time::timeout(deadline, work)
		.await
		.map_err(|_| scenario_error("stage deadline elapsed"))?;

	let mut items = Vec::with_capacity(outcomes.len());
	for outcome in outcomes {
		let item = outcome.map_err(scenario_error)??;
		items.push(item);
	}
	Ok(items)
}
