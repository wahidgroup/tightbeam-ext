//! HoneyBadgerMPC end to end over the tightbeam mesh: five parties run
//! offline preprocessing (RanSha, RanDouSha, triple generation), then an
//! online Beaver multiplication, entirely over mutually-authenticated
//! multiplexed tightbeam links on localhost TCP. The output stage
//! reconstructs the products from every party's result shares and checks
//! them against the plaintext arithmetic.

use core::time::Duration;
use std::collections::BTreeMap;
use std::sync::Arc;

use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::rand::rngs::{OsRng, StdRng};
use ark_std::rand::SeedableRng;
use ark_std::test_rng;
use stoffelcrypto::common::rbc::rbc::Avid;
use stoffelcrypto::common::{MPCProtocol, PreprocessingMPCProtocol, SecretSharingScheme};
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelcrypto::honeybadger::{HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts, SessionId};
use tightbeam_mpc::testing::establish_mesh;
use tightbeam_mpc::TightbeamNetwork;
use tokio::time::timeout;

/// The engine under test, running Avid reliable broadcast.
type Engine = HoneyBadgerMPCNode<Fr, Avid<SessionId>>;

/// HoneyBadgerMPC needs at least five parties.
const PARTIES: usize = 5;

/// Corruption threshold: must satisfy `t < (n + 2) / 3`.
const THRESHOLD: usize = 1;

/// Products computed in the online phase.
const MULTIPLICATIONS: usize = 2;

/// Shared protocol instance id: every party must agree on it.
const INSTANCE: u32 = 111;

/// Offline preprocessing runs many chained subprotocols; generous so a
/// hit means breakage, not a slow machine.
const PREPROCESSING_DEADLINE: Duration = Duration::from_secs(90);

/// The online multiplication is a couple of rounds.
const MUL_DEADLINE: Duration = Duration::from_secs(30);

/// Build one engine node bound to the tightbeam network type.
fn engine(id: usize, opts: &HoneyBadgerMPCNodeOpts) -> Engine {
	<Engine as MPCProtocol<Fr, RobustShare<Fr>, TightbeamNetwork>>::setup(id, opts.clone(), Vec::new())
		.expect("the engine node should set up")
}

/// Drive one party's message loop: every mesh delivery goes into the
/// engine's dispatcher. Engine nodes share state through clones, so the
/// loop's clone and the caller's handle see one protocol state.
fn spawn_message_loop(node: &Engine, network: &Arc<TightbeamNetwork>) {
	let mut inbox = network.take_inbox().expect("the inbox should be takeable once");
	let mut node = node.clone();
	let network = Arc::clone(network);

	tokio::spawn(async move {
		while let Some((sender, raw)) = inbox.recv().await {
			let _ = node.process(sender, raw, Arc::clone(&network)).await;
		}
	});
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn honeybadger_preprocessing_mul_and_output_over_tightbeam() {
	let networks = establish_mesh(PARTIES).await.expect("the mesh should establish");

	// Triple demand rounds up to a multiple of the recon group (2t+1),
	// so ask for exactly one group's worth and expect MULTIPLICATIONS
	// of them to survive the online phase.
	let opts = HoneyBadgerMPCNodeOpts::new(
		PARTIES,
		THRESHOLD,
		2 * THRESHOLD + 1,
		2,
		INSTANCE,
		0,
		0,
		0,
		0,
		Duration::from_secs(60),
	)
	.expect("the protocol options should validate");

	let nodes: Vec<Engine> = (0..PARTIES).map(|id| engine(id, &opts)).collect();
	for (node, network) in nodes.iter().zip(&networks) {
		spawn_message_loop(node, network);
	}

	let preprocessing = nodes.iter().zip(&networks).map(|(node, network)| {
		let mut node = node.clone();
		let network = Arc::clone(network);
		tokio::spawn(async move {
			let mut rng = StdRng::from_rng(OsRng).expect("the system rng should seed");
			node.run_preprocessing(network, &mut rng)
				.await
				.expect("preprocessing should complete");
		})
	});
	let outcomes = timeout(PREPROCESSING_DEADLINE, futures_util::future::join_all(preprocessing))
		.await
		.expect("preprocessing should beat the deadline");
	for outcome in outcomes {
		outcome.expect("the preprocessing task should not panic");
	}

	for node in &nodes {
		let material = node.preprocessing_material.lock().await.length();
		assert!(
			material.beaver_triples >= MULTIPLICATIONS,
			"every party holds enough Beaver triples for the online phase"
		);
	}

	let mut rng = test_rng();
	let mut expected = Vec::new();
	let mut x_shares_per_party = vec![Vec::new(); PARTIES];
	let mut y_shares_per_party = vec![Vec::new(); PARTIES];

	for _ in 0..MULTIPLICATIONS {
		let x = Fr::rand(&mut rng);
		let y = Fr::rand(&mut rng);
		expected.push(x * y);

		let x_shares = RobustShare::compute_shares(x, PARTIES, THRESHOLD, None, &mut rng).expect("x should share");
		let y_shares = RobustShare::compute_shares(y, PARTIES, THRESHOLD, None, &mut rng).expect("y should share");
		for party in 0..PARTIES {
			x_shares_per_party[party].push(x_shares[party].clone());
			y_shares_per_party[party].push(y_shares[party].clone());
		}
	}

	let multiplications = nodes.iter().zip(&networks).enumerate().map(|(party, (node, network))| {
		let mut node = node.clone();
		let network = Arc::clone(network);
		let x = x_shares_per_party[party].clone();
		let y = y_shares_per_party[party].clone();
		tokio::spawn(async move {
			let products = node.mul(x, y, network).await.expect("mul should complete");
			(party, products)
		})
	});
	let outcomes = timeout(MUL_DEADLINE, futures_util::future::join_all(multiplications))
		.await
		.expect("multiplication should beat the deadline");

	let mut result_shares: BTreeMap<usize, Vec<RobustShare<Fr>>> = BTreeMap::new();
	for outcome in outcomes {
		let (party, products) = outcome.expect("the multiplication task should not panic");
		assert_eq!(products.len(), MULTIPLICATIONS, "every party yields one share per product");
		result_shares.insert(party, products);
	}

	for (index, product) in expected.iter().enumerate() {
		let shares: Vec<RobustShare<Fr>> = result_shares.values().map(|products| products[index].clone()).collect();

		let (_, recovered) =
			RobustShare::recover_secret(&shares, PARTIES, THRESHOLD).expect("the product should reconstruct");
		assert_eq!(recovered, *product, "the reconstructed product matches plaintext arithmetic");
	}
}
