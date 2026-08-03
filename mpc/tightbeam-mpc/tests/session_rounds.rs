//! Session round machine and client-readiness gates over real localhost TCP.

use core::time::Duration;
use std::sync::Arc;

use ark_bls12_381::Fr;
use stoffelcrypto::common::rbc::rbc::Avid;
use stoffelcrypto::common::MPCProtocol;
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelcrypto::honeybadger::{HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts, SessionId};
use tightbeam_mpc::testing::establish_parties;
use tightbeam_mpc::{Error, PartySession, Round, SessionError, TightbeamNetwork};

type Engine = HoneyBadgerMPCNode<Fr, Avid<SessionId>>;
type Party = PartySession<Fr, Avid<SessionId>>;

const PARTIES: usize = 3;
/// `t < (n + 2) / 3` -> for n=3 only t=0 is valid; enough for round-machine checks.
const THRESHOLD: usize = 0;
const CONSUMER: usize = 100;
const INPUT_STORE_WAIT: Duration = Duration::from_millis(50);
const CLIENT_READY_DEADLINE: Duration = Duration::from_millis(200);

fn engine(id: usize) -> Engine {
	let opts = HoneyBadgerMPCNodeOpts::new(PARTIES, THRESHOLD, 1, 1, 1, 0, 0, 0, 0, Duration::from_secs(30))
		.expect("the protocol options should validate");

	<Engine as MPCProtocol<Fr, RobustShare<Fr>, TightbeamNetwork>>::setup(id, opts, vec![CONSUMER])
		.expect("the engine node should set up")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn collect_input_before_preprocess_is_rejected() {
	let networks = establish_parties(PARTIES, CONSUMER)
		.await
		.expect("the parties should establish");

	let mut party = Party::open(engine(0), Arc::clone(&networks[0])).expect("party session should open");
	assert_eq!(party.round(), Round::Idle, "a fresh session starts idle");

	let outcome = party.collect_input(CONSUMER, 1, INPUT_STORE_WAIT).await;
	assert!(
		matches!(
			outcome,
			Err(SessionError::WrongRound { current: Round::Idle, required: Round::Ready })
		),
		"collect_input before preprocess must report WrongRound, got {outcome:?}"
	);
	assert_eq!(party.round(), Round::Idle, "a rejected phase must not advance the round");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn await_clients_times_out_when_the_consumer_never_dials() {
	let networks = establish_parties(PARTIES, CONSUMER)
		.await
		.expect("the parties should establish");
	let outcome = networks[0].await_clients(&[CONSUMER], CLIENT_READY_DEADLINE).await;
	assert!(
		matches!(outcome, Err(Error::ClientsNotReady { connected: 0, expected: 1 })),
		"await_clients must time out with ClientsNotReady, got {outcome:?}"
	);
}
