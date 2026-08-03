//! Control-lane isolation over real localhost TCP: control traffic
//! surfaces only on control inboxes, engine traffic only on engine
//! inboxes, in both the party and consumer directions.

use core::time::Duration;

use tightbeam_mpc::testing::TestTopology;
use tokio::time::timeout;

const PARTIES: usize = 3;
const CONSUMER: usize = 100;
const RECEIVE_DEADLINE: Duration = Duration::from_secs(10);
const SILENCE_WINDOW: Duration = Duration::from_millis(300);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_traffic_stays_off_the_engine_inbox() {
	let formed = TestTopology::establish(PARTIES, CONSUMER)
		.await
		.expect("the topology should establish");
	let networks = formed.networks;
	let client = formed.client;

	let mut party_engine = networks[0].take_inbox().expect("the engine inbox should be takeable");
	let mut party_control = networks[0].take_control_inbox().expect("the control inbox should be takeable");

	client
		.send_control(0, b"ctrl-from-client")
		.await
		.expect("the control send should reach party 0");

	let (sender, payload) = timeout(RECEIVE_DEADLINE, party_control.recv())
		.await
		.expect("the control delivery should beat the deadline")
		.expect("the control inbox should stay open");
	assert_eq!(sender, CONSUMER, "control must attribute the consumer");
	assert_eq!(payload, b"ctrl-from-client", "control payload must arrive intact");

	let silent = timeout(SILENCE_WINDOW, party_engine.recv()).await;
	assert!(silent.is_err(), "control traffic must not land on the engine inbox");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn party_control_reaches_the_consumer_control_inbox() {
	let formed = TestTopology::establish(PARTIES, CONSUMER)
		.await
		.expect("the topology should establish");
	let networks = formed.networks;
	let client = formed.client;

	let mut client_engine = client.take_inbox().expect("the client engine inbox should be takeable");
	let mut client_control = client
		.take_control_inbox()
		.expect("the client control inbox should be takeable");

	networks[1]
		.await_clients(&[CONSUMER], Duration::from_secs(10))
		.await
		.expect("party 1 should see the consumer linked");
	networks[1]
		.send_control_to_client(CONSUMER, b"ctrl-to-client")
		.await
		.expect("the control reply should reach the consumer");

	let (sender, payload) = timeout(RECEIVE_DEADLINE, client_control.recv())
		.await
		.expect("the control delivery should beat the deadline")
		.expect("the control inbox should stay open");
	assert_eq!(sender, 1, "control must attribute the sending party");
	assert_eq!(payload, b"ctrl-to-client", "control payload must arrive intact");

	let silent = timeout(SILENCE_WINDOW, client_engine.recv()).await;
	assert!(silent.is_err(), "control traffic must not land on the client engine inbox");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acceptor_side_control_crosses_an_accepted_link() {
	let formed = TestTopology::establish(PARTIES, CONSUMER)
		.await
		.expect("the topology should establish");
	let networks = formed.networks;

	let mut control = networks[0].take_control_inbox().expect("the control inbox should be takeable");

	networks[1]
		.send_control(0, b"peer-ctrl")
		.await
		.expect("the acceptor-side control send should cross the accepted link");

	let (sender, payload) = timeout(RECEIVE_DEADLINE, control.recv())
		.await
		.expect("the control delivery should beat the deadline")
		.expect("the control inbox should stay open");
	assert_eq!(sender, 1, "control must attribute the peer");
	assert_eq!(payload, b"peer-ctrl", "control payload must arrive intact");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_and_mesh_control_deliver() {
	let formed = TestTopology::establish(PARTIES, CONSUMER)
		.await
		.expect("the topology should establish");
	let networks = formed.networks;

	let mut control = networks[2].take_control_inbox().expect("the control inbox should be takeable");

	networks[0]
		.send_control(2, b"mesh-ctrl")
		.await
		.expect("the control send should cross the mesh");
	networks[2]
		.send_control(2, b"local-ctrl")
		.await
		.expect("the local control send should loop back");

	let mut seen = Vec::new();
	for _ in 0..2 {
		let delivery = timeout(RECEIVE_DEADLINE, control.recv())
			.await
			.expect("the control delivery should beat the deadline")
			.expect("the control inbox should stay open");
		seen.push(delivery);
	}

	assert!(
		seen.iter().any(|(sender, payload)| *sender == 0 && payload == b"mesh-ctrl"),
		"mesh control must arrive from party 0"
	);
	assert!(
		seen.iter().any(|(sender, payload)| *sender == 2 && payload == b"local-ctrl"),
		"local control must loop back to party 2"
	);
}
