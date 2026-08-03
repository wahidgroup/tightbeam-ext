//! Multi-party round trip over real localhost TCP: three parties
//! establish the full mesh, exchange directed sends and broadcasts, and
//! every delivery carries authenticated sender attribution.

use core::time::Duration;
use std::collections::BTreeMap;
use std::sync::Arc;

use stoffelnet::network_utils::{Network, NetworkError};
use tightbeam_mpc::testing::establish_mesh;
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;

/// Generous per-await deadline: localhost traffic settles in
/// milliseconds, so a hit means the mesh is broken, not slow.
const DEADLINE: Duration = Duration::from_secs(10);

async fn mesh(count: usize) -> Vec<Arc<tightbeam_mpc::TightbeamNetwork>> {
	establish_mesh(count).await.expect("the mesh should establish")
}

/// Drain `count` deliveries from an inbox into a sender-keyed map.
async fn drain(inbox: &mut Receiver<(usize, Vec<u8>)>, count: usize) -> BTreeMap<usize, Vec<Vec<u8>>> {
	let mut deliveries: BTreeMap<usize, Vec<Vec<u8>>> = BTreeMap::new();
	for _ in 0..count {
		let (sender, payload) = timeout(DEADLINE, inbox.recv())
			.await
			.expect("delivery should beat the deadline")
			.expect("the inbox should stay open");
		deliveries.entry(sender).or_default().push(payload);
	}
	deliveries
}

#[tokio::test(flavor = "multi_thread")]
async fn directed_sends_reach_exactly_the_recipient() {
	let networks = mesh(3).await;
	let mut inbox_1 = networks[1].take_inbox().expect("the inbox should be takeable once");

	let sent = networks[0]
		.send(1, b"zero-to-one")
		.await
		.expect("the directed send should succeed");
	assert_eq!(sent, b"zero-to-one".len(), "send reports the payload length");

	let sent = networks[2]
		.send(1, b"two-to-one")
		.await
		.expect("the directed send should succeed");
	assert_eq!(sent, b"two-to-one".len(), "send reports the payload length");

	let deliveries = drain(&mut inbox_1, 2).await;
	assert_eq!(
		deliveries[&0],
		vec![b"zero-to-one".to_vec()],
		"party 0's message is attributed to party 0"
	);
	assert_eq!(
		deliveries[&2],
		vec![b"two-to-one".to_vec()],
		"party 2's message is attributed to party 2"
	);
}

#[tokio::test(flavor = "multi_thread")]
async fn broadcast_reaches_every_party_including_self() {
	let networks = mesh(3).await;
	let mut inboxes: Vec<_> = networks
		.iter()
		.map(|network| network.take_inbox().expect("the inbox should be takeable once"))
		.collect();

	let total = networks[1].broadcast(b"round-1").await.expect("the broadcast should succeed");
	assert_eq!(total, b"round-1".len() * 3, "broadcast reports bytes across all parties");

	for inbox in &mut inboxes {
		let deliveries = drain(inbox, 1).await;
		assert_eq!(
			deliveries[&1],
			vec![b"round-1".to_vec()],
			"every party hears party 1 exactly once"
		);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn self_send_loops_into_the_local_inbox() {
	let networks = mesh(2).await;
	let mut inbox_0 = networks[0].take_inbox().expect("the inbox should be takeable once");

	networks[0]
		.send(0, b"note-to-self")
		.await
		.expect("the self send should succeed");

	let deliveries = drain(&mut inbox_0, 1).await;
	assert_eq!(
		deliveries[&0],
		vec![b"note-to-self".to_vec()],
		"the self send arrives attributed to self"
	);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_all_to_all_traffic_arrives_fully_attributed() {
	const MESSAGES_PER_PAIR: usize = 25;

	let networks = mesh(3).await;
	let mut inboxes: Vec<_> = networks
		.iter()
		.map(|network| network.take_inbox().expect("the inbox should be takeable once"))
		.collect();

	let mut senders = Vec::new();
	for network in &networks {
		let network = Arc::clone(network);
		senders.push(tokio::spawn(async move {
			for round in 0..MESSAGES_PER_PAIR {
				let payload = format!("from-{}-round-{round}", network.local_party_id());
				network
					.broadcast(payload.as_bytes())
					.await
					.expect("the broadcast should succeed");
			}
		}));
	}
	for sender in senders {
		sender.await.expect("the sender task should finish");
	}

	for inbox in &mut inboxes {
		let deliveries = drain(inbox, 3 * MESSAGES_PER_PAIR).await;
		for (sender, messages) in &deliveries {
			assert_eq!(messages.len(), MESSAGES_PER_PAIR, "every sender delivered its full round count");
			let all_attributed = messages
				.iter()
				.all(|message| message.starts_with(format!("from-{sender}-").as_bytes()));
			assert!(all_attributed, "every payload names the link it arrived on");
		}
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn sends_to_unknown_parties_are_refused() {
	let networks = mesh(2).await;

	let outcome = networks[0].send(9, b"nobody-home").await;
	assert!(
		matches!(outcome, Err(NetworkError::PartyNotFound(9))),
		"an out-of-roster recipient is a PartyNotFound error"
	);
}
