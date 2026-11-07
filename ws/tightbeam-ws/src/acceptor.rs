//! The upgrade plane behind [`WsListener`](crate::protocol::WsListener).
//!
//! The HTTP upgrade reads bytes that an unauthenticated peer controls, so an
//! [`Acceptor`] runs each upgrade apart from the accept loop. A peer that
//! stalls or fails an upgrade costs one slot, and the caller of
//! [`Acceptor::next`] sees finished sockets only.
//!
//! - One slot covers a socket from TCP accept until a caller takes it, so a
//!   full accept loop stops new upgrades (CWE-770).
//! - A deadline covers each upgrade, so a stalled peer returns its slot (CWE-400).
//!
//! # Sources
//!
//! - CWE-400, uncontrolled resource consumption: <https://cwe.mitre.org/data/definitions/400.html>
//! - CWE-770, resource allocation without limits: <https://cwe.mitre.org/data/definitions/770.html>

use core::time::Duration;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{accept_async_with_config, MaybeTlsStream, WebSocketStream};

use tightbeam::constants::{DEFAULT_ACCEPT_RETRY_DELAY, DEFAULT_MAX_SERVER_CONNECTIONS};
use tightbeam::transport::{TransportError, TransportLimits};

use crate::io::WsStream;

/// The byte stream shared by both ends of a WebSocket connection.
pub(crate) type WsInner = MaybeTlsStream<TcpStream>;

/// One socket the upgrade plane holds for a caller.
struct Upgraded {
	stream: WebSocketStream<WsInner>,
	addr: SocketAddr,
	/// Returns to the plane when a caller takes the socket.
	_slot: OwnedSemaphorePermit,
}

/// What the upgrade plane hands to the accept loop.
type Arrival = io::Result<Upgraded>;

/// The ceilings and the deadline every upgrade runs under.
#[derive(Clone, Copy)]
struct UpgradeTerms {
	ceilings: WebSocketConfig,
	deadline: Duration,
}

impl From<&TransportLimits> for UpgradeTerms {
	fn from(limits: &TransportLimits) -> Self {
		Self { ceilings: WsStream::socket_config(limits), deadline: limits.handshake_timeout }
	}
}

/// One accepted TCP socket on its way to a WebSocket.
struct Upgrade {
	tcp: TcpStream,
	addr: SocketAddr,
	slot: OwnedSemaphorePermit,
	terms: UpgradeTerms,
}

impl Upgrade {
	/// Upgrade the socket and queue it. A failed or late upgrade ends here, so
	/// the peer's fault returns the slot and reaches no caller.
	async fn run(self, arrivals: Sender<Arrival>) {
		let socket = MaybeTlsStream::Plain(self.tcp);
		let upgrading = accept_async_with_config(socket, Some(self.terms.ceilings));
		let Ok(Ok(stream)) = timeout(self.terms.deadline, upgrading).await else {
			return;
		};

		let upgraded = Upgraded { stream, addr: self.addr, _slot: self.slot };

		// The receiver leaves only with the plane, which aborts this task.
		let _ = arrivals.send(Ok(upgraded)).await;
	}
}

/// The upgrade plane: a task that accepts TCP and upgrades each socket, and
/// the queue of sockets that finished.
pub(crate) struct Acceptor {
	arrivals: Mutex<Receiver<Arrival>>,
	task: AbortHandle,
}

impl Acceptor {
	/// Start the plane on `listener`, with one slot per connection a server
	/// admits by default.
	pub(crate) fn start(listener: TcpListener, limits: &TransportLimits) -> Self {
		Self::with_slots(listener, limits, DEFAULT_MAX_SERVER_CONNECTIONS.get())
	}

	/// Start the plane on `listener` with `capacity` slots.
	fn with_slots(listener: TcpListener, limits: &TransportLimits, capacity: usize) -> Self {
		let (sender, receiver) = mpsc::channel(capacity);
		let slots = Arc::new(Semaphore::new(capacity));
		let task = tokio::spawn(Self::run(listener, UpgradeTerms::from(limits), slots, sender));

		Self { arrivals: Mutex::new(receiver), task: task.abort_handle() }
	}

	/// Accept TCP while a slot is free, and upgrade each socket on a task the
	/// plane owns, so an abort of this task ends every upgrade in flight.
	async fn run(listener: TcpListener, terms: UpgradeTerms, slots: Arc<Semaphore>, arrivals: Sender<Arrival>) {
		let mut upgrades = JoinSet::new();
		// The semaphore stays open for the life of the plane, so the wait ends
		// only in a slot.
		while let Ok(slot) = Arc::clone(&slots).acquire_owned().await {
			match listener.accept().await {
				Ok((tcp, addr)) => {
					let upgrade = Upgrade { tcp, addr, slot, terms };
					upgrades.spawn(upgrade.run(arrivals.clone()));
				}
				Err(error) => {
					drop(slot);
					Self::report(&arrivals, error);
					sleep(DEFAULT_ACCEPT_RETRY_DELAY).await;
				}
			}

			while upgrades.try_join_next().is_some() {}
		}
	}

	/// Queue a failed TCP accept for the accept loop, which backs off on it.
	///
	/// Only an empty queue takes a failure: the plane paces its own retries,
	/// and a backlog of stale failures would stall the loop after the fault
	/// cleared.
	fn report(arrivals: &Sender<Arrival>, error: io::Error) {
		if arrivals.capacity() == arrivals.max_capacity() {
			let _ = arrivals.try_send(Err(error));
		}
	}

	/// The next upgraded socket, and the address of its peer.
	///
	/// Cancel safe: a socket stays queued until this call returns it.
	///
	/// # Errors
	///
	/// - [`TransportError::IoError`] -- the listener failed to accept a TCP connection.
	/// - [`TransportError::ConnectionClosed`] -- the plane stopped.
	pub(crate) async fn next(&self) -> Result<(WebSocketStream<WsInner>, SocketAddr), TransportError> {
		let mut arrivals = self.arrivals.lock().await;
		match arrivals.recv().await {
			Some(Ok(upgraded)) => Ok((upgraded.stream, upgraded.addr)),
			Some(Err(error)) => Err(TransportError::IoError(error)),
			None => Err(TransportError::ConnectionClosed),
		}
	}
}

impl Drop for Acceptor {
	fn drop(&mut self) {
		self.task.abort();
	}
}

#[cfg(test)]
mod tests {
	use tokio::io::AsyncReadExt;
	use tokio::task::yield_now;
	use tokio_tungstenite::connect_async;

	use super::*;

	type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

	/// How long a healthy upgrade may take on loopback.
	const PROMPT: Duration = Duration::from_secs(2);

	/// How long a test watches for an upgrade that MUST NOT finish.
	const HELD: Duration = Duration::from_millis(200);

	/// Start a plane with `capacity` slots on an ephemeral loopback port.
	async fn plane(limits: &TransportLimits, capacity: usize) -> Result<(Acceptor, SocketAddr), io::Error> {
		let listener = TcpListener::bind("127.0.0.1:0").await?;
		let addr = listener.local_addr()?;
		Ok((Acceptor::with_slots(listener, limits, capacity), addr))
	}

	/// A plane with no task, fed by the test.
	fn idle_plane(arrivals: Receiver<Arrival>) -> Acceptor {
		let task = tokio::spawn(async {});
		Acceptor { arrivals: Mutex::new(arrivals), task: task.abort_handle() }
	}

	#[tokio::test]
	async fn a_full_plane_stops_new_upgrades() -> TestResult {
		let (acceptor, addr) = plane(&TransportLimits::default(), 1).await?;
		let url = format!("ws://{addr}/");

		let first = connect_async(url.clone()).await?;
		let mut second = tokio::spawn(connect_async(url));

		let held = timeout(HELD, &mut second).await;
		assert!(held.is_err(), "a socket waiting for a caller MUST hold its slot");

		timeout(PROMPT, acceptor.next()).await??;
		let second = timeout(PROMPT, second).await???;

		drop((first, second));
		Ok(())
	}

	#[tokio::test]
	async fn a_late_upgrade_returns_its_slot() -> TestResult {
		let limits = TransportLimits { handshake_timeout: Duration::from_millis(50), ..TransportLimits::default() };
		let (acceptor, addr) = plane(&limits, 1).await?;

		let _stalled = TcpStream::connect(addr).await?;
		let client = tokio::spawn(connect_async(format!("ws://{addr}/")));

		timeout(PROMPT, acceptor.next()).await??;
		client.await??;
		Ok(())
	}

	#[tokio::test]
	async fn a_failure_enters_only_an_empty_queue() -> TestResult {
		let (sender, mut receiver) = mpsc::channel(2);
		Acceptor::report(&sender, io::ErrorKind::OutOfMemory.into());
		Acceptor::report(&sender, io::ErrorKind::OutOfMemory.into());
		drop(sender);
		assert!(receiver.recv().await.is_some());
		assert!(receiver.recv().await.is_none());
		Ok(())
	}

	#[tokio::test]
	async fn a_listener_failure_reaches_the_caller() -> TestResult {
		let (sender, receiver) = mpsc::channel(1);
		let acceptor = idle_plane(receiver);

		Acceptor::report(&sender, io::ErrorKind::OutOfMemory.into());

		let failure = timeout(PROMPT, acceptor.next()).await?;
		assert!(matches!(failure, Err(TransportError::IoError(_))));
		Ok(())
	}

	#[tokio::test]
	async fn a_stopped_plane_reads_as_closed() -> TestResult {
		let (sender, receiver) = mpsc::channel(1);
		let acceptor = idle_plane(receiver);
		drop(sender);

		let closed = timeout(PROMPT, acceptor.next()).await?;
		assert!(matches!(closed, Err(TransportError::ConnectionClosed)));
		Ok(())
	}

	#[tokio::test]
	async fn a_dropped_plane_ends_the_upgrades_in_flight() -> TestResult {
		let (acceptor, addr) = plane(&TransportLimits::default(), 2).await?;
		let mut stalled = TcpStream::connect(addr).await?;

		// This test runs on one thread, so one yield lets the plane take the
		// socket before the drop ends the upgrade.
		yield_now().await;
		drop(acceptor);

		let mut byte = [0_u8; 1];
		let read = timeout(PROMPT, stalled.read(&mut byte)).await?;
		assert!(!matches!(read, Ok(1..)), "a dropped plane MUST close its sockets");
		Ok(())
	}
}
