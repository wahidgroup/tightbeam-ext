//! The upgrade plane behind [`WsListener`](crate::protocol::WsListener), as
//! `docs/ws.md` (Listener) states it.
//!
//! # Sources
//!
//! - CWE-400, uncontrolled resource consumption: <https://cwe.mitre.org/data/definitions/400.html>
//! - CWE-770, resource allocation without limits: <https://cwe.mitre.org/data/definitions/770.html>

use core::future::Future;
use core::pin::pin;
use core::time::Duration;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::{AbortHandle, JoinSet};
use tokio_tungstenite::MaybeTlsStream;

use tightbeam::clock::{Clock, MonotonicInstant, Timer};
use tightbeam::constants::{DEFAULT_ACCEPT_RETRY_DELAY, DEFAULT_MAX_SERVER_CONNECTIONS};
use tightbeam::transport::TransportLimits;

use crate::io::WsStream;

/// The byte stream shared by both ends of a WebSocket connection.
pub(crate) type WsInner = MaybeTlsStream<TcpStream>;

/// One socket the upgrade plane holds for a caller.
struct Upgraded {
	stream: WsStream<WsInner>,
	addr: SocketAddr,
	/// Returns to the plane when a caller takes the socket.
	_slot: OwnedSemaphorePermit,
}

/// One accepted TCP socket on its way to a WebSocket.
struct Upgrade {
	tcp: TcpStream,
	addr: SocketAddr,
	slot: OwnedSemaphorePermit,
	/// The ceilings of the socket, and the deadline of its upgrade.
	limits: TransportLimits,
	/// The bound of the upgrade, on the clock of the listener.
	timer: Timer,
	/// The instant of the TCP accept, which the deadline runs from.
	accepted: MonotonicInstant,
}

impl Upgrade {
	/// Upgrade the socket and queue it. A failed or late upgrade returns its
	/// slot here, so the fault of the peer reaches no caller.
	async fn run(self, sockets: Sender<Upgraded>) {
		let Self { tcp, addr, slot, limits, mut timer, accepted } = self;
		let spent = timer.clock().monotonic().saturating_duration_since(accepted);
		let left = limits.handshake_timeout.saturating_sub(spent);

		let upgrading = pin!(WsStream::upgrade(tcp, &limits));
		let Ok(Ok(stream)) = timer.within(left, upgrading).await else {
			return;
		};

		let upgraded = Upgraded { stream, addr, _slot: slot };

		// The receiver leaves only with the plane, which aborts this task.
		let _ = sockets.send(upgraded).await;
	}
}

/// The clock of the upgrade plane, which times each upgrade from its TCP
/// accept and the retry wait after a failed accept.
struct PlaneClock {
	timer: Timer,
	/// The span of the retry wait.
	retry: Duration,
}

impl PlaneClock {
	/// The clock of a plane on `clock`, whose retry wait spans
	/// [`DEFAULT_ACCEPT_RETRY_DELAY`].
	fn on(clock: Arc<dyn Clock>) -> Self {
		Self { timer: Timer::new(clock), retry: DEFAULT_ACCEPT_RETRY_DELAY }
	}

	/// The upgrade of `tcp`, a socket that the plane accepted now.
	fn accepted(
		&self,
		tcp: TcpStream,
		addr: SocketAddr,
		slot: OwnedSemaphorePermit,
		limits: TransportLimits,
	) -> Upgrade {
		let clock = self.timer.clock();
		let accepted = clock.monotonic();
		let timer = Timer::new(Arc::clone(clock));
		Upgrade { tcp, addr, slot, limits, timer, accepted }
	}

	/// The retry wait after a failed accept, armed here. The slot of the
	/// failed accept returns once the wait is armed.
	fn absorb(&mut self, slot: OwnedSemaphorePermit) -> impl Future<Output = ()> + use<'_> {
		let wait = self.timer.sleep(self.retry);
		drop(slot);
		wait
	}
}

/// The upgrade plane: a task that accepts TCP and upgrades each socket, and
/// the queue of sockets that finished.
///
/// - One slot covers a socket from TCP accept until a caller takes it (CWE-770).
/// - A deadline from the TCP accept covers each upgrade (CWE-400).
/// - The deadline and the accept retry run on the clock of the listener.
pub(crate) struct Acceptor {
	sockets: Mutex<Receiver<Upgraded>>,
	task: AbortHandle,
	/// A share of the slots of the plane, whose free count orders the steps of
	/// a test.
	#[cfg(test)]
	slots: Arc<Semaphore>,
}

impl Acceptor {
	/// Start the plane on `listener`, with one slot per connection a server
	/// admits by default.
	pub(crate) fn start(listener: TcpListener, limits: &TransportLimits, clock: Arc<dyn Clock>) -> Self {
		Self::with_slots(listener, limits, PlaneClock::on(clock), DEFAULT_MAX_SERVER_CONNECTIONS.get())
	}

	/// Start the plane on `listener` with `capacity` slots, on `clock`.
	fn with_slots(listener: TcpListener, limits: &TransportLimits, clock: PlaneClock, capacity: usize) -> Self {
		let (sender, sockets) = mpsc::channel(capacity);
		let slots = Arc::new(Semaphore::new(capacity));
		let task = tokio::spawn(Self::run(listener, *limits, clock, Arc::clone(&slots), sender));

		Self {
			sockets: Mutex::new(sockets),
			task: task.abort_handle(),
			#[cfg(test)]
			slots,
		}
	}

	/// Accept TCP while a slot is free, and upgrade each socket on a task the
	/// plane owns, so an abort of this task ends every upgrade in flight.
	/// After a failed TCP accept, the plane holds the retry wait of
	/// [`PlaneClock::absorb`] before the next accept.
	async fn run(
		listener: TcpListener,
		limits: TransportLimits,
		mut clock: PlaneClock,
		slots: Arc<Semaphore>,
		sockets: Sender<Upgraded>,
	) {
		let mut upgrades = JoinSet::new();
		// The semaphore stays open for the life of the plane, so the wait ends
		// only in a slot.
		while let Ok(slot) = Arc::clone(&slots).acquire_owned().await {
			match listener.accept().await {
				Ok((tcp, addr)) => {
					let upgrade = clock.accepted(tcp, addr, slot, limits);
					upgrades.spawn(upgrade.run(sockets.clone()));
				}
				Err(_shortage) => clock.absorb(slot).await,
			}

			while upgrades.try_join_next().is_some() {}
		}
	}

	/// The next upgraded socket and the address of its peer, or `None` once
	/// the task of the plane stopped.
	///
	/// Cancel safe: a socket stays queued until this call returns it.
	pub(crate) async fn next(&self) -> Option<(WsStream<WsInner>, SocketAddr)> {
		let mut sockets = self.sockets.lock().await;
		let upgraded = sockets.recv().await?;
		Some((upgraded.stream, upgraded.addr))
	}
}

impl Drop for Acceptor {
	fn drop(&mut self) {
		self.task.abort();
	}
}

#[cfg(test)]
mod tests {
	use core::task::{Context, Waker};
	use core::time::Duration;
	use std::process::Command;
	use std::{env, io, thread};

	use tightbeam::clock::ManualClock;
	use tokio::io::AsyncReadExt;
	use tokio::task::yield_now;
	use tokio::time::timeout;
	use tokio_tungstenite::connect_async;

	use super::*;

	type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

	/// How long a healthy upgrade may take on loopback.
	const PROMPT: Duration = Duration::from_secs(2);

	/// The slots of every plane under test, so a slot that a socket holds
	/// shows beside the slot that the plane waits in accept with.
	const CAPACITY: usize = 2;

	/// The retry wait of every plane under test, longer than [`PROMPT`], so
	/// only an advance of the clock of the plane ends it in time.
	const RETRY: Duration = Duration::from_secs(60);

	/// Start a plane on an ephemeral loopback port whose deadlines and retry
	/// wait run on `clock`, and wait until it waits in accept.
	async fn plane(limits: &TransportLimits, clock: Arc<dyn Clock>) -> TestResult<(Acceptor, SocketAddr)> {
		let listener = TcpListener::bind("127.0.0.1:0").await?;
		let addr = listener.local_addr()?;

		let plane_clock = PlaneClock { timer: Timer::new(clock), retry: RETRY };
		let acceptor = Acceptor::with_slots(listener, limits, plane_clock, CAPACITY);
		settled(&acceptor, CAPACITY - 1).await?;
		Ok((acceptor, addr))
	}

	/// Wait until the plane holds `free` slots free.
	async fn settled(acceptor: &Acceptor, free: usize) -> TestResult {
		let settling = async {
			while acceptor.slots.available_permits() != free {
				yield_now().await;
			}
		};

		timeout(PROMPT, settling).await?;
		Ok(())
	}

	// The paused tokio clock moves only while the runtime idles, so only the
	// plane clock can end the retry wait between the two polls.
	#[tokio::test(start_paused = true)]
	async fn a_failed_accept_waits_on_the_clock_of_the_plane() -> TestResult {
		let clock = Arc::new(ManualClock::default());
		let slots = Arc::new(Semaphore::new(1));
		let slot = Arc::clone(&slots).acquire_owned().await?;
		let mut plane_clock = PlaneClock::on(clock.clone());

		let mut context = Context::from_waker(Waker::noop());
		let mut wait = pin!(plane_clock.absorb(slot));
		assert_eq!(slots.available_permits(), 1, "an armed wait MUST return its slot");
		assert!(wait.as_mut().poll(&mut context).is_pending());

		clock.advance(DEFAULT_ACCEPT_RETRY_DELAY);
		assert!(wait.as_mut().poll(&mut context).is_ready());
		Ok(())
	}

	#[tokio::test]
	async fn a_taken_socket_frees_its_slot() -> TestResult {
		let (acceptor, addr) = plane(&TransportLimits::default(), Arc::new(ManualClock::default())).await?;
		let url = format!("ws://{addr}/");

		let first = connect_async(url.clone()).await?;
		let second = connect_async(url.clone()).await?;

		// Every slot holds an upgraded socket, so the third upgrade runs once a
		// caller takes one.
		let third = tokio::spawn(connect_async(url));
		acceptor.next().await.ok_or("the plane stopped")?;

		let third = timeout(PROMPT, third).await???;
		drop((first, second, third));
		Ok(())
	}

	#[tokio::test]
	async fn a_late_upgrade_returns_its_slot() -> TestResult {
		let clock = Arc::new(ManualClock::default());
		let limits = TransportLimits::default();
		let (acceptor, addr) = plane(&limits, clock.clone()).await?;

		// The stalled socket holds a slot from its accept, and the plane waits
		// in accept with the other.
		let _stalled = TcpStream::connect(addr).await?;
		settled(&acceptor, 0).await?;
		clock.advance(limits.handshake_timeout);
		settled(&acceptor, CAPACITY - 1).await?;

		let client = tokio::spawn(connect_async(format!("ws://{addr}/")));
		timeout(PROMPT, acceptor.next()).await?.ok_or("the plane stopped")?;
		client.await??;
		Ok(())
	}

	#[tokio::test]
	async fn a_stopped_plane_reads_as_closed() -> TestResult {
		let (acceptor, _addr) = plane(&TransportLimits::default(), Arc::new(ManualClock::default())).await?;
		acceptor.task.abort();

		let closed = timeout(PROMPT, acceptor.next()).await?;
		assert!(closed.is_none(), "a stopped plane MUST yield no socket");
		Ok(())
	}

	#[tokio::test]
	async fn a_dropped_plane_ends_the_upgrades_in_flight() -> TestResult {
		let (acceptor, addr) = plane(&TransportLimits::default(), Arc::new(ManualClock::default())).await?;
		let mut stalled = TcpStream::connect(addr).await?;

		// The upgrade of the stalled socket holds one slot, and the plane
		// waits in accept with the other.
		settled(&acceptor, 0).await?;
		drop(acceptor);

		let mut byte = [0_u8; 1];
		let read = timeout(PROMPT, stalled.read(&mut byte)).await?;
		assert!(!matches!(read, Ok(1..)), "a dropped plane MUST close its sockets");
		Ok(())
	}

	/// The errno of a process whose descriptor table is full, on Linux and
	/// macOS.
	#[cfg(unix)]
	const TABLE_FULL: i32 = 24;

	/// Copies of one open file, opened until the process holds no free
	/// descriptor. The descriptors free again as the copies drop.
	#[cfg(unix)]
	fn exhaust_descriptors() -> io::Result<Vec<std::fs::File>> {
		let mut held = vec![std::fs::File::open("/dev/null")?];
		loop {
			match held[0].try_clone() {
				Ok(copy) => held.push(copy),
				Err(full) if full.raw_os_error() == Some(TABLE_FULL) => return Ok(held),
				Err(error) => return Err(error),
			}
		}
	}

	/// The variable that marks the child process of
	/// [`a_descriptor_shortage_never_reaches_the_caller`], the one process
	/// where its body runs.
	#[cfg(unix)]
	const SHORTAGE_CHILD: &str = "TIGHTBEAM_WS_SHORTAGE_CHILD";

	/// Run the test of the calling thread alone in a child process that
	/// [`SHORTAGE_CHILD`] marks, and fail unless the child passed that one
	/// test.
	///
	/// libtest names the thread of each test after the test.
	#[cfg(unix)]
	fn in_a_child_process() -> TestResult {
		let thread = thread::current();
		let test = thread.name().ok_or("libtest names the thread of each test")?;
		let child = Command::new(env::current_exe()?)
			.args([test, "--exact"])
			.env(SHORTAGE_CHILD, "1")
			.output()?;

		let report = String::from_utf8_lossy(&child.stdout);
		let passed_alone = child.status.success() && report.contains("test result: ok. 1 passed;");
		assert!(passed_alone, "the child MUST pass this one test:\n{report}");
		Ok(())
	}

	// The body exhausts the descriptors of its process, so it runs only in the
	// child process that the run of this test starts.
	#[cfg(unix)]
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn a_descriptor_shortage_never_reaches_the_caller() -> TestResult {
		if env::var_os(SHORTAGE_CHILD).is_none() {
			return in_a_child_process();
		}

		let clock = Arc::new(ManualClock::default());
		let (acceptor, addr) = plane(&TransportLimits::default(), clock.clone()).await?;

		let socket = tokio::net::TcpSocket::new_v4()?;
		let held = exhaust_descriptors()?;
		let tcp = socket.connect(addr).await?;

		// The failed accept arms its retry wait, then returns the slot it
		// took.
		settled(&acceptor, CAPACITY).await?;
		drop(held);
		clock.advance(RETRY);

		let upgrading = tokio_tungstenite::client_async(format!("ws://{addr}/"), tcp);
		let (accepted, upgraded) = tokio::join!(timeout(PROMPT, acceptor.next()), timeout(PROMPT, upgrading));
		let peer = accepted?.map(|(_, peer)| peer);
		assert!(peer.is_some(), "a cleared shortage MUST yield the socket behind it");
		upgraded??;
		Ok(())
	}
}
