//! The connection plane behind [`GrpcListener`](crate::protocol::GrpcListener).
//!
//! Every byte before a tunnel call parses comes from a peer that no handshake
//! has proved, so each connection holds a slot and a deadline while no caller
//! holds its tunnel:
//!
//! - A slot covers a connection from TCP accept until a caller takes its
//!   tunnel, so a full plane leaves new connections in the backlog (CWE-770).
//! - A connection that opens no call by `handshake_timeout` closes and returns
//!   its slot (CWE-400). A call that ends before a caller takes its tunnel
//!   leaves that deadline as it was.
//! - A proxy may send the next tunnel call over a connection whose tunnel a
//!   caller took, so the end of that call waits the connection again under a
//!   free slot and a fresh deadline, and with no slot when none is free.
//! - On a TLS edge, a connection completes its TLS handshake on a task of its
//!   own under the slot and the deadline of its lane, so a slow handshake
//!   holds back no other connection, and one that fails or passes the
//!   deadline closes and returns its slot before the HTTP/2 server sees it.
//!
//! The [`Lane`] of each connection holds that state, and every change to it
//! names the call it belongs to, so a call that a later call replaced changes
//! nothing.
//!
//! # Sources
//!
//! - CWE-400, uncontrolled resource consumption: <https://cwe.mitre.org/data/definitions/400.html>
//! - CWE-770, resource allocation without limits: <https://cwe.mitre.org/data/definitions/770.html>

use core::convert::Infallible;
use core::future::Future;
use core::mem;
#[cfg(feature = "couple")]
use core::num::NonZeroU32;
use core::pin::Pin;
use core::task::{ready, Context, Poll, Waker};
use core::time::Duration;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{sleep, sleep_until, timeout, Instant, Sleep};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tokio_stream::Stream;
use tokio_util::sync::PollSemaphore;
use tonic::transport::server::Connected;

use tightbeam::constants::DEFAULT_ACCEPT_RETRY_DELAY;

#[cfg(feature = "couple")]
use crate::couple::Caller;
use crate::tunnel::Arrival;

/// Lock `mutex`. A panic never holds one of these locks across user code, so
/// a poisoned lock still holds a consistent state.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
	mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The slots of one server: the semaphore every connection draws from, and
/// the slot the accept loop holds while it waits for the next TCP connection.
pub(crate) struct Slots {
	semaphore: Arc<Semaphore>,
	parked: Mutex<Option<OwnedSemaphorePermit>>,
}

impl Slots {
	/// `capacity` slots, none of them taken.
	pub(crate) fn new(capacity: usize) -> Arc<Self> {
		let semaphore = Arc::new(Semaphore::new(capacity));
		Arc::new(Self { semaphore, parked: Mutex::new(None) })
	}

	/// A slot for a connection that is already open: a free one, or else the
	/// one the accept loop holds, because an open connection goes before one
	/// still in the backlog.
	fn take(&self) -> Option<OwnedSemaphorePermit> {
		let free = Arc::clone(&self.semaphore).try_acquire_owned();
		free.ok().or_else(|| lock(&self.parked).take())
	}

	/// Hold `slot` for the next TCP accept.
	fn park(&self, slot: OwnedSemaphorePermit) {
		*lock(&self.parked) = Some(slot);
	}

	/// The slot held for the next TCP accept, unless an open connection took it.
	fn reclaim(&self) -> Option<OwnedSemaphorePermit> {
		lock(&self.parked).take()
	}
}

/// What a connection waits under, and which calls hold it. The first call
/// fixes the kind of the connection: a tunnel stage never becomes a coupled
/// stage, and a coupled stage never becomes a tunnel stage.
enum Stage {
	/// No call has come. The connection holds a slot and closes at
	/// `deadline`, or never when the idle time passes the range of the clock.
	Fresh { slot: OwnedSemaphorePermit, deadline: Option<Instant> },
	/// The connection carries tunnels.
	Tunnel(TunnelStage),
	/// The connection carries coupled calls.
	#[cfg(feature = "couple")]
	Coupled(CoupledStage),
	/// The connection closed.
	Closed,
}

/// The stage of a connection that carries tunnels.
enum TunnelStage {
	/// No call holds the connection. It holds a slot and closes at
	/// `deadline`.
	Waiting { slot: OwnedSemaphorePermit, deadline: Option<Instant> },
	/// No call holds the connection and no slot was free when its last call
	/// ended. A call takes a slot if one is free by then, and the connection
	/// closes at `deadline`.
	Draining { deadline: Option<Instant> },
	/// The tunnel of `call` waits for a caller of `accept`, under the slot of
	/// the connection. The connection closes at `expires` when no caller has
	/// taken the tunnel by then, and `waiting` is the deadline it waits under
	/// again when the call ends first.
	Queued {
		slot: OwnedSemaphorePermit,
		waiting: Option<Instant>,
		expires: Option<Instant>,
		call: u64,
	},
	/// A caller holds the tunnel of `call`, and the slot returned.
	Established { call: u64 },
}

/// The stage of a connection that carries coupled calls. It holds a permit of
/// the coupled lanes in both stages, so the permits bound connections.
#[cfg(feature = "couple")]
enum CoupledStage {
	/// `calls` coupled calls are open on the connection.
	Busy { calls: NonZeroU32, permit: OwnedSemaphorePermit },
	/// No coupled call is open, and the connection closes at `deadline`.
	Idle { permit: OwnedSemaphorePermit, deadline: Option<Instant> },
}

impl Stage {
	/// The deadline at which the connection closes in this stage, if any.
	fn deadline(&self) -> Option<Instant> {
		match self {
			Self::Fresh { deadline, .. } => *deadline,
			Self::Tunnel(TunnelStage::Waiting { deadline, .. } | TunnelStage::Draining { deadline }) => *deadline,
			Self::Tunnel(TunnelStage::Queued { expires, .. }) => *expires,
			#[cfg(feature = "couple")]
			Self::Coupled(CoupledStage::Idle { deadline, .. }) => *deadline,
			#[cfg(feature = "couple")]
			Self::Coupled(CoupledStage::Busy { .. }) => None,
			Self::Tunnel(TunnelStage::Established { .. }) | Self::Closed => None,
		}
	}
}

/// The stage of one connection, the number of the last call it admitted, and
/// the waker of its last read, which a change of stage wakes so the read sees
/// it.
struct LaneState {
	stage: Stage,
	calls: u64,
	reader: Option<Waker>,
}

impl LaneState {
	/// Enter `stage`, and wake the read of the connection so it sees the
	/// deadline of the stage.
	fn enter(&mut self, stage: Stage) {
		self.stage = stage;
		if let Some(reader) = self.reader.take() {
			reader.wake();
		}
	}
}

/// What every lane of one server lives under, which the edge of the server
/// decides.
#[derive(Clone)]
pub(crate) struct LaneTerms {
	/// How long a connection waits for its next call.
	pub(crate) idle: Duration,
	/// Whether a tunnel call replaces a queued call on its connection. Only a
	/// server that admits one stream per connection replaces, because there
	/// a queued call that a new call meets has ended.
	pub(crate) replaces: bool,
	/// The permits of the coupled lanes, or `None` when the server carries no
	/// coupled call.
	#[cfg(feature = "couple")]
	pub(crate) coupled: Option<Arc<Semaphore>>,
}

/// The slot, the deadline, and the calls of one connection, shared by its
/// I/O, which closes the connection, by the calls that hold it, and by the
/// tunnel that waits for a caller.
#[derive(Clone)]
pub(crate) struct Lane(Arc<LaneInner>);

struct LaneInner {
	state: Mutex<LaneState>,
	slots: Arc<Slots>,
	terms: LaneTerms,
}

impl Lane {
	/// A lane that waits under `slot` on the `terms` of its server.
	fn new(slot: OwnedSemaphorePermit, slots: Arc<Slots>, terms: LaneTerms) -> Self {
		let deadline = Instant::now().checked_add(terms.idle);
		let stage = Stage::Fresh { slot, deadline };
		let state = Mutex::new(LaneState { stage, calls: 0, reader: None });
		Self(Arc::new(LaneInner { state, slots, terms }))
	}

	/// The deadline of a wait that starts now.
	fn fresh_deadline(&self) -> Option<Instant> {
		Instant::now().checked_add(self.0.terms.idle)
	}

	/// Admit a tunnel call on the connection, under its slot, and give its
	/// tunnel until a fresh deadline to reach a caller:
	///
	/// - A fresh or waiting connection gives the call its slot and deadline.
	/// - On a server that replaces, a queued call whose stream closed before a
	///   caller took its tunnel gives the new call its place and its expiry,
	///   so one connection never holds two slots and never renews its expiry
	///   by replacing calls.
	/// - On a server that replaces, after a caller took a tunnel, the call
	///   takes a free slot and a fresh deadline. A draining connection keeps
	///   its deadline, so a peer cannot hold it open with calls that find no
	///   slot.
	/// - On a server that does not replace, a queued or established tunnel
	///   refuses the call, because a second live call may share the
	///   connection.
	///
	/// `None` when the call is refused: no slot is free, a coupled call holds
	/// the connection, or the connection closed.
	pub(crate) fn claim_tunnel(&self) -> Option<Claim> {
		let mut state = lock(&self.0.state);
		let replaces = self.0.terms.replaces;
		let stage = mem::replace(&mut state.stage, Stage::Closed);
		let (slot, waiting, expires) = match stage {
			Stage::Fresh { slot, deadline } | Stage::Tunnel(TunnelStage::Waiting { slot, deadline }) => {
				(slot, deadline, self.fresh_deadline())
			}
			Stage::Tunnel(TunnelStage::Queued { slot, waiting, expires, .. }) if replaces => (slot, waiting, expires),
			Stage::Tunnel(TunnelStage::Established { .. }) if replaces => {
				let deadline = self.fresh_deadline();
				let Some(slot) = self.0.slots.take() else {
					state.enter(Stage::Tunnel(TunnelStage::Draining { deadline }));
					return None;
				};
				(slot, deadline, self.fresh_deadline())
			}
			Stage::Tunnel(TunnelStage::Draining { deadline }) => {
				let Some(slot) = self.0.slots.take() else {
					state.enter(Stage::Tunnel(TunnelStage::Draining { deadline }));
					return None;
				};
				(slot, deadline, self.fresh_deadline())
			}
			held @ Stage::Tunnel(_) => {
				state.stage = held;
				return None;
			}
			#[cfg(feature = "couple")]
			held @ Stage::Coupled(_) => {
				state.stage = held;
				return None;
			}
			Stage::Closed => return None,
		};

		state.calls += 1;
		let call = state.calls;
		state.enter(Stage::Tunnel(TunnelStage::Queued { slot, waiting, expires, call }));
		Some(Claim { lane: self.clone(), call })
	}

	/// Hand the tunnel of `call` to a caller, which returns the slot.
	///
	/// `false` when the call ended, a later call replaced it, or the
	/// connection closed, so the tunnel is dead.
	fn establish(&self, call: u64) -> bool {
		let mut state = lock(&self.0.state);
		let queued = matches!(state.stage, Stage::Tunnel(TunnelStage::Queued { call: queued, .. }) if queued == call);
		if queued {
			state.enter(Stage::Tunnel(TunnelStage::Established { call }));
		}

		queued
	}

	/// End the tunnel call `call`:
	///
	/// - A call no caller took returns the connection to the slot and the
	///   deadline it waited under before the call.
	/// - A call whose tunnel a caller took waits the connection again under a
	///   free slot and a fresh deadline, or drains when no slot is free.
	/// - The end of a call that a later call replaced changes nothing.
	fn end(&self, call: u64) {
		let mut state = lock(&self.0.state);
		let stage = mem::replace(&mut state.stage, Stage::Closed);
		let next = match stage {
			Stage::Tunnel(TunnelStage::Queued { slot, waiting, call: queued, .. }) if queued == call => {
				Stage::Tunnel(TunnelStage::Waiting { slot, deadline: waiting })
			}
			Stage::Tunnel(TunnelStage::Established { call: held }) if held == call => {
				let deadline = self.fresh_deadline();
				match self.0.slots.take() {
					Some(slot) => Stage::Tunnel(TunnelStage::Waiting { slot, deadline }),
					None => Stage::Tunnel(TunnelStage::Draining { deadline }),
				}
			}
			unchanged => unchanged,
		};

		state.enter(next);
	}

	/// Open a coupled call on the connection:
	///
	/// - A fresh connection returns its slot and takes a permit of the
	///   coupled lanes, because its caller proved its TLS client chain.
	/// - An idle or busy coupled connection counts one more call under the
	///   permit it holds.
	///
	/// `None` when the server carries no coupled call, no permit is free, a
	/// tunnel holds the connection, or the connection closed.
	#[cfg(feature = "couple")]
	pub(crate) fn open_coupled(&self) -> Option<CoupledSlot> {
		let mut state = lock(&self.0.state);
		let stage = mem::replace(&mut state.stage, Stage::Closed);
		let busy = match stage {
			Stage::Fresh { slot, deadline } => {
				let free = self
					.0
					.terms
					.coupled
					.as_ref()
					.map(|coupled| Arc::clone(coupled).try_acquire_owned());
				let Some(Ok(permit)) = free else {
					state.stage = Stage::Fresh { slot, deadline };
					return None;
				};
				drop(slot);
				CoupledStage::Busy { calls: NonZeroU32::MIN, permit }
			}
			Stage::Coupled(CoupledStage::Idle { permit, .. }) => CoupledStage::Busy { calls: NonZeroU32::MIN, permit },
			Stage::Coupled(CoupledStage::Busy { calls, permit }) => {
				let Some(calls) = calls.checked_add(1) else {
					state.stage = Stage::Coupled(CoupledStage::Busy { calls, permit });
					return None;
				};
				CoupledStage::Busy { calls, permit }
			}
			held @ Stage::Tunnel(_) => {
				state.stage = held;
				return None;
			}
			Stage::Closed => return None,
		};

		state.enter(Stage::Coupled(busy));
		Some(CoupledSlot { lane: self.clone() })
	}

	/// Close one coupled call. The last one leaves the connection idle under
	/// its permit until a fresh deadline.
	#[cfg(feature = "couple")]
	fn close_coupled(&self) {
		let mut state = lock(&self.0.state);
		let stage = mem::replace(&mut state.stage, Stage::Closed);
		let next = match stage {
			Stage::Coupled(CoupledStage::Busy { calls, permit }) => {
				let remaining = NonZeroU32::new(calls.get() - 1);
				match remaining {
					Some(calls) => Stage::Coupled(CoupledStage::Busy { calls, permit }),
					None => Stage::Coupled(CoupledStage::Idle { permit, deadline: self.fresh_deadline() }),
				}
			}
			unchanged => unchanged,
		};

		state.enter(next);
	}

	/// Close the lane, which returns a slot or a permit it holds.
	fn close(&self) {
		lock(&self.0.state).stage = Stage::Closed;
	}

	/// Whether the connection must close: its stage passed its deadline, or
	/// it closed. A read that sees it open registers to wake at the deadline
	/// and at a change of stage.
	fn poll_expired(&self, cx: &mut Context<'_>, timer: &mut Pin<Box<Sleep>>) -> bool {
		let mut state = lock(&self.0.state);
		let registered = state.reader.as_ref().is_some_and(|reader| reader.will_wake(cx.waker()));
		if !registered {
			state.reader = Some(cx.waker().clone());
		}

		if let Stage::Closed = state.stage {
			return true;
		}

		let Some(deadline) = state.stage.deadline() else {
			return false;
		};

		if timer.deadline() != deadline {
			timer.as_mut().reset(deadline);
		}

		let expired = timer.as_mut().poll(cx).is_ready();
		if expired {
			state.stage = Stage::Closed;
		}

		expired
	}
}

/// One coupled call open on its lane. It closes the call when it drops, which
/// is when the response of the call is written or the call is refused.
#[cfg(feature = "couple")]
pub(crate) struct CoupledSlot {
	lane: Lane,
}

#[cfg(feature = "couple")]
impl Drop for CoupledSlot {
	fn drop(&mut self) {
		self.lane.close_coupled();
	}
}

/// The claim of one call on its lane. It ends the call when it drops, which
/// is when the response of the call ends or the call is refused.
pub(crate) struct Claim {
	lane: Lane,
	call: u64,
}

impl Claim {
	/// The ticket that hands the tunnel of this call to a caller.
	pub(crate) fn ticket(&self) -> Ticket {
		Ticket { lane: self.lane.clone(), call: self.call }
	}
}

impl Drop for Claim {
	fn drop(&mut self) {
		self.lane.end(self.call);
	}
}

/// The right of a queued tunnel to its connection, which a caller of
/// `accept` redeems.
pub(crate) struct Ticket {
	lane: Lane,
	call: u64,
}

impl Ticket {
	/// Hand the tunnel to a caller. `false` when the tunnel is dead.
	pub(crate) fn redeem(&self) -> bool {
		self.lane.establish(self.call)
	}
}

/// What every request on a connection carries in its extensions: the lane of
/// the connection, the address of its peer, and on a coupled edge the caller
/// that its TLS client chain proved.
#[derive(Clone)]
pub(crate) struct GrpcConnectInfo {
	pub(crate) lane: Lane,
	pub(crate) peer: SocketAddr,
	#[cfg(feature = "couple")]
	pub(crate) caller: Option<Arc<Caller>>,
}

/// The byte stream of one connection: TCP, or TLS over TCP once its
/// handshake completed.
enum EdgeIo {
	Plain(TcpStream),
	Tls(Box<TlsStream<TcpStream>>),
}

impl EdgeIo {
	/// The caller of the client certificate that the TLS handshake verified,
	/// or `None` for a connection that presented none, or that runs no TLS.
	#[cfg(feature = "couple")]
	fn caller(&self) -> Option<Caller> {
		let Self::Tls(tls) = self else {
			return None;
		};

		let (_, session) = tls.get_ref();
		let leaf = session.peer_certificates()?.first()?;
		Caller::from_leaf(leaf)
	}
}

impl AsyncRead for EdgeIo {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		match self.get_mut() {
			Self::Plain(tcp) => Pin::new(tcp).poll_read(cx, buf),
			Self::Tls(tls) => Pin::new(tls.as_mut()).poll_read(cx, buf),
		}
	}
}

impl AsyncWrite for EdgeIo {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		match self.get_mut() {
			Self::Plain(tcp) => Pin::new(tcp).poll_write(cx, buf),
			Self::Tls(tls) => Pin::new(tls.as_mut()).poll_write(cx, buf),
		}
	}

	fn poll_write_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buffers: &[io::IoSlice<'_>],
	) -> Poll<io::Result<usize>> {
		match self.get_mut() {
			Self::Plain(tcp) => Pin::new(tcp).poll_write_vectored(cx, buffers),
			Self::Tls(tls) => Pin::new(tls.as_mut()).poll_write_vectored(cx, buffers),
		}
	}

	fn is_write_vectored(&self) -> bool {
		match self {
			Self::Plain(tcp) => tcp.is_write_vectored(),
			Self::Tls(tls) => tls.is_write_vectored(),
		}
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		match self.get_mut() {
			Self::Plain(tcp) => Pin::new(tcp).poll_flush(cx),
			Self::Tls(tls) => Pin::new(tls.as_mut()).poll_flush(cx),
		}
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		match self.get_mut() {
			Self::Plain(tcp) => Pin::new(tcp).poll_shutdown(cx),
			Self::Tls(tls) => Pin::new(tls.as_mut()).poll_shutdown(cx),
		}
	}
}

/// One accepted connection, which fails its next read once its lane expires,
/// so the server closes it, and which closes its lane when it drops.
pub(crate) struct GrpcConnection {
	io: EdgeIo,
	lane: Lane,
	peer: SocketAddr,
	timer: Pin<Box<Sleep>>,
	/// The caller that the TLS client chain of the connection proved, parsed
	/// once when its handshake completed.
	#[cfg(feature = "couple")]
	caller: Option<Arc<Caller>>,
}

impl GrpcConnection {
	fn new(io: EdgeIo, peer: SocketAddr, lane: Lane) -> Self {
		let timer = Box::pin(sleep_until(Instant::now()));
		#[cfg(feature = "couple")]
		let caller = io.caller().map(Arc::new);
		Self {
			io,
			lane,
			peer,
			timer,
			#[cfg(feature = "couple")]
			caller,
		}
	}
}

impl Drop for GrpcConnection {
	fn drop(&mut self) {
		self.lane.close();
	}
}

impl Connected for GrpcConnection {
	type ConnectInfo = GrpcConnectInfo;

	fn connect_info(&self) -> Self::ConnectInfo {
		GrpcConnectInfo {
			lane: self.lane.clone(),
			peer: self.peer,
			#[cfg(feature = "couple")]
			caller: self.caller.clone(),
		}
	}
}

impl AsyncRead for GrpcConnection {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		let this = self.get_mut();
		if this.lane.poll_expired(cx, &mut this.timer) {
			let expired = io::Error::from(io::ErrorKind::TimedOut);
			return Poll::Ready(Err(expired));
		}

		Pin::new(&mut this.io).poll_read(cx, buf)
	}
}

impl AsyncWrite for GrpcConnection {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
	}

	fn poll_write_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buffers: &[io::IoSlice<'_>],
	) -> Poll<io::Result<usize>> {
		Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, buffers)
	}

	fn is_write_vectored(&self) -> bool {
		self.io.is_write_vectored()
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.get_mut().io).poll_flush(cx)
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
	}
}

/// The connections the server serves: each TCP accept waits for a free slot,
/// and a failed accept reaches a caller of `accept`, then backs off.
pub(crate) struct GrpcIncoming {
	listener: TcpListener,
	slots: Arc<Slots>,
	free: PollSemaphore,
	terms: LaneTerms,
	arrivals: Sender<Arrival>,
	/// The pause after a failed accept, such as one past the file limit.
	backoff: Option<Pin<Box<Sleep>>>,
	/// The acceptor of a TLS edge, or `None` for h2c.
	tls: Option<TlsAcceptor>,
	/// The TLS handshakes in flight, each under the slot of its lane. A
	/// handshake that fails or passes the idle time of the terms yields no
	/// connection, and the drop of its lane returns the slot.
	securing: JoinSet<Option<GrpcConnection>>,
}

impl GrpcIncoming {
	/// The connections of `listener`, each under one of `slots` and the
	/// `terms` of the server, which secures itself under `tls` within the
	/// idle time of the terms. A failed accept queues on `arrivals`.
	pub(crate) fn new(
		listener: TcpListener,
		slots: Arc<Slots>,
		terms: LaneTerms,
		tls: Option<TlsAcceptor>,
		arrivals: Sender<Arrival>,
	) -> Self {
		let free = PollSemaphore::new(Arc::clone(&slots.semaphore));
		let securing = JoinSet::new();
		Self { listener, slots, free, terms, arrivals, backoff: None, tls, securing }
	}

	/// Queue a failed TCP accept for a caller of `accept`. Only an empty queue
	/// takes a failure: the plane paces its own retries, and a backlog of
	/// stale failures would hold back the tunnels behind them.
	fn report(&self, error: io::Error) {
		if self.arrivals.capacity() == self.arrivals.max_capacity() {
			let _ = self.arrivals.try_send(Err(error));
		}
	}

	/// The next TCP connection under a slot: the slot that the accept loop
	/// holds, or a free one. `None` once the slots close.
	fn poll_tcp(&mut self, cx: &mut Context<'_>) -> Poll<Option<(TcpStream, SocketAddr, OwnedSemaphorePermit)>> {
		if let Some(backoff) = &mut self.backoff {
			ready!(backoff.as_mut().poll(cx));
			self.backoff = None;
		}

		let slot = match self.slots.reclaim() {
			Some(slot) => slot,
			None => match ready!(self.free.poll_acquire(cx)) {
				Some(slot) => slot,
				None => return Poll::Ready(None),
			},
		};

		let accepted = match self.listener.poll_accept(cx) {
			Poll::Ready(accepted) => accepted,
			Poll::Pending => {
				self.slots.park(slot);
				return Poll::Pending;
			}
		};

		match accepted {
			Ok((tcp, peer)) => Poll::Ready(Some((tcp, peer, slot))),
			Err(error) => {
				self.slots.park(slot);
				self.report(error);
				self.backoff = Some(Box::pin(sleep(DEFAULT_ACCEPT_RETRY_DELAY)));
				cx.waker().wake_by_ref();
				Poll::Pending
			}
		}
	}

	/// Secure `tcp` under `acceptor` on a task of its own, which yields the
	/// connection once its handshake completes within the idle time, and
	/// drops it, with its lane, otherwise.
	fn secure(&mut self, acceptor: TlsAcceptor, tcp: TcpStream, peer: SocketAddr, lane: Lane) {
		let handshake = acceptor.accept(tcp);
		let idle = self.terms.idle;
		self.securing.spawn(async move {
			let secured = timeout(idle, handshake).await;
			let tls = secured.ok()?.ok()?;
			Some(GrpcConnection::new(EdgeIo::Tls(Box::new(tls)), peer, lane))
		});
	}
}

impl Stream for GrpcIncoming {
	type Item = Result<GrpcConnection, Infallible>;

	fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let this = self.get_mut();
		loop {
			// A connection whose handshake completed goes before a new accept.
			while let Poll::Ready(Some(joined)) = this.securing.poll_join_next(cx) {
				if let Ok(Some(connection)) = joined {
					return Poll::Ready(Some(Ok(connection)));
				}
			}

			let Some((tcp, peer, slot)) = ready!(this.poll_tcp(cx)) else {
				return Poll::Ready(None);
			};

			// The tunnel carries small envelopes in both directions, so the
			// socket sends each one at once, as tonic's own listener does by
			// default.
			let _ = tcp.set_nodelay(true);
			let slots = Arc::clone(&this.slots);
			let lane = Lane::new(slot, slots, this.terms.clone());

			let Some(acceptor) = this.tls.clone() else {
				let connection = GrpcConnection::new(EdgeIo::Plain(tcp), peer, lane);
				return Poll::Ready(Some(Ok(connection)));
			};

			this.secure(acceptor, tcp, peer, lane);
		}
	}
}
