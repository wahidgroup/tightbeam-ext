//! The connection plane behind [`GrpcListener`](crate::protocol::GrpcListener),
//! whose slots and deadlines `docs/grpc.md` describes.
//!
//! # Sources
//!
//! - CWE-400, uncontrolled resource consumption: <https://cwe.mitre.org/data/definitions/400.html>
//! - CWE-770, resource allocation without limits: <https://cwe.mitre.org/data/definitions/770.html>

use core::convert::Infallible;
use core::future::Future;
use core::mem;
use core::num::{NonZeroU32, NonZeroUsize};
use core::pin::Pin;
use core::task::{ready, Context, Poll, Waker};
use core::time::Duration;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

#[cfg(feature = "couple")]
use http::HeaderMap;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tokio_stream::Stream;
use tokio_util::sync::PollSemaphore;
use tonic::transport::server::Connected;

use tightbeam::clock::{Clock, Lapse};
use tightbeam::constants::DEFAULT_ACCEPT_RETRY_DELAY;
#[cfg(feature = "couple")]
use tightbeam::transport::TransportError;

#[cfg(feature = "couple")]
use crate::couple::{CallFault, Credential, LiveCallers, TlsIdentity};
use crate::deadline::{Deadline, DeadlineSleep, DeadlineTimer};
use crate::edge::ProxyHops;
use crate::service::Served;
use crate::tunnel::{Arrival, BoxFuture, CallRefusal, EdgeAudit, EdgeRefusal, Tunnel};

/// Lock `mutex`. Each of these locks is released before user code runs, so a
/// poisoned lock still holds a consistent state.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
	mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The slots of one server, under one lock: the free slots that every
/// connection draws from, and the slot that the accept loop holds while it
/// waits for the next TCP connection. [`LaneInner::state`] states the order
/// of its lock.
pub(crate) struct Slots(Mutex<SlotState>);

/// Where each slot of a server waits that no connection holds.
struct SlotState {
	/// The free slots, and the wait of the accept loop for one.
	free: PollSemaphore,
	/// The slot that the accept loop holds for its next TCP accept.
	parked: Option<OwnedSemaphorePermit>,
	/// The waker of the accept loop, which a free slot wakes.
	accept: Option<Waker>,
}

/// What a server of one capacity starts from: its slots, the queue of
/// arrivals for a caller of `accept`, and the receiver of that queue.
pub(crate) struct ServerSlots {
	pub(crate) slots: Arc<Slots>,
	pub(crate) queue: Arrivals,
	pub(crate) arrivals: Receiver<Arrival>,
}

impl ServerSlots {
	/// `capacity` slots, none of them taken, and the queue of arrivals for a
	/// caller of `accept`, which [`Arrivals`] sizes to them.
	pub(crate) fn new(capacity: NonZeroUsize) -> Self {
		let free = PollSemaphore::new(Arc::new(Semaphore::new(capacity.get())));
		let (queue, arrivals) = Arrivals::sized(capacity);
		let slots = Arc::new(Slots(Mutex::new(SlotState { free, parked: None, accept: None })));
		Self { slots, queue, arrivals }
	}
}

impl Slots {
	/// A slot for a connection that is already open: a free one, or else the
	/// one the accept loop holds, because an open connection goes before one
	/// still in the backlog.
	fn take(&self) -> Option<OwnedSemaphorePermit> {
		let mut state = lock(&self.0);
		state.free().or_else(|| state.parked.take())
	}

	/// Accept the next TCP connection of `listener` under the slot that the
	/// accept loop holds, or a free one. The slot stays under the lock of
	/// [`Slots::take`] for the whole poll, so an open connection finds it.
	///
	/// `None` once the slots close.
	fn poll_accept(&self, listener: &TcpListener, cx: &mut Context<'_>) -> Poll<Option<io::Result<Accepted>>> {
		let mut state = lock(&self.0);
		state.accept = Some(cx.waker().clone());
		let slot = match state.parked.take() {
			Some(slot) => slot,
			None => match ready!(state.free.poll_acquire(cx)) {
				Some(slot) => slot,
				None => return Poll::Ready(None),
			},
		};

		match listener.poll_accept(cx) {
			Poll::Ready(Ok((tcp, peer))) => Poll::Ready(Some(Ok(Accepted { tcp, peer, slot }))),
			Poll::Ready(Err(error)) => {
				state.parked = Some(slot);
				Poll::Ready(Some(Err(error)))
			}
			Poll::Pending => {
				state.parked = Some(slot);
				Poll::Pending
			}
		}
	}
}

impl SlotState {
	/// A free slot, or the one that the wait of the accept loop already holds.
	/// The wait keeps the waker of the accept loop, and the poll runs outside
	/// the cooperative budget of the caller, so a free slot is taken at once.
	fn free(&mut self) -> Option<OwnedSemaphorePermit> {
		let waker = self.accept.clone().unwrap_or_else(|| Waker::noop().clone());
		let acquire = tokio::task::unconstrained(core::future::poll_fn(|cx| self.free.poll_acquire(cx)));
		match core::pin::pin!(acquire).poll(&mut Context::from_waker(&waker)) {
			Poll::Ready(slot) => slot,
			Poll::Pending => None,
		}
	}
}

/// A TCP connection that the accept loop took under a slot.
struct Accepted {
	tcp: TcpStream,
	peer: SocketAddr,
	slot: OwnedSemaphorePermit,
}

/// What a connection waits under, and which calls hold it. The first call
/// fixes the kind of the connection for its life: tunnels, or coupled calls.
enum Stage {
	/// No call has come. The connection holds a slot and closes at
	/// `deadline`, or stays open when the idle time passes the range of the
	/// clock.
	Fresh { slot: OwnedSemaphorePermit, deadline: Deadline },
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
	Waiting { slot: OwnedSemaphorePermit, deadline: Deadline },
	/// No call holds the connection and no slot was free when its last call
	/// ended. A call takes a slot if one is free by then, and the connection
	/// closes at `deadline`.
	Draining { deadline: Deadline },
	/// The tunnel of `call` waits for a caller of `accept`, under the slot of
	/// the connection. The connection closes at `expires` when no caller has
	/// taken the tunnel by then, and `waiting` is the deadline it waits under
	/// again when the call ends first.
	Queued { slot: OwnedSemaphorePermit, waiting: Deadline, expires: Deadline, call: u64 },
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
	Idle { permit: OwnedSemaphorePermit, deadline: Deadline },
}

impl Stage {
	/// The deadline at which the connection closes in this stage, or
	/// `unbounded` for a stage that a call holds or that closed.
	fn deadline<'a>(&'a self, unbounded: &'a Deadline) -> &'a Deadline {
		match self {
			Self::Fresh { deadline, .. } => deadline,
			Self::Tunnel(TunnelStage::Waiting { deadline, .. } | TunnelStage::Draining { deadline }) => deadline,
			Self::Tunnel(TunnelStage::Queued { expires, .. }) => expires,
			#[cfg(feature = "couple")]
			Self::Coupled(CoupledStage::Idle { deadline, .. }) => deadline,
			#[cfg(feature = "couple")]
			Self::Coupled(CoupledStage::Busy { .. }) => unbounded,
			Self::Tunnel(TunnelStage::Established { .. }) | Self::Closed => unbounded,
		}
	}
}

/// The stage of one connection, the number of the last call it admitted, and
/// the waker of its last read or write, which a change of stage wakes so the
/// read or write sees it.
struct LaneState {
	stage: Stage,
	calls: u64,
	reader: Option<Waker>,
}

impl LaneState {
	/// Enter `stage`, and wake the read or write of the connection so it sees
	/// the deadline of the stage.
	fn enter(&mut self, stage: Stage) {
		self.stage = stage;
		if let Some(reader) = self.reader.take() {
			reader.wake();
		}
	}
}

/// The sender of the arrivals for a caller of `accept`. A live tunnel holds
/// a slot, so the queue has room for a tunnel per slot and one failed accept.
#[derive(Clone)]
pub(crate) struct Arrivals(Sender<Arrival>);

impl Arrivals {
	/// The queue of a server of `slots` slots, and its receiver.
	fn sized(slots: NonZeroUsize) -> (Self, Receiver<Arrival>) {
		let (queue, arrivals) = mpsc::channel(slots.get() + 1);
		(Self(queue), arrivals)
	}

	/// Queue the tunnel of a call that the edge admitted.
	///
	/// # Errors
	///
	/// - [`CallRefusal::QueueFull`] -- no caller took the tunnels that fill the queue. Beside the live
	///   tunnels, tunnels that ended or that a later call replaced, and loopback tunnels, take its places.
	pub(crate) fn queue(&self, tunnel: Tunnel) -> Result<(), CallRefusal> {
		self.0.try_send(Ok(tunnel)).map_err(|_| CallRefusal::QueueFull)
	}

	/// Queue the loopback tunnel of a coupler with a send that waits for room,
	/// so that tunnel always reaches the queue.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the listener dropped its queue.
	#[cfg(feature = "couple")]
	pub(crate) async fn loopback(&self, tunnel: Tunnel) -> Result<(), TransportError> {
		self.0.send(Ok(tunnel)).await.map_err(|_| TransportError::ConnectionClosed)
	}

	/// Queue a failed TCP accept for a caller of `accept`. Only an empty queue
	/// takes a failure: the plane paces its own retries, and a backlog of
	/// stale failures would hold back the tunnels behind them.
	fn report(&self, error: io::Error) {
		if self.0.capacity() == self.0.max_capacity() {
			let _ = self.0.try_send(Err(error));
		}
	}
}

/// What every lane of one server lives under, which what the server serves
/// decides.
#[derive(Clone)]
pub(crate) struct LaneTerms {
	/// How long a connection waits for its next call.
	idle: Duration,
	/// The clock of the server, which every deadline of a lane and the pace
	/// of its accepts run on.
	clock: Arc<dyn Clock>,
	/// The deadline on `clock` beyond every reading, of a stage that a call
	/// holds or that closed.
	unbounded: Deadline,
	/// The HTTP/2 streams that a connection admits at once.
	streams: NonZeroU32,
	/// The permits of the coupled lanes, or `None` when the server carries no
	/// coupled call.
	#[cfg(feature = "couple")]
	coupled: Option<Arc<Semaphore>>,
}

impl LaneTerms {
	/// The terms of each connection of a server that serves `served`, which
	/// waits `idle` for its next call on `clock`.
	pub(crate) fn of<P>(idle: Duration, served: &Served<P>, clock: Arc<dyn Clock>) -> Self
	where
		P: tightbeam::transport::handshake::HandshakeProvider + Send + Sync + 'static,
	{
		Self {
			idle,
			unbounded: Deadline::unbounded(&clock),
			clock,
			streams: served.streams(),
			#[cfg(feature = "couple")]
			coupled: served.lanes(),
		}
	}

	/// The HTTP/2 streams that a connection admits at once, which the server
	/// advertises.
	pub(crate) fn streams(&self) -> NonZeroU32 {
		self.streams
	}

	/// The deadline of a wait for the next call that starts now, on the clock
	/// of the server.
	fn fresh(&self) -> Deadline {
		Deadline::after(&self.clock, self.idle)
	}

	/// Whether a tunnel call replaces a queued call on its connection. Only a
	/// server that admits one stream per connection replaces, because there a
	/// queued call that a new call meets has ended.
	fn replaces(&self) -> bool {
		self.streams == NonZeroU32::MIN
	}

	/// A free permit of the coupled lanes, or `None` when the server carries
	/// no coupled call or no permit is free.
	#[cfg(feature = "couple")]
	fn coupled_permit(&self) -> Option<OwnedSemaphorePermit> {
		let coupled = self.coupled.as_ref()?;
		Arc::clone(coupled).try_acquire_owned().ok()
	}
}

/// Why a lane refuses a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LaneRefusal {
	/// No slot was free for a tunnel after the last tunnel of the connection
	/// ended.
	NoSlot,
	/// A call of the other kind holds the connection.
	#[cfg(feature = "couple")]
	OtherKind,
	/// A queued or established tunnel holds the connection, on a server that
	/// admits more than one stream per connection.
	TunnelHeld,
	/// The server carries no coupled call, or no coupled permit is free.
	#[cfg(feature = "couple")]
	NoPermit,
	/// The connection carries the most coupled calls it counts.
	#[cfg(feature = "couple")]
	CallsExhausted,
	/// The connection closed.
	Closed,
}

impl LaneRefusal {
	/// The name that the audit trail records the refusal under.
	#[cfg(feature = "instrument")]
	pub(crate) fn as_str(&self) -> &'static str {
		match self {
			Self::NoSlot => "no-slot",
			#[cfg(feature = "couple")]
			Self::OtherKind => "other-kind",
			Self::TunnelHeld => "tunnel-held",
			#[cfg(feature = "couple")]
			Self::NoPermit => "no-permit",
			#[cfg(feature = "couple")]
			Self::CallsExhausted => "calls-exhausted",
			Self::Closed => "closed",
		}
	}
}

/// Why a connection never reaches the HTTP/2 server.
enum Unsecured {
	/// Its PROXY header refused it, which the trail records as the verdict of
	/// the header.
	Header,
	/// Its TLS handshake failed.
	Tls,
	/// It passed neither its PROXY header nor its TLS handshake before the
	/// deadline of its lane.
	Late,
	/// The clock of the edge gave its wait for its PROXY header and its TLS
	/// handshake no timer.
	NoTimer,
}

impl Unsecured {
	/// The refusal that the trail records for the connection, or `None` for a
	/// header whose verdict it recorded already.
	fn refusal(self) -> Option<EdgeRefusal> {
		match self {
			Self::Header => None,
			Self::Tls => Some(EdgeRefusal::Tls),
			Self::Late => Some(EdgeRefusal::Late),
			Self::NoTimer => Some(EdgeRefusal::NoTimer),
		}
	}
}

/// A lapsed bound on the deadline of a lane refuses its connection:
/// [`Unsecured::Late`] once the deadline passed, and [`Unsecured::NoTimer`]
/// when the clock gave the wait no timer.
impl From<Lapse> for Unsecured {
	fn from(lapse: Lapse) -> Self {
		match lapse {
			Lapse::Passed => Self::Late,
			Lapse::NoTimer => Self::NoTimer,
		}
	}
}

/// The slot, the deadline, and the calls of one connection, shared by its
/// I/O, which closes the connection, by the calls that hold it, and by the
/// tunnel that waits for a caller.
#[derive(Clone)]
pub(crate) struct Lane(Arc<LaneInner>);

struct LaneInner {
	/// The stage of the connection. Its lock comes before the lock of the
	/// [`Slots`], which a change of stage takes under it.
	state: Mutex<LaneState>,
	slots: Arc<Slots>,
	terms: LaneTerms,
}

impl Lane {
	/// A lane that waits under `slot` on the `terms` of its server.
	fn new(slot: OwnedSemaphorePermit, slots: Arc<Slots>, terms: LaneTerms) -> Self {
		let deadline = terms.fresh();
		let stage = Stage::Fresh { slot, deadline };
		let state = Mutex::new(LaneState { stage, calls: 0, reader: None });
		Self(Arc::new(LaneInner { state, slots, terms }))
	}

	/// The deadline of a wait that starts now.
	fn fresh_deadline(&self) -> Deadline {
		self.0.terms.fresh()
	}

	/// The connection that `prepared` secures, once it completes before the
	/// deadline of the lane. A connection that fails or ends late answers its
	/// [`Unsecured`], and the drop of the lane returns its slot.
	///
	/// # Errors
	///
	/// - The [`Unsecured`] of a connection that fails.
	/// - [`Unsecured::Late`] -- the connection passed the deadline of the lane.
	/// - [`Unsecured::NoTimer`] -- the clock of the edge gave the wait no timer.
	async fn prepare<F>(self, prepared: F) -> Result<GrpcConnection, Unsecured>
	where
		F: Future<Output = Result<(EdgeIo, SocketAddr), Unsecured>>,
	{
		let deadline = lock(&self.0.state).stage.deadline(&self.0.terms.unbounded).clone();
		let (io, peer) = deadline.bound(prepared).await??;
		if deadline.passed() {
			return Err(Unsecured::Late);
		}

		Ok(GrpcConnection::new(io, peer, self))
	}

	/// Admit a tunnel call on the connection, under its slot, and give its
	/// tunnel until a fresh deadline to reach a caller:
	///
	/// - A fresh or waiting connection gives the call its slot and deadline.
	/// - On a server that replaces, a queued call whose stream closed before a
	///   caller took its tunnel gives the new call its place and its expiry,
	///   so one connection holds one slot, and a replacing call keeps the
	///   expiry.
	/// - On a server that replaces, after a caller took a tunnel, the call
	///   takes a free slot and a fresh deadline. A draining connection keeps
	///   its deadline, so calls that find no slot leave it to close then.
	/// - On a server of more than one stream per connection, a queued or
	///   established tunnel refuses the call, because a second live call may
	///   share the connection.
	///
	/// # Errors
	///
	/// - The [`LaneRefusal`] of a call that the lane refuses: no slot is free,
	///   a coupled call holds the connection, a tunnel holds it on a server
	///   of more than one stream per connection, or the connection closed.
	fn claim_tunnel(&self, peer: SocketAddr) -> Result<Claim, LaneRefusal> {
		let mut state = lock(&self.0.state);
		let replaces = self.0.terms.replaces();
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
					return Err(LaneRefusal::NoSlot);
				};
				(slot, deadline, self.fresh_deadline())
			}
			Stage::Tunnel(TunnelStage::Draining { deadline }) => {
				let Some(slot) = self.0.slots.take() else {
					state.enter(Stage::Tunnel(TunnelStage::Draining { deadline }));
					return Err(LaneRefusal::NoSlot);
				};
				(slot, deadline, self.fresh_deadline())
			}
			held @ Stage::Tunnel(TunnelStage::Queued { .. } | TunnelStage::Established { .. }) => {
				state.stage = held;
				return Err(LaneRefusal::TunnelHeld);
			}
			#[cfg(feature = "couple")]
			held @ Stage::Coupled(_) => {
				state.stage = held;
				return Err(LaneRefusal::OtherKind);
			}
			Stage::Closed => return Err(LaneRefusal::Closed),
		};

		state.calls += 1;

		let call = state.calls;

		state.enter(Stage::Tunnel(TunnelStage::Queued { slot, waiting, expires, call }));
		Ok(Claim { lane: self.clone(), call, peer })
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
	/// - The end of a call that a later call replaced changes nothing, nor
	///   does the end of a call on a connection that waits, drains, or closed.
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
			replaced @ Stage::Tunnel(TunnelStage::Queued { .. } | TunnelStage::Established { .. }) => replaced,
			idle @ Stage::Tunnel(TunnelStage::Waiting { .. } | TunnelStage::Draining { .. }) => idle,
			fresh @ Stage::Fresh { .. } => fresh,
			#[cfg(feature = "couple")]
			coupled @ Stage::Coupled(_) => coupled,
			Stage::Closed => Stage::Closed,
		};

		state.enter(next);
	}

	/// Open a coupled call on the connection:
	///
	/// - A fresh connection returns its slot and takes a permit of the
	///   coupled lanes, because the coupler proved the caller of the call.
	/// - An idle or busy coupled connection counts one more call under the
	///   permit it holds.
	///
	/// # Errors
	///
	/// - The [`LaneRefusal`] of a call that the lane refuses: the server
	///   carries no coupled call, no permit is free, a tunnel holds the
	///   connection, it counts its most calls, or it closed.
	#[cfg(feature = "couple")]
	fn open_coupled(&self) -> Result<CoupledSlot, LaneRefusal> {
		let mut state = lock(&self.0.state);
		let stage = mem::replace(&mut state.stage, Stage::Closed);
		let busy = match stage {
			Stage::Fresh { slot, deadline } => {
				let Some(permit) = self.0.terms.coupled_permit() else {
					state.stage = Stage::Fresh { slot, deadline };
					return Err(LaneRefusal::NoPermit);
				};

				drop(slot);
				CoupledStage::Busy { calls: NonZeroU32::MIN, permit }
			}
			Stage::Coupled(CoupledStage::Idle { permit, .. }) => CoupledStage::Busy { calls: NonZeroU32::MIN, permit },
			Stage::Coupled(CoupledStage::Busy { calls, permit }) => {
				let Some(calls) = calls.checked_add(1) else {
					state.stage = Stage::Coupled(CoupledStage::Busy { calls, permit });
					return Err(LaneRefusal::CallsExhausted);
				};
				CoupledStage::Busy { calls, permit }
			}
			held @ Stage::Tunnel(_) => {
				state.stage = held;
				return Err(LaneRefusal::OtherKind);
			}
			Stage::Closed => return Err(LaneRefusal::Closed),
		};

		state.enter(Stage::Coupled(busy));
		Ok(CoupledSlot { lane: self.clone() })
	}

	/// Close one coupled call. The last one leaves the connection idle under
	/// its permit until a fresh deadline. A connection that closed stays
	/// closed, and no other stage holds a coupled call.
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
			idle @ Stage::Coupled(CoupledStage::Idle { .. }) => idle,
			fresh @ Stage::Fresh { .. } => fresh,
			tunnel @ Stage::Tunnel(_) => tunnel,
			Stage::Closed => Stage::Closed,
		};

		state.enter(next);
	}

	/// Close the lane, which returns a slot or a permit it holds.
	fn close(&self) {
		lock(&self.0.state).stage = Stage::Closed;
	}

	/// Whether the connection must close: its stage passed its deadline, or
	/// it closed. A read or write that sees it open registers to wake at the
	/// deadline and at a change of stage.
	fn poll_expired(&self, cx: &mut Context<'_>, timer: &mut DeadlineTimer) -> bool {
		let mut state = lock(&self.0.state);
		let registered = state.reader.as_ref().is_some_and(|reader| reader.will_wake(cx.waker()));
		if !registered {
			state.reader = Some(cx.waker().clone());
		}

		if let Stage::Closed = state.stage {
			return true;
		}

		let expired = timer.poll_passed(state.stage.deadline(&self.0.terms.unbounded), cx);
		if expired {
			state.stage = Stage::Closed;
		}

		expired
	}
}

/// The lane of a connection whose caller the coupler proved, which alone
/// opens a coupled call on the lane.
#[cfg(feature = "couple")]
pub(crate) struct ProvenLane(Lane);

#[cfg(feature = "couple")]
impl ProvenLane {
	/// Open a coupled call on the lane, as [`Lane::open_coupled`] opens it.
	///
	/// # Errors
	///
	/// - The errors of [`Lane::open_coupled`].
	pub(crate) fn open_coupled(&self) -> Result<CoupledSlot, LaneRefusal> {
		self.0.open_coupled()
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
	peer: SocketAddr,
}

impl Claim {
	/// The address of the peer of the connection.
	pub(crate) fn peer(&self) -> SocketAddr {
		self.peer
	}

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
/// the connection, the address of its peer, and on a coupled edge its client
/// chain.
#[derive(Clone)]
pub(crate) struct GrpcConnectInfo {
	lane: Lane,
	peer: SocketAddr,
	#[cfg(feature = "couple")]
	chain: ClientChain,
}

impl GrpcConnectInfo {
	/// Claim the lane of the connection for a tunnel call.
	///
	/// # Errors
	///
	/// - The [`LaneRefusal`] of a lane that refuses the tunnel.
	pub(crate) fn claim_tunnel(&self) -> Result<Claim, LaneRefusal> {
		self.lane.claim_tunnel(self.peer)
	}

	/// The lane of the connection, once `credential` proves a caller on it,
	/// which the coupled calls of the caller open on.
	#[cfg(feature = "couple")]
	pub(crate) fn proven_lane(&self, _credential: &Credential) -> ProvenLane {
		ProvenLane(self.lane.clone())
	}

	/// The client chain that the TLS handshake of the connection verified.
	#[cfg(feature = "couple")]
	pub(crate) fn chain(&self) -> &ClientChain {
		&self.chain
	}
}

/// The client chain that the TLS handshake of a connection verified, parsed
/// once when the handshake completed.
#[cfg(feature = "couple")]
#[derive(Clone)]
pub(crate) enum ClientChain {
	/// The connection presented no client chain, or runs no TLS.
	Absent,
	/// The verified chain names this principal.
	Named(Arc<TlsIdentity>),
	/// The verified chain names no principal, so its calls prove no caller.
	Nameless,
}

#[cfg(feature = "couple")]
impl ClientChain {
	/// The credential that a call with `headers` proves on a connection of
	/// this chain under `callers`: [`LiveCallers::of_chain`] gives it for a
	/// named chain, and [`LiveCallers::bearer`] for a connection with none.
	///
	/// # Errors
	///
	/// - [`CallFault::Unauthenticated`] -- the chain names no principal.
	/// - The errors of [`LiveCallers::of_chain`] and [`LiveCallers::bearer`].
	pub(crate) fn credential(&self, callers: &LiveCallers, headers: &HeaderMap) -> Result<Credential, CallFault> {
		match self {
			Self::Named(identity) => callers.of_chain(identity, headers),
			Self::Absent => callers.bearer(headers),
			Self::Nameless => Err(CallFault::Unauthenticated),
		}
	}
}

/// The byte stream of one connection: TCP, or TLS over TCP once its
/// handshake completed.
enum EdgeIo {
	Plain(TcpStream),
	Tls(Box<TlsStream<TcpStream>>),
}

impl EdgeIo {
	/// The client chain that the TLS handshake verified: absent for a
	/// connection that presented none or runs no TLS, and nameless for one
	/// whose leaf names no principal.
	#[cfg(feature = "couple")]
	fn chain(&self) -> ClientChain {
		let Self::Tls(tls) = self else {
			return ClientChain::Absent;
		};

		let (_, session) = tls.get_ref();
		let Some(leaf) = session.peer_certificates().and_then(<[_]>::first) else {
			return ClientChain::Absent;
		};

		TlsIdentity::of(leaf).map_or(ClientChain::Nameless, |identity| ClientChain::Named(Arc::new(identity)))
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

/// One accepted connection, which fails its next read or write once its lane
/// expires, so the server closes it, and which closes its lane when it drops.
pub(crate) struct GrpcConnection {
	io: EdgeIo,
	lane: Lane,
	peer: SocketAddr,
	/// The sleep of the deadline of the lane, made at the first read or write
	/// that waits under it.
	timer: DeadlineTimer,
	/// The client chain of the connection, parsed once when its handshake
	/// completed.
	#[cfg(feature = "couple")]
	chain: ClientChain,
}

impl GrpcConnection {
	fn new(io: EdgeIo, peer: SocketAddr, lane: Lane) -> Self {
		#[cfg(feature = "couple")]
		let chain = io.chain();
		Self {
			io,
			lane,
			peer,
			timer: DeadlineTimer::default(),
			#[cfg(feature = "couple")]
			chain,
		}
	}

	/// Fail once the lane of the connection expires. Each read and write of
	/// the connection asks first, so one that waits on its socket also wakes
	/// at the deadline of the lane.
	///
	/// # Errors
	///
	/// - [`io::ErrorKind::TimedOut`] -- the stage of the lane passed its deadline, or the lane closed.
	fn alive(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
		if self.lane.poll_expired(cx, &mut self.timer) {
			return Err(io::Error::from(io::ErrorKind::TimedOut));
		}

		Ok(())
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
			chain: self.chain.clone(),
		}
	}
}

impl AsyncRead for GrpcConnection {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		let this = self.get_mut();
		this.alive(cx)?;
		Pin::new(&mut this.io).poll_read(cx, buf)
	}
}

impl AsyncWrite for GrpcConnection {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		let this = self.get_mut();
		this.alive(cx)?;
		Pin::new(&mut this.io).poll_write(cx, buf)
	}

	fn poll_write_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buffers: &[io::IoSlice<'_>],
	) -> Poll<io::Result<usize>> {
		let this = self.get_mut();
		this.alive(cx)?;
		Pin::new(&mut this.io).poll_write_vectored(cx, buffers)
	}

	fn is_write_vectored(&self) -> bool {
		self.io.is_write_vectored()
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let this = self.get_mut();
		this.alive(cx)?;
		Pin::new(&mut this.io).poll_flush(cx)
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let this = self.get_mut();
		this.alive(cx)?;
		Pin::new(&mut this.io).poll_shutdown(cx)
	}
}

/// What a connection passes before the HTTP/2 server sees it: the PROXY
/// header of a hop, and the TLS handshake of the edge, which one decision
/// starts.
#[derive(Clone)]
pub(crate) struct Securing {
	hops: ProxyHops,
	tls: Option<TlsAcceptor>,
	audit: EdgeAudit,
}

/// A connection that its securing began.
enum Begun {
	/// The connection passes nothing, so the server takes it at once.
	Ready(GrpcConnection),
	/// The connection passes its header or its handshake on a task of its
	/// own, under the slot and the deadline of its lane.
	Pending(BoxFuture<Option<GrpcConnection>>),
}

impl Securing {
	/// The securing of the connections of an edge: the PROXY header of each
	/// connection of `hops`, which `audit` records, and the TLS handshake of
	/// `tls` when it is `Some`.
	pub(crate) fn new(hops: ProxyHops, tls: Option<TlsAcceptor>, audit: EdgeAudit) -> Self {
		Self { hops, tls, audit }
	}

	/// Begin to secure `tcp`, a connection from `peer` on `lane`. A
	/// connection that its securing refuses reaches the trail.
	fn begin(&self, mut tcp: TcpStream, peer: SocketAddr, lane: Lane) -> Begun {
		let header = self.hops.expects(peer);
		if header.is_none() && self.tls.is_none() {
			return Begun::Ready(GrpcConnection::new(EdgeIo::Plain(tcp), peer, lane));
		}

		let tls = self.tls.clone();
		let audit = self.audit.clone();
		let proxied = audit.clone();
		let prepared = async move {
			let peer = match header {
				Some(header) => {
					let verdict = header.read(&mut tcp).await;
					verdict.record(&proxied);
					verdict.peer().ok_or(Unsecured::Header)?
				}
				None => peer,
			};

			let io = match tls {
				Some(acceptor) => {
					let accepted = acceptor.accept(tcp).await;
					EdgeIo::Tls(Box::new(accepted.map_err(|_| Unsecured::Tls)?))
				}
				None => EdgeIo::Plain(tcp),
			};
			Ok((io, peer))
		};

		Begun::Pending(Box::pin(async move {
			let unsecured = match lane.prepare(prepared).await {
				Ok(connection) => return Some(connection),
				Err(unsecured) => unsecured,
			};

			if let Some(refusal) = unsecured.refusal() {
				audit.refuse(refusal);
			}
			None
		}))
	}
}

/// The connections the server serves: each TCP accept waits for a free slot,
/// and a failed accept reaches a caller of `accept`, then backs off.
pub(crate) struct GrpcIncoming {
	listener: TcpListener,
	slots: Arc<Slots>,
	terms: LaneTerms,
	arrivals: Arrivals,
	/// The pause after a failed accept, such as one past the file limit.
	backoff: Option<DeadlineSleep>,
	/// How each connection passes its header and its handshake.
	securing: Securing,
	/// The PROXY headers and TLS handshakes in flight, each under the slot and
	/// the deadline of its lane.
	pending: JoinSet<Option<GrpcConnection>>,
}

impl GrpcIncoming {
	/// The connections of `listener`, each under one of `slots` and the
	/// `terms` of the server, secured by `securing`. A failed accept queues
	/// on `arrivals`.
	pub(crate) fn new(
		listener: TcpListener,
		slots: Arc<Slots>,
		terms: LaneTerms,
		securing: Securing,
		arrivals: Arrivals,
	) -> Self {
		let pending = JoinSet::new();
		Self { listener, slots, terms, arrivals, backoff: None, securing, pending }
	}

	/// The next TCP connection under a slot: the slot that the accept loop
	/// holds, or a free one. `None` once the slots close.
	fn poll_tcp(&mut self, cx: &mut Context<'_>) -> Poll<Option<Accepted>> {
		if let Some(backoff) = &mut self.backoff {
			ready!(Pin::new(backoff).poll(cx));
			self.backoff = None;
		}

		match ready!(self.slots.poll_accept(&self.listener, cx)) {
			Some(Ok(accepted)) => Poll::Ready(Some(accepted)),
			Some(Err(error)) => {
				self.arrivals.report(error);
				self.backoff = Some(self.pace());
				cx.waker().wake_by_ref();
				Poll::Pending
			}
			None => Poll::Ready(None),
		}
	}

	/// The pause after a failed accept, on the clock of the server.
	fn pace(&self) -> DeadlineSleep {
		Deadline::after(&self.terms.clock, DEFAULT_ACCEPT_RETRY_DELAY).sleep()
	}
}

impl Stream for GrpcIncoming {
	type Item = Result<GrpcConnection, Infallible>;

	fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let this = self.get_mut();
		loop {
			// A connection whose handshake completed goes before a new accept.
			while let Poll::Ready(Some(joined)) = this.pending.poll_join_next(cx) {
				if let Ok(Some(connection)) = joined {
					return Poll::Ready(Some(Ok(connection)));
				}
			}

			let Some(Accepted { tcp, peer, slot }) = ready!(this.poll_tcp(cx)) else {
				return Poll::Ready(None);
			};

			// The tunnel carries small envelopes in both directions, so the
			// socket sends each one at once, as tonic's own listener does by
			// default.
			let _ = tcp.set_nodelay(true);
			let slots = Arc::clone(&this.slots);
			let lane = Lane::new(slot, slots, this.terms.clone());
			match this.securing.begin(tcp, peer, lane) {
				Begun::Ready(connection) => return Poll::Ready(Some(Ok(connection))),
				Begun::Pending(prepared) => {
					this.pending.spawn(prepared);
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use core::future::poll_fn;
	use core::marker::PhantomData;

	use tightbeam::clock::{ManualClock, SystemClock};
	use tightbeam::prelude::TightBeamSocketAddr;
	use tightbeam::testing::{ClientEnv, ScenarioConfig, SetupEnv};
	use tightbeam::urn::Urn;
	use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn, TightBeamError};
	use tightbeam_ws::testing::EventWatch;

	use super::*;
	use crate::events::EDGE_REFUSED;

	type Provider = tightbeam::crypto::profiles::DefaultCryptoProvider;

	/// A claim of the open connection that took the one slot of its server.
	const LANE_CLAIMED: Urn<'static> = urn!("test", "event:lane/claimed");

	/// How many claims of the open connection race the accept poll.
	const RACES: u32 = 2000;

	/// How long a connection of a tunnel server of a scenario waits for its
	/// next call.
	const IDLE: Duration = Duration::from_secs(60);

	/// The terms of a tunnel server whose connections wait [`IDLE`] on
	/// `clock`.
	fn tunnel_terms(clock: Arc<dyn Clock>) -> LaneTerms {
		LaneTerms::of(IDLE, &Served::<Provider>::Tunnel(PhantomData), clock)
	}

	/// The one slot of a server, and an open connection whose lane holds it.
	struct OneSlot {
		slots: Arc<Slots>,
		arrivals: Arrivals,
		lane: Lane,
	}

	impl OneSlot {
		fn new() -> Self {
			let ServerSlots { slots, queue: arrivals, arrivals: _queued } = ServerSlots::new(NonZeroUsize::MIN);
			let slot = slots.take().expect("the one slot is free");
			let lane = Lane::new(slot, Arc::clone(&slots), tunnel_terms(Arc::new(SystemClock)));
			Self { slots, arrivals, lane }
		}
	}

	tb_assert_spec! {
		/// Each claim of an open connection whose tunnel a caller took finds
		/// the one slot of its server, which the accept loop holds while it
		/// polls.
		pub RacedSlotSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(LANE_CLAIMED, exactly!(RACES)),
				(EDGE_REFUSED, exactly!(0))
			]
		}
	}

	// The accept loop polls its listener on one worker while the open
	// connection claims tunnels on another. Each claim replaces a tunnel that
	// a caller took, so it takes the one slot from the accept loop.
	tb_scenario! {
		name: a_claim_that_races_the_accept_poll_takes_the_held_slot,
		spec: RacedSlotSpec,
		environment ServiceClient {
			worker_threads: 2,
			context: OneSlot::new(),
			server: |SetupEnv { trace, context }| async move {
				let listener = TcpListener::bind("127.0.0.1:0").await?;
				let addr = TightBeamSocketAddr(listener.local_addr()?);
				let hops = ProxyHops::new([] as [&str; 0]).map_err(TransportError::from)?;
				let securing = Securing::new(hops, None, EdgeAudit::on(Some(trace.share())));
				let slots = Arc::clone(&context.slots);
				let terms = tunnel_terms(Arc::new(SystemClock));
				let mut incoming = GrpcIncoming::new(listener, slots, terms, securing, context.arrivals.clone());

				// The poll runs until the connection that ends the race.
				let polled = tokio::spawn(async move {
					while poll_fn(|cx| Poll::Ready(incoming.poll_tcp(cx).is_pending())).await {
						tokio::task::yield_now().await;
					}
				});
				Ok((polled, addr))
			},
			client: |ClientEnv { trace, addr, context }| async move {
				let audit = EdgeAudit::on(Some(trace.share()));
				let mut held = context.lane.claim_tunnel(addr.0).map_err(|_| TransportError::ConnectionClosed)?;
				for _ in 0..RACES {
					held.ticket().redeem();
					match context.lane.claim_tunnel(addr.0) {
						Ok(claim) => {
							trace.event(LANE_CLAIMED)?;
							held = claim;
						}
						Err(refusal) => audit.refuse(EdgeRefusal::Call(CallRefusal::Lane(refusal))),
					}
				}

				drop(held);
				let _ends = TcpStream::connect(addr.0).await?;
				Ok(())
			}
		}
	}

	/// A lane whose clock gives the wait for its PROXY header and its TLS
	/// handshake no timer, as `SystemClock` does on a thread outside any tokio
	/// runtime, refuses its connection for want of a timer.
	#[test]
	fn a_lane_whose_clock_gives_no_timer_refuses_its_connection() {
		let OneSlot { lane, .. } = OneSlot::new();
		let securing = core::future::pending::<Result<(EdgeIo, SocketAddr), Unsecured>>();
		let mut prepared = core::pin::pin!(lane.prepare(securing));
		let refused = match prepared.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
			Poll::Ready(Err(unsecured)) => unsecured.refusal(),
			_ => None,
		};
		assert_eq!(
			refused,
			Some(EdgeRefusal::NoTimer),
			"a wait with no timer MUST refuse the connection"
		);
	}

	/// On a server of one stream per connection, a tunnel call that meets a
	/// queued call takes its place, and the end of the replaced call leaves
	/// the new one to reach a caller.
	#[test]
	fn a_tunnel_call_that_meets_a_queued_call_takes_its_place() -> Result<(), LaneRefusal> {
		let context = OneSlot::new();
		let peer = SocketAddr::from(([127, 0, 0, 1], 1));
		let queued = context.lane.claim_tunnel(peer)?;
		let replacing = context.lane.claim_tunnel(peer)?;
		drop(queued);

		assert!(replacing.ticket().redeem(), "the replacing call MUST reach a caller");
		Ok(())
	}

	/// The pause after a failed accept waits on the clock of the server, so a
	/// clock that the test moves past the pause ends it.
	#[tokio::test]
	async fn a_failed_accept_waits_on_the_clock_of_the_server() -> io::Result<()> {
		let clock = Arc::new(ManualClock::default());
		let ServerSlots { slots, queue: arrivals, arrivals: _queued } = ServerSlots::new(NonZeroUsize::MIN);
		let listener = TcpListener::bind("127.0.0.1:0").await?;
		let hops = ProxyHops::new([] as [&str; 0]).map_err(io::Error::other)?;
		let securing = Securing::new(hops, None, EdgeAudit::default());
		let terms = tunnel_terms(Arc::clone(&clock) as Arc<dyn Clock>);
		let incoming = GrpcIncoming::new(listener, slots, terms, securing, arrivals);

		let mut pace = incoming.pace();
		let mut cx = Context::from_waker(Waker::noop());
		assert!(Pin::new(&mut pace).poll(&mut cx).is_pending());

		clock.advance(DEFAULT_ACCEPT_RETRY_DELAY);
		assert!(
			Pin::new(&mut pace).poll(&mut cx).is_ready(),
			"the pause MUST end on the clock of the server"
		);
		Ok(())
	}

	/// A write of the connection that parked on its full socket.
	const WRITE_PARKED: Urn<'static> = urn!("test", "event:lane/write-parked");

	/// What an I/O poll of the connection answered once its lane expired: the
	/// kind of its error, `ready`, or `pending`.
	const IO_ENDED: Urn<'static> = urn!("test", "event:lane/io-ended");

	/// The events of the scenario of a peer that reads nothing.
	static STALLED_EVENTS: EventWatch = EventWatch::new();

	/// What a poll of an I/O of the connection answered, as [`IO_ENDED`]
	/// records it.
	fn answered<T>(polled: Poll<io::Result<T>>) -> String {
		match polled {
			Poll::Ready(Err(error)) => format!("{:?}", error.kind()),
			Poll::Ready(Ok(_)) => "ready".to_owned(),
			Poll::Pending => "pending".to_owned(),
		}
	}

	tb_assert_spec! {
		/// A connection whose peer reads nothing: its write parks on the full
		/// socket and fails once its lane expires, and a later write, flush
		/// and shutdown of it each fail the same way.
		pub StalledWriteSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(WRITE_PARKED, exactly!(1)),
				(IO_ENDED, exactly!(4), equals!("TimedOut"))
			]
		}
	}

	// The connection writes to a peer that reads nothing until its write
	// parks, as HTTP/2 parks on the pong of each ping that such a peer sends.
	// The clock then passes the deadline of the lane, which wakes the parked
	// write.
	tb_scenario! {
		name: a_write_that_its_peer_never_reads_fails_once_its_lane_expires,
		config: ScenarioConfig::builder().with_trace(STALLED_EVENTS.trace()).with_spec(StalledWriteSpec::latest()).build(),
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let clock = Arc::new(ManualClock::default());
				let ServerSlots { slots, .. } = ServerSlots::new(NonZeroUsize::MIN);
				let slot = slots.take().ok_or(TransportError::ConnectionClosed)?;
				let lane = Lane::new(slot, Arc::clone(&slots), tunnel_terms(Arc::clone(&clock) as Arc<dyn Clock>));

				let listener = TcpListener::bind("127.0.0.1:0").await?;
				let _silent = TcpStream::connect(listener.local_addr()?).await?;
				let (tcp, peer) = listener.accept().await?;
				let mut connection = GrpcConnection::new(EdgeIo::Plain(tcp), peer, lane);

				let recorder = trace.share();
				let writing = tokio::spawn(async move {
					let chunk = vec![0_u8; 64 * 1024];
					let buffers = [io::IoSlice::new(&chunk)];
					let mut parked = false;
					let ended = poll_fn(|cx| loop {
						match Pin::new(&mut connection).poll_write_vectored(cx, &buffers) {
							Poll::Ready(Ok(_)) => {}
							Poll::Ready(Err(error)) => return Poll::Ready(error),
							Poll::Pending => {
								parked = parked || recorder.event(WRITE_PARKED).is_ok();
								return Poll::Pending;
							}
						}
					});
					let ended = ended.await;
					recorder.event_with(IO_ENDED, &[], format!("{:?}", ended.kind()))?;
					Ok::<_, TightBeamError>(connection)
				});

				STALLED_EVENTS.recorded(WRITE_PARKED, 1).await?;
				clock.advance(IDLE);
				STALLED_EVENTS.recorded(IO_ENDED, 1).await?;

				let mut connection = writing.await.map_err(|_| TransportError::ConnectionClosed)??;
				let mut cx = Context::from_waker(Waker::noop());
				let wrote = Pin::new(&mut connection).poll_write(&mut cx, b"late");
				trace.event_with(IO_ENDED, &[], answered(wrote))?;
				let flushed = Pin::new(&mut connection).poll_flush(&mut cx);
				trace.event_with(IO_ENDED, &[], answered(flushed))?;
				let shut = Pin::new(&mut connection).poll_shutdown(&mut cx);
				trace.event_with(IO_ENDED, &[], answered(shut))?;
				Ok(())
			}
		}
	}
}
