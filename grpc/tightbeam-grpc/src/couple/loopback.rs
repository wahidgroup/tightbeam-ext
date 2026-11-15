//! The loopback session: one tightbeam session from the coupler into the
//! accept queue of its own listener. Its task makes every change of state.

use core::convert::Infallible;
use core::future::{pending, ready, Future};
use core::marker::PhantomData;
use core::pin::pin;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use tokio::sync::{watch, Mutex, Notify, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

use tightbeam::clock::{Clock, Lapse};
use tightbeam::constants::DEFAULT_MUX_CANCEL_BUDGET;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::{Certificate, KeyCurves};
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::handshake::HandshakeProvider;
use tightbeam::transport::multiplex::{MuxConnector, MuxHandle, MuxRole, RequestSink, SpawnedMux, StreamBody};
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, MessageEmitter, TransportError, TransportFailure};
use tightbeam::urn::Urn;
use tightbeam::Frame;

use super::fault::CallFault;
use super::saga::{CallRecorder, Coupler};
use super::voucher::HeadPart;
use crate::deadline::{Deadline, StreamLapse};
use crate::edge::{EdgeError, EdgeProfile};
use crate::incoming::Arrivals;
use crate::io::{GrpcStream, GrpcTransport};
use crate::protocol::GrpcListener;
use crate::tunnel::Tunnel;

/// The state of the session, which its task alone writes.
enum State<P: HandshakeProvider + Send + Sync + 'static> {
	Opening,
	Mux(Arc<MuxSession>),
	Single(Arc<Mutex<GrpcTransport<P>>>),
	Backoff,
}

impl<P: HandshakeProvider + Send + Sync + 'static> State<P> {
	/// Whether the state carries calls, as a session that renews does.
	fn is_live(&self) -> bool {
		!matches!(self.offer(), Offer::Closed)
	}

	/// What the state offers a new call: a multiplexed session that takes it,
	/// the transport of a single session that may carry another exchange, or
	/// a session that renews. A held single session is read once its call
	/// releases it.
	fn offer(&self) -> Offer<P> {
		match self {
			Self::Mux(session) if session.admits() => Offer::Ready(Ready::Mux(Arc::clone(session))),
			Self::Mux(session) if session.carries() => Offer::Renewing,
			Self::Single(transport) if transport.try_lock().map_or(true, |transport| transport.is_leasable()) => {
				Offer::Ready(Ready::Single(Arc::clone(transport)))
			}
			Self::Mux(_) | Self::Single(_) | Self::Opening | Self::Backoff => Offer::Closed,
		}
	}

	/// The multiplexed session of the state, which renews, or `None` for a
	/// state with no session that cancels.
	fn mux(&self) -> Option<Arc<MuxSession>> {
		match self {
			Self::Mux(session) => Some(Arc::clone(session)),
			Self::Single(_) | Self::Opening | Self::Backoff => None,
		}
	}
}

/// What a state offers a new call.
enum Offer<P: HandshakeProvider + Send + Sync + 'static> {
	/// A session that takes the call.
	Ready(Ready<P>),
	/// A session that renews, whose next session takes the call.
	Renewing,
	/// No session.
	Closed,
}

/// A multiplexed loopback session, and the cancels that its calls left with
/// the gateway.
///
/// - The gateway serves the session under the cancel budget of tightbeam,
///   `DEFAULT_MUX_CANCEL_BUDGET`, and ends it with a GoAway at the first
///   rapid cancel past it (`docs/grpc.md`, Streams).
/// - Each open call holds a place under a [`CancelLease`], which counts a
///   cancel, rapid or not, when the call ends while it may be live at the
///   gateway, because the start of its handler lies there.
/// - A `Timeout` cancel of the gateway, and an answer of the gateway of
///   `DEADLINE_EXCEEDED`, read as a stall, so their calls count a cancel
///   that the gateway never charged, which only renews the session sooner.
/// - A session whose cancels reach [`MuxSession::RENEWAL`] takes no new
///   call, so the cancels of its open calls stay within the budget.
pub(crate) struct MuxSession {
	/// The drivers of the session, whose drop ends it once no call holds it.
	spawned: SpawnedMux,
	/// The places of the open calls, which close at the renewal.
	open: Arc<Semaphore>,
	/// The cancels that the calls of the session left with the gateway.
	cancels: AtomicU32,
	/// The wake of the task once the cancels reach [`MuxSession::RENEWAL`].
	renewal: Notify,
}

impl MuxSession {
	/// The cancels after which the task opens the next session, while this
	/// one carries its calls: half the budget.
	const RENEWAL: u32 = DEFAULT_MUX_CANCEL_BUDGET / 2;

	/// The places of the open calls of a session: the half of the budget that
	/// the cancels of a renewing session may still take.
	const PLACES: u32 = DEFAULT_MUX_CANCEL_BUDGET - Self::RENEWAL;

	/// The open streams of a coupler at most: half the places of a session,
	/// so its unary calls keep the other half.
	pub(crate) const STREAM_PLACES: usize = (Self::PLACES / 2) as usize;

	fn new(spawned: SpawnedMux) -> Self {
		Self {
			spawned,
			open: Arc::new(Semaphore::new(Self::PLACES as usize)),
			cancels: AtomicU32::new(0),
			renewal: Notify::new(),
		}
	}

	/// Whether the session carries its open calls: its drivers run.
	fn carries(&self) -> bool {
		!self.spawned.drivers.is_finished()
	}

	/// Whether the session takes a new call: it carries, and its places are
	/// open.
	fn admits(&self) -> bool {
		self.carries() && !self.open.is_closed()
	}

	/// A place for one call, once one comes free within `expires`. The lease
	/// owes no cancel until it arms.
	///
	/// # Errors
	///
	/// - [`Refusal::Renewing`] -- the session renews, so its places closed.
	/// - [`Refusal::Fault`] -- no place came free within `expires`, or the clock gave the wait no timer.
	async fn lease(self: &Arc<Self>, expires: &Deadline) -> Result<CancelLease, Refusal> {
		let place = expires.bound(Arc::clone(&self.open).acquire_owned()).await;
		let place = place?.map_err(|_| Refusal::Renewing)?;

		Ok(CancelLease { session: Arc::clone(self), place: Some(place), owed: AtomicBool::new(false) })
	}

	/// Resolve once `session` has left the cancels after which it renews, and
	/// never for no session.
	async fn renews(session: Option<Arc<Self>>) {
		match session {
			Some(session) => session.renewal.notified().await,
			None => pending().await,
		}
	}
}

/// Why a session takes no new call.
#[derive(Debug)]
enum Refusal {
	/// The session renews, so the next session takes the call.
	Renewing,
	/// The call fails with this fault.
	Fault(CallFault),
}

impl From<CallFault> for Refusal {
	fn from(fault: CallFault) -> Self {
		Self::Fault(fault)
	}
}

impl From<Lapse> for Refusal {
	fn from(lapse: Lapse) -> Self {
		Self::Fault(lapse.into())
	}
}

/// The place that one call of a multiplexed session holds among its open
/// calls, and the session, which the call keeps open.
///
/// - [`CancelLease::arm`] marks the call as one that may reach the gateway.
/// - [`CancelLease::settle`] gives the place back once the call ended.
/// - A drop before then gives it back too, and counts one cancel if the lease is armed, as tightbeam
///   cancels a call whose reply body or response drops before its end.
pub(crate) struct CancelLease {
	session: Arc<MuxSession>,
	/// The place among the open calls, until the lease settles.
	place: Option<OwnedSemaphorePermit>,
	/// Whether the call may be live at the gateway.
	owed: AtomicBool,
}

impl CancelLease {
	/// Mark the call as one that may reach the gateway.
	fn arm(&self) {
		self.owed.store(true, Ordering::Release);
	}

	/// The answer of `attempt`, an open of a stream, during which the call
	/// may reach the gateway. An attempt that finds every stream taken sent
	/// no Open, so the call owes no cancel after it.
	async fn during<T, E>(
		&self,
		attempt: impl Future<Output = Result<Result<T, TransportError>, E>>,
	) -> Result<Result<T, TransportError>, E> {
		self.arm();
		let tried = attempt.await;
		if matches!(
			tried,
			Ok(Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted)))
		) {
			self.owed.store(false, Ordering::Release);
		}

		tried
	}

	/// Give the place back, as a call that ended owes the gateway no cancel.
	pub(crate) fn settle(&mut self) {
		self.place = None;
	}

	/// Settle the lease of an attempt that failed with `failure`, unless the
	/// failure may leave its stream live at the gateway.
	fn failed(&mut self, failure: &SendFailure) {
		if !failure.leaves_live() {
			self.settle();
		}
	}
}

impl Drop for CancelLease {
	fn drop(&mut self) {
		let open = self.place.take().is_some();
		if !open || !*self.owed.get_mut() {
			return;
		}

		let cancels = self.session.cancels.fetch_add(1, Ordering::AcqRel) + 1;
		if cancels == MuxSession::RENEWAL {
			self.session.open.close();
			self.session.renewal.notify_one();
		}
	}
}

/// The open session that a coupler holds one work request on.
enum Ready<P: HandshakeProvider + Send + Sync + 'static> {
	Mux(Arc<MuxSession>),
	Single(Arc<Mutex<GrpcTransport<P>>>),
}

impl<P: HandshakeProvider + Send + Sync + 'static> Ready<P> {
	/// Hold a live session for one send, within the deadline of the call.
	///
	/// - The send holds a place on a multiplexed session once it has a free
	///   stream. That stream is not reserved, so the send waits again when
	///   another call takes it.
	/// - The send holds the transport of a single session, which carries one
	///   call at a time. A session that a call left mid-exchange lost its
	///   stream position, so it carries no other call (CWE-672).
	///
	/// # Errors
	///
	/// - [`Refusal::Renewing`] -- the multiplexed session renews.
	/// - [`CallFault::Deadline`] -- a place or the session came free at `expires` or later.
	/// - [`CallFault::Internal`] -- the clock gave a wait no timer.
	/// - [`CallFault::Unavailable`] -- the session ended, drains, or lost its position.
	async fn hold(self, expires: &Deadline) -> Result<Held<P>, Refusal> {
		match self {
			Self::Mux(session) => {
				let lease = session.lease(expires).await?;
				let slot = expires.bound(session.spawned.handle.wait_for_stream_slot()).await;
				slot?.map_err(|_| CallFault::Unavailable)?;
				Ok(Held::Mux(lease))
			}
			Self::Single(transport) => {
				let transport = expires.bound(transport.lock_owned()).await?;
				if !transport.is_leasable() {
					return Err(CallFault::Unavailable.into());
				}

				Ok(Held::Single(transport))
			}
		}
	}

	/// Open a duplex stream to the servlet type `servlet` on a multiplexed
	/// session, under a place among its open calls, on a free stream as
	/// [`FreeStream::take`] takes it. Nothing leaves until the first push of
	/// the sink.
	///
	/// # Errors
	///
	/// - [`Refusal::Renewing`] -- the session renews.
	/// - [`CallFault::Deadline`] -- a place among the open calls, or a stream, came free at `expires` or
	///   later.
	/// - [`CallFault::Internal`] -- the clock gave a wait for a place or a free stream no timer.
	/// - [`CallFault::Unavailable`] -- the session runs one call at a time, ended, or drains.
	async fn open_stream(self, servlet: &Urn<'static>, expires: &Deadline) -> Result<Duplex, Refusal> {
		let Self::Mux(session) = self else {
			return Err(CallFault::Unavailable.into());
		};

		let lease = session.lease(expires).await?;
		let handle = &session.spawned.handle;
		let free = FreeStream { handle, expires };

		let opened = free
			.take(|| ready(Ok::<_, Infallible>(handle.open_duplex_to(servlet.clone()))))
			.await;
		match opened {
			Ok((sink, body)) => Ok(Duplex { sink, body, lease }),
			Err(TakeFault::Tried(never)) => match never {},
			Err(TakeFault::Failed(_) | TakeFault::Closed(_)) => Err(CallFault::Unavailable.into()),
			Err(TakeFault::Lapsed(lapse)) => Err(lapse.into()),
		}
	}
}

/// The streams of a multiplexed session, of which a call takes a free one by
/// `expires`, the deadline of the call.
struct FreeStream<'a> {
	handle: &'a MuxHandle,
	expires: &'a Deadline,
}

impl FreeStream<'_> {
	/// The answer of `attempt` on a free stream. Each attempt that finds
	/// every stream taken, which another call may take first, waits for a
	/// free stream and tries again.
	///
	/// # Errors
	///
	/// - [`TakeFault::Tried`] -- the failure of an attempt itself.
	/// - [`TakeFault::Failed`] -- an attempt failed with an error other than that every stream is taken.
	/// - [`TakeFault::Closed`] -- the wait for a free stream failed, because the session ended or drains.
	/// - [`TakeFault::Lapsed`] -- the wait for a free stream lapsed.
	async fn take<T, E, F>(&self, mut attempt: impl FnMut() -> F) -> Result<T, TakeFault<E>>
	where
		F: Future<Output = Result<Result<T, TransportError>, E>>,
	{
		loop {
			match attempt().await.map_err(TakeFault::Tried)? {
				Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted)) => {
					let slot = self.expires.bound(self.handle.wait_for_stream_slot()).await;
					slot.map_err(TakeFault::Lapsed)?.map_err(TakeFault::Closed)?;
				}
				tried => return tried.map_err(TakeFault::Failed),
			}
		}
	}
}

/// Why an attempt on a free stream of a multiplexed session failed: its own
/// failure, a transport error, the end of the session, or the lapse of the
/// wait for a free stream. Each caller of [`FreeStream::take`] maps it to its
/// own fault.
enum TakeFault<E> {
	/// The attempt failed with this failure of its own.
	Tried(E),
	/// The attempt failed with this error, other than that every stream is
	/// taken.
	Failed(TransportError),
	/// The wait for a free stream failed with this error.
	Closed(TransportError),
	/// The wait for a free stream lapsed so, before any byte of the attempt
	/// left.
	Lapsed(Lapse),
}

/// A duplex stream to a servlet that no push has opened yet: the sink of its
/// requests, the body of its answers, and its unit of the cancel budget.
pub(crate) struct Duplex {
	sink: RequestSink,
	body: StreamBody,
	lease: CancelLease,
}

impl Duplex {
	/// Push `head`, the first part of the stream, within `expires`, and give
	/// the sink, the body, and the unit of the stream once the head lands.
	///
	/// # Errors
	///
	/// - [`SendFailure::Transport`] -- the session failed the push.
	/// - [`SendFailure::Unanswered`] -- the push passed `expires`, or a clock gave it no timer, after a
	///   byte of the head may have left.
	/// - [`SendFailure::Stalled`] -- the push waited past the read deadline of the session.
	pub(crate) async fn push_head(self, head: &HeadPart, expires: &Deadline) -> Result<OpenedDuplex, SendFailure> {
		let Self { mut sink, body, mut lease } = self;
		lease.arm();
		let failure = match expires.bound(sink.push(head.as_bytes())).await {
			Ok(Ok(())) => return Ok(OpenedDuplex { sink, body, lease }),
			Ok(Err(error)) => SendFailure::of_push(error),
			Err(_) => SendFailure::Unanswered,
		};

		lease.failed(&failure);
		Err(failure)
	}
}

/// A duplex stream to a servlet whose head the push opened: the sink of its
/// requests, the body of its answers, and its unit of the cancel budget.
pub(crate) struct OpenedDuplex {
	pub(crate) sink: RequestSink,
	pub(crate) body: StreamBody,
	pub(crate) lease: CancelLease,
}

/// The session that one call holds for its send: its place on a multiplexed
/// session, or the transport of a single session.
pub(crate) enum Held<P: HandshakeProvider + Send + Sync + 'static> {
	Mux(CancelLease),
	Single(OwnedMutexGuard<GrpcTransport<P>>),
}

impl<P: HandshakeProvider + Send + Sync + 'static> Held<P> {
	/// Send `work` and return the reply of the gateway, within `expires`. On
	/// a multiplexed session, the lease of the send arms while each emit
	/// runs, and a stream that another call took first is waited for again.
	///
	/// # Errors
	///
	/// - [`SendFailure::Transport`] -- the [`TransportError`] of the send or of the reply.
	/// - [`SendFailure::Expired`] -- no stream came free before `expires`, or the clock gave the wait no
	///   timer.
	/// - [`SendFailure::Unanswered`] -- the reply did not come before `expires`, or the clock gave the wait
	///   no timer.
	/// - [`SendFailure::Stalled`] -- a wait of the send passed a read deadline of the session, as
	///   [`CallFault::Stalled`] states.
	pub(crate) async fn send(self, work: &Frame, expires: &Deadline) -> Result<Option<Frame>, SendFailure> {
		let mut lease = match self {
			Self::Mux(lease) => lease,
			Self::Single(mut transport) => {
				let reply = expires.bound(transport.emit(work.clone(), None)).await;
				let reply = reply.map_err(|_| SendFailure::Unanswered)?;
				return reply.map_err(|error| SendFailure::of_emit(error, expires));
			}
		};

		let handle = &lease.session.spawned.handle;
		let free = FreeStream { handle, expires };

		let sent = free.take(|| lease.during(expires.bound(handle.emit_on_stream(work)))).await;
		let sent = sent.map_err(|fault| SendFailure::of_take(fault, expires));
		match &sent {
			Ok(_) => lease.settle(),
			Err(failure) => lease.failed(failure),
		}

		sent
	}
}

/// Why the pivot of a coupled call failed: its send on the loopback session.
#[derive(Debug)]
pub(crate) enum SendFailure {
	/// The session failed the send or its reply with this error.
	Transport(TransportError),
	/// The call passed its deadline, or the clock gave its wait no timer,
	/// while it waited for a stream, before any byte of its frame left.
	Expired,
	/// The call passed its deadline, or the clock gave its wait no timer,
	/// after its frame may have left: during the push of the head of its
	/// stream, or while it waited for the reply.
	Unanswered,
	/// A wait of the send passed the read deadline of an end of the session,
	/// or the gateway answered so, as [`CallFault::Stalled`] states.
	Stalled,
}

impl SendFailure {
	/// The failure of an emit under `expires` whose frame may have left when
	/// the session failed it with `error`:
	///
	/// - Stalled on `DeadlineExceeded`, as [`CallFault::Stalled`] states.
	/// - Unanswered on `FailedPrecondition` while the clock of `expires` gives
	///   the polling thread no timer, the lapse of the bound of tightbeam,
	///   which the bound of the coupler reads the same way.
	/// - The error of the session otherwise, such as another status that the
	///   gateway answered.
	fn of_emit(error: TransportError, expires: &Deadline) -> Self {
		match error {
			TransportError::OperationFailed(TransportFailure::DeadlineExceeded) => Self::Stalled,
			TransportError::OperationFailed(TransportFailure::FailedPrecondition) if expires.gives_no_timer() => {
				Self::Unanswered
			}
			error => Self::Transport(error),
		}
	}

	/// The failure of a send under `expires` whose attempt on a free stream
	/// failed with `fault`: unanswered once the bound of its emit lapsed,
	/// expired once its wait for a free stream lapsed, and as
	/// [`SendFailure::of_emit`] reads the error of the emit otherwise.
	fn of_take(fault: TakeFault<Lapse>, expires: &Deadline) -> Self {
		match fault {
			TakeFault::Tried(_) => Self::Unanswered,
			TakeFault::Failed(error) => Self::of_emit(error, expires),
			TakeFault::Closed(error) => Self::Transport(error),
			TakeFault::Lapsed(_) => Self::Expired,
		}
	}

	/// The failure of the push of a head whose bytes may have left when the
	/// sink failed it with `error`: stalled once a wait of the push passed
	/// the read deadline of the session, unanswered once the clock gave that
	/// wait no timer, as the bound of the coupler reads that lapse, and the
	/// error of the session otherwise.
	fn of_push(error: TransportError) -> Self {
		match error.lapse() {
			Some(Lapse::Passed) => Self::Stalled,
			Some(Lapse::NoTimer) => Self::Unanswered,
			None => Self::Transport(error),
		}
	}

	/// Whether the failure proves that no servlet reads the frame, as
	/// tightbeam proves an error before the write. An expired call got no
	/// stream for its frame.
	pub(crate) fn proves_unsent(&self) -> bool {
		match self {
			Self::Transport(error) => !error.is_connection_error(),
			Self::Expired => true,
			Self::Unanswered | Self::Stalled => false,
		}
	}

	/// Whether the send may have left its stream live at the gateway: an emit
	/// that a bound cut after its frame may have left. A stall that the
	/// gateway ended with its own `Timeout` cancel reads the same, so its
	/// lease counts a cancel that the gateway never charged, which only
	/// renews the session sooner. Every other end of the send resolved its
	/// stream, or opened none.
	fn leaves_live(&self) -> bool {
		match self {
			Self::Unanswered | Self::Stalled => true,
			Self::Transport(_) | Self::Expired => false,
		}
	}

	/// The fault that answers the call.
	pub(crate) fn fault(&self) -> CallFault {
		match self {
			Self::Transport(_) => CallFault::Unavailable,
			Self::Expired | Self::Unanswered => CallFault::Deadline,
			Self::Stalled => CallFault::Stalled,
		}
	}
}

/// The state that the session task and the coupler share, the wake of each
/// call that waits for its next session, and the health of the edge: whether
/// a session outlived its last probe.
struct Shared<P: HandshakeProvider + Send + Sync + 'static> {
	state: StdMutex<State<P>>,
	changed: Notify,
	serving: watch::Sender<bool>,
}

impl<P: HandshakeProvider + Send + Sync + 'static> Shared<P> {
	fn new(state: State<P>, serving: watch::Sender<bool>) -> Self {
		Self { state: StdMutex::new(state), changed: Notify::new(), serving }
	}

	/// Enter `state`. A state that carries no call ends the health of the
	/// edge at once, and an open one serves from its first probe.
	fn set(&self, state: State<P>) {
		let live = state.is_live();
		*self.state.lock().unwrap_or_else(PoisonError::into_inner) = state;
		self.changed.notify_waiters();
		if !live {
			self.publish(false);
		}
	}

	/// Enter `state`, a state with no session, unless a session carries
	/// calls, as one that renews does until the next one opens.
	fn unless_live(&self, state: State<P>) {
		let mut current = self.state.lock().unwrap_or_else(PoisonError::into_inner);
		if current.is_live() {
			return;
		}

		*current = state;

		drop(current);
		self.changed.notify_waiters();
		self.publish(false);
	}

	/// Publish the health of the edge to each health watch.
	fn publish(&self, serving: bool) {
		self.serving.send_if_modified(|was| core::mem::replace(was, serving) != serving);
	}

	fn is_live(&self) -> bool {
		self.state.lock().unwrap_or_else(PoisonError::into_inner).is_live()
	}

	/// The answer of `attempt` on the session that takes a new call, within
	/// `expires`. A call that finds the session renewing waits for the next
	/// one, and tries again there.
	///
	/// # Errors
	///
	/// - [`CallFault::Unavailable`] -- no session is open.
	/// - [`CallFault::Deadline`] -- the next session opened at `expires` or later.
	/// - [`CallFault::Internal`] -- the clock gave the wait for the next session no timer.
	/// - The fault of `attempt`.
	async fn admit<T, F>(&self, expires: &Deadline, mut attempt: impl FnMut(Ready<P>) -> F) -> Result<T, CallFault>
	where
		F: Future<Output = Result<T, Refusal>>,
	{
		loop {
			let changed = self.changed.notified();
			let mut changed = pin!(changed);
			changed.as_mut().enable();

			let offer = self.state.lock().unwrap_or_else(PoisonError::into_inner).offer();
			match offer {
				Offer::Ready(ready) => match attempt(ready).await {
					Err(Refusal::Renewing) => continue,
					Err(Refusal::Fault(fault)) => return Err(fault),
					Ok(taken) => return Ok(taken),
				},
				Offer::Renewing => expires.bound(changed).await?,
				Offer::Closed => return Err(CallFault::Unavailable),
			}
		}
	}
}

/// How the task opens a session: the queue and the address of the listener,
/// the pin of its certificate, the handshake identity of the voucher, the mux
/// offer of the coupler, and the clock of the edge, which the client of each
/// session and the task measure against.
struct Opener<P, C> {
	queue: Arrivals,
	local: SocketAddr,
	pin: Arc<dyn CertificateTrust>,
	handshake: SigningIdentity,
	offer: Arc<TransportOffer>,
	clock: Arc<dyn Clock>,
	_listener: PhantomData<fn() -> (P, C)>,
}

impl<P, C> Opener<P, C>
where
	P: HandshakeProvider + Send + Sync + 'static,
	C: EdgeProfile,
{
	/// Queue an in-process tunnel for the listener, complete the client
	/// handshake over it, and keep it multiplexed when the edge negotiated
	/// mux. The client carries no restart policy, so no send of the session
	/// goes out twice.
	async fn open(&self) -> Result<State<P>, TransportError> {
		let (client, server) = GrpcStream::loopback();
		self.queue.loopback(Tunnel::loopback(server, self.local)).await?;

		let builder = ClientBuilder::<GrpcListener<P, C>>::on_clock(Arc::clone(&self.clock));
		let builder = builder.with_trust_store(Arc::clone(&self.pin));
		let builder = builder.with_client_identity(self.handshake.clone());
		let client = builder.adopt(client)?;

		let mut transport = client.into_transport().with_mux_offer(Some(Arc::clone(&self.offer)));
		transport.complete_client_handshake().await?;

		match transport.negotiated_mux() {
			Some(_) => {
				let spawned = transport.into_mux(MuxRole::Client)?.spawn();
				Ok(State::Mux(Arc::new(MuxSession::new(spawned))))
			}
			None => Ok(State::Single(Arc::new(Mutex::new(transport)))),
		}
	}
}

/// The loopback session of one coupled listener, whose task ends with the
/// drop of the listener. Each session ends once no call holds it.
pub(crate) struct LoopbackSession<P: HandshakeProvider + Send + Sync + 'static> {
	shared: Arc<Shared<P>>,
	task: JoinHandle<()>,
}

/// The certificate that a listener presents, which its loopback session
/// trusts alone.
pub(crate) struct GatewayPin(Arc<dyn CertificateTrust>);

impl GatewayPin {
	/// The pin of `gateway`.
	///
	/// # Errors
	///
	/// - [`EdgeError::Trust`] -- tightbeam refuses `gateway` as a pin.
	pub(crate) fn of(gateway: &Certificate) -> Result<Self, EdgeError> {
		let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
		Ok(Self(Arc::new(builder.with_certificate(gateway.clone())?.build())))
	}
}

impl<P: HandshakeProvider + Send + Sync + 'static> LoopbackSession<P> {
	/// Start the session of the listener of profile `C` bound at `local`,
	/// which queues its tunnel on `queue`, trusts `pin`, presents `handshake`
	/// with `streams` streams of mux on offer, records each open on
	/// `recorder`, and runs on `clock`.
	pub(crate) fn start<C: EdgeProfile>(
		queue: Arrivals,
		local: SocketAddr,
		GatewayPin(pin): GatewayPin,
		handshake: SigningIdentity,
		streams: u32,
		recorder: CallRecorder,
		clock: Arc<dyn Clock>,
	) -> Self {
		let offer = Arc::new(TransportOffer::mux(streams));
		let opener = Opener::<P, C> { queue, local, pin, handshake, offer, clock, _listener: PhantomData };

		let (serving, _) = watch::channel(false);
		let shared = Arc::new(Shared::new(State::Opening, serving));
		let driven = Arc::clone(&shared);
		let task = tokio::spawn(async move { Self::run(driven, opener, recorder).await });
		Self { shared, task }
	}

	/// Drive the session for as long as the listener lives, with its probes
	/// and its backoff on the clock of `opener`, and record each open on
	/// `recorder`.
	///
	/// - Each deadline is read before the health of the edge changes, or before the record of an open, so a
	///   scenario that reads the change or the record reads it after the deadline that follows it.
	/// - A multiplexed session whose cancels reach [`MuxSession::RENEWAL`] renews: the next session opens
	///   at once, while this one carries its calls, and takes every call after it. The last call of this
	///   one ends it. A next session that fails to open ends the renewal, so its waiting calls fail.
	async fn run<C: EdgeProfile>(shared: Arc<Shared<P>>, opener: Opener<P, C>, recorder: CallRecorder) {
		let clock = Arc::clone(&opener.clock);
		loop {
			shared.unless_live(State::Opening);
			if let Ok(opened) = opener.open().await {
				let mut probe = Deadline::after(&clock, Coupler::LIVENESS_PROBE);
				let mut renewal = pin!(MuxSession::renews(opened.mux()));
				shared.set(opened);
				recorder.session_opened();
				let renews = loop {
					tokio::select! {
						() = probe.sleep() => {}
						() = &mut renewal => break true,
					}

					if !shared.is_live() {
						break false;
					}

					probe = Deadline::after(&clock, Coupler::LIVENESS_PROBE);
					shared.publish(true);
				};

				if renews {
					continue;
				}
			}

			let retry = Deadline::after(&clock, Coupler::SESSION_BACKOFF);
			shared.set(State::Backoff);
			retry.sleep().await;
		}
	}

	/// Hold the session that takes a new call for one send, within
	/// `expires`, as [`Shared::admit`] admits it.
	///
	/// # Errors
	///
	/// - The errors of [`Shared::admit`].
	pub(crate) async fn hold(&self, expires: &Deadline) -> Result<Held<P>, CallFault> {
		self.shared.admit(expires, |ready| ready.hold(expires)).await
	}

	/// Open a duplex stream to the servlet type `servlet` on the session that
	/// takes a new call, within `expires`, as [`Shared::admit`] admits it.
	///
	/// # Errors
	///
	/// - The errors of [`Shared::admit`].
	pub(crate) async fn open_stream(&self, servlet: &Urn<'static>, expires: &Deadline) -> Result<Duplex, CallFault> {
		self.shared.admit(expires, |ready| ready.open_stream(servlet, expires)).await
	}

	/// Whether a session outlived its last probe, which the health check of
	/// the edge answers: `false` until one does, as for a session that the
	/// gateway refuses after its handshake (`docs/grpc.md`, Health).
	pub(crate) fn health(&self) -> bool {
		*self.shared.serving.borrow()
	}

	/// The health of the edge, now and at each change, which a health watch
	/// answers.
	pub(crate) fn watch(&self) -> watch::Receiver<bool> {
		self.shared.serving.subscribe()
	}
}

impl<P: HandshakeProvider + Send + Sync + 'static> Drop for LoopbackSession<P> {
	fn drop(&mut self) {
		self.task.abort();
	}
}

#[cfg(test)]
mod tests {
	use futures_util::FutureExt;
	use tightbeam::builder::TypeBuilder;
	use tightbeam::clock::SystemClock;
	use tightbeam::crypto::profiles::DefaultCryptoProvider;
	use tightbeam::der::asn1::OctetString;
	use tightbeam::transport::handshake::negotiation::MuxSettings;
	use tightbeam::transport::multiplex::MuxTransport;
	use tightbeam::transport::tcp::r#async::TokioStream;
	use tightbeam::transport::{EndpointConfig, TcpTransport};
	use tightbeam::Version;
	use tokio::net::{TcpListener, TcpStream};

	use core::time::Duration;
	use tightbeam_ws::testing::Identity;

	use super::super::message::{CoupledCall, CoupledPart, PartWire, StreamTerms};
	use super::super::method::MethodPath;
	use super::super::routes::StreamShape;
	use super::super::voucher::{Identities, RequestId, Voucher};
	use super::*;

	type TestResult = Result<(), Box<dyn std::error::Error>>;

	/// A multiplexed session over a cleartext loopback connection, and the
	/// accepted end, which holds the connection open and never answers.
	async fn session() -> Result<(Arc<MuxSession>, TcpStream), Box<dyn std::error::Error>> {
		let listener = TcpListener::bind("127.0.0.1:0").await?;
		let dialing = TcpStream::connect(listener.local_addr()?).await?;
		let (accepted, _) = listener.accept().await?;
		let stream = TokioStream::from(dialing);
		let config = EndpointConfig::cleartext();
		let transport: TcpTransport<TokioStream> = TcpTransport::new(stream, config);
		let (reader, writer) = transport.into_split()?;

		let mux = MuxTransport::new(reader, writer, MuxRole::Client, MuxSettings::symmetric(4));
		Ok((Arc::new(MuxSession::new(mux.spawn())), accepted))
	}

	/// The state that `state` starts, shared, and the health watch of it.
	fn shared(state: State<DefaultCryptoProvider>) -> (Shared<DefaultCryptoProvider>, watch::Receiver<bool>) {
		let (serving, health) = watch::channel(true);
		(Shared::new(state, serving), health)
	}

	/// A deadline beyond every reading, so a wait for a place never lapses.
	fn unbounded() -> Deadline {
		let clock: Arc<dyn Clock> = Arc::new(SystemClock);
		Deadline::unbounded(&clock)
	}

	/// An unsigned work frame.
	fn work() -> Result<Frame, Box<dyn std::error::Error>> {
		let part = PartWire::Message(OctetString::new(b"order".to_vec())?);
		let draft = Version::V1.compose().with_id(b"call").with_order(1);
		Ok(draft.with_message(CoupledPart { part }).build()?)
	}

	/// The head of a stream, signed by the voucher of minted identities.
	async fn head() -> Result<HeadPart, Box<dyn std::error::Error>> {
		let lifetime = Duration::from_secs(60);
		let session = Identity::mint("CN=session", 2, lifetime)?;
		let signer = Identity::mint("CN=coupler", 3, lifetime)?;
		let identities = Identities { handshake: session.signing_identity(), signer: signer.signing_identity() };
		let voucher = Voucher::new(identities);
		let terms = StreamTerms::new(StreamShape::Bidi, 4096);
		let method: MethodPath = "/orders.v1.Orders/Watch".parse()?;

		let signed = voucher.sign(CoupledCall::head(&method, terms)?, RequestId::new([1; 16])).await;
		let signed = signed.map_err(|fault| format!("{fault:?}"))?;
		Ok(signed.into_head(terms).map_err(|fault| format!("{fault:?}"))?)
	}

	/// The lease that `session` gives at once, if any, outside the budget of
	/// polls of the task, which would otherwise make a long run of leases
	/// wait.
	fn now(session: &Arc<MuxSession>, expires: &Deadline) -> Option<Result<CancelLease, Refusal>> {
		tokio::task::unconstrained(session.lease(expires)).now_or_never()
	}

	/// The lease that `session` gives at once.
	fn leased(session: &Arc<MuxSession>, expires: &Deadline) -> Result<CancelLease, Box<dyn std::error::Error>> {
		match now(session, expires) {
			Some(leased) => leased.map_err(|refusal| format!("{refusal:?}").into()),
			None => Err("the lease waits".into()),
		}
	}

	/// Leave `count` cancels on `session`, each a lease that drops armed.
	fn cancel(session: &Arc<MuxSession>, expires: &Deadline, count: u32) -> TestResult {
		for _ in 0..count {
			leased(session, expires)?.arm();
		}

		Ok(())
	}

	/// Whether `held` holds a place on `session`.
	fn holds(held: Option<Result<Held<DefaultCryptoProvider>, CallFault>>, session: &Arc<MuxSession>) -> bool {
		matches!(held, Some(Ok(Held::Mux(lease))) if Arc::ptr_eq(&lease.session, session))
	}

	#[tokio::test]
	async fn a_session_holds_its_places_of_open_calls_and_no_more() -> TestResult {
		let (session, _peer) = session().await?;
		let expires = unbounded();
		let mut open = Vec::new();
		for _ in 0..MuxSession::PLACES {
			open.push(leased(&session, &expires)?);
		}

		assert!(now(&session, &expires).is_none(), "a call past the places MUST wait");

		if let Some(mut ended) = open.pop() {
			ended.settle();
		}

		assert!(leased(&session, &expires).is_ok(), "a call that ended MUST free its place");
		Ok(())
	}

	#[tokio::test]
	async fn a_session_renews_once_its_cancels_reach_half_the_budget() -> TestResult {
		let (session, _peer) = session().await?;
		let expires = unbounded();

		cancel(&session, &expires, MuxSession::RENEWAL - 1)?;

		let early = MuxSession::renews(Some(Arc::clone(&session))).now_or_never();
		assert!(early.is_none(), "a session short of the renewal MUST NOT renew");

		cancel(&session, &expires, 1)?;

		let renewed = MuxSession::renews(Some(Arc::clone(&session))).now_or_never();
		assert!(renewed.is_some(), "the cancel that reaches the renewal MUST renew the session");
		Ok(())
	}

	#[tokio::test]
	async fn a_renewing_session_takes_no_new_call_and_keeps_serving() -> TestResult {
		let (session, _peer) = session().await?;
		let expires = unbounded();

		cancel(&session, &expires, MuxSession::RENEWAL)?;

		let refused = now(&session, &expires);
		assert!(
			matches!(refused, Some(Err(Refusal::Renewing))),
			"a renewing session MUST refuse a lease"
		);

		let (shared, health) = shared(State::Mux(Arc::clone(&session)));
		shared.unless_live(State::Backoff);
		assert!(*health.borrow(), "a renewing session MUST keep serving");
		Ok(())
	}

	#[tokio::test]
	async fn a_call_during_the_renewal_waits_for_the_next_session() -> TestResult {
		let (renewing, _renewing_peer) = session().await?;
		let (next, _next_peer) = session().await?;
		let expires = unbounded();
		cancel(&renewing, &expires, MuxSession::RENEWAL)?;

		let (shared, _health) = shared(State::Mux(Arc::clone(&renewing)));
		let mut waiting = pin!(shared.admit(&expires, |ready| ready.hold(&expires)));
		let early = waiting.as_mut().now_or_never();
		assert!(early.is_none(), "a call during the renewal MUST wait for the next session");

		shared.set(State::Mux(Arc::clone(&next)));
		assert!(holds(waiting.now_or_never(), &next), "the next session MUST take the call");
		Ok(())
	}

	#[tokio::test]
	async fn a_call_that_waits_for_a_place_moves_to_the_next_session_at_the_renewal() -> TestResult {
		let (renewing, _renewing_peer) = session().await?;
		let (next, _next_peer) = session().await?;
		let expires = unbounded();
		cancel(&renewing, &expires, MuxSession::RENEWAL - 1)?;
		let mut open = Vec::new();
		for _ in 0..MuxSession::PLACES {
			open.push(leased(&renewing, &expires)?);
		}

		let (shared, _health) = shared(State::Mux(Arc::clone(&renewing)));
		let mut waiting = pin!(shared.admit(&expires, |ready| ready.hold(&expires)));
		assert!(waiting.as_mut().now_or_never().is_none(), "a call past the places MUST wait");

		if let Some(ended) = open.pop() {
			ended.arm();
		}

		let early = waiting.as_mut().now_or_never();
		assert!(
			early.is_none(),
			"a call that waited past the renewal MUST wait for the next session"
		);

		shared.set(State::Mux(Arc::clone(&next)));
		assert!(holds(waiting.now_or_never(), &next), "the next session MUST take the call");
		Ok(())
	}

	#[tokio::test]
	async fn a_send_that_drops_while_it_waits_for_a_stream_counts_no_cancel() -> TestResult {
		let (session, _peer) = session().await?;
		let expires = unbounded();
		let mut taken = Vec::new();
		let exhausted = loop {
			match session.spawned.handle.open_duplex() {
				Ok(duplex) => taken.push(duplex),
				Err(error) => break error,
			}
		};

		let streams_exhausted = TransportError::OperationFailed(TransportFailure::StreamsExhausted);
		assert_eq!(
			exhausted.to_string(),
			streams_exhausted.to_string(),
			"the duplexes MUST take every stream"
		);

		let frame = work()?;
		let held = Held::<DefaultCryptoProvider>::Mux(leased(&session, &expires)?);
		let sent = tokio::task::unconstrained(held.send(&frame, &expires)).now_or_never();
		assert!(sent.is_none(), "a send with every stream taken MUST wait");
		assert_eq!(
			session.cancels.load(Ordering::Acquire),
			0,
			"a send that sent no Open MUST count no cancel"
		);
		Ok(())
	}

	#[tokio::test]
	async fn a_send_that_drops_once_its_open_may_have_left_counts_a_cancel() -> TestResult {
		let (session, _peer) = session().await?;
		let expires = unbounded();

		let frame = work()?;
		let held = Held::<DefaultCryptoProvider>::Mux(leased(&session, &expires)?);
		let sent = tokio::task::unconstrained(held.send(&frame, &expires)).now_or_never();
		assert!(sent.is_none(), "a send that the peer never answers MUST wait");
		assert_eq!(
			session.cancels.load(Ordering::Acquire),
			1,
			"a send whose Open may have left MUST count a cancel"
		);
		Ok(())
	}

	#[tokio::test]
	async fn a_head_that_a_draining_session_refuses_counts_no_cancel() -> TestResult {
		let (session, _peer) = session().await?;
		let head = head().await?;
		let (sink, body) = session.spawned.handle.open_duplex()?;
		let duplex = Duplex { sink, body, lease: leased(&session, &unbounded())? };

		session.spawned.handle.shutdown().await?;

		let clock: Arc<dyn Clock> = Arc::new(SystemClock);
		let expires = Deadline::after(&clock, Duration::from_secs(10));
		let failure = duplex.push_head(&head, &expires).await.err();
		let refused = matches!(failure, Some(SendFailure::Transport(_)));
		assert!(refused, "a draining session MUST refuse the head, got {failure:?}");

		let cancels = session.cancels.load(Ordering::Acquire);
		assert_eq!(cancels, 0, "a head that opened no stream MUST count no cancel");
		Ok(())
	}
}
