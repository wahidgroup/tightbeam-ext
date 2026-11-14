//! The loopback session: one tightbeam session from the coupler into the
//! accept queue of its own listener. Its task makes every change of state.

use core::convert::Infallible;
use core::future::{pending, ready, Future};
use core::marker::PhantomData;
use core::pin::pin;
use core::sync::atomic::{AtomicU32, Ordering};
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
	/// Whether the state carries calls.
	fn is_live(&self) -> bool {
		self.ready().is_some()
	}

	/// What a call sends on, or `None` while the state carries no call: a
	/// multiplexed session that carries a new call, or the transport of a
	/// single session that may carry another exchange. A held single session
	/// is read once its call releases it.
	fn ready(&self) -> Option<Ready<P>> {
		match self {
			Self::Mux(session) if session.carries() => Some(Ready::Mux(Arc::clone(session))),
			Self::Single(transport) if transport.try_lock().map_or(true, |transport| transport.is_leasable()) => {
				Some(Ready::Single(Arc::clone(transport)))
			}
			Self::Mux(_) | Self::Single(_) | Self::Opening | Self::Backoff => None,
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

/// A multiplexed loopback session, and the share of the cancel budget of the
/// gateway that its calls hold.
///
/// - The gateway serves the session under the cancel budget of tightbeam,
///   `DEFAULT_MUX_CANCEL_BUDGET`, and ends it with a GoAway at the first
///   rapid cancel past it (`docs/grpc.md`, Streams).
/// - Each call holds one unit of the budget while it is open, under a
///   [`CancelLease`] that arms at the start of its first push. An armed call
///   keeps its unit and counts a cancel, rapid or not, because the start of
///   its handler lies at the gateway. A unary send that ends with a reply,
///   or with a failure that [`SendFailure::leaves_live`] reads as resolving
///   its stream, gives the unit back, as a stream whose body ended does.
/// - A `Timeout` cancel of the gateway, and an answer of the gateway of
///   `DEADLINE_EXCEEDED`, read as a stall, so their calls count a cancel
///   that the gateway never charged, which only renews the session sooner.
/// - At most half the budget is open at once, so the cancels reach
///   [`MuxSession::RENEWAL`], and the session renews, before a call waits on
///   a unit that cancels hold.
pub(crate) struct MuxSession {
	/// The drivers of the session, whose drop ends it once no call holds it.
	spawned: SpawnedMux,
	/// The places of the open calls: the half of the budget that cancels do
	/// not take before the session renews.
	open: Arc<Semaphore>,
	/// The units of the budget that open calls hold or that cancels spent.
	held: AtomicU32,
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
	/// cancels do not take before the session renews.
	const PLACES: u32 = DEFAULT_MUX_CANCEL_BUDGET - Self::RENEWAL;

	/// The open streams of a coupler at most: half the places of a session,
	/// so its unary calls keep the other half.
	pub(crate) const STREAM_PLACES: usize = (Self::PLACES / 2) as usize;

	fn new(spawned: SpawnedMux) -> Self {
		Self {
			spawned,
			open: Arc::new(Semaphore::new(Self::PLACES as usize)),
			held: AtomicU32::new(0),
			cancels: AtomicU32::new(0),
			renewal: Notify::new(),
		}
	}

	/// Whether the session carries a new call: its drivers run, and its
	/// cancels left a unit of the budget.
	fn carries(&self) -> bool {
		!self.spawned.drivers.is_finished() && self.cancels.load(Ordering::Acquire) < DEFAULT_MUX_CANCEL_BUDGET
	}

	/// A unit of the budget for one call, once a place among the open calls
	/// comes free within `expires`. The unit owes no cancel until
	/// [`CancelLease::arm`].
	///
	/// # Errors
	///
	/// - [`LeaseFault::Lapsed`] -- no place came free within `expires`, or the clock gave the wait no timer.
	/// - [`LeaseFault::Spent`] -- open calls and cancels hold the whole budget.
	async fn lease(self: &Arc<Self>, expires: &Deadline) -> Result<CancelLease, LeaseFault> {
		let place = expires.bound(Arc::clone(&self.open).acquire_owned()).await;
		let place = place.map_err(LeaseFault::Lapsed)?.map_err(|_| LeaseFault::Spent)?;
		let taken = self.held.fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
			(held < DEFAULT_MUX_CANCEL_BUDGET).then_some(held + 1)
		});
		taken.map_err(|_| LeaseFault::Spent)?;

		Ok(CancelLease { session: Arc::clone(self), place: Some(place), owed: false })
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

/// Why a call of a multiplexed session gets no unit of the cancel budget, so
/// nothing of it leaves.
#[derive(Debug)]
enum LeaseFault {
	/// No place among the open calls came free within the deadline of the
	/// call, or the clock gave the wait no timer.
	Lapsed(Lapse),
	/// Open calls and cancels hold the whole budget.
	Spent,
}

/// A call with no unit fails as a send that never left: expired with its
/// deadline, and unavailable on a spent session.
impl From<LeaseFault> for SendFailure {
	fn from(fault: LeaseFault) -> Self {
		match fault {
			LeaseFault::Lapsed(_) => Self::Expired,
			LeaseFault::Spent => Self::Transport(TransportError::OperationFailed(TransportFailure::Unavailable)),
		}
	}
}

/// A stream with no unit fails with the lapse of its wait, or as unavailable
/// on a spent session.
impl From<LeaseFault> for CallFault {
	fn from(fault: LeaseFault) -> Self {
		match fault {
			LeaseFault::Lapsed(lapse) => lapse.into(),
			LeaseFault::Spent => Self::Unavailable,
		}
	}
}

/// The unit of the cancel budget that one call of a multiplexed session
/// holds, its place among the open calls, and the session, which the call
/// keeps open.
///
/// - [`CancelLease::arm`] marks the call as one that may reach the gateway, before its first push.
/// - [`CancelLease::settle`] gives the unit and the place back once the call ended.
/// - A drop before then gives them back too, unless the lease is armed: then it counts one cancel and
///   keeps the unit, as tightbeam cancels a call whose reply body or response drops before its end.
pub(crate) struct CancelLease {
	session: Arc<MuxSession>,
	/// The place among the open calls, until the lease settles.
	place: Option<OwnedSemaphorePermit>,
	/// Whether the call may be live at the gateway.
	owed: bool,
}

impl CancelLease {
	/// Mark the call as one that may reach the gateway, before its first push.
	fn arm(&mut self) {
		self.owed = true;
	}

	/// Give the unit and the place back, as a call that ended owes the gateway
	/// no cancel.
	pub(crate) fn settle(&mut self) {
		if self.place.take().is_some() {
			self.session.held.fetch_sub(1, Ordering::AcqRel);
		}
	}
}

impl Drop for CancelLease {
	fn drop(&mut self) {
		if self.place.take().is_none() {
			return;
		}

		if !self.owed {
			self.session.held.fetch_sub(1, Ordering::AcqRel);
			return;
		}

		let cancels = self.session.cancels.fetch_add(1, Ordering::AcqRel) + 1;
		if cancels == MuxSession::RENEWAL {
			self.session.renewal.notify_one();
		}
	}
}

/// The open session that a coupler holds one work request on.
pub(crate) enum Ready<P: HandshakeProvider + Send + Sync + 'static> {
	Mux(Arc<MuxSession>),
	Single(Arc<Mutex<GrpcTransport<P>>>),
}

impl<P: HandshakeProvider + Send + Sync + 'static> Ready<P> {
	/// Hold a live session for one send, within the deadline of the call.
	///
	/// - The send holds a multiplexed session once it has a free stream. That
	///   stream is not reserved, so the send waits again when another call
	///   takes it.
	/// - The send holds the transport of a single session, which carries one
	///   call at a time. A session that a call left mid-exchange lost its
	///   stream position, so it carries no other call (CWE-672).
	///
	/// # Errors
	///
	/// - [`CallFault::Deadline`] -- the session came free at `expires` or later.
	/// - [`CallFault::Internal`] -- the clock gave the wait for the session no timer.
	/// - [`CallFault::Unavailable`] -- the session ended, drains, or lost its position.
	pub(crate) async fn hold(self, expires: &Deadline) -> Result<Held<P>, CallFault> {
		match self {
			Self::Mux(session) => {
				let slot = expires.bound(session.spawned.handle.wait_for_stream_slot()).await;
				slot?.map_err(|_| CallFault::Unavailable)?;
				Ok(Held::Mux(session))
			}
			Self::Single(transport) => {
				let transport = expires.bound(transport.lock_owned()).await?;
				if !transport.is_leasable() {
					return Err(CallFault::Unavailable);
				}

				Ok(Held::Single(transport))
			}
		}
	}

	/// Open a duplex stream to the servlet type `servlet` on a multiplexed
	/// session, under a unit of its cancel budget, on a free stream as
	/// [`FreeStream::take`] takes it. Nothing leaves until the first push of
	/// the sink.
	///
	/// # Errors
	///
	/// - [`CallFault::Deadline`] -- a place among the open calls, or a stream, came free at `expires` or
	///   later.
	/// - [`CallFault::Internal`] -- the clock gave a wait for a place or a free stream no timer.
	/// - [`CallFault::Unavailable`] -- the session runs one call at a time, ended, drains, or spent its
	///   cancel budget.
	pub(crate) async fn open_stream(self, servlet: Urn<'static>, expires: &Deadline) -> Result<Duplex, CallFault> {
		let Self::Mux(session) = self else {
			return Err(CallFault::Unavailable);
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
			Err(TakeFault::Failed(_) | TakeFault::Closed(_)) => Err(CallFault::Unavailable),
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
		match expires.bound(sink.push(head.as_bytes())).await {
			Ok(Ok(())) => Ok(OpenedDuplex { sink, body, lease }),
			Ok(Err(error)) => Err(SendFailure::of_push(error)),
			Err(_) => Err(SendFailure::Unanswered),
		}
	}
}

/// A duplex stream to a servlet whose head the push opened: the sink of its
/// requests, the body of its answers, and its unit of the cancel budget.
pub(crate) struct OpenedDuplex {
	pub(crate) sink: RequestSink,
	pub(crate) body: StreamBody,
	pub(crate) lease: CancelLease,
}

/// The session that one call holds for its send.
pub(crate) enum Held<P: HandshakeProvider + Send + Sync + 'static> {
	Mux(Arc<MuxSession>),
	Single(OwnedMutexGuard<GrpcTransport<P>>),
}

impl<P: HandshakeProvider + Send + Sync + 'static> Held<P> {
	/// Send `work` and return the reply of the gateway, within `expires`. On
	/// a multiplexed session, the send holds a unit of its cancel budget, and
	/// a stream that another call took first is waited for again.
	///
	/// # Errors
	///
	/// - [`SendFailure::Transport`] -- the [`TransportError`] of the send or of the reply, or a spent cancel
	///   budget, before any byte left.
	/// - [`SendFailure::Expired`] -- no place among the open calls, or no stream, came free before
	///   `expires`, or the clock gave the wait no timer.
	/// - [`SendFailure::Unanswered`] -- the reply did not come before `expires`, or the clock gave the wait
	///   no timer.
	/// - [`SendFailure::Stalled`] -- a wait of the send passed a read deadline of the session, as
	///   [`CallFault::Stalled`] states.
	pub(crate) async fn send(self, work: &Frame, expires: &Deadline) -> Result<Option<Frame>, SendFailure> {
		let session = match self {
			Self::Mux(session) => session,
			Self::Single(mut transport) => {
				let reply = expires.bound(transport.emit(work.clone(), None)).await;
				let reply = reply.map_err(|_| SendFailure::Unanswered)?;
				return reply.map_err(|error| SendFailure::of_emit(error, expires));
			}
		};

		let mut lease = session.lease(expires).await?;
		lease.arm();

		let handle = &session.spawned.handle;
		let free = FreeStream { handle, expires };

		let sent = free.take(|| expires.bound(handle.emit_on_stream(work))).await;
		let sent = sent.map_err(|fault| SendFailure::of_take(fault, expires));
		if !sent.as_ref().err().is_some_and(SendFailure::leaves_live) {
			lease.settle();
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

/// The state that the session task and the coupler share, and the health of
/// the edge: whether a session outlived its last probe.
struct Shared<P: HandshakeProvider + Send + Sync + 'static> {
	state: StdMutex<State<P>>,
	serving: watch::Sender<bool>,
}

impl<P: HandshakeProvider + Send + Sync + 'static> Shared<P> {
	/// Enter `state`. A state that carries no call ends the health of the
	/// edge at once, and an open one serves from its first probe.
	fn set(&self, state: State<P>) {
		let live = state.is_live();
		*self.state.lock().unwrap_or_else(PoisonError::into_inner) = state;
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
		self.publish(false);
	}

	/// Publish the health of the edge to each health watch.
	fn publish(&self, serving: bool) {
		self.serving.send_if_modified(|was| core::mem::replace(was, serving) != serving);
	}

	fn is_live(&self) -> bool {
		self.state.lock().unwrap_or_else(PoisonError::into_inner).is_live()
	}

	/// What a call sends on, or `None` while the session carries no call.
	fn ready(&self) -> Option<Ready<P>> {
		self.state.lock().unwrap_or_else(PoisonError::into_inner).ready()
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
		let shared = Arc::new(Shared { state: StdMutex::new(State::Opening), serving });
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
	///   one ends it.
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
			shared.unless_live(State::Backoff);
			retry.sleep().await;
		}
	}

	/// What a call sends on, or `None` while the session carries no call.
	pub(crate) fn ready(&self) -> Option<Ready<P>> {
		self.shared.ready()
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
	use tightbeam::clock::SystemClock;
	use tightbeam::crypto::profiles::DefaultCryptoProvider;
	use tightbeam::transport::handshake::negotiation::MuxSettings;
	use tightbeam::transport::multiplex::MuxTransport;
	use tightbeam::transport::tcp::r#async::TokioStream;
	use tightbeam::transport::{EndpointConfig, TcpTransport};
	use tokio::net::{TcpListener, TcpStream};

	use super::*;

	type TestResult = Result<(), Box<dyn std::error::Error>>;

	/// A multiplexed session over a cleartext loopback connection, and the
	/// accepted end, which holds the connection open. A lease touches no byte
	/// of the connection.
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

	/// A deadline beyond every reading, so a wait for a place never lapses.
	fn unbounded() -> Deadline {
		let clock: Arc<dyn Clock> = Arc::new(SystemClock);
		Deadline::unbounded(&clock)
	}

	/// The lease that `session` gives at once, if any, outside the budget of
	/// polls of the task, which would otherwise make a long run of leases
	/// wait.
	fn now(session: &Arc<MuxSession>, expires: &Deadline) -> Option<Result<CancelLease, LeaseFault>> {
		tokio::task::unconstrained(session.lease(expires)).now_or_never()
	}

	/// The lease that `session` gives at once.
	fn leased(session: &Arc<MuxSession>, expires: &Deadline) -> Result<CancelLease, Box<dyn std::error::Error>> {
		match now(session, expires) {
			Some(leased) => leased.map_err(|fault| format!("{fault:?}").into()),
			None => Err("the lease waits".into()),
		}
	}

	/// Leave `count` cancels on `session`, each a lease that drops armed.
	fn cancel(session: &Arc<MuxSession>, expires: &Deadline, count: u32) -> TestResult {
		for _ in 0..count {
			let mut lease = leased(session, expires)?;
			lease.arm();
		}

		Ok(())
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
	async fn a_session_whose_cancels_hold_the_budget_carries_no_call() -> TestResult {
		let (session, _peer) = session().await?;
		let expires = unbounded();

		cancel(&session, &expires, DEFAULT_MUX_CANCEL_BUDGET)?;

		let refused = now(&session, &expires);
		assert!(
			matches!(refused, Some(Err(LeaseFault::Spent))),
			"a spent session MUST refuse a lease"
		);
		assert!(!session.carries(), "a spent session MUST carry no new call");

		let state = State::<DefaultCryptoProvider>::Mux(Arc::clone(&session));
		assert!(state.ready().is_none(), "a spent session MUST NOT be ready");

		let (serving, health) = watch::channel(true);
		let shared = Shared { state: StdMutex::new(state), serving };
		shared.unless_live(State::Backoff);
		assert!(!*health.borrow(), "a spent session MUST read NOT_SERVING");
		Ok(())
	}
}
