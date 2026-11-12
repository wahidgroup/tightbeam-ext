//! The loopback session: one tightbeam session from the coupler into the
//! accept queue of its own listener. Its task makes every change of state.

use core::convert::Infallible;
use core::future::{ready, Future};
use core::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use tokio::sync::{watch, Mutex, OwnedMutexGuard};
use tokio::task::JoinHandle;

use tightbeam::clock::{Clock, Lapse};
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
use crate::deadline::Deadline;
use crate::edge::{EdgeError, EdgeProfile};
use crate::incoming::Arrivals;
use crate::io::{GrpcStream, GrpcTransport};
use crate::protocol::GrpcListener;
use crate::tunnel::Tunnel;

/// The state of the session, which its task alone writes.
enum State<P: HandshakeProvider + Send + Sync + 'static> {
	Opening,
	Mux(Box<SpawnedMux>),
	Single(Arc<Mutex<GrpcTransport<P>>>),
	Backoff,
}

impl<P: HandshakeProvider + Send + Sync + 'static> State<P> {
	/// Whether the state carries calls.
	fn is_live(&self) -> bool {
		self.ready().is_some()
	}

	/// What a call sends on, or `None` while the state carries no call: the
	/// drivers of a multiplexed session run, or the transport of a single
	/// session may carry another exchange. A held single session is read once
	/// its call releases it.
	fn ready(&self) -> Option<Ready<P>> {
		match self {
			Self::Mux(spawned) if !spawned.drivers.is_finished() => Some(Ready::Mux(spawned.handle.clone())),
			Self::Single(transport) if transport.try_lock().map_or(true, |transport| transport.is_leasable()) => {
				Some(Ready::Single(Arc::clone(transport)))
			}
			Self::Mux(_) | Self::Single(_) | Self::Opening | Self::Backoff => None,
		}
	}
}

/// The open session that a coupler holds one work request on.
pub(crate) enum Ready<P: HandshakeProvider + Send + Sync + 'static> {
	Mux(MuxHandle),
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
			Self::Mux(handle) => {
				let slot = expires.bound(handle.wait_for_stream_slot()).await;
				slot?.map_err(|_| CallFault::Unavailable)?;
				Ok(Held::Mux(handle))
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
	/// session, on a free stream as [`FreeStream::take`] takes it. Nothing
	/// leaves until the first push of the sink.
	///
	/// # Errors
	///
	/// - [`CallFault::Deadline`] -- a stream came free at `expires` or later.
	/// - [`CallFault::Internal`] -- the clock gave the wait for a free stream no timer.
	/// - [`CallFault::Unavailable`] -- the session runs one call at a time, ended, or drains.
	pub(crate) async fn open_stream(self, servlet: Urn<'static>, expires: &Deadline) -> Result<Duplex, CallFault> {
		let Self::Mux(handle) = self else {
			return Err(CallFault::Unavailable);
		};

		let free = FreeStream { handle: &handle, expires };
		let opened = free
			.take(|| ready(Ok::<_, Infallible>(handle.open_duplex_to(servlet.clone()))))
			.await;
		match opened {
			Ok((sink, body)) => Ok(Duplex { sink, body }),
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
/// requests, and the body of its answers.
pub(crate) struct Duplex {
	sink: RequestSink,
	body: StreamBody,
}

impl Duplex {
	/// Push `head`, the first part of the stream, within `expires`, and give
	/// the sink and the body of the stream once the head lands.
	///
	/// # Errors
	///
	/// - [`SendFailure::Transport`] -- the session failed the push.
	/// - [`SendFailure::Unanswered`] -- the push passed `expires`, or the clock gave it no timer, after a
	///   byte of the head may have left.
	pub(crate) async fn push_head(self, head: &HeadPart, expires: &Deadline) -> Result<OpenedDuplex, SendFailure> {
		let Self { mut sink, body } = self;
		match expires.bound(sink.push(head.as_bytes())).await {
			Ok(Ok(())) => Ok(OpenedDuplex { sink, body }),
			Ok(Err(error)) => Err(SendFailure::Transport(error)),
			Err(_) => Err(SendFailure::Unanswered),
		}
	}
}

/// A duplex stream to a servlet whose head the push opened: the sink of its
/// requests, and the body of its answers.
pub(crate) struct OpenedDuplex {
	pub(crate) sink: RequestSink,
	pub(crate) body: StreamBody,
}

/// The session that one call holds for its send.
pub(crate) enum Held<P: HandshakeProvider + Send + Sync + 'static> {
	Mux(MuxHandle),
	Single(OwnedMutexGuard<GrpcTransport<P>>),
}

impl<P: HandshakeProvider + Send + Sync + 'static> Held<P> {
	/// Send `work` and return the reply of the gateway, within `expires`. On
	/// a multiplexed session, a stream that another call took first is
	/// waited for again.
	///
	/// # Errors
	///
	/// - [`SendFailure::Transport`] -- the [`TransportError`] of the send or of the reply.
	/// - [`SendFailure::Expired`] -- no stream came free before `expires`, or the clock gave the wait no
	///   timer.
	/// - [`SendFailure::Unanswered`] -- the reply did not come before `expires`, or the clock gave the wait
	///   no timer.
	pub(crate) async fn send(self, work: &Frame, expires: &Deadline) -> Result<Option<Frame>, SendFailure> {
		let handle = match self {
			Self::Mux(handle) => handle,
			Self::Single(mut transport) => {
				let reply = expires.bound(transport.emit(work.clone(), None)).await;
				return reply.map_err(|_| SendFailure::Unanswered)?.map_err(SendFailure::Transport);
			}
		};

		let free = FreeStream { handle: &handle, expires };
		let sent = free.take(|| expires.bound(handle.emit_on_stream(work))).await;
		sent.map_err(SendFailure::from)
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
}

/// A send whose attempt on a free stream failed fails so: unanswered once the
/// bound of its emit lapsed, expired once its wait for a free stream lapsed,
/// and with the error of the session otherwise.
impl From<TakeFault<Lapse>> for SendFailure {
	fn from(fault: TakeFault<Lapse>) -> Self {
		match fault {
			TakeFault::Tried(_) => Self::Unanswered,
			TakeFault::Failed(error) | TakeFault::Closed(error) => Self::Transport(error),
			TakeFault::Lapsed(_) => Self::Expired,
		}
	}
}

impl SendFailure {
	/// Whether the failure proves that no servlet reads the frame, as
	/// tightbeam proves an error before the write. An expired call got no
	/// stream for its frame.
	pub(crate) fn proves_unsent(&self) -> bool {
		match self {
			Self::Transport(error) => !error.is_connection_error(),
			Self::Expired => true,
			Self::Unanswered => false,
		}
	}

	/// The fault that answers the call.
	pub(crate) fn fault(&self) -> CallFault {
		match self {
			Self::Transport(_) => CallFault::Unavailable,
			Self::Expired | Self::Unanswered => CallFault::Deadline,
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
			Some(_) => Ok(State::Mux(Box::new(transport.into_mux(MuxRole::Client)?.spawn()))),
			None => Ok(State::Single(Arc::new(Mutex::new(transport)))),
		}
	}
}

/// The loopback session of one coupled listener, which ends with the drop of
/// the listener.
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
	async fn run<C: EdgeProfile>(shared: Arc<Shared<P>>, opener: Opener<P, C>, recorder: CallRecorder) {
		let clock = Arc::clone(&opener.clock);
		loop {
			shared.set(State::Opening);
			if let Ok(opened) = opener.open().await {
				let mut probe = Deadline::after(&clock, Coupler::LIVENESS_PROBE);
				shared.set(opened);
				recorder.session_opened();
				loop {
					probe.sleep().await;
					if !shared.is_live() {
						break;
					}

					probe = Deadline::after(&clock, Coupler::LIVENESS_PROBE);
					shared.publish(true);
				}
			}

			let retry = Deadline::after(&clock, Coupler::SESSION_BACKOFF);
			shared.set(State::Backoff);
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
