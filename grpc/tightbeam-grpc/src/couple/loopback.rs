//! The loopback session: one tightbeam session from the coupler into the
//! accept queue of its own listener. Its task makes every change of state.

use core::marker::PhantomData;
use core::time::Duration;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use tokio::sync::mpsc::Sender;
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout_at, Instant};

use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::{Certificate, KeyCurves};
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::handshake::HandshakeProvider;
use tightbeam::transport::multiplex::{MuxConnector, MuxHandle, MuxRole, SpawnedMux};
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, MessageEmitter, TransportError};
use tightbeam::Frame;

use super::fault::CallFault;
use crate::edge::{EdgeError, EdgeProfile};
use crate::io::{GrpcStream, GrpcTransport};
use crate::protocol::GrpcListener;
use crate::tunnel::{Arrival, Tunnel};

/// How often the task reads the liveness of an open session.
const LIVENESS_PROBE: Duration = Duration::from_millis(200);

/// How long the task waits before it opens a session that failed again.
const BACKOFF: Duration = Duration::from_millis(500);

/// The state of the session, which its task alone writes.
enum State<P: HandshakeProvider + Send + Sync + 'static> {
	Opening,
	Mux(Box<SpawnedMux>),
	Single(Arc<Mutex<GrpcTransport<P>>>),
	Backoff,
}

impl<P: HandshakeProvider + Send + Sync + 'static> State<P> {
	/// Whether the state carries calls: the drivers of a multiplexed session
	/// run, or the transport of a single session may carry another exchange.
	/// A held single session is read once its call releases it.
	fn is_live(&self) -> bool {
		match self {
			Self::Mux(spawned) => !spawned.drivers.is_finished(),
			Self::Single(transport) => transport.try_lock().map_or(true, |transport| transport.is_leasable()),
			Self::Opening | Self::Backoff => false,
		}
	}
}

/// The open session that a coupler holds one work request on.
pub(crate) enum Ready<P: HandshakeProvider + Send + Sync + 'static> {
	Mux(MuxHandle),
	Single(Arc<Mutex<GrpcTransport<P>>>),
}

impl<P: HandshakeProvider + Send + Sync + 'static> Ready<P> {
	/// Hold a live session for one send before `expires`: a free stream of a
	/// multiplexed session, or the transport of a single session, which one
	/// call holds at a time. A single session that a call left mid-exchange
	/// carries no other call, because its stream position is lost (CWE-672).
	///
	/// # Errors
	///
	/// - [`CallFault::Deadline`] -- the deadline passed first.
	/// - [`CallFault::Unavailable`] -- the session ended, drains, or lost its position.
	pub(crate) async fn hold(self, expires: Instant) -> Result<Held<P>, CallFault> {
		let held = match self {
			Self::Mux(handle) => {
				let slot = timeout_at(expires, handle.wait_for_stream_slot()).await;
				slot.map_err(|_| CallFault::Deadline)?.map_err(|_| CallFault::Unavailable)?;
				Held::Mux(handle)
			}
			Self::Single(transport) => {
				let locked = timeout_at(expires, transport.lock_owned()).await;
				let transport = locked.map_err(|_| CallFault::Deadline)?;
				if !transport.is_leasable() {
					return Err(CallFault::Unavailable);
				}
				Held::Single(transport)
			}
		};

		if Instant::now() >= expires {
			return Err(CallFault::Deadline);
		}

		Ok(held)
	}
}

/// The session that one call holds for its send.
pub(crate) enum Held<P: HandshakeProvider + Send + Sync + 'static> {
	Mux(MuxHandle),
	Single(OwnedMutexGuard<GrpcTransport<P>>),
}

impl<P: HandshakeProvider + Send + Sync + 'static> Held<P> {
	/// Send `work` and return the reply of the gateway.
	///
	/// # Errors
	///
	/// - The [`TransportError`] of the send or of the reply.
	pub(crate) async fn send(self, work: Frame) -> Result<Option<Frame>, TransportError> {
		match self {
			Self::Mux(handle) => handle.emit_on_stream(&work).await,
			Self::Single(mut transport) => transport.emit(work, None).await,
		}
	}
}

/// The state that the session task and the coupler share.
struct Shared<P: HandshakeProvider + Send + Sync + 'static> {
	state: StdMutex<State<P>>,
}

impl<P: HandshakeProvider + Send + Sync + 'static> Shared<P> {
	fn set(&self, state: State<P>) {
		*self.state.lock().unwrap_or_else(PoisonError::into_inner) = state;
	}

	fn is_live(&self) -> bool {
		self.state.lock().unwrap_or_else(PoisonError::into_inner).is_live()
	}
}

/// How the task opens a session: the queue and the address of the listener,
/// the pin of its certificate, the handshake identity of the voucher, and the
/// mux offer of the coupler.
struct Opener<P, C> {
	queue: Sender<Arrival>,
	local: SocketAddr,
	pin: Arc<dyn CertificateTrust>,
	handshake: SigningIdentity,
	offer: Arc<TransportOffer>,
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
		let arrival = Ok(Tunnel::loopback(server, self.local));
		self.queue.send(arrival).await.map_err(|_| TransportError::ConnectionClosed)?;

		let builder = ClientBuilder::<GrpcListener<P, C>>::builder().with_trust_store(Arc::clone(&self.pin));
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

impl<P: HandshakeProvider + Send + Sync + 'static> LoopbackSession<P> {
	/// Start the session of the listener of profile `C` bound at `local`,
	/// which queues its tunnel on `queue`, pins `gateway`, the certificate the
	/// listener presents, and presents `handshake`, with `streams` streams of
	/// mux on offer.
	///
	/// # Errors
	///
	/// - [`EdgeError::Trust`] -- tightbeam refuses `gateway` as a pin.
	pub(crate) fn start<C: EdgeProfile>(
		queue: Sender<Arrival>,
		local: SocketAddr,
		gateway: &Certificate,
		handshake: SigningIdentity,
		streams: u32,
	) -> Result<Self, EdgeError> {
		let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
		let pin: Arc<dyn CertificateTrust> = Arc::new(builder.with_certificate(gateway.clone())?.build());
		let offer = Arc::new(TransportOffer::mux(streams));
		let opener = Opener::<P, C> { queue, local, pin, handshake, offer, _listener: PhantomData };

		let shared = Arc::new(Shared { state: StdMutex::new(State::Opening) });
		let driven = Arc::clone(&shared);
		let task = tokio::spawn(async move { Self::run(driven, opener).await });
		Ok(Self { shared, task })
	}

	/// Drive the session for as long as the listener lives.
	async fn run<C: EdgeProfile>(shared: Arc<Shared<P>>, opener: Opener<P, C>) {
		loop {
			shared.set(State::Opening);
			if let Ok(opened) = opener.open().await {
				shared.set(opened);
				while shared.is_live() {
					sleep(LIVENESS_PROBE).await;
				}
			}

			shared.set(State::Backoff);
			sleep(BACKOFF).await;
		}
	}

	/// What a call sends on, or `None` while the session is not open.
	pub(crate) fn ready(&self) -> Option<Ready<P>> {
		let state = self.shared.state.lock().unwrap_or_else(PoisonError::into_inner);
		if !state.is_live() {
			return None;
		}

		match &*state {
			State::Mux(spawned) => Some(Ready::Mux(spawned.handle.clone())),
			State::Single(transport) => Some(Ready::Single(Arc::clone(transport))),
			State::Opening | State::Backoff => None,
		}
	}

	/// Whether the session carries calls, which the health check of the edge
	/// answers.
	pub(crate) fn health(&self) -> bool {
		self.shared.is_live()
	}
}

impl<P: HandshakeProvider + Send + Sync + 'static> Drop for LoopbackSession<P> {
	fn drop(&mut self) {
		self.task.abort();
	}
}
