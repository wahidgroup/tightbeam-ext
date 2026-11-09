//! The saga of one coupled call, and the coupler that runs it.
//!
//! Each act takes the proof of the act before it by value, so no act runs out
//! of order. A claim is spent only once the call holds the session, and the
//! send is the one act that cannot be undone.

use core::fmt;
use core::num::{NonZeroU32, NonZeroUsize};
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::net::SocketAddr;
use std::sync::Arc;

use http::request::Parts;
use http::HeaderValue;
use tokio::sync::mpsc::Sender;
use tokio::sync::Semaphore;
use tokio::time::Instant;

use tightbeam::clock::UnixMillis;
use tightbeam::colony::hive::ReplayGuard;
use tightbeam::colony::work::ClusterWorkResponse;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::x509::Certificate;
use tightbeam::transport::handshake::HandshakeProvider;
use tightbeam::transport::{TransportError, TransportFailure};
use tightbeam::urn::Urn;
use tightbeam::{Frame, TightBeamError};
use tonic::{Code, Status};

#[cfg(feature = "instrument")]
use tightbeam::trace::TraceCollector;

use super::claim::{CallClaim, VerifiedClaim};
use super::fault::CallFault;
use super::loopback::{Held, LoopbackSession};
use super::message::CoupledReply;
use super::principal::{Caller, Principal};
use super::routes::{Assurance, Grants, Route, Routes, Servlet};
use super::trust::CallerTrust;
use super::voucher::Voucher;
use crate::edge::{EdgeError, EdgeProfile};
use crate::incoming::{CoupledSlot, GrpcConnectInfo};
use crate::tunnel::Arrival;

#[cfg(feature = "instrument")]
use crate::events::{COUPLED_CALL_ADMITTED, COUPLED_CALL_ANSWERED, COUPLED_CALL_REFUSED};

/// The replay window of a claim, unless [`Coupler::with_replay_window`] sets
/// one.
const DEFAULT_REPLAY_WINDOW: Duration = Duration::from_secs(60);

/// The deadline of a call that sends no `grpc-timeout`, and the most that a
/// call may ask for, unless [`Coupler::with_call_limits`] sets one.
const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// The coupled connections that an edge holds at once, by default.
const DEFAULT_COUPLED_LANES: NonZeroUsize = NonZeroUsize::new(256).unwrap();

/// The calls that one coupled connection carries at once, by default.
const DEFAULT_CALL_STREAMS: NonZeroU32 = NonZeroU32::new(32).unwrap();

/// The limits of the calls of a coupled edge.
#[derive(Clone, Copy, Debug)]
struct CallLimits {
	timeout: Duration,
	lanes: NonZeroUsize,
	streams: NonZeroU32,
}

/// The coupler of an edge, as a profile provisions it: whom it trusts, whom
/// it speaks as, what it routes, and to whom.
///
/// The listener that binds a coupled edge starts one live coupler from it,
/// which holds the replay window and the loopback session, so a clone of the
/// configuration shares neither.
///
/// # Examples
///
/// ```no_run
/// use tightbeam_grpc::couple::{CallerTrust, Coupler, Grants, Routes, Servlet, Voucher};
///
/// # fn coupler(callers: CallerTrust, voucher: Voucher, routes: Routes<Servlet>, grants: Grants) -> Result<(), tightbeam_grpc::edge::EdgeError> {
/// let coupler = Coupler::new(callers, voucher, routes, grants)?;
/// # Ok(())
/// # }
/// ```
pub struct Coupler {
	callers: CallerTrust,
	voucher: Voucher,
	routes: Arc<Routes<Servlet>>,
	grants: Arc<Grants>,
	limits: CallLimits,
	replay_window: Duration,
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
}

impl Coupler {
	/// A coupler that trusts `callers`, speaks as `voucher`, routes `routes`,
	/// and permits `grants`.
	///
	/// # Errors
	///
	/// - [`EdgeError::NoRoute`] -- `routes` routes no method.
	/// - [`EdgeError::Method`] -- a grant names a method that no route serves.
	pub fn new(
		callers: CallerTrust,
		voucher: Voucher,
		routes: Routes<Servlet>,
		grants: Grants,
	) -> Result<Self, EdgeError> {
		routes.cover(&grants)?;

		let limits = CallLimits {
			timeout: DEFAULT_CALL_TIMEOUT,
			lanes: DEFAULT_COUPLED_LANES,
			streams: DEFAULT_CALL_STREAMS,
		};
		Ok(Self {
			callers,
			voucher,
			routes: Arc::new(routes),
			grants: Arc::new(grants),
			limits,
			replay_window: DEFAULT_REPLAY_WINDOW,
			#[cfg(feature = "instrument")]
			trace: None,
		})
	}

	/// Record each admission, refusal, and answer of the coupler on `trace`.
	///
	/// The gateway binds its edge through `EncryptedProtocol::bind_with`,
	/// which carries no trace, so the profile that provisions the coupler
	/// attaches it.
	#[cfg(feature = "instrument")]
	#[must_use]
	pub fn with_trace(mut self, trace: TraceCollector) -> Self {
		self.trace = Some(trace);
		self
	}

	/// Hold each claim for `window` around the clock of the edge, in place of
	/// 60 seconds. The window refuses a stale claim and a spent one.
	#[must_use]
	pub fn with_replay_window(mut self, window: Duration) -> Self {
		self.replay_window = window;
		self
	}

	/// Give each call at most `timeout`, whatever `grpc-timeout` it asks for,
	/// hold at most `lanes` coupled connections, and carry at most `streams`
	/// calls on each one.
	#[must_use]
	pub fn with_call_limits(mut self, timeout: Duration, lanes: NonZeroUsize, streams: NonZeroU32) -> Self {
		self.limits = CallLimits { timeout, lanes, streams };
		self
	}

	/// The HTTP/2 streams that a connection of the edge admits at once.
	pub(crate) fn stream_limit(&self) -> u32 {
		self.limits.streams.get()
	}

	/// The trace of the coupler, which the listener of a coupled edge also
	/// records the refusals of its tunnel on.
	#[cfg(feature = "instrument")]
	pub(crate) fn trace(&self) -> Option<&TraceCollector> {
		self.trace.as_ref()
	}

	/// The trust of the coupler in its callers.
	pub(crate) fn callers(&self) -> &CallerTrust {
		&self.callers
	}
}

/// A clone shares the trace of the original, and starts no live coupler.
impl Clone for Coupler {
	fn clone(&self) -> Self {
		Self {
			callers: self.callers.clone(),
			voucher: self.voucher.clone(),
			routes: Arc::clone(&self.routes),
			grants: Arc::clone(&self.grants),
			limits: self.limits,
			replay_window: self.replay_window,
			#[cfg(feature = "instrument")]
			trace: self.trace.as_ref().map(TraceCollector::share),
		}
	}
}

impl fmt::Debug for Coupler {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Coupler").finish_non_exhaustive()
	}
}

/// The coupler of one bound listener: its configuration, its replay window,
/// its loopback session, and the permits of its coupled connections.
pub(crate) struct LiveCoupler<P: HandshakeProvider + Send + Sync + 'static> {
	config: Coupler,
	replay: ReplayGuard,
	session: LoopbackSession<P>,
	lanes: Arc<Semaphore>,
	ceiling: usize,
	requests: AtomicU64,
}

impl<P: HandshakeProvider + Send + Sync + 'static> LiveCoupler<P> {
	/// Start the coupler of the listener of profile `C` bound at `local`,
	/// which queues its loopback tunnel on `queue`, presents `gateway`, and
	/// holds every message to `ceiling`.
	///
	/// # Errors
	///
	/// - The errors of `LoopbackSession::start`.
	pub(crate) fn start<C: EdgeProfile>(
		config: Coupler,
		queue: Sender<Arrival>,
		local: SocketAddr,
		gateway: &Certificate,
		ceiling: usize,
	) -> Result<Self, EdgeError> {
		let handshake = config.voucher.handshake().clone();
		let streams = config.stream_limit();
		let session = LoopbackSession::start::<C>(queue, local, gateway, handshake, streams)?;
		let replay = ReplayGuard::new(config.replay_window);
		let lanes = Arc::new(Semaphore::new(config.limits.lanes.get()));
		Ok(Self { config, replay, session, lanes, ceiling, requests: AtomicU64::new(0) })
	}

	/// The permits of the coupled connections of the edge.
	pub(crate) fn lanes(&self) -> Arc<Semaphore> {
		Arc::clone(&self.lanes)
	}

	/// Whether the loopback session carries calls.
	pub(crate) fn health(&self) -> bool {
		self.session.health()
	}

	/// The envelope ceiling of the edge, which each coupled body decodes
	/// under.
	pub(crate) fn ceiling(&self) -> usize {
		self.ceiling
	}

	/// Step 1: parse the head of a coupled call: its caller, which the TLS
	/// handshake of its connection proved, then its route, its grant, its
	/// deadline, and its claim. A call with no caller refuses before its
	/// method is looked up, so an unauthenticated peer learns no route, and a
	/// call that no grant names refuses before it takes a lane.
	///
	/// # Errors
	///
	/// - [`CallFault::Unauthenticated`] -- the connection carries no caller.
	/// - [`CallFault::Unrouted`] -- the edge routes no such method.
	/// - [`CallFault::Denied`] -- no grant names the principal for the method.
	/// - [`CallFault::Timeout`] -- the `grpc-timeout` does not parse.
	/// - [`CallFault::ClaimRefused`] -- the claim does not decode.
	pub(crate) fn head(&self, head: &Parts) -> Result<CoupledHead, CallFault> {
		let connection = head.extensions.get::<GrpcConnectInfo>().ok_or(CallFault::Unauthenticated)?;
		let caller = connection.caller.clone().ok_or(CallFault::Unauthenticated)?;

		let method = head.uri.path();
		let route = self.config.routes.route(method).ok_or(CallFault::Unrouted)?.clone();
		if !self.config.grants.permits(caller.principal(), method) {
			return Err(CallFault::Denied);
		}

		let asked = head.headers.get("grpc-timeout").map(Self::timeout_of).transpose()?;
		let deadline = asked.map_or(self.config.limits.timeout, |asked| asked.min(self.config.limits.timeout));
		let expires = Instant::now() + deadline;
		let claim = CallClaim::of_head(&head.headers)?;

		Ok(CoupledHead { caller, method: method.to_owned(), route, expires, claim })
	}

	/// The duration of a `grpc-timeout` value: one to eight ASCII digits and
	/// one unit of `H`, `M`, `S`, `m`, `u`, or `n`.
	fn timeout_of(value: &HeaderValue) -> Result<Duration, CallFault> {
		let text = value.to_str().map_err(|_| CallFault::Timeout)?;
		let split = text.len().checked_sub(1).ok_or(CallFault::Timeout)?;
		let (digits, unit) = text.split_at(split);

		let digit_count = (1..=8).contains(&digits.len()) && digits.bytes().all(|byte| byte.is_ascii_digit());
		if !digit_count {
			return Err(CallFault::Timeout);
		}

		let amount: u64 = digits.parse().map_err(|_| CallFault::Timeout)?;
		match unit {
			"H" => Ok(Duration::from_secs(amount * 3600)),
			"M" => Ok(Duration::from_secs(amount * 60)),
			"S" => Ok(Duration::from_secs(amount)),
			"m" => Ok(Duration::from_millis(amount)),
			"u" => Ok(Duration::from_micros(amount)),
			"n" => Ok(Duration::from_nanos(amount)),
			_ => Err(CallFault::Timeout),
		}
	}

	/// Steps 3 to 9 of the call that `opened` holds, with its decoded request
	/// `body`, and the record of its outcome.
	pub(crate) async fn serve(&self, opened: Opened, body: Vec<u8>) -> Result<VerifiedAnswer, CallFault> {
		let method = opened.head.method.clone();
		let served = self.carry(opened, body).await;
		match &served {
			Ok(answer) => self.record_answer(&method, answer.code),
			Err(fault) => self.record_refusal(*fault),
		}

		served
	}

	/// Steps 3 to 9.
	async fn carry(&self, opened: Opened, body: Vec<u8>) -> Result<VerifiedAnswer, CallFault> {
		let presented = opened.present(body, self.config.callers.claims())?;
		let permitted = presented.permit()?;
		self.record_admission(&permitted);

		let request_id = self.next_request_id();
		let vouched = self.config.voucher.vouch(permitted, request_id, self.ceiling).await?;
		let ready = self.session.ready().ok_or(CallFault::Unavailable)?;
		let held = ready.hold(vouched.opened.head.expires).await?;
		let spent = self.spend(vouched)?;

		let submitted = spent.send(held, &self.replay).await?;
		submitted.verify()
	}

	/// Step 8: spend the claim of the call in the replay window, which only
	/// this coupler holds, once the call holds the session.
	///
	/// # Errors
	///
	/// - [`CallFault::Replayed`] -- the window holds the claim, or the claim is stale.
	pub(crate) fn spend(&self, vouched: VouchedWork) -> Result<Spent, CallFault> {
		if let Some(claim) = &vouched.claim {
			let now = UnixMillis::now();
			let admitted = self
				.replay
				.check_and_insert(claim.signer_key(), claim.signature(), claim.order(), now);
			if !admitted {
				return Err(CallFault::Replayed);
			}
		}

		Ok(Spent { vouched })
	}

	/// A fresh request id: the time in milliseconds and a counter.
	fn next_request_id(&self) -> [u8; 16] {
		let count = self.requests.fetch_add(1, Ordering::Relaxed);
		let mut id = [0_u8; 16];
		id[..8].copy_from_slice(&UnixMillis::now().get().to_be_bytes());
		id[8..].copy_from_slice(&count.to_be_bytes());
		id
	}

	#[cfg(feature = "instrument")]
	fn record_admission(&self, permitted: &Permitted) {
		if let Some(trace) = &self.config.trace {
			// The trace refuses an event only under the fault that the
			// `testing-fault` feature of tightbeam injects, and the call
			// carries on either way.
			let _ = trace.emit_event_with_value(
				COUPLED_CALL_ADMITTED,
				permitted.method().to_owned(),
				permitted.presented.assurance.as_str(),
			);
		}
	}

	#[cfg(not(feature = "instrument"))]
	fn record_admission(&self, _permitted: &Permitted) {}

	#[cfg(feature = "instrument")]
	fn record_refusal(&self, fault: CallFault) {
		if let Some(trace) = &self.config.trace {
			let _ = trace.emit_event_with_value(COUPLED_CALL_REFUSED, fault.as_str(), fault.as_str());
		}
	}

	#[cfg(not(feature = "instrument"))]
	fn record_refusal(&self, _fault: CallFault) {}

	#[cfg(feature = "instrument")]
	fn record_answer(&self, method: &str, code: Code) {
		if let Some(trace) = &self.config.trace {
			let _ = trace.emit_event_with_value(COUPLED_CALL_ANSWERED, method.to_owned(), code as i32 as u32);
		}
	}

	#[cfg(not(feature = "instrument"))]
	fn record_answer(&self, _method: &str, _code: Code) {}

	/// Record a refusal before the saga starts, such as one of step 1 or 2.
	pub(crate) fn refused(&self, fault: CallFault) -> Status {
		self.record_refusal(fault);
		fault.status()
	}
}

/// Step 1: the parsed head of a coupled call.
pub(crate) struct CoupledHead {
	caller: Arc<Caller>,
	method: String,
	route: Route<Servlet>,
	/// When the deadline of the call passes, counted from the arrival of its
	/// head.
	expires: Instant,
	claim: Option<CallClaim>,
}

impl CoupledHead {
	/// When the deadline of the call passes, which bounds every later step.
	pub(crate) fn expires(&self) -> Instant {
		self.expires
	}

	/// Step 2: the head with the coupled slot of its lane.
	pub(crate) fn opened(self, slot: CoupledSlot) -> Opened {
		Opened { head: self, slot }
	}
}

/// Step 2: a call that holds its coupled slot.
pub(crate) struct Opened {
	head: CoupledHead,
	slot: CoupledSlot,
}

impl Opened {
	/// Step 3: what the call proves. A call with no claim is vouched, and a
	/// call with a claim is signed when the claim verifies, and refused when
	/// it does not.
	///
	/// # Errors
	///
	/// - [`CallFault::ClaimRefused`] -- the claim does not verify.
	fn present(
		mut self,
		body: Vec<u8>,
		claims: &dyn tightbeam::crypto::x509::store::CertificateTrust,
	) -> Result<Presented, CallFault> {
		let claim = match self.head.claim.take() {
			None => None,
			Some(claim) => Some(claim.verify(&self.head.caller, &self.head.method, &body, claims)?),
		};
		let assurance = match claim {
			None => Assurance::Vouched,
			Some(_) => Assurance::Signed,
		};

		Ok(Presented { opened: self, body, claim, assurance })
	}
}

/// Step 3: a call and what it proves.
pub(crate) struct Presented {
	opened: Opened,
	body: Vec<u8>,
	claim: Option<VerifiedClaim>,
	assurance: Assurance,
}

impl Presented {
	/// Step 4: the call, when its route accepts what it proves.
	///
	/// # Errors
	///
	/// - [`CallFault::Denied`] -- the route requires more assurance.
	fn permit(self) -> Result<Permitted, CallFault> {
		if !self.opened.head.route.accepts(self.assurance) {
			return Err(CallFault::Denied);
		}

		Ok(Permitted { presented: self })
	}
}

/// Step 4: a call that its caller may make.
pub(crate) struct Permitted {
	presented: Presented,
}

impl Permitted {
	/// The principal of the caller.
	pub(crate) fn principal(&self) -> &Principal {
		self.presented.opened.head.caller.principal()
	}

	/// The method of the call.
	pub(crate) fn method(&self) -> &str {
		&self.presented.opened.head.method
	}

	/// The encoded request message of the call.
	pub(crate) fn body(&self) -> &[u8] {
		&self.presented.body
	}

	/// The servlet type that serves the call.
	pub(crate) fn servlet(&self) -> &Urn<'static> {
		self.presented.opened.head.route.target().urn()
	}

	/// The claim of the call, when it signed one.
	pub(crate) fn claim(&self) -> Option<&VerifiedClaim> {
		self.presented.claim.as_ref()
	}

	/// Step 5: the call with its work request `work` under `request_id`.
	pub(crate) fn vouched(self, work: Frame, request_id: [u8; 16]) -> VouchedWork {
		let Presented { opened, claim, .. } = self.presented;
		VouchedWork { opened, work, request_id, claim }
	}
}

/// Step 5: the work request of a call, signed under the voucher.
pub(crate) struct VouchedWork {
	opened: Opened,
	work: Frame,
	request_id: [u8; 16],
	claim: Option<VerifiedClaim>,
}

/// Step 8: a call whose claim is spent.
pub(crate) struct Spent {
	vouched: VouchedWork,
}

impl Spent {
	/// Step 9, the pivot: send the work on `held`, and resolve the reply of the
	/// gateway into the frame of the servlet. A send that fails before it
	/// leaves the session forgets the claim in `replay`, so the caller may
	/// retry it. A deadline that ends the send keeps the claim spent, because
	/// the frame may have left.
	///
	/// # Errors
	///
	/// - [`CallFault::Transit`] -- the gateway refused the work.
	/// - [`CallFault::Unavailable`] -- the session failed.
	/// - [`CallFault::Internal`] -- the reply does not decode.
	async fn send<P: HandshakeProvider + Send + Sync + 'static>(
		self,
		held: Held<P>,
		replay: &ReplayGuard,
	) -> Result<Submitted, CallFault> {
		let VouchedWork { opened, work, request_id, claim } = self.vouched;
		let reply = match held.send(work).await {
			Err(error) => {
				if Self::never_left(&error) {
					if let Some(claim) = &claim {
						replay.forget(claim.signature());
					}
				}

				return Err(CallFault::Unavailable);
			}
			Ok(reply) => reply,
		};

		let served = ClusterWorkResponse::served_reply(reply);
		let reply = served.map_err(|error| match error {
			TightBeamError::WorkRefused(status) => CallFault::Transit(status),
			_ => CallFault::Internal,
		})?;

		Ok(Submitted { opened, reply, request_id })
	}

	/// Whether a failed send never left the session, so the gateway never saw
	/// the work.
	fn never_left(error: &TransportError) -> bool {
		let refused = matches!(
			error,
			TransportError::OperationFailed(
				TransportFailure::StreamsExhausted
					| TransportFailure::BudgetExhausted
					| TransportFailure::ResourceExhausted
			)
		);
		refused || matches!(error, TransportError::Draining)
	}
}

/// Step 9: the frame that the servlet answered a call with.
pub(crate) struct Submitted {
	opened: Opened,
	reply: Frame,
	request_id: [u8; 16],
}

impl Submitted {
	/// Step 10: the answer of the servlet, once its frame answers the id of the
	/// request and its signature verifies under the signer of the route.
	///
	/// # Errors
	///
	/// - [`CallFault::AnswerRefused`] -- the id differs, the signature fails, or the answer does not decode.
	fn verify(self) -> Result<VerifiedAnswer, CallFault> {
		let Self { opened, reply, request_id } = self;
		if reply.metadata().id() != request_id.as_slice() {
			return Err(CallFault::AnswerRefused);
		}

		let signer = opened.head.route.target().answered_by();
		let verified = reply.verify_under(signer, &Secp256k1Policy::default());
		verified.map_err(|_| CallFault::AnswerRefused)?;

		let answer: CoupledReply = reply.decode_message().map_err(|_| CallFault::AnswerRefused)?;

		let code = Code::from_i32(answer.code);
		let body = answer.body.into_bytes();
		Ok(VerifiedAnswer { code, message: answer.message, body, _slot: opened.slot })
	}
}

/// Step 10: an answer that verified, which still holds the coupled slot of its
/// call until the response is written.
pub(crate) struct VerifiedAnswer {
	code: Code,
	message: Option<String>,
	body: Vec<u8>,
	_slot: CoupledSlot,
}

impl VerifiedAnswer {
	/// The response of the call: the body for `OK`, and the status of the
	/// servlet otherwise.
	pub(crate) fn into_response(self) -> Result<tonic::Response<Vec<u8>>, Status> {
		if self.code == Code::Ok {
			return Ok(tonic::Response::new(self.body));
		}

		let message = self.message.unwrap_or_default();
		Err(Status::new(self.code, message))
	}
}
