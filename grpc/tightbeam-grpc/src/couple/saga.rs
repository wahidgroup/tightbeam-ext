//! The saga of one coupled call, and the coupler that runs it.
//!
//! - Each act takes the proof of the act before it by value, so no act runs out of order.
//! - A claim is spent only once the call holds its session, which the spend takes.
//! - The send is the one act that stays done.
//! - From the spend on, each act holds the deadline of the call itself.
//! - The spend is undone when the send proves that its frame stayed in the
//!   session, when the ledger answers past the deadline, or when the clock
//!   gives the wait for the ledger no timer.

use core::fmt;
use core::future::Future;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use std::net::SocketAddr;
use std::sync::Arc;

use http::request::Parts;
use http::{HeaderMap, Method, Request as HttpRequest, Response as HttpResponse};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use tightbeam::clock::{Clock, UnixMillis};
use tightbeam::colony::work::ClusterWorkResponse;
use tightbeam::crypto::x509::Certificate;
use tightbeam::transport::handshake::HandshakeProvider;
use tightbeam::urn::Urn;
use tightbeam::{Frame, TightBeamError};
use tonic::body::Body;
use tonic::codec::Streaming;
use tonic::metadata::MetadataMap;
use tonic::{Code, Status};

use rustls::server::danger::ClientCertVerifier;

use super::claim::{CallClaim, Forgotten, ReplayGuard, SpentClaim, VerifiedClaim};
use super::error::CoupleError;
use super::fault::CallFault;
use super::ledger::{ClaimLedger, MemoryLedger};
use super::limits::{CallLimits, GrpcTimeout, MAX_SPAN};
use super::loopback::{Duplex, GatewayPin, Held, LoopbackSession, MuxSession, SendFailure};
use super::message::{CoupledCall, CoupledReply, OriginProof, StreamTerms, VouchedOrigin};
use super::metadata::{CallMetadata, MetadataKey};
use super::method::MethodPath;
use super::proof::Proof;
use super::reflection::{Reflection, Serve};
use super::routes::{AccessRefusal, Assurance, Granted, Grants, Policy, Route, Routes, Servlet, StreamShape};
use super::stream::{OpenStream, StreamRelay};
use super::trust::{CallerTrust, LiveCallers, ProvenCaller};
use super::voucher::{HeadPart, RequestId, Voucher, WorkRequest};
use super::web::{WebCall, WebOrigins};
use crate::deadline::{Deadline, WallClock};
use crate::edge::{EdgeError, EdgeProfile};
use crate::health::{WatchHold, WatchTerms};
use crate::incoming::{Arrivals, CoupledSlot, GrpcConnectInfo};
use crate::service::ReflectionVersion;
use crate::tunnel::EdgeAudit;

#[cfg(feature = "instrument")]
use crate::events::{
	COUPLED_CALL_ADMITTED, COUPLED_CALL_ANSWERED, COUPLED_CALL_OPENED, COUPLED_CALL_REFUSED, COUPLED_CLAIM_FORGOTTEN,
	COUPLED_CLAIM_SPENT, COUPLED_SESSION_OPENED,
};

/// The coupler of an edge, as a profile provisions it: whom it trusts, whom
/// it speaks as, what it routes, and to whom.
///
/// - The listener that binds a coupled edge starts one live coupler from it,
///   which holds the replay window and the loopback session, so each bind of
///   a clone of the configuration starts its own. A clone shares the claim
///   ledger of the original, the default `MemoryLedger` too.
///
/// # Examples
///
/// ```
/// use tightbeam::urn;
/// use tightbeam_grpc::couple::{
/// 	Assurance, CallerTrust, Coupler, Grants, Identities, Principal, Routes, Servlet, Voucher,
/// };
/// # use tightbeam_grpc::testing::TlsAuthority;
/// # use tightbeam_ws::testing::Identity;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let lifetime = core::time::Duration::from_secs(60);
/// # let tls = TlsAuthority::mint("CN=edge root", lifetime)?;
/// # let claims = Identity::mint("CN=claims", 1, lifetime)?;
/// # let (session, signer) = (Identity::mint("CN=session", 2, lifetime)?, Identity::mint("CN=coupler", 3, lifetime)?);
/// # let place_signer = Identity::mint("CN=place", 4, lifetime)?.certificate().clone();
///
/// let callers = CallerTrust::new([tls.root()], claims.trust_anchor()?)?;
/// let voucher = Voucher::new(Identities { handshake: session.signing_identity(), signer: signer.signing_identity() });
/// let place = Servlet::new(urn!("orders", "servlet:place"), place_signer)?;
/// let routes = Routes::new().unary("/orders.v1.Orders/Place", place, Assurance::Signed)?;
/// let grants = Grants::deny_all().grant(Principal::subject("CN=web,O=acme")?, "/orders.v1.Orders/Place")?;
/// let coupler = Coupler::new(callers, voucher, routes, grants)?;
/// # Ok(())
/// # }
/// ```
pub struct Coupler {
	callers: CallerTrust,
	voucher: Voucher,
	policy: Arc<Policy<Servlet>>,
	limits: CallLimits,
	replay_window: Duration,
	forwarded: Arc<[MetadataKey]>,
	web: Option<WebOrigins>,
	reflection: Option<Reflection>,
	ledger: Arc<dyn ClaimLedger>,
}

impl Coupler {
	/// The replay window of a claim, unless [`Coupler::with_replay_window`]
	/// sets one.
	pub const DEFAULT_REPLAY_WINDOW: Duration = Duration::from_secs(60);

	/// How often the loopback session of the edge reads its liveness, and how
	/// long a new session lives before the edge serves.
	pub const LIVENESS_PROBE: Duration = Duration::from_millis(200);

	/// How long the loopback session of the edge waits before it opens again,
	/// after a session that failed to open or ended.
	pub const SESSION_BACKOFF: Duration = Duration::from_millis(500);

	/// A coupler that trusts `callers`, speaks as `voucher`, routes `routes`,
	/// and permits `grants`.
	///
	/// # Errors
	///
	/// - [`CoupleError::NoRoute`] -- `routes` routes no method.
	/// - [`CoupleError::Method`] -- a grant names a method that no route serves.
	pub fn new(
		callers: CallerTrust,
		voucher: Voucher,
		routes: Routes<Servlet>,
		grants: Grants,
	) -> Result<Self, CoupleError> {
		let policy = Policy::new(routes, grants)?;

		Ok(Self {
			callers,
			voucher,
			policy: Arc::new(policy),
			limits: CallLimits::default(),
			replay_window: Self::DEFAULT_REPLAY_WINDOW,
			forwarded: Arc::from([]),
			web: None,
			reflection: None,
			ledger: Arc::new(MemoryLedger::new()),
		})
	}

	/// Forward every value of the request metadata under `keys`, such as
	/// `traceparent`, to the servlet of each call.
	///
	/// # Errors
	///
	/// - [`CoupleError::Metadata`] -- a key is not lowercase ASCII letters,
	///   digits, `-`, `_`, and `.`, names gRPC, a key that the edge stamps,
	///   HTTP/2, or a credential of the caller, or repeats.
	pub fn with_forwarded_metadata<K: AsRef<str>>(
		mut self,
		keys: impl IntoIterator<Item = K>,
	) -> Result<Self, CoupleError> {
		let mut forwarded: Vec<MetadataKey> = Vec::new();
		for key in keys {
			let key = MetadataKey::new(key.as_ref())?;
			if forwarded.contains(&key) {
				return Err(CoupleError::Metadata(key.as_str().to_owned()));
			}

			forwarded.push(key);
		}

		self.forwarded = Arc::from(forwarded);
		Ok(self)
	}

	/// Serve gRPC-Web to the pages of `origins`, each a scheme, a host, and a
	/// port when it is not the default, such as `https://shop.example`.
	///
	/// - Each origin reads as its RFC 6454 serialization: the scheme and the
	///   host in lowercase, and no default port.
	/// - The edge answers the CORS preflight of each origin, and refuses every other origin with 403.
	/// - A gRPC-Web call with no `origin`, from no page, is served.
	/// - A page presents no client certificate, so its calls usually prove a bearer token.
	///
	/// # Errors
	///
	/// - [`CoupleError::Origin`] -- an origin of `origins` that the variant
	///   describes.
	pub fn with_grpc_web<O: AsRef<str>>(mut self, origins: impl IntoIterator<Item = O>) -> Result<Self, CoupleError> {
		self.web = Some(WebOrigins::new(origins)?);
		Ok(self)
	}

	/// Serve server reflection of the routed methods from `descriptors`, an
	/// encoded `FileDescriptorSet`, to each caller that the edge identifies.
	///
	/// - Every unrouted service and method leaves the set, and every file that no routed service needs.
	///
	/// # Errors
	///
	/// - [`CoupleError::Reflection`] -- `descriptors` does not decode, or a descriptor does not resolve.
	pub fn with_reflection(mut self, descriptors: &[u8]) -> Result<Self, CoupleError> {
		self.reflection = Some(Reflection::new(descriptors, self.policy.methods())?);
		Ok(self)
	}

	/// Hold each claim for `window` around the clock of the edge, in place of
	/// [`Coupler::DEFAULT_REPLAY_WINDOW`]. The window refuses a stale claim and
	/// a spent one.
	///
	/// - A `window` past one day counts as one day.
	#[must_use]
	pub fn with_replay_window(mut self, window: Duration) -> Self {
		self.replay_window = window.min(MAX_SPAN);
		self
	}

	/// Spend each claim in `ledger`, in place of the `MemoryLedger` that this
	/// coupler and its clones share. Every replica of the edge that shares
	/// `ledger` spends a claim once between them.
	///
	/// - The ledger is a driver of [`ClaimLedger`] over any store the replicas share.
	/// - A spend that the ledger fails refuses the signed call with 14. A
	///   forget that it fails keeps the claim spent, and the call answers its
	///   own fault.
	#[must_use]
	pub fn with_claim_ledger(mut self, ledger: Arc<dyn ClaimLedger>) -> Self {
		self.ledger = ledger;
		self
	}

	/// Bound the calls of the edge by `limits`, in place of
	/// [`CallLimits::default`].
	///
	/// # Errors
	///
	/// - [`CoupleError::Streams`] -- the coupler routes a stream, and `limits` carry fewer than 2 streams.
	pub fn with_call_limits(mut self, limits: CallLimits) -> Result<Self, CoupleError> {
		if !self.policy.carries(&limits) {
			return Err(CoupleError::Streams);
		}

		self.limits = limits;
		Ok(self)
	}

	/// The coupler of a bind whose listener presents `gateway` and runs on
	/// `clock`: the pin of its loopback session, the verifier of its client
	/// chains, and its callers.
	///
	/// # Errors
	///
	/// - [`EdgeError::Trust`] -- tightbeam refuses `gateway` as a pin.
	/// - [`EdgeError::Verifier`] -- rustls refuses a CRL of the callers.
	pub(crate) fn prepare(&self, gateway: &Certificate, clock: &Arc<dyn Clock>) -> Result<PreparedCoupler, EdgeError> {
		let pin = GatewayPin::of(gateway)?;
		let verifier = self.callers.verifier()?;
		let callers = self.callers.live(WallClock::of(clock))?;
		Ok(PreparedCoupler { config: self.clone(), pin, verifier, callers, clock: Arc::clone(clock) })
	}
}

/// A clone shares the configuration of the original, and the bind of each
/// clone starts a live coupler of its own.
impl Clone for Coupler {
	fn clone(&self) -> Self {
		Self {
			callers: self.callers.clone(),
			voucher: self.voucher.clone(),
			policy: Arc::clone(&self.policy),
			limits: self.limits,
			replay_window: self.replay_window,
			forwarded: Arc::clone(&self.forwarded),
			web: self.web.clone(),
			reflection: self.reflection.clone(),
			ledger: Arc::clone(&self.ledger),
		}
	}
}

impl fmt::Debug for Coupler {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Coupler").finish_non_exhaustive()
	}
}

/// What a coupled bind builds before its socket binds: the configuration,
/// the pin of the loopback session, the verifier of the client chains, the
/// callers, and the clock of the edge.
pub(crate) struct PreparedCoupler {
	config: Coupler,
	pin: GatewayPin,
	verifier: Arc<dyn ClientCertVerifier>,
	callers: LiveCallers,
	clock: Arc<dyn Clock>,
}

impl PreparedCoupler {
	/// The verifier of the client chain of each connection, which admits a
	/// connection with no client chain.
	pub(crate) fn verifier(&self) -> Arc<dyn ClientCertVerifier> {
		Arc::clone(&self.verifier)
	}
}

/// The coupler of one bound listener: its configuration, its replay guard,
/// its loopback session, and the permits of its coupled connections.
pub(crate) struct LiveCoupler<P: HandshakeProvider + Send + Sync + 'static> {
	config: Coupler,
	/// Who the caller of each call is.
	callers: LiveCallers,
	guard: ReplayGuard,
	session: LoopbackSession<P>,
	lanes: Arc<Semaphore>,
	/// The permits of open streams, which [`CallLimits::relays`] counts.
	relays: Arc<Semaphore>,
	recorder: CallRecorder,
	ceiling: usize,
	requests: AtomicU64,
	/// The clock of the edge, which the deadline of each call and the call
	/// limit of each health watch run on.
	clock: Arc<dyn Clock>,
}

impl<P: HandshakeProvider + Send + Sync + 'static> LiveCoupler<P> {
	/// Start the coupler of `prepared` for the listener of profile `C` bound
	/// at `local`, which records on `recorder`, queues its loopback tunnel on
	/// `queue`, and holds every message to `ceiling`.
	pub(crate) fn start<C: EdgeProfile>(
		prepared: PreparedCoupler,
		recorder: CallRecorder,
		queue: Arrivals,
		local: SocketAddr,
		ceiling: usize,
	) -> Self {
		let PreparedCoupler { config, pin, callers, clock, .. } = prepared;
		let handshake = config.voucher.handshake().clone();
		let streams = config.limits.streams().get();
		let recorded = recorder.clone();
		let session = LoopbackSession::start::<C>(queue, local, pin, handshake, streams, recorded, Arc::clone(&clock));
		let ledger = Arc::clone(&config.ledger);
		let guard = ReplayGuard::new(ledger, config.replay_window, config.limits.timeout(), recorder.clone(), &clock);
		let lanes = Arc::new(Semaphore::new(config.limits.lanes().get()));

		// Open streams hold at most half the places of the loopback session, so
		// its unary calls keep the other half.
		let relays = config.limits.relays().map_or(0, core::num::NonZeroUsize::get);
		let relays = Arc::new(Semaphore::new(relays.min(MuxSession::STREAM_PLACES)));
		let requests = AtomicU64::new(0);

		Self {
			config,
			callers,
			guard,
			session,
			lanes,
			relays,
			recorder,
			ceiling,
			requests,
			clock,
		}
	}

	/// The permits of the coupled connections of the edge.
	pub(crate) fn lanes(&self) -> Arc<Semaphore> {
		Arc::clone(&self.lanes)
	}

	/// The HTTP/2 streams that a connection of the edge admits at once.
	pub(crate) fn streams(&self) -> core::num::NonZeroU32 {
		self.config.limits.streams()
	}

	/// Whether the loopback session carries calls.
	pub(crate) fn health(&self) -> bool {
		self.session.health()
	}

	/// What a call of `method` with `headers` is to the gRPC-Web arm of the
	/// edge: every call of an edge with no gRPC-Web is native.
	pub(crate) fn web_call(&self, method: &Method, headers: &HeaderMap) -> WebCall {
		let web = self.config.web.as_ref();
		web.map_or(WebCall::Native, |web| web.call_of(method, headers))
	}

	/// Serve `request` on a routed path, which calls the version `reflection`
	/// of server reflection when it is `Some`: server reflection where the
	/// edge serves it, and the coupled call of its route otherwise.
	pub(crate) async fn route(
		self: Arc<Self>,
		reflection: Option<ReflectionVersion>,
		request: HttpRequest<Body>,
	) -> HttpResponse<Body> {
		let served = self.config.reflection.as_ref();
		let reflected = served.zip(reflection).map(|(served, version)| served.of(version));
		match reflected {
			Some(serve) => self.reflect(serve, request).await,
			None => self.couple(request).await,
		}
	}

	/// Serve `request` through `serve`, a version of server reflection, to a
	/// caller that the edge identifies, or refuse it.
	async fn reflect(&self, serve: Serve, request: HttpRequest<Body>) -> HttpResponse<Body> {
		let connection = request.extensions().get::<GrpcConnectInfo>();
		let caller = connection.map(|connection| self.callers.caller_of(connection, request.headers()));
		match caller {
			Some(Ok(_)) => serve(request).await,
			_ => self.refused(CallFault::Unauthenticated).into_http(),
		}
	}

	/// Parse the head of `request` and open its call, then run the rest of
	/// its saga, unary or streamed, within its deadline.
	async fn couple(self: Arc<Self>, request: HttpRequest<Body>) -> HttpResponse<Body> {
		let (head, body) = request.into_parts();
		let opened = self.head(&head).and_then(CoupledHead::open);
		let opened = match opened {
			Ok(opened) => opened,
			Err(fault) => return self.refused(fault).into_http(),
		};

		self.recorder.opening(&opened.head().method);
		let request = HttpRequest::from_parts(head, body);
		opened.serve(self, request).await
	}

	/// The terms of a health watch on the connection of `head`.
	pub(crate) fn watch(&self, head: &Parts) -> WatchTerms {
		let hold = self.watch_hold(head);
		WatchTerms::changing(self.session.watch(), hold)
	}

	/// The hold of a watch on the connection of `head`: a caller that the
	/// edge identifies and that holds a grant takes a coupled slot for the
	/// call limit of the coupler.
	fn watch_hold(&self, head: &Parts) -> Option<WatchHold> {
		let connection = head.extensions.get::<GrpcConnectInfo>()?;
		let caller = self.callers.caller_of(connection, &head.headers).ok()?;
		if !self.config.policy.names(caller.principal()) {
			return None;
		}

		let slot = caller.open_coupled().ok()?;
		let until = Deadline::after(&self.clock, self.config.limits.deadline(None));
		Some(WatchHold::new(slot, until))
	}

	/// The envelope ceiling of the edge, which each coupled body decodes
	/// under.
	pub(crate) fn ceiling(&self) -> usize {
		self.ceiling
	}

	/// Parse the head of a coupled call into its connection, its caller, its
	/// grant, its deadline, and its claim. The TLS handshake of the connection
	/// proved the caller.
	///
	/// - A call with no caller refuses before its method is looked up, so an
	///   unauthenticated peer learns no route.
	/// - A call that no grant names refuses before it takes a lane.
	///
	/// # Errors
	///
	/// - [`CallFault::Unauthenticated`] -- the connection carries no caller.
	/// - [`CallFault::Access`] -- no route serves the method, or no grant names the principal for it.
	/// - [`CallFault::Timeout`] -- the `grpc-timeout` does not parse.
	/// - [`CallFault::ClaimRefused`] -- the claim does not decode.
	/// - [`CallFault::Metadata`] -- a forwarded metadata value does not decode.
	pub(crate) fn head(&self, head: &Parts) -> Result<CoupledHead, CallFault> {
		let connection = head.extensions.get::<GrpcConnectInfo>().ok_or(CallFault::Unauthenticated)?;
		let caller = self.callers.caller_of(connection, &head.headers)?;

		let method = MethodPath::try_from(head.uri.path()).map_err(|_| AccessRefusal::Unrouted)?;
		let granted = self.config.policy.grant(caller.principal(), &method)?;

		let asked = GrpcTimeout::of(&head.headers)?;
		let expires = Deadline::after(&self.clock, self.config.limits.deadline(asked));
		let map = MetadataMap::from_headers(head.headers.clone());
		let claim = CallClaim::of_head(&map)?;
		let metadata = CallMetadata::read(&self.config.forwarded, &map).map_err(|_| CallFault::Metadata)?;
		Ok(CoupledHead { caller, method, granted, expires, claim, metadata })
	}

	/// The end of `call` on the audit trail of the coupler.
	pub(crate) fn ending(&self, call: &OpenedCall) -> CallEnding {
		let method = call.head().method.clone();
		CallEnding(Arc::new(Ending {
			recorder: self.recorder.clone(),
			method,
			ended: AtomicBool::new(false),
			pivoted: AtomicBool::new(false),
		}))
	}

	/// The saga of the unary call that `opened` holds, with its decoded
	/// request `body`, which `ending` records the end of.
	pub(crate) async fn serve(
		&self,
		opened: Opened<Unary>,
		body: Vec<u8>,
		ending: &CallEnding,
	) -> Result<VerifiedAnswer, CallFault> {
		let served = self.carry(opened, body, ending).await;
		ending.end(served.as_ref().map(VerifiedAnswer::code).map_err(|fault| *fault));
		served
	}

	/// Prove the call, hold the session, vouch, spend, send, and verify the
	/// answer. The call holds the session before it vouches, so the deadline
	/// that it carries counts the wait. `ending` hands the deadline to the
	/// spend and then to the send.
	async fn carry(
		&self,
		opened: Opened<Unary>,
		body: Vec<u8>,
		ending: &CallEnding,
	) -> Result<VerifiedAnswer, CallFault> {
		let permitted = self.permit(opened, body)?;
		let ready = self.session.ready().ok_or(CallFault::Unavailable)?;
		let held = ready.hold(permitted.expires()).await?;
		let vouched = permitted
			.vouch(&self.config.voucher, self.next_request_id(), self.ceiling)
			.await?;

		let spent = vouched.spend(&self.guard, held, ending).await?;
		let submitted = spent.send().await?;
		submitted.verify()
	}

	/// The relay of the streaming call that `opened` holds, with the `requests`
	/// of its caller, which records its end through `ending`, or the refusal
	/// of the call.
	pub(crate) async fn open_stream(
		&self,
		opened: Opened<StreamShape>,
		requests: Streaming<Vec<u8>>,
		ending: CallEnding,
	) -> Result<StreamRelay, CallFault> {
		let open = match self.start_stream(opened, &ending).await {
			Ok(open) => open,
			Err(fault) => {
				ending.end(Err(fault));
				return Err(fault);
			}
		};

		let signer = self.config.voucher.signer().clone();
		Ok(StreamRelay::new(open, requests, signer, ending))
	}

	/// Prove a streaming call, take a relay permit, open its stream, vouch,
	/// spend, and push its head. A claim covers an empty body, and the head
	/// leaves last, after the claim is spent. `ending` hands the deadline to
	/// the spend and then to the push.
	async fn start_stream(&self, opened: Opened<StreamShape>, ending: &CallEnding) -> Result<OpenStream, CallFault> {
		let permitted = self.permit(opened, Vec::new())?;
		let permit = Arc::clone(&self.relays).try_acquire_owned().map_err(|_| CallFault::Streams)?;
		let ready = self.session.ready().ok_or(CallFault::Unavailable)?;
		let duplex = ready.open_stream(permitted.servlet().clone(), permitted.expires()).await?;
		let vouched = permitted
			.vouch_head(&self.config.voucher, self.next_request_id(), self.ceiling)
			.await?;

		let spent = vouched.spend(&self.guard, duplex, ending).await?;
		spent.open(permit).await
	}

	/// What the call proves, once its route accepts it, and the record of its
	/// admission.
	fn permit<K>(&self, opened: Opened<K>, body: Vec<u8>) -> Result<Permitted<K>, CallFault> {
		let presented = opened.present(body, &self.callers)?;
		let permitted = presented.permit()?;
		self.recorder.admission(&permitted.hold.method, permitted.proof.assurance());
		Ok(permitted)
	}

	/// A fresh request id: the time in milliseconds and a counter.
	fn next_request_id(&self) -> RequestId {
		let count = self.requests.fetch_add(1, Ordering::Relaxed);
		let mut id = [0_u8; 16];
		id[..8].copy_from_slice(&UnixMillis::now().get().to_be_bytes());
		id[8..].copy_from_slice(&count.to_be_bytes());
		RequestId::new(id)
	}

	/// Record a refusal before the saga starts, such as that of a head.
	pub(crate) fn refused(&self, fault: CallFault) -> Status {
		self.recorder.refusal(fault);
		fault.status()
	}
}

/// The audit trail of a coupler: each admission, refusal, and answer of its
/// calls, on the audit trail of its edge.
#[derive(Clone)]
pub(crate) struct CallRecorder {
	#[cfg(feature = "instrument")]
	audit: EdgeAudit,
}

impl CallRecorder {
	/// The audit trail of the coupler of the edge that `audit` records.
	pub(crate) fn new(audit: EdgeAudit) -> Self {
		#[cfg(not(feature = "instrument"))]
		let _ = audit;

		Self {
			#[cfg(feature = "instrument")]
			audit,
		}
	}

	/// Record that a head opened a call of `method` on its lane.
	#[cfg(feature = "instrument")]
	fn opening(&self, method: &MethodPath) {
		self.audit
			.record(COUPLED_CALL_OPENED, method.as_str().to_owned(), method.as_str().to_owned());
	}

	#[cfg(not(feature = "instrument"))]
	fn opening(&self, _method: &MethodPath) {}

	/// Record that the coupler admitted a call of `method` as `assurance`.
	#[cfg(feature = "instrument")]
	fn admission(&self, method: &MethodPath, assurance: Assurance) {
		self.audit
			.record(COUPLED_CALL_ADMITTED, method.as_str().to_owned(), assurance.as_str());
	}

	#[cfg(not(feature = "instrument"))]
	fn admission(&self, _method: &MethodPath, _assurance: Assurance) {}

	/// Record that the coupler refused a call for `fault`, under the name of
	/// the fault.
	#[cfg(feature = "instrument")]
	fn refusal(&self, fault: CallFault) {
		self.audit.record(COUPLED_CALL_REFUSED, fault.as_str(), fault.as_str());
	}

	#[cfg(not(feature = "instrument"))]
	fn refusal(&self, _fault: CallFault) {}

	/// Record the end of a call of `method`: the code of its answer, or the
	/// fault that refused it.
	fn end(&self, method: &MethodPath, end: Result<Code, CallFault>) {
		match end {
			Ok(code) => self.answer(method, code),
			Err(fault) => self.refusal(fault),
		}
	}

	#[cfg(feature = "instrument")]
	fn answer(&self, method: &MethodPath, code: Code) {
		self.audit
			.record(COUPLED_CALL_ANSWERED, method.as_str().to_owned(), code as i32 as u32);
	}

	#[cfg(not(feature = "instrument"))]
	fn answer(&self, _method: &MethodPath, _code: Code) {}

	/// Record that the ledger took the claim of a call.
	#[cfg(feature = "instrument")]
	pub(crate) fn spent(&self) {
		self.audit.record(COUPLED_CLAIM_SPENT, "spent", "spent");
	}

	#[cfg(not(feature = "instrument"))]
	pub(crate) fn spent(&self) {}

	/// Record that the coupler forgot the spend of a claim for `cause`.
	#[cfg(feature = "instrument")]
	pub(crate) fn forgot(&self, cause: Forgotten) {
		self.audit.record(COUPLED_CLAIM_FORGOTTEN, cause.as_str(), cause.as_str());
	}

	#[cfg(not(feature = "instrument"))]
	pub(crate) fn forgot(&self, _cause: Forgotten) {}

	/// Record that a loopback session of the coupler opened, after it read
	/// the deadline of its first probe.
	#[cfg(feature = "instrument")]
	pub(crate) fn session_opened(&self) {
		self.audit.record(COUPLED_SESSION_OPENED, "opened", "opened");
	}

	#[cfg(not(feature = "instrument"))]
	pub(crate) fn session_opened(&self) {}
}

/// The end of one coupled call on the audit trail, which the trail records
/// once, as the first of these gives it:
///
/// - The end that its saga gives, or the lapse of the deadline of its edge.
/// - The failure of the request body of a unary call, `cancelled` for a reset.
/// - The refusal of tonic that its response carries.
/// - `cancelled` once every holder drops it with no end.
#[derive(Clone)]
pub(crate) struct CallEnding(Arc<Ending>);

/// What a [`CallEnding`] records the end on, and whether the call reached the
/// spend of its claim, after which the spend and the pivot hold its deadline.
struct Ending {
	recorder: CallRecorder,
	method: MethodPath,
	ended: AtomicBool,
	pivoted: AtomicBool,
}

impl CallEnding {
	/// Record `end`, unless the call ended already.
	pub(crate) fn end(&self, end: Result<Code, CallFault>) {
		if !self.0.ended.swap(true, Ordering::AcqRel) {
			self.0.recorder.end(&self.0.method, end);
		}
	}

	/// The response of `served` within `expires`:
	///
	/// - A call whose bound lapses before the spend of its claim ends with the
	///   fault of the lapse, 4 once `expires` passed.
	/// - A call past that point ends as its spend and its pivot answer, under the deadline that they hold,
	///   so the spend is undone or kept before the call ends.
	pub(crate) async fn within<F>(&self, expires: &Deadline, served: F) -> HttpResponse<Body>
	where
		F: Future<Output = HttpResponse<Body>>,
	{
		let mut served = core::pin::pin!(served);
		let fault = match expires.bound(served.as_mut()).await {
			Ok(answered) => return answered,
			Err(lapse) => CallFault::from(lapse),
		};

		if self.0.pivoted.load(Ordering::Acquire) {
			return served.await;
		}

		self.end(Err(fault));
		fault.status().into_http()
	}

	/// Record the refusal of tonic that `response` carries in its head, unless
	/// the call ended already. tonic answers so when it refuses a request
	/// before the coupler reads it.
	pub(crate) fn settle(&self, response: &HttpResponse<Body>) {
		if let Some(status) = Status::from_header_map(response.headers()) {
			self.end(Err(CallFault::from(status)));
		}
	}

	/// Hand the deadline of the call to its spend and its pivot, before the
	/// ledger is asked.
	fn pivot(&self) {
		self.0.pivoted.store(true, Ordering::Release);
	}
}

/// A call that every holder dropped with no end, such as one that its caller
/// reset, ends as cancelled.
impl Drop for Ending {
	fn drop(&mut self) {
		if !*self.ended.get_mut() {
			self.recorder.end(&self.method, Err(CallFault::Cancelled));
		}
	}
}

/// The parsed head of a coupled call.
pub(crate) struct CoupledHead {
	caller: ProvenCaller,
	method: MethodPath,
	granted: Granted<Servlet>,
	/// When the deadline of the call passes, counted from the arrival of its
	/// head.
	expires: Deadline,
	claim: Option<CallClaim>,
	metadata: CallMetadata,
}

impl CoupledHead {
	/// The call that the head opens on the lane that proved its caller,
	/// unary or streamed as its route.
	///
	/// # Errors
	///
	/// - [`CallFault::Lane`] -- the lane carries no coupled call now, with the refusal of the lane.
	fn open(self) -> Result<OpenedCall, CallFault> {
		let slot = self.caller.open_coupled().map_err(CallFault::Lane)?;

		let opened = match self.granted.shape().streamed() {
			Some(shape) => OpenedCall::Stream(Opened { head: self, slot, kind: shape }),
			None => OpenedCall::Unary(Opened { head: self, slot, kind: Unary }),
		};
		Ok(opened)
	}
}

/// An open call of a unary route, or of a streaming one.
pub(crate) enum OpenedCall {
	Unary(Opened<Unary>),
	Stream(Opened<StreamShape>),
}

impl OpenedCall {
	/// When the deadline of the call passes.
	pub(crate) fn expires(&self) -> &Deadline {
		&self.head().expires
	}

	/// The parsed head of the call.
	fn head(&self) -> &CoupledHead {
		match self {
			Self::Unary(opened) => &opened.head,
			Self::Stream(opened) => &opened.head,
		}
	}
}

/// The carriage of a call of a unary route: one request, one answer, and one
/// send.
pub(crate) struct Unary;

/// A call that holds its coupled slot, which its route carries as `K`: a
/// [`Unary`] exchange, or a stream of its [`StreamShape`].
pub(crate) struct Opened<K> {
	head: CoupledHead,
	slot: CoupledSlot,
	kind: K,
}

impl<K> Opened<K> {
	/// What the call proves with its claim over `body`, among `callers`.
	///
	/// # Errors
	///
	/// - The errors of [`ProvenCaller::prove`].
	fn present(mut self, body: Vec<u8>, callers: &LiveCallers) -> Result<Presented<K>, CallFault> {
		let claim = self.head.claim.take();
		let proof = self.head.caller.prove(claim, &self.head.method, &body, callers)?;
		Ok(Presented { opened: self, body, proof })
	}
}

/// A call and what it proves.
struct Presented<K> {
	opened: Opened<K>,
	body: Vec<u8>,
	proof: Proof<VerifiedClaim>,
}

impl<K> Presented<K> {
	/// The call, when its route accepts what it proves.
	///
	/// # Errors
	///
	/// - [`CallFault::Access`] -- the route requires more assurance.
	fn permit(self) -> Result<Permitted<K>, CallFault> {
		let Self { opened, body, proof } = self;
		let Opened { head, slot, kind } = opened;
		let CoupledHead { caller, method, granted, expires, metadata, .. } = head;
		let route = granted.accept(proof.assurance())?;

		let hold = CallHold { method, route, expires, _slot: slot };
		Ok(Permitted { hold, caller, metadata, body, proof, kind })
	}
}

/// What one call holds from its permit to its end: its method, its route,
/// its deadline, and its coupled slot.
pub(crate) struct CallHold {
	method: MethodPath,
	route: Route<Servlet>,
	expires: Deadline,
	_slot: CoupledSlot,
}

impl CallHold {
	/// When the deadline of the call passes.
	pub(crate) fn expires(&self) -> &Deadline {
		&self.expires
	}

	/// The servlet of the call, whose pinned signer signs each answer.
	pub(crate) fn servlet(&self) -> &Servlet {
		self.route.target()
	}
}

/// A call that its caller may make, which its route carries as `K`.
pub(crate) struct Permitted<K> {
	hold: CallHold,
	caller: ProvenCaller,
	metadata: CallMetadata,
	body: Vec<u8>,
	proof: Proof<VerifiedClaim>,
	kind: K,
}

impl<K> Permitted<K> {
	/// The servlet type that serves the call.
	fn servlet(&self) -> &Urn<'static> {
		self.hold.servlet().urn()
	}

	/// When the deadline of the call passes.
	fn expires(&self) -> &Deadline {
		&self.hold.expires
	}

	/// `call` as the voucher signs it for the caller: with the origin that
	/// its proof makes, what remains of its deadline, and the metadata that
	/// it forwards.
	///
	/// # Errors
	///
	/// - [`CallFault::Internal`] -- the call does not encode.
	fn vouched(&self, call: CoupledCall) -> Result<CoupledCall, CallFault> {
		let proof = OriginProof::try_from(&self.proof)?;
		let origin = VouchedOrigin { principal: self.caller.principal().named().into(), proof };
		let call = match self.hold.expires.left() {
			Some(left) => call.with_timeout(left),
			None => call,
		};
		call.vouched_for(origin, &self.metadata).map_err(|_| CallFault::Internal)
	}
}

impl Permitted<Unary> {
	/// The work request of the servlet of the call, which carries the call
	/// that `voucher` signs under `id`, within `ceiling`.
	///
	/// # Errors
	///
	/// - [`CallFault::Internal`] -- the call does not encode.
	/// - The errors of [`Voucher::sign`] and of [`Signed::into_work`](super::voucher::Signed::into_work).
	async fn vouch(
		mut self,
		voucher: &Voucher,
		id: RequestId,
		ceiling: usize,
	) -> Result<Vouched<WorkRequest>, CallFault> {
		let body = core::mem::take(&mut self.body);
		let call = CoupledCall::direct(self.hold.method.clone(), body).map_err(|_| CallFault::Internal)?;
		let signed = voucher.sign(self.vouched(call)?, id).await?;
		let work = signed.into_work(self.servlet(), ceiling)?;

		Ok(Vouched { hold: self.hold, work, proof: self.proof })
	}
}

impl Permitted<StreamShape> {
	/// The head of the stream: the call with an empty body and the terms of
	/// its shape, which `voucher` signs under `id`, as a part within
	/// `ceiling`, which the terms declare.
	///
	/// # Errors
	///
	/// - [`CallFault::Internal`] -- the head does not encode.
	/// - The errors of [`Voucher::sign`] and of [`Signed::into_head`](super::voucher::Signed::into_head).
	async fn vouch_head(
		self,
		voucher: &Voucher,
		id: RequestId,
		ceiling: usize,
	) -> Result<Vouched<HeadPart>, CallFault> {
		let declared = u64::try_from(ceiling).map_err(|_| CallFault::Internal)?;
		let terms = StreamTerms::new(self.kind, declared);
		let call = CoupledCall::head(&self.hold.method, terms).map_err(|_| CallFault::Internal)?;
		let signed = voucher.sign(self.vouched(call)?, id).await?;
		let head = signed.into_head(terms)?;

		Ok(Vouched { hold: self.hold, work: head, proof: self.proof })
	}
}

/// A call, what the voucher signed for it, and what it proves.
struct Vouched<W> {
	hold: CallHold,
	work: W,
	proof: Proof<VerifiedClaim>,
}

/// A session that a pivot sends on, and the work that it carries.
trait Pivot {
	/// The work that the pivot sends on the session.
	type Work;
}

/// The held session of a unary send carries its work request.
impl<P: HandshakeProvider + Send + Sync + 'static> Pivot for Held<P> {
	type Work = WorkRequest;
}

/// The duplex stream that the head of a stream opens carries the head.
impl Pivot for Duplex {
	type Work = HeadPart;
}

impl<W> Vouched<W> {
	/// Spend the claim of the call under `guard`, once the call holds
	/// `session`: the held session of a unary send, or the duplex stream that
	/// the head of a stream opens. `ending` hands the deadline of the call to
	/// the spend and then to the pivot, before the ledger is asked.
	///
	/// # Errors
	///
	/// - The errors of [`Proof::spend`].
	async fn spend<S: Pivot<Work = W>>(
		self,
		guard: &ReplayGuard,
		session: S,
		ending: &CallEnding,
	) -> Result<Spent<W, S>, CallFault> {
		ending.pivot();
		let spent = self.proof.spend(guard, &self.hold.expires).await?;
		Ok(Spent { hold: self.hold, work: self.work, spent, session })
	}
}

/// A call, the spend of its claim, which the pivot can undo, and the session
/// `S` that the pivot sends on.
struct Spent<W, S> {
	hold: CallHold,
	work: W,
	spent: Option<SpentClaim>,
	session: S,
}

impl<W, S> Spent<W, S> {
	/// Undo `spent` for `failure`, the send that failed, which forgets the
	/// claim when its frame stayed in the session, and give the fault that
	/// answers the call.
	async fn unwind(spent: Option<SpentClaim>, failure: SendFailure) -> CallFault {
		if let Some(spent) = spent {
			spent.release(&failure).await;
		}

		failure.fault()
	}
}

impl<P: HandshakeProvider + Send + Sync + 'static> Spent<WorkRequest, Held<P>> {
	/// The pivot: send the work on the held session within the deadline of
	/// the call, and resolve the reply of the gateway into the frame of the
	/// servlet. A send that fails unwinds the spend.
	///
	/// # Errors
	///
	/// - [`CallFault::Transit`] -- the gateway refused the work.
	/// - [`CallFault::Unavailable`] -- the session failed.
	/// - [`CallFault::Deadline`] -- no stream came free, or no reply came, within the deadline, or the
	///   clock gave a wait of the send no timer.
	/// - [`CallFault::Stalled`] -- a wait of the send passed a read deadline of the session, as that fault
	///   states.
	/// - [`CallFault::Internal`] -- the reply does not decode.
	async fn send(self) -> Result<Submitted, CallFault> {
		let Self { hold, work, spent, session } = self;
		let reply = match session.send(work.frame(), &hold.expires).await {
			Ok(reply) => reply,
			Err(failure) => return Err(Self::unwind(spent, failure).await),
		};

		let served = ClusterWorkResponse::served_reply(reply);
		let reply = served.map_err(|error| match error {
			TightBeamError::WorkRefused(status) => CallFault::Transit(status),
			_ => CallFault::Internal,
		})?;

		Ok(Submitted { hold, reply, id: *work.id() })
	}
}

impl Spent<HeadPart, Duplex> {
	/// The pivot of a stream: push its head on the duplex stream within the
	/// deadline of the call, under the relay `permit`. A push that fails
	/// unwinds the spend.
	///
	/// # Errors
	///
	/// - [`CallFault::Unavailable`] -- the session failed.
	/// - [`CallFault::Deadline`] -- the push of the head passed the deadline, or the clock gave the push no
	///   timer.
	/// - [`CallFault::Stalled`] -- the push of the head passed a read deadline of the session, as that
	///   fault states.
	async fn open(self, permit: OwnedSemaphorePermit) -> Result<OpenStream, CallFault> {
		let Self { hold, work, spent, session } = self;
		match session.push_head(&work, hold.expires()).await {
			Ok(opened) => Ok(OpenStream::new(hold, &work, opened, permit)),
			Err(failure) => Err(Self::unwind(spent, failure).await),
		}
	}
}

/// The frame that the servlet answered a call with.
struct Submitted {
	hold: CallHold,
	reply: Frame,
	id: RequestId,
}

impl Submitted {
	/// The answer of the servlet, once its frame answers the id of the
	/// request and the servlet of the route verifies it.
	///
	/// # Errors
	///
	/// - [`CallFault::AnswerRefused`] -- the id differs, the signature fails, or the answer does not decode.
	fn verify(self) -> Result<VerifiedAnswer, CallFault> {
		let Self { hold, reply, id } = self;
		let answers = reply.metadata().id() == id.as_bytes().as_slice();
		if !answers || !hold.servlet().verifies(&reply) {
			return Err(CallFault::AnswerRefused);
		}

		let answer: CoupledReply = reply.decode_message().map_err(|_| CallFault::AnswerRefused)?;
		Ok(VerifiedAnswer { answer, _hold: hold })
	}
}

/// An answer that verified, which still holds the coupled slot of its call
/// until the response is written.
pub(crate) struct VerifiedAnswer {
	answer: CoupledReply,
	_hold: CallHold,
}

impl VerifiedAnswer {
	/// The status code of the answer, which the audit trail records.
	pub(crate) fn code(&self) -> Code {
		self.answer.code()
	}

	/// The answer as the caller reads it.
	///
	/// # Errors
	///
	/// - The errors of [`CoupledReply::into_result`].
	pub(crate) fn into_result(self) -> Result<Vec<u8>, Status> {
		self.answer.into_result()
	}
}

#[cfg(test)]
mod tests {
	use core::pin::pin;
	use core::task::{Context, Poll, Waker};

	use tightbeam::clock::SystemClock;

	use super::*;

	/// A call whose clock gives its bound no timer, as `SystemClock` does on
	/// a thread outside any tokio runtime, ends before its spend with 13.
	#[test]
	fn a_call_whose_clock_gives_no_timer_ends_with_internal() -> Result<(), CoupleError> {
		let method = MethodPath::try_from("/orders.v1.Orders/Get")?;
		let recorder = CallRecorder::new(EdgeAudit::default());
		let ended = AtomicBool::new(false);
		let ending = CallEnding(Arc::new(Ending { recorder, method, ended, pivoted: AtomicBool::new(false) }));
		let clock: Arc<dyn Clock> = Arc::new(SystemClock);
		let expires = Deadline::after(&clock, Duration::from_secs(60));

		let mut within = pin!(ending.within(&expires, core::future::pending()));
		let code = match within.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
			Poll::Ready(response) => Status::from_header_map(response.headers()).map(|status| status.code()),
			Poll::Pending => None,
		};
		assert_eq!(code, Some(Code::Internal), "a bound with no timer MUST end the call with 13");
		Ok(())
	}
}
