//! Tightbeam scenarios of the served plane and of links past their read
//! deadline, as `docs/ws.md` (Test support) states.

#![cfg(feature = "testing")]

pub mod support;

use core::future::pending;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tightbeam::clock::ManualClock;
use tightbeam::constants::KEEPALIVE_PROBES_PER_DEADLINE;
use tightbeam::instrumentation::events;
use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::error::TestingError;
use tightbeam::testing::{ClientEnv, FaultModel, ScenarioConfig, SetupEnv, TestFrame};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::{MuxBudgets, MuxSettings};
use tightbeam::transport::multiplex::{
	CallContext, MuxAcceptor, MuxHandle, MuxRole, MuxService, ReplySink, SpawnedMux, StreamBody,
};
use tightbeam::transport::policy::CollectorGateConfig;
use tightbeam::transport::{
	ClientBuilder, EncryptedMessageIO, EncryptedProtocol, EndpointConfig, TransportError, TransportLimits,
};
use tightbeam::urn::Urn;
use tightbeam::{bps, exactly, tb_assert_spec, tb_process_spec, tb_scenario, urn, Frame, TightBeamError};
use tightbeam_ws::io::WsTransport;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::serve::{AcceptedLink, LinkError, KEEPALIVE_ANSWERED};
use tightbeam_ws::testing::{DemoPaywall, DemoSettlement, EchoService, EventWatch, Identity, Security};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_tungstenite::MaybeTlsStream;

use support::{bounded, Answers};

/// Whether the served plane answered each stream kind as upstream did.
const MATCHES_UPSTREAM: Urn<'static> = urn!("test", "event:served-mux/matches-upstream");

/// Whether an emit after a renewal echoed its frame.
const SERVES_AFTER_RENEWAL: Urn<'static> = urn!("test", "event:served-mux/serves-after-renewal");

/// Whether a cleartext link refused an encrypted transport as encrypted.
const REFUSED_AS_ENCRYPTED: Urn<'static> = urn!("test", "event:served-mux/refused-as-encrypted");

/// Whether an emit after a silence past the read deadline echoed its frame.
const SERVES_AFTER_SILENCE: Urn<'static> = urn!("test", "event:served-mux/serves-after-silence");

/// Whether the probe after a silence past the read deadline found the link
/// closed.
const CLOSED_AFTER_SILENCE: Urn<'static> = urn!("test", "event:served-mux/closed-after-silence");

/// The transport an accepted WebSocket connection follows.
type ServerTransport = WsTransport<MaybeTlsStream<TcpStream>>;

/// The server of a scenario, and the socket address it bound.
type Served = Result<(JoinHandle<Result<(), TightBeamError>>, TightBeamSocketAddr), TightBeamError>;

/// The stream cap that both ends of a differential case offer.
const STREAMS: u32 = 4;

/// How long each identity stays valid.
const VALIDITY: Duration = Duration::from_secs(3600);

/// An outcome that the case did not expect.
fn unexpected(what: &'static str) -> TightBeamError {
	TightBeamError::TestingError(TestingError::UnexpectedOutcome(what))
}

/// A gate that answers one fixed verdict.
struct Verdict(TransitStatus);

impl GatePolicy for Verdict {
	fn evaluate(&self, _message: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		self.0
	}
}

/// A service whose every handler fails with an error of its own: one that
/// carries a transit status, or one that carries none.
#[derive(Clone, Copy)]
enum Failing {
	Carried(TransitStatus),
	Bare,
}

impl Failing {
	fn failure(self) -> TightBeamError {
		match self {
			Self::Carried(status) => TightBeamError::TransportError(TransportError::from(status)),
			Self::Bare => TightBeamError::InvalidBody,
		}
	}
}

impl MuxService for Failing {
	async fn unary(&self, _frame: Frame, _cx: CallContext) -> Result<Option<Frame>, TightBeamError> {
		Err(self.failure())
	}

	async fn streaming(&self, _body: StreamBody, _cx: CallContext) -> Result<Option<Frame>, TightBeamError> {
		Err(self.failure())
	}

	async fn duplex(&self, _body: StreamBody, _reply: ReplySink, _cx: CallContext) -> Result<(), TightBeamError> {
		Err(self.failure())
	}
}

/// A service that leaves every kind to the defaults of the trait.
#[derive(Clone, Copy)]
struct Unserved;

impl MuxService for Unserved {}

/// The serve a server runs over its accepted transport.
#[derive(Clone, Copy)]
enum Plane {
	/// Upstream [`MuxAcceptor::serve`].
	Upstream,
	/// [`ServedMux::serve`](tightbeam_ws::serve::ServedMux::serve).
	Served,
}

impl Plane {
	/// Serve `transport`, which negotiated `settings`, with `service` until it
	/// ends.
	async fn serve<S: MuxService>(
		self,
		transport: ServerTransport,
		settings: MuxSettings,
		service: S,
	) -> Result<(), TightBeamError> {
		match self {
			Self::Upstream => transport.serve(settings, service, None).await?,
			Self::Served => {
				let link = AcceptedLink::accepted(transport).map_err(io::Error::other)?;
				link.spawn().serve(service, pending()).await?;
			}
		}

		Ok(())
	}
}

/// One dialed client mux: the handle a case emits on, and the tasks it holds.
struct Client(SpawnedMux);

impl Client {
	/// Dial `addr` under `security`, pinning `server`, with the mux offer of
	/// `streams` streams, on a transport that records on `trace`. A paywalled
	/// kind pays its invoice up to `payments` times.
	async fn dial(
		addr: TightBeamSocketAddr,
		server: &Identity,
		security: &Security,
		(streams, payments): (u32, usize),
		trace: &TraceCollector,
	) -> Result<Self, TightBeamError> {
		let trust = server.trust_anchor()?;
		let builder = security.client_builder::<WsListener>(trust);

		let dialed = builder.connect(addr).await?;
		let traced = dialed.into_transport().with_trace(trace.share());
		let mut transport = security.meter_dial(traced, streams, payments);
		transport.perform_client_handshake().await?;

		let mux = transport.into_mux(MuxRole::Client)?;
		Ok(Self(mux.spawn()))
	}

	fn handle(&self) -> &MuxHandle {
		&self.0.handle
	}
}

/// The identity of a server or a client.
fn identity(subject: &str, serial: u32) -> Identity {
	let issued = Identity::mint(subject, serial, VALIDITY);
	issued.expect("the identity issues")
}

/// A listener of `security` on loopback that presents `server`.
async fn listen(server: &Identity, security: &Security) -> Result<(WsListener, TightBeamSocketAddr), TightBeamError> {
	let config = security.server_config(server)?;
	let loopback = TightBeamSocketAddr("127.0.0.1:0".parse()?);

	let bound = <WsListener as EncryptedProtocol>::bind_with(loopback, config).await?;
	Ok(bound)
}

/// Accept one dial on `listener` under `security` on a transport that
/// records on `trace`, install `gate`, and serve it on `plane` until it ends.
async fn serve_one<S: MuxService>(
	listener: WsListener,
	security: Arc<Security>,
	streams: u32,
	(gate, service): (impl GatePolicy + 'static, S),
	(plane, trace): (Plane, TraceCollector),
) -> Result<(), TightBeamError> {
	let (transport, _peer) = listener.accept().await?;
	let metered = security.meter(transport.with_trace(trace), streams);
	let mut gated = metered.with_collector_gate(gate);
	let negotiated = gated.negotiate_mux().await?;
	let settings = negotiated.ok_or_else(|| unexpected("the peer negotiated no multiplexing"))?;

	plane.serve(gated, settings, service).await
}

/// What a client observes of each stream kind on a server of `plane` whose
/// gate answers `verdict`, with both ends recording on `trace`.
async fn answers_on<S: MuxService>(
	plane: Plane,
	(verdict, service): (TransitStatus, S),
	trace: &TraceCollector,
) -> Result<Answers, TightBeamError> {
	let server = identity("CN=differential server,O=tightbeam-ws,C=US", 1);
	let security = Arc::new(Security::ServerAuth);
	let (listener, addr) = listen(&server, &security).await?;
	let serve = serve_one(
		listener,
		Arc::clone(&security),
		STREAMS,
		(Verdict(verdict), service),
		(plane, trace.share()),
	);

	let serving = tokio::spawn(serve);
	let client = Client::dial(addr, &server, &security, (STREAMS, 1), trace).await?;
	let answers = Answers::of(client.handle()).await;
	serving.abort();

	answers
}

/// Record on `trace` whether a served mux answers every stream kind under
/// `verdict` as upstream `MuxAcceptor::serve` answers it.
async fn differential(verdict: TransitStatus, trace: &TraceCollector) -> Result<(), TightBeamError> {
	let upstream = answers_on(Plane::Upstream, (verdict, EchoService), trace).await?;
	let served = answers_on(Plane::Served, (verdict, EchoService), trace).await?;

	trace.event_with(MATCHES_UPSTREAM, &[], served == upstream)?;
	Ok(())
}

/// One differential scenario per gate verdict, and the spec that grades it:
/// the served plane answers each stream kind as upstream does, and both
/// planes record the verdict of the gate for each of their three streams,
/// with the status that the call answers.
///
/// - `admits` grades a gate that admits every call.
/// - `refuses (status)` grades a gate whose calls answer `status`, which is
///   `Internal` for a gate that answers `Unknown`.
macro_rules! differential {
	($($name:ident: $verdict:expr => $spec:ident, $kind:ident $(($answered:expr))?;)*) => {
		$(
			differential!(@spec $spec, $kind $(($answered))?);

			tb_scenario! {
				name: $name,
				spec: $spec,
				environment Bare {
					exec: |SetupEnv { trace, .. }| async move { differential($verdict, &trace).await }
				}
			}
		)*
	};
	(@spec $spec:ident, admits) => {
		tb_assert_spec! {
			pub $spec,
			V(1,0,0): {
				mode: Accept,
				assertions: [
					(MATCHES_UPSTREAM, exactly!(1), equals!(true)),
					(events::GATE_ACCEPT, exactly!(6), equals!(TransitStatus::Ok)),
					(events::GATE_REJECT, exactly!(0))
				]
			}
		}
	};
	(@spec $spec:ident, refuses ($answered:expr)) => {
		tb_assert_spec! {
			pub $spec,
			V(1,0,0): {
				mode: Accept,
				assertions: [
					(MATCHES_UPSTREAM, exactly!(1), equals!(true)),
					(events::GATE_ACCEPT, exactly!(0)),
					(events::GATE_REJECT, exactly!(6), equals!($answered))
				]
			}
		}
	};
}

// Every gate verdict, `Unknown` included, answers each stream kind on a served
// mux as it answers on upstream `MuxAcceptor::serve`, and both planes audit it
// alike.
differential! {
	served_mux_answers_ok_as_upstream_serve: TransitStatus::Ok => OkVerdictSpec, admits;
	served_mux_answers_cancelled_as_upstream_serve: TransitStatus::Cancelled => CancelledVerdictSpec, refuses(TransitStatus::Cancelled);
	served_mux_answers_unknown_as_upstream_serve: TransitStatus::Unknown => UnknownVerdictSpec, refuses(TransitStatus::Internal);
	served_mux_answers_invalid_argument_as_upstream_serve: TransitStatus::InvalidArgument => InvalidArgumentVerdictSpec, refuses(TransitStatus::InvalidArgument);
	served_mux_answers_deadline_exceeded_as_upstream_serve: TransitStatus::DeadlineExceeded => DeadlineExceededVerdictSpec, refuses(TransitStatus::DeadlineExceeded);
	served_mux_answers_not_found_as_upstream_serve: TransitStatus::NotFound => NotFoundVerdictSpec, refuses(TransitStatus::NotFound);
	served_mux_answers_already_exists_as_upstream_serve: TransitStatus::AlreadyExists => AlreadyExistsVerdictSpec, refuses(TransitStatus::AlreadyExists);
	served_mux_answers_permission_denied_as_upstream_serve: TransitStatus::PermissionDenied => PermissionDeniedVerdictSpec, refuses(TransitStatus::PermissionDenied);
	served_mux_answers_resource_exhausted_as_upstream_serve: TransitStatus::ResourceExhausted => ResourceExhaustedVerdictSpec, refuses(TransitStatus::ResourceExhausted);
	served_mux_answers_failed_precondition_as_upstream_serve: TransitStatus::FailedPrecondition => FailedPreconditionVerdictSpec, refuses(TransitStatus::FailedPrecondition);
	served_mux_answers_aborted_as_upstream_serve: TransitStatus::Aborted => AbortedVerdictSpec, refuses(TransitStatus::Aborted);
	served_mux_answers_out_of_range_as_upstream_serve: TransitStatus::OutOfRange => OutOfRangeVerdictSpec, refuses(TransitStatus::OutOfRange);
	served_mux_answers_unimplemented_as_upstream_serve: TransitStatus::Unimplemented => UnimplementedVerdictSpec, refuses(TransitStatus::Unimplemented);
	served_mux_answers_internal_as_upstream_serve: TransitStatus::Internal => InternalVerdictSpec, refuses(TransitStatus::Internal);
	served_mux_answers_unavailable_as_upstream_serve: TransitStatus::Unavailable => UnavailableVerdictSpec, refuses(TransitStatus::Unavailable);
	served_mux_answers_data_loss_as_upstream_serve: TransitStatus::DataLoss => DataLossVerdictSpec, refuses(TransitStatus::DataLoss);
	served_mux_answers_unauthenticated_as_upstream_serve: TransitStatus::Unauthenticated => UnauthenticatedVerdictSpec, refuses(TransitStatus::Unauthenticated);
}

/// Record on `trace` whether a served mux answers every stream kind of
/// `service`, behind a gate that admits each call, as upstream
/// `MuxAcceptor::serve` answers it.
async fn settles_as_upstream<S: MuxService + Copy>(service: S, trace: &TraceCollector) -> Result<(), TightBeamError> {
	let upstream = answers_on(Plane::Upstream, (TransitStatus::Ok, service), trace).await?;
	let served = answers_on(Plane::Served, (TransitStatus::Ok, service), trace).await?;

	trace.event_with(MATCHES_UPSTREAM, &[], served == upstream)?;
	Ok(())
}

/// One scenario per handler outcome, and the spec that grades it: the served
/// plane answers each stream kind as upstream does, and both planes record
/// the failure of each of their three handlers with the status it answers.
macro_rules! settled {
	($($name:ident: $service:expr => $spec:ident, $failed:expr, $refused:expr $(, ($answered:expr))?;)*) => {
		$(
			tb_assert_spec! {
				pub $spec,
				V(1,0,0): {
					mode: Accept,
					assertions: [
						(MATCHES_UPSTREAM, exactly!(1), equals!(true)),
						(events::GATE_ACCEPT, exactly!(6), equals!(TransitStatus::Ok)),
						(events::HANDLER_FAILED, exactly!($failed) $(, equals!($answered))?),
						(events::MUX_STREAM_REFUSED, exactly!($refused))
					]
				}
			}

			tb_scenario! {
				name: $name,
				spec: $spec,
				environment Bare {
					exec: |SetupEnv { trace, .. }| async move { settles_as_upstream($service, &trace).await }
				}
			}
		)*
	};
}

// A handler that fails with an error of its own answers the status of the
// failure on a served mux as on upstream `MuxAcceptor::serve`, and both planes
// record the failure. A kind that the service leaves out answers
// `Unimplemented` on both, as a refused stream and not a failure.
settled! {
	a_carried_status_answers_as_upstream: Failing::Carried(TransitStatus::PermissionDenied) => CarriedFailureSpec, 6, 0, (TransitStatus::PermissionDenied);
	a_carried_unavailable_answers_unknown_as_upstream: Failing::Carried(TransitStatus::Unavailable) => UnavailableFailureSpec, 6, 0, (TransitStatus::Unknown);
	a_failure_with_no_status_answers_internal_as_upstream: Failing::Bare => BareFailureSpec, 6, 0, (TransitStatus::Internal);
	an_unserved_kind_answers_unimplemented_as_upstream: Unserved => UnservedKindSpec, 0, 6;
}

/// A trace whose fault model refuses every record of an admitted verdict, as
/// a sink that fails does.
fn refusing_admissions() -> TraceCollector {
	let refused = || TightBeamError::ChannelClosed;
	let model = FaultModel::default().with_event_fault(events::GATE_ACCEPT, refused, bps!(10000));
	TraceCollector::new().with_fault_model(model)
}

tb_assert_spec! {
	pub RefusedRecordSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(MATCHES_UPSTREAM, exactly!(1), equals!(true)),
			(events::GATE_ACCEPT, exactly!(0))
		]
	}
}

// A call whose admission the trace refuses to record fails on both planes
// alike, so neither plane answers a call that it could not audit, and the
// trace holds no admission.
tb_scenario! {
	name: a_verdict_that_the_trace_refuses_fails_the_call_as_upstream,
	config: ScenarioConfig::builder().with_spec(RefusedRecordSpec::latest()).with_trace(refusing_admissions()).build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let upstream = answers_on(Plane::Upstream, (TransitStatus::Ok, EchoService), &trace).await?;
			let served = answers_on(Plane::Served, (TransitStatus::Ok, EchoService), &trace).await?;

			let answered = served.answered();
			assert!(answered.is_empty(), "a call whose verdict the trace refuses MUST fail, got {served:?}");
			trace.event_with(MATCHES_UPSTREAM, &[], served == upstream)?;
			Ok(())
		}
	}
}

/// Admits a call from a peer that the handshake proved, and refuses one from
/// an anonymous peer, as a peer-list gate does.
struct PeerRequired;

impl GatePolicy for PeerRequired {
	fn evaluate(&self, _message: Option<&Frame>, session: &SessionContext) -> TransitStatus {
		let Some(_peer) = session.peer_certificate() else {
			return TransitStatus::PermissionDenied;
		};

		TransitStatus::Ok
	}
}

/// The stream cap of the metered session, which keeps its drain reserve small.
const METERED_STREAMS: u32 = 1;

/// The credit ceiling of the metered session. The client budget sits above
/// the drain reserve of one stream each way, and low enough that a few dozen
/// emits spend it. Only the client opens a renewal, so the server budget
/// outlasts it, and the client renews before the server drains.
const METERED_CEILING: MuxBudgets = MuxBudgets { client_to_server: 160, server_to_client: 4096 };

/// How many invoices the metered dial pays: the handshake and every renewal.
const METERED_PAYMENTS: usize = 16;

/// The most emits the renewal case sends before it gives up on a renewal.
const RENEWAL_BOUND: usize = 1024;

/// The identities and the kind of the metered session.
struct Metered {
	server: Identity,
	security: Arc<Security>,
}

impl Metered {
	/// A paywalled kind under [`METERED_CEILING`], which pins its client.
	fn generate() -> Self {
		let server = identity("CN=renewal server,O=tightbeam-ws,C=US", 1);
		let client = identity("CN=renewal client,O=tightbeam-ws,C=US", 2);
		let settlement = DemoSettlement { invoice: b"serve-test-invoice", payment: b"serve-test-payment" };
		let paywall = DemoPaywall::new(settlement, METERED_CEILING);
		let paywall = paywall.expect("the invoice and the payment encode");

		let security = Security::Paywalled { pinned: client, paywall: Arc::new(paywall) };
		Self { server, security: Arc::new(security) }
	}
}

/// The receipt the session of `handle` holds now, as DER.
fn receipt_of(handle: &MuxHandle) -> Result<Option<Vec<u8>>, TightBeamError> {
	let Some(receipt) = handle.session_receipt() else {
		return Ok(None);
	};

	let der = receipt.to_der()?;
	Ok(Some(der))
}

/// Emit `frame` on `handle` until the session receipt rotates, expecting each
/// emit to echo, and fail past [`RENEWAL_BOUND`] emits.
async fn emit_until_renewed(handle: &MuxHandle, frame: &Frame) -> Result<(), TightBeamError> {
	let first = receipt_of(handle)?;
	for _ in 0..RENEWAL_BOUND {
		let echoed = bounded(handle.emit_on_stream(frame)).await??;
		if echoed.as_ref() != Some(frame) {
			return Err(unexpected("an emit answered no echo"));
		}

		let now = receipt_of(handle)?;
		if now != first {
			return Ok(());
		}
	}

	Err(unexpected("the session never renewed its receipt"))
}

tb_assert_spec! {
	pub RenewalSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(2)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(2)),
			(events::MUX_REKEY_REQUESTED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(2)),
			(events::MUX_REKEY_REFUSED, exactly!(0)),
			(events::GATE_REJECT, exactly!(0)),
			(SERVES_AFTER_RENEWAL, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	/// The renewal of a metered session, in order: both ends settle the
	/// receipt of the handshake, the client requests the renewal, the server
	/// issues its receipt, the client countersigns it, and both ends renew.
	pub RenewalProcess,
	events {
		observable {
			events::SESSION_RECEIPT_SETTLED,
			events::MUX_REKEY_REQUESTED,
			events::MUX_REKEY_RECEIPT_ISSUED,
			events::MUX_REKEY_RECEIPT_COUNTERSIGNED,
			events::MUX_REKEY_RENEWED
		}
		hidden { }
	}
	states {
		Handshaking => { events::SESSION_RECEIPT_SETTLED => HalfSettled },
		HalfSettled => { events::SESSION_RECEIPT_SETTLED => Settled },
		Settled => { events::MUX_REKEY_REQUESTED => Requested },
		Requested => { events::MUX_REKEY_RECEIPT_ISSUED => Issued },
		Issued => { events::MUX_REKEY_RECEIPT_COUNTERSIGNED => Countersigned },
		Countersigned => { events::MUX_REKEY_RENEWED => HalfRenewed },
		HalfRenewed => { events::MUX_REKEY_RENEWED => Renewed },
		Renewed => { }
	}
	terminal { Renewed }
}

// A metered session renews in band, and a gate that reads the peer admits each
// call after the renewal, because a renewal keeps the peer of the session.
// The spec counts each step of the renewal once, and the process grades their
// order.
tb_scenario! {
	name: a_metered_session_keeps_serving_after_a_renewal,
	config: ScenarioConfig::builder().with_spec(RenewalSpec::latest()).with_csp(RenewalProcess).build(),
	environment ServiceClient {
		worker_threads: 2,
		context: Metered::generate(),
		server: |SetupEnv { trace, context }| async move {
			let (listener, addr) = listen(&context.server, &context.security).await?;
			let plane = (Plane::Served, trace.share());
			let served = (PeerRequired, EchoService);
			let serve = serve_one(listener, Arc::clone(&context.security), METERED_STREAMS, served, plane);
			Ok((tokio::spawn(serve), addr))
		},
		client: |ClientEnv { trace, context, addr }| async move {
			let budget = (METERED_STREAMS, METERED_PAYMENTS);
			let client = Client::dial(addr, &context.server, &context.security, budget, &trace).await?;
			let frame = TestFrame::v0(None, None);

			emit_until_renewed(client.handle(), &frame).await?;

			let after = bounded(client.handle().emit_on_stream(&frame)).await??;
			trace.event_with(SERVES_AFTER_RENEWAL, &[], after == Some(frame))?;
			Ok(())
		}
	}
}

/// The identity of the single-flight server, and the signal that it recorded
/// the refusal of its link.
struct SingleFlight {
	server: Identity,
	refused: Notify,
}

impl SingleFlight {
	fn generate() -> Self {
		let server = identity("CN=cleartext refusal server,O=tightbeam-ws,C=US", 1);
		Self { server, refused: Notify::new() }
	}

	/// Bind a server-auth listener, and on a task accept one dial with no
	/// multiplexing on a transport that records on `trace`, then record
	/// whether a cleartext link refuses the transport as encrypted.
	async fn serve(case: Arc<Self>, trace: TraceCollector) -> Served {
		let (listener, addr) = listen(&case.server, &Security::ServerAuth).await?;

		let accepting = tokio::spawn(async move {
			let (transport, _peer) = listener.accept().await?;
			let mut transport = transport.with_trace(trace.share());
			let negotiated = transport.negotiate_mux().await?;
			if negotiated.is_some() {
				return Err(unexpected("the session negotiated multiplexing"));
			}

			let refused = AcceptedLink::cleartext(transport, MuxSettings::symmetric(STREAMS));
			trace.event_with(REFUSED_AS_ENCRYPTED, &[], matches!(refused, Err(LinkError::Encrypted)))?;
			case.refused.notify_one();
			Ok(())
		});

		Ok((accepting, addr))
	}

	/// Dial `addr`, pinning the server, complete the handshake with no mux
	/// offer on a transport that records on `trace`, and wait for the server
	/// to record its refusal.
	async fn dial(&self, addr: TightBeamSocketAddr, trace: &TraceCollector) -> Result<(), TightBeamError> {
		let trust = self.server.trust_anchor()?;
		let builder = ClientBuilder::<WsListener>::builder().with_trust_store(trust);
		let dialed = builder.connect(addr).await?;

		let mut transport = dialed.into_transport().with_trace(trace.share());
		transport.perform_client_handshake().await?;
		bounded(self.refused.notified()).await
	}
}

tb_assert_spec! {
	pub CleartextRefusalSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(2)),
			(REFUSED_AS_ENCRYPTED, exactly!(1), equals!(true))
		]
	}
}

// A transport whose handshake completed is encrypted, so a cleartext link
// refuses it.
tb_scenario! {
	name: an_encrypted_transport_is_refused_as_cleartext,
	spec: CleartextRefusalSpec,
	environment ServiceClient {
		context: SingleFlight::generate(),
		server: |SetupEnv { trace, context }| SingleFlight::serve(context, trace),
		client: |ClientEnv { trace, context, addr }| async move { context.dial(addr, &trace).await }
	}
}

/// The identity of a server whose listener measures each deadline of its
/// endpoint on a clock that the case moves, and the limits of that endpoint.
struct Clocked {
	server: Identity,
	clock: Arc<ManualClock>,
	limits: TransportLimits,
}

impl Clocked {
	/// The read deadline of the endpoint. A third of it outlasts the patience
	/// of [`EventWatch`], so a deadline or a keepalive on the system clock
	/// fails the case.
	const READ_DEADLINE: Duration = Duration::from_secs(60);

	fn generate() -> Self {
		let server = identity("CN=clocked server,O=tightbeam-ws,C=US", 1);
		let limits = TransportLimits { operation_timeout: Self::READ_DEADLINE, ..TransportLimits::default() };
		Self { server, clock: Arc::default(), limits }
	}

	/// The read deadline of the endpoint that the case binds.
	fn deadline(&self) -> Duration {
		self.limits.operation_timeout
	}

	/// Serve one dial on `plane` behind a gate that admits each call, on a
	/// listener whose endpoint runs on the clock of the case, with the server
	/// recording on `trace`.
	async fn serve(case: Arc<Self>, plane: Plane, trace: TraceCollector) -> Served {
		let config = Security::ServerAuth.server_config(&case.server)?;
		let endpoint = EndpointConfig::try_from(config)?.with_limits(case.limits)?;
		let listener = WsListener::bind("127.0.0.1:0", endpoint, case.clock.clone()).await?;
		let addr = TightBeamSocketAddr(listener.local_addr());

		let security = Arc::new(Security::ServerAuth);
		let served = (Verdict(TransitStatus::Ok), EchoService);
		let serve = serve_one(listener, security, STREAMS, served, (plane, trace));
		Ok((tokio::spawn(serve), addr))
	}

	/// Dial the server at `addr` on a transport that records on `trace`, and
	/// probe it once, so its link reads under its deadline before the clock
	/// moves.
	async fn dial(&self, addr: TightBeamSocketAddr, trace: &TraceCollector) -> Result<Client, TightBeamError> {
		let client = Client::dial(addr, &self.server, &Security::ServerAuth, (STREAMS, 1), trace).await?;
		bounded(client.handle().ping()).await??;
		Ok(client)
	}
}

/// The probes of a served session that its silent client answers until one
/// interval past the read deadline: the first probe, and one at the end of
/// each of the [`KEEPALIVE_PROBES_PER_DEADLINE`] intervals of the deadline and
/// of the interval past it.
const SILENCE_PROBES: u32 = KEEPALIVE_PROBES_PER_DEADLINE + 2;

/// The events of the scenario of a served session whose client stays silent,
/// which the case waits on.
static SERVED_EVENTS: EventWatch = EventWatch::new();

tb_assert_spec! {
	pub SilenceSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(KEEPALIVE_ANSWERED, exactly!(SILENCE_PROBES)),
			(events::GATE_ACCEPT, exactly!(1), equals!(TransitStatus::Ok)),
			(SERVES_AFTER_SILENCE, exactly!(1), equals!(true))
		]
	}
}

// A served session whose client stays silent outlives a silence past the read
// deadline of the server through the keepalive of its link, on the clock of
// its endpoint. The case moves the clock one interval after each probe that
// the trace records as answered.
tb_scenario! {
	name: a_served_session_outlives_a_silence_of_its_client_past_the_read_deadline,
	config: ScenarioConfig::builder().with_spec(SilenceSpec::latest()).with_trace(SERVED_EVENTS.trace()).build(),
	environment ServiceClient {
		worker_threads: 2,
		context: Clocked::generate(),
		server: |SetupEnv { trace, context }| Clocked::serve(context, Plane::Served, trace),
		client: |ClientEnv { trace, context, addr }| async move {
			let client = Client::dial(addr, &context.server, &Security::ServerAuth, (STREAMS, 1), &trace).await?;
			let interval = context.deadline() / KEEPALIVE_PROBES_PER_DEADLINE;

			let mut answered = 1;
			SERVED_EVENTS.recorded(KEEPALIVE_ANSWERED, answered).await?;
			for _ in 1..SILENCE_PROBES {
				context.clock.advance(interval);
				answered += 1;
				SERVED_EVENTS.recorded(KEEPALIVE_ANSWERED, answered).await?;
			}

			let frame = TestFrame::v0(None, None);
			let after = bounded(client.handle().emit_on_stream(&frame)).await??;
			trace.event_with(SERVES_AFTER_SILENCE, &[], after == Some(frame))?;
			Ok(())
		}
	}
}

/// The events of the scenario of a silent session, which the case waits on.
static SILENT_EVENTS: EventWatch = EventWatch::new();

tb_assert_spec! {
	pub SilentEndSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CLOSED_AFTER_SILENCE, exactly!(1), equals!(true))
		]
	}
}

// A session that no probe keeps inside the read deadline of the server ends
// once a silence passes that deadline, on the clock of its endpoint. The
// upstream plane runs no keepalive, so the probe of the dial is the last read
// of the server before the clock moves.
tb_scenario! {
	name: a_silent_session_ends_at_the_read_deadline,
	config: ScenarioConfig::builder().with_spec(SilentEndSpec::latest()).with_trace(SILENT_EVENTS.trace()).build(),
	environment ServiceClient {
		worker_threads: 2,
		context: Clocked::generate(),
		server: |SetupEnv { trace, context }| Clocked::serve(context, Plane::Upstream, trace),
		client: |ClientEnv { trace, context, addr }| async move {
			let client = context.dial(addr, &trace).await?;
			context.clock.advance(context.deadline());
			SILENT_EVENTS.recorded(events::CONNECTION_CLOSED, 1).await?;

			let probed = bounded(client.handle().ping()).await?;
			trace.event_with(CLOSED_AFTER_SILENCE, &[], matches!(probed, Err(TransportError::ConnectionClosed)))?;
			Ok(())
		}
	}
}
