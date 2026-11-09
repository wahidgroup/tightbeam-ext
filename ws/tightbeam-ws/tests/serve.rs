//! The gated push-serve of [`ServedMux::serve`] beside upstream
//! [`MuxAcceptor::serve`], over loopback handshakes, as tightbeam scenarios.
//!
//! The differential cases install one gate verdict on a server of each plane,
//! dial it, and compare what a client observes of a unary, a streaming, and a
//! duplex stream. Both planes run the same echo, so every difference is a
//! difference of the gate. The renewal case meters a session tight enough to
//! renew in band, and keeps serving behind a gate that reads the peer. The
//! cleartext case refuses an encrypted transport as a cleartext link.
//!
//! Every transport records on the trace of its scenario, and both planes
//! record the verdict of their gate for each stream, so a differential spec
//! counts the verdicts of both.
//!
//! [`MuxAcceptor::serve`]: tightbeam::transport::multiplex::MuxAcceptor::serve
//! [`ServedMux::serve`]: tightbeam_ws::serve::ServedMux::serve

#![cfg(feature = "testing")]

use core::future::pending;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tightbeam::instrumentation::events;
use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::error::TestingError;
use tightbeam::testing::{ClientEnv, FaultModel, ScenarioConfig, SetupEnv, TestFrame};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::{MuxBudgets, MuxSettings};
use tightbeam::transport::multiplex::{
	MuxAcceptor, MuxDispatch, MuxHandle, MuxRole, ReplySink, SpawnedMux, StreamBody, StreamRoute,
};
use tightbeam::transport::policy::CollectorGateConfig;
use tightbeam::transport::{
	ClientBuilder, ConnectionBuilder, EncryptedMessageIO, EncryptedProtocol, ResponsePackage, TransportResult,
};
use tightbeam::urn::Urn;
use tightbeam::{bps, encode, exactly, tb_assert_spec, tb_process_spec, tb_scenario, urn, Frame, TightBeamError};
use tightbeam_ws::io::WsTransport;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::serve::{AcceptedLink, LinkError};
use tightbeam_ws::testing::{DemoPaywall, EchoService, Identity, Security};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_tungstenite::MaybeTlsStream;

/// Whether the served plane answered each stream kind as upstream did.
const MATCHES_UPSTREAM: Urn<'static> = urn!("test", "event:served-mux/matches-upstream");

/// Whether an emit after a renewal echoed its frame.
const SERVES_AFTER_RENEWAL: Urn<'static> = urn!("test", "event:served-mux/serves-after-renewal");

/// Whether a cleartext link refused an encrypted transport as encrypted.
const REFUSED_AS_ENCRYPTED: Urn<'static> = urn!("test", "event:served-mux/refused-as-encrypted");

/// The transport an accepted WebSocket connection follows.
type ServerTransport = WsTransport<MaybeTlsStream<TcpStream>>;

/// The server of a scenario, and the socket address it bound.
type Served = Result<(JoinHandle<Result<(), TightBeamError>>, TightBeamSocketAddr), TightBeamError>;

/// The stream cap that both ends of a differential case offer.
const STREAMS: u32 = 4;

/// How long one stream may take before a case fails instead of hanging.
const DEADLINE: Duration = Duration::from_secs(5);

/// How long each identity stays valid.
const VALIDITY: Duration = Duration::from_secs(3600);

/// The duplex chunk a client sends.
const CHUNK: &[u8] = b"differential-duplex";

/// A deadline that passed, as the failure of the exchange it bounded.
fn late(elapsed: tokio::time::error::Elapsed) -> TightBeamError {
	TightBeamError::IoError(elapsed.into())
}

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

/// The echo of [`EchoService`], as the [`MuxDispatch`] a served mux takes.
struct EchoDispatch;

impl MuxDispatch for EchoDispatch {
	async fn unary(&self, frame: Arc<Frame>) -> TransportResult<ResponsePackage> {
		let echoed = Frame::clone(&frame);
		Ok(ResponsePackage::new(TransitStatus::Ok, Some(echoed)))
	}

	async fn streaming(&self, body: StreamBody, _route: StreamRoute) -> TransportResult<ResponsePackage> {
		let frame = body.into_frame().await?;
		Ok(ResponsePackage::new(TransitStatus::Ok, Some(frame)))
	}

	async fn duplex(
		&self,
		mut body: StreamBody,
		mut reply: ReplySink,
		_route: StreamRoute,
	) -> TransportResult<TransitStatus> {
		while let Some(chunk) = body.chunk().await? {
			reply.push(&chunk).await?;
		}

		Ok(TransitStatus::Ok)
	}
}

/// The serve a server runs over its accepted transport.
#[derive(Clone, Copy)]
enum Plane {
	/// Upstream [`MuxAcceptor::serve`] over [`EchoService`].
	Upstream,
	/// [`ServedMux::serve`](tightbeam_ws::serve::ServedMux::serve) over
	/// [`EchoDispatch`].
	Served,
}

impl Plane {
	/// Serve `transport`, which negotiated `settings`, until it ends.
	async fn serve(self, transport: ServerTransport, settings: MuxSettings) -> Result<(), TightBeamError> {
		match self {
			Self::Upstream => transport.serve(settings, EchoService, None).await?,
			Self::Served => {
				let link = AcceptedLink::accepted(transport).map_err(io::Error::other)?;
				link.spawn().serve(EchoDispatch, pending()).await?;
			}
		}

		Ok(())
	}
}

/// What a client observes of a stream: its answer, or the debug form of the
/// error it failed with.
type Observed<T> = Result<T, String>;

/// What a client observes of one stream of each kind.
#[derive(Debug, PartialEq)]
struct Answers {
	unary: Observed<Option<Frame>>,
	streaming: Observed<Option<Frame>>,
	duplex: Observed<Vec<Vec<u8>>>,
}

/// The debug form of `outcome`'s error, which a case compares across planes.
fn observed<T>(outcome: TransportResult<T>) -> Observed<T> {
	outcome.map_err(|error| format!("{error:?}"))
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
		let mut builder = ClientBuilder::<WsListener>::builder().with_trust_store(trust);
		if let Some(client) = security.client_identity() {
			builder = builder.with_client_identity(client.signing_identity()?);
		}

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

	/// Open one stream of each kind, and observe how each ends.
	async fn answers(&self) -> Result<Answers, TightBeamError> {
		let frame = TestFrame::v0(None, None);
		let der = encode(&frame)?;

		let unary = timeout(DEADLINE, self.handle().emit_on_stream(&frame)).await.map_err(late)?;

		let (sink, response) = self.handle().open_stream()?;
		let _closed = sink.close_with(&der).await;
		let streaming = timeout(DEADLINE, response).await.map_err(late)?;

		let (sink, body) = self.handle().open_duplex()?;
		let _closed = sink.close_with(CHUNK).await;
		let duplex = timeout(DEADLINE, Self::chunks(body)).await.map_err(late)?;

		Ok(Answers { unary: observed(unary), streaming: observed(streaming), duplex: observed(duplex) })
	}

	/// Every chunk of `body` until it ends.
	async fn chunks(mut body: StreamBody) -> TransportResult<Vec<Vec<u8>>> {
		let mut chunks = Vec::new();
		while let Some(chunk) = body.chunk().await? {
			chunks.push(chunk);
		}

		Ok(chunks)
	}
}

/// The identity of a server or a client.
fn identity(subject: &str, serial: u32) -> Identity {
	let minted = Identity::mint(subject, serial, VALIDITY);
	minted.expect("the identity mints")
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
async fn serve_one(
	listener: WsListener,
	security: Arc<Security>,
	streams: u32,
	gate: impl GatePolicy + 'static,
	(plane, trace): (Plane, TraceCollector),
) -> Result<(), TightBeamError> {
	let (transport, _peer) = listener.accept().await?;
	let metered = security.meter(transport.with_trace(trace), streams);
	let mut gated = metered.with_collector_gate(gate);
	let negotiated = gated.negotiate_mux().await?;
	let settings = negotiated.ok_or_else(|| unexpected("the peer negotiated no multiplexing"))?;

	plane.serve(gated, settings).await
}

/// What a client observes of each stream kind on a server of `plane` whose
/// gate answers `verdict`, with both ends recording on `trace`.
async fn answers_on(plane: Plane, verdict: TransitStatus, trace: &TraceCollector) -> Result<Answers, TightBeamError> {
	let server = identity("CN=differential server,O=tightbeam-ws,C=US", 1);
	let security = Arc::new(Security::ServerAuth);
	let (listener, addr) = listen(&server, &security).await?;
	let serve = serve_one(
		listener,
		Arc::clone(&security),
		STREAMS,
		Verdict(verdict),
		(plane, trace.share()),
	);

	let serving = tokio::spawn(serve);
	let client = Client::dial(addr, &server, &security, (STREAMS, 1), trace).await?;
	let answers = client.answers().await;
	serving.abort();

	answers
}

/// Record on `trace` whether a served mux answers every stream kind under
/// `verdict` as upstream `MuxAcceptor::serve` answers it.
async fn differential(verdict: TransitStatus, trace: &TraceCollector) -> Result<(), TightBeamError> {
	let upstream = answers_on(Plane::Upstream, verdict, trace).await?;
	let served = answers_on(Plane::Served, verdict, trace).await?;

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
			let upstream = answers_on(Plane::Upstream, TransitStatus::Ok, &trace).await?;
			let served = answers_on(Plane::Served, TransitStatus::Ok, &trace).await?;

			let failed = served.unary.is_err() && served.streaming.is_err() && served.duplex.is_err();
			assert!(failed, "a call whose verdict the trace refuses MUST fail, got {served:?}");
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
		let paywall = DemoPaywall::new(b"serve-test-invoice", b"serve-test-payment", METERED_CEILING);
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
		let echoed = timeout(DEADLINE, handle.emit_on_stream(frame)).await.map_err(late)??;
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

// A metered session renews in band, and the served plane keeps serving it
// behind a gate that reads the peer, because a renewal keeps the peer of the
// session:
// - The spec counts each step of the renewal once, and the process grades
//   their order.
// - The gate reads the peer, and it refuses no call before or after the
//   renewal.
tb_scenario! {
	name: a_metered_session_keeps_serving_after_a_renewal,
	config: ScenarioConfig::builder().with_spec(RenewalSpec::latest()).with_csp(RenewalProcess).build(),
	environment ServiceClient {
		worker_threads: 2,
		context: Metered::generate(),
		server: |SetupEnv { trace, context }| async move {
			let (listener, addr) = listen(&context.server, &context.security).await?;
			let plane = (Plane::Served, trace.share());
			let serve = serve_one(listener, Arc::clone(&context.security), METERED_STREAMS, PeerRequired, plane);
			Ok((tokio::spawn(serve), addr))
		},
		client: |ClientEnv { trace, context, addr }| async move {
			let budget = (METERED_STREAMS, METERED_PAYMENTS);
			let client = Client::dial(addr, &context.server, &context.security, budget, &trace).await?;
			let frame = TestFrame::v0(None, None);

			emit_until_renewed(client.handle(), &frame).await?;

			let after = timeout(DEADLINE, client.handle().emit_on_stream(&frame)).await.map_err(late)??;
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
		timeout(DEADLINE, self.refused.notified()).await.map_err(late)
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
