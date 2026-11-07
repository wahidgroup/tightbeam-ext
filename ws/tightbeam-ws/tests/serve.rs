//! The gated push-serve of [`ServedMux::serve`] beside upstream
//! [`MuxAcceptor::serve`], over loopback handshakes.
//!
//! The differential cases install one gate verdict on a server of each plane,
//! dial it, and compare what a client observes of a unary, a streaming, and a
//! duplex stream. Both planes run the same echo, so every difference is a
//! difference of the gate. The renewal case meters a session tight enough to
//! renew in band, and keeps serving behind a gate that reads the peer. The
//! cleartext case refuses an encrypted transport as a cleartext link.
//!
//! [`MuxAcceptor::serve`]: tightbeam::transport::multiplex::MuxAcceptor::serve

#![cfg(feature = "testing")]

use core::future::pending;
use std::sync::Arc;
use std::time::Duration;

use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::TestFrame;
use tightbeam::transport::handshake::negotiation::{MuxBudgets, MuxSettings};
use tightbeam::transport::multiplex::{
	CallContext, MuxAcceptor, MuxDispatch, MuxHandle, MuxRole, MuxService, ReplySink, SpawnedMux, StreamBody,
	StreamRoute,
};
use tightbeam::transport::policy::CollectorGateConfig;
use tightbeam::transport::{
	ClientBuilder, ConnectionBuilder, EncryptedMessageIO, EncryptedProtocol, ResponsePackage, TransportError,
	TransportResult,
};
use tightbeam::{encode, tb_cases, Frame, TightBeamError};
use tightbeam_ws::io::WsTransport;
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::serve::{AcceptedLink, LinkError};
use tightbeam_ws::testing::{DemoPaywall, Identity, Security};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::MaybeTlsStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The transport an accepted WebSocket connection follows.
type ServerTransport = WsTransport<MaybeTlsStream<TcpStream>>;

/// The stream cap that both ends of a differential case offer.
const STREAMS: u32 = 4;

/// How long one stream may take before a case fails instead of hanging.
const DEADLINE: Duration = Duration::from_secs(5);

/// How long each identity stays valid.
const VALIDITY: Duration = Duration::from_secs(3600);

/// The duplex chunk a client sends.
const CHUNK: &[u8] = b"differential-duplex";

/// A gate that answers one fixed verdict.
struct Verdict(TransitStatus);

impl GatePolicy for Verdict {
	fn evaluate(&self, _message: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		self.0
	}
}

/// Echoes every kind of stream through upstream [`MuxService`].
struct EchoService;

impl MuxService for EchoService {
	async fn unary(&self, frame: Frame, _cx: CallContext) -> Result<Option<Frame>, TightBeamError> {
		Ok(Some(frame))
	}

	async fn streaming(&self, body: StreamBody, _cx: CallContext) -> Result<Option<Frame>, TightBeamError> {
		let frame = body.into_frame().await?;
		Ok(Some(frame))
	}

	async fn duplex(&self, mut body: StreamBody, mut reply: ReplySink, _cx: CallContext) -> Result<(), TightBeamError> {
		while let Some(chunk) = body.chunk().await? {
			reply.push(&chunk).await?;
		}

		Ok(())
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
	async fn serve(self, transport: ServerTransport, settings: MuxSettings) -> Result<(), BoxError> {
		match self {
			Self::Upstream => transport.serve(settings, EchoService, None).await?,
			Self::Served => {
				let link = AcceptedLink::accepted(transport)?;
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
	/// `streams` streams. A paywalled kind pays its invoice up to `payments`
	/// times.
	async fn dial(
		addr: TightBeamSocketAddr,
		server: &Identity,
		security: &Security,
		streams: u32,
		payments: usize,
	) -> Result<Self, BoxError> {
		let trust = server.trust_anchor()?;
		let mut builder = ClientBuilder::<WsListener>::builder().with_trust_store(trust);
		if let Some(client) = security.client_identity() {
			builder = builder.with_client_identity(client.signing_identity()?);
		}

		let dialed = builder.connect(addr).await?;
		let mut transport = security.meter_dial(dialed.into_transport(), streams, payments);
		transport.perform_client_handshake().await?;

		let mux = transport.into_mux(MuxRole::Client)?;
		Ok(Self(mux.spawn()))
	}

	fn handle(&self) -> &MuxHandle {
		&self.0.handle
	}

	/// Open one stream of each kind, and observe how each ends.
	async fn answers(&self) -> Result<Answers, BoxError> {
		let frame = TestFrame::v0(None, None);
		let der = encode(&frame)?;

		let unary = timeout(DEADLINE, self.handle().emit_on_stream(&frame)).await?;

		let (sink, response) = self.handle().open_stream()?;
		let _closed = sink.close_with(&der).await;
		let streaming = timeout(DEADLINE, response).await?;

		let (sink, body) = self.handle().open_duplex()?;
		let _closed = sink.close_with(CHUNK).await;
		let duplex = timeout(DEADLINE, Self::chunks(body)).await?;

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
async fn listen(server: &Identity, security: &Security) -> Result<(WsListener, TightBeamSocketAddr), BoxError> {
	let config = security.server_config(server)?;
	let loopback = TightBeamSocketAddr("127.0.0.1:0".parse()?);

	let bound = <WsListener as EncryptedProtocol>::bind_with(loopback, config).await?;
	Ok(bound)
}

/// Accept one dial on `listener` under `security`, install `gate`, and serve
/// it on `plane` until it ends.
async fn serve_one(
	listener: WsListener,
	security: Arc<Security>,
	streams: u32,
	gate: impl GatePolicy + 'static,
	plane: Plane,
) -> Result<(), BoxError> {
	let (transport, _peer) = listener.accept().await?;
	let mut gated = security.meter(transport, streams).with_collector_gate(gate);
	let negotiated = gated.negotiate_mux().await?;
	let settings = negotiated.ok_or("the peer negotiated no multiplexing")?;

	plane.serve(gated, settings).await
}

/// What a client observes of each stream kind on a server of `plane` whose
/// gate answers `verdict`.
async fn answers_on(plane: Plane, verdict: TransitStatus) -> Result<Answers, BoxError> {
	let server = identity("CN=differential server,O=tightbeam-ws,C=US", 1);
	let security = Arc::new(Security::ServerAuth);
	let (listener, addr) = listen(&server, &security).await?;

	let serving = tokio::spawn(serve_one(listener, Arc::clone(&security), STREAMS, Verdict(verdict), plane));
	let client = Client::dial(addr, &server, &security, STREAMS, 1).await?;
	let answers = client.answers().await;
	serving.abort();

	answers
}

// Every gate verdict, `Unknown` included, answers each stream kind on a served
// mux as it answers on upstream `MuxAcceptor::serve`.
tb_cases! {
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn served_mux_answers_every_gate_verdict_as_upstream_serve(verdict: TransitStatus) -> Result<(), BoxError> {
		let upstream = answers_on(Plane::Upstream, verdict).await?;
		let served = answers_on(Plane::Served, verdict).await?;

		assert_eq!(served, upstream);
		Ok(())
	}
	cases {
		ok => TransitStatus::Ok,
		cancelled => TransitStatus::Cancelled,
		unknown => TransitStatus::Unknown,
		invalid_argument => TransitStatus::InvalidArgument,
		deadline_exceeded => TransitStatus::DeadlineExceeded,
		not_found => TransitStatus::NotFound,
		already_exists => TransitStatus::AlreadyExists,
		permission_denied => TransitStatus::PermissionDenied,
		resource_exhausted => TransitStatus::ResourceExhausted,
		failed_precondition => TransitStatus::FailedPrecondition,
		aborted => TransitStatus::Aborted,
		out_of_range => TransitStatus::OutOfRange,
		unimplemented => TransitStatus::Unimplemented,
		internal => TransitStatus::Internal,
		unavailable => TransitStatus::Unavailable,
		data_loss => TransitStatus::DataLoss,
		unauthenticated => TransitStatus::Unauthenticated,
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

/// The paywalled kind over `client`, under [`METERED_CEILING`].
fn metered(client: Identity) -> Security {
	let paywall = DemoPaywall::new(b"serve-test-invoice", b"serve-test-payment", METERED_CEILING);
	let paywall = paywall.expect("the invoice and the payment encode");
	Security::Paywalled { pinned: client, paywall: Arc::new(paywall) }
}

/// The receipt the session of `handle` holds now, as DER.
fn receipt_of(handle: &MuxHandle) -> Result<Option<Vec<u8>>, BoxError> {
	let Some(receipt) = handle.session_receipt() else {
		return Ok(None);
	};

	let der = receipt.to_der()?;
	Ok(Some(der))
}

/// Emit `frame` on `handle` until the session receipt rotates, expecting each
/// emit to echo, and fail past [`RENEWAL_BOUND`] emits.
async fn emit_until_renewed(handle: &MuxHandle, frame: &Frame) -> Result<(), BoxError> {
	let first = receipt_of(handle)?;
	for _ in 0..RENEWAL_BOUND {
		let echoed = timeout(DEADLINE, handle.emit_on_stream(frame)).await??;
		if echoed.as_ref() != Some(frame) {
			return Err("an emit answered no echo".into());
		}

		let now = receipt_of(handle)?;
		if now != first {
			return Ok(());
		}
	}

	Err(TransportError::InvalidState.into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_metered_session_keeps_serving_after_a_renewal() -> Result<(), BoxError> {
	let server = identity("CN=renewal server,O=tightbeam-ws,C=US", 1);
	let client = identity("CN=renewal client,O=tightbeam-ws,C=US", 2);
	let security = Arc::new(metered(client));
	let (listener, addr) = listen(&server, &security).await?;

	let serve = serve_one(listener, Arc::clone(&security), METERED_STREAMS, PeerRequired, Plane::Served);
	let serving = tokio::spawn(serve);
	let client = Client::dial(addr, &server, &security, METERED_STREAMS, METERED_PAYMENTS).await?;
	let frame = TestFrame::v0(None, None);

	emit_until_renewed(client.handle(), &frame).await?;

	let after = timeout(DEADLINE, client.handle().emit_on_stream(&frame)).await??;
	serving.abort();
	assert_eq!(after, Some(frame));
	Ok(())
}

/// Accept one dial on `listener`, which offers no multiplexing, and complete
/// its handshake as a single-flight session.
async fn single_flight(listener: &WsListener) -> Result<ServerTransport, BoxError> {
	let (mut transport, _peer) = listener.accept().await?;
	let negotiated = transport.negotiate_mux().await?;
	if negotiated.is_some() {
		return Err("the session negotiated multiplexing".into());
	}

	Ok(transport)
}

/// Dial `addr`, pinning `server`, and complete the handshake with no mux
/// offer.
async fn dial_single_flight(addr: TightBeamSocketAddr, server: &Identity) -> Result<(), BoxError> {
	let trust = server.trust_anchor()?;
	let builder = ClientBuilder::<WsListener>::builder().with_trust_store(trust);
	let dialed = builder.connect(addr).await?;

	let mut transport = dialed.into_transport();
	transport.perform_client_handshake().await?;
	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_encrypted_transport_is_refused_as_cleartext() -> Result<(), BoxError> {
	let server = identity("CN=cleartext refusal server,O=tightbeam-ws,C=US", 1);
	let (listener, addr) = listen(&server, &Security::ServerAuth).await?;
	let (accepted, dialed) = tokio::join!(single_flight(&listener), dial_single_flight(addr, &server));

	dialed?;

	let refused = AcceptedLink::cleartext(accepted?, MuxSettings::symmetric(STREAMS));
	assert!(matches!(refused, Err(LinkError::Encrypted)));
	Ok(())
}
