//! The compensation of a spent claim, against a gateway on the coupled
//! listener itself that refuses work or withholds the credit of a stream, and
//! the clock of the loopback session against a gateway that withholds its
//! handshake.

mod support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tightbeam::constants::{DEFAULT_HANDSHAKE_TIMEOUT, MIN_MUX_CHUNK_SIZE};
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};
use tightbeam::prelude::collect::CollectorGateConfig;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::{ClientEnv, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::multiplex::{CallContext, CreditGrantor, MuxAcceptor, MuxRole, MuxService, StreamId};
use tightbeam::transport::{EncryptedProtocol, MessageIO, TransportError, TransportFailure, TransportLimits};
use tightbeam::urn::Urn;
use tightbeam::{exactly, server, tb_assert_spec, tb_scenario, urn, Frame, TightBeamError};
use tightbeam_grpc::couple::{Assurance, CallLimits, Coupler, Grants, Principal, Routes, Servlet};
use tightbeam_grpc::edge::{Dial, Edge, EdgeProfile};
use tightbeam_grpc::events::{
	COUPLED_CALL_ADMITTED, COUPLED_CALL_REFUSED, COUPLED_CLAIM_FORGOTTEN, COUPLED_CLAIM_SPENT,
};
use tightbeam_grpc::protocol::{GrpcAddr, GrpcListener};
use tightbeam_ws::testing::{EventWatch, WorkClient};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use support::{bounded, code_of, edge_error, Coupled, Graded, WEB};

/// The method of every call, which requires `Signed`.
const PLACE: &str = "/orders.v1.Orders/Place";

/// A bidirectional stream that requires `Signed`.
const CHAT: &str = "/orders.v1.Orders/Chat";

/// The call limit of the edge whose gateway withholds the credit of a stream,
/// on a clock that the scenario moves: past [`OPENING`], so only an advance of
/// that clock ends the call in time.
const WITHHELD_LIMIT: core::time::Duration = core::time::Duration::from_secs(8);

/// A work request that the handler of the gateway read.
const READ: Urn<'static> = urn!("test", "event:gateway/read");

/// The streams that the gateway admits from the loopback session.
const STREAMS: u32 = 8;

/// The handler of a gateway: it reads each work request that its gate admits,
/// and refuses it with `ResourceExhausted`, as a gateway does whose answer
/// the session cannot carry.
struct ExhaustedGateway {
	trace: TraceCollector,
}

/// A clone records on the trace of the original.
impl Clone for ExhaustedGateway {
	fn clone(&self) -> Self {
		Self { trace: self.trace.share() }
	}
}

impl MuxService for ExhaustedGateway {
	async fn unary(&self, _frame: Frame, _cx: CallContext) -> Result<Option<Frame>, TightBeamError> {
		self.trace.event(READ)?;
		Err(TransportError::OperationFailed(TransportFailure::ResourceExhausted).into())
	}
}

/// The gate of a gateway, which refuses one frame with `Unavailable`, before
/// any handler runs, while `refusing` holds, and admits every other.
struct Gate {
	refusing: Arc<AtomicBool>,
}

impl GatePolicy for Gate {
	fn evaluate(&self, message: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		let refused = message.is_some() && self.refusing.swap(false, Ordering::SeqCst);
		if refused {
			return TransitStatus::Unavailable;
		}

		TransitStatus::Ok
	}
}

/// The edge and the gateway of a scenario.
impl Coupled {
	/// Stage the coupled edge through `stage`, which records on `trace`:
	/// `Place` requires `Signed`, and the web caller holds it.
	fn stage_place(&self, trace: &TraceCollector, stage: fn(Edge, Dial)) -> Result<(), TightBeamError> {
		let orders = Servlet::new(WorkClient::servlet("orders")?, self.answers.certificate().clone());
		let orders = orders.map_err(edge_error)?;
		let routes = Routes::new().unary(PLACE, orders, Assurance::Signed).map_err(edge_error)?;
		let web = Principal::subject(WEB).map_err(edge_error)?;
		let grants = Grants::deny_all().grant(web, PLACE).map_err(edge_error)?;

		let coupler = self.coupler(routes, grants)?;
		self.stage_coupler(trace, stage, coupler)
	}

	/// Serve the exhausted gateway on the coupled listener of profile `C`,
	/// whose gate refuses the first work when `refusing` holds.
	async fn exhausted_gateway<C: EdgeProfile>(
		&self,
		trace: &TraceCollector,
		refusing: bool,
	) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError> {
		let bind: GrpcAddr = "127.0.0.1:0".parse()?;
		let config = self.transport.server_config();
		let (listener, _) =
			<GrpcListener<DefaultCryptoProvider, C> as EncryptedProtocol>::bind_with(bind, config).await?;

		let addr = TightBeamSocketAddr(listener.local_addr());
		let gateway = ExhaustedGateway { trace: trace.share() };
		let refusing = Arc::new(AtomicBool::new(refusing));
		let served = server! {
			protocol GrpcListener<DefaultCryptoProvider, C>: listener,
			policies: {
				with_mux_offer: [ Some(TransportOffer::mux(STREAMS)) ],
				with_collector_gate: [ Gate { refusing: Arc::clone(&refusing) } ]
			},
			service: gateway
		};
		Ok((served, addr))
	}

	/// Send one call of `Place` from the web caller to the edge at `addr`
	/// under one claim, three times: the codes of the three answers.
	async fn thrice(&self, addr: TightBeamSocketAddr) -> Result<[Option<tonic::Code>; 3], TightBeamError> {
		let web = self.caller(WEB, None);
		let channel = self.channel(&GrpcAddr::from(addr.0), Some(&web)).await?;
		channel.serving(&self.clock).await?;

		let claim = self.claim(&web, PLACE, b"order").await?;

		let first = code_of(channel.call(PLACE, b"order", Some(&claim)).await?);
		let second = code_of(channel.call(PLACE, b"order", Some(&claim)).await?);
		let third = code_of(channel.call(PLACE, b"order", Some(&claim)).await?);
		Ok([first, second, third])
	}
}

tightbeam_grpc::staged_profile! {
	/// The coupled edge in front of a gateway whose gate admits every work.
	ReadEdge
}

tb_assert_spec! {
	/// One claim sent three times to a gateway that reads each work: the
	/// coupler admits all three, the gateway reads the first, and the coupler
	/// refuses the other two as replays.
	pub KeptSpendSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(3)),
			(READ, exactly!(1)),
			(COUPLED_CALL_REFUSED, exactly!(3))
		]
	}
}

// A send that the handler of the gateway refused left the session, so the
// coupler keeps its claim spent, and refuses each retry as a replay.
tb_scenario! {
	name: a_claim_whose_send_left_stays_spent,
	spec: KeptSpendSpec,
	environment ServiceClient {
		context: Coupled::mint(),
		server: |SetupEnv { trace, context }| async move {
			context.stage_place(&trace, ReadEdge::stage)?;
			context.exhausted_gateway::<ReadEdge>(&trace, false).await
		},
		client: |ClientEnv { addr, context, .. }| async move {
			let codes = context.thrice(addr).await?;
			let (refused, replayed) = (Some(tonic::Code::Unavailable), Some(tonic::Code::Unauthenticated));
			assert_eq!(codes, [refused, replayed, replayed], "a claim whose send left MUST stay spent");
			Ok(())
		}
	}
}

tightbeam_grpc::staged_profile! {
	/// The coupled edge in front of a gateway whose gate refuses the first
	/// work.
	GatedEdge
}

tb_assert_spec! {
	/// One claim sent three times to a gateway whose gate refuses the first
	/// work: the coupler admits all three, the gateway reads the second, and
	/// the coupler refuses the third as a replay.
	pub ForgottenSpendSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(3)),
			(READ, exactly!(1)),
			(COUPLED_CALL_REFUSED, exactly!(3))
		]
	}
}

// A send that the gate of the gateway refused stayed in the session, so the
// coupler forgets its claim, and the retry spends it again.
tb_scenario! {
	name: a_claim_whose_send_never_left_is_forgotten,
	spec: ForgottenSpendSpec,
	environment ServiceClient {
		context: Coupled::mint(),
		server: |SetupEnv { trace, context }| async move {
			context.stage_place(&trace, GatedEdge::stage)?;
			context.exhausted_gateway::<GatedEdge>(&trace, true).await
		},
		client: |ClientEnv { addr, context, .. }| async move {
			let codes = context.thrice(addr).await?;
			let (refused, replayed) = (Some(tonic::Code::Unavailable), Some(tonic::Code::Unauthenticated));
			assert_eq!(codes, [refused, refused, replayed], "the retry of a forgotten claim MUST spend it again");
			Ok(())
		}
	}
}

/// The credit policy of a gateway that admits the first chunk of a stream
/// and grants no more, as a peer that never reads the stream does.
struct Withheld;

impl CreditGrantor for Withheld {
	fn replenish(&self, _stream_id: StreamId, _received: u64, _limit: u64) -> Option<u64> {
		None
	}
}

/// The edge and the withholding gateway of a scenario.
impl Coupled {
	/// Stage the coupled edge through `stage`, which records on `trace`: `Chat`
	/// requires `Signed`, the web caller holds it, and each call has
	/// [`WITHHELD_LIMIT`].
	fn stage_chat(&self, trace: &TraceCollector, stage: fn(Edge, Dial)) -> Result<(), TightBeamError> {
		let orders = Servlet::new(WorkClient::servlet("orders")?, self.answers.certificate().clone());
		let routes = Routes::new().bidi_stream(CHAT, orders.map_err(edge_error)?, Assurance::Signed);
		let web = Principal::subject(WEB).map_err(edge_error)?;
		let grants = Grants::deny_all().grant(web, CHAT).map_err(edge_error)?;

		let coupler = self.coupler(routes.map_err(edge_error)?, grants)?;
		let limits = CallLimits::default().with_timeout(WITHHELD_LIMIT);
		self.stage_coupler(trace, stage, coupler.with_call_limits(limits).map_err(edge_error)?)
	}

	/// Serve a gateway on the coupled listener of profile `C` that takes the
	/// loopback session of its coupler, admits one chunk of each stream, and
	/// grants no further credit.
	async fn withholding_gateway<C: EdgeProfile>(
		&self,
	) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError> {
		let bind: GrpcAddr = "127.0.0.1:0".parse()?;
		let config = self.transport.server_config();
		let (listener, _) =
			<GrpcListener<DefaultCryptoProvider, C> as EncryptedProtocol>::bind_with(bind, config).await?;

		let addr = TightBeamSocketAddr(listener.local_addr());
		let offer = TransportOffer::mux(STREAMS)
			.with_initial_stream_credit(1)
			.with_chunk_payload_size(MIN_MUX_CHUNK_SIZE);
		let served = tokio::spawn(async move {
			let Ok((transport, _peer)) = listener.accept().await else {
				return;
			};

			let mut transport = transport.with_mux_offer(Some(Arc::new(offer)));
			let Ok(Some(_)) = transport.negotiate_mux().await else {
				return;
			};

			let Ok(mux) = transport.into_mux(MuxRole::Server) else {
				return;
			};

			// The gateway holds its session until the scenario ends.
			let _session = mux.with_credit_grantor(Arc::new(Withheld)).spawn();
			core::future::pending::<()>().await;
		});
		Ok((served, addr))
	}

	/// A stream of `Chat` from the web caller under `claim`, which a hang of
	/// the edge fails within [`OPENING`]: the status that ended it.
	async fn chat(
		&self,
		channel: &support::StockChannel,
		claim: &tightbeam_grpc::couple::CallClaim,
	) -> Result<Option<tonic::Code>, TightBeamError> {
		let streamed = channel.stream(CHAT, &[b"hello"], Some(claim)).await?;
		Ok(code_of(streamed))
	}
}

tightbeam_grpc::staged_profile! {
	/// The coupled edge in front of a gateway that withholds the credit of a
	/// stream.
	WithheldEdge
}

tb_assert_spec! {
	/// One claim on a stream, opened twice against a gateway that withholds
	/// its credit: the push of the first head passes its deadline with part of
	/// the head sent, so the coupler refuses it with 4 and keeps the claim
	/// spent. It refuses the second as a replay, which spends nothing.
	pub WithheldHeadSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(COUPLED_CALL_ADMITTED, exactly!(2)),
			(COUPLED_CLAIM_SPENT, exactly!(1)),
			(COUPLED_CLAIM_FORGOTTEN, exactly!(0)),
			(COUPLED_CALL_REFUSED, exactly!(2))
		]
	}
}

/// The events of the scenario of a head whose push passes its deadline.
static WITHHELD_HEAD_EVENTS: EventWatch = EventWatch::new();

// A head whose push passes its deadline may have reached the servlet whole,
// so the coupler keeps its claim spent, and refuses the retry as a replay.
tb_scenario! {
	name: a_head_whose_push_passes_its_deadline_keeps_its_claim,
	config: WithheldHeadSpec::latest().watched(&WITHHELD_HEAD_EVENTS),
	environment ServiceClient {
		context: Coupled::clocked(&WITHHELD_HEAD_EVENTS),
		server: |SetupEnv { trace, context }| async move {
			context.stage_chat(&trace, WithheldEdge::stage)?;
			context.withholding_gateway::<WithheldEdge>().await
		},
		client: |ClientEnv { addr, context, .. }| async move {
			let web = context.caller(WEB, None);
			let channel = context.channel(&GrpcAddr::from(addr.0), Some(&web)).await?;
			channel.serving(&context.clock).await?;
			let claim = context.claim(&web, CHAT, b"").await?;

			// The push of the head starts once the claim is spent, and parks on
			// the credit that the gateway withholds.
			let advancing = async {
				WITHHELD_HEAD_EVENTS.recorded(COUPLED_CLAIM_SPENT, 1).await?;
				context.clock.advance(WITHHELD_LIMIT)
			};
			let (first, advanced) = tokio::join!(context.chat(&channel, &claim), advancing);
			advanced?;
			assert_eq!(first?, Some(tonic::Code::DeadlineExceeded), "a held head MUST pass its deadline");

			let retried = context.chat(&channel, &claim).await?;
			assert_eq!(retried, Some(tonic::Code::Unauthenticated), "the claim of a head that may have left MUST stay spent");
			Ok(())
		}
	}
}

/// The first message of a loopback tunnel that the silent gateway read.
const LOOPBACK_HELLO: Urn<'static> = urn!("test", "event:gateway/loopback-hello");

/// A loopback tunnel that its client ended before its handshake completed.
const LOOPBACK_ENDED: Urn<'static> = urn!("test", "event:gateway/loopback-ended");

/// How long the silent gateway waits for a handshake: past the handshake
/// deadline of the client of a loopback session, so that client ends first.
const SILENT_HANDSHAKE: core::time::Duration = DEFAULT_HANDSHAKE_TIMEOUT.saturating_mul(2);

/// Raised by the silent gateway each time the client of a loopback tunnel
/// ends it.
static SILENT_ENDED: Notify = Notify::const_new();

impl Coupled {
	/// Serve a gateway on the coupled listener of profile `C`, which reads the
	/// first message of each loopback tunnel and answers none, and records on
	/// `trace` that message and each tunnel that its client ends, which also
	/// raises [`SILENT_ENDED`].
	async fn silent_gateway<C: EdgeProfile>(
		&self,
		trace: &TraceCollector,
	) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError> {
		let bind: GrpcAddr = "127.0.0.1:0".parse()?;
		let limits = TransportLimits { handshake_timeout: SILENT_HANDSHAKE, ..TransportLimits::default() };
		let config = self.transport.server_config().with_limits(limits)?;
		let (listener, _) =
			<GrpcListener<DefaultCryptoProvider, C> as EncryptedProtocol>::bind_with(bind, config).await?;

		let addr = TightBeamSocketAddr(listener.local_addr());
		let trace = trace.share();
		let served = tokio::spawn(async move {
			while let Ok((mut transport, _peer)) = listener.accept().await {
				if transport.read_envelope_bytes().await.is_err() {
					return;
				}

				let _ = trace.event(LOOPBACK_HELLO);
				if transport.read_envelope_bytes().await.is_err() {
					let _ = trace.event(LOOPBACK_ENDED);
					SILENT_ENDED.notify_one();
				}
			}
		});
		Ok((served, addr))
	}
}

tightbeam_grpc::staged_profile! {
	/// The coupled edge in front of a gateway that never answers the
	/// handshake of the loopback session.
	SilentEdge
}

tb_assert_spec! {
	/// Two loopback sessions in turn against a gateway that never answers
	/// their handshake: the client of the first ends at its handshake
	/// deadline, and the second opens after the backoff of the session.
	pub SilentSessionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(LOOPBACK_HELLO, exactly!(2)),
			(LOOPBACK_ENDED, exactly!(1))
		]
	}
}

/// The events of the scenario of a gateway that never answers a handshake.
static SILENT_SESSION_EVENTS: EventWatch = EventWatch::new();

// The client of the loopback session runs on the clock of the edge, so its
// handshake ends only as the scenario moves that clock, and the next session
// opens after the backoff.
tb_scenario! {
	name: a_loopback_session_handshake_runs_on_the_clock_of_the_edge,
	config: SilentSessionSpec::latest().watched(&SILENT_SESSION_EVENTS),
	environment ServiceClient {
		context: Coupled::clocked(&SILENT_SESSION_EVENTS),
		server: |SetupEnv { trace, context }| async move {
			context.stage_chat(&trace, SilentEdge::stage)?;
			context.silent_gateway::<SilentEdge>(&trace).await
		},
		client: |ClientEnv { context, .. }| async move {
			SILENT_SESSION_EVENTS.recorded(LOOPBACK_HELLO, 1).await?;
			context.clock.advance(DEFAULT_HANDSHAKE_TIMEOUT)?;
			bounded(SILENT_ENDED.notified()).await?;

			context.clock.advance(Coupler::SESSION_BACKOFF)?;
			Ok(SILENT_SESSION_EVENTS.recorded(LOOPBACK_HELLO, 2).await?)
		}
	}
}
