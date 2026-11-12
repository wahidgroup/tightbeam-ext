//! Refusals and ends of a tunnel against real peers: a stock tonic client,
//! raw `h2` peers, and the dialing transport. `docs/grpc.md` lists them.

mod support;

use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use h2::server::SendResponse;
use h2::RecvStream;
use http::header::{ALLOW, CONTENT_TYPE};
use http::uri::PathAndQuery;
use http::{Method, Response, StatusCode};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tonic::client::Grpc;
use tonic::transport::Endpoint;

use tightbeam::instrumentation::events;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::{ClientEnv, ScenarioConfig, SetupEnv, TestFrame};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::policy::RestartLinearBackoff;
use tightbeam::transport::{EndpointConfig, MessageCollector, MessageEmitter, Protocol, TransportLimits};
use tightbeam::urn::Urn;
use tightbeam::{client, exactly, tb_assert_spec, tb_process_spec, tb_scenario, urn, TightBeamError};
use tightbeam_grpc::edge::{Dial, Edge, EdgeProfile};
use tightbeam_grpc::events::EDGE_REFUSED;
use tightbeam_grpc::protocol::{GrpcAddr, GrpcListener, TUNNEL_PATH};
use tightbeam_grpc::staged_profile;

use support::{bounded, unexpected, EchoServer, Graded, H2Tunnel, RawCodec, Served};
use tightbeam_ws::testing::specs::DialCeilingSpec;
use tightbeam_ws::testing::{EventWatch, ReadOutcome};

/// The gRPC status code that a peer read.
const GRPC_STATUS: Urn<'static> = urn!("test", "event:grpc-refusal/grpc-status");

/// The HTTP status that a peer read.
const HTTP_STATUS: Urn<'static> = urn!("test", "event:grpc-refusal/http-status");

/// The methods that a refusal of the method names in its `Allow` header.
const ALLOWED: Urn<'static> = urn!("test", "event:grpc-refusal/allowed");

staged_profile! {
	/// The edge of the scenario of another path.
	OtherPathEdge
}

staged_profile! {
	/// The edge of the scenario of a compressed call.
	CompressedCallEdge
}

staged_profile! {
	/// The edge of the scenario of another media type.
	MediaTypeEdge
}

staged_profile! {
	/// The edge of the scenario of another method.
	MethodEdge
}

staged_profile! {
	/// The edge of the scenario of a compressed message.
	CompressedMessageEdge
}

staged_profile! {
	/// The edge of the scenario of a message past the ceiling.
	CeilingEdge
}

/// The shared echo on a cleartext listener of profile `C` on loopback, whose
/// h2c edge `stage` stages to record on `trace`.
async fn echo<C: EdgeProfile>(stage: fn(Edge, Dial), trace: &TraceCollector) -> Served {
	stage(Edge::h2c().with_trace(trace.share()), Dial::H2c);
	EchoServer::cleartext::<C>(trace).await
}

/// One exchange of a tightbeam client with the echo at `addr`, which proves
/// that the listener still serves after a refusal.
async fn still_serves(addr: TightBeamSocketAddr) -> Result<(), TightBeamError> {
	let mut client = client! {
		connect GrpcListener: GrpcAddr::from(addr.0),
		cleartext,
		policies: {
			restart_policy: RestartLinearBackoff::default(),
		}
	};

	let message = TestFrame::v0(None, None);
	let reply = client.emit(message.clone(), None).await?;
	assert_eq!(reply, Some(message), "the listener MUST still serve after a refusal");
	Ok(())
}

/// One gRPC message frame: the compressed flag, the declared length, and
/// `payload`.
fn message_frame(compressed: bool, declared: u32, payload: &[u8]) -> Bytes {
	let mut frame = BytesMut::with_capacity(5 + payload.len());
	frame.put_u8(u8::from(compressed));
	frame.put_u32(declared);
	frame.put_slice(payload);
	frame.freeze()
}

/// The declared length one byte past the ceiling of the default limits.
fn past_the_ceiling() -> Result<u32, TightBeamError> {
	let ceiling = TransportLimits::default().max_envelope();
	u32::try_from(ceiling + 1).map_err(unexpected)
}

/// Record the gRPC status of `response` on `trace`, when it carries one.
async fn record_grpc_status(trace: &TraceCollector, response: Response<RecvStream>) -> Result<(), TightBeamError> {
	if let Some(code) = H2Tunnel::grpc_status(response).await? {
		trace.event_with(GRPC_STATUS, &[], code)?;
	}
	Ok(())
}

/// What the client and the raw server of one scenario signal each other: the
/// client read the head of the answer, and the server dropped its connection.
#[derive(Default)]
struct RawSignals {
	headed: Notify,
	dropped: Notify,
}

/// A raw `h2` server on an ephemeral loopback port, which answers the first
/// call it accepts with `answer`, and drives its connection until the client
/// raises `headed` or closes it. It then drops the connection and raises
/// `dropped`.
async fn raw_server<F>(answer: F, signals: Arc<RawSignals>) -> Served<Result<(), TightBeamError>>
where
	F: FnOnce(SendResponse<Bytes>) -> Result<(), TightBeamError> + Send + 'static,
{
	let listener = TcpListener::bind("127.0.0.1:0").await.map_err(unexpected)?;
	let addr = listener.local_addr().map_err(unexpected)?;

	let server = tokio::spawn(async move {
		let (socket, _peer) = listener.accept().await.map_err(unexpected)?;
		let mut connection = h2::server::handshake(socket).await.map_err(unexpected)?;
		let accepted = connection.accept().await.ok_or_else(|| unexpected("the dial opened no call"))?;
		let (_request, respond) = accepted.map_err(unexpected)?;
		answer(respond)?;

		// The connection writes the answer while it is driven.
		let driven = async { while connection.accept().await.is_some() {} };
		tokio::select! {
			() = signals.headed.notified() => {}
			() = driven => {}
		}

		drop(connection);
		signals.dropped.notify_one();
		Ok(())
	});

	Ok((server, TightBeamSocketAddr(addr)))
}

/// The response head of a tunnel call that a raw server answers.
fn grpc_head() -> Result<Response<()>, TightBeamError> {
	let head = Response::builder().status(StatusCode::OK);
	let head = head.header(CONTENT_TYPE, "application/grpc");
	head.body(()).map_err(unexpected)
}

/// A dialing transport to `addr` whose endpoint records on `trace`.
async fn traced_dial(
	addr: TightBeamSocketAddr,
	trace: &TraceCollector,
) -> Result<<GrpcListener as Protocol>::Transport, TightBeamError> {
	let stream = <GrpcListener as Protocol>::connect(GrpcAddr::from(addr.0));
	let stream = bounded(stream).await??;
	let config = EndpointConfig::cleartext().with_trace(trace.share());
	Ok(<GrpcListener as Protocol>::create_transport(stream, config))
}

tb_process_spec! {
	/// A call that the listener refuses, in order: the listener records the
	/// refusal, the peer reads the answer of the refusal, and the listener
	/// then accepts the next client and its gate admits it. The listener
	/// therefore records each refusal before its answer leaves, and serves on.
	pub RefusedThenServed,
	events {
		observable {
			EDGE_REFUSED,
			GRPC_STATUS,
			HTTP_STATUS,
			ALLOWED,
			events::CONNECTION_ACCEPTED,
			events::GATE_ACCEPT
		}
		hidden { }
	}
	states {
		Listening => { EDGE_REFUSED => Refused },
		Refused => { GRPC_STATUS => Answered, HTTP_STATUS => Answered },
		Answered => { ALLOWED => Answered, events::CONNECTION_ACCEPTED => Accepted },
		Accepted => { events::GATE_ACCEPT => Served },
		Served => { }
	}
	terminal { Served }
}

tb_assert_spec! {
	pub OtherPathSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(EDGE_REFUSED, exactly!(1), equals!("path")),
			(GRPC_STATUS, exactly!(1), equals!(12u32)),
			(events::CONNECTION_ACCEPTED, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(1))
		]
	}
}

// A stock tonic client that calls another path reads status 12, and the call
// opens no session.
tb_scenario! {
	name: a_stock_client_on_another_path_reads_unimplemented,
	config: ScenarioConfig::builder().with_spec(OtherPathSpec::latest()).with_csp(RefusedThenServed).build(),
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move { echo::<OtherPathEdge>(OtherPathEdge::stage, &trace).await },
		client: |ClientEnv { trace, addr, .. }| async move {
			let endpoint = Endpoint::from_shared(format!("http://{}", addr.0)).map_err(unexpected)?;
			let mut grpc = Grpc::new(bounded(endpoint.connect()).await?.map_err(unexpected)?);
			bounded(grpc.ready()).await?.map_err(unexpected)?;

			let path = PathAndQuery::from_static("/other.v1.Service/Call");
			let requests = tonic::Request::new(tokio_stream::iter(vec![b"probe".to_vec()]));
			let called = bounded(grpc.streaming(requests, path, RawCodec)).await?;
			if let Err(refused) = called {
				let code = u32::try_from(i32::from(refused.code())).map_err(unexpected)?;
				trace.event_with(GRPC_STATUS, &[], code)?;
			}

			still_serves(addr).await
		}
	}
}

tb_assert_spec! {
	pub CompressedCallSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(EDGE_REFUSED, exactly!(0)),
			(GRPC_STATUS, exactly!(1), equals!(12u32)),
			(events::CONNECTION_ACCEPTED, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(1))
		]
	}
}

// A call in gzip reads status 12, and the call opens no session. tonic
// refuses the encoding before the listener sees the call, so the listener
// records no refusal of its own.
tb_scenario! {
	name: a_compressed_call_reads_unimplemented,
	spec: CompressedCallSpec,
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move { echo::<CompressedCallEdge>(CompressedCallEdge::stage, &trace).await },
		client: |ClientEnv { trace, addr, .. }| async move {
			let mut peer = H2Tunnel::connect(addr.0, &[]).await?;
			let mut head = peer.tunnel_head()?;
			head.headers_mut().insert("grpc-encoding", "gzip".parse().map_err(unexpected)?);

			let response = peer.call(head, None).await?;
			record_grpc_status(&trace, response).await?;
			still_serves(addr).await
		}
	}
}

tb_assert_spec! {
	pub MediaTypeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(EDGE_REFUSED, exactly!(1), equals!("media-type")),
			(HTTP_STATUS, exactly!(1), equals!(415u32)),
			(events::CONNECTION_ACCEPTED, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(1))
		]
	}
}

// A call outside `application/grpc` reads HTTP 415, and the call opens no
// session.
tb_scenario! {
	name: a_call_outside_application_grpc_reads_unsupported_media_type,
	config: ScenarioConfig::builder().with_spec(MediaTypeSpec::latest()).with_csp(RefusedThenServed).build(),
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move { echo::<MediaTypeEdge>(MediaTypeEdge::stage, &trace).await },
		client: |ClientEnv { trace, addr, .. }| async move {
			let mut peer = H2Tunnel::connect(addr.0, &[]).await?;
			let head = peer.head(Method::POST, &PathAndQuery::from_static(TUNNEL_PATH), "text/plain")?;

			let response = peer.call(head, None).await?;
			trace.event_with(HTTP_STATUS, &[], u32::from(response.status().as_u16()))?;
			still_serves(addr).await
		}
	}
}

tb_assert_spec! {
	pub MethodSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(EDGE_REFUSED, exactly!(1), equals!("method")),
			(HTTP_STATUS, exactly!(1), equals!(405u32)),
			(ALLOWED, exactly!(1), equals!("POST")),
			(events::CONNECTION_ACCEPTED, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(1))
		]
	}
}

// A call other than POST reads HTTP 405, which names POST as the method the
// tunnel allows, and the call opens no session.
tb_scenario! {
	name: a_call_other_than_post_reads_method_not_allowed,
	config: ScenarioConfig::builder().with_spec(MethodSpec::latest()).with_csp(RefusedThenServed).build(),
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move { echo::<MethodEdge>(MethodEdge::stage, &trace).await },
		client: |ClientEnv { trace, addr, .. }| async move {
			let mut peer = H2Tunnel::connect(addr.0, &[]).await?;
			let head = peer.head(Method::GET, &PathAndQuery::from_static(TUNNEL_PATH), "application/grpc")?;

			let response = peer.call(head, None).await?;
			trace.event_with(HTTP_STATUS, &[], u32::from(response.status().as_u16()))?;
			if let Some(allow) = response.headers().get(ALLOW) {
				trace.event_with(ALLOWED, &[], allow.to_str().map_err(unexpected)?)?;
			}
			still_serves(addr).await
		}
	}
}

tb_assert_spec! {
	pub CompressedMessageSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(EDGE_REFUSED, exactly!(0)),
			(GRPC_STATUS, exactly!(1), equals!(13u32)),
			(events::TRANSPORT_ENVELOPE_REFUSED, exactly!(1), equals!("InvalidMessage")),
			(events::CONNECTION_ACCEPTED, exactly!(2)),
			(events::GATE_ACCEPT, exactly!(1))
		]
	}
}

/// The events of the scenario of a compressed message with no encoding.
static COMPRESSED_MESSAGE_EVENTS: EventWatch = EventWatch::new();

// A compressed message on a call with no encoding opens a session, whose read
// refuses the message as invalid and answers status 13.
tb_scenario! {
	name: a_compressed_message_with_no_encoding_reads_internal,
	config: CompressedMessageSpec::latest().watched(&COMPRESSED_MESSAGE_EVENTS),
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move { echo::<CompressedMessageEdge>(CompressedMessageEdge::stage, &trace).await },
		client: |ClientEnv { trace, addr, .. }| async move {
			let mut peer = H2Tunnel::connect(addr.0, &[]).await?;
			let head = peer.tunnel_head()?;

			let response = peer.call(head, Some(message_frame(true, 1, b"x"))).await?;
			record_grpc_status(&trace, response).await?;
			COMPRESSED_MESSAGE_EVENTS.recorded(events::TRANSPORT_ENVELOPE_REFUSED, 1).await?;
			still_serves(addr).await
		}
	}
}

tb_assert_spec! {
	pub CeilingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(EDGE_REFUSED, exactly!(0)),
			(GRPC_STATUS, exactly!(1), equals!(11u32)),
			(events::TRANSPORT_ENVELOPE_REFUSED, exactly!(1), equals!("SizeExceeded")),
			(events::CONNECTION_ACCEPTED, exactly!(2)),
			(events::GATE_ACCEPT, exactly!(1))
		]
	}
}

/// The events of the scenario of a message past the ceiling.
static CEILING_EVENTS: EventWatch = EventWatch::new();

// A message one byte past the ceiling opens a session, whose read refuses the
// message by its size and answers status 11.
tb_scenario! {
	name: a_message_past_the_ceiling_reads_out_of_range,
	config: CeilingSpec::latest().watched(&CEILING_EVENTS),
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move { echo::<CeilingEdge>(CeilingEdge::stage, &trace).await },
		client: |ClientEnv { trace, addr, .. }| async move {
			let mut peer = H2Tunnel::connect(addr.0, &[]).await?;
			let head = peer.tunnel_head()?;

			let response = peer.call(head, Some(message_frame(false, past_the_ceiling()?, &[]))).await?;
			record_grpc_status(&trace, response).await?;
			CEILING_EVENTS.recorded(events::TRANSPORT_ENVELOPE_REFUSED, 1).await?;
			still_serves(addr).await
		}
	}
}

// The dial refuses an answer past its ceiling by its declared size, before any
// byte of the message arrives. tightbeam files no refusal of that answer, so
// the client records the failure that the emit returned.
tb_scenario! {
	name: the_dial_refuses_a_message_past_its_ceiling_by_the_declared_size,
	spec: DialCeilingSpec,
	environment ServiceClient {
		context: RawSignals::default(),
		server: |SetupEnv { context, .. }| async move {
			let declared = past_the_ceiling()?;
			let answer = move |mut respond: SendResponse<Bytes>| {
				let mut body = respond.send_response(grpc_head()?, false).map_err(unexpected)?;
				body.send_data(message_frame(false, declared, &[]), false).map_err(unexpected)
			};
			raw_server(answer, context).await
		},
		client: |ClientEnv { trace, addr, .. }| async move {
			let mut transport = traced_dial(addr, &trace).await?;
			let emitted = bounded(transport.emit(TestFrame::v0(None, None), None)).await?;
			ReadOutcome::record(&emitted, &trace)
		}
	}
}

tb_assert_spec! {
	pub DroppedConnectionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(ReadOutcome::EVENT, exactly!(1), equals!("io")),
			(events::TRANSPORT_ENVELOPE_REFUSED, exactly!(0))
		]
	}
}

// A tunnel whose connection drops mid-call reads the drop as an I/O failure,
// and the transport files no refusal of an envelope for it.
tb_scenario! {
	name: a_tunnel_whose_connection_drops_mid_call_reads_as_io,
	spec: DroppedConnectionSpec,
	environment ServiceClient {
		context: RawSignals::default(),
		server: |SetupEnv { context, .. }| async move {
			let answer = |mut respond: SendResponse<Bytes>| {
				respond.send_response(grpc_head()?, false).map_err(unexpected)?;
				Ok(())
			};
			raw_server(answer, context).await
		},
		client: |ClientEnv { trace, addr, context }| async move {
			// The dial returns once the head of the answer arrived.
			let mut transport = traced_dial(addr, &trace).await?;
			context.headed.notify_one();
			bounded(context.dropped.notified()).await?;

			let read = bounded(transport.collect_message()).await?;
			ReadOutcome::record(&read, &trace)
		}
	}
}
