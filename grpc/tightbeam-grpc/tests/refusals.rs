//! Refusals and ends of a tunnel against real peers, as tightbeam scenarios:
//! a stock tonic client, `h2` peers that write each frame of a call by hand,
//! and the dialing transport itself.
//!
//! - A server-side case serves a traced `server!` echo on a listener that
//!   records its own refusals as [`TUNNEL_REFUSED`]. A raw peer sends the
//!   refused call and records the status it read, and a tightbeam client then
//!   round-trips on the same listener. The spec grades the refusal that the
//!   listener recorded, the status that the peer read, whether the refused
//!   call opened a session, and the one exchange the gate admitted.
//! - A dial-side case dials a raw `h2` server with a transport whose endpoint
//!   records on the trace, records how its read ended as a [`ReadOutcome`],
//!   and the spec grades that outcome and the refusals the transport files.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use h2::client::SendRequest;
use h2::server::SendResponse;
use h2::RecvStream;
use http::header::{ALLOW, CONTENT_TYPE, TE};
use http::uri::PathAndQuery;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tonic::client::Grpc;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::transport::Endpoint;
use tonic::Status;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::instrumentation::events;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::{ClientEnv, ScenarioConfig, SetupEnv, TestFrame};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::policy::RestartLinearBackoff;
use tightbeam::transport::{
	EndpointConfig, MessageCollector, MessageEmitter, Protocol, TransportError, TransportLimits,
};
use tightbeam::urn::Urn;
use tightbeam::{client, exactly, tb_assert_spec, tb_process_spec, tb_scenario, urn, TightBeamError};
use tightbeam_grpc::events::TUNNEL_REFUSED;
use tightbeam_grpc::protocol::{GrpcAddr, GrpcListener, TUNNEL_PATH};
use tightbeam_ws::testing::specs::DialCeilingSpec;
use tightbeam_ws::testing::{EchoService, ReadOutcome};

/// The gRPC status code that a peer read.
const GRPC_STATUS: Urn<'static> = urn!("test", "event:grpc-refusal/grpc-status");

/// The HTTP status that a peer read.
const HTTP_STATUS: Urn<'static> = urn!("test", "event:grpc-refusal/http-status");

/// The methods that a refusal of the method names in its `Allow` header.
const ALLOWED: Urn<'static> = urn!("test", "event:grpc-refusal/allowed");

/// How long a healthy exchange may take on loopback.
const PROMPT: Duration = Duration::from_secs(5);

/// The server of a scenario, and the socket address it bound.
type Served<T> = Result<(JoinHandle<T>, TightBeamSocketAddr), TightBeamError>;

/// A failure of a raw peer or of its timing, which the scenario reads as an
/// I/O failure of the exchange.
fn peer_fault(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> TightBeamError {
	TransportError::IoError(io::Error::other(error.into())).into()
}

/// The codec of a stock tonic client that sends raw bytes as each message.
#[derive(Clone, Copy, Default)]
struct RawCodec;

impl Codec for RawCodec {
	type Encode = Vec<u8>;
	type Decode = Vec<u8>;
	type Encoder = RawCodec;
	type Decoder = RawCodec;

	fn encoder(&mut self) -> Self::Encoder {
		*self
	}

	fn decoder(&mut self) -> Self::Decoder {
		*self
	}
}

impl Encoder for RawCodec {
	type Item = Vec<u8>;
	type Error = Status;

	fn encode(&mut self, item: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
		dst.put_slice(&item);
		Ok(())
	}
}

impl Decoder for RawCodec {
	type Item = Vec<u8>;
	type Error = Status;

	fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Vec<u8>>, Status> {
		let length = src.remaining();
		let message = src.copy_to_bytes(length);
		Ok(Some(message.into()))
	}
}

/// The shared echo on a cleartext listener on an ephemeral loopback port,
/// which records each session on `trace`.
async fn echo(trace: &TraceCollector) -> Served<()> {
	let listener = GrpcListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await?;
	let listener = listener.with_trace(trace.share());
	let addr = TightBeamSocketAddr(listener.local_addr());
	Ok((EchoService::serve(listener, None, trace), addr))
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

/// Wait, within [`PROMPT`], until the server records `event` on `trace`.
///
/// The server answers a refused message to its peer before tightbeam files
/// the refusal on the trace, so a case that grades the refusal waits for it,
/// whatever the flavor of its runtime.
async fn filed(trace: &TraceCollector, event: Urn<'static>) -> Result<(), TightBeamError> {
	let recorded = async {
		while trace.recorded(event.clone()) == 0 {
			sleep(Duration::from_millis(5)).await;
		}
	};

	timeout(PROMPT, recorded).await.map_err(peer_fault)
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
	u32::try_from(ceiling + 1).map_err(peer_fault)
}

/// A raw `h2` client of one listener, which writes each frame of a call by
/// hand.
struct H2Peer {
	authority: SocketAddr,
	calls: SendRequest<Bytes>,
}

impl H2Peer {
	/// An HTTP/2 connection to `addr`, which a task of its own drives.
	async fn connect(addr: TightBeamSocketAddr) -> Result<Self, TightBeamError> {
		let tcp = TcpStream::connect(addr.0).await.map_err(peer_fault)?;
		let (calls, connection) = h2::client::handshake(tcp).await.map_err(peer_fault)?;
		tokio::spawn(async move {
			// The driver ends with the connection, and the scenario reads
			// each outcome from its calls.
			let _ = connection.await;
		});

		let calls = calls.ready().await.map_err(peer_fault)?;
		Ok(Self { authority: addr.0, calls })
	}

	/// The head of a call on the tunnel path with `method` and
	/// `content_type`.
	fn head(&self, method: Method, content_type: &str) -> Result<Request<()>, TightBeamError> {
		let uri = format!("http://{}{TUNNEL_PATH}", self.authority);
		let head = Request::builder().method(method).uri(uri);
		let head = head.header(CONTENT_TYPE, content_type).header(TE, "trailers");
		head.body(()).map_err(peer_fault)
	}

	/// Open a call with `head`, write `message` on it, and read the head of
	/// the response within [`PROMPT`]. A call with no message ends its
	/// request with its head.
	async fn call(
		&mut self,
		head: Request<()>,
		message: Option<Bytes>,
	) -> Result<Response<RecvStream>, TightBeamError> {
		let ends_with_head = message.is_none();
		let (response, mut requests) = self.calls.send_request(head, ends_with_head).map_err(peer_fault)?;
		if let Some(message) = message {
			requests.send_data(message, false).map_err(peer_fault)?;
		}

		let answered = timeout(PROMPT, response).await.map_err(peer_fault)?;
		answered.map_err(peer_fault)
	}

	/// The `grpc-status` of `response`: from its headers for a trailers-only
	/// response, or else from its trailers, within [`PROMPT`].
	async fn grpc_status(response: Response<RecvStream>) -> Result<Option<u32>, TightBeamError> {
		let from_headers = Self::status_of(response.headers());
		if from_headers.is_some() {
			return Ok(from_headers);
		}

		let mut body = response.into_body();
		let drained = timeout(PROMPT, async {
			while let Some(chunk) = body.data().await {
				chunk?;
			}
			body.trailers().await
		});
		let trailers = drained.await.map_err(peer_fault)?.map_err(peer_fault)?;
		Ok(trailers.as_ref().and_then(Self::status_of))
	}

	fn status_of(headers: &HeaderMap) -> Option<u32> {
		let status = headers.get("grpc-status")?;
		status.to_str().ok()?.parse().ok()
	}
}

/// Record the gRPC status of `response` on `trace`, when it carries one.
async fn record_grpc_status(trace: &TraceCollector, response: Response<RecvStream>) -> Result<(), TightBeamError> {
	if let Some(code) = H2Peer::grpc_status(response).await? {
		trace.event_with(GRPC_STATUS, &[], code)?;
	}
	Ok(())
}

/// A raw `h2` server on an ephemeral loopback port, which answers the first
/// call it accepts with `answer`, drops the connection once it has written
/// the answer, and then raises `dropped`.
async fn raw_server<F>(answer: F, dropped: Arc<Notify>) -> Served<Result<(), TightBeamError>>
where
	F: FnOnce(SendResponse<Bytes>) -> Result<(), TightBeamError> + Send + 'static,
{
	let listener = TcpListener::bind("127.0.0.1:0").await.map_err(peer_fault)?;
	let addr = listener.local_addr().map_err(peer_fault)?;

	let server = tokio::spawn(async move {
		let (socket, _peer) = listener.accept().await.map_err(peer_fault)?;
		let mut connection = h2::server::handshake(socket).await.map_err(peer_fault)?;
		let accepted = connection.accept().await.ok_or_else(|| peer_fault("the dial opened no call"))?;
		let (_request, respond) = accepted.map_err(peer_fault)?;
		answer(respond)?;

		// The connection writes the answer while it is polled, and the
		// accept that ends this window carries no signal.
		let _ = timeout(Duration::from_millis(300), connection.accept()).await;
		drop(connection);
		dropped.notify_one();
		Ok(())
	});

	Ok((server, TightBeamSocketAddr(addr)))
}

/// The response head of a tunnel call that a raw server answers.
fn grpc_head() -> Result<Response<()>, TightBeamError> {
	let head = Response::builder().status(StatusCode::OK);
	let head = head.header(CONTENT_TYPE, "application/grpc");
	head.body(()).map_err(peer_fault)
}

/// A dialing transport to `addr` whose endpoint records on `trace`.
async fn traced_dial(
	addr: TightBeamSocketAddr,
	trace: &TraceCollector,
) -> Result<<GrpcListener as Protocol>::Transport, TightBeamError> {
	let stream = <GrpcListener as Protocol>::connect(GrpcAddr::from(addr.0));
	let stream = timeout(PROMPT, stream).await.map_err(peer_fault)??;
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
			TUNNEL_REFUSED,
			GRPC_STATUS,
			HTTP_STATUS,
			ALLOWED,
			events::CONNECTION_ACCEPTED,
			events::GATE_ACCEPT
		}
		hidden { }
	}
	states {
		Listening => { TUNNEL_REFUSED => Refused },
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
			(TUNNEL_REFUSED, exactly!(1), equals!("path")),
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
		server: |SetupEnv { trace, .. }| async move { echo(&trace).await },
		client: |ClientEnv { trace, addr, .. }| async move {
			let endpoint = Endpoint::from_shared(format!("http://{}", addr.0)).map_err(peer_fault)?;
			let mut grpc = Grpc::new(endpoint.connect().await.map_err(peer_fault)?);
			grpc.ready().await.map_err(peer_fault)?;

			let path = PathAndQuery::from_static("/other.v1.Service/Call");
			let requests = tonic::Request::new(tokio_stream::iter(vec![b"probe".to_vec()]));
			let called = timeout(PROMPT, grpc.streaming(requests, path, RawCodec)).await.map_err(peer_fault)?;
			if let Err(refused) = called {
				let code = u32::try_from(i32::from(refused.code())).map_err(peer_fault)?;
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
			(TUNNEL_REFUSED, exactly!(0)),
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
		server: |SetupEnv { trace, .. }| async move { echo(&trace).await },
		client: |ClientEnv { trace, addr, .. }| async move {
			let mut peer = H2Peer::connect(addr).await?;
			let mut head = peer.head(Method::POST, "application/grpc")?;
			head.headers_mut().insert("grpc-encoding", "gzip".parse().map_err(peer_fault)?);

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
			(TUNNEL_REFUSED, exactly!(1), equals!("media-type")),
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
		server: |SetupEnv { trace, .. }| async move { echo(&trace).await },
		client: |ClientEnv { trace, addr, .. }| async move {
			let mut peer = H2Peer::connect(addr).await?;
			let head = peer.head(Method::POST, "text/plain")?;

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
			(TUNNEL_REFUSED, exactly!(1), equals!("method")),
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
		server: |SetupEnv { trace, .. }| async move { echo(&trace).await },
		client: |ClientEnv { trace, addr, .. }| async move {
			let mut peer = H2Peer::connect(addr).await?;
			let head = peer.head(Method::GET, "application/grpc")?;

			let response = peer.call(head, None).await?;
			trace.event_with(HTTP_STATUS, &[], u32::from(response.status().as_u16()))?;
			if let Some(allow) = response.headers().get(ALLOW) {
				trace.event_with(ALLOWED, &[], allow.to_str().map_err(peer_fault)?)?;
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
			(TUNNEL_REFUSED, exactly!(0)),
			(GRPC_STATUS, exactly!(1), equals!(13u32)),
			(events::TRANSPORT_ENVELOPE_REFUSED, exactly!(1), equals!("InvalidMessage")),
			(events::CONNECTION_ACCEPTED, exactly!(2)),
			(events::GATE_ACCEPT, exactly!(1))
		]
	}
}

// A compressed message on a call with no encoding opens a session, whose read
// refuses the message as invalid and answers status 13.
tb_scenario! {
	name: a_compressed_message_with_no_encoding_reads_internal,
	spec: CompressedMessageSpec,
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move { echo(&trace).await },
		client: |ClientEnv { trace, addr, .. }| async move {
			let mut peer = H2Peer::connect(addr).await?;
			let head = peer.head(Method::POST, "application/grpc")?;

			let response = peer.call(head, Some(message_frame(true, 1, b"x"))).await?;
			record_grpc_status(&trace, response).await?;
			filed(&trace, events::TRANSPORT_ENVELOPE_REFUSED).await?;
			still_serves(addr).await
		}
	}
}

tb_assert_spec! {
	pub CeilingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(TUNNEL_REFUSED, exactly!(0)),
			(GRPC_STATUS, exactly!(1), equals!(11u32)),
			(events::TRANSPORT_ENVELOPE_REFUSED, exactly!(1), equals!("SizeExceeded")),
			(events::CONNECTION_ACCEPTED, exactly!(2)),
			(events::GATE_ACCEPT, exactly!(1))
		]
	}
}

// A message one byte past the ceiling opens a session, whose read refuses the
// message by its size and answers status 11.
tb_scenario! {
	name: a_message_past_the_ceiling_reads_out_of_range,
	spec: CeilingSpec,
	environment ServiceClient {
		server: |SetupEnv { trace, .. }| async move { echo(&trace).await },
		client: |ClientEnv { trace, addr, .. }| async move {
			let mut peer = H2Peer::connect(addr).await?;
			let head = peer.head(Method::POST, "application/grpc")?;

			let response = peer.call(head, Some(message_frame(false, past_the_ceiling()?, &[]))).await?;
			record_grpc_status(&trace, response).await?;
			filed(&trace, events::TRANSPORT_ENVELOPE_REFUSED).await?;
			still_serves(addr).await
		}
	}
}

// The dial refuses an answer past its ceiling by the declared size, before
// any byte of the message arrives: the raw server declares the size and sends
// nothing more, so a read that waited for the bytes would not end.
//
// The emit path of tightbeam files no `TRANSPORT_ENVELOPE_REFUSED` for an
// answer that its read refuses before the decode, so the client records the
// failure that the emit returned.
tb_scenario! {
	name: the_dial_refuses_a_message_past_its_ceiling_by_the_declared_size,
	spec: DialCeilingSpec,
	environment ServiceClient {
		context: Notify::new(),
		server: |SetupEnv { context, .. }| async move {
			let declared = past_the_ceiling()?;
			let answer = move |mut respond: SendResponse<Bytes>| {
				let mut body = respond.send_response(grpc_head()?, false).map_err(peer_fault)?;
				body.send_data(message_frame(false, declared, &[]), false).map_err(peer_fault)
			};
			raw_server(answer, context).await
		},
		client: |ClientEnv { trace, addr, .. }| async move {
			let mut transport = traced_dial(addr, &trace).await?;
			let emitted = timeout(PROMPT, transport.emit(TestFrame::v0(None, None), None)).await.map_err(peer_fault)?;
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
		context: Notify::new(),
		server: |SetupEnv { context, .. }| async move {
			let answer = |mut respond: SendResponse<Bytes>| {
				respond.send_response(grpc_head()?, false).map_err(peer_fault)?;
				Ok(())
			};
			raw_server(answer, context).await
		},
		client: |ClientEnv { trace, addr, context }| async move {
			let mut transport = traced_dial(addr, &trace).await?;
			timeout(PROMPT, context.notified()).await.map_err(peer_fault)?;

			let read = timeout(PROMPT, transport.collect_message()).await.map_err(peer_fault)?;
			ReadOutcome::record(&read, &trace)
		}
	}
}
