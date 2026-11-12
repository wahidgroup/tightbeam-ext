//! The PKI, the stock caller, the coupler, the echo, and the raw peers that
//! the scenarios share.
#![allow(dead_code)]

use core::future::Future;
use core::num::NonZeroUsize;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes};
use futures_util::stream;
use h2::client::{ResponseFuture, SendRequest};
use h2::{RecvStream, SendStream};
use http::header::{CONTENT_TYPE, TE};
use http::uri::PathAndQuery;
use http::{HeaderMap, Method, Response};
use rustls::{AlertDescription, ClientConfig};
use rustls_pki_types::ServerName;
use tightbeam::clock::{Clock, ManualClock, SystemClock, UnixMillis};
use tightbeam::colony::cluster::{Cluster, ClusterGateway, EdgePlane};
use tightbeam::constants::DEFAULT_OPERATION_TIMEOUT;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::x509::policy::CertificateValidation;
use tightbeam::crypto::x509::store::{CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::KeyCurves;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::macros::BuiltAssertSpec;
use tightbeam::testing::{Expect, Layer, ScenarioConfig, ScenarioConfigError};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::handshake::PeerAuthentication;
use tightbeam::transport::multiplex::StreamBody;
use tightbeam::transport::{
	ConnectionBuilder, ConnectionPool, EncryptedProtocol, PoolConfig, PooledClient, Protocol,
	TransportEncryptionConfig, TransportError,
};
use tightbeam::urn::Urn;
use tightbeam::TightBeamError;
use tightbeam_grpc::couple::{
	CallClaim, CallerTrust, ClaimSigner, Coupler, Grants, Identities, Routes, Servlet, Voucher,
};
use tightbeam_grpc::edge::{Dial, Edge, EdgeProfile};
use tightbeam_grpc::events::COUPLED_SESSION_OPENED;
use tightbeam_grpc::protocol::{GrpcAddr, GrpcListener, HEALTH_WATCH_PATH, TUNNEL_PATH};
use tightbeam_grpc::testing::{OpenedStream, PartFrames, StreamParts, StreamSigners, TlsAuthority, TlsLeaf};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::{EchoService, EventWatch, Identity, WorkClient};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tonic::client::Grpc;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder, Streaming};
use tonic::metadata::MetadataValue;
use tonic::transport::{
	Certificate as TonicCertificate, Channel, ClientTlsConfig, Endpoint, Identity as TonicIdentity,
};
use tonic::{Request, Status};

/// The SPIFFE ID of the billing caller.
pub const BILLING: &str = "spiffe://acme/billing";

/// The subject of the web caller, and of the identity its claims sign under.
pub const WEB: &str = "CN=web,O=acme,C=US";

/// How long every identity of a scenario stays valid.
pub const LIFETIME: Duration = Duration::from_secs(3600);

/// How long a scenario waits for each answer of a peer.
pub const OPENING: Duration = Duration::from_secs(5);

/// The encoded `HealthCheckResponse` of `SERVING`.
pub const SERVING: [u8; 2] = [0x08, 0x01];

/// The encoded `HealthCheckResponse` of `NOT_SERVING`.
pub const NOT_SERVING: [u8; 2] = [0x08, 0x02];

/// The id of each direct stream.
const DIRECT_STREAM: &[u8; 16] = b"direct-stream-01";

/// The part ceiling that each direct stream declares.
const DIRECT_CEILING: u64 = 64 * 1024;

/// The server of a scenario, and the socket address it bound.
pub type Served<T = ()> = Result<(JoinHandle<T>, TightBeamSocketAddr), TightBeamError>;

/// Declare the staged profile `$edge` of one scenario, and the gateway
/// `$gateway` whose coupled edge binds under it.
#[macro_export]
macro_rules! coupled {
	($edge:ident, $gateway:ident) => {
		tightbeam_grpc::staged_profile! {
			/// The coupled edge of one scenario.
			$edge
		}

		tightbeam::cluster! {
			/// The gateway of one scenario, with its coupled edge.
			pub $gateway,
			protocol: tightbeam_ws::protocol::WsListener,
			edge: tightbeam_grpc::protocol::GrpcListener<tightbeam::crypto::profiles::DefaultCryptoProvider, $edge>
		}
	};
}

/// The codec of a stock call whose messages the scenario encodes itself.
#[derive(Clone, Copy, Debug, Default)]
pub struct RawCodec;

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
		Ok(Some(src.copy_to_bytes(length).to_vec()))
	}
}

/// The identities and the TLS PKI of one scenario.
pub struct Coupled {
	/// The colony: the gateway, the hive, and the servlet run under it.
	pub transport: Identity,
	/// The signer of the answers of the servlet, which each route pins.
	pub answers: Identity,
	/// The handshake identity of the loopback session of the coupler.
	pub session: Identity,
	/// The signer of the calls the coupler vouches for.
	pub vouching: Identity,
	/// The identity that the web caller signs its claims and its direct calls
	/// under.
	pub claims: Identity,
	/// The root of the TLS of the edge, of every caller, and of a backend.
	pub tls: TlsAuthority,
	/// The events that a servlet of the scenario waits on, when it holds a
	/// call until a count of one.
	pub events: &'static EventWatch,
	/// The clock that the edge and the adapter of the scenario run on.
	pub clock: ScenarioClock,
}

/// The clock that the edge and the adapter of a scenario run on.
#[derive(Clone, Default)]
pub enum ScenarioClock {
	/// The operating system's clocks, which pass every deadline themselves.
	#[default]
	System,
	/// A clock that the scenario moves.
	Manual(ManualScenario),
}

impl ScenarioClock {
	/// The clock as the edge and the adapter take it.
	pub fn edge(&self) -> Arc<dyn Clock> {
		match self {
			Self::System => Arc::new(SystemClock),
			Self::Manual(manual) => manual.edge(),
		}
	}

	/// Move the clock by `span`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of the operating system's clocks, which no scenario moves.
	/// - The errors of [`ManualScenario::moved`].
	pub fn advance(&self, span: Duration) -> Result<(), TightBeamError> {
		match self {
			Self::System => Err(unexpected("the scenario moves no clock")),
			Self::Manual(manual) => manual.moved(span),
		}
	}

	/// Move the clock up to the unix time of the operating system, which runs
	/// on while the scenario sets up, so a span that the scenario advances
	/// next counts from the readings of its callers.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of the operating system's clocks, which no scenario moves.
	/// - The errors of [`ManualScenario::moved`].
	pub fn catch_up(&self) -> Result<(), TightBeamError> {
		match self {
			Self::System => Err(unexpected("the scenario moves no clock")),
			Self::Manual(manual) => manual.catch_up(),
		}
	}

	/// Move the clock past the first probe of the next loopback session that
	/// opens, once the events of the scenario record that open. The operating
	/// system's clocks pass the probe themselves.
	///
	/// # Errors
	///
	/// - The errors of [`ManualScenario::opened`].
	pub async fn opened(&self) -> Result<(), TightBeamError> {
		match self {
			Self::System => Ok(()),
			Self::Manual(manual) => manual.opened().await,
		}
	}
}

/// A clock that a scenario moves, the events of the scenario, which record
/// each open of the loopback session of its coupler, and the count of the
/// opens that a wait of the scenario claimed, to move the clock past the
/// first probe of each.
#[derive(Clone)]
pub struct ManualScenario {
	clock: Arc<ManualClock>,
	events: &'static EventWatch,
	probed: Arc<AtomicUsize>,
}

impl ManualScenario {
	/// A clock at its start, whose opens `events` record.
	fn new(events: &'static EventWatch) -> Self {
		Self { clock: Arc::default(), events, probed: Arc::default() }
	}

	/// The clock as the edge and the adapter take it.
	fn edge(&self) -> Arc<dyn Clock> {
		Arc::clone(&self.clock) as Arc<dyn Clock>
	}

	/// Move the clock up to the unix time of the operating system.
	///
	/// # Errors
	///
	/// - The errors of [`ManualScenario::moved`].
	fn catch_up(&self) -> Result<(), TightBeamError> {
		let lag = UnixMillis::now().get().saturating_sub(self.clock.unix().get());
		self.moved(Duration::from_millis(lag))
	}

	/// Move the clock past the first probe of the next loopback session that
	/// opens, once the events record that open. Each call claims the next
	/// open before it waits.
	///
	/// # Errors
	///
	/// - The errors of [`EventWatch::recorded`] and [`ManualScenario::moved`].
	async fn opened(&self) -> Result<(), TightBeamError> {
		let next = self.probed.fetch_add(1, Ordering::AcqRel) + 1;
		self.events.recorded(COUPLED_SESSION_OPENED, next).await?;
		self.moved(Coupler::LIVENESS_PROBE)
	}

	/// Move the clock by `span`, while every advance of the scenario sums to
	/// less than the operation timeout of the edge transports on it.
	/// A cluster gateway binds its edge at the default limits.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of an advance that takes the sum to [`DEFAULT_OPERATION_TIMEOUT`].
	fn moved(&self, span: Duration) -> Result<(), TightBeamError> {
		let sum = self.clock.elapsed().saturating_add(span);
		if sum >= DEFAULT_OPERATION_TIMEOUT {
			return Err(unexpected(
				"the advances of the scenario reach the operation timeout of its edge",
			));
		}

		self.clock.advance(span);
		Ok(())
	}
}

/// The events of a scenario whose servlet holds no call.
static UNWATCHED: EventWatch = EventWatch::new();

impl Coupled {
	/// Create every identity of a scenario.
	pub fn mint() -> Self {
		let identity =
			|subject: &str, serial| Identity::mint(subject, serial, LIFETIME).expect("an identity is created");
		let tls = TlsAuthority::mint("CN=edge root,O=acme,C=US", LIFETIME).expect("a TLS root is created");
		Self {
			transport: identity("CN=colony,O=acme,C=US", 1),
			answers: identity("CN=orders servlet,O=acme,C=US", 2),
			session: identity("CN=coupler session,O=acme,C=US", 3),
			vouching: identity("CN=coupler,O=acme,C=US", 4),
			claims: identity(WEB, 5),
			tls,
			events: &UNWATCHED,
			clock: ScenarioClock::System,
		}
	}

	/// Create every identity of a scenario whose servlet waits on `events`.
	pub fn watched(events: &'static EventWatch) -> Self {
		Self { events, ..Self::mint() }
	}

	/// Create every identity of a scenario whose servlet waits on `events`,
	/// and whose edge and adapter run on a clock that the scenario moves.
	/// The clock starts once the identities exist, so the validity of each
	/// has begun on it.
	pub fn clocked(events: &'static EventWatch) -> Self {
		let minted = Self::mint();
		let clock = ScenarioClock::Manual(ManualScenario::new(events));
		Self { events, clock, ..minted }
	}

	/// The trust of the coupler in its callers: the TLS root, and the claims
	/// of the web caller.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a claim anchor that does not build, or of a TLS root that the trust
	///   refuses.
	pub fn callers(&self) -> Result<CallerTrust, TightBeamError> {
		CallerTrust::new([self.tls.root()], self.claims.trust_anchor()?).map_err(edge_error)
	}

	/// The coupler of the edge, which routes `routes` and grants `grants`.
	///
	/// # Errors
	///
	/// - The errors of [`Coupled::callers`] and [`Coupled::coupler_trusting`].
	pub fn coupler(&self, routes: Routes<Servlet>, grants: Grants) -> Result<Coupler, TightBeamError> {
		self.coupler_trusting(self.callers()?, routes, grants)
	}

	/// The coupler of the edge, which trusts `callers`, routes `routes`, and
	/// grants `grants`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a coupler that refuses `routes` or `grants`.
	pub fn coupler_trusting(
		&self,
		callers: CallerTrust,
		routes: Routes<Servlet>,
		grants: Grants,
	) -> Result<Coupler, TightBeamError> {
		let identities = Identities {
			handshake: self.session.signing_identity(),
			signer: self.vouching.signing_identity(),
		};
		let voucher = Voucher::new(identities);
		Coupler::new(callers, voucher, routes, grants).map_err(edge_error)
	}

	/// Stage the coupled edge of `coupler`, which records on `trace`, through
	/// `stage`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a TLS edge or a dial that the root of the scenario does not create.
	pub fn stage_coupler(
		&self,
		trace: &TraceCollector,
		stage: fn(Edge, Dial),
		coupler: Coupler,
	) -> Result<(), TightBeamError> {
		let tls = self.tls.edge("CN=orders edge,O=acme,C=US").map_err(mint_error)?;
		let dial = self.tls.dial().map_err(edge_error)?;
		let edge = Edge::coupled(tls, coupler).with_trace(trace.share());
		stage(edge.with_clock(self.clock.edge()), Dial::Tls(dial));
		Ok(())
	}

	/// The edge plane of `gateway`, `single_gateway`, `narrow_gateway` and
	/// `mutual_gateway`: on loopback, and open to the streams of the coupler.
	fn edge_plane() -> EdgePlane {
		EdgePlane::new("127.0.0.1:0").with_streams()
	}

	/// Start the gateway `G`, whose edge binds on loopback.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a gateway that does not start.
	pub async fn gateway<G: Cluster>(&self, trace: &TraceCollector) -> Result<G, TightBeamError> {
		let config = self.transport.cluster_config(Self::edge_plane())?;
		G::start(Arc::new(trace.share()), config).await
	}

	/// Start the gateway `G`, whose edge plane refuses every stream open.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a gateway that does not start.
	pub async fn unary_gateway<G: Cluster>(&self, trace: &TraceCollector) -> Result<G, TightBeamError> {
		let config = self.transport.cluster_config(EdgePlane::new("127.0.0.1:0"))?;
		G::start(Arc::new(trace.share()), config).await
	}

	/// Start the gateway `G`, which offers no mux, so the loopback session of
	/// its coupler carries one call at a time.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a gateway that does not start.
	pub async fn single_gateway<G: Cluster>(&self, trace: &TraceCollector) -> Result<G, TightBeamError> {
		let mut config = self.transport.cluster_config(Self::edge_plane())?;
		config.pool_config.mux_offer = None;
		G::start(Arc::new(trace.share()), config).await
	}

	/// Start the gateway `G`, which admits one stream at a time from each
	/// peer, so the loopback session of its coupler carries one call at once.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a gateway that does not start.
	pub async fn narrow_gateway<G: Cluster>(&self, trace: &TraceCollector) -> Result<G, TightBeamError> {
		let mut config = self.transport.cluster_config(Self::edge_plane())?;
		config.pool_config.mux_offer = Some(Arc::new(TransportOffer::mux(1)));
		G::start(Arc::new(trace.share()), config).await
	}

	/// Start the gateway `G`, whose accept planes authenticate each client
	/// under the certificates of `trusted` alone.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a trusted certificate that the store refuses, or of a gateway that does
	///   not start.
	pub async fn mutual_gateway<G: Cluster>(
		&self,
		trace: &TraceCollector,
		trusted: &[&Identity],
	) -> Result<G, TightBeamError> {
		let mut builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
		for identity in trusted {
			builder = builder.with_certificate(identity.certificate().clone())?;
		}

		let validator: Arc<dyn CertificateValidation> = Arc::new(builder.build());
		let mut config = self.transport.cluster_config(Self::edge_plane())?;
		config.tls.client_authentication = PeerAuthentication::Anonymous.and(validator);
		G::start(Arc::new(trace.share()), config).await
	}

	/// A channel to the edge of `gateway` under the billing caller, once the
	/// coupler serves.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a gateway with no edge.
	/// - The errors of [`Coupled::channel`] and [`StockChannel::serving`].
	pub async fn billing<E>(&self, gateway: &ClusterGateway<WsListener, E>) -> Result<StockChannel, TightBeamError>
	where
		E: Protocol<Address = GrpcAddr>,
	{
		let billing = self.billing_caller();
		let channel = self.channel(&WorkClient::edge_of(gateway)?, Some(&billing)).await?;
		channel.serving(&self.clock).await?;
		Ok(channel)
	}

	/// The web caller, and a channel to the edge of `gateway` under it once
	/// the coupler serves.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a gateway with no edge.
	/// - The errors of [`Coupled::channel`] and [`StockChannel::serving`].
	pub async fn web<E>(&self, gateway: &ClusterGateway<WsListener, E>) -> Result<WebCaller, TightBeamError>
	where
		E: Protocol<Address = GrpcAddr>,
	{
		let leaf = self.caller(WEB, None);
		let channel = self.channel(&WorkClient::edge_of(gateway)?, Some(&leaf)).await?;
		channel.serving(&self.clock).await?;
		Ok(WebCaller { leaf, channel })
	}

	/// The TLS client material of the billing caller, under [`BILLING`].
	pub fn billing_caller(&self) -> TlsLeaf {
		self.caller("CN=billing,O=acme,C=US", Some(BILLING))
	}

	/// The TLS client material of a caller named `subject`, with `spiffe` as
	/// its SPIFFE ID when it is `Some`.
	pub fn caller(&self, subject: &str, spiffe: Option<&str>) -> TlsLeaf {
		let created = self.tls.caller(subject, spiffe);
		created.expect("a caller certificate is created")
	}

	/// A stock tonic channel to the edge at `edge` that trusts the TLS root,
	/// and presents the chain of `caller` when it is `Some`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a TLS root that does not encode, or of an endpoint that does not connect
	///   within [`OPENING`].
	pub async fn channel(&self, edge: &GrpcAddr, caller: Option<&TlsLeaf>) -> Result<StockChannel, TightBeamError> {
		let root = TonicCertificate::from_pem(self.tls.root_pem().map_err(mint_error)?);
		let mut tls = ClientTlsConfig::new().ca_certificate(root).domain_name("localhost");
		if let Some(caller) = caller {
			tls = tls.identity(TonicIdentity::from_pem(caller.chain_pem(), caller.key_pem()));
		}

		let endpoint = Endpoint::from_shared(format!("https://{edge}")).map_err(unexpected)?;
		let endpoint = endpoint.tls_config(tls).map_err(unexpected)?;
		let channel = bounded(endpoint.connect()).await?.map_err(unexpected)?;
		Ok(StockChannel(channel))
	}

	/// The alert that the edge at `edge` ends the TLS handshake of `caller`
	/// with.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a TLS client that does not build, of a TCP connection that does not open
	///   within [`OPENING`], or of a handshake that does not end within it.
	/// - The [`TightBeamError`] of a handshake that ends or fails with no alert.
	pub async fn alert_of(&self, edge: &GrpcAddr, caller: &TlsLeaf) -> Result<AlertDescription, TightBeamError> {
		let config = H2Tunnel::tls(&self.tls, Some(caller))?;
		let tcp = bounded(tokio::net::TcpStream::connect(edge.to_string())).await??;
		let name = ServerName::try_from("localhost").map_err(unexpected)?;
		let read = async {
			let mut tls = TlsConnector::from(Arc::new(config)).connect(name, tcp).await?;
			tls.read(&mut [0_u8; 1]).await
		};

		let Err(failed) = bounded(read).await? else {
			return Err(unexpected("the handshake ended with no alert"));
		};

		let failed = failed.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>());
		match failed {
			Some(rustls::Error::AlertReceived(alert)) => Ok(*alert),
			_ => Err(unexpected("the handshake failed with no alert")),
		}
	}

	/// The claim signer of the web caller, bound to `caller`, which issues
	/// strictly increasing orders.
	pub fn signer(&self, caller: &TlsLeaf) -> ClaimSigner {
		ClaimSigner::new(self.claims.signing_identity(), [], caller.leaf())
	}

	/// The claim of the web caller over `body` for `method`, bound to `caller`,
	/// under a signer of its own.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a `method` that is no path, or of a signature that the signer does not
	///   make.
	pub async fn claim(&self, caller: &TlsLeaf, method: &str, body: &[u8]) -> Result<CallClaim, TightBeamError> {
		let signer = self.signer(caller);
		signer.sign(&method.parse().map_err(edge_error)?, body).await
	}

	/// A bidirectional stream on `route` straight over the colony plane at
	/// `colony`, with no coupler: its head and one message, signed under
	/// `signers`. The first message of the answer, or the failure that ended
	/// it.
	///
	/// # Errors
	///
	/// - The errors of [`Coupled::direct_answer`] and [`DirectAnswer::first`].
	pub async fn direct_stream(
		&self,
		colony: &<WsListener as Protocol>::Address,
		route: DirectRoute<'_>,
		signers: StreamSigners<'_>,
	) -> Result<Result<Option<Vec<u8>>, TransportError>, TightBeamError> {
		let answer = self.direct_answer(colony, route, signers, TransportOffer::mux(4)).await?;
		answer.first().await
	}

	/// The answer of the stream of [`Coupled::direct_stream`] on a connection
	/// that offers `offer`, which the caller reads when it chooses.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a trust anchor that does not build, or of a connection, a stream, a head
	///   or a part that does not open, sign, or push within [`OPENING`].
	pub async fn direct_answer(
		&self,
		colony: &<WsListener as Protocol>::Address,
		DirectRoute { servlet, method }: DirectRoute<'_>,
		signers: StreamSigners<'_>,
		offer: TransportOffer,
	) -> Result<DirectAnswer, TightBeamError> {
		let config = PoolConfig {
			idle_timeout: None,
			max_connections: NonZeroUsize::MIN,
			mux_offer: Some(Arc::new(offer)),
		};

		let pool = ConnectionPool::<WsListener>::builder().with_config(config);
		let pool = Arc::new(pool.with_trust_store(self.transport.trust_anchor()?).build());
		let ceiling = usize::try_from(DIRECT_CEILING).map_err(unexpected)?;
		let opened = async {
			let client = pool.connect(*colony).await?;
			let (mut sink, body) = client.open_duplex_to(servlet)?;

			let opened = StreamParts::open(method, DIRECT_STREAM, DIRECT_CEILING, signers).await?;
			let OpenedStream { head, mut parts } = opened;
			sink.push(&head).await?;
			sink.push(&parts.message(b"hello").await?).await?;
			sink.close().await?;
			Ok::<_, TightBeamError>(DirectAnswer { _client: client, body, read: PartFrames::new(ceiling) })
		};

		bounded(opened).await?
	}
}

/// The route of a direct stream: the servlet type that serves it, and the
/// method that its head names.
#[derive(Clone)]
pub struct DirectRoute<'a> {
	pub servlet: Urn<'static>,
	pub method: &'a str,
}

/// The messages of an answer that a direct stream read whole, and the
/// failure that ended it, or `None` for an answer that ended cleanly.
pub struct AnswerRead {
	pub messages: Vec<Vec<u8>>,
	pub failure: Option<TransportError>,
}

/// The answer of a direct stream, which its caller reads when it chooses.
pub struct DirectAnswer {
	/// The lease of the connection, which carries the stream until the answer
	/// drops.
	_client: PooledClient<WsListener>,
	body: StreamBody,
	/// The bytes of the answer that a read took, split into whole parts.
	read: PartFrames,
}

impl DirectAnswer {
	/// The first message of the answer, or the failure that ended it, within
	/// [`OPENING`].
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a part that does not decode, or of an answer that hangs.
	pub async fn first(mut self) -> Result<Result<Option<Vec<u8>>, TransportError>, TightBeamError> {
		let Self { body, read, .. } = &mut self;
		let reading = async {
			loop {
				match body.chunk().await {
					Ok(Some(chunk)) => read.extend(&chunk),
					Ok(None) => return Ok(Ok(None)),
					Err(error) => return Ok(Err(error)),
				}

				if let Some(answer) = read.next_frame()? {
					return Ok(Ok(StreamParts::message_of(&answer)?));
				}
			}
		};

		bounded(reading).await?
	}

	/// Wait, within [`OPENING`], until the first chunk of the answer arrives,
	/// which the later reads of the answer read first.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of an answer that ends or fails with no chunk, or that hangs.
	pub async fn arrived(&mut self) -> Result<(), TightBeamError> {
		let chunk = bounded(self.body.chunk()).await??;
		let chunk = chunk.ok_or_else(|| unexpected("the answer ended with no chunk"))?;
		self.read.extend(&chunk);
		Ok(())
	}

	/// The answer once all of it is read within [`OPENING`].
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a part that does not decode, or of an answer that hangs.
	pub async fn messages(mut self) -> Result<AnswerRead, TightBeamError> {
		let Self { body, read, .. } = &mut self;
		let mut messages = Vec::new();
		let reading = async {
			loop {
				let ended = match body.chunk().await {
					Ok(Some(chunk)) => {
						read.extend(&chunk);
						None
					}
					Ok(None) => Some(None),
					Err(error) => Some(Some(error)),
				};

				while let Some(part) = read.next_frame()? {
					messages.extend(StreamParts::message_of(&part)?);
				}

				if let Some(failure) = ended {
					return Ok(AnswerRead { messages, failure });
				}
			}
		};

		bounded(reading).await?
	}
}

/// One ASCII metadata entry of a stock call: its key, and its value.
pub struct Field {
	pub key: &'static str,
	pub value: String,
}

/// The web caller of a scenario, as [`Coupled::web`] gives it: its TLS
/// client material, and a channel to the edge under it.
pub struct WebCaller {
	pub leaf: TlsLeaf,
	pub channel: StockChannel,
}

/// A stock tonic channel to an edge, as a stock gRPC caller holds it.
#[derive(Clone)]
pub struct StockChannel(Channel);

impl From<Channel> for StockChannel {
	fn from(channel: Channel) -> Self {
		Self(channel)
	}
}

impl StockChannel {
	/// A stock client of the channel, once it is ready within [`OPENING`].
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a channel that fails, or that holds its readiness past [`OPENING`].
	pub async fn client(&self) -> Result<Grpc<Channel>, TightBeamError> {
		let mut grpc = Grpc::new(self.0.clone());
		bounded(grpc.ready()).await?.map_err(unexpected)?;
		Ok(grpc)
	}

	/// The channel itself, for a generated client.
	pub fn channel(&self) -> Channel {
		self.0.clone()
	}

	/// A unary call of `method` with `body`, and `claim` when it is `Some`:
	/// the answer, or the status that ended it.
	///
	/// # Errors
	///
	/// - The errors of [`StockChannel::client`] and of [`bounded`].
	pub async fn call(
		&self,
		method: &'static str,
		body: &[u8],
		claim: Option<&CallClaim>,
	) -> Result<Result<Vec<u8>, Status>, TightBeamError> {
		self.request(method, body, claim, None).await
	}

	/// A unary call of `method` with `body` and `claim`, with the deadline
	/// `within`, which the caller sends as `grpc-timeout`.
	///
	/// # Errors
	///
	/// - The errors of [`StockChannel::client`] and of [`bounded`].
	pub async fn call_within(
		&self,
		method: &'static str,
		body: &[u8],
		claim: &CallClaim,
		within: Duration,
	) -> Result<Result<Vec<u8>, Status>, TightBeamError> {
		self.request(method, body, Some(claim), Some(within)).await
	}

	/// A unary call of `method` with `body`, the ASCII metadata `metadata`,
	/// and `claim` when it is `Some`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a value that is no metadata.
	/// - The errors of [`StockChannel::client`] and of [`bounded`].
	pub async fn call_with(
		&self,
		method: &'static str,
		body: &[u8],
		metadata: &[Field],
		claim: Option<&CallClaim>,
	) -> Result<Result<Vec<u8>, Status>, TightBeamError> {
		let mut grpc = self.client().await?;
		let mut request = Request::new(body.to_vec());
		for Field { key, value } in metadata {
			let value = MetadataValue::try_from(value.as_str()).map_err(unexpected)?;
			request.metadata_mut().insert(*key, value);
		}

		if let Some(claim) = claim {
			claim.attach(request.metadata_mut());
		}

		let answered = bounded(grpc.unary(request, PathAndQuery::from_static(method), RawCodec)).await?;
		Ok(answered.map(tonic::Response::into_inner))
	}

	/// A unary call of `method` with `body` that appends each of `metadata` as
	/// its own header field.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a value that is no metadata.
	/// - The errors of [`StockChannel::client`] and of [`bounded`].
	pub async fn call_appending(
		&self,
		method: &'static str,
		body: &[u8],
		metadata: &[Field],
	) -> Result<Result<Vec<u8>, Status>, TightBeamError> {
		let mut grpc = self.client().await?;
		let mut request = Request::new(body.to_vec());
		for Field { key, value } in metadata {
			let value = MetadataValue::try_from(value.as_str()).map_err(unexpected)?;
			request.metadata_mut().append(*key, value);
		}

		let answered = bounded(grpc.unary(request, PathAndQuery::from_static(method), RawCodec)).await?;
		Ok(answered.map(tonic::Response::into_inner))
	}

	/// A streaming call of `method` that sends `messages`, under `claim` when
	/// it is `Some`: the messages of the answer, or the status that ended it.
	///
	/// # Errors
	///
	/// - The errors of [`StockChannel::client`] and of [`bounded`].
	pub async fn stream(
		&self,
		method: &'static str,
		messages: &[&[u8]],
		claim: Option<&CallClaim>,
	) -> Result<Result<Vec<Vec<u8>>, Status>, TightBeamError> {
		let mut grpc = self.client().await?;
		let messages: Vec<Vec<u8>> = messages.iter().map(|message| message.to_vec()).collect();
		let mut request = Request::new(stream::iter(messages));
		if let Some(claim) = claim {
			claim.attach(request.metadata_mut());
		}

		let answered = async {
			let response = grpc.streaming(request, PathAndQuery::from_static(method), RawCodec).await?;
			let mut answers = response.into_inner();
			let mut collected = Vec::new();
			while let Some(answer) = answers.message().await? {
				collected.push(answer);
			}

			Ok(collected)
		};

		bounded(answered).await
	}

	/// Wait until a health watch of the edge answers `SERVING`, by
	/// [`Watch::serving`].
	///
	/// # Errors
	///
	/// - The errors of [`StockChannel::watch`] and [`Watch::serving`].
	/// - The [`TightBeamError`] of a watch that the edge refuses.
	pub async fn serving(&self, clock: &ScenarioClock) -> Result<(), TightBeamError> {
		let mut answers = self.watch(&[]).await?.map_err(unexpected)?;
		answers.serving(clock).await
	}

	/// A health watch of `service`, an encoded `HealthCheckRequest`, once
	/// its head answers: its answers, or the status that refused it.
	///
	/// # Errors
	///
	/// - The errors of [`StockChannel::client`] and of [`bounded`].
	pub async fn watch(&self, service: &[u8]) -> Result<Result<Watch, Status>, TightBeamError> {
		let mut grpc = self.client().await?;
		let path = PathAndQuery::from_static(HEALTH_WATCH_PATH);
		let watched = grpc.server_streaming(Request::new(service.to_vec()), path, RawCodec);
		let watched = bounded(watched).await?;
		Ok(watched.map(|response| Watch(response.into_inner())))
	}

	/// One unary call, with `claim` and a deadline of `within` when each is
	/// `Some`.
	///
	/// # Errors
	///
	/// - The errors of [`StockChannel::client`] and of [`bounded`].
	async fn request(
		&self,
		method: &'static str,
		body: &[u8],
		claim: Option<&CallClaim>,
		within: Option<Duration>,
	) -> Result<Result<Vec<u8>, Status>, TightBeamError> {
		let mut grpc = self.client().await?;
		let mut request = Request::new(body.to_vec());
		if let Some(claim) = claim {
			claim.attach(request.metadata_mut());
		}

		if let Some(within) = within {
			request.set_timeout(within);
		}

		let path = PathAndQuery::from_static(method);
		let answered = bounded(grpc.unary(request, path, RawCodec)).await?;
		Ok(answered.map(tonic::Response::into_inner))
	}
}

/// The answers of one health watch.
pub struct Watch(Streaming<Vec<u8>>);

impl Watch {
	/// The next answer of the watch, `None` once the edge ends it with 0, or
	/// the status that ended it, within [`OPENING`].
	///
	/// # Errors
	///
	/// - The errors of [`bounded`].
	pub async fn next(&mut self) -> Result<Result<Option<Vec<u8>>, Status>, TightBeamError> {
		bounded(self.0.message()).await
	}

	/// Read the answers of the watch until one is `SERVING`, which the edge
	/// answers once the loopback session of the coupler opens and outlives
	/// its first probe, which `clock` passes.
	///
	/// # Errors
	///
	/// - The errors of [`Watch::next`] and [`ScenarioClock::opened`].
	/// - The [`TightBeamError`] of a watch that ends, or that fails, before it reads `SERVING`.
	pub async fn serving(&mut self, clock: &ScenarioClock) -> Result<(), TightBeamError> {
		while let Some(answer) = self.next().await?.map_err(unexpected)? {
			if answer == SERVING {
				return Ok(());
			}

			clock.opened().await?;
		}

		Err(unexpected("the watch ended before the coupler served"))
	}
}

/// `future`, a wait on a peer, within [`OPENING`].
///
/// # Errors
///
/// - The [`TightBeamError`] of a peer that holds the wait past [`OPENING`].
pub async fn bounded<F: Future>(future: F) -> Result<F::Output, TightBeamError> {
	tokio::time::timeout(OPENING, future).await.map_err(unexpected)
}

/// The failure of a profile, as the transport error that a bind reads.
pub fn edge_error(error: impl Into<tightbeam_grpc::edge::EdgeError>) -> TightBeamError {
	TightBeamError::from(TransportError::from(error.into()))
}

/// The failure of the test PKI, as an I/O error that holds the failure as its
/// inner error.
pub fn mint_error(error: tightbeam_grpc::testing::MintError) -> TightBeamError {
	unexpected(error)
}

/// A failure of a peer of a scenario, or of its timing, as an I/O failure of
/// the exchange that holds `error` as its inner error.
pub fn unexpected(error: impl Into<Box<dyn Error + Send + Sync>>) -> TightBeamError {
	TightBeamError::IoError(io::Error::other(error))
}

/// The configs of a scenario that a spec grades.
pub trait Graded {
	/// The config that grades a run with the spec on a trace of `events`,
	/// which its parties wait on.
	///
	/// # Errors
	///
	/// - The [`ScenarioConfigError`] of a config that does not build.
	fn watched(&'static self, events: &'static EventWatch) -> Result<ScenarioConfig, ScenarioConfigError>;

	/// The config that grades a run with the spec, and expects the spec to
	/// reject it.
	///
	/// # Errors
	///
	/// - The [`ScenarioConfigError`] of a config that does not build.
	fn rejected(&'static self) -> Result<ScenarioConfig, ScenarioConfigError>;
}

impl Graded for BuiltAssertSpec {
	fn watched(&'static self, events: &'static EventWatch) -> Result<ScenarioConfig, ScenarioConfigError> {
		ScenarioConfig::builder().with_trace(events.trace()).with_spec(self).build()
	}

	fn rejected(&'static self) -> Result<ScenarioConfig, ScenarioConfigError> {
		let config = ScenarioConfig::builder().with_spec(self);
		config.with_expect(Expect::Violation(Layer::Assertion)).build()
	}
}

/// The status code of a refused call.
pub fn code_of<T>(answer: Result<T, Status>) -> Option<tonic::Code> {
	answer.err().map(|status| status.code())
}

/// The identity of an encrypted server named `subject`, which its client
/// pins.
pub fn server_identity(subject: &str) -> Identity {
	let created = Identity::mint(subject, 1, LIFETIME);
	created.expect("a test identity is created")
}

/// The shared echo of `tightbeam-ws` on a gRPC listener of profile `C`, which
/// records each session on the trace of the scenario.
pub struct EchoServer;

impl EchoServer {
	/// The echo on `listener`, which offers `mux`.
	fn on<C: EdgeProfile>(
		listener: GrpcListener<DefaultCryptoProvider, C>,
		mux: Option<TransportOffer>,
		trace: &TraceCollector,
	) -> (JoinHandle<()>, TightBeamSocketAddr) {
		let addr = TightBeamSocketAddr(listener.local_addr());
		(EchoService::serve(listener, mux, trace), addr)
	}

	/// The echo on a cleartext listener on loopback.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a listener that does not bind.
	pub async fn cleartext<C: EdgeProfile>(trace: &TraceCollector) -> Served {
		let listener = GrpcListener::<DefaultCryptoProvider, C>::bind_cleartext("127.0.0.1:0").await?;
		Ok(Self::on(listener, None, trace))
	}

	/// The echo on an encrypted listener on loopback under `config`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a listener that does not bind.
	pub async fn encrypted<C: EdgeProfile>(
		config: TransportEncryptionConfig<DefaultCryptoProvider>,
		mux: Option<TransportOffer>,
		trace: &TraceCollector,
	) -> Served {
		let bind: GrpcAddr = "127.0.0.1:0".parse()?;
		let bound = <GrpcListener<DefaultCryptoProvider, C> as EncryptedProtocol>::bind_with(bind, config);
		let (listener, _addr) = bound.await?;
		Ok(Self::on(listener, mux, trace))
	}
}

/// A raw `h2` client of one edge, which writes the head of each tunnel call
/// by hand.
pub struct H2Tunnel {
	origin: String,
	calls: SendRequest<Bytes>,
}

impl H2Tunnel {
	/// An HTTP/2 connection to `addr` that opens with `header`, such as a
	/// PROXY header, and that a task of its own drives.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a TCP connection that does not open within [`OPENING`].
	/// - The [`TightBeamError`] of the HTTP/2 handshake of [`H2Tunnel`].
	pub async fn connect(addr: SocketAddr, header: &[u8]) -> Result<Self, TightBeamError> {
		let opened = async {
			let mut tcp = TcpStream::connect(addr).await?;
			tcp.write_all(header).await?;
			Ok::<_, io::Error>(tcp)
		};

		let tcp = bounded(opened).await??;
		Self::over(tcp, format!("http://{addr}")).await
	}

	/// An HTTP/2 connection over TLS to the edge at `addr`, which trusts the
	/// root of `authority`, presents the chain of `caller`, or no client
	/// certificate when it is `None`, as a browser does, and opens with
	/// `header` before its handshake.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a TLS client that does not build, or of a TLS connection that does not
	///   secure within [`OPENING`].
	/// - The [`TightBeamError`] of the HTTP/2 handshake of [`H2Tunnel`].
	pub async fn connect_tls(
		addr: impl ToSocketAddrs,
		header: &[u8],
		authority: &TlsAuthority,
		caller: Option<&TlsLeaf>,
	) -> Result<Self, TightBeamError> {
		let config = Self::tls(authority, caller)?;
		let name = ServerName::try_from("localhost").map_err(unexpected)?;
		let secured = async {
			let mut tcp = TcpStream::connect(addr).await?;
			tcp.write_all(header).await?;
			TlsConnector::from(Arc::new(config)).connect(name, tcp).await
		};

		let tls = bounded(secured).await??;
		Self::over(tls, "https://localhost".to_owned()).await
	}

	/// The TLS 1.3 client of a peer of an edge, under ring and with ALPN
	/// `h2`, which trusts the root of `authority` and presents the chain of
	/// `caller` when it is `Some`.
	fn tls(authority: &TlsAuthority, caller: Option<&TlsLeaf>) -> Result<ClientConfig, TightBeamError> {
		let mut roots = rustls::RootCertStore::empty();
		roots.add(authority.root()).map_err(unexpected)?;
		let provider = Arc::new(rustls::crypto::ring::default_provider());
		let config = ClientConfig::builder_with_provider(provider).with_protocol_versions(&[&rustls::version::TLS13]);
		let config = config.map_err(unexpected)?.with_root_certificates(roots);
		let mut config = match caller {
			Some(caller) => config.with_client_auth_cert(caller.chain(), caller.key()).map_err(unexpected)?,
			None => config.with_no_client_auth(),
		};

		config.alpn_protocols = vec![b"h2".to_vec()];
		Ok(config)
	}

	/// The client over `io`, whose calls name `origin`.
	async fn over<S>(io: S, origin: String) -> Result<Self, TightBeamError>
	where
		S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	{
		let (calls, connection) = bounded(h2::client::handshake(io)).await?.map_err(unexpected)?;
		tokio::spawn(async move {
			// The driver ends with the connection, and the scenario reads
			// each outcome from its calls.
			let _ = connection.await;
		});

		let calls = bounded(calls.ready()).await?.map_err(unexpected)?;
		Ok(Self { origin, calls })
	}

	/// The head of a call with `method` on `path` of the origin of the
	/// connection, under `content_type`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a head that does not build.
	pub fn head(
		&self,
		method: Method,
		path: &PathAndQuery,
		content_type: &str,
	) -> Result<http::Request<()>, TightBeamError> {
		let head = http::Request::builder().method(method).uri(format!("{}{path}", self.origin));
		let head = head.header(CONTENT_TYPE, content_type).header(TE, "trailers");
		head.body(()).map_err(unexpected)
	}

	/// The head of a well-formed tunnel call: `POST` on the tunnel path under
	/// `application/grpc`.
	///
	/// # Errors
	///
	/// - The errors of [`H2Tunnel::head`].
	pub fn tunnel_head(&self) -> Result<http::Request<()>, TightBeamError> {
		self.head(Method::POST, &PathAndQuery::from_static(TUNNEL_PATH), "application/grpc")
	}

	/// Open a call with `head`, and leave its request side open.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a connection that refuses a new call.
	pub fn open(&mut self, head: http::Request<()>) -> Result<(ResponseFuture, SendStream<Bytes>), TightBeamError> {
		self.calls.send_request(head, false).map_err(unexpected)
	}

	/// Open a call with `head`, write `message` on it, and read the head of
	/// the response within [`OPENING`]. A call with no message ends its
	/// request with its head.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a connection that refuses the call or its message, or of a head that does
	///   not arrive within [`OPENING`].
	pub async fn call(
		&mut self,
		head: http::Request<()>,
		message: Option<Bytes>,
	) -> Result<Response<RecvStream>, TightBeamError> {
		let ends_with_head = message.is_none();
		let (response, mut requests) = self.calls.send_request(head, ends_with_head).map_err(unexpected)?;
		if let Some(message) = message {
			requests.send_data(message, false).map_err(unexpected)?;
		}

		bounded(response).await?.map_err(unexpected)
	}

	/// The `grpc-status` of `response`: from its headers for a trailers-only
	/// response, or else from its trailers, within [`OPENING`].
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a body or trailers that do not arrive within [`OPENING`].
	pub async fn grpc_status(response: Response<RecvStream>) -> Result<Option<u32>, TightBeamError> {
		let from_headers = Self::status_of(response.headers());
		if from_headers.is_some() {
			return Ok(from_headers);
		}

		let mut body = response.into_body();
		let drained = bounded(async {
			while let Some(chunk) = body.data().await {
				chunk?;
			}
			body.trailers().await
		});
		let trailers = drained.await?.map_err(unexpected)?;
		Ok(trailers.as_ref().and_then(Self::status_of))
	}

	fn status_of(headers: &HeaderMap) -> Option<u32> {
		let status = headers.get("grpc-status")?;
		status.to_str().ok()?.parse().ok()
	}
}

/// A call of `method` from a page of `origin`.
#[derive(Clone, Copy)]
pub struct PageCall<'a> {
	pub method: &'a str,
	pub origin: &'a str,
}

/// The messages and the trailers of a gRPC-Web answer.
pub struct WebAnswer {
	pub messages: Vec<Vec<u8>>,
	pub trailers: String,
}

/// What a page read of one call.
pub struct PageRead {
	/// The HTTP status of the answer.
	pub status: http::StatusCode,
	/// The origin that the CORS answer allows.
	pub allowed: Option<String>,
	/// The response headers that the answer lets the page read.
	pub exposed: Option<String>,
	/// The body of the answer.
	pub body: Vec<u8>,
}

impl H2Tunnel {
	/// The preflight of a page before `call`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a call whose answer does not arrive whole within [`OPENING`].
	pub async fn preflight(&mut self, call: PageCall<'_>) -> Result<PageRead, TightBeamError> {
		let request = http::Request::builder().method(Method::OPTIONS);
		let request = request.header("access-control-request-method", "POST");
		let request = request.header("access-control-request-headers", "authorization,content-type,x-grpc-web");
		self.page_call(request, call, None).await
	}

	/// The gRPC-Web `call` with `message`, under the bearer `token`.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a message too long to frame, or of an answer that does not arrive whole
	///   within [`OPENING`].
	pub async fn web_call(
		&mut self,
		call: PageCall<'_>,
		message: &[u8],
		token: &str,
	) -> Result<PageRead, TightBeamError> {
		let request = http::Request::builder().method(Method::POST);
		let request = request
			.header("content-type", "application/grpc-web+proto")
			.header("x-grpc-web", "1");
		let request = request.header("authorization", format!("Bearer {token}"));
		let length = u32::try_from(message.len()).map_err(unexpected)?;
		let framed = [&[0][..], &length.to_be_bytes(), message].concat();
		self.page_call(request, call, Some(framed)).await
	}

	/// A gRPC-Web text call of `method` with `message`, from no page, under
	/// the bearer `token`: the messages and the trailers of its base64 answer.
	///
	/// # Errors
	///
	/// - The [`TightBeamError`] of a message too long to frame, or of an answer that does not arrive whole
	///   within [`OPENING`] or does not decode.
	pub async fn web_text_call(
		&mut self,
		method: &str,
		message: &[u8],
		token: &str,
	) -> Result<WebAnswer, TightBeamError> {
		use base64::engine::general_purpose::STANDARD;
		use base64::Engine;

		let head = http::Request::builder()
			.method(Method::POST)
			.uri(format!("{}{method}", self.origin));
		let head = head
			.header("content-type", "application/grpc-web-text")
			.header("x-grpc-web", "1");
		let head = head.header("accept", "application/grpc-web-text");
		let head = head
			.header("authorization", format!("Bearer {token}"))
			.body(())
			.map_err(unexpected)?;

		let length = u32::try_from(message.len()).map_err(unexpected)?;
		let framed = STANDARD.encode([&[0][..], &length.to_be_bytes(), message].concat());
		let (response, mut send) = self.calls.send_request(head, false).map_err(unexpected)?;
		send.send_data(Bytes::from(framed), true).map_err(unexpected)?;

		let response = bounded(response).await?.map_err(unexpected)?;
		let text = Self::read_body(response.into_body()).await?;

		let decoded: Vec<u8> = text
			.split(|byte| *byte == b'=')
			.filter(|piece| !piece.is_empty())
			.map(|piece| STANDARD.decode(Self::pad(piece)))
			.collect::<Result<Vec<_>, _>>()
			.map_err(unexpected)?
			.concat();
		Ok(Self::web_frames(&decoded))
	}

	/// The answer of a gRPC-Web answer body.
	pub fn web_frames(mut body: &[u8]) -> WebAnswer {
		let (mut messages, mut trailers) = (Vec::new(), String::new());
		while let Some((head, rest)) = body.split_first_chunk::<5>() {
			let length =
				usize::try_from(u32::from_be_bytes([head[1], head[2], head[3], head[4]])).unwrap_or(usize::MAX);
			let Some((frame, rest)) = rest.split_at_checked(length) else {
				break;
			};

			match head[0] & 0x80 {
				0 => messages.push(frame.to_vec()),
				_ => trailers.push_str(&String::from_utf8_lossy(frame)),
			}

			body = rest;
		}

		WebAnswer { messages, trailers }
	}

	/// The page `call`, as `request` builds its head, with `body` when it is
	/// `Some`.
	async fn page_call(
		&mut self,
		request: http::request::Builder,
		PageCall { method, origin }: PageCall<'_>,
		body: Option<Vec<u8>>,
	) -> Result<PageRead, TightBeamError> {
		let head = request.uri(format!("{}{method}", self.origin)).header("origin", origin);
		let head = head.body(()).map_err(unexpected)?;
		let (response, mut send) = self.calls.send_request(head, body.is_none()).map_err(unexpected)?;
		if let Some(body) = body {
			send.send_data(Bytes::from(body), true).map_err(unexpected)?;
		}

		let response = bounded(response).await?.map_err(unexpected)?;
		let status = response.status();
		let allowed = response
			.headers()
			.get("access-control-allow-origin")
			.and_then(|value| value.to_str().ok());
		let allowed = allowed.map(str::to_owned);
		let exposed = response.headers().get("access-control-expose-headers");
		let exposed = exposed.and_then(|value| value.to_str().ok()).map(str::to_owned);

		let body = Self::read_body(response.into_body()).await?;
		Ok(PageRead { status, allowed, exposed, body })
	}

	/// Every byte of `stream`, read to its end within [`OPENING`].
	async fn read_body(mut stream: RecvStream) -> Result<Vec<u8>, TightBeamError> {
		let reading = async {
			let mut read = Vec::new();
			while let Some(chunk) = stream.data().await {
				let chunk = chunk.map_err(unexpected)?;
				let _ = stream.flow_control().release_capacity(chunk.len());
				read.extend_from_slice(&chunk);
			}

			Ok(read)
		};

		bounded(reading).await?
	}

	/// `piece` of base64, padded back to a whole block.
	fn pad(piece: &[u8]) -> Vec<u8> {
		let mut padded = piece.to_vec();
		while !padded.len().is_multiple_of(4) {
			padded.push(b'=');
		}
		padded
	}
}
