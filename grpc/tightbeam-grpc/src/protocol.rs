//! The tightbeam protocol over a tunnel call on HTTP/2, which `docs/grpc.md`
//! describes.
//!
//! # Sources
//!
//! - RFC 9113, HTTP/2, June 2022, sections 3.2 and 3.3, HTTP/2 over TLS and
//!   with prior knowledge:
//!   <https://www.rfc-editor.org/rfc/rfc9113#section-3>

use core::fmt;
use core::marker::PhantomData;
use core::num::NonZeroUsize;
use core::str::FromStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use http::uri::Authority;
use rustls_pki_types::{DnsName, ServerName};
use tokio::net::{lookup_host, TcpListener};
use tokio::sync::mpsc::Receiver;
use tokio::sync::{oneshot, Mutex};
use tokio_util::sync::CancellationToken;
use tonic::transport::Endpoint;

use tightbeam::constants::DEFAULT_MAX_SERVER_CONNECTIONS;
use tightbeam::crypto::aead::{RecvCipher, SendCipher};
use tightbeam::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use tightbeam::transport::handshake::HandshakeProvider;
use tightbeam::transport::{
	AsyncListenerTrait, CheckedLimits, EncryptedProtocol, EndpointConfig, PersistentConnection, Protocol, TcpTransport,
	TightBeamAddress, TransportEncryptionConfig, TransportError,
};

use crate::edge::{EdgeProfile, H2c, PreparedEdge};
use crate::incoming::ServerSlots;
use crate::io::{GrpcStream, GrpcTransport};
use crate::tunnel::Arrival;

pub use crate::health::{HEALTH_CHECK_PATH, HEALTH_WATCH_PATH};
pub use crate::tunnel::TUNNEL_PATH;

/// The address of a tunnel: a host and a port, which a dial sends as
/// `:authority`, so a proxy that routes by host reaches the server behind it.
/// A bind resolves the host to a socket address.
///
/// # Examples
///
/// ```
/// use tightbeam::transport::TransportError;
/// use tightbeam_grpc::protocol::GrpcAddr;
///
/// let addr: GrpcAddr = "Gateway.Internal:7443".parse()?;
/// assert_eq!(addr.to_string(), "gateway.internal:7443");
///
/// let portless = "gateway.internal".parse::<GrpcAddr>();
/// assert!(matches!(portless, Err(TransportError::InvalidAddress)));
/// # Ok::<(), TransportError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrpcAddr {
	host: Host,
	port: u16,
}

/// The longest DNS name in its dotted text form, which RFC 1035 section
/// 2.3.4 bounds at 255 octets.
const MAX_NAME: usize = 253;

/// The longest label of a DNS name, in octets (RFC 1035 section 2.3.4).
const MAX_LABEL: usize = 63;

/// The host of a [`GrpcAddr`]: an IP address, or a registered name in lower
/// case, which a TLS dial verifies the server under as it is.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Host {
	Ip(IpAddr),
	Name(DnsName<'static>),
}

impl Host {
	/// The host of `text`, the host part of an authority: an IPv6 address in
	/// brackets, an IPv4 address, or a DNS name of labels of letters, digits,
	/// and inner hyphens, whose last label is not all digits (RFC 1123
	/// section 2.1).
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidAddress`] -- the text is none of the three.
	fn parse(text: &str) -> Result<Self, TransportError> {
		if let Some(bracketed) = text.strip_prefix('[') {
			let literal = bracketed.strip_suffix(']').ok_or(TransportError::InvalidAddress)?;
			let ip = Ipv6Addr::from_str(literal).map_err(|_| TransportError::InvalidAddress)?;
			return Ok(Self::Ip(IpAddr::V6(ip)));
		}

		if let Ok(ip) = Ipv4Addr::from_str(text) {
			return Ok(Self::Ip(IpAddr::V4(ip)));
		}

		let labels: Vec<&str> = text.split('.').collect();
		let numeric_last = labels.last().is_some_and(|last| last.bytes().all(|byte| byte.is_ascii_digit()));
		let is_name = text.len() <= MAX_NAME && !numeric_last && labels.into_iter().all(Self::is_label);
		if !is_name {
			return Err(TransportError::InvalidAddress);
		}

		let name = DnsName::try_from(text.to_ascii_lowercase()).map_err(|_| TransportError::InvalidAddress)?;
		Ok(Self::Name(name))
	}

	/// Whether `label` is one label of a DNS name: one to 63 letters, digits,
	/// and hyphens, with no hyphen at either end.
	fn is_label(label: &str) -> bool {
		let bytes = label.as_bytes();
		let length = (1..=MAX_LABEL).contains(&bytes.len());
		let characters = bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-');
		let ends = !label.starts_with('-') && !label.ends_with('-');

		length && characters && ends
	}

	/// The name that a TLS dial verifies the server under: the IP address, or
	/// the DNS name.
	fn server_name(&self) -> ServerName<'static> {
		match self {
			Self::Ip(ip) => ServerName::IpAddress((*ip).into()),
			Self::Name(name) => ServerName::DnsName(name.clone()),
		}
	}
}

/// The host form of an authority: an IPv6 address in brackets, an IPv4
/// address, or the DNS name.
impl fmt::Display for Host {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]"),
			Self::Ip(IpAddr::V4(ip)) => write!(f, "{ip}"),
			Self::Name(name) => f.write_str(name.as_ref()),
		}
	}
}

/// Parses an authority with a host, a port, and no user information, such as
/// `127.0.0.1:0`, `[::1]:7443`, or `gateway.internal:7443`.
///
/// # Errors
///
/// - [`TransportError::InvalidAddress`] -- the text is no authority, names no port or no
///   host, carries user information, or names a host that is no address or name.
impl FromStr for GrpcAddr {
	type Err = TransportError;

	fn from_str(text: &str) -> Result<Self, Self::Err> {
		let authority = Authority::from_str(text).map_err(|_| TransportError::InvalidAddress)?;
		let port = authority.port_u16().ok_or(TransportError::InvalidAddress)?;
		if authority.as_str().contains('@') {
			return Err(TransportError::InvalidAddress);
		}

		let host = Host::parse(authority.host())?;
		Ok(Self { host, port })
	}
}

/// The address of a bound or accepted socket. An authority carries no IPv6
/// zone, so the address drops it.
impl From<SocketAddr> for GrpcAddr {
	fn from(addr: SocketAddr) -> Self {
		let host = Host::Ip(addr.ip());
		Self { host, port: addr.port() }
	}
}

/// The authority form: `host:port`, with an IPv6 host in brackets.
impl fmt::Display for GrpcAddr {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}:{}", self.host, self.port)
	}
}

/// The octets of the authority form.
impl From<GrpcAddr> for Vec<u8> {
	fn from(addr: GrpcAddr) -> Self {
		addr.to_string().into_bytes()
	}
}

impl TightBeamAddress for GrpcAddr {}

impl GrpcAddr {
	/// The tonic endpoint of a dial to the address, under the `http` scheme.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidAddress`] -- tonic refuses the URI of the address.
	pub(crate) fn endpoint(&self) -> Result<Endpoint, TransportError> {
		Endpoint::from_shared(format!("http://{self}")).map_err(|_| TransportError::InvalidAddress)
	}

	/// The name that a TLS dial verifies the server under: the IP address, or
	/// the DNS name, of the host.
	pub(crate) fn server_name(&self) -> ServerName<'static> {
		self.host.server_name()
	}

	/// Bind the first socket address that the host resolves to and that binds.
	///
	/// # Errors
	///
	/// - The [`io::Error`] of the resolve, or of the last bind that failed.
	async fn bind(&self) -> io::Result<TcpListener> {
		let mut last_failure = io::Error::from(io::ErrorKind::AddrNotAvailable);
		let candidates = lookup_host(self.to_string()).await?;
		for candidate in candidates {
			match TcpListener::bind(candidate).await {
				Ok(listener) => return Ok(listener),
				Err(error) => last_failure = error,
			}
		}

		Err(last_failure)
	}
}

/// A tightbeam listener that speaks the protocol over tunnel calls, under the
/// deployment that its profile `C` provisions.
///
/// - Every accepted transport builds from the one [`EndpointConfig`] that the
///   listener holds, so its provisioning and ceilings reach each connection.
/// - `C` provisions each bind through [`EdgeProfile::edge`] and each dial
///   through [`EdgeProfile::dial`]. The default, [`H2c`], runs no TLS, so a
///   bare `GrpcListener` is the h2c listener.
/// - Under a profile that binds [`Edge::tls`](crate::edge::Edge::tls), each
///   connection completes its TLS handshake under its slot and before its
///   deadline, or closes, before any byte reaches the HTTP/2 server.
/// - The listener serves on a task of its own, so a tunnel call queues
///   whether or not a caller waits in [`accept`](Self::accept).
/// - The drop of the listener closes the socket and ends every tunnel that no
///   caller took.
///
/// # Examples
///
/// ```
/// use tightbeam_grpc::protocol::GrpcListener;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), tightbeam::transport::TransportError> {
/// let listener: GrpcListener = GrpcListener::bind_cleartext("127.0.0.1:0").await?;
/// assert!(listener.local_addr().ip().is_loopback());
/// # Ok(())
/// # }
/// ```
pub struct GrpcListener<P: CryptoProvider = DefaultCryptoProvider, C: EdgeProfile = H2c> {
	arrivals: Mutex<Receiver<Arrival>>,
	/// Cancelled when the server task ends for any cause, so a waiting accept
	/// returns although a connection task still holds the queue.
	stopped: CancellationToken,
	/// Its drop stops the server.
	_shutdown: oneshot::Sender<()>,
	local_addr: SocketAddr,
	config: EndpointConfig<P>,
	_profile: PhantomData<fn() -> C>,
}

impl<P: HandshakeProvider + Send + Sync + 'static, C: EdgeProfile> GrpcListener<P, C> {
	/// Provision and prepare the bind of `C` under `config`, then bind
	/// `addr`, so a profile whose provision fails binds no socket.
	///
	/// # Errors
	///
	/// - The [`TransportError`] of the [`crate::edge::EdgeError`] of the profile.
	/// - [`TransportError::IoError`] -- the host resolves to no address that binds.
	async fn provision(
		addr: &GrpcAddr,
		config: &EndpointConfig<P>,
	) -> Result<(TcpListener, PreparedEdge), TransportError> {
		let edge = C::edge()?.prepare(config)?;
		let listener = addr.bind().await?;
		Ok((listener, edge))
	}

	/// Start the server on `listener` under `edge`, with one slot per
	/// connection a server admits by default.
	fn serve(listener: TcpListener, config: EndpointConfig<P>, edge: PreparedEdge) -> Result<Self, TransportError> {
		Self::with_slots(listener, config, DEFAULT_MAX_SERVER_CONNECTIONS, edge)
	}

	/// The one constructor: start the server on `listener` under `edge`, with
	/// `capacity` slots.
	fn with_slots(
		listener: TcpListener,
		config: EndpointConfig<P>,
		capacity: NonZeroUsize,
		edge: PreparedEdge,
	) -> Result<Self, TransportError> {
		let local_addr = listener.local_addr()?;
		let config = edge.clocked(config);
		let limits = config.limits();

		let ServerSlots { slots, queue, arrivals } = ServerSlots::new(capacity);
		let bind = edge.bind::<P, C>(queue, local_addr, limits);

		let (shutdown, signal) = oneshot::channel::<()>();
		let stopping = async {
			let _ = signal.await;
		};

		let server = bind.serve(listener, slots, stopping);

		let stopped = CancellationToken::new();
		let finished = stopped.clone();
		tokio::spawn(async move {
			let _stopped = finished.drop_guard();
			let _ = server.await;
		});

		Ok(Self {
			arrivals: Mutex::new(arrivals),
			stopped,
			_shutdown: shutdown,
			local_addr,
			config,
			_profile: PhantomData,
		})
	}

	/// Bind a cleartext listener to `addr`, such as `127.0.0.1:0`.
	///
	/// - Its transports run no tightbeam handshake, so they carry no end-to-end
	///   confidentiality, integrity, or peer authentication (CWE-319).
	/// - TLS under the profile `C` protects each hop to the listener alone.
	/// - [`EncryptedProtocol::bind_with`] binds an encrypted listener.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidAddress`] -- `addr` is no [`GrpcAddr`].
	/// - The [`TransportError`] of the [`crate::edge::EdgeError`] of the profile.
	/// - [`TransportError::IoError`] -- the host resolves to no address that binds.
	pub async fn bind_cleartext(addr: impl AsRef<str>) -> Result<Self, TransportError> {
		let addr = GrpcAddr::from_str(addr.as_ref())?;
		let config = EndpointConfig::cleartext();
		let (listener, edge) = Self::provision(&addr, &config).await?;
		Self::serve(listener, config, edge)
	}

	/// The local address that the listener is bound to, with the port that
	/// the system picked for a bind on port 0.
	pub fn local_addr(&self) -> SocketAddr {
		self.local_addr
	}
}

impl<P: HandshakeProvider + Send + Sync + 'static, C: EdgeProfile> GrpcListener<P, C> {
	/// Accept the next live tunnel as a transport built from this listener's
	/// configuration. A tunnel whose call ended before a caller took it is
	/// passed over.
	///
	/// Cancel safe: a tunnel stays queued until this call returns it.
	///
	/// # Errors
	///
	/// - [`TransportError::IoError`] -- the listener failed to accept a TCP connection.
	/// - [`TransportError::ConnectionClosed`] -- the server stopped.
	pub async fn accept(&self) -> Result<(GrpcTransport<P>, SocketAddr), TransportError> {
		let mut arrivals = self.arrivals.lock().await;
		loop {
			let arrival = tokio::select! {
				biased;
				arrival = arrivals.recv() => arrival,
				() = self.stopped.cancelled() => None,
			};

			let tunnel = arrival.ok_or(TransportError::ConnectionClosed)??;
			if let Some((stream, peer)) = tunnel.into_stream() {
				let transport = TcpTransport::new(stream, self.config.clone());
				return Ok((transport, peer));
			}
		}
	}
}

impl<P: HandshakeProvider + Send + Sync + 'static, C: EdgeProfile> Protocol for GrpcListener<P, C> {
	type Listener = GrpcListener<P, C>;
	type Stream = GrpcStream;
	type Transport = GrpcTransport<P>;
	type Error = TransportError;
	type Address = GrpcAddr;
	type CryptoProvider = P;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		GrpcAddr::from_str("127.0.0.1:0")
	}

	async fn bind_cleartext(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let config = EndpointConfig::cleartext();
		let (listener, edge) = Self::provision(&addr, &config).await?;

		let bound = Self::serve(listener, config, edge)?;
		let local_addr = GrpcAddr::from(bound.local_addr);
		Ok((bound, local_addr))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		Self::connect_within(addr, &CheckedLimits::default()).await
	}

	/// Provision the dial of `C`, then dial the tunnel at `addr` under it.
	async fn connect_within(addr: Self::Address, limits: &CheckedLimits) -> Result<Self::Stream, Self::Error> {
		let dial = C::dial()?;
		GrpcStream::dial(&addr, limits, &dial).await
	}

	fn create_transport(stream: Self::Stream, config: EndpointConfig<P>) -> Self::Transport {
		TcpTransport::new(stream, config)
	}
}

impl<P: HandshakeProvider + Send + Sync + 'static, C: EdgeProfile> EncryptedProtocol for GrpcListener<P, C> {
	type Encryptor = SendCipher;
	type Decryptor = RecvCipher;

	async fn bind_with(
		addr: Self::Address,
		config: TransportEncryptionConfig<P>,
	) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let config = EndpointConfig::try_from(config)?;
		let (listener, edge) = Self::provision(&addr, &config).await?;

		let bound = Self::serve(listener, config, edge)?;
		let local_addr = GrpcAddr::from(bound.local_addr);
		Ok((bound, local_addr))
	}
}

impl<P: HandshakeProvider + Send + Sync + 'static, C: EdgeProfile> AsyncListenerTrait for GrpcListener<P, C> {
	async fn accept(&self) -> Result<(Self::Transport, Self::Address), Self::Error> {
		let (transport, peer) = GrpcListener::accept(self).await?;
		Ok((transport, GrpcAddr::from(peer)))
	}
}

/// Pooling support: lets tunnel endpoints sit behind tightbeam's
/// [`ConnectionPool`](tightbeam::transport::ConnectionPool), and therefore
/// the colony stack, reusing one encrypted, multiplexed connection across
/// leases.
impl<P: HandshakeProvider + Send + Sync + 'static, C: EdgeProfile> PersistentConnection for GrpcListener<P, C> {
	fn is_connected(transport: &Self::Transport) -> bool {
		transport.is_leasable()
	}

	fn try_close(_transport: &mut Self::Transport) {
		// The tunnel ends when the transport drops.
	}
}

#[cfg(test)]
mod tests {
	use core::future::{poll_fn, Future};
	use core::pin::pin;
	use core::task::Poll;
	use core::time::Duration;
	use std::io;
	use std::sync::Arc;

	use bytes::Bytes;
	use h2::client::{ResponseFuture, SendRequest};
	use h2::{Ping, PingPong, SendStream};
	use http::header::{CONTENT_TYPE, TE};
	use http::{Method, Request};
	use tokio::net::TcpStream;
	use tokio::task::JoinHandle;
	use tokio::time::timeout;

	use tightbeam::clock::{Clock, ManualClock, SystemClock};
	use tightbeam::testing::macros::BuiltAssertSpec;
	use tightbeam::testing::specs::ProcessSpec;
	use tightbeam::testing::{ScenarioConfig, ScenarioConfigError, SetupEnv};
	use tightbeam::trace::TraceCollector;
	use tightbeam::transport::{AsyncProtocolStream, MessageIO, TransportFailure, TransportLimits};
	use tightbeam::urn::Urn;
	use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario, urn, TightBeamError};

	use super::*;
	use crate::edge::{Dial, Edge};
	use crate::events::EDGE_REFUSED;

	type BoxError = Box<dyn std::error::Error + Send + Sync>;

	/// How long a healthy dial, accept, or close may take on loopback, which
	/// bounds a wait that would hang.
	const PROMPT: Duration = Duration::from_secs(2);

	/// The idle deadline of the scenarios that watch a connection close, past
	/// [`PROMPT`], so only an advance of the clock of the plane closes it in
	/// time.
	const IDLE: Duration = Duration::from_secs(10);

	/// The span short of [`IDLE`] that a scenario advances first, at which the
	/// connection still answers.
	const SHORT_OF_IDLE: Duration = IDLE.saturating_sub(Duration::from_millis(1));

	/// A dial that completed, of the first peer of a scenario.
	const FIRST_DIALED: Urn<'static> = urn!("test", "event:plane/first-dialed");

	/// A dial that completed, of a later peer of a scenario.
	const NEXT_DIALED: Urn<'static> = urn!("test", "event:plane/next-dialed");

	/// A tunnel that a caller of `accept` took, of the first peer.
	const FIRST_ACCEPTED: Urn<'static> = urn!("test", "event:plane/first-accepted");

	/// A tunnel that a caller of `accept` took, of a later peer.
	const NEXT_ACCEPTED: Urn<'static> = urn!("test", "event:plane/next-accepted");

	/// A tunnel that a caller of `accept` took, of the sentinel peer.
	const SENTINEL_ACCEPTED: Urn<'static> = urn!("test", "event:plane/sentinel-accepted");

	/// A connection that the plane closed, as its peer read the close.
	const CLOSED: Urn<'static> = urn!("test", "event:plane/closed");

	/// The `grpc-status` that a peer read of a tunnel call.
	const CALL_STATUS: Urn<'static> = urn!("test", "event:plane/call-status");

	/// The `grpc-status` that a peer read of a tunnel call that the plane
	/// refused.
	const REFUSED_STATUS: Urn<'static> = urn!("test", "event:plane/refused-status");

	/// A ping that the plane answered a millisecond before the deadline of its
	/// connection.
	const ANSWERED_BEFORE: Urn<'static> = urn!("test", "event:plane/answered-before");

	/// A read of an accepted tunnel transport that its read deadline ended.
	const READ_LAPSED: Urn<'static> = urn!("test", "event:plane/read-lapsed");

	/// The failure of a wait of a scenario, or of a peer, as an I/O error that
	/// holds the failure as its inner error.
	fn unexpected(error: impl Into<BoxError>) -> TightBeamError {
		TightBeamError::IoError(io::Error::other(error))
	}

	/// `future`, within [`PROMPT`], so a wait that hangs fails the scenario.
	async fn prompt<F: Future>(future: F) -> Result<F::Output, TightBeamError> {
		timeout(PROMPT, future).await.map_err(unexpected)
	}

	/// The config that grades a run with `spec` and the order of `process`.
	fn ordered(
		spec: &'static BuiltAssertSpec,
		process: impl ProcessSpec + Send + Sync + 'static,
	) -> Result<ScenarioConfig, ScenarioConfigError> {
		ScenarioConfig::builder().with_spec(spec).with_csp(process).build()
	}

	/// A cleartext listener with `capacity` slots under `limits`, on an
	/// ephemeral loopback port, whose edge records on `trace` and runs on
	/// `clock`.
	async fn plane(
		limits: TransportLimits,
		capacity: usize,
		trace: &TraceCollector,
		clock: Arc<dyn Clock>,
	) -> Result<GrpcListener, TightBeamError> {
		let capacity = NonZeroUsize::new(capacity).ok_or_else(|| unexpected("a plane holds one slot or more"))?;
		let listener = TcpListener::bind("127.0.0.1:0").await?;
		let config = EndpointConfig::cleartext().with_limits(limits)?;
		let edge = Edge::h2c()
			.with_trace(trace.share())
			.with_clock(clock)
			.prepare(&config)
			.map_err(TransportError::from)?;
		Ok(GrpcListener::with_slots(listener, config, capacity, edge)?)
	}

	/// A plane on the operating system's clocks, for a scenario that waits on
	/// no deadline of the plane.
	fn system() -> Arc<dyn Clock> {
		Arc::new(SystemClock)
	}

	/// Limits whose connections close after `IDLE` with no call.
	fn idle_limits() -> TransportLimits {
		TransportLimits { handshake_timeout: IDLE, ..TransportLimits::default() }
	}

	/// Dial a tunnel to `plane` under the default limits.
	async fn dial(plane: &GrpcListener) -> Result<GrpcStream, TightBeamError> {
		let (addr, limits) = (GrpcAddr::from(plane.local_addr()), TransportLimits::default());
		Ok(prompt(GrpcStream::dial(&addr, &limits, &Dial::H2c)).await??)
	}

	/// The next tunnel that a caller of `accept` takes from `plane`, and the
	/// peer of its connection.
	async fn accepted(
		plane: &GrpcListener,
	) -> Result<(GrpcTransport<DefaultCryptoProvider>, SocketAddr), TightBeamError> {
		Ok(prompt(plane.accept()).await??)
	}

	/// An HTTP/2 connection to a plane from the `h2` client, and the task that
	/// drives it, whose end is the end of the connection.
	struct H2Connection {
		calls: SendRequest<Bytes>,
		pings: PingPong,
		driver: JoinHandle<Result<(), h2::Error>>,
		authority: SocketAddr,
		local: SocketAddr,
	}

	impl H2Connection {
		/// Open a connection, and ping it once, so the plane answers it under
		/// a lane, which read its deadline when the plane accepted it.
		async fn open(plane: &GrpcListener) -> Result<Self, TightBeamError> {
			let authority = plane.local_addr();
			let tcp = TcpStream::connect(authority).await?;
			let local = tcp.local_addr()?;
			let (calls, mut connection) = prompt(h2::client::handshake(tcp)).await?.map_err(unexpected)?;
			let pings = connection
				.ping_pong()
				.ok_or_else(|| unexpected("a new connection holds its pings"))?;
			let driver = tokio::spawn(connection);

			let mut opened = Self { calls, pings, driver, authority, local };
			opened.ping().await?;
			Ok(opened)
		}

		/// Ping the plane, and wait for its answer.
		async fn ping(&mut self) -> Result<(), TightBeamError> {
			prompt(self.pings.ping(Ping::opaque())).await?.map_err(unexpected)?;
			Ok(())
		}

		/// Ping the plane, and record on `trace` that it answered.
		async fn answered(&mut self, trace: &TraceCollector) -> Result<(), TightBeamError> {
			self.ping().await?;
			trace.event(ANSWERED_BEFORE)?;
			Ok(())
		}

		/// Open a call on the tunnel path with `headers` added to its head.
		async fn call(
			&mut self,
			headers: &[(&'static str, &'static str)],
		) -> Result<(ResponseFuture, SendStream<Bytes>), TightBeamError> {
			let uri = format!("http://{}{TUNNEL_PATH}", self.authority);
			let mut head = Request::builder().method(Method::POST).uri(uri);
			head = head.header(CONTENT_TYPE, "application/grpc").header(TE, "trailers");

			for (name, value) in headers {
				head = head.header(*name, *value);
			}

			let mut calls = prompt(self.calls.clone().ready()).await?.map_err(unexpected)?;
			let call = calls.send_request(head.body(()).map_err(unexpected)?, false);
			call.map_err(unexpected)
		}

		/// Wait until the plane closes the connection, and record the close on
		/// `trace`.
		async fn closed(&mut self, trace: &TraceCollector) -> Result<(), TightBeamError> {
			let _ended = prompt(&mut self.driver).await?;
			trace.event(CLOSED)?;
			Ok(())
		}
	}

	/// The `grpc-status` of the trailers of `response`, recorded on `trace`.
	async fn trailed(response: ResponseFuture, trace: &TraceCollector) -> Result<(), TightBeamError> {
		let response = prompt(response).await?.map_err(unexpected)?;
		let mut responses = response.into_body();
		let trailers = prompt(responses.trailers()).await?.map_err(unexpected)?;
		let status = trailers.as_ref().and_then(|trailers| trailers.get("grpc-status"));
		let status = status.map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
		trace.event_with(CALL_STATUS, &[], status.unwrap_or_default())?;
		Ok(())
	}

	tb_assert_spec! {
		/// Two dials of a plane of one slot, and both of their tunnels taken.
		pub FullPlaneSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(FIRST_DIALED, exactly!(1)),
				(FIRST_ACCEPTED, exactly!(1)),
				(NEXT_DIALED, exactly!(1)),
				(NEXT_ACCEPTED, exactly!(1)),
				(EDGE_REFUSED, exactly!(0))
			]
		}
	}

	tb_process_spec! {
		/// The second dial of a full plane completes only once a caller took
		/// the tunnel of the first, which returns the one slot.
		pub FullPlaneOrder,
		events {
			observable { FIRST_DIALED, FIRST_ACCEPTED, NEXT_DIALED, NEXT_ACCEPTED }
			hidden { }
		}
		states {
			Open => { FIRST_DIALED => Dialed },
			Dialed => { FIRST_ACCEPTED => Freed },
			Freed => { NEXT_DIALED => Waited },
			Waited => { NEXT_ACCEPTED => Done },
			Done => { }
		}
		terminal { Done }
	}

	tb_scenario! {
		name: a_full_plane_takes_a_dial_once_a_tunnel_is_accepted,
		config: ordered(FullPlaneSpec::latest(), FullPlaneOrder),
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let plane = Arc::new(plane(TransportLimits::default(), 1, &trace, system()).await?);
				let _first = dial(&plane).await?;
				trace.event(FIRST_DIALED)?;

				let (waiting, recorded) = (Arc::clone(&plane), trace.share());
				let second = tokio::spawn(async move {
					let dialed = dial(&waiting).await?;
					recorded.event(NEXT_DIALED)?;
					Ok::<_, TightBeamError>(dialed)
				});

				accepted(&plane).await?;
				trace.event(FIRST_ACCEPTED)?;
				let _second = prompt(second).await?.map_err(unexpected)??;
				accepted(&plane).await?;
				trace.event(NEXT_ACCEPTED)?;
				Ok(())
			}
		}
	}

	tb_assert_spec! {
		/// A connection with no call, which answers a millisecond before its
		/// deadline and closes at it, then a dial that takes its slot.
		pub IdleCloseSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(ANSWERED_BEFORE, exactly!(1)),
				(CLOSED, exactly!(1)),
				(NEXT_DIALED, exactly!(1)),
				(EDGE_REFUSED, exactly!(0))
			]
		}
	}

	tb_scenario! {
		name: a_connection_with_no_call_closes_at_its_deadline_and_returns_its_slot,
		spec: IdleCloseSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let clock = Arc::new(ManualClock::default());
				let plane = plane(idle_limits(), 1, &trace, Arc::clone(&clock) as Arc<dyn Clock>).await?;
				let mut idle = H2Connection::open(&plane).await?;

				clock.advance(SHORT_OF_IDLE);
				idle.answered(&trace).await?;
				clock.advance(IDLE - SHORT_OF_IDLE);
				idle.closed(&trace).await?;

				let _next = dial(&plane).await?;
				trace.event(NEXT_DIALED)?;
				Ok(())
			}
		}
	}

	tb_assert_spec! {
		/// Two tunnels in turn on one connection under the one slot: each ends
		/// with status 0 and a caller takes each, and the connection then
		/// closes at the deadline that the end of the second one read.
		pub NextCallSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(FIRST_ACCEPTED, exactly!(1)),
				(CALL_STATUS, exactly!(2), equals!("0")),
				(NEXT_ACCEPTED, exactly!(1)),
				(CLOSED, exactly!(1)),
				(EDGE_REFUSED, exactly!(0))
			]
		}
	}

	tb_scenario! {
		name: a_connection_whose_tunnel_ended_carries_the_next_call_under_the_one_slot,
		spec: NextCallSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let clock = Arc::new(ManualClock::default());
				let plane = plane(idle_limits(), 1, &trace, Arc::clone(&clock) as Arc<dyn Clock>).await?;
				let mut connection = H2Connection::open(&plane).await?;

				let (response, requests) = connection.call(&[]).await?;
				let (transport, _peer) = accepted(&plane).await?;
				trace.event(FIRST_ACCEPTED)?;
				drop(transport);
				trailed(response, &trace).await?;

				// The server resets the request side once its response is
				// complete (RFC 9113 section 8.1), so the stream has closed
				// both ways.
				drop(requests);

				let (next, next_requests) = connection.call(&[]).await?;
				accepted(&plane).await?;
				trace.event(NEXT_ACCEPTED)?;
				// The end of the second call returns the connection to its
				// slot under a fresh deadline before the trailers of the call.
				trailed(next, &trace).await?;
				drop(next_requests);
				clock.advance(IDLE);
				connection.closed(&trace).await
			}
		}
	}

	tb_assert_spec! {
		/// A connection whose tunnel ends short of its first deadline: it
		/// answers past that deadline, and closes at the deadline that the end
		/// of the tunnel read.
		pub RenewedSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CALL_STATUS, exactly!(1), equals!("0")),
				(ANSWERED_BEFORE, exactly!(1)),
				(CLOSED, exactly!(1)),
				(EDGE_REFUSED, exactly!(0))
			]
		}
	}

	tb_scenario! {
		name: a_connection_whose_tunnel_ended_waits_out_the_deadline_from_its_end,
		spec: RenewedSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let clock = Arc::new(ManualClock::default());
				let plane = plane(idle_limits(), 1, &trace, Arc::clone(&clock) as Arc<dyn Clock>).await?;
				let mut connection = H2Connection::open(&plane).await?;

				clock.advance(SHORT_OF_IDLE);
				let (response, requests) = connection.call(&[]).await?;
				let (transport, _peer) = accepted(&plane).await?;
				drop(transport);
				trailed(response, &trace).await?;
				drop(requests);

				clock.advance(IDLE - SHORT_OF_IDLE);
				connection.answered(&trace).await?;
				clock.advance(SHORT_OF_IDLE);
				connection.closed(&trace).await
			}
		}
	}

	tb_assert_spec! {
		/// A tunnel that ends while a dial holds the one slot: the next call of
		/// its connection is refused with 14 as `no-slot`, and the connection
		/// drains.
		pub DrainedSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CALL_STATUS, exactly!(1)),
				(REFUSED_STATUS, exactly!(1), equals!("14")),
				(EDGE_REFUSED, exactly!(1), equals!("no-slot")),
				(CLOSED, exactly!(1))
			]
		}
	}

	tb_scenario! {
		name: a_connection_whose_tunnel_ends_with_no_free_slot_refuses_its_next_call_and_drains,
		spec: DrainedSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let clock = Arc::new(ManualClock::default());
				let plane = plane(idle_limits(), 1, &trace, Arc::clone(&clock) as Arc<dyn Clock>).await?;
				let mut connection = H2Connection::open(&plane).await?;

				let (response, requests) = connection.call(&[]).await?;
				let (transport, _peer) = accepted(&plane).await?;
				let _holder = dial(&plane).await?;

				drop(transport);
				trailed(response, &trace).await?;
				drop(requests);

				let (refused, _refused_requests) = connection.call(&[]).await?;
				let refused = prompt(refused).await?.map_err(unexpected)?;
				let status = refused.headers().get("grpc-status");
				let status = status.map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
				trace.event_with(REFUSED_STATUS, &[], status.unwrap_or_default())?;

				// The refusal drained the connection under the deadline that
				// the end of its tunnel or the refusal read, whichever came
				// first.
				clock.advance(IDLE);
				connection.closed(&trace).await
			}
		}
	}

	tb_assert_spec! {
		/// A tunnel that no caller takes, whose connection answers a
		/// millisecond before its deadline and closes at it, then a dial that
		/// takes its slot and a caller that takes its tunnel.
		pub IdleTunnelSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(ANSWERED_BEFORE, exactly!(1)),
				(CLOSED, exactly!(1)),
				(NEXT_DIALED, exactly!(1)),
				(NEXT_ACCEPTED, exactly!(1)),
				(EDGE_REFUSED, exactly!(0))
			]
		}
	}

	tb_scenario! {
		name: a_tunnel_no_caller_takes_closes_its_connection_at_its_deadline,
		spec: IdleTunnelSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let clock = Arc::new(ManualClock::default());
				let plane = plane(idle_limits(), 1, &trace, Arc::clone(&clock) as Arc<dyn Clock>).await?;
				let mut connection = H2Connection::open(&plane).await?;

				// The head answers once the plane queued the tunnel under its
				// deadline.
				let (silent, _silent_requests) = connection.call(&[]).await?;
				let _head = prompt(silent).await?.map_err(unexpected)?;
				clock.advance(SHORT_OF_IDLE);
				connection.answered(&trace).await?;
				clock.advance(IDLE - SHORT_OF_IDLE);
				connection.closed(&trace).await?;

				let _next = dial(&plane).await?;
				trace.event(NEXT_DIALED)?;
				accepted(&plane).await?;
				trace.event(NEXT_ACCEPTED)?;
				Ok(())
			}
		}
	}

	tb_assert_spec! {
		/// A call reset before any caller took its tunnel, then a tunnel of
		/// another connection, the next call of the reset connection, and a
		/// sentinel, each taken once.
		pub ResetSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(FIRST_ACCEPTED, exactly!(1)),
				(NEXT_ACCEPTED, exactly!(1)),
				(SENTINEL_ACCEPTED, exactly!(1)),
				(EDGE_REFUSED, exactly!(0))
			]
		}
	}

	tb_process_spec! {
		/// A caller of `accept` takes the tunnel of the other connection first,
		/// so the reset call holds no slot. The sentinel comes last, so nothing
		/// else was queued.
		pub ResetOrder,
		events {
			observable { FIRST_ACCEPTED, NEXT_ACCEPTED, SENTINEL_ACCEPTED }
			hidden { }
		}
		states {
			Open => { FIRST_ACCEPTED => Other },
			Other => { NEXT_ACCEPTED => Next },
			Next => { SENTINEL_ACCEPTED => Done },
			Done => { }
		}
		terminal { Done }
	}

	tb_scenario! {
		name: a_call_reset_before_accept_holds_no_second_slot_and_never_reaches_a_caller,
		config: ordered(ResetSpec::latest(), ResetOrder),
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let plane = plane(TransportLimits::default(), 2, &trace, system()).await?;
				let mut connection = H2Connection::open(&plane).await?;

				// Each tunnel that a caller takes records the role of its peer.
				let reset_peer = connection.local;
				let role = move |peer: SocketAddr, sentinel: Option<SocketAddr>| match peer {
					peer if Some(peer) == sentinel => SENTINEL_ACCEPTED,
					peer if peer == reset_peer => NEXT_ACCEPTED,
					_ => FIRST_ACCEPTED,
				};

				let (reset, mut reset_requests) = connection.call(&[]).await?;
				reset_requests.send_reset(h2::Reason::CANCEL);
				drop(reset);

				let _other = dial(&plane).await?;
				let (_other_tunnel, peer) = accepted(&plane).await?;
				trace.event(role(peer, None))?;

				let (_next, _next_requests) = connection.call(&[]).await?;
				let (_next_tunnel, peer) = accepted(&plane).await?;
				trace.event(role(peer, None))?;

				let mut sentinel = H2Connection::open(&plane).await?;
				let (_sentinel, _sentinel_requests) = sentinel.call(&[]).await?;
				let (_sentinel_tunnel, peer) = accepted(&plane).await?;
				trace.event(role(peer, Some(sentinel.local)))?;
				Ok(())
			}
		}
	}

	tb_assert_spec! {
		/// A call that tonic refuses after its parse with 12, a millisecond
		/// before the deadline of its connection, which still closes at it.
		pub UnrenewedSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CALL_STATUS, exactly!(1), equals!("12")),
				(CLOSED, exactly!(1)),
				(EDGE_REFUSED, exactly!(0))
			]
		}
	}

	// A call refused after its parse holds no lane, so the connection closes
	// one millisecond after it, at the deadline that its open read.
	tb_scenario! {
		name: calls_refused_after_their_parse_never_renew_the_deadline,
		spec: UnrenewedSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let clock = Arc::new(ManualClock::default());
				let plane = plane(idle_limits(), 1, &trace, Arc::clone(&clock) as Arc<dyn Clock>).await?;
				let mut connection = H2Connection::open(&plane).await?;

				clock.advance(SHORT_OF_IDLE);
				let (refused, _requests) = connection.call(&[("grpc-encoding", "gzip")]).await?;
				let refused = prompt(refused).await?.map_err(unexpected)?;
				let status = refused.headers().get("grpc-status");
				let status = status.map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
				trace.event_with(CALL_STATUS, &[], status.unwrap_or_default())?;

				clock.advance(IDLE - SHORT_OF_IDLE);
				connection.closed(&trace).await
			}
		}
	}

	tb_assert_spec! {
		/// A tunnel whose dialer stays silent: the read of the transport that a
		/// caller of `accept` took ends at the read deadline of the plane.
		pub SilentTunnelSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(READ_LAPSED, exactly!(1)),
				(EDGE_REFUSED, exactly!(0))
			]
		}
	}

	// The read deadline of an accepted transport runs on the clock of the
	// plane, so the read ends once the clock passes it, and only then.
	tb_scenario! {
		name: a_tunnel_read_ends_at_the_read_deadline_on_the_clock_of_the_plane,
		spec: SilentTunnelSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let clock = Arc::new(ManualClock::default());
				let limits = TransportLimits { operation_timeout: IDLE, ..TransportLimits::default() };
				let plane = plane(limits, 1, &trace, Arc::clone(&clock) as Arc<dyn Clock>).await?;
				let _silent = dial(&plane).await?;
				let (mut transport, _peer) = accepted(&plane).await?;

				// The first poll reads the deadline of the read and waits.
				let mut read = pin!(transport.read_envelope_bytes());
				let waits = poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx).is_pending())).await;
				if !waits {
					return Err(unexpected("the read of a silent tunnel MUST wait"));
				}

				clock.advance(IDLE);
				let lapsed = prompt(read).await?;
				if !matches!(lapsed, Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded))) {
					return Err(unexpected(format!("the read MUST end at its deadline, got {lapsed:?}")));
				}

				trace.event(READ_LAPSED)?;
				Ok(())
			}
		}
	}

	tb_assert_spec! {
		/// A tunnel that no caller took, which the drop of its listener ends.
		pub DroppedTunnelSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CLOSED, exactly!(1)),
				(EDGE_REFUSED, exactly!(0))
			]
		}
	}

	tb_scenario! {
		name: a_dropped_listener_ends_every_tunnel_no_caller_took,
		spec: DroppedTunnelSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let plane = plane(TransportLimits::default(), 2, &trace, system()).await?;
				let mut stream = dial(&plane).await?;
				drop(plane);

				let read = prompt(stream.read_frame(64)).await?;
				if !matches!(read, Err(TransportError::ConnectionClosed)) {
					return Err(unexpected(format!("the tunnel MUST end with its listener, got {read:?}")));
				}
				trace.event(CLOSED)?;
				Ok(())
			}
		}
	}

	tb_assert_spec! {
		/// An idle connection, which the drop of its listener closes.
		pub DroppedConnectionSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CLOSED, exactly!(1)),
				(EDGE_REFUSED, exactly!(0))
			]
		}
	}

	tb_scenario! {
		name: a_dropped_listener_closes_its_idle_connections,
		spec: DroppedConnectionSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let plane = plane(TransportLimits::default(), 2, &trace, system()).await?;
				let mut connection = H2Connection::open(&plane).await?;
				drop(plane);
				connection.closed(&trace).await
			}
		}
	}

	#[test]
	fn an_address_parses_a_host_and_a_port_and_nothing_else() {
		let parsed = ["127.0.0.1:0", "[::1]:7443", "Gateway.Internal:7443", "edge-1.example:80"];
		let printed = ["127.0.0.1:0", "[::1]:7443", "gateway.internal:7443", "edge-1.example:80"];
		for (text, expected) in parsed.into_iter().zip(printed) {
			let addr = GrpcAddr::from_str(text).map(|addr| addr.to_string());
			assert_eq!(addr.ok().as_deref(), Some(expected));
		}

		let refused = [
			"gateway.internal",
			":80",
			"*:1",
			"[foo]:1",
			"user@host:1",
			"under_score:1",
			"999.1.1.1:1",
			"a..b:1",
			"-edge:1",
			"edge-:1",
			"edge.:1",
			"",
		];
		for text in refused {
			assert!(matches!(GrpcAddr::from_str(text), Err(TransportError::InvalidAddress)));
		}
	}
}
