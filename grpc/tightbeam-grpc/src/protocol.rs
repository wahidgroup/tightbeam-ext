//! gRPC protocol implementation for tightbeam.
//!
//! [`GrpcListener`] implements tightbeam's [`Protocol`], [`EncryptedProtocol`],
//! and [`AsyncListenerTrait`] traits over a tunnel call on HTTP/2, so a cluster
//! gateway declares `edge: GrpcListener` the way it declares a WebSocket edge.
//! The [`EdgeProfile`] of the listener decides whether HTTP/2 runs with prior
//! knowledge (h2c), the default, or over TLS 1.3.
//!
//! # Sources
//!
//! - RFC 9113, HTTP/2, June 2022, sections 3.2 and 3.3, HTTP/2 over TLS and with prior knowledge: <https://www.rfc-editor.org/rfc/rfc9113#section-3>

use core::fmt;
use core::marker::PhantomData;
use core::num::NonZeroUsize;
use core::str::FromStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[cfg(feature = "couple")]
use std::sync::Arc;

use http::uri::Authority;
use rustls_pki_types::ServerName;
use tokio::net::{lookup_host, TcpListener};
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::{oneshot, Mutex};
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;

#[cfg(feature = "couple")]
use tokio::sync::Semaphore;

use tightbeam::constants::DEFAULT_MAX_SERVER_CONNECTIONS;
use tightbeam::crypto::aead::{RecvCipher, SendCipher};
use tightbeam::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use tightbeam::transport::handshake::HandshakeProvider;
use tightbeam::transport::{
	AsyncListenerTrait, CheckedLimits, EncryptedProtocol, EndpointConfig, PersistentConnection, Protocol, TcpTransport,
	TightBeamAddress, TransportEncryptionConfig, TransportError,
};

#[cfg(feature = "instrument")]
use tightbeam::trace::TraceCollector;

use crate::edge::{Edge, EdgeProfile, H2c};
use crate::incoming::{GrpcIncoming, LaneTerms, Slots};
use crate::io::{GrpcStream, GrpcTransport};
use crate::service::{EdgeService, Served};
use crate::tunnel::{Arrival, RefusalAudit, TunnelService};

#[cfg(feature = "couple")]
use crate::couple::LiveCoupler;
#[cfg(feature = "couple")]
use crate::edge::EdgeError;

pub use crate::health::HEALTH_CHECK_PATH;

/// The permits of the coupled connections of an edge, which only a coupled
/// edge holds.
#[cfg(feature = "couple")]
type CoupledLanes = Option<Arc<Semaphore>>;

/// An edge with no coupler holds no coupled connection.
#[cfg(not(feature = "couple"))]
type CoupledLanes = ();
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

/// The longest DNS name, in octets (RFC 1035 section 2.3.4).
const MAX_NAME: usize = 253;

/// The longest label of a DNS name, in octets (RFC 1035 section 2.3.4).
const MAX_LABEL: usize = 63;

/// The host of a [`GrpcAddr`]: an IP address, or a registered name in lower
/// case, because a DNS name compares without case.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Host {
	Ip(IpAddr),
	Name(String),
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

		Ok(Self::Name(text.to_ascii_lowercase()))
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
		match &self.host {
			Host::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
			Host::Ip(IpAddr::V4(ip)) => write!(f, "{ip}:{}", self.port),
			Host::Name(name) => write!(f, "{name}:{}", self.port),
		}
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
	/// The name that a TLS dial verifies the server under: the IP address, or
	/// the DNS name, of the host.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidAddress`] -- rustls refuses the DNS name.
	pub(crate) fn server_name(&self) -> Result<ServerName<'static>, TransportError> {
		match &self.host {
			Host::Ip(ip) => Ok(ServerName::IpAddress((*ip).into())),
			Host::Name(name) => ServerName::try_from(name.clone()).map_err(|_| TransportError::InvalidAddress),
		}
	}

	/// Bind the first socket address that the host resolves to and that binds.
	///
	/// # Errors
	///
	/// - The I/O error of the resolve, or of the last bind that failed.
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
/// Every accepted transport builds from the one [`EndpointConfig`] the
/// listener holds, so the listener's provisioning and ceilings reach each
/// connection.
///
/// `C` provisions each bind through [`EdgeProfile::edge`] and each dial
/// through [`EdgeProfile::dial`]. [`H2c`], the default, runs no TLS, so
/// `GrpcListener` names the h2c listener. Under a profile that binds
/// [`Edge::Tls`], each connection completes its TLS handshake under its slot
/// and before its deadline, or closes, before any byte reaches the HTTP/2
/// server.
///
/// The listener serves on a task of its own, so a tunnel call queues whether
/// or not a caller is waiting in [`accept`](Self::accept). The drop of the
/// listener stops the server: it closes the socket, and every tunnel that no
/// caller took ends.
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
	/// Shared with the service of the server, which records each call it
	/// refuses on it.
	#[cfg(feature = "instrument")]
	refusals: RefusalAudit,
	_profile: PhantomData<fn() -> C>,
}

impl<P: HandshakeProvider + Send + Sync + 'static, C: EdgeProfile> GrpcListener<P, C> {
	/// Provision the bind of `C`, then bind `addr`, so a profile that cannot
	/// provision binds no socket.
	///
	/// # Errors
	///
	/// - The [`TransportError`] of the [`crate::edge::EdgeError`] of the profile.
	/// - [`TransportError::IoError`] -- the host resolves to no address that binds.
	async fn provision(addr: &GrpcAddr) -> Result<(TcpListener, Edge), TransportError> {
		let edge = C::edge()?;
		let listener = addr.bind().await?;
		Ok((listener, edge))
	}

	/// Start the server on `listener` under `edge`, with one slot per
	/// connection a server admits by default.
	fn serve(listener: TcpListener, config: EndpointConfig<P>, edge: &Edge) -> Result<Self, TransportError> {
		Self::with_slots(listener, config, DEFAULT_MAX_SERVER_CONNECTIONS, edge)
	}

	/// The one constructor: start the server on `listener` under `edge`, with
	/// `capacity` slots.
	fn with_slots(
		listener: TcpListener,
		config: EndpointConfig<P>,
		capacity: NonZeroUsize,
		edge: &Edge,
	) -> Result<Self, TransportError> {
		let local_addr = listener.local_addr()?;
		let limits = config.limits();
		let ceiling = limits.max_envelope();

		// A live tunnel holds a slot, so the queue holds every live tunnel and
		// one failed accept. A coupler sends its loopback tunnel with a send
		// that waits for room, so it never drops.
		let slots = Slots::new(capacity.get());
		let (queue, arrivals) = mpsc::channel(capacity.get() + 1);
		let (served, coupled) = Self::served(edge, &config, &queue, local_addr, ceiling)?;
		#[cfg(not(feature = "couple"))]
		let () = coupled;

		let streams = edge.stream_limit();
		let terms = LaneTerms {
			idle: limits.handshake_timeout,
			replaces: streams == 1,
			#[cfg(feature = "couple")]
			coupled,
		};

		let acceptor = edge.acceptor()?;
		let incoming = GrpcIncoming::new(listener, slots, terms, acceptor, queue.clone());
		let refusals = RefusalAudit::default();
		// A gateway binds its edge through `bind_with`, which takes no trace,
		// so a coupled edge records its refusals on the trace of its coupler.
		#[cfg(all(feature = "couple", feature = "instrument"))]
		if let Some(trace) = edge.trace() {
			refusals.attach(trace.share());
		}

		let tunnel = TunnelService::new(queue, ceiling, refusals.clone());
		let service = EdgeService::new(tunnel, refusals.clone(), served);

		let (shutdown, signal) = oneshot::channel::<()>();
		let stopping = async {
			let _ = signal.await;
		};

		let builder = Server::builder().max_concurrent_streams(streams);
		let server = builder.serve_with_incoming_shutdown(service, incoming, stopping);

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
			#[cfg(feature = "instrument")]
			refusals,
			_profile: PhantomData,
		})
	}

	/// What the edge serves beside its tunnel, and the permits of its coupled
	/// connections: the tunnel alone for an h2c or a TLS edge, and the coupler
	/// of a coupled edge, which starts here under the certificate that `config`
	/// presents, so its loopback session pins it.
	///
	/// # Errors
	///
	/// - [`EdgeError::RequiresEncryption`] -- a coupled edge binds in the clear.
	/// - The errors of the coupler as it starts.
	#[cfg_attr(not(feature = "couple"), allow(unused_variables))]
	fn served(
		edge: &Edge,
		config: &EndpointConfig<P>,
		queue: &mpsc::Sender<Arrival>,
		local: SocketAddr,
		ceiling: usize,
	) -> Result<(Served<P>, CoupledLanes), TransportError> {
		match edge {
			Edge::H2c | Edge::Tls(_) => Ok((Served::Tunnel(PhantomData), CoupledLanes::default())),
			#[cfg(feature = "couple")]
			Edge::Coupled(_, coupler) => {
				let gateway = config.encryption().server_certificate().ok_or(EdgeError::RequiresEncryption)?;
				let live = LiveCoupler::start::<C>(coupler.clone(), queue.clone(), local, gateway, ceiling)?;
				let lanes = live.lanes();
				Ok((Served::Coupled(Arc::new(live)), Some(lanes)))
			}
		}
	}

	/// Record each call that this listener refuses before any session exists
	/// on `trace`, as [`TUNNEL_REFUSED`], in place of the trace of an earlier
	/// call.
	///
	/// The server runs from the bind on, so a call that it refuses before
	/// this attach records nothing. A session that a tunnel opens records on
	/// the trace of its own transport, which `server!` attaches through
	/// `with_trace`. A listener
	/// that a colony gateway binds for its edge takes no trace, because the
	/// gateway binds it through [`EncryptedProtocol::bind_with`].
	///
	/// [`TUNNEL_REFUSED`]: crate::events::TUNNEL_REFUSED
	#[cfg(feature = "instrument")]
	#[must_use]
	pub fn with_trace(self, trace: TraceCollector) -> Self {
		self.refusals.attach(trace);
		self
	}

	/// Bind a cleartext listener to `addr`, such as `127.0.0.1:0`.
	///
	/// Accepted transports run no tightbeam handshake, so they carry no
	/// end-to-end confidentiality, integrity, or peer authentication
	/// (CWE-319), and the name says it. TLS under the profile `C` protects
	/// each hop to the listener alone. An encrypted bind goes through
	/// [`EncryptedProtocol::bind_with`].
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidAddress`] -- `addr` is no [`GrpcAddr`].
	/// - The [`TransportError`] of the [`crate::edge::EdgeError`] of the profile.
	/// - [`TransportError::IoError`] -- the host resolves to no address that binds.
	pub async fn bind_cleartext(addr: impl AsRef<str>) -> Result<Self, TransportError> {
		let addr = GrpcAddr::from_str(addr.as_ref())?;
		let (listener, edge) = Self::provision(&addr).await?;
		let config = EndpointConfig::cleartext();
		Self::serve(listener, config, &edge)
	}

	/// The local address the listener is bound to.
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
		let (listener, edge) = Self::provision(&addr).await?;
		let config = EndpointConfig::cleartext();

		let bound = Self::serve(listener, config, &edge)?;
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
		let (listener, edge) = Self::provision(&addr).await?;

		let bound = Self::serve(listener, config, &edge)?;
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
	use core::time::Duration;
	use std::sync::Arc;

	use bytes::Bytes;
	use h2::client::{ResponseFuture, SendRequest};
	use h2::SendStream;
	use http::header::{CONTENT_TYPE, TE};
	use http::{Method, Request};
	use tokio::io::AsyncReadExt;
	use tokio::net::TcpStream;
	use tokio::task::JoinHandle;
	use tokio::time::{timeout, Instant};

	use tightbeam::transport::{AsyncProtocolStream, TransportLimits};

	use super::*;
	use crate::edge::Dial;

	type BoxError = Box<dyn std::error::Error + Send + Sync>;
	type TestResult = Result<(), BoxError>;

	/// How long a healthy dial, accept, or close may take on loopback.
	const PROMPT: Duration = Duration::from_secs(2);

	/// How long a test watches for a dial that MUST NOT finish.
	const HELD: Duration = Duration::from_millis(200);

	/// The idle deadline of the tests that watch a connection close.
	const IDLE: Duration = Duration::from_millis(400);

	/// A cleartext listener with `capacity` slots under `limits`, on an
	/// ephemeral loopback port.
	async fn plane(limits: TransportLimits, capacity: usize) -> Result<GrpcListener, BoxError> {
		let capacity = NonZeroUsize::new(capacity).ok_or("a plane holds one slot or more")?;
		let listener = TcpListener::bind("127.0.0.1:0").await?;
		let config = EndpointConfig::cleartext().with_limits(limits)?;
		Ok(GrpcListener::with_slots(listener, config, capacity, &Edge::H2c)?)
	}

	/// Limits whose connections close after `IDLE` with no call.
	fn idle_limits() -> TransportLimits {
		TransportLimits { handshake_timeout: IDLE, ..TransportLimits::default() }
	}

	/// Dial a tunnel to `plane` under the default limits.
	async fn dial(plane: &GrpcListener) -> Result<GrpcStream, TransportError> {
		let addr = GrpcAddr::from(plane.local_addr());
		GrpcStream::dial(&addr, &TransportLimits::default(), &Dial::H2c).await
	}

	/// An HTTP/2 connection to a plane from the `h2` client, and the task that
	/// drives it, whose end is the end of the connection.
	struct H2Connection {
		calls: SendRequest<Bytes>,
		driver: JoinHandle<Result<(), h2::Error>>,
		authority: SocketAddr,
		local: SocketAddr,
	}

	impl H2Connection {
		async fn open(plane: &GrpcListener) -> Result<Self, BoxError> {
			let authority = plane.local_addr();
			let tcp = TcpStream::connect(authority).await?;
			let local = tcp.local_addr()?;
			let (calls, connection) = h2::client::handshake(tcp).await?;
			let driver = tokio::spawn(connection);
			Ok(Self { calls, driver, authority, local })
		}

		/// Open a call on the tunnel path with `headers` added to its head.
		async fn call(
			&mut self,
			headers: &[(&'static str, &'static str)],
		) -> Result<(ResponseFuture, SendStream<Bytes>), BoxError> {
			let uri = format!("http://{}{TUNNEL_PATH}", self.authority);
			let mut head = Request::builder().method(Method::POST).uri(uri);
			head = head.header(CONTENT_TYPE, "application/grpc").header(TE, "trailers");

			for (name, value) in headers {
				head = head.header(*name, *value);
			}

			let ready = timeout(PROMPT, self.calls.clone().ready()).await?;
			let mut calls = ready?;
			let call = calls.send_request(head.body(())?, false)?;
			Ok(call)
		}

		/// Whether the server closes the connection within `within`.
		async fn closes_within(&mut self, within: Duration) -> bool {
			let closed = timeout(within, &mut self.driver).await;
			closed.is_ok()
		}
	}

	#[tokio::test]
	async fn a_full_plane_holds_a_dial_until_a_tunnel_is_accepted() -> TestResult {
		let plane = Arc::new(plane(TransportLimits::default(), 1).await?);

		let _first = timeout(PROMPT, dial(&plane)).await??;
		let waiting = Arc::clone(&plane);
		let mut second = tokio::spawn(async move { dial(&waiting).await });

		let held = timeout(HELD, &mut second).await;
		assert!(held.is_err());

		timeout(PROMPT, plane.accept()).await??;
		let _second = timeout(PROMPT, second).await???;
		Ok(())
	}

	#[tokio::test]
	async fn a_connection_with_no_call_closes_at_its_deadline_and_returns_its_slot() -> TestResult {
		let plane = plane(idle_limits(), 1).await?;
		let started = Instant::now();
		let mut idle = TcpStream::connect(plane.local_addr()).await?;

		let mut received = Vec::new();
		let _ = timeout(PROMPT, idle.read_to_end(&mut received)).await?;
		assert!(started.elapsed() >= IDLE);

		let _next = timeout(PROMPT, dial(&plane)).await??;
		Ok(())
	}

	#[tokio::test]
	async fn a_connection_whose_tunnel_ended_carries_the_next_call_under_the_one_slot() -> TestResult {
		let plane = plane(idle_limits(), 1).await?;
		let mut connection = H2Connection::open(&plane).await?;

		let (response, requests) = connection.call(&[]).await?;
		let (transport, _peer) = timeout(PROMPT, plane.accept()).await??;
		drop(transport);

		let response = timeout(PROMPT, response).await??;
		let mut responses = response.into_body();
		let trailers = timeout(PROMPT, responses.trailers()).await??;
		let status = trailers.as_ref().and_then(|trailers| trailers.get("grpc-status"));
		assert_eq!(status.map(|value| value.as_bytes()), Some(&b"0"[..]));

		// The server resets the request side once its response is complete
		// (RFC 9113 section 8.1), so the stream has closed both ways.
		drop(requests);

		let (_next, _next_requests) = connection.call(&[]).await?;
		timeout(PROMPT, plane.accept()).await??;
		assert!(connection.closes_within(PROMPT).await);
		Ok(())
	}

	#[tokio::test]
	async fn a_connection_whose_tunnel_ends_with_no_free_slot_refuses_its_next_call_and_drains() -> TestResult {
		let plane = plane(idle_limits(), 1).await?;
		let mut connection = H2Connection::open(&plane).await?;

		let (response, requests) = connection.call(&[]).await?;
		let (transport, _peer) = timeout(PROMPT, plane.accept()).await??;
		let _holder = timeout(PROMPT, dial(&plane)).await??;

		drop(transport);
		let response = timeout(PROMPT, response).await??;
		let mut responses = response.into_body();
		timeout(PROMPT, responses.trailers()).await??;
		drop(requests);

		let (refused, _refused_requests) = connection.call(&[]).await?;
		let refused = timeout(PROMPT, refused).await??;
		let status = refused.headers().get("grpc-status").map(|value| value.as_bytes());
		assert_eq!(status, Some(&b"14"[..]));
		assert!(connection.closes_within(PROMPT).await);
		Ok(())
	}

	#[tokio::test]
	async fn a_tunnel_no_caller_takes_closes_its_connection_at_its_deadline() -> TestResult {
		let plane = plane(idle_limits(), 1).await?;
		let started = Instant::now();
		let mut connection = H2Connection::open(&plane).await?;

		let (_silent, _silent_requests) = connection.call(&[]).await?;
		assert!(connection.closes_within(PROMPT).await);
		assert!(started.elapsed() >= IDLE);

		let _next = timeout(PROMPT, dial(&plane)).await??;
		timeout(PROMPT, plane.accept()).await??;
		Ok(())
	}

	#[tokio::test]
	async fn a_call_reset_before_accept_holds_no_second_slot_and_never_reaches_a_caller() -> TestResult {
		let plane = plane(TransportLimits::default(), 2).await?;
		let mut connection = H2Connection::open(&plane).await?;

		let (reset, mut reset_requests) = connection.call(&[]).await?;
		reset_requests.send_reset(h2::Reason::CANCEL);
		drop(reset);

		let _other = timeout(PROMPT, dial(&plane)).await??;
		let (_other_tunnel, other_peer) = timeout(PROMPT, plane.accept()).await??;
		assert_ne!(other_peer, connection.local);

		let (_next, _next_requests) = connection.call(&[]).await?;
		let (_next_tunnel, next_peer) = timeout(PROMPT, plane.accept()).await??;
		assert_eq!(next_peer, connection.local);

		let none_left = timeout(HELD, plane.accept()).await;
		assert!(none_left.is_err());
		Ok(())
	}

	#[tokio::test]
	async fn calls_refused_after_their_parse_never_renew_the_deadline() -> TestResult {
		let plane = plane(idle_limits(), 1).await?;
		let started = Instant::now();
		let mut connection = H2Connection::open(&plane).await?;

		// A peer that renews the deadline with each refused call would keep
		// the connection open until the loop gives up at three deadlines.
		let closed_after = loop {
			let Ok((refused, _requests)) = connection.call(&[("grpc-encoding", "gzip")]).await else {
				break started.elapsed();
			};
			let _ = timeout(PROMPT, refused).await;

			let closed = connection.closes_within(IDLE / 4).await;
			if closed || started.elapsed() > IDLE * 3 {
				break started.elapsed();
			}
		};

		assert!(closed_after >= IDLE);
		assert!(closed_after < IDLE + IDLE / 2);
		Ok(())
	}

	#[tokio::test]
	async fn a_dropped_listener_ends_every_tunnel_no_caller_took() -> TestResult {
		let plane = plane(TransportLimits::default(), 2).await?;
		let mut stream = timeout(PROMPT, dial(&plane)).await??;
		drop(plane);

		let read = timeout(PROMPT, stream.read_frame(64)).await?;
		assert!(matches!(read, Err(TransportError::ConnectionClosed)));
		Ok(())
	}

	#[tokio::test]
	async fn a_dropped_listener_closes_its_idle_connections() -> TestResult {
		let plane = plane(TransportLimits::default(), 2).await?;
		let mut connection = H2Connection::open(&plane).await?;
		drop(plane);

		assert!(connection.closes_within(PROMPT).await);
		Ok(())
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
