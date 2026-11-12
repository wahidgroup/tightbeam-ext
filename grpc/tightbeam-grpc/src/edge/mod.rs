//! The deployment profile of a gRPC edge, which `docs/grpc.md` describes.
//!
//! # Sources
//!
//! - RFC 8446, TLS 1.3, August 2018: <https://www.rfc-editor.org/rfc/rfc8446>
//! - RFC 9113, HTTP/2, June 2022, section 3.2: <https://www.rfc-editor.org/rfc/rfc9113#section-3.2>

use core::fmt;
use core::future::Future;
use core::marker::PhantomData;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tightbeam::clock::{Clock, SystemClock};
use tightbeam::transport::handshake::HandshakeProvider;
use tightbeam::transport::{EndpointConfig, TransportError, TransportLimits};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tonic::transport::{Channel, Server};

#[cfg(feature = "instrument")]
use tightbeam::trace::TraceCollector;

use crate::incoming::{Arrivals, GrpcIncoming, LaneTerms, Securing, Slots};
use crate::io::EndClass;
use crate::protocol::GrpcAddr;
use crate::service::{EdgeService, Served};
use crate::tunnel::{EdgeAudit, TunnelService};

#[cfg(feature = "couple")]
use crate::couple::{CallRecorder, CoupleError, LiveCoupler, PreparedCoupler};

mod proxy;
mod staged;
mod tls;

pub use proxy::ProxyHops;
pub use staged::StagedCell;
#[cfg(feature = "couple")]
pub(crate) use tls::EdgeTlsPolicy;
pub(crate) use tls::TlsEndpoint;
pub use tls::{DialTls, EdgeTls, EdgeTlsFiles};

/// The deployment of a gRPC edge, as a type that provisions itself.
///
/// - [`GrpcListener<P, C>`](crate::protocol::GrpcListener) calls
///   [`EdgeProfile::edge`] before each bind and [`EdgeProfile::dial`] before
///   each dial.
/// - A profile that reads its material from files caches it when a dial must
///   not read the files again.
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
///
/// use tightbeam_grpc::edge::{Dial, DialTls, Edge, EdgeError, EdgeProfile, EdgeTls, EdgeTlsFiles};
/// # use tightbeam_grpc::testing::{CoupledStack, MintError};
///
/// /// The edge of the orders gateway, under the certificates that its pod
/// /// mounts at `EDGE_CERTS`.
/// struct Orders;
///
/// impl Orders {
/// 	/// The mounted file `name`.
/// 	fn mounted(name: &str) -> PathBuf {
/// 		PathBuf::from(std::env::var_os("EDGE_CERTS").unwrap_or_default()).join(name)
/// 	}
/// }
///
/// impl EdgeProfile for Orders {
/// 	fn edge() -> Result<Edge, EdgeError> {
/// 		let files = EdgeTlsFiles { chain: Self::mounted("edge.crt"), key: Self::mounted("edge.key") };
/// 		let tls = EdgeTls::from_pem(files)?;
/// 		Ok(Edge::tls(tls))
/// 	}
///
/// 	fn dial() -> Result<Dial, EdgeError> {
/// 		let tls = DialTls::from_pem(Self::mounted("root.pem"))?;
/// 		Ok(Dial::Tls(tls))
/// 	}
/// }
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let dir = std::env::temp_dir().join(format!("tightbeam-grpc-doc-profile-{}", std::process::id()));
/// # let stack = CoupledStack::at(dir);
/// # stack.write(core::time::Duration::from_secs(60), |_| Ok::<(), MintError>(()))?;
/// # std::env::set_var("EDGE_CERTS", stack.dir());
/// # Orders::edge()?;
/// # Orders::dial()?;
/// # std::fs::remove_dir_all(stack.dir())?;
/// # Ok(())
/// # }
/// ```
pub trait EdgeProfile: Send + Sync + 'static {
	/// The setup of one bind.
	///
	/// # Errors
	///
	/// - The [`EdgeError`] of material that the profile cannot read or that rustls refuses.
	fn edge() -> Result<Edge, EdgeError>;

	/// The setup of one dial.
	///
	/// # Errors
	///
	/// - The [`EdgeError`] of material that the profile cannot read or that rustls refuses.
	fn dial() -> Result<Dial, EdgeError>;
}

/// The default profile: the tunnel on HTTP/2 with prior knowledge (h2c), and
/// no TLS, for the hops that route h2c, such as a sidecar mesh or an L4 load
/// balancer.
#[derive(Clone, Copy, Debug, Default)]
pub struct H2c;

impl EdgeProfile for H2c {
	fn edge() -> Result<Edge, EdgeError> {
		Ok(Edge::h2c())
	}

	fn dial() -> Result<Dial, EdgeError> {
		Ok(Dial::H2c)
	}
}

/// The setup of one bind of an edge: how it secures and serves its
/// connections, the trace that records what it refuses, and the hops whose
/// PROXY headers it reads.
///
/// # Examples
///
/// ```
/// use tightbeam_grpc::edge::{Edge, EdgeTls, EdgeTlsFiles, ProxyHops};
/// # use tightbeam_grpc::testing::{CoupledStack, MintError};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let dir = std::env::temp_dir().join(format!("tightbeam-grpc-doc-hops-{}", std::process::id()));
/// # let stack = CoupledStack::at(dir);
/// # stack.write(core::time::Duration::from_secs(60), |_| Ok::<(), MintError>(()))?;
/// # let (chain, key) = (stack.edge_chain(), stack.edge_key());
///
/// let tls = EdgeTls::from_pem(EdgeTlsFiles { chain, key })?;
/// let edge = Edge::tls(tls).with_proxy_protocol(ProxyHops::new(["10.0.0.0/8"])?);
/// # std::fs::remove_dir_all(stack.dir())?;
/// # Ok(())
/// # }
/// ```
pub struct Edge {
	kind: EdgeKind,
	hops: ProxyHops,
	clock: Arc<dyn Clock>,
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
}

/// How an edge secures and serves its connections.
#[derive(Clone, Debug)]
enum EdgeKind {
	/// The tunnel on HTTP/2 with prior knowledge, and no TLS.
	H2c,
	/// TLS 1.3 under the certificate of the [`EdgeTls`], with ALPN `h2`.
	Tls(EdgeTls),
	/// TLS 1.3 that verifies the client chain of each caller under the trust
	/// of the coupler, and the coupler, which serves routed methods beside
	/// the tunnel.
	#[cfg(feature = "couple")]
	Coupled(EdgeTls, Box<crate::couple::Coupler>),
}

impl EdgeKind {
	/// What a bind of this kind under `config` builds before its socket binds:
	/// the acceptor of its TLS, and the coupler of a coupled edge, which runs
	/// on `clock`.
	///
	/// # Errors
	///
	/// - [`EdgeError::RequiresEncryption`] -- a coupled edge binds in the clear.
	/// - [`EdgeError::Tls`] -- rustls refuses the TLS of the bind.
	/// - [`EdgeError::Verifier`] -- rustls refuses the client verifier of the bind.
	/// - [`EdgeError::Trust`] -- tightbeam refuses the certificate of the gateway as the pin of the coupler.
	fn prepare<P>(&self, config: &EndpointConfig<P>, clock: &Arc<dyn Clock>) -> Result<Prepared, EdgeError>
	where
		P: HandshakeProvider + Send + Sync + 'static,
	{
		#[cfg(not(feature = "couple"))]
		let _ = (config, clock);

		match self {
			Self::H2c => Ok(Prepared::Tunnel(None)),
			Self::Tls(tls) => Ok(Prepared::Tunnel(Some(tls.acceptor(None)?))),
			#[cfg(feature = "couple")]
			Self::Coupled(tls, coupler) => {
				let gateway = config.encryption().server_certificate().ok_or(EdgeError::RequiresEncryption)?;
				let coupler = coupler.prepare(gateway, clock)?;
				let acceptor = tls.acceptor(Some(coupler.verifier()))?;
				Ok(Prepared::Coupled(acceptor, Box::new(coupler)))
			}
		}
	}
}

impl Edge {
	/// The tunnel on HTTP/2 with prior knowledge (h2c), and no TLS.
	#[must_use]
	pub fn h2c() -> Self {
		Self::of(EdgeKind::H2c)
	}

	/// TLS 1.3 under the certificate of `tls`, with ALPN `h2`.
	#[must_use]
	pub fn tls(tls: EdgeTls) -> Self {
		Self::of(EdgeKind::Tls(tls))
	}

	/// TLS 1.3 under the certificate of `tls`, which verifies the client
	/// chain of each caller under the trust of `coupler`, and `coupler`,
	/// which serves the routed methods of stock gRPC callers beside the
	/// tunnel.
	#[cfg(feature = "couple")]
	#[must_use]
	pub fn coupled(tls: EdgeTls, coupler: crate::couple::Coupler) -> Self {
		Self::of(EdgeKind::Coupled(tls, Box::new(coupler)))
	}

	fn of(kind: EdgeKind) -> Self {
		Self {
			kind,
			hops: ProxyHops::default(),
			clock: Arc::new(SystemClock),
			#[cfg(feature = "instrument")]
			trace: None,
		}
	}

	/// Record what the edge refuses before any session exists, each PROXY
	/// header it reads, and each admission, refusal, and answer of its
	/// coupler, on `trace`, from the first connection of each bind on.
	#[cfg(feature = "instrument")]
	#[must_use]
	pub fn with_trace(mut self, trace: TraceCollector) -> Self {
		self.trace = Some(trace);
		self
	}

	/// Read a PROXY protocol v2 header at the start of each connection from
	/// `hops`, and take the source address it names as the peer of the
	/// connection.
	///
	/// - A connection from a hop that sends no header closes.
	/// - The edge reads no header from any other address.
	/// - Under `instrument`, the trace of the edge records each header it reads, and each that it refuses.
	#[must_use]
	pub fn with_proxy_protocol(mut self, hops: ProxyHops) -> Self {
		self.hops = hops;
		self
	}

	/// Run on `clock`, in place of [`SystemClock`], the timers and the unix
	/// readings of each bind of the edge that `docs/grpc.md` (Edge profile)
	/// lists.
	#[must_use]
	pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
		self.clock = clock;
		self
	}

	/// What a bind of the edge under `config` builds before its socket binds:
	/// the acceptor of its TLS, the coupler of a coupled edge, and the audit
	/// trail of the bind. A profile whose material is refused binds no socket.
	///
	/// # Errors
	///
	/// - The errors of [`EdgeKind::prepare`].
	pub(crate) fn prepare<P>(&self, config: &EndpointConfig<P>) -> Result<PreparedEdge, EdgeError>
	where
		P: HandshakeProvider + Send + Sync + 'static,
	{
		let prepared = self.kind.prepare(config, &self.clock)?;

		#[cfg(feature = "instrument")]
		let audit = EdgeAudit::on(self.trace.as_ref().map(TraceCollector::share));
		#[cfg(not(feature = "instrument"))]
		let audit = EdgeAudit::default();

		Ok(PreparedEdge { prepared, hops: self.hops.clone(), audit, clock: Arc::clone(&self.clock) })
	}
}

/// How a prepared bind secures and serves its connections.
enum Prepared {
	/// The tunnel alone, in the clear or under the TLS of this acceptor.
	Tunnel(Option<TlsAcceptor>),
	/// The tunnel and a coupler, under the TLS of this acceptor, which
	/// verifies the client chain of each caller.
	#[cfg(feature = "couple")]
	Coupled(TlsAcceptor, Box<PreparedCoupler>),
}

impl Prepared {
	/// What the bind serves beside its tunnel, and the acceptor of its TLS,
	/// for the listener of profile `C` once its socket bound at `local`. A
	/// coupled edge starts its coupler here, which records on `audit`, queues
	/// its loopback tunnel on `queue`, and holds every message to `ceiling`.
	fn serve<P, C>(
		self,
		audit: &EdgeAudit,
		queue: &Arrivals,
		local: SocketAddr,
		ceiling: usize,
	) -> (Served<P>, Option<TlsAcceptor>)
	where
		P: HandshakeProvider + Send + Sync + 'static,
		C: EdgeProfile,
	{
		#[cfg(not(feature = "couple"))]
		let _ = (audit, queue, local, ceiling, PhantomData::<C>);

		match self {
			Self::Tunnel(tls) => (Served::Tunnel(PhantomData), tls),
			#[cfg(feature = "couple")]
			Self::Coupled(tls, coupler) => {
				let recorder = CallRecorder::new(audit.clone());
				let live = LiveCoupler::start::<C>(*coupler, recorder, queue.clone(), local, ceiling);
				(Served::Coupled(Arc::new(live)), Some(tls))
			}
		}
	}
}

/// A bind of an edge, prepared before its socket binds.
pub(crate) struct PreparedEdge {
	prepared: Prepared,
	hops: ProxyHops,
	audit: EdgeAudit,
	clock: Arc<dyn Clock>,
}

impl PreparedEdge {
	/// `config` on the clock of the edge, so each tunnel transport of the
	/// bind measures its deadlines there.
	pub(crate) fn clocked<P: HandshakeProvider>(&self, config: EndpointConfig<P>) -> EndpointConfig<P> {
		config.with_clock(Arc::clone(&self.clock))
	}

	/// The bind of the listener of profile `C` once its socket bound at
	/// `local`, which queues its tunnels on `queue` under `limits`:
	///
	/// - What it serves beside its tunnel. A coupled edge starts its coupler
	///   here, which records on the audit trail of the bind.
	/// - The terms that each of its connections waits under.
	/// - How each connection passes the PROXY header of a hop and the TLS
	///   handshake, which the audit trail records.
	pub(crate) fn bind<P, C>(self, queue: Arrivals, local: SocketAddr, limits: &TransportLimits) -> EdgeBind<P>
	where
		P: HandshakeProvider + Send + Sync + 'static,
		C: EdgeProfile,
	{
		let Self { prepared, hops, audit, clock } = self;
		let ceiling = limits.max_envelope();
		let (served, tls) = prepared.serve::<P, C>(&audit, &queue, local, ceiling);

		let terms = LaneTerms::of(limits.handshake_timeout, &served, clock);
		let securing = Securing::new(hops, tls, audit.clone());
		EdgeBind { served, terms, securing, audit, queue, ceiling }
	}
}

/// One bind of an edge, which the edge builds whole: what it serves, the
/// terms of its lanes, how each connection is secured, the audit trail that
/// records them, the queue of its tunnels, and the ceiling of every message
/// of a tunnel.
pub(crate) struct EdgeBind<P: HandshakeProvider + Send + Sync + 'static> {
	served: Served<P>,
	terms: LaneTerms,
	securing: Securing,
	audit: EdgeAudit,
	queue: Arrivals,
	ceiling: usize,
}

impl<P: HandshakeProvider + Send + Sync + 'static> EdgeBind<P> {
	/// The server of the bind on `listener` until `stopping` resolves: each
	/// connection under one of `slots`, each tunnel queued on the queue of
	/// the bind, and every message of a tunnel held to its ceiling.
	pub(crate) fn serve(
		self,
		listener: TcpListener,
		slots: Arc<Slots>,
		stopping: impl Future<Output = ()> + Send + 'static,
	) -> impl Future<Output = Result<(), tonic::transport::Error>> + Send + 'static {
		let Self { served, terms, securing, audit, queue, ceiling } = self;
		let streams = terms.streams();
		let incoming = GrpcIncoming::new(listener, slots, terms, securing, queue.clone());
		let tunnel = TunnelService::new(queue, ceiling, audit.clone());
		let service = EdgeService::new(tunnel, audit, served);

		let builder = Server::builder().max_concurrent_streams(streams.get());
		builder.serve_with_incoming_shutdown(service, incoming, stopping)
	}
}

/// A clone records on the trace of the original.
impl Clone for Edge {
	fn clone(&self) -> Self {
		Self {
			kind: self.kind.clone(),
			hops: self.hops.clone(),
			clock: Arc::clone(&self.clock),
			#[cfg(feature = "instrument")]
			trace: self.trace.as_ref().map(TraceCollector::share),
		}
	}
}

impl fmt::Debug for Edge {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Edge")
			.field("kind", &self.kind)
			.field("hops", &self.hops)
			.finish_non_exhaustive()
	}
}

/// The setup of one dial of an edge.
#[derive(Clone, Debug)]
pub enum Dial {
	/// The tunnel on HTTP/2 with prior knowledge, and no TLS.
	H2c,
	/// TLS 1.3 that verifies the certificate of the edge against the roots of
	/// the [`DialTls`], with ALPN `h2`.
	Tls(DialTls),
}

impl Dial {
	/// Connect the channel of one tunnel call to `addr`: `http` over TCP for
	/// h2c, and over the TLS endpoint of the dial, which names the host of
	/// `addr` as the server it verifies.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidAddress`] -- tonic refuses the URI of `addr`.
	/// - The [`TransportError`] of the [`EndClass`] of the failed connect.
	pub(crate) async fn channel(&self, addr: &GrpcAddr) -> Result<Channel, TransportError> {
		let connected = match self {
			Self::H2c => addr.endpoint()?.connect().await,
			Self::Tls(tls) => {
				let TlsEndpoint { endpoint, dialer } = tls.endpoint(addr)?;
				endpoint.connect_with_connector(dialer).await
			}
		};

		let channel = connected.map_err(|error| EndClass::of_error(error.into()))?;
		Ok(channel)
	}
}

/// Why a profile cannot provision a bind or a dial.
#[derive(Debug)]
pub enum EdgeError {
	/// A file of the profile cannot be read.
	Io(io::Error),
	/// A PEM source is malformed, or holds no item of the kind it must hold.
	Pem(rustls_pki_types::pem::Error),
	/// A certificate chain or a set of roots holds no certificate.
	NoCertificate,
	/// rustls refuses the material, such as a key that does not match its
	/// certificate, or a root that does not parse.
	Tls(rustls::Error),
	/// The profile holds no material, such as a staged profile that its
	/// deployment has not staged.
	Unprovisioned,
	/// A bind in the clear of a coupled edge, whose loopback session needs
	/// the tightbeam handshake.
	RequiresEncryption,
	/// A PROXY hop that is no address, or no address and prefix length.
	ProxyHop(String),
	/// rustls refuses the client verifier of a coupled edge, such as one of
	/// its CRLs.
	#[cfg(feature = "couple")]
	Verifier(rustls::server::VerifierBuilderError),
	/// tightbeam refuses a certificate or a trust store of the coupler.
	#[cfg(feature = "couple")]
	Trust(tightbeam::crypto::x509::error::CertificateValidationError),
	/// The coupler of the profile refuses its configuration.
	#[cfg(feature = "couple")]
	Couple(CoupleError),
}

impl fmt::Display for EdgeError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Io(error) => write!(f, "the profile cannot read its material: {error}"),
			Self::Pem(error) => write!(f, "the PEM material of the profile is malformed: {error}"),
			Self::NoCertificate => f.write_str("the profile names no certificate"),
			Self::Tls(error) => write!(f, "TLS refuses the material of the profile: {error}"),
			Self::Unprovisioned => f.write_str("the profile holds no material"),
			Self::RequiresEncryption => f.write_str("a coupled edge binds only through EncryptedProtocol::bind_with"),
			Self::ProxyHop(hop) => write!(f, "`{hop}` is no address or CIDR range of a PROXY hop"),
			#[cfg(feature = "couple")]
			Self::Verifier(error) => write!(f, "rustls refuses the client verifier of the edge: {error}"),
			#[cfg(feature = "couple")]
			Self::Trust(error) => write!(f, "tightbeam refuses a certificate of the coupler: {error}"),
			#[cfg(feature = "couple")]
			Self::Couple(error) => write!(f, "the coupler refuses its configuration: {error}"),
		}
	}
}

impl std::error::Error for EdgeError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Io(error) => Some(error),
			Self::Pem(error) => Some(error),
			Self::Tls(error) => Some(error),
			#[cfg(feature = "couple")]
			Self::Trust(error) => Some(error),
			#[cfg(feature = "couple")]
			Self::Verifier(error) => Some(error),
			#[cfg(feature = "couple")]
			Self::Couple(error) => Some(error),
			Self::NoCertificate | Self::Unprovisioned | Self::RequiresEncryption | Self::ProxyHop(_) => None,
		}
	}
}

impl From<io::Error> for EdgeError {
	fn from(error: io::Error) -> Self {
		Self::Io(error)
	}
}

/// A PEM file that cannot be opened is an I/O failure, and every other PEM
/// failure is malformed material.
impl From<rustls_pki_types::pem::Error> for EdgeError {
	fn from(error: rustls_pki_types::pem::Error) -> Self {
		match error {
			rustls_pki_types::pem::Error::Io(error) => Self::Io(error),
			malformed => Self::Pem(malformed),
		}
	}
}

#[cfg(feature = "couple")]
impl From<rustls::server::VerifierBuilderError> for EdgeError {
	fn from(error: rustls::server::VerifierBuilderError) -> Self {
		Self::Verifier(error)
	}
}

#[cfg(feature = "couple")]
impl From<tightbeam::crypto::x509::error::CertificateValidationError> for EdgeError {
	fn from(error: tightbeam::crypto::x509::error::CertificateValidationError) -> Self {
		Self::Trust(error)
	}
}

#[cfg(feature = "couple")]
impl From<CoupleError> for EdgeError {
	fn from(error: CoupleError) -> Self {
		Self::Couple(error)
	}
}

impl From<rustls::Error> for EdgeError {
	fn from(error: rustls::Error) -> Self {
		Self::Tls(error)
	}
}

/// A bind or a dial fails with the transport error of the refusal where
/// tightbeam names one: the I/O error of material that cannot be read, a
/// missing encryption, or a refused certificate. Every other refusal is an
/// `InvalidInput` I/O error that holds it as its inner error.
impl From<EdgeError> for TransportError {
	fn from(error: EdgeError) -> Self {
		match error {
			EdgeError::Io(error) => error.into(),
			EdgeError::RequiresEncryption => Self::MissingEncryption,
			#[cfg(feature = "couple")]
			EdgeError::Trust(error) => Self::InvalidCertificate(error),
			refused => io::Error::new(io::ErrorKind::InvalidInput, refused).into(),
		}
	}
}
