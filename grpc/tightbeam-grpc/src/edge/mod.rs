//! The deployment profile of a gRPC edge: what a listener binds with, and what
//! a dial connects with.
//!
//! tightbeam binds the edge of a gateway through
//! [`EncryptedProtocol::bind_with`], and a client dials through
//! [`Protocol::connect`]. Neither call carries a value for the deployment, so
//! [`GrpcListener<P, C>`] names its deployment as the type `C`, and the
//! [`EdgeProfile`] of `C` provisions each bind and each dial from the sources
//! of the profile itself: a file, a secret mount, or a cell that a test fills.
//!
//! - [`H2c`], the default profile, runs the tunnel on HTTP/2 with prior knowledge and no TLS.
//! - A profile whose bind returns [`Edge::Tls`] terminates TLS 1.3 at the
//!   listener, before any byte reaches the HTTP/2 server, and its dial returns
//!   [`Dial::Tls`], which verifies the certificate of the edge against its
//!   roots.
//!
//! The tightbeam handshake inside each tunnel runs unchanged under either
//! profile, so TLS adds a layer for the hops in front of the edge and replaces
//! nothing.
//!
//! [`EncryptedProtocol::bind_with`]: tightbeam::transport::EncryptedProtocol::bind_with
//! [`Protocol::connect`]: tightbeam::transport::Protocol::connect
//! [`GrpcListener<P, C>`]: crate::protocol::GrpcListener
//!
//! # Sources
//!
//! - RFC 8446, TLS 1.3, August 2018: <https://www.rfc-editor.org/rfc/rfc8446>
//! - RFC 7301, TLS ALPN, July 2014: <https://www.rfc-editor.org/rfc/rfc7301>
//! - RFC 9113, HTTP/2, June 2022, section 3.2, HTTP/2 over TLS: <https://www.rfc-editor.org/rfc/rfc9113#section-3.2>

use core::fmt;
use std::io;

use tokio_rustls::TlsAcceptor;
use tonic::transport::{Channel, Endpoint};

use tightbeam::transport::TransportError;

use crate::io::EndClass;
use crate::protocol::GrpcAddr;

mod tls;

pub use tls::{DialTls, EdgeTls};

/// The deployment of a gRPC edge, as a type that provisions itself.
///
/// [`GrpcListener<P, C>`](crate::protocol::GrpcListener) calls
/// [`EdgeProfile::edge`] once for each bind, before it binds the socket, and
/// [`EdgeProfile::dial`] once for each dial, before it connects. A profile
/// that reads its material from files caches what it read, if a dial must not
/// read them again.
///
/// # Examples
///
/// ```no_run
/// use tightbeam_grpc::edge::{Dial, DialTls, Edge, EdgeError, EdgeProfile, EdgeTls};
///
/// /// The edge of the orders gateway, under the certificates that its pod mounts.
/// struct Orders;
///
/// impl EdgeProfile for Orders {
///     fn edge() -> Result<Edge, EdgeError> {
///         let tls = EdgeTls::from_pem("/run/edge/tls.crt", "/run/edge/tls.key")?;
///         Ok(Edge::Tls(tls))
///     }
///
///     fn dial() -> Result<Dial, EdgeError> {
///         let tls = DialTls::from_pem("/run/edge/ca.crt")?;
///         Ok(Dial::Tls(tls))
///     }
/// }
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
		Ok(Edge::H2c)
	}

	fn dial() -> Result<Dial, EdgeError> {
		Ok(Dial::H2c)
	}
}

/// The setup of one bind of an edge.
#[derive(Clone, Debug)]
pub enum Edge {
	/// The tunnel on HTTP/2 with prior knowledge, and no TLS.
	H2c,
	/// TLS 1.3 under the certificate of the [`EdgeTls`], with ALPN `h2`.
	Tls(EdgeTls),
	/// TLS 1.3 under the certificate of the [`EdgeTls`], which verifies the
	/// client chain of each caller under the trust of the [`Coupler`], and
	/// the coupler, which serves the routed methods of stock gRPC callers
	/// beside the tunnel.
	///
	/// [`Coupler`]: crate::couple::Coupler
	#[cfg(feature = "couple")]
	Coupled(EdgeTls, crate::couple::Coupler),
}

impl Edge {
	/// The acceptor that secures each connection of the bind, or `None` when
	/// the bind runs no TLS. A coupled bind verifies the client chain of a
	/// connection that presents one, and admits a connection that presents
	/// none, such as a native tunnel client.
	///
	/// # Errors
	///
	/// - [`EdgeError::Tls`] -- rustls refuses the material of a coupled bind.
	/// - [`EdgeError::Verifier`] -- rustls refuses the CRLs of a coupled bind.
	pub(crate) fn acceptor(&self) -> Result<Option<TlsAcceptor>, EdgeError> {
		match self {
			Self::H2c => Ok(None),
			Self::Tls(tls) => Ok(Some(tls.acceptor())),
			#[cfg(feature = "couple")]
			Self::Coupled(tls, coupler) => {
				let verifier = coupler.callers().verifier(tls::provider())?;
				Ok(Some(tls.verifying(verifier)?))
			}
		}
	}

	/// The trace that a coupled bind records on, which its coupler holds.
	#[cfg(all(feature = "couple", feature = "instrument"))]
	pub(crate) fn trace(&self) -> Option<&tightbeam::trace::TraceCollector> {
		match self {
			Self::H2c | Self::Tls(_) => None,
			Self::Coupled(_, coupler) => coupler.trace(),
		}
	}

	/// The HTTP/2 streams that a connection of the bind admits at once: one
	/// for a tunnel edge, which carries one tunnel per connection, and the
	/// stream limit of the coupler for a coupled edge.
	pub(crate) fn stream_limit(&self) -> u32 {
		match self {
			Self::H2c | Self::Tls(_) => 1,
			#[cfg(feature = "couple")]
			Self::Coupled(_, coupler) => coupler.stream_limit(),
		}
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
	/// - [`TransportError::InvalidAddress`] -- tonic refuses the URI of `addr`,
	///   or TLS cannot name its host.
	/// - The [`TransportError`] of the [`EndClass`] of the failed connect.
	pub(crate) async fn channel(&self, addr: &GrpcAddr) -> Result<Channel, TransportError> {
		let connected = match self {
			Self::H2c => {
				let uri = format!("http://{addr}");
				let endpoint = Endpoint::from_shared(uri).map_err(|_| TransportError::InvalidAddress)?;
				endpoint.connect().await
			}
			Self::Tls(tls) => {
				let (endpoint, dialer) = tls.endpoint(addr)?;
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
	/// scenario has not staged.
	Unprovisioned,
	/// A bind in the clear of a coupled edge, whose loopback session needs
	/// the tightbeam handshake.
	RequiresEncryption,
	/// A coupler that routes no method.
	#[cfg(feature = "couple")]
	NoRoute,
	/// rustls refuses the client verifier of a coupled edge, such as one of
	/// its CRLs.
	#[cfg(feature = "couple")]
	Verifier(rustls::server::VerifierBuilderError),
	/// A principal that names no SPIFFE ID or distinguished name.
	#[cfg(feature = "couple")]
	Principal(String),
	/// A method that is no unary gRPC path, that a route names twice, that a
	/// reserved path takes, or that a grant names and no route serves.
	#[cfg(feature = "couple")]
	Method(String),
	/// tightbeam refuses a certificate or a trust store of the coupler.
	#[cfg(feature = "couple")]
	Trust(tightbeam::crypto::x509::error::CertificateValidationError),
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
			#[cfg(feature = "couple")]
			Self::Principal(text) => write!(f, "`{text}` names no SPIFFE ID or distinguished name"),
			#[cfg(feature = "couple")]
			Self::Method(method) => write!(f, "`{method}` is no method a coupled edge can route"),
			#[cfg(feature = "couple")]
			Self::Trust(error) => write!(f, "tightbeam refuses a certificate of the coupler: {error}"),
			#[cfg(feature = "couple")]
			Self::NoRoute => f.write_str("the coupler routes no method"),
			#[cfg(feature = "couple")]
			Self::Verifier(error) => write!(f, "rustls refuses the client verifier of the edge: {error}"),
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
			Self::Principal(_) | Self::Method(_) | Self::NoRoute => None,
			Self::NoCertificate | Self::Unprovisioned | Self::RequiresEncryption => None,
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

impl From<rustls::Error> for EdgeError {
	fn from(error: rustls::Error) -> Self {
		Self::Tls(error)
	}
}

/// A bind or a dial fails with the I/O error of a profile that cannot read
/// its material, and with an `InvalidInput` I/O error that holds every other
/// failure as its source.
impl From<EdgeError> for TransportError {
	fn from(error: EdgeError) -> Self {
		let error = match error {
			EdgeError::Io(error) => error,
			refused => io::Error::new(io::ErrorKind::InvalidInput, refused),
		};
		error.into()
	}
}
