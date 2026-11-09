//! TLS 1.3 with ALPN `h2` at each end of an edge, under the ring provider.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;
use std::path::Path;
use std::sync::Arc;

use http::Uri;
use hyper_util::rt::TokioIo;
use rustls::crypto::{ring, CryptoProvider};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tonic::transport::Endpoint;
use tower_service::Service;

use tightbeam::transport::TransportError;

use super::EdgeError;
use crate::protocol::GrpcAddr;

/// The one ALPN protocol of an edge: HTTP/2 over TLS (RFC 9113 section 3.2).
const ALPN_H2: &[u8] = b"h2";

/// The provider of every config of this module, and of the client verifier
/// of a coupled edge.
pub(crate) fn provider() -> Arc<CryptoProvider> {
	Arc::new(ring::default_provider())
}

/// The TLS of the bind of an edge: the certificate chain that the edge
/// presents, and its private key.
///
/// # Examples
///
/// ```no_run
/// use tightbeam_grpc::edge::{Edge, EdgeError, EdgeTls};
///
/// let tls = EdgeTls::from_pem("/run/edge/tls.crt", "/run/edge/tls.key")?;
/// let edge = Edge::Tls(tls);
/// # Ok::<(), EdgeError>(())
/// ```
#[derive(Clone, Debug)]
pub struct EdgeTls {
	config: Arc<ServerConfig>,
	/// The chain and the key of the config, which a coupled edge builds a
	/// config with its client verifier from, because rustls fixes the
	/// verifier of a config when it builds it.
	#[cfg(feature = "couple")]
	chain: Vec<CertificateDer<'static>>,
	#[cfg(feature = "couple")]
	key: Arc<PrivateKeyDer<'static>>,
}

impl EdgeTls {
	/// TLS under `chain`, the certificate of the edge first and the
	/// certificates of its issuers after it, and `key`, the private key of the
	/// certificate of the edge.
	///
	/// # Errors
	///
	/// - [`EdgeError::NoCertificate`] -- `chain` is empty.
	/// - [`EdgeError::Tls`] -- rustls refuses the chain or the key, such as a
	///   key that does not match the certificate.
	pub fn new(
		chain: impl IntoIterator<Item = CertificateDer<'static>>,
		key: PrivateKeyDer<'static>,
	) -> Result<Self, EdgeError> {
		let chain: Vec<CertificateDer<'static>> = chain.into_iter().collect();
		if chain.is_empty() {
			return Err(EdgeError::NoCertificate);
		}

		#[cfg(feature = "couple")]
		let (material, kept) = (chain.clone(), Arc::new(key.clone_key()));
		let builder = ServerConfig::builder_with_provider(provider()).with_protocol_versions(&[&TLS13])?;
		let mut config = builder.with_no_client_auth().with_single_cert(chain, key)?;
		config.alpn_protocols = vec![ALPN_H2.to_vec()];
		Ok(Self {
			config: Arc::new(config),
			#[cfg(feature = "couple")]
			chain: material,
			#[cfg(feature = "couple")]
			key: kept,
		})
	}

	/// TLS under the PEM certificate chain in the file `chain` and the PEM
	/// private key in the file `key`, as [`EdgeTls::new`] takes them.
	///
	/// # Errors
	///
	/// - [`EdgeError::Io`] -- a file cannot be read.
	/// - [`EdgeError::Pem`] -- a file is malformed, or `key` holds no private key.
	/// - The errors of [`EdgeTls::new`].
	pub fn from_pem(chain: impl AsRef<Path>, key: impl AsRef<Path>) -> Result<Self, EdgeError> {
		let certificates = CertificateDer::pem_file_iter(chain)?;
		let chain = certificates.collect::<Result<Vec<_>, _>>()?;
		let key = PrivateKeyDer::from_pem_file(key)?;
		Self::new(chain, key)
	}

	/// The acceptor that secures each connection of a bind.
	pub(super) fn acceptor(&self) -> TlsAcceptor {
		TlsAcceptor::from(Arc::clone(&self.config))
	}

	/// The acceptor of a coupled bind, which verifies each client chain with
	/// `verifier`.
	///
	/// # Errors
	///
	/// - [`EdgeError::Tls`] -- rustls refuses the chain or the key.
	#[cfg(feature = "couple")]
	pub(super) fn verifying(
		&self,
		verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
	) -> Result<TlsAcceptor, EdgeError> {
		let builder = ServerConfig::builder_with_provider(provider()).with_protocol_versions(&[&TLS13])?;
		let builder = builder.with_client_cert_verifier(verifier);
		let mut config = builder.with_single_cert(self.chain.clone(), self.key.clone_key())?;
		config.alpn_protocols = vec![ALPN_H2.to_vec()];
		Ok(TlsAcceptor::from(Arc::new(config)))
	}
}

/// The TLS of a dial of an edge: the roots that the certificate of the edge
/// must chain to.
///
/// The dial names the host of its [`GrpcAddr`] as the server it verifies, so
/// the certificate of the edge carries that DNS name or IP address as a
/// subject alternative name.
///
/// # Examples
///
/// ```no_run
/// use tightbeam_grpc::edge::{Dial, DialTls, EdgeError};
///
/// let tls = DialTls::from_pem("/run/edge/ca.crt")?;
/// let dial = Dial::Tls(tls);
/// # Ok::<(), EdgeError>(())
/// ```
#[derive(Clone, Debug)]
pub struct DialTls {
	roots: Arc<RootCertStore>,
	config: Arc<ClientConfig>,
}

impl DialTls {
	/// TLS that trusts `roots` as the anchors of the certificate of the edge.
	///
	/// # Errors
	///
	/// - [`EdgeError::NoCertificate`] -- `roots` is empty.
	/// - [`EdgeError::Tls`] -- a root does not parse as a trust anchor.
	pub fn new(roots: impl IntoIterator<Item = CertificateDer<'static>>) -> Result<Self, EdgeError> {
		let mut store = RootCertStore::empty();
		for root in roots {
			store.add(root)?;
		}

		if store.is_empty() {
			return Err(EdgeError::NoCertificate);
		}

		let roots = Arc::new(store);
		let builder = ClientConfig::builder_with_provider(provider()).with_protocol_versions(&[&TLS13])?;

		let mut config = builder.with_root_certificates(Arc::clone(&roots)).with_no_client_auth();
		config.alpn_protocols = vec![ALPN_H2.to_vec()];
		Ok(Self { roots, config: Arc::new(config) })
	}

	/// The same TLS, which presents `chain`, the client certificate first and
	/// its issuers after it, with its private key `key`, to a server that
	/// authenticates its clients.
	///
	/// # Errors
	///
	/// - [`EdgeError::NoCertificate`] -- `chain` is empty.
	/// - [`EdgeError::Tls`] -- rustls refuses the chain or the key.
	pub fn with_identity(
		self,
		chain: impl IntoIterator<Item = CertificateDer<'static>>,
		key: PrivateKeyDer<'static>,
	) -> Result<Self, EdgeError> {
		let chain: Vec<CertificateDer<'static>> = chain.into_iter().collect();
		if chain.is_empty() {
			return Err(EdgeError::NoCertificate);
		}

		let builder = ClientConfig::builder_with_provider(provider()).with_protocol_versions(&[&TLS13])?;
		let builder = builder.with_root_certificates(Arc::clone(&self.roots));
		let mut config = builder.with_client_auth_cert(chain, key)?;
		config.alpn_protocols = vec![ALPN_H2.to_vec()];
		Ok(Self { roots: self.roots, config: Arc::new(config) })
	}

	/// TLS that trusts the PEM certificates in the file `roots`, as
	/// [`DialTls::new`] takes them.
	///
	/// # Errors
	///
	/// - [`EdgeError::Io`] -- the file cannot be read.
	/// - [`EdgeError::Pem`] -- the file is malformed.
	/// - The errors of [`DialTls::new`].
	pub fn from_pem(roots: impl AsRef<Path>) -> Result<Self, EdgeError> {
		let certificates = CertificateDer::pem_file_iter(roots)?;
		let roots = certificates.collect::<Result<Vec<_>, _>>()?;
		Self::new(roots)
	}

	/// The endpoint of a TLS dial to `addr`, and the connector that secures
	/// its connection.
	///
	/// The connect URI stays `http`, so tonic hands the connection to the
	/// connector whether or not an application enables a TLS feature of tonic,
	/// which would otherwise refuse an `https` URI that carries no tonic TLS
	/// config. The origin of each call names `https`, so its `:scheme` says
	/// TLS.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidAddress`] -- tonic refuses the URI of
	///   `addr`, or TLS cannot name its host.
	pub(crate) fn endpoint(&self, addr: &GrpcAddr) -> Result<(Endpoint, TlsDialer), TransportError> {
		let endpoint = Endpoint::from_shared(format!("http://{addr}")).map_err(|_| TransportError::InvalidAddress)?;
		let origin = Uri::try_from(format!("https://{addr}")).map_err(|_| TransportError::InvalidAddress)?;

		let name = addr.server_name()?;
		let connector = TlsConnector::from(Arc::clone(&self.config));
		let dialer = TlsDialer { connector, authority: addr.to_string(), name };

		Ok((endpoint.origin(origin), dialer))
	}
}

/// The connector of one TLS dial, which tonic calls for the connection of
/// its channel: TCP to the authority of the dial, then the TLS handshake that
/// verifies the named server.
#[derive(Clone)]
pub(crate) struct TlsDialer {
	connector: TlsConnector,
	authority: String,
	name: ServerName<'static>,
}

impl Service<Uri> for TlsDialer {
	type Response = TokioIo<TlsStream<TcpStream>>;
	type Error = io::Error;
	type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send + 'static>>;

	fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Poll::Ready(Ok(()))
	}

	/// The dial connects to its own authority, which is the authority of the
	/// URI that tonic passes.
	fn call(&mut self, _uri: Uri) -> Self::Future {
		let connector = self.connector.clone();
		let authority = self.authority.clone();
		let name = self.name.clone();

		Box::pin(async move {
			let tcp = TcpStream::connect(authority).await?;
			// The tunnel carries small envelopes in both directions, so the
			// socket sends each one at once, as the listener's sockets do.
			let _ = tcp.set_nodelay(true);

			let secured = connector.connect(name, tcp).await?;
			Ok(TokioIo::new(secured))
		})
	}
}
