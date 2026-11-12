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
use rustls::server::danger::ClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
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

/// The TLS of every end of an edge: TLS 1.3 alone and ALPN `h2` alone, under
/// the ring provider.
pub(crate) struct EdgeTlsPolicy;

impl EdgeTlsPolicy {
	/// The provider of every config of an edge, and of the client verifier
	/// of a coupled edge.
	pub(crate) fn provider() -> Arc<CryptoProvider> {
		Arc::new(ring::default_provider())
	}

	/// The key of `chain`, the certificate of an end first, once the provider
	/// loads `key` and it matches the certificate.
	///
	/// # Errors
	///
	/// - [`EdgeError::NoCertificate`] -- `chain` is empty.
	/// - [`EdgeError::Tls`] -- rustls refuses the key, or it does not match the certificate.
	fn certified(
		chain: Vec<CertificateDer<'static>>,
		key: PrivateKeyDer<'static>,
	) -> Result<Arc<CertifiedKey>, EdgeError> {
		if chain.is_empty() {
			return Err(EdgeError::NoCertificate);
		}

		let certified = CertifiedKey::from_der(chain, key, &Self::provider())?;
		Ok(Arc::new(certified))
	}

	/// The config of a bind that presents `key`, and verifies the client chain
	/// of each connection with `verifier`.
	///
	/// # Errors
	///
	/// - [`EdgeError::Tls`] -- the provider refuses TLS 1.3.
	fn server(key: &Arc<CertifiedKey>, verifier: Arc<dyn ClientCertVerifier>) -> Result<ServerConfig, EdgeError> {
		let builder = ServerConfig::builder_with_provider(Self::provider()).with_protocol_versions(&[&TLS13])?;
		let resolver = Arc::new(SingleCertAndKey::from(Arc::clone(key)));
		let mut config = builder.with_client_cert_verifier(verifier).with_cert_resolver(resolver);
		config.alpn_protocols = vec![ALPN_H2.to_vec()];
		Ok(config)
	}

	/// The config of a dial that trusts `roots`, and presents `identity` when
	/// it is `Some`.
	///
	/// # Errors
	///
	/// - [`EdgeError::Tls`] -- the provider refuses TLS 1.3.
	fn client(roots: &Arc<RootCertStore>, identity: Option<&Arc<CertifiedKey>>) -> Result<ClientConfig, EdgeError> {
		let builder = ClientConfig::builder_with_provider(Self::provider()).with_protocol_versions(&[&TLS13])?;
		let builder = builder.with_root_certificates(Arc::clone(roots));
		let mut config = match identity {
			Some(identity) => builder.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(Arc::clone(identity)))),
			None => builder.with_no_client_auth(),
		};

		config.alpn_protocols = vec![ALPN_H2.to_vec()];
		Ok(config)
	}
}

/// The TLS of the bind of an edge: the certificate chain that the edge
/// presents, and its private key.
///
/// # Examples
///
/// ```
/// use tightbeam_grpc::edge::{Edge, EdgeTls, EdgeTlsFiles};
/// # use tightbeam_grpc::testing::{CoupledStack, MintError};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let dir = std::env::temp_dir().join(format!("tightbeam-grpc-doc-edge-{}", std::process::id()));
/// # let stack = CoupledStack::at(dir);
/// # stack.write(core::time::Duration::from_secs(60), |_| Ok::<(), MintError>(()))?;
/// # let (chain, key) = (stack.edge_chain(), stack.edge_key());
///
/// let tls = EdgeTls::from_pem(EdgeTlsFiles { chain, key })?;
/// let edge = Edge::tls(tls);
/// # std::fs::remove_dir_all(stack.dir())?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct EdgeTls {
	key: Arc<CertifiedKey>,
}

impl EdgeTls {
	/// TLS under `chain`, the certificate of the edge first and the
	/// certificates of its issuers after it, and `key`, the private key of the
	/// certificate of the edge.
	///
	/// # Errors
	///
	/// - [`EdgeError::NoCertificate`] -- `chain` is empty.
	/// - [`EdgeError::Tls`] -- rustls refuses the key, such as a key that does
	///   not match the certificate.
	pub fn new(
		chain: impl IntoIterator<Item = CertificateDer<'static>>,
		key: PrivateKeyDer<'static>,
	) -> Result<Self, EdgeError> {
		let key = EdgeTlsPolicy::certified(chain.into_iter().collect(), key)?;
		Ok(Self { key })
	}

	/// TLS under the PEM certificate chain and the PEM private key in
	/// `files`, as [`EdgeTls::new`] takes them.
	///
	/// # Errors
	///
	/// - [`EdgeError::Io`] -- a file cannot be read.
	/// - [`EdgeError::Pem`] -- a file is malformed, or the key file holds no private key.
	/// - The errors of [`EdgeTls::new`].
	pub fn from_pem<P: AsRef<Path>>(files: EdgeTlsFiles<P>) -> Result<Self, EdgeError> {
		let certificates = CertificateDer::pem_file_iter(files.chain)?;
		let chain = certificates.collect::<Result<Vec<_>, _>>()?;
		let key = PrivateKeyDer::from_pem_file(files.key)?;
		Self::new(chain, key)
	}

	/// The acceptor of a bind that verifies each client chain with
	/// `verifier`, or admits every connection with no client chain when it
	/// is `None`.
	///
	/// # Errors
	///
	/// - The errors of [`EdgeTlsPolicy::server`].
	pub(super) fn acceptor(&self, verifier: Option<Arc<dyn ClientCertVerifier>>) -> Result<TlsAcceptor, EdgeError> {
		let verifier = verifier.unwrap_or_else(WebPkiClientVerifier::no_client_auth);
		let config = EdgeTlsPolicy::server(&self.key, verifier)?;
		Ok(TlsAcceptor::from(Arc::new(config)))
	}
}

/// The PEM files of the TLS of an edge, which [`EdgeTls::from_pem`] reads.
#[derive(Clone, Debug)]
pub struct EdgeTlsFiles<P> {
	/// The file of the certificate chain: the certificate of the edge first,
	/// and the certificates of its issuers after it.
	pub chain: P,
	/// The file of the private key of the certificate of the edge.
	pub key: P,
}

/// The TLS of a dial of an edge: the roots that the certificate of the edge
/// must chain to.
///
/// - The dial names the host of its [`GrpcAddr`] as the server it verifies,
///   so the certificate of the edge carries that DNS name or IP address as a
///   subject alternative name.
///
/// # Examples
///
/// ```
/// use tightbeam_grpc::edge::{Dial, DialTls};
/// # use tightbeam_grpc::testing::{CoupledStack, MintError};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let dir = std::env::temp_dir().join(format!("tightbeam-grpc-doc-dial-{}", std::process::id()));
/// # let stack = CoupledStack::at(dir);
/// # stack.write(core::time::Duration::from_secs(60), |_| Ok::<(), MintError>(()))?;
/// # let roots = stack.root();
///
/// let tls = DialTls::from_pem(&roots)?;
/// let dial = Dial::Tls(tls);
/// # std::fs::remove_dir_all(stack.dir())?;
/// # Ok(())
/// # }
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
		let config = EdgeTlsPolicy::client(&roots, None)?;
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
		let identity = EdgeTlsPolicy::certified(chain.into_iter().collect(), key)?;
		let config = EdgeTlsPolicy::client(&self.roots, Some(&identity))?;
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
	/// - The connect URI stays `http`, so tonic hands the connection to the
	///   connector under any tonic features.
	/// - The origin of each call names `https`, so its `:scheme` says TLS.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidAddress`] -- tonic refuses the URI of `addr`.
	pub(crate) fn endpoint(&self, addr: &GrpcAddr) -> Result<TlsEndpoint, TransportError> {
		let endpoint = addr.endpoint()?;
		let origin = Uri::try_from(format!("https://{addr}")).map_err(|_| TransportError::InvalidAddress)?;

		let name = addr.server_name();
		let connector = TlsConnector::from(Arc::clone(&self.config));
		let dialer = TlsDialer { connector, authority: addr.to_string(), name };

		Ok(TlsEndpoint { endpoint: endpoint.origin(origin), dialer })
	}
}

/// The endpoint of one TLS dial, and the connector that secures its
/// connection.
pub(crate) struct TlsEndpoint {
	pub(crate) endpoint: Endpoint,
	pub(crate) dialer: TlsDialer,
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
