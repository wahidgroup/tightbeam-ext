//! The browser WebSocket as a tightbeam protocol. Compiled only for `wasm32`
//! targets.
//!
//! The wasm32 counterpart of `tightbeam_ws::protocol::WsListener`.
//! [`ClientBuilder`] provisions every client: it answers the dialer rule and
//! the key-purpose check, then hands the transport to
//! [`Protocol::create_transport`].

use core::marker::PhantomData;
use std::sync::Arc;

use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::KeyCurves;
use tightbeam::der::Decode;
use tightbeam::transport::handshake::HandshakeProvider;
use tightbeam::transport::{
	ClientBuilder, ConnectionBuilder, EndpointConfig, Protocol, TcpTransport, TightBeamAddress, TransportError,
	TransportResult,
};

use tightbeam::x509::Certificate;

use crate::clock::BrowserClock;
use crate::stream::{GlooStream, WsTransport};

/// The address of a socket the page already opened.
///
/// The bindings open each socket through the lifecycle observer, so nothing
/// dials through [`Protocol::connect`].
#[derive(Clone)]
pub struct OpenedSocket;

impl From<OpenedSocket> for Vec<u8> {
	fn from(_: OpenedSocket) -> Self {
		Vec::new()
	}
}

impl TightBeamAddress for OpenedSocket {}

/// A tightbeam protocol over a browser WebSocket, under the provider `P`.
pub struct BrowserSocket<P>(PhantomData<fn() -> P>);

/// The protocol of a socket the page opened, so it adopts and never dials.
///
/// A page opens each socket itself, and [`BrowserSocket::pinned`] adopts it
/// into a transport. [`Protocol::connect`] and [`Protocol::bind_cleartext`]
/// therefore refuse with [`TransportError::InvalidState`], and
/// [`Protocol::create_transport`] wraps the stream an adopt hands it.
impl<P: CryptoProvider + Send + Sync + 'static> Protocol for BrowserSocket<P> {
	type Listener = ();
	type Stream = GlooStream;
	type Transport = WsTransport<P>;
	type Error = TransportError;
	type Address = OpenedSocket;
	type CryptoProvider = P;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		Ok(OpenedSocket)
	}

	/// A page accepts no connections.
	async fn bind_cleartext(_addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		Err(TransportError::InvalidState)
	}

	async fn connect(_addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		Err(TransportError::InvalidState)
	}

	fn create_transport(stream: Self::Stream, config: EndpointConfig<P>) -> Self::Transport {
		TcpTransport::new(stream, config)
	}
}

impl<P: HandshakeProvider> BrowserSocket<P> {
	/// A builder on the host's clock.
	fn builder() -> ClientBuilder<Self> {
		ClientBuilder::on_clock(Arc::new(BrowserClock))
	}

	/// The transport of a client that pins `trust_store` over `stream`, and
	/// presents `identity` when a server demands mutual authentication.
	///
	/// The provider `P` is a compile-time choice. `trust_store` MUST validate
	/// under the algorithms of `P`, or every handshake fails.
	///
	/// # Errors
	///
	/// - [`TransportError`] -- the dialer rule or the key-purpose check refuses
	///   the provisioning.
	pub fn pinned(
		stream: impl Into<GlooStream>,
		trust_store: Arc<dyn CertificateTrust>,
		identity: Option<SigningIdentity>,
	) -> TransportResult<WsTransport<P>> {
		let mut builder = Self::builder().with_trust_store(trust_store);
		if let Some(identity) = identity {
			builder = builder.with_client_identity(identity);
		}

		let client = builder.adopt(stream.into())?;
		Ok(client.into_transport())
	}

	/// A transport over `stream` that carries no confidentiality, integrity,
	/// or peer authentication.
	///
	/// # Errors
	///
	/// - [`TransportError`] -- the dialer rule refuses the provisioning.
	pub(crate) fn cleartext(stream: GlooStream) -> TransportResult<WsTransport<P>> {
		let client = Self::builder().allow_cleartext().adopt(stream)?;
		Ok(client.into_transport())
	}
}

impl BrowserSocket<DefaultCryptoProvider> {
	/// The trust store of the default profile: one anchor that pins the
	/// certificate in `server_cert_der`, validated under the secp256k1
	/// certificate policy on the host's clock.
	///
	/// # Errors
	///
	/// - [`TransportError::DerError`] -- `server_cert_der` is no DER certificate.
	/// - [`TransportError::InvalidCertificate`] -- the store refuses the certificate.
	pub fn trust_store(server_cert_der: impl AsRef<[u8]>) -> TransportResult<Arc<dyn CertificateTrust>> {
		let server_cert = Certificate::from_der(server_cert_der.as_ref())?;
		let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
		let builder = builder.with_clock(Arc::new(BrowserClock));

		let store = builder.with_certificate(server_cert)?.build();
		Ok(Arc::new(store))
	}
}
