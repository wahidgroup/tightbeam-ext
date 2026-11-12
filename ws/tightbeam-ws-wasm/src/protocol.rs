//! The browser WebSocket as a tightbeam protocol, and the states of a session
//! on it, as the session profiles section of `docs/ws-wasm.md` describes.

use core::marker::PhantomData;
use std::sync::Arc;

use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::KeyCurves;
use tightbeam::transport::handshake::negotiation::{MuxSettings, TransportOffer};
use tightbeam::transport::handshake::receipt::ReceiptApprover;
use tightbeam::transport::handshake::HandshakeProvider;
use tightbeam::transport::multiplex::{MuxRole, MuxTransport};
use tightbeam::transport::{
	ClientBuilder, ConnectionBuilder, EncryptedMessageIO, EndpointConfig, Protocol, TcpTransport, TightBeamAddress,
	TransportError, TransportResult,
};

use tightbeam::x509::Certificate;

use crate::clock::BrowserClock;
use crate::mux::{BrowserMux, SessionParts};
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

/// The protocol of a socket the page opened, which it adopts in place of a
/// dial.
///
/// - A page opens each socket itself, and [`BrowserSocket::pinned`] adopts it into a transport.
/// - [`Protocol::connect`] and [`Protocol::bind_cleartext`] therefore refuse with
///   [`TransportError::InvalidState`].
/// - [`Protocol::create_transport`] wraps the stream an adopt hands it.
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
		ClientBuilder::on_clock(Arc::new(BrowserClock::host()))
	}

	/// The transport of a client that pins `trust_store` over `stream`, offers
	/// `mux` for its handshake, and presents `identity` when a server demands
	/// mutual authentication.
	///
	/// - The provider `P` is a compile-time choice.
	/// - `trust_store` MUST validate under the algorithms of `P`, or every handshake fails.
	///
	/// # Errors
	///
	/// - The [`TransportError`] of the dialer rule or the key-purpose check, when
	///   either refuses the provisioning.
	pub fn pinned(
		stream: impl Into<GlooStream>,
		trust_store: Arc<dyn CertificateTrust>,
		identity: Option<SigningIdentity>,
		mux: TransportOffer,
	) -> TransportResult<Pinned<P>> {
		let mut builder = Self::builder().with_trust_store(trust_store);
		if let Some(identity) = identity {
			builder = builder.with_client_identity(identity);
		}

		let client = builder.adopt(stream.into())?;
		let transport = client.into_transport().with_mux_offer(Some(mux));
		Ok(Pinned(transport))
	}
}

impl BrowserSocket<DefaultCryptoProvider> {
	/// The trust store of the default profile: one anchor that pins
	/// `server_cert`, validated under the secp256k1 certificate policy on the
	/// host's clock.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidCertificate`] -- the store refuses the certificate.
	pub fn trust_store(server_cert: Certificate) -> TransportResult<Arc<dyn CertificateTrust>> {
		let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
		let builder = builder.with_clock(Arc::new(BrowserClock::host()));

		let store = builder.with_certificate(server_cert)?.build();
		Ok(Arc::new(store))
	}

	/// The multiplexed session of `role` over `stream`, under the symmetric
	/// stream cap `streams`. It carries no confidentiality, integrity, or peer
	/// authentication.
	///
	/// # Errors
	///
	/// - The [`TransportError`] of the dialer rule when it refuses the provisioning, or of a
	///   transport that fails to split into its halves.
	pub(crate) fn cleartext_session(
		stream: impl Into<GlooStream>,
		role: MuxRole,
		streams: u32,
	) -> TransportResult<SessionParts> {
		let client = Self::builder().allow_cleartext().adopt(stream.into())?;
		let (reader, writer) = client.into_transport().into_split()?;

		let mux = MuxTransport::new(reader, writer, role, MuxSettings::symmetric(streams));
		mux.split()
	}
}

/// A transport that pins its server and offers multiplexing, which awaits its
/// handshake.
pub struct Pinned<P: HandshakeProvider>(WsTransport<P>);

impl<P: HandshakeProvider> Pinned<P> {
	/// This transport, with `approver` paying each settlement challenge of the
	/// session.
	#[must_use]
	pub fn approving(self, approver: Arc<dyn ReceiptApprover>) -> Self {
		Self(self.0.with_receipt_approver(approver))
	}

	/// Run the client handshake, and answer the session it negotiated.
	///
	/// # Errors
	///
	/// - The [`TransportError`] of a handshake that fails.
	pub async fn handshake(self) -> TransportResult<Session<P>> {
		let mut transport = self.0;
		transport.perform_client_handshake().await?;
		Ok(Session(transport))
	}
}

/// A transport whose handshake completed, which splits into a multiplexed
/// session through [`BrowserMux`].
pub struct Session<P: HandshakeProvider>(WsTransport<P>);

impl<P: HandshakeProvider> Session<P> {
	/// The usable outbound credits of each epoch, as the handshake negotiated
	/// them, or `None` when the session is unmetered.
	#[must_use]
	pub fn usable_send_budget(&self) -> Option<u64> {
		self.0.negotiated_mux().and_then(|settings| settings.usable_send_budget())
	}

	/// The transport, for the split of the session.
	pub(crate) fn into_transport(self) -> WsTransport<P> {
		self.0
	}
}
