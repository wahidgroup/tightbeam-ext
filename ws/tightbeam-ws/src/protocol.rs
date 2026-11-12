//! The tightbeam listener over WebSocket, [`WsListener`], as `docs/ws.md`
//! (Listener) states it.

use core::str::FromStr;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, ToSocketAddrs};

use tightbeam::clock::{Clock, SystemClock};
use tightbeam::crypto::aead::{RecvCipher, SendCipher};
use tightbeam::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::{
	AsyncListenerTrait, CheckedLimits, EncryptedProtocol, EndpointConfig, PersistentConnection, Protocol, TcpTransport,
	TransportEncryptionConfig, TransportError,
};

use crate::acceptor::{Acceptor, WsInner};
use crate::io::{WsStream, WsTransport};

/// A tightbeam listener that speaks the protocol over WebSocket connections.
///
/// - Every accepted transport builds from the one [`EndpointConfig`] that the listener holds.
/// - The listener upgrades on a task of its own, which ends when the listener drops.
/// - The upgrade deadline, the accept retry, and every transport run on the one clock of the bind.
///
/// # Examples
///
/// ```
/// use tightbeam_ws::protocol::WsListener;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> tightbeam_ws::Result<()> {
/// let listener: WsListener = WsListener::bind_cleartext("127.0.0.1:0").await?;
/// assert!(listener.local_addr().ip().is_loopback());
/// # Ok(())
/// # }
/// ```
pub struct WsListener<P: CryptoProvider = DefaultCryptoProvider> {
	acceptor: Acceptor,
	local_addr: SocketAddr,
	config: EndpointConfig<P>,
}

impl<P: CryptoProvider> WsListener<P> {
	/// Bind a listener to `addr` whose accepted transports build from
	/// `config` and measure against `clock`. Its accept task starts here.
	///
	/// - `clock` replaces the clock that `config` holds ([`EndpointConfig::with_clock`]).
	///
	/// # Errors
	///
	/// - The [`io::Error`] of an `addr` that does not bind.
	pub async fn bind(addr: impl ToSocketAddrs, config: EndpointConfig<P>, clock: Arc<dyn Clock>) -> io::Result<Self> {
		let listener = TcpListener::bind(addr).await?;
		let local_addr = listener.local_addr()?;
		let config = config.with_clock(Arc::clone(&clock));
		let acceptor = Acceptor::start(listener, config.limits(), clock);
		Ok(Self { acceptor, local_addr, config })
	}

	/// Bind a cleartext listener to `addr` on [`SystemClock`].
	///
	/// Accepted transports carry no confidentiality, integrity, or peer
	/// authentication (CWE-319), so the name says it. An encrypted bind goes
	/// through [`EncryptedProtocol::bind_with`].
	///
	/// # Errors
	///
	/// - [`Error::Io`](crate::Error::Io) -- `addr` does not bind.
	pub async fn bind_cleartext(addr: impl AsRef<str>) -> crate::Result<Self> {
		Ok(Self::bind(addr.as_ref(), EndpointConfig::cleartext(), Arc::new(SystemClock)).await?)
	}

	/// The local address the listener is bound to.
	#[must_use]
	pub fn local_addr(&self) -> SocketAddr {
		self.local_addr
	}
}

impl<P: CryptoProvider + Send + Sync + 'static> WsListener<P> {
	/// The next finished upgrade, as a transport of this listener and the
	/// address of its peer.
	///
	/// The listener retries a failed TCP accept, and only its drop ends the
	/// accept task.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the accept task is gone.
	pub async fn accept(&self) -> Result<(WsTransport<WsInner, P>, SocketAddr), TransportError> {
		let (stream, addr) = self.acceptor.next().await.ok_or(TransportError::ConnectionClosed)?;
		let transport = TcpTransport::new(stream, self.config.clone());
		Ok((transport, addr))
	}
}

impl<P: CryptoProvider + Send + Sync + 'static> Protocol for WsListener<P> {
	type Listener = WsListener<P>;
	type Stream = WsStream<WsInner>;
	type Transport = WsTransport<WsInner, P>;
	type Error = TransportError;
	type Address = TightBeamSocketAddr;
	type CryptoProvider = P;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		let addr = SocketAddr::from_str("127.0.0.1:0")
			.map_err(|error| TransportError::IoError(io::Error::new(io::ErrorKind::InvalidInput, error)))?;
		Ok(TightBeamSocketAddr(addr))
	}

	async fn bind_cleartext(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let config = EndpointConfig::cleartext();
		let bound = Self::bind(addr.0, config, Arc::new(SystemClock))
			.await
			.map_err(TransportError::IoError)?;
		let local_addr = TightBeamSocketAddr(bound.local_addr);
		Ok((bound, local_addr))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		Self::connect_within(addr, &CheckedLimits::default()).await
	}

	async fn connect_within(addr: Self::Address, limits: &CheckedLimits) -> Result<Self::Stream, Self::Error> {
		let url = format!("ws://{}/", addr.0);
		WsStream::dial(&url, limits).await
	}

	fn create_transport(stream: Self::Stream, config: EndpointConfig<P>) -> Self::Transport {
		TcpTransport::new(stream, config)
	}
}

impl<P: CryptoProvider + Send + Sync + 'static> EncryptedProtocol for WsListener<P> {
	type Encryptor = SendCipher;
	type Decryptor = RecvCipher;

	async fn bind_with(
		addr: Self::Address,
		config: TransportEncryptionConfig<P>,
	) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let config = EndpointConfig::try_from(config)?;
		let bound = Self::bind(addr.0, config, Arc::new(SystemClock))
			.await
			.map_err(TransportError::IoError)?;
		let local_addr = TightBeamSocketAddr(bound.local_addr);
		Ok((bound, local_addr))
	}
}

impl<P: CryptoProvider + Send + Sync + 'static> AsyncListenerTrait for WsListener<P> {
	async fn accept(&self) -> Result<(Self::Transport, Self::Address), Self::Error> {
		let (transport, addr) = WsListener::accept(self).await?;
		Ok((transport, TightBeamSocketAddr(addr)))
	}
}

/// A WebSocket endpoint behind a
/// [`ConnectionPool`](tightbeam::transport::ConnectionPool), which reuses one
/// connection across leases.
impl<P: CryptoProvider + Send + Sync + 'static> PersistentConnection for WsListener<P> {
	fn is_connected(transport: &Self::Transport) -> bool {
		transport.is_leasable()
	}

	/// The socket closes with no Close frame when the transport drops, as
	/// `docs/ws.md` (Limitations) states.
	fn try_close(_transport: &mut Self::Transport) {}
}
