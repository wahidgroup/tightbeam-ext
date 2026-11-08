//! WebSocket protocol implementation for tightbeam.
//!
//! [`WsListener`] implements tightbeam's [`Protocol`], [`EncryptedProtocol`],
//! and [`AsyncListenerTrait`] traits which define the transport layer.

use core::str::FromStr;
use std::io;
use std::net::SocketAddr;

use tokio::net::TcpListener;

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
/// Every accepted transport builds from the one [`EndpointConfig`] the
/// listener holds, so the listener's provisioning and ceilings reach each
/// connection.
///
/// The listener accepts on a task of its own, so a socket upgrades whether or
/// not a caller is waiting in [`accept`](Self::accept). The task ends when the
/// listener drops.
///
/// # Examples
///
/// ```
/// use tightbeam_ws::protocol::WsListener;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> tightbeam_ws::Result<()> {
/// let listener: WsListener = WsListener::bind_cleartext("127.0.0.1:0").await?;
/// assert!(listener.local_addr()?.ip().is_loopback());
/// # Ok(())
/// # }
/// ```
pub struct WsListener<P: CryptoProvider = DefaultCryptoProvider> {
	acceptor: Acceptor,
	local_addr: SocketAddr,
	config: EndpointConfig<P>,
}

impl<P: CryptoProvider> WsListener<P> {
	/// The one constructor: every bind starts its accept task here.
	fn from_listener(listener: TcpListener, config: EndpointConfig<P>) -> io::Result<Self> {
		let local_addr = listener.local_addr()?;
		let acceptor = Acceptor::start(listener, config.limits());
		Ok(Self { acceptor, local_addr, config })
	}

	/// Bind a cleartext listener to `addr`, such as `127.0.0.1:0`.
	///
	/// Accepted transports carry no confidentiality, integrity, or peer
	/// authentication (CWE-319), so the name says it. An encrypted bind goes
	/// through [`EncryptedProtocol::bind_with`].
	pub async fn bind_cleartext(addr: impl AsRef<str>) -> crate::Result<Self> {
		let listener = TcpListener::bind(addr.as_ref()).await?;
		let config = EndpointConfig::cleartext();
		Ok(Self::from_listener(listener, config)?)
	}

	/// The local address the listener is bound to.
	pub fn local_addr(&self) -> crate::Result<SocketAddr> {
		Ok(self.local_addr)
	}
}

impl<P: CryptoProvider + Send + Sync + 'static> WsListener<P> {
	/// Accept the next connection as a transport built from this listener's
	/// configuration.
	///
	/// Inherent accept used by the `server!` macro loop.
	/// Yields the raw [`SocketAddr`] (see also
	/// [`AsyncListenerTrait::accept`]).
	///
	/// Only a finished upgrade reaches this call, so the failure of an accept
	/// is the listener's own.
	///
	/// # Errors
	///
	/// - [`TransportError::IoError`] -- the listener failed to accept a TCP connection.
	/// - [`TransportError::ConnectionClosed`] -- the accept task stopped.
	pub async fn accept(&self) -> Result<(WsTransport<WsInner, P>, SocketAddr), TransportError> {
		let (stream, addr) = self.acceptor.next().await?;
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
		let listener = TcpListener::bind(addr.0).await.map_err(TransportError::IoError)?;
		let config = EndpointConfig::cleartext();

		let bound = Self::from_listener(listener, config).map_err(TransportError::IoError)?;
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
		let listener = TcpListener::bind(addr.0).await.map_err(TransportError::IoError)?;
		let config = EndpointConfig::try_from(config)?;

		let bound = Self::from_listener(listener, config).map_err(TransportError::IoError)?;
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

/// Pooling support: lets WebSocket endpoints sit behind tightbeam's
/// [`ConnectionPool`](tightbeam::transport::ConnectionPool), and therefore
/// the colony stack, reusing one encrypted, multiplexed connection across
/// leases.
impl<P: CryptoProvider + Send + Sync + 'static> PersistentConnection for WsListener<P> {
	fn is_connected(transport: &Self::Transport) -> bool {
		transport.is_leasable()
	}

	fn try_close(_transport: &mut Self::Transport) {
		// The WebSocket closes when the transport drops.
	}
}
