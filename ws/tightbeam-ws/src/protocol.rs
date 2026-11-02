//! WebSocket protocol implementation for tightbeam.
//!
//! [`WsListener`] implements tightbeam's [`Protocol`], [`EncryptedProtocol`],
//! and [`AsyncListenerTrait`] traits which define the transport layer.

use core::str::FromStr;

use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async_with_config, connect_async_with_config, MaybeTlsStream};

use tightbeam::crypto::aead::{RecvCipher, SendCipher};
use tightbeam::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::{
	AsyncListenerTrait, EncryptedProtocol, EndpointConfig, PersistentConnection, Protocol, TcpTransport,
	TransportEncryptionConfig, TransportError, TransportLimits,
};

use crate::io::{bounded_config, map_ws_error, WsStream, WsTransport};

/// The byte stream shared by both ends of a WebSocket connection.
type WsInner = MaybeTlsStream<TcpStream>;

fn io_error(error: std::io::Error) -> TransportError {
	TransportError::IoError(error)
}

/// A tightbeam listener that speaks the protocol over WebSocket connections.
///
/// Every accepted transport builds from the one [`EndpointConfig`] the
/// listener holds, so the listener's provisioning and ceilings reach each
/// connection.
pub struct WsListener<P: CryptoProvider = DefaultCryptoProvider> {
	listener: TcpListener,
	config: EndpointConfig<P>,
}

impl<P: CryptoProvider> WsListener<P> {
	/// Bind a cleartext listener to `addr` (e.g. `127.0.0.1:0`).
	///
	/// Accepted transports carry no confidentiality, integrity, or peer
	/// authentication (CWE-319), so the name says it. An encrypted bind goes
	/// through [`EncryptedProtocol::bind_with`].
	pub async fn bind_cleartext(addr: impl AsRef<str>) -> crate::Result<Self> {
		let listener = TcpListener::bind(addr.as_ref()).await?;
		let config = EndpointConfig::cleartext();

		Ok(Self { listener, config })
	}

	/// The local address the listener is bound to.
	pub fn local_addr(&self) -> crate::Result<std::net::SocketAddr> {
		Ok(self.listener.local_addr()?)
	}
}

impl<P: CryptoProvider + Send + Sync + 'static> WsListener<P> {
	/// Accept the next connection as a transport built from this listener's
	/// configuration.
	///
	/// Inherent accept used by the `server!` macro loop.
	/// Yields the raw [`std::net::SocketAddr`] (see also
	/// [`AsyncListenerTrait::accept`]).
	pub async fn accept(&self) -> Result<(WsTransport<WsInner, P>, std::net::SocketAddr), TransportError> {
		let (tcp, addr) = self.listener.accept().await.map_err(io_error)?;
		let ceilings = bounded_config(self.config.limits());

		let upgraded = accept_async_with_config(MaybeTlsStream::Plain(tcp), Some(ceilings)).await;
		let websocket = upgraded.map_err(map_ws_error)?;
		let transport = TcpTransport::new(WsStream::new(websocket), self.config.clone());

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
		let addr = std::net::SocketAddr::from_str("127.0.0.1:0")
			.map_err(|e| io_error(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
		Ok(TightBeamSocketAddr(addr))
	}

	async fn bind_cleartext(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = TcpListener::bind(addr.0).await.map_err(io_error)?;
		let bound = listener.local_addr().map_err(io_error)?;
		let config = EndpointConfig::cleartext();

		Ok((Self { listener, config }, TightBeamSocketAddr(bound)))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		let url = format!("ws://{}/", addr.0);

		// The dial runs ahead of the endpoint configuration, so the socket
		// takes the default ceilings. The transport narrows each read to the
		// ceiling of its own phase.
		let ceilings = bounded_config(&TransportLimits::default());
		let dialed = connect_async_with_config(url, Some(ceilings), false).await;
		let (websocket, _response) = dialed.map_err(map_ws_error)?;

		Ok(WsStream::new(websocket))
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
		let listener = TcpListener::bind(addr.0).await.map_err(io_error)?;
		let bound = listener.local_addr().map_err(io_error)?;
		let config = EndpointConfig::try_from(config)?;

		Ok((Self { listener, config }, TightBeamSocketAddr(bound)))
	}
}

impl<P: CryptoProvider + Send + Sync + 'static> AsyncListenerTrait for WsListener<P> {
	async fn accept(&self) -> Result<(Self::Transport, Self::Address), Self::Error> {
		let (transport, addr) = WsListener::accept(self).await?;
		Ok((transport, TightBeamSocketAddr(addr)))
	}
}

/// Pooling support: lets WebSocket endpoints sit behind tightbeam's
/// `ConnectionPool` (and therefore the colony stack), reusing one
/// encrypted, multiplexed connection across leases.
impl<P: CryptoProvider + Send + Sync + 'static> PersistentConnection for WsListener<P> {
	fn is_connected(transport: &Self::Transport) -> bool {
		transport.is_leasable()
	}

	fn try_close(_transport: &mut Self::Transport) {
		// The WebSocket closes when the transport drops.
	}
}
