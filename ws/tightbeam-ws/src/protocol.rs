//! WebSocket protocol implementation for tightbeam.
//!
//! [`WsListener`] implements tightbeam's [`Protocol`], [`EncryptedProtocol`],
//! and [`AsyncListenerTrait`] traits which define the transport layer.

use core::str::FromStr;

use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, connect_async, MaybeTlsStream};

use tightbeam::crypto::aead::RuntimeAead;
use tightbeam::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::{
	AsyncListenerTrait, EncryptedProtocol, Protocol, TransportEncryptionConfig, TransportError,
};

use crate::io::{map_ws_error, WsStream, WsTransport};

/// The byte stream shared by both ends of a WebSocket connection.
type WsInner = MaybeTlsStream<TcpStream>;

fn io_error(error: std::io::Error) -> TransportError {
	TransportError::IoError(error)
}

/// A tightbeam listener that speaks the protocol over WebSocket connections.
pub struct WsListener<P: CryptoProvider = DefaultCryptoProvider> {
	listener: TcpListener,
	config: Option<TransportEncryptionConfig<P>>,
}

impl<P: CryptoProvider> WsListener<P> {
	/// Bind a cleartext listener to `addr` (e.g. `127.0.0.1:0`).
	pub async fn bind(addr: &str) -> crate::Result<Self> {
		let listener = TcpListener::bind(addr).await?;
		Ok(Self { listener, config: None })
	}

	/// The local address the listener is bound to.
	pub fn local_addr(&self) -> crate::Result<std::net::SocketAddr> {
		Ok(self.listener.local_addr()?)
	}
}

impl<P: CryptoProvider + Send + Sync> WsListener<P> {
	/// Accept the next connection, applying server encryption when configured.
	///
	/// Inherent accept used by the `server!` macro loop.
	/// Yields the raw [`std::net::SocketAddr`] (see also
	/// [`AsyncListenerTrait::accept`]).
	pub async fn accept(&self) -> Result<(WsTransport<WsInner, P>, std::net::SocketAddr), TransportError> {
		let (tcp, addr) = self.listener.accept().await.map_err(io_error)?;
		let websocket = accept_async(MaybeTlsStream::Plain(tcp)).await.map_err(map_ws_error)?;
		let mut transport = WsTransport::from(WsStream::new(websocket));

		if let Some(config) = &self.config {
			transport = transport.with_server_encryption(config.clone());
		}

		Ok((transport, addr))
	}
}

impl<P: CryptoProvider + Send + Sync> Protocol for WsListener<P> {
	type Listener = WsListener<P>;
	type Stream = WsStream<WsInner>;
	type Transport = WsTransport<WsInner, P>;
	type Error = TransportError;
	type Address = TightBeamSocketAddr;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		let addr = std::net::SocketAddr::from_str("127.0.0.1:0")
			.map_err(|e| io_error(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
		Ok(TightBeamSocketAddr(addr))
	}

	async fn bind(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = TcpListener::bind(addr.0).await.map_err(io_error)?;
		let bound = listener.local_addr().map_err(io_error)?;
		Ok((Self { listener, config: None }, TightBeamSocketAddr(bound)))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		let url = format!("ws://{}/", addr.0);
		let (websocket, _response) = connect_async(url).await.map_err(map_ws_error)?;
		Ok(WsStream::new(websocket))
	}

	fn create_transport(stream: Self::Stream) -> Self::Transport {
		WsTransport::from(stream)
	}

	fn to_tightbeam_addr(&self) -> Result<Self::Address, Self::Error> {
		let addr = self.listener.local_addr().map_err(io_error)?;
		Ok(TightBeamSocketAddr(addr))
	}
}

impl<P: CryptoProvider + Send + Sync> EncryptedProtocol for WsListener<P> {
	type Encryptor = RuntimeAead;
	type Decryptor = RuntimeAead;
	type CryptoProvider = P;

	async fn bind_with(
		addr: Self::Address,
		config: TransportEncryptionConfig<P>,
	) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = TcpListener::bind(addr.0).await.map_err(io_error)?;
		let bound = listener.local_addr().map_err(io_error)?;
		Ok((Self { listener, config: Some(config) }, TightBeamSocketAddr(bound)))
	}
}

impl<P: CryptoProvider + Send + Sync> AsyncListenerTrait for WsListener<P> {
	async fn accept(&self) -> Result<(Self::Transport, Self::Address), Self::Error> {
		let (transport, addr) = WsListener::accept(self).await?;
		Ok((transport, TightBeamSocketAddr(addr)))
	}
}
