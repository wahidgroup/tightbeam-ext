use tightbeam::Errorizable;

/// Result alias for fallible `tightbeam-ws` operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced by the WebSocket transport.
#[derive(Debug, Errorizable)]
#[non_exhaustive]
pub enum Error {
	/// An underlying I/O operation failed.
	#[error("i/o error: {0}")]
	#[from]
	Io(std::io::Error),
	/// The WebSocket protocol layer (handshake or framing) failed.
	#[error("websocket protocol error: {0}")]
	Tungstenite(Box<tokio_tungstenite::tungstenite::Error>),
	/// A tightbeam crypto, certificate, or transport operation failed.
	#[error("tightbeam error: {0}")]
	#[from]
	Tightbeam(tightbeam::TightBeamError),
	/// A transport-layer operation failed while driving a handshake.
	#[cfg(feature = "testing")]
	#[error("transport error: {0}")]
	#[from]
	Transport(tightbeam::transport::error::TransportError),
	/// The peer sent an encrypted container during the cleartext
	/// handshake phase.
	#[cfg(feature = "testing")]
	#[error("handshake containers must be cleartext")]
	HandshakeCiphertext,
	/// The handshake did not complete within the message ceiling.
	#[cfg(feature = "testing")]
	#[error("the handshake did not complete within the message ceiling")]
	HandshakeIncomplete,
}

impl From<tokio_tungstenite::tungstenite::Error> for Error {
	fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
		Self::Tungstenite(Box::new(error))
	}
}
