//! Assemble a multiplexed plane over a handshaken WebSocket transport.
//!
//! Thin re-shape of [`TcpTransport::into_mux`]: the transport owns the
//! settings/rekey/split choreography, this module only pins the
//! WebSocket half types.
//!
//! [`TcpTransport::into_mux`]: tightbeam::transport::tcp::r#async::TcpTransport::into_mux

use tokio::io::{AsyncRead, AsyncWrite};

use tightbeam::transport::multiplex::{MuxRole, MuxTransport};
use tightbeam::transport::tcp::r#async::{TransportReader, TransportWriter};
use tightbeam::transport::TransportResult;

use crate::io::{WsReadHalf, WsTransport, WsWriteHalf};

/// Envelope read half produced by [`assemble_mux`].
pub type MuxReadHalf<S> = TransportReader<WsReadHalf<S>>;
/// Envelope write half produced by [`assemble_mux`].
pub type MuxWriteHalf<S> = TransportWriter<WsWriteHalf<S>>;

/// Multiplexed plane assembled by [`assemble_mux`].
pub type AssembledMux<S> = MuxTransport<MuxReadHalf<S>, MuxWriteHalf<S>>;

/// Split a handshaken encrypted WebSocket transport into a
/// [`MuxTransport`], attaching rekey materials when the session carries
/// a dual-signed receipt.
///
/// # Errors
/// - `InvalidState`: the peer did not negotiate multiplexing
/// - rekey harvest / split failures from the underlying transport
pub fn assemble_mux<S>(transport: WsTransport<S>, role: MuxRole) -> TransportResult<AssembledMux<S>>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	transport.into_mux(role)
}
