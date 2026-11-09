//! An echo that any tightbeam transport runs against itself, so the suites of
//! the transports share one server side and one client side.

use core::hash::Hash;
use core::num::NonZeroUsize;
use std::sync::Arc;

use tightbeam::crypto::profiles::CryptoProvider;
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::marker::MaybeSend;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::error::TransportError;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::multiplex::{CallContext, MuxAcceptor, MuxConnector, MuxService, ReplySink, StreamBody};
use tightbeam::transport::policy::PolicyConfig;
use tightbeam::transport::state::EncryptedProtocolState;
use tightbeam::transport::{
	AsyncListenerTrait, AsyncProtocolStream, ClientBuilder, ConnectionBuilder, ConnectionPool, MessageCollector,
	MessageEmitter, PersistentConnection, PoolConfig, Protocol, TcpTransport,
};
use tightbeam::{encode, server, Frame, TightBeamError};
use tokio::task::JoinHandle;

use crate::Result as WsResult;

/// The concurrent streams of the pooled echo.
const POOL_STREAMS: u32 = 8;

/// The two chunks of the duplex echo.
const DUPLEX_CHUNKS: [&[u8]; 2] = [b"pooled-duplex-a", b"pooled-duplex-b"];

/// An echo of every stream kind, and of one request on one connection.
///
/// - Unary echoes the frame.
/// - Streaming reassembles the body through [`StreamBody::into_frame`] and
///   echoes the frame.
/// - Duplex echoes each request chunk on the reply sink.
#[derive(Clone, Copy, Debug, Default)]
pub struct EchoService;

/// What one pooled, multiplexed connection echoed: whether the lease pinned
/// the certificate of its peer, and the answer of each stream kind.
#[derive(Debug, PartialEq)]
pub struct PoolEchoes {
	/// Whether the lease exposes the certificate that its handshake pinned.
	pub peer_pinned: bool,
	/// The answer of a unary emit.
	pub unary: Option<Frame>,
	/// The answer of a stream that carried the DER of the frame in two chunks.
	pub streamed: Option<Frame>,
	/// The chunks of a duplex echo, in order, up to its end.
	pub duplex: Vec<Vec<u8>>,
}

impl PoolEchoes {
	/// The echoes of a transport that carries every stream kind of `frame`.
	pub fn of(frame: &Frame) -> Self {
		let duplex = DUPLEX_CHUNKS.iter().map(|chunk| chunk.to_vec()).collect();
		Self {
			peer_pinned: true,
			unary: Some(frame.clone()),
			streamed: Some(frame.clone()),
			duplex,
		}
	}
}

impl EchoService {
	/// Serve this echo on every connection that `listener` accepts, through
	/// tightbeam's `server!`, recording each session on `trace`.
	///
	/// The server answers `offer` to a client that offers multiplexing, and a
	/// client that offers none gets the single-flight unary echo. A `None`
	/// offer declines multiplexing to every client.
	pub fn serve<L, S, C>(listener: L, offer: Option<TransportOffer>, trace: &TraceCollector) -> JoinHandle<()>
	where
		L: AsyncListenerTrait<Transport = TcpTransport<S, C>> + Send + Sync + 'static,
		S: AsyncProtocolStream,
		C: CryptoProvider + Send + Sync,
		TransportError: From<S::Error>,
		TcpTransport<S, C>: MessageCollector + MuxAcceptor + EncryptedProtocolState + Send + 'static,
	{
		let trace = trace.share();
		// The accept loop re-applies policies per connection, so the share and
		// the clone stay expressions that give each accept a fresh value.
		server! {
			protocol L: listener,
			policies: {
				with_trace: [ trace.share() ],
				with_mux_offer: [ offer.clone() ]
			},
			service: EchoService
		}
	}

	/// Echo `frame` once over a dial of the protocol `P` to `addr`, whose
	/// server serves this echo, with a client that pins `trust`, and return
	/// the answer.
	///
	/// The client dials through `ClientBuilder`, which takes no trace, and
	/// sends `frame` on the transport of the dial with `trace` attached, so the
	/// handshake of the client records beside the session of the server.
	///
	/// # Errors
	///
	/// - [`Error::Tightbeam`](crate::Error::Tightbeam) -- the dial, the
	///   handshake, or the exchange fails.
	pub async fn exchange<P, S, C>(
		addr: P::Address,
		trust: Arc<dyn CertificateTrust>,
		frame: Frame,
		trace: &TraceCollector,
	) -> WsResult<Option<Frame>>
	where
		P: Protocol<Transport = TcpTransport<S, C>> + MaybeSend,
		S: AsyncProtocolStream,
		C: CryptoProvider + Send + Sync,
		TransportError: From<S::Error>,
		TcpTransport<S, C>: MessageEmitter + MessageCollector + PolicyConfig,
	{
		let builder = ClientBuilder::<P>::builder().with_trust_store(trust);
		let dialed = builder.connect(addr).await?;

		let mut transport = dialed.into_transport().with_trace(trace.share());
		let answer = transport.emit(frame, None).await?;
		Ok(answer)
	}

	/// Run every stream kind over one pooled, multiplexed connection of the
	/// protocol `P` to `addr`, whose server serves this echo, with a client
	/// that pins `trust` and records its pool events on `trace`.
	///
	/// # Errors
	///
	/// - The [`Error::Transport`](crate::Error::Transport) or
	///   [`Error::Tightbeam`](crate::Error::Tightbeam) of a dial or a stream.
	pub async fn through_pool<P>(
		addr: P::Address,
		trust: Arc<dyn CertificateTrust>,
		frame: &Frame,
		trace: &TraceCollector,
	) -> WsResult<PoolEchoes>
	where
		P: Protocol + PersistentConnection + Send + Sync,
		P::Address: Hash + Eq + Clone + Send + Sync,
		P::Transport:
			MessageEmitter + MessageCollector + PolicyConfig + MuxConnector + EncryptedProtocolState + Send + Sync,
	{
		let offer = Some(Arc::new(TransportOffer::mux(POOL_STREAMS)));
		let config = PoolConfig { idle_timeout: None, max_connections: NonZeroUsize::MIN, mux_offer: offer };
		let builder = ConnectionPool::<P>::builder().with_config(config).with_trust_store(trust);
		let pool = Arc::new(builder.with_trace(trace.share()).build());

		let mut lease = pool.connect(addr).await?;
		let peer_pinned = lease.peer_certificate().is_some();
		let unary = lease.emit(frame.clone(), None).await?;

		let der = encode(frame)?;
		let (head, tail) = der.split_at(der.len() / 2);
		let (mut sink, response) = lease.open_stream()?;
		sink.push(head).await?;
		sink.close_with(tail).await?;
		let streamed = response.await?;

		let [first, last] = DUPLEX_CHUNKS;
		let (mut sink, mut body) = lease.open_duplex()?;
		sink.push(first).await?;
		sink.close_with(last).await?;
		let mut duplex = Vec::new();
		while let Some(chunk) = body.chunk().await? {
			duplex.push(chunk);
		}

		Ok(PoolEchoes { peer_pinned, unary, streamed, duplex })
	}
}

impl MuxService for EchoService {
	async fn unary(&self, frame: Frame, _ctx: CallContext) -> Result<Option<Frame>, TightBeamError> {
		Ok(Some(frame))
	}

	async fn streaming(&self, body: StreamBody, _ctx: CallContext) -> Result<Option<Frame>, TightBeamError> {
		let frame = body.into_frame().await?;
		Ok(Some(frame))
	}

	async fn duplex(
		&self,
		mut body: StreamBody,
		mut reply: ReplySink,
		_ctx: CallContext,
	) -> Result<(), TightBeamError> {
		while let Some(chunk) = body.chunk().await? {
			reply.push(&chunk).await?;
		}
		Ok(())
	}
}
