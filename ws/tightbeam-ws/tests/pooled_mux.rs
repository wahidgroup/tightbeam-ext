//! Pooled multiplexing over the WebSocket transport.
//!
//! Proves [`PersistentConnection`] wires WebSocket endpoints into
//! tightbeam's `ConnectionPool`: one encrypted, mux-negotiated WebSocket
//! connection serves unary and streaming interactions through pooled
//! leases against a `server!` service.
//!
//! [`PersistentConnection`]: tightbeam::transport::PersistentConnection

#![cfg(feature = "testing")]

use std::sync::Arc;
use std::time::Duration;

use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::create_v0_tightbeam;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::multiplex::{ReplySink, StreamBody};
use tightbeam::transport::serve::{CallContext, MuxService};
use tightbeam::transport::{ConnectionBuilder, ConnectionPool, EncryptedProtocol, PoolConfig};
use tightbeam::{encode, server, Frame, TightBeamError};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::Identity;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Unary echoes the frame; streaming reassembles via [`StreamBody::into_frame`];
/// duplex echoes each request chunk on the reply sink.
#[derive(Clone)]
struct PooledEchoService;

impl MuxService for PooledEchoService {
	async fn unary(&self, frame: Frame, _ctx: CallContext) -> Result<Option<Frame>, TightBeamError> {
		Ok(Some(frame))
	}

	async fn streaming(&self, body: StreamBody, _ctx: CallContext) -> Result<Option<Frame>, TightBeamError> {
		Ok(Some(body.into_frame().await?))
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_pooled_ws_connection_serves_multiple_stream_kinds() -> Result<(), BoxError> {
	let identity = Identity::mint_root("CN=pooled echo,O=tightbeam-ws,C=US", 1, Duration::from_secs(3600))?;

	let bind_addr = TightBeamSocketAddr("127.0.0.1:0".parse()?);
	let (server, addr) = <WsListener as EncryptedProtocol>::bind_with(bind_addr, identity.server_config()).await?;

	let server_handle = server! {
		protocol WsListener: server,
		policies: { with_mux_offer: [ Some(TransportOffer::mux(8)) ] },
		service: PooledEchoService
	};

	let pool = Arc::new(
		ConnectionPool::<WsListener>::builder()
			.with_config(PoolConfig {
				idle_timeout: None,
				max_connections: 1,
				mux_offer: Some(Arc::new(TransportOffer::mux(8))),
			})
			.with_trust_store(identity.trust_anchor()?)
			.build(),
	);

	// Unary through a pooled lease. Mux dial pins peer cert at handshake.
	let mut lease = pool.connect(addr).await?;
	assert!(
		lease.peer_certificate().is_some(),
		"pooled mux lease must expose handshake peer certificate"
	);
	let expected = create_v0_tightbeam(None, None);
	let echoed = lease.emit(expected.clone(), None).await?;
	assert_eq!(echoed, Some(expected.clone()), "pooled unary emit must echo over the WebSocket");

	// Streaming on the same pooled connection: the frame's DER bytes
	// arrive in two chunks and the service reassembles and echoes.
	let der = encode(&expected)?;
	let split_at = der.len() / 2;
	let (mut sink, response) = lease.open_stream()?;
	sink.push(&der[..split_at]).await?;
	sink.close_with(&der[split_at..]).await?;

	let reply = response.await?;
	assert_eq!(
		reply,
		Some(expected),
		"streamed frame must reassemble and echo over the WebSocket"
	);

	// Duplex chunk echo on the same lease.
	let (mut duplex_sink, mut duplex_body) = lease.open_duplex()?;
	let first = b"pooled-duplex-a";
	let second = b"pooled-duplex-b";
	duplex_sink.push(first).await?;
	duplex_sink.close_with(second).await?;
	assert_eq!(
		duplex_body.chunk().await?,
		Some(first.to_vec()),
		"duplex first chunk must echo over the WebSocket"
	);
	assert_eq!(
		duplex_body.chunk().await?,
		Some(second.to_vec()),
		"duplex final chunk must echo over the WebSocket"
	);
	assert_eq!(duplex_body.chunk().await?, None, "duplex body must end after last");

	server_handle.abort();
	Ok(())
}
