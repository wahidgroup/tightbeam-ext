//! Shared helpers for the encrypted WebSocket round-trip integration tests.

use std::sync::Arc;

use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::policy::TransitStatus;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::{AsyncListenerTrait, MessageCollector, MessageEmitter, Protocol, X509ClientConfig};
use tightbeam::Frame;
use tightbeam_ws::protocol::WsListener;

/// Boxed error shared by the async integration tests.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Execute an encrypted echo round-trip over the WebSocket transport: spawn a
/// one-shot echo server on the bound `server`, connect a client pinning
/// `trust_store`, emit `expected`, and assert the server echoes it back over
/// the encrypted channel.
pub async fn echo_round_trip(
	server: WsListener,
	addr: TightBeamSocketAddr,
	trust_store: Arc<dyn CertificateTrust>,
	expected: Frame,
) -> Result<(), BoxError> {
	let server_handle = tokio::spawn(async move {
		let (mut transport, _addr) = AsyncListenerTrait::accept(&server).await?;
		let (request, status) = transport.collect_message().await?;
		let message = match status {
			TransitStatus::Ok => Some(Arc::try_unwrap(request).unwrap_or_else(|shared| (*shared).clone())),
			_ => None,
		};

		transport.send_response(status, message).await
	});

	let stream = <WsListener as Protocol>::connect(addr).await?;
	let mut transport = <WsListener as Protocol>::create_transport(stream).with_trust_store(trust_store);

	let response = transport.emit(expected.clone(), None).await?;
	assert_eq!(
		response,
		Some(expected),
		"encrypted server must echo the frame back over the WebSocket"
	);

	server_handle.await??;
	Ok(())
}
