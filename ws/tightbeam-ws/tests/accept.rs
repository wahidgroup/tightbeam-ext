//! The accept path of [`WsListener`] under stalled and failed upgrades.

#![cfg(feature = "socket")]

use core::time::Duration;
use std::net::SocketAddr;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam_ws::protocol::WsListener;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::task::yield_now;
use tokio::time::timeout;
use tokio_tungstenite::connect_async;

/// Boxed error shared by the accept tests.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// How long a healthy upgrade may take on loopback.
const PROMPT: Duration = Duration::from_secs(2);

/// Bind a cleartext listener on an ephemeral loopback port.
async fn bound_listener() -> Result<(WsListener, SocketAddr), BoxError> {
	let listener = WsListener::bind_cleartext("127.0.0.1:0").await?;
	let addr = listener.local_addr()?;
	Ok((listener, addr))
}

/// Run a client upgrade against `addr` and hold the socket open.
async fn upgraded_client(addr: SocketAddr) -> Result<impl Sized, BoxError> {
	let url = format!("ws://{addr}/");
	let (client, _response) = connect_async(url).await?;
	Ok(client)
}

#[tokio::test]
async fn a_stalled_upgrade_delays_no_other_connection() -> Result<(), BoxError> {
	let (listener, addr) = bound_listener().await?;
	// A hostile peer: a real client never stalls before its upgrade, and the
	// server under test is real.
	let _stalled = TcpStream::connect(addr).await?;

	let client = tokio::spawn(upgraded_client(addr));
	let accepted = timeout(PROMPT, listener.accept()).await?;
	accepted?;

	client.await??;
	Ok(())
}

#[tokio::test]
async fn a_failed_upgrade_never_reaches_the_caller() -> Result<(), BoxError> {
	let (listener, addr) = bound_listener().await?;

	// A hostile peer: a real client never sends a request with no upgrade,
	// and the server under test is real.
	let mut refused = TcpStream::connect(addr).await?;
	refused.write_all(b"GET / HTTP/1.1\r\n\r\n").await?;

	let client = tokio::spawn(upgraded_client(addr));
	let accepted = timeout(PROMPT, listener.accept()).await?;
	accepted?;

	client.await??;
	Ok(())
}

#[tokio::test]
async fn a_dropped_listener_releases_its_port() -> Result<(), BoxError> {
	let (listener, addr) = bound_listener().await?;
	drop(listener);

	let rebound = timeout(PROMPT, async {
		loop {
			let rebinding = WsListener::<DefaultCryptoProvider>::bind_cleartext(addr.to_string());
			if let Ok(listener) = rebinding.await {
				return listener;
			}

			yield_now().await;
		}
	})
	.await?;
	assert_eq!(rebound.local_addr()?, addr);
	Ok(())
}
