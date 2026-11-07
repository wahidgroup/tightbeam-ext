//! The dial of [`WsListener`] under the limits of its endpoint.

#![cfg(feature = "socket")]

use core::error::Error;
use core::future::pending;
use core::time::Duration;

use futures_util::StreamExt;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::TestFrame;
use tightbeam::transport::error::TransportFailure;
use tightbeam::transport::{CheckedLimits, ClientBuilder, ConnectionBuilder, TransportError, TransportLimits};
use tightbeam_ws::protocol::WsListener;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::accept_async;

/// Boxed error shared by the dial tests.
type BoxError = Box<dyn Error + Send + Sync>;

/// How long a refusal by declared length may take on loopback. A socket that
/// admits the frame waits for its payload until the default operation timeout,
/// which is far longer.
const PROMPT: Duration = Duration::from_secs(2);

/// Both envelope ceilings of the dialing endpoint, below the default ceilings.
const CEILING: usize = 32 * 1024;

/// The header of a binary WebSocket frame whose 16-bit extended length declares
/// one octet past [`CEILING`] (RFC 6455 § 5.2).
const PAST_CEILING: [u8; 4] = [0x82, 126, 0x80, 0x01];

/// Limits whose envelope ceilings both sit at [`CEILING`].
fn narrow() -> CheckedLimits {
	let limits = TransportLimits {
		cleartext_envelope: CEILING,
		encrypted_envelope: CEILING,
		..TransportLimits::default()
	};

	limits.checked().expect("a handshake message fits the narrow cleartext ceiling")
}

/// A peer that upgrades, reads the first message, then declares a frame past
/// [`CEILING`] and sends none of its payload.
///
/// It is a hostile peer: a real peer never sends this input, and the client
/// under test is real.
async fn declaring_peer() -> TightBeamSocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("a loopback port binds");
	let addr = listener.local_addr().expect("the bound port has an address");

	tokio::spawn(async move {
		let (stream, _addr) = listener.accept().await.expect("the dial arrives");
		let mut socket = accept_async(stream).await.expect("the upgrade completes");
		let _request = socket.next().await;

		socket.get_mut().write_all(&PAST_CEILING).await.expect("the header leaves");
		pending::<()>().await;
	});

	TightBeamSocketAddr(addr)
}

#[tokio::test]
async fn a_dial_refuses_a_frame_past_the_ceiling_of_its_endpoint() -> Result<(), BoxError> {
	let addr = declaring_peer().await;
	let builder = ClientBuilder::<WsListener>::builder().allow_cleartext().with_limits(narrow());
	let mut client = builder.build().connect(addr).await?;
	let frame = TestFrame::v0(None, None);
	let emitted = timeout(PROMPT, client.emit(frame, None)).await?;

	let refused = matches!(emitted, Err(TransportError::OperationFailed(TransportFailure::SizeExceeded)));
	assert!(refused);
	Ok(())
}
