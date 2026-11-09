//! The dial of [`WsListener`] under the limits of its endpoint, as a
//! tightbeam scenario.

#![cfg(feature = "testing")]

use core::future::pending;
use core::time::Duration;
use std::io;

use futures_util::StreamExt;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::{ClientEnv, SetupEnv, TestFrame};
use tightbeam::transport::{CheckedLimits, ClientBuilder, ConnectionBuilder, TransportLimits};
use tightbeam::{tb_scenario, TightBeamError};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::specs::DialCeilingSpec;
use tightbeam_ws::testing::ReadOutcome;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_tungstenite::accept_async;

/// The hostile peer of the scenario, and the socket address it bound.
type Served = Result<(JoinHandle<Result<(), TightBeamError>>, TightBeamSocketAddr), TightBeamError>;

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
fn narrow() -> Result<CheckedLimits, TightBeamError> {
	let limits = TransportLimits {
		cleartext_envelope: CEILING,
		encrypted_envelope: CEILING,
		..TransportLimits::default()
	};

	Ok(limits.checked()?)
}

/// A peer that upgrades, reads the first message, then declares a frame past
/// [`CEILING`] and sends none of its payload.
///
/// It is a hostile peer: a real peer never sends this input, and the client
/// under test is real.
async fn declaring_peer() -> Served {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let addr = listener.local_addr()?;

	let peer = tokio::spawn(async move {
		let (stream, _addr) = listener.accept().await?;
		let mut socket = accept_async(stream).await.map_err(io::Error::other)?;
		let _request = socket.next().await;

		socket.get_mut().write_all(&PAST_CEILING).await?;
		pending::<Result<(), TightBeamError>>().await
	});

	Ok((peer, TightBeamSocketAddr(addr)))
}

// The dial refuses a frame past the ceiling of its endpoint by its declared
// length, before any byte of its payload arrives, so the refusal comes within
// `PROMPT`. The emit path of tightbeam files no refusal event for it, so the
// client records the outcome of its read.
tb_scenario! {
	name: a_dial_refuses_a_frame_past_the_ceiling_of_its_endpoint,
	spec: DialCeilingSpec,
	environment ServiceClient {
		server: |_env: SetupEnv| declaring_peer(),
		client: |ClientEnv { trace, addr, .. }| async move {
			let builder = ClientBuilder::<WsListener>::builder().allow_cleartext().with_limits(narrow()?);
			let mut client = builder.build().connect(addr).await?;

			let emit = client.emit(TestFrame::v0(None, None), None);
			let emitted = timeout(PROMPT, emit).await.map_err(|elapsed| TightBeamError::IoError(elapsed.into()))?;
			ReadOutcome::record(&emitted, &trace)
		}
	}
}
