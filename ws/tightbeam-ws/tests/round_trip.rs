//! End-to-end round-trips over the WebSocket transport.
//!
//! These exercise the public surface only: the cleartext case proves
//! tightbeam's `server!` / `client!` macros drive a WebSocket transport, and
//! the encrypted case proves the HPKE handshake completes over the same
//! transport via the `Protocol` / `EncryptedProtocol` / `AsyncListenerTrait`
//! implementations.

use std::sync::{mpsc, Arc};
use std::time::Duration;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::TestFrame;
use tightbeam::transport::error::TransportFailure;
use tightbeam::transport::policy::RestartLinearBackoff;
use tightbeam::transport::TransportError;
use tightbeam::Frame;
use tightbeam_ws::protocol::WsListener;

mod common;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleartext_round_trip_drives_ws_macros() -> Result<(), BoxError> {
	let listener = WsListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await?;
	let addr = TightBeamSocketAddr(listener.local_addr()?);

	let (tx, rx) = mpsc::channel();
	let tx = Arc::new(tx);

	let server_handle = tightbeam::server! {
		protocol WsListener: listener,
		handle: move |message: Frame| {
			let tx = Arc::clone(&tx);
			async move {
				let _ = tx.send(message);
				Ok(None)
			}
		}
	};

	let mut client = tightbeam::client! {
		connect WsListener: addr,
		cleartext,
		policies: {
			restart_policy: RestartLinearBackoff::default(),
		}
	};

	let message = TestFrame::v0(None, None);
	client.emit(message.clone(), None).await?;

	let received = rx
		.recv_timeout(Duration::from_secs(5))
		.map_err(|_| TransportError::OperationFailed(TransportFailure::DeadlineExceeded))?;
	assert_eq!(message, received, "server should receive the frame sent over the WebSocket");

	server_handle.abort();
	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_round_trip_over_ws() -> Result<(), BoxError> {
	use core::str::FromStr;

	use tightbeam::crypto::policy::Secp256k1Policy;
	use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
	use tightbeam::crypto::x509::KeyCurves;
	use tightbeam::testing::{TestCertificate, TestIdentity, TestKey};
	use tightbeam::transport::{EncryptedProtocol, TransportEncryptionConfig};

	let signing_key = TestKey::insecure_fixed_signing();
	let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(TestIdentity::of(&signing_key));
	let bind_addr = TightBeamSocketAddr::from_str("127.0.0.1:0")?;
	let (server, addr) = <WsListener as EncryptedProtocol>::bind_with(bind_addr, config).await?;

	let trust = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
	let trust = trust.with_certificate(TestCertificate::self_signed(&signing_key))?;
	let trust_store: Arc<dyn CertificateTrust> = Arc::new(trust.build());

	let expected = TestFrame::v0(None, None);
	common::echo_round_trip(server, addr, trust_store, expected).await
}
