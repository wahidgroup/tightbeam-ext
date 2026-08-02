//! End-to-end round-trips over the WebSocket transport.
//!
//! These exercise the public surface only: the cleartext case proves
//! tightbeam's `server!` / `client!` macros drive a WebSocket transport, and
//! the encrypted case proves the ECIES handshake completes over the same
//! transport via the `Protocol` / `EncryptedProtocol` / `AsyncListenerTrait`
//! implementations.

use std::sync::{mpsc, Arc};
use std::time::Duration;

use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::create_v0_tightbeam;
use tightbeam::transport::error::TransportFailure;
use tightbeam::transport::policy::{PolicyConfig, RestartLinearBackoff};
use tightbeam::transport::TransportError;
use tightbeam::Frame;
use tightbeam_ws::protocol::WsListener;

mod common;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleartext_round_trip_drives_ws_macros() -> Result<(), BoxError> {
	let listener = WsListener::bind("127.0.0.1:0").await?;
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
		policies: {
			restart_policy: RestartLinearBackoff::default(),
		}
	};

	let message = create_v0_tightbeam(None, None);
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

	use tightbeam::crypto::hash::Sha3_256;
	use tightbeam::crypto::policy::Secp256k1Policy;
	use tightbeam::crypto::profiles::DefaultCryptoProvider;
	use tightbeam::crypto::sign::ecdsa::Secp256k1VerifyingKey;
	use tightbeam::crypto::sign::Sha3Signer;
	use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
	use tightbeam::spki::SubjectPublicKeyInfoOwned;
	use tightbeam::testing::create_test_signing_key;
	use tightbeam::transport::{EncryptedProtocol, TransportEncryptionConfig};

	let signing_key = create_test_signing_key();
	let verifying_key = Secp256k1VerifyingKey::from(&signing_key);
	let sha3_signer = Sha3Signer::from(&signing_key);
	let spki = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;

	let cert = tightbeam::cert!(
		profile: Root,
		subject: "CN=Test Root CA,O=Test Org,C=US",
		serial: 1u32,
		duration: Duration::from_secs(365 * 24 * 60 * 60),
		signer: &sha3_signer,
		subject_public_key: spki
	)?;

	let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(cert.clone(), signing_key.clone().into());
	let bind_addr = TightBeamSocketAddr::from_str("127.0.0.1:0")?;
	let (server, addr) = <WsListener as EncryptedProtocol>::bind_with(bind_addr, config).await?;

	let trust_store: Arc<dyn CertificateTrust> = Arc::new(
		CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
			.with_certificate(cert)?
			.build(),
	);

	let expected = create_v0_tightbeam(None, None);
	common::echo_round_trip(server, addr, trust_store, expected).await
}
