//! Encrypted round trips over the WebSocket transport, as tightbeam
//! scenarios.

#![cfg(feature = "testing")]

use core::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::{ClientEnv, SetupEnv, TestCertificate, TestFrame, TestIdentity, TestKey};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::{EncryptedProtocol, TransportEncryptionConfig};
use tightbeam::{tb_scenario, TightBeamError};
use tightbeam_ws::protocol::WsListener;
use tightbeam_ws::testing::specs::EncryptedRoundTripSpec;
use tightbeam_ws::testing::{EchoService, Identity, Pinned};
use tokio::task::JoinHandle;

/// The server of a scenario, and the socket address it bound.
type Served = Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError>;

/// The shared echo on an encrypted listener under `config`, which records
/// each session on `trace`.
async fn echo(config: TransportEncryptionConfig<DefaultCryptoProvider>, trace: &TraceCollector) -> Served {
	let loopback = TightBeamSocketAddr::from_str("127.0.0.1:0")?;
	let (listener, addr) = <WsListener as EncryptedProtocol>::bind_with(loopback, config).await?;
	Ok((EchoService::serve(listener, None, trace), addr))
}

/// Send one frame to `addr` with a client that pins `trust` and records on
/// `trace`, and require its echo.
async fn echoed(
	addr: TightBeamSocketAddr,
	trust: Arc<dyn CertificateTrust>,
	trace: &TraceCollector,
) -> Result<(), TightBeamError> {
	let expected = TestFrame::v0(None, None);
	let reply = EchoService::exchange::<WsListener, _, _>(addr, trust, expected.clone(), trace).await?;
	assert_eq!(
		reply,
		Some(expected),
		"the encrypted server MUST echo the frame back over the WebSocket"
	);
	Ok(())
}

/// A server identity issued, written to its DER certificate and raw key, and
/// reloaded from them, as the generator writes it and its peers reload it.
fn reloaded_identity() -> Identity {
	let issued = Identity::mint("CN=fixture echo,O=tightbeam-ws,C=US", 1, Duration::from_secs(3600));
	let issued = issued.expect("a test identity issues");
	let cert_der = issued.certificate_der().expect("the certificate encodes as DER");
	let key_bytes = issued.signing_key_bytes();

	let reloaded = Identity::from_der(&cert_der, &key_bytes);
	reloaded.expect("the DER fixtures reload")
}

// One HPKE handshake completes at each end under a self-signed test identity,
// and the gate admits the one encrypted request.
tb_scenario! {
	name: encrypted_round_trip_over_ws,
	spec: EncryptedRoundTripSpec,
	environment ServiceClient {
		context: TestKey::insecure_fixed_signing(),
		server: |SetupEnv { trace, context }| async move {
			let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(TestIdentity::of(&context));
			echo(config, &trace).await
		},
		client: |ClientEnv { trace, addr, context }| async move {
			let trust = Pinned::from(TestCertificate::self_signed(&context)).trust()?;
			echoed(addr, trust, &trace).await
		}
	}
}

// The reloaded DER fixtures drive one HPKE handshake at each end, and the
// gate admits the one encrypted request.
tb_scenario! {
	name: encrypted_round_trip_over_der_fixtures,
	spec: EncryptedRoundTripSpec,
	environment ServiceClient {
		context: reloaded_identity(),
		server: |SetupEnv { trace, context }| async move { echo(context.server_config(), &trace).await },
		client: |ClientEnv { trace, addr, context }| async move { echoed(addr, context.trust_anchor()?, &trace).await }
	}
}
