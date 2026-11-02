//! HPKE handshake driving and trust pinning for the e2e stack's example
//! servers and native clients.
//!
//! Compiled only under the `testing` feature.

use std::sync::Arc;

use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::KeyCurves;
use tightbeam::der::Decode;
use tightbeam::transport::multiplex::MuxAcceptor;
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;

use crate::error::Result;
use crate::io::WsTransport;

/// Drive the server-side HPKE handshake to completion over cleartext
/// containers.
///
/// The transport serves rounds until its session is encrypted, under the
/// handshake deadline of its endpoint.
pub async fn serve_handshake(transport: &mut WsTransport<MaybeTlsStream<TcpStream>>) -> Result<()> {
	transport.negotiate_mux().await?;
	Ok(())
}

/// Build a single-anchor trust store pinning `certificate`, for a peer
/// that authenticates that identity under the tightbeam profile.
pub(crate) fn pin(certificate: Certificate) -> core::result::Result<Arc<dyn CertificateTrust>, TightBeamError> {
	let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
	let store = builder.with_certificate(certificate)?.build();
	Ok(Arc::new(store))
}

/// Build a single-anchor trust store from a DER-encoded certificate: what a
/// native client loads from a provisioned fixture file.
pub fn pinned_trust(certificate_der: &[u8]) -> Result<Arc<dyn CertificateTrust>> {
	let certificate = Certificate::from_der(certificate_der).map_err(TightBeamError::from)?;
	Ok(pin(certificate)?)
}
