//! ECIES handshake driving and trust pinning for the e2e stack's
//! example servers and native clients.
//!
//! Compiled only under the `testing` feature.

use std::sync::Arc;

use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
use tightbeam::der::{Decode, Encode};
use tightbeam::transport::handshake::TcpHandshakeState;
use tightbeam::transport::state::EncryptedProtocolState;
use tightbeam::transport::{EncryptedMessageIO, MessageIO, WireEnvelope};
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;

use crate::error::{Error, Result};
use crate::io::WsTransport;

/// Handshake message ceiling: ECIES completes in two client messages, so
/// anything beyond a small bound is a protocol violation.
const MAX_HANDSHAKE_MESSAGES: usize = 4;

/// Drive the server-side ECIES handshake to completion over cleartext
/// containers, bounded by four handshake messages.
pub async fn serve_handshake(transport: &mut WsTransport<MaybeTlsStream<TcpStream>>) -> Result<()> {
	for _ in 0..MAX_HANDSHAKE_MESSAGES {
		if transport.to_handshake_state() == TcpHandshakeState::Complete {
			return Ok(());
		}

		let wire_bytes = transport.read_envelope_bytes().await?;
		let wire_envelope = WireEnvelope::from_der(&wire_bytes).map_err(TightBeamError::from)?;
		let WireEnvelope::Cleartext(envelope) = wire_envelope else {
			return Err(Error::HandshakeCiphertext);
		};

		let handshake_bytes = envelope.to_der().map_err(TightBeamError::from)?;
		transport.perform_server_handshake(&handshake_bytes).await?;
	}

	if transport.to_handshake_state() == TcpHandshakeState::Complete {
		return Ok(());
	}

	Err(Error::HandshakeIncomplete)
}

/// Build a single-anchor trust store pinning `certificate`, for a peer
/// that authenticates that identity under the tightbeam profile.
pub(crate) fn pin(certificate: Certificate) -> core::result::Result<Arc<dyn CertificateTrust>, TightBeamError> {
	let store = CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
		.with_certificate(certificate)?
		.build();

	Ok(Arc::new(store))
}

/// Build a single-anchor trust store from a DER-encoded certificate: what a
/// native client loads from a provisioned fixture file.
pub fn pinned_trust(certificate_der: &[u8]) -> Result<Arc<dyn CertificateTrust>> {
	let certificate = Certificate::from_der(certificate_der).map_err(TightBeamError::from)?;
	Ok(pin(certificate)?)
}
