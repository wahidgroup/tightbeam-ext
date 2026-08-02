//! X.509 identity fixtures for the encrypted WebSocket end-to-end tests.
//!
//! The browser cannot mint certificates (it has no clock), so identities
//! are generated natively here and provisioned as DER certificate + raw signing
//! key bytes. A single code path mints, serializes, and reloads them, keeping
//! the generator binary, the encrypted echo server, and the integration tests
//! on one source of truth.

use std::io::{Error as IoError, ErrorKind};
use std::sync::Arc;
use std::time::Duration;
use std::{env, fs};

use tightbeam::cert;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::ecdsa::{Secp256k1SigningKey, Secp256k1VerifyingKey};
use tightbeam::crypto::sign::Sha3Signer;
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::der::{Decode, Encode};
use tightbeam::random::OsRng;
use tightbeam::spki::SubjectPublicKeyInfoOwned;
use tightbeam::transport::handshake::HandshakeKeyManager;
use tightbeam::transport::TransportEncryptionConfig;
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;

use crate::Result;

/// Size in bytes of a raw secp256k1 signing scalar.
pub const SIGNING_KEY_LEN: usize = 32;

/// Environment variable naming the server certificate DER file.
const SERVER_CERT_ENV: &str = "TBWS_SERVER_CERT";

/// Environment variable naming the raw 32-byte server signing key file.
const SERVER_KEY_ENV: &str = "TBWS_SERVER_KEY";

/// A self-signed X.509 identity: a certificate paired with its secp256k1
/// signing key.
pub struct Identity {
	certificate: Certificate,
	signing_key: Secp256k1SigningKey,
}

impl Identity {
	/// Mint a fresh self-signed root identity valid for `validity` from now.
	pub fn mint_root(subject: &str, serial: u32, validity: Duration) -> Result<Self> {
		Ok(mint_root(subject, serial, validity)?)
	}

	/// Reconstruct an identity from a DER certificate and a raw 32-byte key,
	/// exactly as the generator writes and the server/browser reload it.
	pub fn from_der(certificate_der: &[u8], signing_key: &[u8; SIGNING_KEY_LEN]) -> Result<Self> {
		Ok(load(certificate_der, signing_key)?)
	}

	/// Load the server identity from the files named by `TBWS_SERVER_CERT`
	/// and `TBWS_SERVER_KEY`, as the echo-server examples are provisioned.
	pub fn from_env() -> Result<Self> {
		let certificate_der = fs::read(required_path(SERVER_CERT_ENV)?)?;
		let key_bytes = fs::read(required_path(SERVER_KEY_ENV)?)?;

		let key: [u8; SIGNING_KEY_LEN] = key_bytes
			.as_slice()
			.try_into()
			.map_err(|_| IoError::new(ErrorKind::InvalidData, "signing key file must hold exactly 32 bytes"))?;

		Self::from_der(&certificate_der, &key)
	}

	/// Borrow the certificate.
	pub fn certificate(&self) -> &Certificate {
		&self.certificate
	}

	/// DER-encode the certificate for provisioning to peers.
	pub fn certificate_der(&self) -> Result<Vec<u8>> {
		Ok(self.certificate.to_der().map_err(TightBeamError::from)?)
	}

	/// The raw 32-byte secp256k1 signing scalar.
	pub fn signing_key_bytes(&self) -> [u8; SIGNING_KEY_LEN] {
		self.signing_key.to_bytes().into()
	}

	/// Build the server-side transport encryption config that presents this
	/// identity during the ECIES handshake.
	pub fn server_config(&self) -> TransportEncryptionConfig<DefaultCryptoProvider> {
		let key_manager = HandshakeKeyManager::from(self.signing_key.clone());
		TransportEncryptionConfig::new(self.certificate.clone(), key_manager)
	}

	/// Client materials for mutual-auth dials that reuse this identity
	/// (demo relay under paywall).
	pub fn client_identity(&self) -> (Arc<Certificate>, Arc<HandshakeKeyManager<DefaultCryptoProvider>>) {
		let certificate = Arc::new(self.certificate.clone());
		let key_manager = Arc::new(HandshakeKeyManager::from(self.signing_key.clone()));
		(certificate, key_manager)
	}

	/// Build a single-anchor trust store pinning this identity's certificate,
	/// for a peer that authenticates this identity.
	pub fn trust_anchor(&self) -> Result<Arc<dyn CertificateTrust>> {
		Ok(super::handshake::pin(self.certificate.clone())?)
	}
}

/// Resolve a required path-valued environment variable.
fn required_path(name: &str) -> core::result::Result<String, IoError> {
	env::var(name).map_err(|_| IoError::new(ErrorKind::NotFound, format!("{name} is not set")))
}

fn mint_root(subject: &str, serial: u32, validity: Duration) -> core::result::Result<Identity, TightBeamError> {
	let signing_key = Secp256k1SigningKey::random(&mut OsRng);
	let verifying_key = Secp256k1VerifyingKey::from(&signing_key);
	let spki = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;
	let signer = Sha3Signer::from(&signing_key);

	let certificate = cert!(
		profile: Root,
		subject: subject,
		serial: serial,
		duration: validity,
		signer: &signer,
		subject_public_key: spki
	)?;

	Ok(Identity { certificate, signing_key })
}

fn load(certificate_der: &[u8], signing_key: &[u8; SIGNING_KEY_LEN]) -> core::result::Result<Identity, TightBeamError> {
	let certificate = Certificate::from_der(certificate_der)?;
	let scalar = *signing_key;
	let signing_key = Secp256k1SigningKey::from_bytes(&scalar.into())?;

	Ok(Identity { certificate, signing_key })
}
