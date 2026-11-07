//! Certificate pinning for the e2e stack's example servers and native
//! clients.
//!
//! Compiled only under the `testing` feature.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::x509::policy::{CertificateValidation, RuntimeCertificatePinning};
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::KeyCurves;
use tightbeam::der::Decode;
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;

use crate::error::Result;

/// A certificate that a peer pins as the one identity it accepts.
///
/// A client pins its server through [`trust`](Self::trust), and a server pins
/// its clients through [`validators`](Self::validators).
///
/// # Examples
///
/// ```
/// use std::time::Duration;
///
/// use tightbeam_ws::testing::{Identity, Pinned};
///
/// let identity = Identity::mint("CN=doc,O=tightbeam-ws,C=US", 1, Duration::from_secs(60))?;
/// let pinned = Pinned::from_der(&identity.certificate_der()?)?;
/// let _trust = pinned.trust()?;
/// assert_eq!(pinned.validators()?.len(), 1);
/// # Ok::<(), tightbeam_ws::Error>(())
/// ```
pub struct Pinned(Certificate);

impl From<Certificate> for Pinned {
	fn from(certificate: Certificate) -> Self {
		Self(certificate)
	}
}

impl Pinned {
	/// The certificate that `der` encodes.
	///
	/// # Errors
	///
	/// - [`Error::Tightbeam`](crate::Error::Tightbeam): `der` is not a DER
	///   certificate.
	pub fn from_der(der: &[u8]) -> Result<Self> {
		let certificate = Certificate::from_der(der).map_err(TightBeamError::from)?;
		Ok(Self(certificate))
	}

	/// The certificate in the DER file at `path`, as a provisioned fixture
	/// holds it.
	///
	/// # Errors
	///
	/// - [`Error::Io`](crate::Error::Io): the file does not read.
	/// - The errors of [`from_der`](Self::from_der).
	pub fn read(path: impl AsRef<Path>) -> Result<Self> {
		let der = fs::read(path)?;
		Self::from_der(&der)
	}

	/// A single-anchor trust store of this certificate under the tightbeam
	/// profile, for a peer that authenticates this identity.
	///
	/// # Errors
	///
	/// - [`Error::Tightbeam`](crate::Error::Tightbeam): the store refuses the
	///   certificate.
	pub fn trust(&self) -> Result<Arc<dyn CertificateTrust>> {
		let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
		let store = builder.with_certificate(self.0.clone()).map_err(TightBeamError::from)?.build();
		Ok(Arc::new(store))
	}

	/// The validators that admit this certificate alone, for a server that
	/// pins its mutual-auth clients.
	///
	/// # Errors
	///
	/// - [`Error::Tightbeam`](crate::Error::Tightbeam): the fingerprint of the
	///   certificate fails to compute.
	pub fn validators(&self) -> Result<Vec<Arc<dyn CertificateValidation>>> {
		let certificate = self.0.clone();
		let pinned = RuntimeCertificatePinning::<Sha3_256>::from_certificates([certificate]);
		let pinning = pinned.map_err(TightBeamError::from)?;
		Ok(vec![Arc::new(pinning)])
	}
}
