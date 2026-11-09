//! The trust of a coupled edge in its callers.

use std::path::Path;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::server::danger::ClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer};
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::{Certificate, KeyCurves};
use tightbeam::der::Decode;

use crate::edge::EdgeError;

/// The trust of a coupled edge in its callers.
///
/// - The TLS roots verify the client chain of each connection, with the
///   CRLs of [`CallerTrust::with_crls`]. A connection with no client chain
///   still connects, so a native tunnel client needs no TLS certificate, and
///   each coupled call on it refuses with `UNAUTHENTICATED`.
/// - The claim store verifies the signer of each claim, a tightbeam identity
///   issued to the same principal as the TLS certificate of its caller.
///
/// # Examples
///
/// ```no_run
/// use tightbeam_grpc::couple::CallerTrust;
///
/// let trust = CallerTrust::from_pem("/run/edge/callers-ca.pem", "/run/edge/claims-ca.pem")?;
/// # Ok::<(), tightbeam_grpc::edge::EdgeError>(())
/// ```
#[derive(Clone, Debug)]
pub struct CallerTrust {
	tls: Arc<RootCertStore>,
	crls: Vec<CertificateRevocationListDer<'static>>,
	claims: Arc<dyn CertificateTrust>,
}

impl CallerTrust {
	/// Trust in callers whose TLS chains end at `tls_roots`, and whose claims
	/// verify under `claims`.
	///
	/// # Errors
	///
	/// - [`EdgeError::NoCertificate`] -- `tls_roots` is empty.
	/// - [`EdgeError::Tls`] -- a root does not parse as a trust anchor.
	pub fn new(
		tls_roots: impl IntoIterator<Item = CertificateDer<'static>>,
		claims: Arc<dyn CertificateTrust>,
	) -> Result<Self, EdgeError> {
		let mut store = RootCertStore::empty();
		for root in tls_roots {
			store.add(root)?;
		}
		if store.is_empty() {
			return Err(EdgeError::NoCertificate);
		}

		Ok(Self { tls: Arc::new(store), crls: Vec::new(), claims })
	}

	/// Trust in callers whose TLS chains end at the PEM roots in the file
	/// `tls_roots`, and whose claims chain to the PEM roots in the file
	/// `claim_roots`, under the secp256k1 policy of tightbeam.
	///
	/// # Errors
	///
	/// - [`EdgeError::Io`] -- a file cannot be read.
	/// - [`EdgeError::Pem`] -- a file is malformed.
	/// - [`EdgeError::Trust`] -- tightbeam refuses a claim root.
	/// - The errors of [`CallerTrust::new`].
	pub fn from_pem(tls_roots: impl AsRef<Path>, claim_roots: impl AsRef<Path>) -> Result<Self, EdgeError> {
		let blocks = CertificateDer::pem_file_iter(tls_roots)?;
		let tls_roots = blocks.collect::<Result<Vec<_>, _>>()?;

		let mut builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
		for root in certificates(claim_roots)? {
			builder = builder.with_certificate(root)?;
		}

		Self::new(tls_roots, Arc::new(builder.build()))
	}

	/// Refuse every TLS client certificate that `crls` revoke.
	#[must_use]
	pub fn with_crls(mut self, crls: impl IntoIterator<Item = CertificateRevocationListDer<'static>>) -> Self {
		self.crls.extend(crls);
		self
	}

	/// The client verifier of the edge under `provider`, which admits a
	/// connection with no client chain.
	///
	/// # Errors
	///
	/// - [`EdgeError::Verifier`] -- rustls refuses a CRL.
	pub(crate) fn verifier(&self, provider: Arc<CryptoProvider>) -> Result<Arc<dyn ClientCertVerifier>, EdgeError> {
		let builder = WebPkiClientVerifier::builder_with_provider(Arc::clone(&self.tls), provider);
		let builder = builder.with_crls(self.crls.iter().cloned()).allow_unauthenticated();
		let verifier = builder.build()?;
		Ok(verifier)
	}

	/// The store that verifies the signer of each claim.
	pub(crate) fn claims(&self) -> &dyn CertificateTrust {
		&*self.claims
	}

	/// The store that verifies the signer of each claim, which the servlets
	/// of the edge share through `AdmissionTrust`, so a claim that the edge
	/// verifies is a claim that each servlet verifies.
	#[must_use]
	pub fn claim_store(&self) -> Arc<dyn CertificateTrust> {
		Arc::clone(&self.claims)
	}
}

/// Every certificate of the PEM file at `path`, decoded as tightbeam takes
/// it.
///
/// # Errors
///
/// - [`EdgeError::Io`] -- the file cannot be read.
/// - [`EdgeError::Pem`] -- the file is malformed.
/// - [`EdgeError::Trust`] -- a certificate does not decode.
fn certificates(path: impl AsRef<Path>) -> Result<Vec<Certificate>, EdgeError> {
	let mut decoded = Vec::new();
	for block in CertificateDer::pem_file_iter(path)? {
		let block = block?;
		let certificate = Certificate::from_der(block.as_ref()).map_err(CertificateValidationError::from)?;
		decoded.push(certificate);
	}

	Ok(decoded)
}
