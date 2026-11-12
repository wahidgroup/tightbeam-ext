//! The test support of the crate, which `docs/grpc.md` lists.

use core::fmt;
use core::str::FromStr;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::EncodePrivateKey;
use rand_core::OsRng;
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tightbeam::der::asn1::{BitString, Ia5String, ObjectIdentifier, Uint};
use tightbeam::der::pem::LineEnding;
use tightbeam::der::referenced::OwnedToRef;
use tightbeam::der::{Decode, Encode, EncodePem};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::ext::pkix::crl::CrlNumber;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, ExtendedKeyUsage, SubjectAltName};
use x509_cert::ext::AsExtension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{DynSignatureAlgorithmIdentifier, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_cert::Version;

use crate::edge::{DialTls, EdgeError, EdgeTls};

#[cfg(feature = "couple")]
mod ledger;

#[cfg(feature = "couple")]
pub use crate::couple::parts::{OpenedStream, PartFrames, StreamParts, StreamSigners};
#[cfg(feature = "couple")]
pub use ledger::{LedgerBreach, LedgerConformance};

/// `id-kp-serverAuth` (RFC 5280 section 4.2.1.12).
const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

/// `id-kp-clientAuth` (RFC 5280 section 4.2.1.12).
const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

/// The DNS name of loopback that every edge certificate names.
const LOCALHOST: &str = "localhost";

/// Why the test PKI cannot create a certificate.
#[derive(Debug)]
pub enum MintError {
	/// The builder refuses the certificate, or the signature fails.
	Certificate(x509_cert::builder::Error),
	/// A name, a validity, or a certificate does not encode, or the material
	/// does not encode as PEM.
	Der(tightbeam::der::Error),
	/// The private key does not encode as PKCS #8.
	Key(p256::pkcs8::Error),
	/// rustls refuses the material that the PKI created.
	Edge(EdgeError),
	/// A file of the material cannot be written.
	Io(io::Error),
}

impl fmt::Display for MintError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Certificate(error) => write!(f, "the certificate does not build: {error}"),
			Self::Der(error) => write!(f, "the material does not encode: {error}"),
			Self::Key(error) => write!(f, "the private key does not encode: {error}"),
			Self::Edge(error) => write!(f, "rustls refuses the created material: {error}"),
			Self::Io(error) => write!(f, "the material cannot be written: {error}"),
		}
	}
}

impl std::error::Error for MintError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Certificate(error) => Some(error),
			Self::Der(error) => Some(error),
			Self::Key(error) => Some(error),
			Self::Edge(error) => Some(error),
			Self::Io(error) => Some(error),
		}
	}
}

impl From<x509_cert::builder::Error> for MintError {
	fn from(error: x509_cert::builder::Error) -> Self {
		Self::Certificate(error)
	}
}

impl From<tightbeam::der::Error> for MintError {
	fn from(error: tightbeam::der::Error) -> Self {
		Self::Der(error)
	}
}

impl From<x509_cert::spki::Error> for MintError {
	fn from(error: x509_cert::spki::Error) -> Self {
		Self::Certificate(error.into())
	}
}

impl From<p256::pkcs8::Error> for MintError {
	fn from(error: p256::pkcs8::Error) -> Self {
		Self::Key(error)
	}
}

impl From<tightbeam::der::pem::Error> for MintError {
	fn from(error: tightbeam::der::pem::Error) -> Self {
		Self::Der(error.into())
	}
}

impl From<EdgeError> for MintError {
	fn from(error: EdgeError) -> Self {
		Self::Edge(error)
	}
}

impl From<io::Error> for MintError {
	fn from(error: io::Error) -> Self {
		Self::Io(error)
	}
}

/// A TLS PKI created at run time: a P-256 certificate authority, which issues
/// the certificate of each edge and caller, intermediate authorities under
/// it, and its CRLs. Each dial trusts its root.
///
/// The PKI signs under P-256, because rustls verifies no secp256k1 signature.
///
/// # Examples
///
/// ```
/// use core::time::Duration;
///
/// use tightbeam_grpc::edge::{Dial, Edge};
/// use tightbeam_grpc::testing::TlsAuthority;
///
/// let authority = TlsAuthority::mint("CN=test root,O=tightbeam-grpc", Duration::from_secs(3600))?;
/// let edge = Edge::tls(authority.edge("CN=edge,O=tightbeam-grpc")?);
/// let dial = Dial::Tls(authority.dial()?);
/// # Ok::<(), tightbeam_grpc::testing::MintError>(())
/// ```
pub struct TlsAuthority {
	key: SigningKey,
	name: Name,
	/// The certificate of this authority.
	certificate: CertificateDer<'static>,
	/// The certificates that a leaf of this authority presents after its own,
	/// from this authority up to the root and without it. Empty for a root.
	issuers: Vec<CertificateDer<'static>>,
	/// The root, which each dial and each edge trusts.
	root: CertificateDer<'static>,
	lifetime: Duration,
	/// The serial number of the next certificate that this authority issues.
	/// A root holds serial number 1.
	serial: AtomicU64,
	/// The number of the next CRL that this authority issues.
	crl_number: AtomicU64,
}

impl TlsAuthority {
	/// A root named `subject`, such as `CN=test root,O=acme`, whose
	/// certificate and every certificate it issues stay valid for `lifetime`
	/// from now.
	///
	/// # Errors
	///
	/// - [`MintError::Der`] -- `subject` is no distinguished name, or
	///   `lifetime` passes the range of a validity.
	/// - [`MintError::Certificate`] -- the root does not build.
	pub fn mint(subject: &str, lifetime: Duration) -> Result<Self, MintError> {
		let key = SigningKey::random(&mut OsRng);
		let name = Name::from_str(subject)?;
		let public = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key())?;
		let validity = Validity::from_now(lifetime)?;

		let serial = SerialNumber::from(1_u64);
		let builder = CertificateBuilder::new(Profile::Root, serial, validity, name.clone(), public, &key)?;
		let root = builder.build::<DerSignature>()?;
		let root = CertificateDer::from(root.to_der()?);
		Ok(Self::of(key, name, root.clone(), Vec::new(), root, lifetime))
	}

	/// The authority of `key`, named `name`, with `certificate` as its own,
	/// `issuers` after a leaf of it, and `root` as its trust anchor.
	fn of(
		key: SigningKey,
		name: Name,
		certificate: CertificateDer<'static>,
		issuers: Vec<CertificateDer<'static>>,
		root: CertificateDer<'static>,
		lifetime: Duration,
	) -> Self {
		Self {
			key,
			name,
			certificate,
			issuers,
			root,
			lifetime,
			serial: AtomicU64::new(2),
			crl_number: AtomicU64::new(1),
		}
	}

	/// An intermediate authority named `subject`, which this authority issues.
	/// Each leaf of it presents its certificate after its own, and chains to
	/// the root of this authority.
	///
	/// # Errors
	///
	/// - [`MintError::Der`] -- `subject` is no distinguished name.
	/// - [`MintError::Certificate`] -- the certificate does not build.
	pub fn intermediate(&self, subject: &str) -> Result<Self, MintError> {
		let key = SigningKey::random(&mut OsRng);
		let name = Name::from_str(subject)?;
		let public = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key())?;
		let validity = Validity::from_now(self.lifetime)?;

		let serial = self.next_serial();
		let profile = Profile::SubCA { issuer: self.name.clone(), path_len_constraint: None };
		let builder = CertificateBuilder::new(profile, serial, validity, name.clone(), public, &self.key)?;
		let certificate = CertificateDer::from(builder.build::<DerSignature>()?.to_der()?);

		let issuers = [certificate.clone()].into_iter().chain(self.issuers.iter().cloned()).collect();
		Ok(Self::of(key, name, certificate, issuers, self.root.clone(), self.lifetime))
	}

	/// The certificate of the root, which a dial trusts.
	pub fn root(&self) -> CertificateDer<'static> {
		self.root.clone()
	}

	/// The certificate of this authority, which a CRL of its issuer revokes.
	pub fn certificate(&self) -> &CertificateDer<'static> {
		&self.certificate
	}

	/// The certificate of the root in PEM, as a stock gRPC client loads its
	/// roots.
	///
	/// # Errors
	///
	/// - [`MintError::Der`] -- the root does not encode.
	pub fn root_pem(&self) -> Result<String, MintError> {
		let root = x509_cert::Certificate::from_der(self.root.as_ref())?;
		Ok(root.to_pem(LineEnding::LF)?)
	}

	/// The CRL of this authority that revokes each of `revoked`, a certificate
	/// that it issued, and that a verifier holds fresh until `next_update`.
	///
	/// # Errors
	///
	/// - [`MintError::Der`] -- a certificate does not decode, or `next_update` passes the range of a CRL.
	/// - [`MintError::Certificate`] -- the key identifier does not derive, or the signature fails.
	pub fn crl(
		&self,
		revoked: &[&CertificateDer<'_>],
		next_update: SystemTime,
	) -> Result<CertificateRevocationListDer<'static>, MintError> {
		let this_update = Time::try_from(SystemTime::now().min(next_update))?;
		let mut entries = Vec::new();
		for certificate in revoked {
			let decoded = x509_cert::Certificate::from_der(certificate.as_ref())?;
			let serial_number = decoded.tbs_certificate.serial_number;
			entries.push(RevokedCert { serial_number, revocation_date: this_update, crl_entry_extensions: None });
		}

		let public = SubjectPublicKeyInfoOwned::from_key(*self.key.verifying_key())?;
		let authority = AuthorityKeyIdentifier::try_from(public.owned_to_ref())?;
		let number = self.crl_number.fetch_add(1, Ordering::Relaxed).to_be_bytes();
		let number = CrlNumber(Uint::new(&number)?);
		let authority = authority.to_extension(&self.name, &[])?;
		let number = number.to_extension(&self.name, core::slice::from_ref(&authority))?;

		let algorithm = self.key.signature_algorithm_identifier()?;
		let tbs = TbsCertList {
			version: Version::V2,
			signature: algorithm.clone(),
			issuer: self.name.clone(),
			this_update,
			next_update: Some(Time::try_from(next_update)?),
			revoked_certificates: (!entries.is_empty()).then_some(entries),
			crl_extensions: Some(vec![authority, number]),
		};

		let signed: DerSignature = self
			.key
			.try_sign(&tbs.to_der()?)
			.map_err(x509_cert::builder::Error::Signature)?;

		let signature = BitString::from_bytes(signed.as_bytes())?;
		let list = CertificateList { tbs_cert_list: tbs, signature_algorithm: algorithm, signature };
		Ok(CertificateRevocationListDer::from(list.to_der()?))
	}

	/// The serial number of the next certificate that this authority issues.
	fn next_serial(&self) -> SerialNumber {
		SerialNumber::from(self.serial.fetch_add(1, Ordering::Relaxed))
	}

	/// A TLS client certificate named `subject`, which this authority issues
	/// for client authentication, with the SPIFFE ID `spiffe` as its one URI
	/// subject alternative name when it is `Some`.
	///
	/// # Errors
	///
	/// - [`MintError::Der`] -- `subject` is no distinguished name, or `spiffe` is no IA5 string.
	/// - [`MintError::Certificate`] -- the certificate does not build.
	/// - [`MintError::Key`] -- the private key does not encode.
	pub fn caller(&self, subject: &str, spiffe: Option<&str>) -> Result<TlsLeaf, MintError> {
		let key = SigningKey::random(&mut OsRng);
		let spiffe = spiffe.map(|id| Ia5String::new(id).map(GeneralName::UniformResourceIdentifier));
		let names = spiffe.transpose()?.into_iter().collect();
		let leaf = self.issue(subject, &key, names, CLIENT_AUTH)?;
		TlsLeaf::new(&leaf, &key, &self.issuers)
	}

	/// A TLS server certificate named `subject`, which this authority issues
	/// for server authentication on loopback: the DNS name `localhost`, and
	/// the addresses `127.0.0.1` and `::1`.
	///
	/// # Errors
	///
	/// - [`MintError::Der`] -- `subject` is no distinguished name.
	/// - [`MintError::Certificate`] -- the certificate does not build.
	/// - [`MintError::Key`] -- the private key does not encode.
	pub fn server(&self, subject: &str) -> Result<TlsLeaf, MintError> {
		let key = SigningKey::random(&mut OsRng);
		let leaf = self.issue(subject, &key, Self::loopback()?, SERVER_AUTH)?;
		TlsLeaf::new(&leaf, &key, &self.issuers)
	}

	/// The names of loopback: the DNS name `localhost`, and the addresses
	/// `127.0.0.1` and `::1`.
	fn loopback() -> Result<Vec<GeneralName>, MintError> {
		Ok(vec![
			GeneralName::DnsName(Ia5String::new(LOCALHOST)?),
			GeneralName::from(IpAddr::V4(Ipv4Addr::LOCALHOST)),
			GeneralName::from(IpAddr::V6(Ipv6Addr::LOCALHOST)),
		])
	}

	/// A certificate named `subject` for the public half of `key`, which this
	/// authority issues for `usage`, with `names` as its subject alternative
	/// names.
	fn issue(
		&self,
		subject: &str,
		key: &SigningKey,
		names: Vec<GeneralName>,
		usage: ObjectIdentifier,
	) -> Result<x509_cert::Certificate, MintError> {
		let public = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key())?;
		let validity = Validity::from_now(self.lifetime)?;
		let serial = self.next_serial();

		let profile = Profile::Leaf {
			issuer: self.name.clone(),
			enable_key_agreement: false,
			enable_key_encipherment: false,
			include_subject_key_identifier: true,
		};

		let subject = Name::from_str(subject)?;
		let mut builder = CertificateBuilder::new(profile, serial, validity, subject, public, &self.key)?;
		if !names.is_empty() {
			builder.add_extension(&SubjectAltName(names))?;
		}

		builder.add_extension(&ExtendedKeyUsage(vec![usage]))?;
		Ok(builder.build::<DerSignature>()?)
	}

	/// The TLS of a dial that trusts this root.
	///
	/// # Errors
	///
	/// - The errors of [`DialTls::new`].
	pub fn dial(&self) -> Result<DialTls, EdgeError> {
		DialTls::new([self.root()])
	}

	/// The TLS of an edge under the certificate of [`TlsAuthority::server`]
	/// named `subject`, which presents its chain.
	///
	/// # Errors
	///
	/// - The errors of [`TlsAuthority::server`].
	/// - [`MintError::Edge`] -- rustls refuses the chain or the key.
	pub fn edge(&self, subject: &str) -> Result<EdgeTls, MintError> {
		let leaf = self.server(subject)?;
		Ok(EdgeTls::new(leaf.chain(), leaf.key())?)
	}
}

/// The TLS material of one leaf that the test PKI issued: its certificate,
/// the chain that it presents, and its private key, in PEM as a stock gRPC
/// peer loads them, and in DER as rustls takes them. A claim of a caller binds
/// to the DER of its certificate.
pub struct TlsLeaf {
	leaf: CertificateDer<'static>,
	issuers: Vec<CertificateDer<'static>>,
	key: PrivatePkcs8KeyDer<'static>,
	certificate_pem: String,
	chain_pem: String,
	key_pem: String,
}

impl TlsLeaf {
	/// The material of `leaf`, which presents `issuers` after itself, and of
	/// its private key `key`.
	fn new(
		leaf: &x509_cert::Certificate,
		key: &SigningKey,
		issuers: &[CertificateDer<'static>],
	) -> Result<Self, MintError> {
		let certificate_pem = leaf.to_pem(LineEnding::LF)?;
		let mut chain_pem = certificate_pem.clone();
		for issuer in issuers {
			let issuer = x509_cert::Certificate::from_der(issuer.as_ref())?;
			chain_pem.push_str(&issuer.to_pem(LineEnding::LF)?);
		}

		let key_pem = key.to_pkcs8_pem(LineEnding::LF)?.to_string();
		let pkcs8 = key.to_pkcs8_der()?;
		let key = PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec());
		let leaf = CertificateDer::from(leaf.to_der()?);
		Ok(Self { leaf, issuers: issuers.to_vec(), key, certificate_pem, chain_pem, key_pem })
	}

	/// The private key of the leaf in DER, as rustls takes it.
	pub fn key(&self) -> PrivateKeyDer<'static> {
		PrivateKeyDer::Pkcs8(self.key.clone_key())
	}

	/// The DER of the certificate of the leaf.
	pub fn leaf(&self) -> &CertificateDer<'static> {
		&self.leaf
	}

	/// The DER of the chain that the leaf presents: its certificate, then
	/// each intermediate authority up to the root, without it.
	pub fn chain(&self) -> Vec<CertificateDer<'static>> {
		[self.leaf.clone()].into_iter().chain(self.issuers.iter().cloned()).collect()
	}

	/// The certificate of the leaf in PEM.
	pub fn certificate_pem(&self) -> &str {
		&self.certificate_pem
	}

	/// The chain of [`TlsLeaf::chain`] in PEM, as a stock gRPC peer presents
	/// it.
	pub fn chain_pem(&self) -> &str {
		&self.chain_pem
	}

	/// The private key of the leaf in PKCS #8 PEM.
	pub fn key_pem(&self) -> &str {
		&self.key_pem
	}
}

/// The coupled edge of the e2e stack: the methods that it routes, the callers
/// that it grants them to, and its TLS material under one directory.
///
/// - The directory holds the root, the certificate of the edge, a stock caller,
///   a signing caller, and the claim identity of the signing caller under
///   [`CoupledStack::CLAIMS`].
/// - The directory holds the whole set from the moment it exists.
///
/// # Examples
///
/// ```
/// use tightbeam_grpc::testing::CoupledStack;
///
/// let mounted = CoupledStack::at("/coupled");
/// assert_eq!(mounted.root(), std::path::Path::new("/coupled/root.pem"));
/// ```
#[derive(Clone, Debug)]
pub struct CoupledStack {
	dir: PathBuf,
}

impl CoupledStack {
	/// The SPIFFE ID of the stock caller.
	pub const CALLER: &'static str = "spiffe://acme/grpcurl";

	/// The subject of the signing caller, and of the claim identity that it
	/// signs its claims under.
	pub const SIGNER: &'static str = "CN=coupled claims,O=acme,C=US";

	/// The name of the claim identity of the signing caller.
	pub const CLAIMS: &'static str = "claims";

	/// The method that the edge of the stack routes as `Vouched`, which the
	/// stock caller calls.
	pub const GET: &'static str = "/orders.v1.Orders/Get";

	/// The method that the edge of the stack routes as `Signed`, which the
	/// signing caller calls.
	pub const PLACE: &'static str = "/orders.v1.Orders/Place";

	/// The stack whose files lie under `dir`.
	pub fn at(dir: impl Into<PathBuf>) -> Self {
		Self { dir: dir.into() }
	}

	/// The stack whose files lie under the `coupled` directory of `certs`, the
	/// certificate directory of the stack.
	pub fn under(certs: impl AsRef<Path>) -> Self {
		Self::at(certs.as_ref().join("coupled"))
	}

	/// The directory that holds the material.
	pub fn dir(&self) -> &Path {
		&self.dir
	}

	/// Whether the set is written, so the stack keeps the material it has.
	pub fn exists(&self) -> bool {
		self.dir.is_dir()
	}

	/// Create each certificate, valid for `lifetime`, write it and its key,
	/// and write the claim identity through `claims`, under a sibling staging
	/// directory that a rename then publishes whole. A write that fails at
	/// any step publishes nothing.
	///
	/// # Errors
	///
	/// - The errors of [`TlsAuthority::mint`], [`TlsAuthority::server`], and [`TlsAuthority::caller`].
	/// - [`MintError::Io`] -- a file cannot be written, or the directory is published already.
	/// - The `E` of a `claims` that fails.
	pub fn write<E: From<MintError>>(
		&self,
		lifetime: Duration,
		claims: impl FnOnce(&Self) -> Result<(), E>,
	) -> Result<(), E> {
		let staged = Self::at(self.staging());
		let _ = fs::remove_dir_all(&staged.dir);

		let written = staged.write_material(lifetime).map_err(E::from).and_then(|()| claims(&staged));
		let published =
			written.and_then(|()| fs::rename(&staged.dir, &self.dir).map_err(|error| E::from(error.into())));
		if published.is_err() {
			let _ = fs::remove_dir_all(&staged.dir);
		}

		published
	}

	/// The sibling directory that a write stages its set in.
	fn staging(&self) -> PathBuf {
		let mut name = self.dir.file_name().unwrap_or_default().to_owned();
		name.push(".staging");
		self.dir.with_file_name(name)
	}

	/// Create each certificate, valid for `lifetime`, and write it and its key
	/// under the directory.
	fn write_material(&self, lifetime: Duration) -> Result<(), MintError> {
		fs::create_dir_all(&self.dir)?;

		let authority = TlsAuthority::mint("CN=coupled edge root,O=acme,C=US", lifetime)?;
		let edge = authority.server("CN=coupled edge,O=acme,C=US")?;
		let caller = authority.caller("CN=grpcurl,O=acme,C=US", Some(Self::CALLER))?;
		let signer = authority.caller(Self::SIGNER, None)?;

		fs::write(self.root(), authority.root_pem()?)?;
		fs::write(self.edge_chain(), edge.certificate_pem())?;
		fs::write(self.edge_key(), edge.key_pem())?;
		fs::write(self.caller_chain(), caller.certificate_pem())?;
		fs::write(self.caller_key(), caller.key_pem())?;
		fs::write(self.signer_chain(), signer.certificate_pem())?;
		fs::write(self.signer_key(), signer.key_pem())?;
		Ok(())
	}

	/// The PEM of the root, which the edge and each caller trust.
	pub fn root(&self) -> PathBuf {
		self.dir.join("root.pem")
	}

	/// The PEM certificate of the edge.
	pub fn edge_chain(&self) -> PathBuf {
		self.dir.join("edge.crt")
	}

	/// The PEM private key of the edge.
	pub fn edge_key(&self) -> PathBuf {
		self.dir.join("edge.key")
	}

	/// The PEM certificate of the stock caller.
	pub fn caller_chain(&self) -> PathBuf {
		self.dir.join("caller.crt")
	}

	/// The PEM private key of the stock caller.
	pub fn caller_key(&self) -> PathBuf {
		self.dir.join("caller.key")
	}

	/// The PEM certificate of the signing caller.
	pub fn signer_chain(&self) -> PathBuf {
		self.dir.join("signer.crt")
	}

	/// The PEM private key of the signing caller.
	pub fn signer_key(&self) -> PathBuf {
		self.dir.join("signer.key")
	}

	/// The PEM certificate of the claim identity, which the edge trusts as
	/// its claim store.
	pub fn claims(&self) -> PathBuf {
		self.dir.join("claims.pem")
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A directory of its own under the temporary directory of the system.
	fn scratch(name: &str) -> PathBuf {
		let unique = format!("tightbeam-grpc-{name}-{}", std::process::id());
		let dir = std::env::temp_dir().join(unique);
		let _ = fs::remove_dir_all(&dir);
		dir
	}

	/// How long the material of a test stays valid.
	const LIFETIME: Duration = Duration::from_secs(3600);

	#[test]
	fn an_interrupted_write_publishes_no_material() {
		let certs = scratch("interrupted");
		let files = CoupledStack::under(&certs);
		let interrupted = io::Error::other("the claims step was interrupted");
		let written = files.write(LIFETIME, |_| Err(MintError::Io(interrupted)));

		assert!(written.is_err());
		assert!(!files.exists(), "a set with no claims MUST read as absent");
		assert!(!files.staging().exists(), "a failed write MUST leave no staging directory");
		let _ = fs::remove_dir_all(&certs);
	}

	#[test]
	fn a_whole_write_publishes_every_file() -> Result<(), MintError> {
		let certs = scratch("whole");
		let files = CoupledStack::under(&certs);
		files.write(LIFETIME, |staged| Ok::<_, MintError>(fs::write(staged.claims(), "claims")?))?;

		let published = [
			files.root(),
			files.edge_chain(),
			files.edge_key(),
			files.caller_chain(),
			files.caller_key(),
		];
		let published = published
			.into_iter()
			.chain([files.signer_chain(), files.signer_key(), files.claims()]);
		assert!(files.exists() && published.into_iter().all(|file| file.is_file()));
		let _ = fs::remove_dir_all(&certs);
		Ok(())
	}
}
