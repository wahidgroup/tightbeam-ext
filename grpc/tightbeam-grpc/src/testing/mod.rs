//! Test support: a TLS PKI minted at run time, and profiles that a scenario
//! stages. rustls verifies no secp256k1, so the test certificates sign under
//! P-256.

use core::fmt;
use core::str::FromStr;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, PoisonError};

use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::EncodePrivateKey;
use rand_core::OsRng;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tightbeam::der::asn1::{Ia5String, ObjectIdentifier};
use tightbeam::der::pem::LineEnding;
use tightbeam::der::{Decode, Encode, EncodePem};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{ExtendedKeyUsage, SubjectAltName};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

use crate::edge::{Dial, DialTls, Edge, EdgeError, EdgeTls};

/// `id-kp-serverAuth` (RFC 5280 section 4.2.1.12).
const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

/// `id-kp-clientAuth` (RFC 5280 section 4.2.1.12).
const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

/// The DNS name of loopback that every edge certificate names.
const LOCALHOST: &str = "localhost";

/// Why the test PKI cannot mint a certificate.
#[derive(Debug)]
pub enum MintError {
	/// The builder refuses the certificate, or the signature fails.
	Certificate(x509_cert::builder::Error),
	/// A name, a validity, or a certificate does not encode.
	Der(tightbeam::der::Error),
	/// The private key does not encode as PKCS #8.
	Key(p256::pkcs8::Error),
	/// The private key does not encode as PEM.
	Pem(tightbeam::der::pem::Error),
	/// rustls refuses the minted material.
	Edge(EdgeError),
}

impl fmt::Display for MintError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Certificate(error) => write!(f, "the certificate does not build: {error}"),
			Self::Der(error) => write!(f, "the certificate does not encode: {error}"),
			Self::Key(error) => write!(f, "the private key does not encode: {error}"),
			Self::Pem(error) => write!(f, "the material does not encode as PEM: {error}"),
			Self::Edge(error) => write!(f, "rustls refuses the minted material: {error}"),
		}
	}
}

impl std::error::Error for MintError {}

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
		Self::Pem(error)
	}
}

impl From<EdgeError> for MintError {
	fn from(error: EdgeError) -> Self {
		Self::Edge(error)
	}
}

/// A TLS PKI minted at run time: a P-256 root, which issues the certificate
/// of each edge, and which each dial trusts.
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
/// let edge = Edge::Tls(authority.edge("CN=edge,O=tightbeam-grpc")?);
/// let dial = Dial::Tls(authority.dial()?);
/// # Ok::<(), tightbeam_grpc::testing::MintError>(())
/// ```
pub struct TlsAuthority {
	key: SigningKey,
	name: Name,
	root: CertificateDer<'static>,
	lifetime: Duration,
	/// The serial number of the next certificate that the root issues. The
	/// root itself holds serial number 1.
	serial: AtomicU64,
}

impl TlsAuthority {
	/// A root named `subject`, such as `CN=test root,O=acme`, whose
	/// certificate and every certificate it issues stay valid for `lifetime`
	/// from now.
	///
	/// # Errors
	///
	/// - [`MintError::Der`] -- `subject` is no distinguished name, or `lifetime` passes the range of a validity.
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

		Ok(Self { key, name, root, lifetime, serial: AtomicU64::new(2) })
	}

	/// The certificate of the root, which a dial trusts.
	pub fn root(&self) -> CertificateDer<'static> {
		self.root.clone()
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

	/// A TLS client certificate named `subject`, which this root issues for
	/// client authentication, with the SPIFFE ID `spiffe` as its one URI
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
		TlsLeaf::new(&leaf, &key)
	}

	/// A TLS server certificate named `subject`, which this root issues for
	/// server authentication on loopback, as a stock gRPC server loads it.
	///
	/// # Errors
	///
	/// - The errors of [`TlsAuthority::edge`].
	pub fn server(&self, subject: &str) -> Result<TlsLeaf, MintError> {
		let key = SigningKey::random(&mut OsRng);
		let leaf = self.issue(subject, &key, Self::loopback()?, SERVER_AUTH)?;
		TlsLeaf::new(&leaf, &key)
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
	/// root issues for `usage`, with `names` as its subject alternative names.
	fn issue(
		&self,
		subject: &str,
		key: &SigningKey,
		names: Vec<GeneralName>,
		usage: ObjectIdentifier,
	) -> Result<x509_cert::Certificate, MintError> {
		let public = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key())?;
		let validity = Validity::from_now(self.lifetime)?;
		let serial = SerialNumber::from(self.serial.fetch_add(1, Ordering::Relaxed));

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

	/// The TLS of an edge under a fresh certificate named `subject`, which
	/// this root issues for server authentication on loopback: the DNS name
	/// `localhost`, and the addresses `127.0.0.1` and `::1`.
	///
	/// # Errors
	///
	/// - [`MintError::Der`] -- `subject` is no distinguished name.
	/// - [`MintError::Certificate`] -- the certificate does not build.
	/// - [`MintError::Key`] -- the private key does not encode.
	/// - [`MintError::Edge`] -- rustls refuses the chain or the key.
	pub fn edge(&self, subject: &str) -> Result<EdgeTls, MintError> {
		let key = SigningKey::random(&mut OsRng);
		let leaf = self.issue(subject, &key, Self::loopback()?, SERVER_AUTH)?;

		let chain = [CertificateDer::from(leaf.to_der()?), self.root()];
		let pkcs8 = key.to_pkcs8_der()?;
		let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec()));
		Ok(EdgeTls::new(chain, key)?)
	}
}

/// The TLS material of one leaf that the test root issued: its certificate
/// and its private key in PEM, as a stock gRPC peer loads them, and in DER, as
/// rustls takes them. A claim of a caller binds to the DER of its certificate.
pub struct TlsLeaf {
	leaf: CertificateDer<'static>,
	key: PrivatePkcs8KeyDer<'static>,
	certificate_pem: String,
	key_pem: String,
}

impl TlsLeaf {
	/// The material of `leaf` and of its private key `key`.
	fn new(leaf: &x509_cert::Certificate, key: &SigningKey) -> Result<Self, MintError> {
		let certificate_pem = leaf.to_pem(LineEnding::LF)?;
		let key_pem = key.to_pkcs8_pem(LineEnding::LF)?.to_string();
		let pkcs8 = key.to_pkcs8_der()?;
		let key = PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec());
		let leaf = CertificateDer::from(leaf.to_der()?);
		Ok(Self { leaf, key, certificate_pem, key_pem })
	}

	/// The private key of the leaf in DER, as rustls takes it.
	pub fn key(&self) -> PrivateKeyDer<'static> {
		PrivateKeyDer::Pkcs8(self.key.clone_key())
	}

	/// The DER of the certificate of the leaf.
	pub fn leaf(&self) -> &CertificateDer<'static> {
		&self.leaf
	}

	/// The certificate of the leaf in PEM.
	pub fn certificate_pem(&self) -> &str {
		&self.certificate_pem
	}

	/// The private key of the leaf in PKCS #8 PEM.
	pub fn key_pem(&self) -> &str {
		&self.key_pem
	}
}

/// The material of a staged profile.
struct Staged {
	edge: Edge,
	dial: Dial,
}

/// The cell of a profile that [`staged_profile!`](crate::staged_profile)
/// declares: the material that a scenario stages, which every later bind and
/// dial of the profile reads.
pub struct StagedCell {
	staged: Mutex<Option<Staged>>,
}

impl StagedCell {
	/// An empty cell, so a bind or a dial before the stage fails with
	/// [`EdgeError::Unprovisioned`].
	#[must_use]
	pub const fn new() -> Self {
		Self { staged: Mutex::new(None) }
	}

	/// Stage `edge` for every later bind and `dial` for every later dial, in
	/// place of the material of an earlier stage.
	pub fn stage(&self, edge: Edge, dial: Dial) {
		let mut staged = self.staged.lock().unwrap_or_else(PoisonError::into_inner);
		*staged = Some(Staged { edge, dial });
	}

	/// The staged setup of a bind.
	///
	/// # Errors
	///
	/// - [`EdgeError::Unprovisioned`] -- nothing is staged.
	pub fn edge(&self) -> Result<Edge, EdgeError> {
		let staged = self.staged.lock().unwrap_or_else(PoisonError::into_inner);
		let edge = staged.as_ref().map(|staged| staged.edge.clone());
		edge.ok_or(EdgeError::Unprovisioned)
	}

	/// The staged setup of a dial.
	///
	/// # Errors
	///
	/// - [`EdgeError::Unprovisioned`] -- nothing is staged.
	pub fn dial(&self) -> Result<Dial, EdgeError> {
		let staged = self.staged.lock().unwrap_or_else(PoisonError::into_inner);
		let dial = staged.as_ref().map(|staged| staged.dial.clone());
		dial.ok_or(EdgeError::Unprovisioned)
	}
}

impl Default for StagedCell {
	fn default() -> Self {
		Self::new()
	}
}

/// Declares an [`EdgeProfile`](crate::edge::EdgeProfile) whose material a
/// scenario stages at run time.
///
/// Each declared type holds a cell of its own, so scenarios that run at once
/// in one test binary stay apart as long as each one declares its own type.
/// The type gains `stage(edge, dial)`, which replaces the material of every
/// later bind and dial.
///
/// # Examples
///
/// ```
/// use core::time::Duration;
///
/// use tightbeam_grpc::edge::{Dial, Edge, EdgeProfile};
/// use tightbeam_grpc::testing::TlsAuthority;
///
/// tightbeam_grpc::staged_profile! {
///     /// The edge of one scenario.
///     EchoEdge
/// }
///
/// assert!(EchoEdge::edge().is_err());
///
/// let authority = TlsAuthority::mint("CN=test root", Duration::from_secs(60))?;
/// EchoEdge::stage(Edge::Tls(authority.edge("CN=edge")?), Dial::Tls(authority.dial()?));
/// assert!(matches!(EchoEdge::edge(), Ok(Edge::Tls(_))));
/// # Ok::<(), tightbeam_grpc::testing::MintError>(())
/// ```
#[macro_export]
macro_rules! staged_profile {
	($(#[$meta:meta])* $vis:vis $name:ident) => {
		$(#[$meta])*
		$vis struct $name;

		impl $name {
			/// The cell of this profile.
			fn cell() -> &'static $crate::testing::StagedCell {
				static CELL: $crate::testing::StagedCell = $crate::testing::StagedCell::new();
				&CELL
			}

			/// Stage `edge` for every later bind and `dial` for every later
			/// dial of this profile.
			#[allow(dead_code)]
			$vis fn stage(edge: $crate::edge::Edge, dial: $crate::edge::Dial) {
				Self::cell().stage(edge, dial);
			}
		}

		impl $crate::edge::EdgeProfile for $name {
			fn edge() -> ::core::result::Result<$crate::edge::Edge, $crate::edge::EdgeError> {
				Self::cell().edge()
			}

			fn dial() -> ::core::result::Result<$crate::edge::Dial, $crate::edge::EdgeError> {
				Self::cell().dial()
			}
		}
	};
}
