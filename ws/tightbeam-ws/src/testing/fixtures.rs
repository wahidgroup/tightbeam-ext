//! The X.509 identity fixtures of the e2e stack, as `docs/ws.md` (Test
//! support) states it.

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tightbeam::cert;
use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::ecdsa::{Secp256k1SigningKey, Secp256k1VerifyingKey};
use tightbeam::crypto::sign::{Sha3Signer, SigningIdentity};
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::crypto::x509::{KeyPurposes, PeerCertificate, Signing};
use tightbeam::der::{Decode, Encode};
use tightbeam::random::OsRng;
use tightbeam::spki::SubjectPublicKeyInfoOwned;
use tightbeam::transport::TransportEncryptionConfig;
use tightbeam::x509::Certificate;
use tightbeam::{Errorizable, Frame, TightBeamError};

use super::env::EnvVar;
use super::handshake::Pinned;
use super::Result;

/// Size in bytes of a raw secp256k1 signing scalar.
pub const SIGNING_KEY_LEN: usize = 32;

/// The variable naming the server certificate DER file, which sits beside
/// its signing key.
const SERVER_CERT: EnvVar = EnvVar::new("TBWS_SERVER_CERT");

/// The suffix of the certificate file of an identity.
const CERTIFICATE_SUFFIX: &str = ".cert.der";

/// The suffix of the signing key file of an identity.
const SIGNING_KEY_SUFFIX: &str = ".key";

/// A self-signed X.509 identity: an end-entity certificate paired with its
/// secp256k1 signing key.
///
/// - The certificate asserts `digitalSignature`, which a handshake and a frame signature read.
/// - It names no `extendedKeyUsage`, so it serves the server, client, and signer roles alike.
/// - A CA certificate asserts only `keyCertSign`, and the signing use refuses it.
/// - Each constructor pairs the key with the certificate once, and refuses a key of another certificate.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
///
/// use tightbeam_ws::testing::Identity;
///
/// let issued = Identity::mint("CN=doc,O=tightbeam-ws,C=US", 1, Duration::from_secs(60))?;
/// let certificate = issued.certificate_der()?;
/// let reloaded = Identity::from_der(&certificate, &issued.signing_key_bytes())?;
/// assert_eq!(reloaded.certificate_der()?, certificate);
/// # Ok::<(), tightbeam_ws::testing::Error>(())
/// ```
pub struct Identity {
	/// The certificate and the provider of its key, paired at construction.
	signing: SigningIdentity,
	signing_key: Secp256k1SigningKey,
}

impl Identity {
	/// Issue a fresh self-signed identity valid for `validity` from now.
	///
	/// # Errors
	///
	/// - [`Error::Ws`](super::Error::Ws) -- the certificate fails to issue.
	pub fn mint(subject: &str, serial: u32, validity: Duration) -> Result<Self> {
		let signing_key = Secp256k1SigningKey::random(&mut OsRng);
		Self::from_key(signing_key, subject, serial, validity)
	}

	/// Issue a self-signed identity over `signing_key`, valid for `validity`
	/// from now.
	///
	/// - A frame that `signing_key` signs verifies under this identity, whatever certificate the signer
	///   presented, so a fixed test key yields a probe that checks the signatures of its peers.
	///
	/// # Errors
	///
	/// - [`Error::Ws`](super::Error::Ws) -- the certificate fails to issue.
	///
	/// # Examples
	///
	/// ```
	/// use std::time::Duration;
	///
	/// use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
	/// use tightbeam::random::OsRng;
	/// use tightbeam_ws::testing::Identity;
	///
	/// let key = Secp256k1SigningKey::random(&mut OsRng);
	/// let scalar: [u8; 32] = key.to_bytes().into();
	/// let probe = Identity::from_key(key, "CN=probe,O=tightbeam-ws,C=US", 1, Duration::from_secs(60))?;
	/// assert_eq!(probe.signing_key_bytes(), scalar);
	/// # Ok::<(), tightbeam_ws::testing::Error>(())
	/// ```
	pub fn from_key(signing_key: Secp256k1SigningKey, subject: &str, serial: u32, validity: Duration) -> Result<Self> {
		Ok(Self::issued(signing_key, subject, serial, validity)?)
	}

	/// The body of [`from_key`](Self::from_key), in the error type the
	/// `cert!` macro converts into.
	fn issued(
		signing_key: Secp256k1SigningKey,
		subject: &str,
		serial: u32,
		validity: Duration,
	) -> core::result::Result<Self, TightBeamError> {
		let verifying_key = Secp256k1VerifyingKey::from(&signing_key);
		let spki = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;
		let signer = Sha3Signer::from(&signing_key);

		let certificate = cert!(
			profile: Leaf,
			subject: subject,
			issuer: subject,
			serial: serial,
			duration: validity,
			subject_public_key: spki,
			signer: &signer
		)?;

		Self::paired(certificate, signing_key)
	}

	/// The identity of `certificate` beside `signing_key`, once the pair
	/// proves that the key is the key of the certificate.
	fn paired(
		certificate: Certificate,
		signing_key: Secp256k1SigningKey,
	) -> core::result::Result<Self, TightBeamError> {
		let key = Arc::new(Secp256k1KeyProvider::from(signing_key.clone()));
		let signing = SigningIdentity::new(certificate, key)?;
		Ok(Self { signing, signing_key })
	}

	/// The identity of a DER certificate and a raw 32-byte key, the form that
	/// [`IdentityFiles`] holds.
	///
	/// # Errors
	///
	/// - [`Error::Ws`](super::Error::Ws) -- the certificate or the key does not decode, or the key is not the
	///   key of the certificate.
	pub fn from_der(certificate_der: &[u8], signing_key: &[u8; SIGNING_KEY_LEN]) -> Result<Self> {
		let certificate = Certificate::from_der(certificate_der).map_err(TightBeamError::from)?;
		let scalar = *signing_key;
		let signing_key = Secp256k1SigningKey::from_bytes(&scalar.into()).map_err(TightBeamError::from)?;

		Ok(Self::paired(certificate, signing_key)?)
	}

	/// Load the server identity from the files that `TBWS_SERVER_CERT` names,
	/// as the echo-server examples are provisioned.
	///
	/// # Errors
	///
	/// - The errors of [`IdentityFiles::from_env`] and [`IdentityFiles::load`].
	pub fn from_env() -> Result<Self> {
		IdentityFiles::from_env(SERVER_CERT)?.load()
	}

	/// The certificate that a peer pins as this identity.
	pub fn certificate(&self) -> &Certificate {
		self.signing.certificate()
	}

	/// DER-encode the certificate for provisioning to peers.
	///
	/// # Errors
	///
	/// - [`Error::Ws`](super::Error::Ws) -- the certificate does not encode.
	pub fn certificate_der(&self) -> Result<Vec<u8>> {
		Ok(self.certificate().to_der().map_err(TightBeamError::from)?)
	}

	/// The raw 32-byte secp256k1 signing scalar.
	pub fn signing_key_bytes(&self) -> [u8; SIGNING_KEY_LEN] {
		self.signing_key.to_bytes().into()
	}

	/// This identity as the certificate and key provider a handshake and a
	/// frame signature take, for a server's reply and a mutual client's
	/// Finished alike.
	pub fn signing_identity(&self) -> SigningIdentity {
		self.signing.clone()
	}

	/// The server transport encryption config that presents this identity in
	/// the HPKE handshake.
	pub fn server_config(&self) -> TransportEncryptionConfig<DefaultCryptoProvider> {
		TransportEncryptionConfig::new(self.signing_identity())
	}

	/// Whether `frame` carries a signature that the certificate of this
	/// identity verifies over the bytes this end received.
	pub fn verifies(&self, frame: &Frame) -> bool {
		let certificate = self.certificate().clone();
		let signer = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(certificate, KeyPurposes::HOUSE.signer);
		signer.is_ok_and(|signer| frame.verify(&signer).is_ok())
	}

	/// Build a single-anchor trust store pinning this identity's certificate,
	/// for a peer that authenticates this identity.
	///
	/// # Errors
	///
	/// - The errors of [`Pinned::trust`].
	pub fn trust_anchor(&self) -> Result<Arc<dyn CertificateTrust>> {
		let pinned = Pinned::from(self.certificate().clone());
		pinned.trust()
	}
}

/// The pair of files that holds one identity under `dir`: the DER certificate
/// `{name}.cert.der` and the raw 32-byte signing key `{name}.key`.
///
/// One carrier names both files, so each path keeps its role.
///
/// # Examples
///
/// ```
/// use std::env;
/// use std::fs;
/// use std::time::Duration;
///
/// use tightbeam_ws::testing::{Identity, IdentityFiles};
///
/// let dir = env::temp_dir().join("tbws-doc-identity-files");
/// fs::create_dir_all(&dir)?;
///
/// let files = IdentityFiles::new(&dir, "doc")?;
/// let issued = Identity::mint("CN=doc,O=tightbeam-ws,C=US", 1, Duration::from_secs(60))?;
/// files.provision(&issued)?;
///
/// let loaded = files.load()?;
/// assert_eq!(loaded.certificate_der()?, issued.certificate_der()?);
/// # Ok::<(), tightbeam_ws::testing::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityFiles {
	dir: PathBuf,
	name: String,
}

impl IdentityFiles {
	/// The files of the identity `name` under `dir`.
	///
	/// # Errors
	///
	/// - [`IdentityFilesError::Unnamed`] -- `name` is empty, so it names no file.
	pub fn new(dir: impl Into<PathBuf>, name: impl Into<String>) -> Result<Self> {
		let name = name.into();
		if name.is_empty() {
			return Err(IdentityFilesError::Unnamed.into());
		}

		Ok(Self { dir: dir.into(), name })
	}

	/// The files of the identity whose certificate file the variable
	/// `certificate` names. The signing key sits beside the certificate.
	///
	/// # Errors
	///
	/// - [`Error::Env`](super::Error::Env) -- the variable is unset.
	/// - [`IdentityFilesError::NotACertificate`] -- the path names no `{name}.cert.der` file.
	pub fn from_env(certificate: EnvVar) -> Result<Self> {
		let path = certificate.required_path()?;
		Self::of_certificate(path)
	}

	/// Write `identity` to these files, so that a certificate file always
	/// has its own key beside it.
	///
	/// The certificate publishes the identity, so the steps run in this order:
	///
	/// 1. Write both files into a sibling staging directory.
	/// 2. Remove the published certificate, which unpublishes an older identity.
	/// 3. Rename the key into place, then the certificate.
	///
	/// # Errors
	///
	/// - [`Error::Ws`](super::Error::Ws) -- a file does not write or move.
	/// - The errors of [`Identity::certificate_der`].
	pub fn provision(&self, identity: &Identity) -> Result<()> {
		let staged = self.staged()?;
		fs::write(staged.certificate(), identity.certificate_der()?)?;
		fs::write(staged.signing_key(), identity.signing_key_bytes())?;

		match fs::remove_file(self.certificate()) {
			Err(error) if error.kind() != ErrorKind::NotFound => return Err(error.into()),
			_unpublished => {}
		}

		fs::rename(staged.signing_key(), self.signing_key())?;
		fs::rename(staged.certificate(), self.certificate())?;
		fs::remove_dir(&staged.dir)?;
		Ok(())
	}

	/// Read the identity these files hold.
	///
	/// # Errors
	///
	/// - [`Error::Ws`](super::Error::Ws) -- a file does not read.
	/// - [`IdentityFilesError::KeyLength`] -- the key file holds another size than [`SIGNING_KEY_LEN`].
	/// - The errors of [`Identity::from_der`].
	pub fn load(&self) -> Result<Identity> {
		let certificate_der = fs::read(self.certificate())?;
		let key_bytes = fs::read(self.signing_key())?;

		let Ok(key) = <[u8; SIGNING_KEY_LEN]>::try_from(key_bytes.as_slice()) else {
			return Err(IdentityFilesError::KeyLength(key_bytes.len()).into());
		};

		Identity::from_der(&certificate_der, &key)
	}

	/// The files whose certificate file is `path`.
	pub(super) fn of_certificate(path: PathBuf) -> Result<Self> {
		let file_name = path.file_name().and_then(|file_name| file_name.to_str());
		let name = file_name.and_then(|file_name| file_name.strip_suffix(CERTIFICATE_SUFFIX));
		let Some(name) = name else {
			return Err(IdentityFilesError::NotACertificate.into());
		};

		let dir = path.parent().map(PathBuf::from).unwrap_or_default();
		Self::new(dir, name)
	}

	/// The same files in an empty staging directory beside these, on the
	/// same file system, so a rename publishes each one whole.
	fn staged(&self) -> Result<Self> {
		let dir = self.dir.join(format!(".{}.staging", self.name));
		match fs::remove_dir_all(&dir) {
			Err(error) if error.kind() != ErrorKind::NotFound => return Err(error.into()),
			_cleared => {}
		}

		fs::create_dir(&dir)?;
		Ok(Self { dir, name: self.name.clone() })
	}

	/// The certificate file.
	fn certificate(&self) -> PathBuf {
		self.dir.join(format!("{}{CERTIFICATE_SUFFIX}", self.name))
	}

	/// The signing key file.
	fn signing_key(&self) -> PathBuf {
		self.dir.join(format!("{}{SIGNING_KEY_SUFFIX}", self.name))
	}
}

/// The refusal of a name, a certificate path, or a key file of
/// [`IdentityFiles`].
///
/// # Examples
///
/// ```
/// use tightbeam_ws::testing::{Error, IdentityFiles, IdentityFilesError};
///
/// let refused = IdentityFiles::new("/certs", "");
/// assert!(matches!(refused, Err(Error::IdentityFiles(IdentityFilesError::Unnamed))));
/// ```
#[derive(Clone, Debug, Errorizable, PartialEq, Eq)]
pub enum IdentityFilesError {
	/// The name of the identity is empty, so it names no file.
	#[error("an identity file name must name the identity")]
	Unnamed,
	/// The name of the certificate file does not end in `.cert.der`.
	#[error("an identity certificate file name ends in .cert.der")]
	NotACertificate,
	/// The key file holds this many bytes, not [`SIGNING_KEY_LEN`].
	#[error("a signing key file holds exactly 32 bytes, not {0}")]
	KeyLength(usize),
}

#[cfg(test)]
mod tests {
	use std::path::PathBuf;
	use std::time::Duration;
	use std::{env, fs, process};

	use tightbeam::builder::TypeBuilder;
	use tightbeam::crypto::sign::SignerError;
	use tightbeam::testing::{TestIdentity, TestKey, TestMessage};
	use tightbeam::{Frame, TightBeamError, Version};

	use super::{Identity, IdentityFiles, IdentityFilesError};
	use crate::testing::Error;

	/// A fresh, empty directory for the files of one test.
	fn scratch_dir(test: &str) -> PathBuf {
		let dir = env::temp_dir().join(format!("tbws-{test}-{}", process::id()));
		let _absent = fs::remove_dir_all(&dir);
		let created = fs::create_dir_all(&dir);
		created.expect("the scratch directory should create");

		dir
	}

	/// A frame that the fixed test key signs under its own self-signed
	/// certificate, as a work-plane client signs its work.
	async fn signed_by_the_test_key() -> Frame {
		let message = TestMessage { content: "probe".into() };
		let built = Version::V1
			.compose()
			.with_id(b"probe")
			.with_order(1)
			.with_message(message)
			.build();

		let mut frame = built.expect("the probe frame builds");
		let signer = TestIdentity::of(&TestKey::insecure_fixed_signing());
		let signed = frame.sign_with_provider(&signer).await;
		signed.expect("the test key signs the frame");

		frame
	}

	#[tokio::test]
	async fn a_test_probe_identity_verifies() -> Result<(), Box<dyn core::error::Error>> {
		let key = TestKey::insecure_fixed_signing();
		let probe = Identity::from_key(key, "CN=probe,O=tightbeam-ws,C=US", 3, Duration::from_secs(60))?;

		let frame = signed_by_the_test_key().await;

		assert!(probe.verifies(&frame));
		Ok(())
	}

	#[test]
	fn identity_files_load_what_they_provision() -> Result<(), Box<dyn core::error::Error>> {
		let files = IdentityFiles::new(scratch_dir("identity-files"), "probe")?;
		let issued = Identity::mint("CN=probe,O=tightbeam-ws,C=US", 7, Duration::from_secs(60))?;
		files.provision(&issued)?;

		let loaded = files.load()?;
		assert_eq!(loaded.certificate_der()?, issued.certificate_der()?);
		assert_eq!(loaded.signing_key_bytes(), issued.signing_key_bytes());
		Ok(())
	}

	#[test]
	fn an_interrupted_provision_publishes_no_certificate() -> Result<(), Box<dyn core::error::Error>> {
		let files = IdentityFiles::new(scratch_dir("interrupted-provision"), "probe")?;
		let identity = Identity::mint("CN=probe,O=tightbeam-ws,C=US", 9, Duration::from_secs(60))?;

		// A directory where the key file goes fails the rename of the key into
		// place.
		fs::create_dir(files.signing_key())?;
		let provisioned = files.provision(&identity);

		assert!(provisioned.is_err(), "a provision whose key fails to move into place MUST fail");
		assert!(
			!files.certificate().exists(),
			"an interrupted provision MUST publish no certificate"
		);
		Ok(())
	}

	#[test]
	fn a_certificate_path_names_the_pair_beside_it() -> Result<(), Box<dyn core::error::Error>> {
		let files = IdentityFiles::of_certificate(PathBuf::from("/certs/client.cert.der"))?;
		assert_eq!(files, IdentityFiles::new("/certs", "client")?);
		Ok(())
	}

	#[test]
	fn an_empty_identity_name_is_refused() {
		let files = IdentityFiles::new("/certs", "");
		assert!(matches!(files, Err(Error::IdentityFiles(IdentityFilesError::Unnamed))));
	}

	#[test]
	fn a_certificate_path_without_the_suffix_is_refused() {
		let files = IdentityFiles::of_certificate(PathBuf::from("/certs/client.der"));
		assert!(matches!(files, Err(Error::IdentityFiles(IdentityFilesError::NotACertificate))));
	}

	#[test]
	fn a_key_file_of_another_length_is_refused() -> Result<(), Box<dyn core::error::Error>> {
		let files = IdentityFiles::new(scratch_dir("key-length"), "probe")?;
		let issued = Identity::mint("CN=probe,O=tightbeam-ws,C=US", 11, Duration::from_secs(60))?;
		files.provision(&issued)?;
		fs::write(files.signing_key(), [0_u8; 31])?;

		let loaded = files.load();
		assert!(matches!(loaded, Err(Error::IdentityFiles(IdentityFilesError::KeyLength(31)))));
		Ok(())
	}

	#[test]
	fn a_key_of_another_identity_is_refused_at_load() -> Result<(), Box<dyn core::error::Error>> {
		let files = IdentityFiles::new(scratch_dir("mismatched-key"), "probe")?;
		let issued = Identity::mint("CN=probe,O=tightbeam-ws,C=US", 13, Duration::from_secs(60))?;
		let other = Identity::mint("CN=other,O=tightbeam-ws,C=US", 14, Duration::from_secs(60))?;
		files.provision(&issued)?;
		fs::write(files.signing_key(), other.signing_key_bytes())?;

		let loaded = files.load();
		let refused = matches!(
			loaded,
			Err(Error::Ws(crate::Error::Tightbeam(TightBeamError::Signer(
				SignerError::KeyMismatch
			))))
		);
		assert!(refused, "a key of another identity MUST fail to load");
		Ok(())
	}
}
