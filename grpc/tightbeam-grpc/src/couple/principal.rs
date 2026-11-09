//! The principal of a coupled caller: the one SPIFFE ID of its certificate,
//! or else its subject.
//!
//! # Sources
//!
//! - SPIFFE ID, `spiffe/spiffe` `standards/SPIFFE-ID.md`: <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md>
//! - RFC 5280, X.509 PKIX, May 2008, section 4.2.1.6: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6>

use core::fmt;
use core::hash::{Hash, Hasher};
use core::str::FromStr;

use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use tightbeam::crypto::x509::ext::pkix::name::GeneralName;
use tightbeam::crypto::x509::ext::pkix::SubjectAltName;
use tightbeam::crypto::x509::name::Name;
use tightbeam::crypto::x509::Certificate;
use tightbeam::der::asn1::ObjectIdentifier;
use tightbeam::der::Decode;

use crate::edge::EdgeError;

/// The scheme of a SPIFFE ID.
const SPIFFE_SCHEME: &str = "spiffe://";

/// The OID of the subject alternative name extension (RFC 5280 section 4.2.1.6).
const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// Who a coupled caller is: the one name that a grant matches.
///
/// # Examples
///
/// ```
/// use tightbeam_grpc::couple::Principal;
///
/// let billing = Principal::spiffe("spiffe://acme/billing")?;
/// let web = Principal::subject("CN=web,O=acme")?;
/// assert_ne!(billing, web);
/// assert_eq!(web.to_string(), "CN=web,O=acme");
/// # Ok::<(), tightbeam_grpc::edge::EdgeError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Principal {
	/// The SPIFFE ID of a certificate that carries one.
	Spiffe(String),
	/// The subject of a certificate that carries no SPIFFE ID.
	Subject(Name),
}

impl Principal {
	/// The principal of the SPIFFE ID `id`, such as `spiffe://acme/billing`.
	///
	/// # Errors
	///
	/// - [`EdgeError::Principal`] -- `id` does not start with `spiffe://`, or names no trust domain.
	pub fn spiffe(id: impl Into<String>) -> Result<Self, EdgeError> {
		let id: String = id.into();
		let domain = id.strip_prefix(SPIFFE_SCHEME).and_then(|rest| rest.split('/').next());
		if domain.is_none_or(str::is_empty) {
			return Err(EdgeError::Principal(id));
		}

		Ok(Self::Spiffe(id))
	}

	/// The principal of the subject `dn`, a distinguished name in the string
	/// form of RFC 4514, such as `CN=web,O=acme`.
	///
	/// # Errors
	///
	/// - [`EdgeError::Principal`] -- `dn` is no distinguished name.
	pub fn subject(dn: &str) -> Result<Self, EdgeError> {
		let name = Name::from_str(dn).map_err(|_| EdgeError::Principal(dn.to_owned()))?;
		Ok(Self::Subject(name))
	}

	/// The principal that `certificate` names, by the rule of this module.
	///
	/// `None` when the certificate carries two SPIFFE IDs, or a subject
	/// alternative name that does not decode.
	pub(crate) fn of(certificate: &Certificate) -> Option<Self> {
		let tbs = &certificate.tbs_certificate;

		let mut ids = Vec::new();
		let extensions = tbs.extensions.as_deref().unwrap_or_default();
		for extension in extensions.iter().filter(|extension| extension.extn_id == SUBJECT_ALT_NAME) {
			let names = SubjectAltName::from_der(extension.extn_value.as_bytes()).ok()?;
			for name in names.0 {
				if let GeneralName::UniformResourceIdentifier(uri) = name {
					let uri = uri.as_str();
					if uri.starts_with(SPIFFE_SCHEME) {
						ids.push(uri.to_owned());
					}
				}
			}
		}

		match ids.as_slice() {
			[] => Some(Self::Subject(tbs.subject.clone())),
			[id] => Some(Self::Spiffe(id.clone())),
			_ => None,
		}
	}
}

/// Equal principals print the same SPIFFE ID or the same RFC 4514 string, so
/// the hash of that text agrees with the equality of the principals.
impl Hash for Principal {
	fn hash<H: Hasher>(&self, state: &mut H) {
		core::mem::discriminant(self).hash(state);
		self.to_string().hash(state);
	}
}

/// The SPIFFE ID, or the subject in the string form of RFC 4514.
impl fmt::Display for Principal {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Spiffe(id) => f.write_str(id),
			Self::Subject(name) => write!(f, "{name}"),
		}
	}
}

/// The caller of one TLS connection: the principal of the client certificate
/// that the edge verified, and the SHA-256 of that certificate, which a claim
/// binds to.
///
/// `GrpcIncoming` builds it once, when the handshake of the connection
/// completes, so every call of the connection reads the same caller.
#[derive(Debug)]
pub(crate) struct Caller {
	principal: Principal,
	leaf_digest: [u8; 32],
}

impl Caller {
	/// The caller of the verified client certificate `leaf`, or `None` when
	/// the certificate does not parse or names no principal.
	pub(crate) fn from_leaf(leaf: &CertificateDer<'_>) -> Option<Self> {
		let certificate = Certificate::from_der(leaf.as_ref()).ok()?;
		let principal = Principal::of(&certificate)?;
		let leaf_digest = Self::digest(leaf.as_ref());
		Some(Self { principal, leaf_digest })
	}

	/// The SHA-256 of the DER of a TLS leaf, which a claim binds to.
	pub(crate) fn digest(leaf: &[u8]) -> [u8; 32] {
		Sha256::digest(leaf).into()
	}

	/// The principal of the caller.
	pub(crate) fn principal(&self) -> &Principal {
		&self.principal
	}

	/// The SHA-256 of the client certificate of the caller.
	pub(crate) fn leaf_digest(&self) -> &[u8; 32] {
		&self.leaf_digest
	}
}
