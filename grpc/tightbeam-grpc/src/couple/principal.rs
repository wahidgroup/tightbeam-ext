//! The principal of a coupled caller: the one SPIFFE ID of its certificate,
//! or else its subject.
//!
//! # Sources
//!
//! - SPIFFE ID, `spiffe/spiffe` `standards/SPIFFE-ID.md`:
//!   <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md>
//! - RFC 5280, X.509 PKIX, May 2008, section 4.2.1.6:
//!   <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6>

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

use super::error::CoupleError;
use super::message::PrincipalWire;

/// The scheme of a SPIFFE ID.
const SPIFFE_SCHEME: &str = "spiffe://";

/// The longest SPIFFE ID, in bytes.
const MAX_ID: usize = 2048;

/// The OID of the subject alternative name extension (RFC 5280 section
/// 4.2.1.6).
const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// A SPIFFE trust domain: lowercase ASCII letters, digits, `.`, `-`, and `_`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct TrustDomain(String);

impl TrustDomain {
	/// The trust domain `name`, such as `acme`, or `None` off its grammar.
	pub(crate) fn parse(name: &str) -> Option<Self> {
		Self::names(name).then(|| Self(name.to_owned()))
	}

	/// Whether `name` is a trust domain.
	fn names(name: &str) -> bool {
		let charset = name
			.bytes()
			.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_'));
		!name.is_empty() && charset
	}

	/// Whether `id` names a workload of this trust domain.
	pub(crate) fn holds(&self, id: &SpiffeId) -> bool {
		id.trust_domain() == self.0
	}

	/// The name of the trust domain.
	pub(crate) fn as_str(&self) -> &str {
		&self.0
	}
}

/// The SPIFFE ID of a workload: `spiffe://`, a [`TrustDomain`], and a path of
/// one or more segments. Each segment is ASCII letters, digits, `.`, `-`, and
/// `_`, and is neither `.` nor `..`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SpiffeId {
	id: String,
	/// The index of the end of the trust domain.
	domain_end: usize,
}

impl SpiffeId {
	/// The SPIFFE ID of the workload that `text` names, or `None` off the
	/// grammar of a workload ID.
	pub(crate) fn parse(text: &str) -> Option<Self> {
		let rest = text.strip_prefix(SPIFFE_SCHEME).filter(|_| text.len() <= MAX_ID)?;
		let (domain, path) = rest.split_once('/')?;
		let named = TrustDomain::names(domain) && path.split('/').all(Self::is_segment);
		named.then(|| Self { id: text.to_owned(), domain_end: SPIFFE_SCHEME.len() + domain.len() })
	}

	/// Whether `segment` is one segment of the path of a workload ID.
	fn is_segment(segment: &str) -> bool {
		let charset = segment
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
		!segment.is_empty() && charset && segment != "." && segment != ".."
	}

	/// The trust domain, such as `acme`.
	pub(crate) fn trust_domain(&self) -> &str {
		&self.id[SPIFFE_SCHEME.len()..self.domain_end]
	}

	/// The ID as its certificate or its token carries it.
	pub(crate) fn as_str(&self) -> &str {
		&self.id
	}
}

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
/// assert!(Principal::spiffe("spiffe://acme").is_err());
/// # Ok::<(), tightbeam_grpc::couple::CoupleError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal(Named);

/// The one name of a principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Named {
	/// The SPIFFE ID of a certificate that carries one.
	Spiffe(SpiffeId),
	/// The subject of a certificate that carries no SPIFFE ID, in the one
	/// form that [`Named::subject`] builds.
	Subject(Name),
}

impl Named {
	/// The subject `name` as `Name::from_str` parses its RFC 4514 string, so
	/// two subjects of one string are equal whatever string type their
	/// issuer encoded. `None` when that string does not parse back.
	fn subject(name: &Name) -> Option<Self> {
		Name::from_str(&name.to_string()).ok().map(Self::Subject)
	}
}

impl Principal {
	/// The principal of the SPIFFE ID `id` of a workload, such as
	/// `spiffe://acme/billing`.
	///
	/// # Errors
	///
	/// - [`CoupleError::Principal`] -- `id` is no SPIFFE ID of a workload: it
	///   names no trust domain, or no path.
	pub fn spiffe(id: &str) -> Result<Self, CoupleError> {
		let parsed = SpiffeId::parse(id).ok_or_else(|| CoupleError::Principal(id.to_owned()))?;
		Ok(Self(Named::Spiffe(parsed)))
	}

	/// The principal of the subject `dn`, a distinguished name in the string
	/// form of RFC 4514, such as `CN=web,O=acme`.
	///
	/// # Errors
	///
	/// - [`CoupleError::Principal`] -- `dn` is no distinguished name.
	pub fn subject(dn: &str) -> Result<Self, CoupleError> {
		let named = Name::from_str(dn).ok().and_then(|name| Named::subject(&name));
		named.map(Self).ok_or_else(|| CoupleError::Principal(dn.to_owned()))
	}

	/// The principal of a SPIFFE ID that its trust verified, such as the
	/// subject of a bearer token.
	pub(crate) fn of_spiffe(id: SpiffeId) -> Self {
		Self(Named::Spiffe(id))
	}

	/// The one name of the principal.
	pub(super) fn named(&self) -> &Named {
		&self.0
	}

	/// The principal that `certificate` names: its one SPIFFE ID, or else its
	/// subject.
	///
	/// `None` when the certificate carries two SPIFFE IDs, one that names no
	/// workload, or a subject alternative name that does not decode.
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
						ids.push(SpiffeId::parse(uri)?);
					}
				}
			}
		}

		let mut ids = ids.into_iter();
		match (ids.next(), ids.next()) {
			(None, _) => Named::subject(&tbs.subject).map(Self),
			(Some(id), None) => Some(Self(Named::Spiffe(id))),
			(Some(_), Some(_)) => None,
		}
	}
}

/// Equal principals print the same SPIFFE ID or the same RFC 4514 string, so
/// the hash of that text agrees with the equality of the principals.
impl Hash for Principal {
	fn hash<H: Hasher>(&self, state: &mut H) {
		core::mem::discriminant(&self.0).hash(state);
		self.to_string().hash(state);
	}
}

/// The SPIFFE ID, or the subject in the string form of RFC 4514.
impl fmt::Display for Named {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Spiffe(id) => f.write_str(id.as_str()),
			Self::Subject(name) => write!(f, "{name}"),
		}
	}
}

/// The text of the one name of the principal.
impl fmt::Display for Principal {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.0.fmt(f)
	}
}

/// An encoded SPIFFE ID passes the one parse of `SpiffeId`, and an encoded
/// subject takes the one form of `Named::subject`.
///
/// # Errors
///
/// - [`CoupleError::Principal`] -- the SPIFFE ID names no workload, or the
///   subject does not parse back from its string.
impl TryFrom<PrincipalWire> for Principal {
	type Error = CoupleError;

	fn try_from(wire: PrincipalWire) -> Result<Self, Self::Error> {
		match wire {
			PrincipalWire::Spiffe(id) => Self::spiffe(&id),
			PrincipalWire::Subject(name) => Named::subject(&name)
				.map(Self)
				.ok_or_else(|| CoupleError::Principal(name.to_string())),
		}
	}
}

/// The SHA-256 of the DER of a TLS client certificate, which a claim binds to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LeafDigest([u8; 32]);

impl LeafDigest {
	/// The digest of the DER `leaf`.
	pub(crate) fn of(leaf: &[u8]) -> Self {
		Self(Sha256::digest(leaf).into())
	}

	pub(crate) fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// What a verified TLS client certificate names: its principal, and the
/// digest of its DER.
#[derive(Debug)]
pub(crate) struct TlsIdentity {
	principal: Principal,
	leaf: LeafDigest,
}

impl TlsIdentity {
	/// The identity of the verified client certificate `leaf`, or `None` when
	/// the certificate does not parse or names no principal.
	pub(crate) fn of(leaf: &CertificateDer<'_>) -> Option<Self> {
		let certificate = Certificate::from_der(leaf.as_ref()).ok()?;
		let principal = Principal::of(&certificate)?;
		Some(Self { principal, leaf: LeafDigest::of(leaf.as_ref()) })
	}

	pub(crate) fn principal(&self) -> &Principal {
		&self.principal
	}

	pub(crate) fn leaf(&self) -> &LeafDigest {
		&self.leaf
	}
}

#[cfg(test)]
mod tests {
	use core::time::Duration;
	use std::collections::HashSet;

	use super::*;
	use crate::testing::TlsAuthority;

	tightbeam::tb_cases! {
		fn a_spiffe_id_off_the_grammar_names_no_principal(id: &str) {
			assert!(Principal::spiffe(id).is_err());
		}

		cases {
			no_trust_domain => "spiffe:///orders",
			another_scheme => "https://acme/orders",
			only_the_scheme => "spiffe://",
			only_a_trust_domain => "spiffe://acme",
			a_trust_domain_and_a_slash => "spiffe://acme/",
		}
	}

	tightbeam::tb_cases! {
		fn a_workload_id_off_its_path_grammar_names_no_principal(id: &str) {
			assert!(Principal::spiffe(id).is_err());
		}

		cases {
			an_empty_segment => "spiffe://acme/orders//edge",
			a_trailing_slash => "spiffe://acme/orders/",
			a_dot_segment => "spiffe://acme/./orders",
			a_dot_dot_segment => "spiffe://acme/../orders",
			a_percent_escape => "spiffe://acme/orders%20",
			a_query => "spiffe://acme/orders?edge",
			an_uppercase_trust_domain => "spiffe://Acme/orders",
			a_port => "spiffe://acme:443/orders",
		}
	}

	#[test]
	fn a_workload_id_names_its_trust_domain() {
		let parsed = SpiffeId::parse("spiffe://acme/orders/edge");
		let domain = TrustDomain::parse("acme");
		assert!(parsed.is_some_and(|id| domain.is_some_and(|domain| domain.holds(&id))));
	}

	#[test]
	fn a_principal_reads_back_from_its_encoded_form() -> Result<(), CoupleError> {
		let billing = Principal::spiffe("spiffe://acme/billing")?;
		assert_eq!(Principal::try_from(PrincipalWire::from(billing.named()))?, billing);
		Ok(())
	}

	/// `CN=web,O=acme` with each value a PrintableString, as Go x509 encodes
	/// a subject, in the hex form of RFC 4514.
	const PRINTABLE_SUBJECT: &str = "CN=#1303776562,O=#130461636d65";

	#[test]
	fn a_printable_subject_names_the_principal_of_its_string_form() -> Result<(), Box<dyn std::error::Error>> {
		let authority = TlsAuthority::mint("CN=test root,O=acme", Duration::from_secs(3600))?;
		let leaf = authority.caller(PRINTABLE_SUBJECT, None)?;
		let granted = HashSet::from([Principal::subject("CN=web,O=acme")?]);
		let identity = TlsIdentity::of(leaf.leaf()).ok_or("the leaf names no principal")?;
		assert!(granted.contains(identity.principal()));
		Ok(())
	}

	#[test]
	fn an_encoded_printable_subject_reads_back_as_its_string_form() -> Result<(), Box<dyn std::error::Error>> {
		let printable = Name::from_str(PRINTABLE_SUBJECT)?;
		let principal = Principal::try_from(PrincipalWire::Subject(printable))?;
		assert_eq!(principal, Principal::subject("CN=web,O=acme")?);
		Ok(())
	}

	#[test]
	fn a_hex_subject_names_the_principal_of_its_string_form() -> Result<(), CoupleError> {
		assert_eq!(Principal::subject(PRINTABLE_SUBJECT)?, Principal::subject("CN=web,O=acme")?);
		Ok(())
	}
}
