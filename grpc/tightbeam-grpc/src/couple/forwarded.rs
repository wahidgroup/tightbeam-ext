//! Callers behind a TLS-terminating proxy: the client chain that a pinned
//! proxy forwards in `x-forwarded-client-cert` (XFCC), under the strict
//! grammar of Envoy.
//!
//! # Sources
//!
//! - Envoy, `x-forwarded-client-cert`:
//!   <https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert>
//! - RFC 3986, URI, January 2005, section 2.1: <https://www.rfc-editor.org/rfc/rfc3986#section-2.1>

use http::HeaderMap;
use rustls::server::danger::ClientCertVerifier;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, UnixTime};

use super::principal::TlsIdentity;

/// One key of an element of the Envoy grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XfccKey {
	By,
	Hash,
	Cert,
	Chain,
	Subject,
	Uri,
	Dns,
}

impl XfccKey {
	/// The key that `text` spells, or `None` for a key outside the grammar.
	fn parse(text: &str) -> Option<Self> {
		match text {
			"By" => Some(Self::By),
			"Hash" => Some(Self::Hash),
			"Cert" => Some(Self::Cert),
			"Chain" => Some(Self::Chain),
			"Subject" => Some(Self::Subject),
			"URI" => Some(Self::Uri),
			"DNS" => Some(Self::Dns),
			_ => None,
		}
	}

	/// Whether one element may carry the key more than once.
	fn repeats(self) -> bool {
		match self {
			Self::By | Self::Uri | Self::Dns => true,
			Self::Hash | Self::Cert | Self::Chain | Self::Subject => false,
		}
	}
}

/// The certificate fields of one element, still percent-encoded, and the
/// keys it has taken.
#[derive(Default)]
struct Element {
	cert: Option<String>,
	chain: Option<String>,
	seen: Vec<XfccKey>,
}

impl Element {
	/// Take `value` under `key`.
	///
	/// `None` for a key outside the grammar, or one that repeats where it may
	/// not.
	fn take(&mut self, key: &str, value: String) -> Option<()> {
		let key = XfccKey::parse(key)?;
		if !key.repeats() && self.seen.contains(&key) {
			return None;
		}

		self.seen.push(key);
		match key {
			XfccKey::Cert => self.cert = Some(value),
			XfccKey::Chain => self.chain = Some(value),
			XfccKey::By | XfccKey::Hash | XfccKey::Subject | XfccKey::Uri | XfccKey::Dns => {}
		}
		Some(())
	}
}

/// The client chain that the XFCC field of a call forwards: the leaf, and the
/// issuers after it. Only [`ForwardedChain::verify`] reads it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ForwardedChain {
	leaf: CertificateDer<'static>,
	intermediates: Vec<CertificateDer<'static>>,
}

impl ForwardedChain {
	/// The metadata key of the forwarded client chain.
	pub(crate) const HEADER: &'static str = "x-forwarded-client-cert";

	/// The chain that the one XFCC field of `headers` forwards, in its last
	/// element, the one that the nearest proxy appended: its `Chain`, or else
	/// its `Cert` alone. It is `None` in each of these cases:
	///
	/// - The headers carry two fields, or an element off the grammar.
	/// - The last element forwards no certificate, or one that does not decode.
	/// - A `Cert` holds more than one certificate, or a `Chain` has a leaf other than its `Cert`.
	pub(crate) fn of(headers: &HeaderMap) -> Option<Self> {
		let mut fields = headers.get_all(Self::HEADER).iter();
		let field = fields.next()?;
		if fields.next().is_some() {
			return None;
		}

		let mut elements = Self::elements(field.to_str().ok()?)?;
		let last = elements.pop()?;
		let cert = match last.cert {
			Some(cert) => {
				let [leaf] = <[_; 1]>::try_from(Self::certificates(&cert)?).ok()?;
				Some(leaf)
			}
			None => None,
		};

		let Some(chain) = last.chain else {
			return Some(Self { leaf: cert?, intermediates: Vec::new() });
		};

		let mut chain = Self::certificates(&chain)?.into_iter();
		let leaf = chain.next()?;
		if cert.is_some_and(|cert| cert != leaf) {
			return None;
		}

		Some(Self { leaf, intermediates: chain.collect() })
	}

	/// What the chain names, once `verifier` verifies it now as it verifies
	/// the client chain of a connection.
	pub(crate) fn verify(&self, verifier: &dyn ClientCertVerifier) -> Option<TlsIdentity> {
		let verified = verifier.verify_client_cert(&self.leaf, &self.intermediates, UnixTime::now());
		verified.ok()?;
		TlsIdentity::of(&self.leaf)
	}

	/// The certificates of the percent-encoded PEM `value`.
	fn certificates(value: &str) -> Option<Vec<CertificateDer<'static>>> {
		let pem = Self::percent_decoded(value)?;
		CertificateDer::pem_slice_iter(&pem).collect::<Result<Vec<_>, _>>().ok()
	}

	/// Every element of `value`: `key=value` pairs that `;` joins, in elements
	/// that `,` joins. A value is a token with no `"`, or one whole quoted
	/// string, and a separator or the end follows it.
	fn elements(value: &str) -> Option<Vec<Element>> {
		let mut elements = vec![Element::default()];
		let mut rest = value;
		loop {
			let (key, after) = rest.trim_start().split_once('=')?;
			let (value, after) = Self::value(after)?;
			elements.last_mut()?.take(key, value)?;

			let mut separated = after.chars();
			match separated.next() {
				None => return Some(elements),
				Some(';') => {}
				Some(',') => elements.push(Element::default()),
				Some(_) => return None,
			}
			rest = separated.as_str();
		}
	}

	/// The value at the head of `text`, and the text after it.
	fn value(text: &str) -> Option<(String, &str)> {
		let Some(quoted) = text.strip_prefix('"') else {
			let end = text.find([';', ',']).unwrap_or(text.len());
			let (token, after) = text.split_at(end);
			return (!token.contains('"')).then(|| (token.to_owned(), after));
		};

		let mut value = String::new();
		let mut characters = quoted.char_indices();
		while let Some((index, character)) = characters.next() {
			match character {
				'"' => return Some((value, &quoted[index + 1..])),
				'\\' => value.push(characters.next()?.1),
				character => value.push(character),
			}
		}

		None
	}

	/// The bytes of the percent-encoded `value`, whose every `%` precedes
	/// two hex digits.
	fn percent_decoded(value: &str) -> Option<Vec<u8>> {
		let bytes = value.as_bytes();
		let mut decoded = Vec::with_capacity(bytes.len());
		let mut index = 0;
		while let Some(&byte) = bytes.get(index) {
			if byte != b'%' {
				decoded.push(byte);
				index += 1;
				continue;
			}

			let hex = bytes
				.get(index + 1..index + 3)
				.filter(|hex| hex.iter().all(u8::is_ascii_hexdigit))?;
			let hex = core::str::from_utf8(hex).ok()?;
			decoded.push(u8::from_str_radix(hex, 16).ok()?);
			index += 3;
		}

		Some(decoded)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use base64::engine::general_purpose::STANDARD;
	use base64::Engine;
	use http::HeaderValue;

	/// The DER of the forwarded leaf, of its issuer, and of the leaf of an
	/// element that a proxy appended before the nearest one.
	const LEAF: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x01];
	const ISSUER: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x02];
	const EARLIER: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x03];

	/// What a field forwards: the leaf and the issuers, as DER.
	type Forwarded = Option<(Vec<u8>, Vec<Vec<u8>>)>;

	/// A PEM block of `der`, percent-encoded as Envoy forwards it.
	fn encoded(der: &[u8]) -> String {
		let block = format!(
			"-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
			STANDARD.encode(der)
		);
		block
			.bytes()
			.map(|byte| match byte {
				b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => char::from(byte).to_string(),
				byte => format!("%{byte:02X}"),
			})
			.collect()
	}

	/// The chain that one XFCC field for each of `fields` forwards.
	fn forwarded(fields: &[String]) -> Forwarded {
		let mut headers = HeaderMap::new();
		for field in fields {
			headers.append(
				ForwardedChain::HEADER,
				HeaderValue::from_str(field).expect("a test field is a header value"),
			);
		}

		let chain = ForwardedChain::of(&headers)?;
		let issuers = chain.intermediates.iter().map(|issuer| issuer.as_ref().to_vec()).collect();
		Some((chain.leaf.as_ref().to_vec(), issuers))
	}

	tightbeam::tb_cases! {
		fn the_last_element_forwards_its_chain((fields, expected): (Vec<String>, Forwarded)) {
			assert_eq!(forwarded(&fields), expected);
		}

		cases {
			a_cert_alone => (
				vec![format!("Hash=ab;Cert={}", encoded(&LEAF))],
				Some((LEAF.to_vec(), Vec::new()))
			),
			a_chain_with_its_issuer => (
				vec![format!(r#"By=spiffe://acme/proxy;Chain="{}{}""#, encoded(&LEAF), encoded(&ISSUER))],
				Some((LEAF.to_vec(), vec![ISSUER.to_vec()]))
			),
			a_chain_and_its_leaf_as_cert => (
				vec![format!(r#"Cert="{}";Chain="{}{}""#, encoded(&LEAF), encoded(&LEAF), encoded(&ISSUER))],
				Some((LEAF.to_vec(), vec![ISSUER.to_vec()]))
			),
			the_element_the_nearest_proxy_appended => (
				vec![format!(
					r#"By=spiffe://acme/edge;Cert="{}",By=spiffe://acme/proxy;Subject="CN=web,O=acme";Cert="{}""#,
					encoded(&EARLIER),
					encoded(&LEAF)
				)],
				Some((LEAF.to_vec(), Vec::new()))
			),
			repeated_uri_and_dns => (
				vec![format!("URI=spiffe://a;URI=spiffe://b;DNS=a;DNS=b;Cert={}", encoded(&LEAF))],
				Some((LEAF.to_vec(), Vec::new()))
			),
		}
	}

	tightbeam::tb_cases! {
		fn a_field_off_the_grammar_forwards_nothing(fields: Vec<String>) {
			assert_eq!(forwarded(&fields), None);
		}

		cases {
			an_injected_quote_that_swallows_the_proxy_element => vec![format!(
				r#"Cert="{}";Subject=",By=spiffe://acme/proxy;Cert="{}""#,
				encoded(&EARLIER),
				encoded(&LEAF)
			)],
			an_unknown_key => vec![format!("Note=x;Cert={}", encoded(&LEAF))],
			a_repeated_cert => vec![format!("Cert={};Cert={}", encoded(&EARLIER), encoded(&LEAF))],
			text_after_a_quoted_value => vec![format!(r#"Cert="{}"x"#, encoded(&LEAF))],
			a_quote_inside_a_token => vec![format!("Cert=a\"{}", encoded(&LEAF))],
			an_unterminated_quote => vec!["Cert=\"%2D%2D".to_owned()],
			a_broken_percent_escape => vec!["Cert=%ZZ".to_owned()],
			a_signed_percent_escape => vec![format!("Cert={}", encoded(&LEAF).replace("%0A", "%+A"))],
			no_certificate_in_the_last_element => vec![format!("Cert={},By=spiffe://acme/proxy", encoded(&LEAF))],
			two_fields => vec![format!("Cert={}", encoded(&EARLIER)), format!("Cert={}", encoded(&LEAF))],
			a_cert_of_two_certificates => vec![format!(r#"Cert="{}{}""#, encoded(&LEAF), encoded(&ISSUER))],
			a_cert_of_no_certificate => vec!["Cert=".to_owned()],
			a_chain_whose_leaf_is_not_its_cert => vec![format!(
				r#"Cert="{}";Chain="{}{}""#,
				encoded(&EARLIER),
				encoded(&LEAF),
				encoded(&ISSUER)
			)],
		}
	}
}
