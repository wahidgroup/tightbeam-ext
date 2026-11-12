//! The metadata that a call carries to its servlet, and that a backend
//! adapter sends on to its server.
//!
//! # Sources
//!
//! - gRPC over HTTP2, `grpc/grpc` `doc/PROTOCOL-HTTP2.md`:
//!   <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md>
//! - RFC 9113, HTTP/2, June 2022, section 8.2.2: <https://www.rfc-editor.org/rfc/rfc9113>

use tonic::metadata::{AsciiMetadataKey, AsciiMetadataValue, BinaryMetadataKey, BinaryMetadataValue, MetadataMap};

use super::admit::Origin;
use super::claim::CallClaim;
use super::error::CoupleError;
use super::message::MetadataEntry;
use super::trust::CallerTrust;

/// The keys that only HTTP/2 or the gRPC protocol itself may set.
const RESERVED: [&str; 8] = [
	"connection",
	"content-type",
	"host",
	"keep-alive",
	"proxy-connection",
	"te",
	"transfer-encoding",
	"upgrade",
];

/// The keys that the edge and a backend stamp on a call themselves.
const STAMPED: [&str; 2] = [Origin::PRINCIPAL_KEY, CallClaim::METADATA_KEY];

/// A metadata key that a call may carry: lowercase ASCII letters, digits, `-`,
/// `_`, and `.`, and no key of gRPC, of HTTP/2, that the edge stamps, or of a
/// credential that names the caller to the edge. A key that ends in `-bin`
/// carries a binary value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MetadataKey {
	Ascii(AsciiMetadataKey),
	Binary(BinaryMetadataKey),
}

impl MetadataKey {
	/// The parsed form of `key`, ASCII or binary by its `-bin` suffix.
	///
	/// # Errors
	///
	/// - [`CoupleError::Metadata`] -- `key` is no key that a call may carry.
	pub(crate) fn new(key: &str) -> Result<Self, CoupleError> {
		let refused = || CoupleError::Metadata(key.to_owned());
		let charset = key
			.bytes()
			.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'));
		let protocol = key.starts_with("grpc-") || RESERVED.contains(&key) || STAMPED.contains(&key);
		let reserved = protocol || CallerTrust::CREDENTIAL_HEADERS.contains(&key);
		if key.is_empty() || !charset || reserved {
			return Err(refused());
		}

		let bytes = key.as_bytes();
		if key.ends_with("-bin") {
			let binary = BinaryMetadataKey::from_bytes(bytes).map_err(|_| refused())?;
			return Ok(Self::Binary(binary));
		}

		let ascii = AsciiMetadataKey::from_bytes(bytes).map_err(|_| refused())?;
		Ok(Self::Ascii(ascii))
	}

	/// The key as it travels.
	pub(crate) fn as_str(&self) -> &str {
		match self {
			Self::Ascii(key) => key.as_str(),
			Self::Binary(key) => key.as_str(),
		}
	}

	/// The entry of this key with `value`.
	///
	/// # Errors
	///
	/// - [`CoupleError::Metadata`] -- the key is ASCII and `value` holds a byte
	///   outside visible ASCII and space.
	pub(crate) fn pair(&self, value: Vec<u8>) -> Result<MetadataPair, CoupleError> {
		match self {
			Self::Ascii(key) => {
				let refused = || CoupleError::Metadata(key.as_str().to_owned());
				let printable = value.iter().all(|byte| (0x20..=0x7e).contains(byte));
				if !printable {
					return Err(refused());
				}

				let value = AsciiMetadataValue::try_from(value.as_slice()).map_err(|_| refused())?;
				Ok(MetadataPair::Ascii(key.clone(), value))
			}
			Self::Binary(key) => Ok(MetadataPair::Binary(key.clone(), value)),
		}
	}

	/// Each value of `map` under this key, as an entry, with a binary value
	/// decoded from base64.
	///
	/// # Errors
	///
	/// - [`CoupleError::Metadata`] -- a value does not decode, or holds a byte
	///   that the key does not admit.
	pub(crate) fn values(&self, map: &MetadataMap) -> Result<Vec<MetadataPair>, CoupleError> {
		match self {
			Self::Ascii(ascii) => {
				let values = map.get_all(ascii.as_str()).iter();
				values.map(|value| self.pair(value.as_bytes().to_vec())).collect()
			}
			Self::Binary(binary) => {
				let refused = || CoupleError::Metadata(binary.as_str().to_owned());
				let values = map.get_all_bin(binary.as_str()).iter();
				values
					.map(|value| self.pair(value.to_bytes().map_err(|_| refused())?.to_vec()))
					.collect()
			}
		}
	}
}

/// One metadata entry of a call, under a key that [`MetadataKey`] admits.
#[derive(Clone, Debug)]
pub(crate) enum MetadataPair {
	Ascii(AsciiMetadataKey, AsciiMetadataValue),
	Binary(BinaryMetadataKey, Vec<u8>),
}

impl MetadataPair {
	/// The key of the entry, and its value, decoded for a binary key.
	pub(crate) fn metadata(&self) -> Metadata<'_> {
		match self {
			Self::Ascii(key, value) => Metadata { key: key.as_str(), value: value.as_bytes() },
			Self::Binary(key, value) => Metadata { key: key.as_str(), value },
		}
	}

	fn append_to(&self, map: &mut MetadataMap) {
		match self {
			Self::Ascii(key, value) => {
				map.append(key.clone(), value.clone());
			}
			Self::Binary(key, value) => {
				map.append_bin(key.clone(), BinaryMetadataValue::from_bytes(value));
			}
		}
	}
}

/// One metadata entry of a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata<'a> {
	/// The key of the entry.
	pub key: &'a str,
	/// The value of the entry, decoded for a key that ends in `-bin`.
	pub value: &'a [u8],
}

/// The metadata entries of one call: by the order of the forwarded keys, each
/// key's values in the order the caller sent them, as an edge reads them, or
/// in the order of the entries of the frame, as a servlet admits them.
#[derive(Clone, Debug)]
pub(crate) struct CallMetadata(Vec<MetadataPair>);

impl CallMetadata {
	/// Each value of `map`, the metadata of a call head, under `keys`, as a
	/// coupled edge reads them, with each binary value decoded from base64.
	///
	/// # Errors
	///
	/// - The errors of [`MetadataKey::values`].
	pub(crate) fn read(keys: &[MetadataKey], map: &MetadataMap) -> Result<Self, CoupleError> {
		let mut pairs = Vec::new();
		for key in keys {
			pairs.extend(key.values(map)?);
		}

		Ok(Self(pairs))
	}

	/// The encoded entries of a call, each admitted again under
	/// [`MetadataKey`].
	///
	/// # Errors
	///
	/// - [`CoupleError::Metadata`] -- an entry holds a key or a value that a
	///   call may not carry.
	pub(crate) fn admit(entries: Option<Vec<MetadataEntry>>) -> Result<Self, CoupleError> {
		let mut pairs = Vec::new();
		for entry in entries.unwrap_or_default() {
			let key = MetadataKey::new(&entry.key)?;
			pairs.push(key.pair(entry.value.into_bytes())?);
		}

		Ok(Self(pairs))
	}

	/// Each entry, in order.
	pub(crate) fn iter(&self) -> impl Iterator<Item = Metadata<'_>> {
		self.0.iter().map(MetadataPair::metadata)
	}

	/// Append each entry to `map`, the metadata of a call that a backend
	/// adapter makes.
	pub(crate) fn append_to(&self, map: &mut MetadataMap) {
		for pair in &self.0 {
			pair.append_to(map);
		}
	}
}

#[cfg(test)]
mod tests {
	use http::HeaderMap;

	use super::*;

	tightbeam::tb_cases! {
		fn a_key_of_grpc_tightbeam_or_http2_is_refused(key: &str) {
			assert!(MetadataKey::new(key).is_err());
		}

		cases {
			a_grpc_key => "grpc-timeout",
			the_principal_key => "tightbeam-principal-bin",
			the_claim_key => "tightbeam-claim-bin",
			a_connection_header => "te",
			the_host => "host",
			the_authorization => "authorization",
			a_forwarded_chain => "x-forwarded-client-cert",
			an_uppercase_key => "Traceparent",
			an_empty_key => "",
			a_space => "a b",
			a_pseudo_header => ":path",
		}
	}

	tightbeam::tb_cases! {
		fn a_key_of_the_caller_is_admitted(key: &str) {
			assert!(MetadataKey::new(key).is_ok());
		}

		cases {
			a_trace_context => "traceparent",
			a_request_id => "x-request-id",
			a_binary_key => "x-tenant-bin",
			baggage => "baggage",
			dots_and_underscores => "a.b_c",
			another_tightbeam_key => "tightbeam-tenant",
		}
	}

	tightbeam::tb_cases! {
		fn a_value_pairs_with_its_key((key, value, admits): (&str, Vec<u8>, bool)) -> Result<(), CoupleError> {
			let key = MetadataKey::new(key)?;
			assert_eq!(key.pair(value).is_ok(), admits);
			Ok(())
		}

		cases {
			an_ascii_value_outside_visible_ascii => ("traceparent", vec![0x80], false),
			a_visible_ascii_value => ("traceparent", b"00-ab".to_vec(), true),
			any_binary_value => ("x-tenant-bin", vec![0x00, 0xff], true),
		}
	}

	#[test]
	fn every_value_of_a_repeated_key_is_read_in_order() -> Result<(), CoupleError> {
		let mut headers = HeaderMap::new();
		headers.append("baggage", "a=1".parse().map_err(|_| CoupleError::Metadata(String::new()))?);
		headers.append("baggage", "b=2".parse().map_err(|_| CoupleError::Metadata(String::new()))?);
		headers.append("x-other", "skipped".parse().map_err(|_| CoupleError::Metadata(String::new()))?);

		let keys = [MetadataKey::new("baggage")?];
		let read = CallMetadata::read(&keys, &MetadataMap::from_headers(headers))?;
		let values: Vec<Metadata<'_>> = read.iter().collect();
		let first = Metadata { key: "baggage", value: b"a=1" };
		assert_eq!(values, [first, Metadata { key: "baggage", value: b"b=2" }]);
		Ok(())
	}

	#[test]
	fn a_binary_value_that_does_not_decode_is_refused() -> Result<(), CoupleError> {
		let mut headers = HeaderMap::new();
		headers.insert("x-tenant-bin", "!!!".parse().map_err(|_| CoupleError::Metadata(String::new()))?);

		let keys = [MetadataKey::new("x-tenant-bin")?];
		assert!(CallMetadata::read(&keys, &MetadataMap::from_headers(headers)).is_err());
		Ok(())
	}

	#[test]
	fn the_encoded_entries_admit_back_to_the_same_entries() -> Result<(), CoupleError> {
		let mut headers = HeaderMap::new();
		headers.insert(
			"traceparent",
			"00-ab".parse().map_err(|_| CoupleError::Metadata(String::new()))?,
		);
		headers.insert(
			"x-tenant-bin",
			"AP8=".parse().map_err(|_| CoupleError::Metadata(String::new()))?,
		);

		let keys = [MetadataKey::new("traceparent")?, MetadataKey::new("x-tenant-bin")?];
		let read = CallMetadata::read(&keys, &MetadataMap::from_headers(headers))?;
		let entries = read.iter().map(MetadataEntry::try_from).collect::<Result<Vec<_>, _>>()?;
		let admitted = CallMetadata::admit(Some(entries))?;
		let values: Vec<Metadata<'_>> = admitted.iter().collect();
		let trace = Metadata { key: "traceparent", value: b"00-ab" };
		assert_eq!(values, [trace, Metadata { key: "x-tenant-bin", value: &[0x00, 0xff] }]);
		Ok(())
	}
}
