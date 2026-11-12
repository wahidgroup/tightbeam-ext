//! Why a coupler, a backend, or a coupled call refuses what it is built from.

use core::convert::Infallible;
use core::fmt;

/// Why a coupler, a backend, or a coupled call refuses its configuration.
#[derive(Debug)]
pub enum CoupleError {
	/// A key set of bearer trust that does not parse, with the error of its
	/// JSON, or that holds no ES256 key with a key ID, with none.
	BearerKeys(Option<serde_json::Error>),
	/// A gRPC-Web origin with no scheme or one other than `http` or `https`, a
	/// path, a query, a fragment, a user or a `*`, no host, a port that is no
	/// number up to 65535, or an authority that does not parse, such as a host
	/// with a space, a `%`, or a byte outside ASCII.
	Origin(String),
	/// Reflection descriptors that do not decode or do not resolve.
	Reflection(Box<dyn std::error::Error + Send + Sync>),
	/// A coupler or a backend that routes no method.
	NoRoute,
	/// A principal or a trust domain off its grammar.
	Principal(String),
	/// A method that is no gRPC path, that a route names twice, that a
	/// reserved path takes, or that a grant names and no route serves.
	Method(String),
	/// A metadata key that a call may not carry, a key named twice, or a value
	/// that its key does not admit.
	Metadata(String),
	/// A body or a value of a coupled call passes the length of a DER octet
	/// string.
	Encoding(tightbeam::der::Error),
	/// Call limits of fewer than 2 streams, which leave a streaming route no
	/// stream beside the unary calls.
	Streams,
}

impl fmt::Display for CoupleError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::BearerKeys(Some(error)) => write!(f, "the bearer key set does not parse: {error}"),
			Self::BearerKeys(None) => f.write_str("the bearer key set holds no ES256 key with a key ID"),
			Self::Origin(origin) => write!(f, "`{origin}` is no origin a gRPC-Web edge serves"),
			Self::Reflection(error) => write!(f, "the reflection descriptors do not resolve: {error}"),
			Self::NoRoute => f.write_str("the coupler routes no method"),
			Self::Principal(text) => write!(f, "`{text}` names no SPIFFE ID, trust domain, or distinguished name"),
			Self::Method(method) => write!(f, "`{method}` is no method a coupled edge can route"),
			Self::Metadata(key) => write!(f, "`{key}` is no metadata a coupled call can carry"),
			Self::Encoding(error) => write!(f, "a coupled call does not encode: {error}"),
			Self::Streams => f.write_str("a streaming route needs call limits of 2 streams or more"),
		}
	}
}

impl std::error::Error for CoupleError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::BearerKeys(error) => error.as_ref().map(|error| error as _),
			Self::Reflection(error) => Some(&**error),
			Self::Encoding(error) => Some(error),
			Self::Origin(_)
			| Self::NoRoute
			| Self::Principal(_)
			| Self::Method(_)
			| Self::Metadata(_)
			| Self::Streams => None,
		}
	}
}

/// An infallible conversion, such as that of a
/// [`MethodPath`](super::MethodPath) to itself, is no error of a coupler.
impl From<Infallible> for CoupleError {
	fn from(never: Infallible) -> Self {
		match never {}
	}
}
