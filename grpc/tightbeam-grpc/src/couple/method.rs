//! The path of one gRPC method, parsed once.
//!
//! # Sources
//!
//! - gRPC over HTTP2, `grpc/grpc` `doc/PROTOCOL-HTTP2.md`:
//!   <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md>

use core::fmt;
use core::str::FromStr;

use http::uri::PathAndQuery;

use super::error::CoupleError;

/// The path of one method of one service, such as `/orders.v1.Orders/Place`:
/// `/`, a service name, `/`, and a method name. Each name is visible ASCII
/// with no `/`, no `?`, and no `#`.
///
/// # Examples
///
/// ```
/// use tightbeam_grpc::couple::MethodPath;
///
/// let place: MethodPath = "/orders.v1.Orders/Place".parse()?;
/// assert_eq!((place.service(), place.name()), ("orders.v1.Orders", "Place"));
/// assert!("/orders.v1.Orders".parse::<MethodPath>().is_err());
/// # Ok::<(), tightbeam_grpc::couple::CoupleError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MethodPath {
	path: PathAndQuery,
	/// The index of the `/` that ends the service name.
	split: usize,
}

impl MethodPath {
	/// The full name of the service, such as `orders.v1.Orders`.
	pub fn service(&self) -> &str {
		&self.as_str()[1..self.split]
	}

	/// The name of the method, such as `Place`.
	pub fn name(&self) -> &str {
		&self.as_str()[self.split + 1..]
	}

	/// The path, as `:path` carries it.
	pub fn as_str(&self) -> &str {
		self.path.as_str()
	}

	/// The path, as a tonic client calls it.
	pub(crate) fn path_and_query(&self) -> PathAndQuery {
		self.path.clone()
	}
}

/// Parses the path of one method.
///
/// # Errors
///
/// - [`CoupleError::Method`] -- the text is not `/`, a service name, `/`, and a method name.
impl TryFrom<&str> for MethodPath {
	type Error = CoupleError;

	fn try_from(text: &str) -> Result<Self, Self::Error> {
		let refused = || CoupleError::Method(text.to_owned());
		let rest = text.strip_prefix('/').ok_or_else(refused)?;
		let (service, method) = rest.split_once('/').ok_or_else(refused)?;

		let visible = text.bytes().all(|byte| byte.is_ascii_graphic() && byte != b'?' && byte != b'#');
		let named = !service.is_empty() && !method.is_empty() && !method.contains('/');
		if !visible || !named {
			return Err(refused());
		}

		let path = PathAndQuery::try_from(text).map_err(|_| refused())?;
		Ok(Self { path, split: service.len() + 1 })
	}
}

impl FromStr for MethodPath {
	type Err = CoupleError;

	fn from_str(text: &str) -> Result<Self, Self::Err> {
		Self::try_from(text)
	}
}

/// The path itself.
impl fmt::Display for MethodPath {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.as_str())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	tightbeam::tb_cases! {
		fn a_path_off_the_grammar_is_refused(path: &str) {
			assert!(MethodPath::try_from(path).is_err());
		}

		cases {
			no_slash => "orders",
			no_method => "/orders",
			an_empty_service => "//Place",
			an_empty_method => "/orders.v1.Orders/",
			a_nested_method => "/a/b/c",
			a_query => "/a.B/C?d",
			a_fragment => "/a#b/C",
			a_fragment_after_the_method => "/a.B/C#d",
			a_space => "/a.B/C D",
		}
	}

	#[test]
	fn a_path_names_its_service_and_its_method() -> Result<(), CoupleError> {
		let path = MethodPath::try_from("/orders.v1.Orders/Place")?;
		assert_eq!(
			(path.service(), path.name(), path.as_str()),
			("orders.v1.Orders", "Place", "/orders.v1.Orders/Place")
		);
		Ok(())
	}
}
