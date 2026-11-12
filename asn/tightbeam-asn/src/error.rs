//! The failure of a conversion between a JavaScript value and a DER type.

use alloc::format;
use alloc::string::{String, ToString};
use core::fmt;

/// A value that does not fit its DER type, named by its path in the message.
///
/// The path reads as a TypeScript access, such as `records[1].subject`, and is
/// empty when the failure is the value handed to the codec itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldError {
	path: String,
	expected: &'static str,
	cause: Option<der::Error>,
}

impl FieldError {
	/// A value that is not `expected`.
	#[doc(hidden)]
	#[must_use]
	pub fn new(expected: &'static str) -> Self {
		Self { path: String::new(), expected, cause: None }
	}

	/// A value that der refused as `expected`.
	#[doc(hidden)]
	#[must_use]
	pub fn refused(expected: &'static str, cause: der::Error) -> Self {
		Self { path: String::new(), expected, cause: Some(cause) }
	}

	/// This failure, one field deeper in the message.
	#[doc(hidden)]
	#[must_use]
	pub fn within(self, key: &str) -> Self {
		self.prefixed(key.to_string())
	}

	/// This failure, at `index` of a collection.
	#[doc(hidden)]
	#[must_use]
	pub fn at(self, index: u32) -> Self {
		self.prefixed(format!("[{index}]"))
	}

	fn prefixed(mut self, head: String) -> Self {
		self.path = match self.path.chars().next() {
			None | Some('[') => format!("{head}{}", self.path),
			Some(_) => format!("{head}.{}", self.path),
		};

		self
	}
}

impl From<der::Error> for FieldError {
	fn from(cause: der::Error) -> Self {
		Self::refused("a value der accepts", cause)
	}
}

impl fmt::Display for FieldError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		if !self.path.is_empty() {
			write!(f, "{}: ", self.path)?;
		}

		write!(f, "expected {}", self.expected)?;

		match &self.cause {
			Some(cause) => write!(f, " ({cause})"),
			None => Ok(()),
		}
	}
}

impl core::error::Error for FieldError {}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_path_reads_as_a_typescript_access() {
		let at_subject = FieldError::new("a string").within("subject");
		let in_record = at_subject.at(1).within("records");
		let error = in_record.within("result");
		assert_eq!(error.to_string(), "result.records[1].subject: expected a string");
	}

	#[test]
	fn a_top_level_failure_has_no_path() {
		assert_eq!(FieldError::new("an object").to_string(), "expected an object");
	}

	#[test]
	fn a_nested_collection_keeps_each_index() {
		let error = FieldError::new("a number").at(2).at(0).within("grid");
		assert_eq!(error.to_string(), "grid[0][2]: expected a number");
	}

	#[test]
	fn a_der_refusal_keeps_its_cause() {
		let cause = der::Error::from(der::ErrorKind::Overflow);
		let error = FieldError::from(cause).within("triple");
		assert_eq!(error.to_string(), format!("triple: expected a value der accepts ({cause})"));
	}
}
