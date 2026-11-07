//! The environment variables that provision the demo stack.
//!
//! Compiled only under the `testing` feature.

use core::error::Error;
use core::fmt;
use core::str::FromStr;
use std::env::{self, VarError};
use std::path::PathBuf;

/// One environment variable of the demo stack, read by name.
///
/// # Examples
///
/// ```
/// use tightbeam_ws::testing::EnvVar;
///
/// let port = EnvVar::new("TBWS_DOC_EXAMPLE_UNSET_PORT").parsed_or(9100u16)?;
/// assert_eq!(port, 9100);
/// # Ok::<(), tightbeam_ws::testing::EnvError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvVar(&'static str);

impl EnvVar {
	/// The variable `name`.
	#[must_use]
	pub const fn new(name: &'static str) -> Self {
		Self(name)
	}

	/// The value of the variable, or `None` when it is unset.
	///
	/// # Errors
	///
	/// - [`EnvError::Unparsed`]: the value is not UTF-8.
	pub fn value(self) -> Result<Option<String>, EnvError> {
		match env::var(self.0) {
			Ok(value) => Ok(Some(value)),
			Err(VarError::NotPresent) => Ok(None),
			Err(VarError::NotUnicode(raw)) => Err(self.unparsed(raw.to_string_lossy().into_owned())),
		}
	}

	/// The value parsed as `T`, or `default` when the variable is unset.
	///
	/// # Errors
	///
	/// - [`EnvError::Unparsed`]: the variable is set, and its value does not
	///   parse as `T`.
	pub fn parsed_or<T: FromStr>(self, default: T) -> Result<T, EnvError> {
		let Some(value) = self.value()? else {
			return Ok(default);
		};

		value.parse().map_err(|_| self.unparsed(value))
	}

	/// The value parsed as `T`, for a variable that the stack always sets.
	///
	/// # Errors
	///
	/// - [`EnvError::Unset`]: the variable is unset.
	/// - [`EnvError::Unparsed`]: the value does not parse as `T`.
	pub fn parsed<T: FromStr>(self) -> Result<T, EnvError> {
		let Some(value) = self.value()? else {
			return Err(EnvError::Unset(self.0));
		};

		value.parse().map_err(|_| self.unparsed(value))
	}

	/// Whether the variable switches its flag on. An unset variable is off.
	///
	/// The words `1`, `true`, `on`, and `yes` are on. An empty value and the
	/// words `0`, `false`, `off`, and `no` are off. Each word compares without
	/// case and surrounding whitespace.
	///
	/// # Errors
	///
	/// - [`EnvError::Unparsed`]: the value is no flag word.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam_ws::testing::EnvVar;
	///
	/// let paywall = EnvVar::new("TBWS_DOC_EXAMPLE_UNSET_FLAG").flag()?;
	/// assert!(!paywall);
	/// # Ok::<(), tightbeam_ws::testing::EnvError>(())
	/// ```
	pub fn flag(self) -> Result<bool, EnvError> {
		let Some(value) = self.value()? else {
			return Ok(false);
		};

		let word = value.trim().to_ascii_lowercase();
		match word.as_str() {
			"1" | "true" | "on" | "yes" => Ok(true),
			"" | "0" | "false" | "off" | "no" => Ok(false),
			_ => Err(self.unparsed(value)),
		}
	}

	/// The path the variable names.
	///
	/// # Errors
	///
	/// - [`EnvError::Unset`]: the variable is unset.
	pub fn path(self) -> Result<PathBuf, EnvError> {
		let value = env::var_os(self.0).ok_or(EnvError::Unset(self.0))?;
		Ok(PathBuf::from(value))
	}

	fn unparsed(self, value: String) -> EnvError {
		EnvError::Unparsed { name: self.0, value }
	}
}

/// Why a demo environment variable gives no value.
///
/// # Examples
///
/// ```
/// use tightbeam_ws::testing::{EnvError, EnvVar};
///
/// let path = EnvVar::new("TBWS_DOC_EXAMPLE_UNSET_PATH").path();
/// assert_eq!(path, Err(EnvError::Unset("TBWS_DOC_EXAMPLE_UNSET_PATH")));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvError {
	/// The variable is unset, and the stack needs it.
	Unset(&'static str),
	/// The variable holds a value that does not parse.
	Unparsed {
		/// The name of the variable.
		name: &'static str,
		/// The value it holds.
		value: String,
	},
}

impl fmt::Display for EnvError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Unset(name) => write!(f, "{name} is not set"),
			Self::Unparsed { name, value } => write!(f, "{name} holds {value:?}, which does not parse"),
		}
	}
}

impl Error for EnvError {}

#[cfg(test)]
mod tests {
	use super::*;

	/// A variable no test sets.
	const UNSET: EnvVar = EnvVar::new("TBWS_TEST_NEVER_SET");

	/// The variable `name`, set to `value`. Each test names its own
	/// variable, so no two tests share one.
	fn set(name: &'static str, value: &str) -> EnvVar {
		env::set_var(name, value);
		EnvVar::new(name)
	}

	#[test]
	fn an_unset_variable_takes_the_default() {
		assert_eq!(UNSET.parsed_or(7u32), Ok(7));
	}

	#[test]
	fn an_unset_required_variable_is_refused() {
		assert_eq!(UNSET.parsed::<u64>(), Err(EnvError::Unset("TBWS_TEST_NEVER_SET")));
	}

	#[test]
	fn an_unset_variable_is_off() {
		assert_eq!(UNSET.flag(), Ok(false));
	}

	#[test]
	fn a_flag_reads_off_and_no_as_off() {
		let off = set("TBWS_TEST_FLAG_OFF", "off");
		let no = set("TBWS_TEST_FLAG_NO", " No ");

		assert_eq!(off.flag(), Ok(false));
		assert_eq!(no.flag(), Ok(false));
	}

	#[test]
	fn a_flag_refuses_an_unknown_word() {
		let flag = set("TBWS_TEST_FLAG_UNKNOWN", "enabled");

		let refused = EnvError::Unparsed { name: "TBWS_TEST_FLAG_UNKNOWN", value: "enabled".to_owned() };
		assert_eq!(flag.flag(), Err(refused));
	}

	#[test]
	fn an_unset_path_is_refused() {
		assert_eq!(UNSET.path(), Err(EnvError::Unset("TBWS_TEST_NEVER_SET")));
	}
}
