//! The TypeScript type-name rule of the `tightbeam-asn` derive and emitter.
//!
//! [`TypeName`] is the one parse of a name that a generated TypeScript module
//! declares a type under, so the derive and the emitter admit the same names.

#![no_std]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::string::String;
use core::fmt;
use core::str::FromStr;

/// The words that TypeScript reserves from the names of types, sorted.
///
/// # Sources
///
/// - ECMA-262, 16th edition (June 2025), § 12.7.2 Keywords and Reserved Words:
///   the reserved words, and the words reserved in strict mode code, which a
///   module always is.
/// - TypeScript 5.9.3, `checkTypeNameIsReserved` in `lib/typescript.js`: the
///   predefined type names that no type may take.
const RESERVED_NAMES: [&str; 56] = [
	"any",
	"await",
	"bigint",
	"boolean",
	"break",
	"case",
	"catch",
	"class",
	"const",
	"continue",
	"debugger",
	"default",
	"delete",
	"do",
	"else",
	"enum",
	"export",
	"extends",
	"false",
	"finally",
	"for",
	"function",
	"if",
	"implements",
	"import",
	"in",
	"instanceof",
	"interface",
	"let",
	"never",
	"new",
	"null",
	"number",
	"object",
	"package",
	"private",
	"protected",
	"public",
	"return",
	"static",
	"string",
	"super",
	"switch",
	"symbol",
	"this",
	"throw",
	"true",
	"try",
	"typeof",
	"undefined",
	"unknown",
	"var",
	"void",
	"while",
	"with",
	"yield",
];

/// A name that TypeScript can declare a type under: an ASCII identifier that
/// is no reserved word.
///
/// An identifier starts with a letter, `_`, or `$`, and continues with
/// letters, digits, `_`, or `$`.
///
/// # Examples
///
/// ```
/// use tightbeam_asn_names::{NameRefusal, TypeName};
///
/// let name: TypeName = "Doc".parse()?;
/// assert_eq!(name.as_str(), "Doc");
///
/// assert_eq!("9Lives".parse::<TypeName>(), Err(NameRefusal::NotIdentifier));
/// assert_eq!("string".parse::<TypeName>(), Err(NameRefusal::Reserved));
/// # Ok::<(), NameRefusal>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeName(String);

impl FromStr for TypeName {
	type Err = NameRefusal;

	/// Admit `name` when TypeScript can declare a type under it.
	///
	/// # Errors
	///
	/// - [`NameRefusal::NotIdentifier`] -- `name` is no ASCII identifier.
	/// - [`NameRefusal::Reserved`] -- `name` is a reserved word.
	fn from_str(name: &str) -> Result<Self, Self::Err> {
		let mut chars = name.chars();
		let starts = chars.next().is_some_and(Self::starts_identifier);
		let continues = chars.all(Self::continues_identifier);
		if !starts || !continues {
			return Err(NameRefusal::NotIdentifier);
		}

		let reserved = RESERVED_NAMES.binary_search(&name).is_ok();
		if reserved {
			return Err(NameRefusal::Reserved);
		}

		Ok(Self(name.to_owned()))
	}
}

impl TypeName {
	/// The name.
	#[must_use]
	pub fn as_str(&self) -> &str {
		&self.0
	}

	/// Whether `ch` may start an identifier: a letter, `_`, or `$`.
	fn starts_identifier(ch: char) -> bool {
		ch.is_ascii_alphabetic() || ch == '_' || ch == '$'
	}

	/// Whether `ch` may follow the start of an identifier: a letter, a digit,
	/// `_`, or `$`.
	fn continues_identifier(ch: char) -> bool {
		ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'
	}
}

impl fmt::Display for TypeName {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

/// Why a name is no [`TypeName`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameRefusal {
	/// The name is no ASCII identifier.
	NotIdentifier,
	/// The name is a word that TypeScript reserves from the names of types.
	Reserved,
}

impl fmt::Display for NameRefusal {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::NotIdentifier => {
				"a TypeScript type name is an ASCII identifier: a letter, `_`, or `$`, then letters, digits, `_`, or `$`"
			}
			Self::Reserved => "a TypeScript type name takes no reserved word",
		};

		f.write_str(message)
	}
}

impl core::error::Error for NameRefusal {}
