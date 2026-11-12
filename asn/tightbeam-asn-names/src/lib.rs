//! The TypeScript names that the `tightbeam-asn` derive and emitter share:
//! [docs/asn.md][type-names].
//!
//! [type-names]: https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/asn.md#type-names

#![no_std]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use core::fmt;
use core::str::FromStr;

/// The words that TypeScript reserves from the names of types.
///
/// # Sources
///
/// - ECMA-262, 16th edition (June 2025), § 12.7.2 Keywords and Reserved Words:
///   the reserved words, and the words reserved in strict mode code, which a
///   module always is.
/// - TypeScript 5.9.3, `checkTypeNameIsReserved` in `lib/typescript.js`: the
///   predefined type names that no type may take.
/// - TypeScript 6.0.3, `parseTypeOperatorOrHigher` in `lib/typescript.js`: the
///   type operators, which a type reference cannot name.
const RESERVED: ReservedWords = ReservedWords::new(&[
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
	"infer",
	"instanceof",
	"interface",
	"keyof",
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
	"readonly",
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
	"unique",
	"unknown",
	"var",
	"void",
	"while",
	"with",
	"yield",
]);

/// The TypeScript type of DER bytes, which wasm-bindgen writes for the `&[u8]`
/// and the `Vec<u8>` of the exports of the derive.
const BYTES: &str = "Uint8Array";

/// The names that the emitted module, or the `.d.ts` it reads, cannot hold as a
/// type name, such as each name that it declares or uses unqualified.
///
/// # Sources
///
/// - `CodecPairs::render` in `tightbeam-asn/src/emit.rs` declares or uses
///   `Asn`, `AsnCodecs`, `MessageCodec`, and `Pick`, and the `constructor`
///   that its `readonly {name}` fields share the class with. TypeScript does
///   not parse its `export type {name}` line for `as`.
/// - The init declarations of the `.d.ts` of a wasm-bindgen 0.2.126
///   `--target web` build, which `Init::of` in `emit.rs` reads, declare or use
///   `InitInput`, `InitOutput`, `Promise`, and `SyncInitInput`.
/// - Each line that [`Export::declaration`] writes uses `Uint8Array`.
const GENERATED: ReservedWords = ReservedWords::new(&[
	"Asn",
	"AsnCodecs",
	"InitInput",
	"InitOutput",
	"MessageCodec",
	"Pick",
	"Promise",
	"SyncInitInput",
	BYTES,
	"as",
	"constructor",
]);

/// A list of reserved words in byte order, which a binary search reads.
struct ReservedWords(&'static [&'static str]);

impl ReservedWords {
	/// The list `words`. The build fails when the words are out of byte order.
	const fn new(words: &'static [&'static str]) -> Self {
		let mut index = 1;
		while index < words.len() {
			assert!(
				Self::below(words[index - 1].as_bytes(), words[index].as_bytes()),
				"reserved words out of byte order"
			);
			index += 1;
		}

		Self(words)
	}

	/// Whether `left` sorts below `right` in byte order.
	const fn below(left: &[u8], right: &[u8]) -> bool {
		let mut index = 0;
		while index < left.len() && index < right.len() {
			if left[index] != right[index] {
				return left[index] < right[index];
			}
			index += 1;
		}

		left.len() < right.len()
	}

	/// Whether `name` is one of the words.
	fn holds(&self, name: &str) -> bool {
		self.0.binary_search(&name).is_ok()
	}
}

/// A name that TypeScript can declare a type under: an ASCII identifier that
/// is no reserved word, and no name that the emitted module cannot hold.
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
/// assert_eq!("readonly".parse::<TypeName>(), Err(NameRefusal::Reserved));
/// assert_eq!("Pick".parse::<TypeName>(), Err(NameRefusal::Generated));
/// assert_eq!("constructor".parse::<TypeName>(), Err(NameRefusal::Generated));
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
	/// - [`NameRefusal::Generated`] -- the emitted module cannot hold `name`.
	fn from_str(name: &str) -> Result<Self, Self::Err> {
		let mut chars = name.chars();
		let starts = chars.next().is_some_and(Self::starts_identifier);
		let continues = chars.all(Self::continues_identifier);
		if !starts || !continues {
			return Err(NameRefusal::NotIdentifier);
		}

		if RESERVED.holds(name) {
			return Err(NameRefusal::Reserved);
		}

		if GENERATED.holds(name) {
			return Err(NameRefusal::Generated);
		}

		Ok(Self(name.to_owned()))
	}
}

impl TypeName {
	/// The identifier as a TypeScript declaration spells it.
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

/// A wasm export of a codec, which the derive declares and the emitter binds.
///
/// # Examples
///
/// ```
/// use tightbeam_asn_names::{CodecExport, Export, NameRefusal, TypeName};
///
/// let doc: TypeName = "Doc".parse()?;
/// assert_eq!(Export::Encode.name(&doc), "encodeDoc");
///
/// let line = "export function decodeDoc(bytes: Uint8Array): Doc;";
/// assert_eq!(Export::Decode.declaration(&doc), line);
///
/// let decode = CodecExport { export: Export::Decode, name: doc };
/// assert_eq!(Export::parse(line), Some(decode));
/// assert_eq!(Export::parse("export function decodeDoc(bytes: Uint8Array): Uint8Array;"), None);
/// assert_eq!(Export::parse("export function decode64(bytes: Uint8Array): Uint8Array;"), None);
/// assert_eq!(Export::parse("export function encodestring(value: string): Uint8Array;"), None);
/// # Ok::<(), NameRefusal>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Export {
	/// `encode{Name}`, which takes a value and returns its DER.
	Encode,
	/// `decode{Name}`, which takes DER and returns the value.
	Decode,
}

impl Export {
	/// The name of this export for the codec of `name`.
	#[must_use]
	pub fn name(self, name: &TypeName) -> String {
		format!("{}{name}", self.prefix())
	}

	/// The name of the one parameter of this export.
	#[must_use]
	pub const fn parameter(self) -> &'static str {
		match self {
			Self::Encode => "value",
			Self::Decode => "bytes",
		}
	}

	/// The line that a wasm `.d.ts` declares this export of the codec of
	/// `name` with.
	#[must_use]
	pub fn declaration(self, name: &TypeName) -> String {
		let (input, output) = match self {
			Self::Encode => (name.as_str(), BYTES),
			Self::Decode => (BYTES, name.as_str()),
		};

		format!("export function {}({}: {input}): {output};", self.name(name), self.parameter())
	}

	/// The codec export that the `.d.ts` line `line` declares. Each line that
	/// [`Export::declaration`] writes parses back. Any other line answers
	/// `None`, such as one whose name after the prefix is no [`TypeName`], or
	/// whose parameter or return type differs.
	#[must_use]
	pub fn parse(line: &str) -> Option<CodecExport> {
		let function = line.strip_prefix("export function ")?;
		[Self::Encode, Self::Decode].into_iter().find_map(|export| {
			let rest = function.strip_prefix(export.prefix())?;
			let name: TypeName = rest[..rest.find('(')?].parse().ok()?;
			(export.declaration(&name) == line).then_some(CodecExport { export, name })
		})
	}

	/// The text that each name of this export starts with.
	const fn prefix(self) -> &'static str {
		match self {
			Self::Encode => "encode",
			Self::Decode => "decode",
		}
	}
}

/// One codec export of a `.d.ts`, which [`Export::parse`] reads from its
/// declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodecExport {
	/// The export that the function name declares.
	pub export: Export,
	/// The type name that the function name carries after the prefix.
	pub name: TypeName,
}

/// Why a name is no [`TypeName`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameRefusal {
	/// The name is no ASCII identifier.
	NotIdentifier,
	/// The name is a word that TypeScript reserves from the names of types.
	Reserved,
	/// The name is one that the emitted module, or the `.d.ts` it reads, cannot
	/// hold, such as a name that it declares or uses.
	Generated,
}

impl fmt::Display for NameRefusal {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::NotIdentifier => {
				"a TypeScript type name is an ASCII identifier: a letter, `_`, or `$`, then letters, digits, `_`, or `$`"
			}
			Self::Reserved => "a TypeScript type name takes no reserved word",
			Self::Generated => "a TypeScript type name takes no name that the emitted module cannot hold",
		};

		f.write_str(message)
	}
}

impl core::error::Error for NameRefusal {}
