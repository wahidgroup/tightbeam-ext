//! The `MessageCodec` module of the codec exports of a wasm `.d.ts`:
//! [docs/asn.md][emit].
//!
//! [emit]: https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/asn.md#emit

use core::fmt;
use core::str::FromStr;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;

use tightbeam::Errorizable;
use tightbeam_asn_names::{CodecExport, Export, TypeName};

/// The package that exports the `MessageCodec` type by default.
const MESSAGE_CODEC_FROM: &str = "@wahidgroup/tightbeam-ws-client";

/// Failure while discovering pairs or writing façades.
#[derive(Debug, Errorizable)]
pub enum EmitError {
	/// Filesystem read or write failed.
	#[error("i/o error: {0}")]
	#[from]
	Io(io::Error),
	/// No matching `encode{Name}` / `decode{Name}` pairs in the `.d.ts`.
	#[error("no encode/decode codec pairs found in .d.ts")]
	NoCodecPairs,
}

/// Options that shape the generated TypeScript module.
///
/// # Examples
///
/// ```
/// use tightbeam_asn::emit::{CodecPairs, EmitOptions};
///
/// let dts = "export function encodeDoc(value: Doc): Uint8Array;\n\
/// 	export function decodeDoc(bytes: Uint8Array): Doc;\n";
/// let pairs: CodecPairs = dts.parse()?;
///
/// let options = EmitOptions::new("#asn-wasm").with_message_codec_from("./message.js");
/// let module = pairs.render(&options);
/// assert!(module.contains("export class AsnCodecs {"));
/// # Ok::<(), tightbeam_asn::emit::EmitError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmitOptions {
	import: ModuleSpecifier,
	message_codec_from: ModuleSpecifier,
}

impl EmitOptions {
	/// Options that read the wasm types from the module specifier `import`,
	/// and `MessageCodec` from `@wahidgroup/tightbeam-ws-client`.
	#[must_use]
	pub fn new(import: impl Into<String>) -> Self {
		let import = ModuleSpecifier::from(import.into());
		let message_codec_from = ModuleSpecifier::from(String::from(MESSAGE_CODEC_FROM));
		Self { import, message_codec_from }
	}

	/// These options, with `MessageCodec` read from the package
	/// `message_codec_from`.
	#[must_use]
	pub fn with_message_codec_from(self, message_codec_from: impl Into<String>) -> Self {
		let message_codec_from = ModuleSpecifier::from(message_codec_from.into());
		Self { message_codec_from, ..self }
	}
}

/// A module specifier, held as the TypeScript string literal that names it.
///
/// The literal escapes every quote, backslash, line terminator, and control
/// character, so any specifier renders as one valid string literal.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ModuleSpecifier(String);

impl From<String> for ModuleSpecifier {
	fn from(specifier: String) -> Self {
		let mut literal = String::with_capacity(specifier.len() + 2);
		literal.push('"');
		for ch in specifier.chars() {
			match ch {
				'"' => literal.push_str("\\\""),
				'\\' => literal.push_str("\\\\"),
				'\n' => literal.push_str("\\n"),
				'\r' => literal.push_str("\\r"),
				'\u{2028}' | '\u{2029}' => literal.push_str(&format!("\\u{:04x}", u32::from(ch))),
				ch if ch.is_control() => literal.push_str(&format!("\\u{:04x}", u32::from(ch))),
				ch => literal.push(ch),
			}
		}

		literal.push('"');

		Self(literal)
	}
}

impl fmt::Display for ModuleSpecifier {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

/// The type names that a wasm `.d.ts` declares both codec exports for, each in
/// its [`Export::declaration`], sorted, at least one, and the init of its
/// module.
///
/// # Examples
///
/// ```
/// use tightbeam_asn::emit::CodecPairs;
///
/// let dts = "export function encodeDoc(value: Doc): Uint8Array;\n\
/// 	export function decodeDoc(bytes: Uint8Array): Doc;\n";
/// let pairs: CodecPairs = dts.parse()?;
/// let names: Vec<&str> = pairs.names().iter().map(|name| name.as_str()).collect();
/// assert_eq!(names, ["Doc"]);
/// # Ok::<(), tightbeam_asn::emit::EmitError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodecPairs {
	names: Vec<TypeName>,
	init: Init,
}

impl FromStr for CodecPairs {
	type Err = EmitError;

	/// Collect the type names of `dts` that have both exports, and read the
	/// init of its module. A name with one export alone names no pair, and a
	/// line that [`Export::parse`] refuses names no export.
	///
	/// # Errors
	///
	/// - [`EmitError::NoCodecPairs`] -- no type name has both exports.
	fn from_str(dts: &str) -> Result<Self, Self::Err> {
		let mut encodes = BTreeSet::new();
		let mut decodes = BTreeSet::new();
		for line in dts.lines() {
			let Some(CodecExport { export, name }) = Export::parse(line.trim()) else {
				continue;
			};

			match export {
				Export::Encode => encodes.insert(name),
				Export::Decode => decodes.insert(name),
			};
		}

		let names: Vec<TypeName> = encodes.intersection(&decodes).cloned().collect();
		if names.is_empty() {
			return Err(EmitError::NoCodecPairs);
		}

		Ok(Self { names, init: Init::of(dts) })
	}
}

impl CodecPairs {
	/// Read the pairs of the `.d.ts` at `from_dts`.
	///
	/// # Errors
	///
	/// - [`EmitError::Io`] -- the read failed.
	/// - [`EmitError::NoCodecPairs`] -- the `.d.ts` exports no codec pair.
	pub fn read(from_dts: impl AsRef<Path>) -> Result<Self, EmitError> {
		let dts = fs::read_to_string(from_dts)?;
		dts.parse()
	}

	/// The type names, sorted.
	#[must_use]
	pub fn names(&self) -> &[TypeName] {
		&self.names
	}

	/// The MessageCodec TypeScript module of these pairs, shaped by `opts`.
	#[must_use]
	pub fn render(&self, opts: &EmitOptions) -> String {
		let names = &self.names;
		let mut out = String::new();
		out.push_str("// Generated by tightbeam-asn-emit. DO NOT EDIT.\n");
		out.push_str("// Regenerate after wasm-pack.\n");
		out.push('\n');
		out.push_str(&format!("import type {{ MessageCodec }} from {};\n\n", opts.message_codec_from));
		out.push_str(&format!("import type * as Asn from {};\n\n", opts.import));

		for name in names {
			out.push_str(&format!("export type {name} = Asn.{name};\n"));
		}

		out.push('\n');
		out.push_str("/**\n");
		out.push_str(" * The MessageCodec of each DER type, bound to the exports of one initialized wasm module.\n");
		out.push_str(" */\n");
		out.push_str("export class AsnCodecs {\n");

		for name in names {
			out.push_str(&format!("\treadonly {name}: MessageCodec<{name}>;\n"));
		}

		let mut exports = Vec::with_capacity(names.len() * 2);
		for name in names {
			exports.push(format!("\"{}\"", Export::Decode.name(name)));
			exports.push(format!("\"{}\"", Export::Encode.name(name)));
		}

		out.push('\n');
		out.push_str("\t/**\n");
		out.push_str("\t * @param asn The codec exports of the wasm module.\n");
		out.push_str(self.init.param_docs());
		out.push_str("\t */\n");
		out.push_str("\tconstructor(asn: Pick<typeof Asn, ");
		out.push_str(&exports.join(" | "));
		out.push('>');
		out.push_str(self.init.params());
		out.push_str(") {\n");

		for name in names {
			let encode = Export::Encode.name(name);
			let decode = Export::Decode.name(name);
			out.push_str(&format!(
				"\t\tthis.{name} = {{ encode: asn.{encode}, decode: asn.{decode} }};\n"
			));
		}

		out.push_str("\t}\n");
		out.push_str("}\n");
		out
	}

	/// Write the module of these pairs, shaped by `opts`, to `out`, and create
	/// the parent directory of `out`.
	///
	/// # Errors
	///
	/// - [`EmitError::Io`] -- a write failed.
	pub fn write(&self, opts: &EmitOptions, out: impl AsRef<Path>) -> Result<(), EmitError> {
		let out = out.as_ref();
		if let Some(parent) = out.parent() {
			if !parent.as_os_str().is_empty() {
				fs::create_dir_all(parent)?;
			}
		}

		fs::write(out, self.render(opts))?;
		Ok(())
	}
}

/// How the wasm module of a `.d.ts` initializes, which the constructor of
/// `AsnCodecs` takes as proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Init {
	/// A web build. Its `init` and `initSync` return the `InitOutput` that the
	/// `.d.ts` declares.
	Web,
	/// A build that initializes on import, such as a nodejs build. Its `.d.ts`
	/// declares no `InitOutput`.
	Sync,
}

impl Init {
	/// The init of the module of `dts`: [`Init::Web`] when it declares
	/// `InitOutput`.
	fn of(dts: &str) -> Self {
		let declares_output = dts.lines().any(|line| {
			let rest = line.trim_start().strip_prefix("export interface InitOutput");
			rest.is_some_and(|rest| rest.trim_start().starts_with('{'))
		});
		if declares_output {
			return Self::Web;
		}

		Self::Sync
	}

	/// The JSDoc lines of the constructor parameters that follow the exports.
	fn param_docs(self) -> &'static str {
		match self {
			Self::Web => {
				"\t * @param _ready The output of the init of the module, which only an init that resolves returns.\n"
			}
			Self::Sync => "",
		}
	}

	/// The constructor parameters that follow the exports.
	fn params(self) -> &'static str {
		match self {
			Self::Web => ", _ready: Asn.InitOutput",
			Self::Sync => "",
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn codec_pairs_intersect_and_sort() {
		let dts = concat!(
			"export function decodeZed(bytes: Uint8Array): Zed;\n",
			"export function encodeZed(value: Zed): Uint8Array;\n",
			"export function encodeOnly(value: Only): Uint8Array;\n",
			"export function decodeAlpha(bytes: Uint8Array): Alpha;\n",
			"export function encodeAlpha(value: Alpha): Uint8Array;\n",
		);

		let pairs: Result<CodecPairs, EmitError> = dts.parse();
		assert!(matches!(
			pairs.as_ref().map(CodecPairs::names),
			Ok([a, b]) if a.as_str() == "Alpha" && b.as_str() == "Zed"
		));
	}

	#[test]
	fn a_dts_with_no_pair_is_refused() {
		let pairs: Result<CodecPairs, EmitError> = "export const x = 1;".parse();
		assert!(matches!(pairs, Err(EmitError::NoCodecPairs)));
	}

	#[test]
	fn a_specifier_with_a_quote_or_a_backslash_renders_as_one_string_literal() -> Result<(), EmitError> {
		let dts = concat!(
			"export function decodeDoc(bytes: Uint8Array): Doc;\n",
			"export function encodeDoc(value: Doc): Uint8Array;\n",
		);
		let pairs: CodecPairs = dts.parse()?;
		let options = EmitOptions::new("./a\"b\\c.js").with_message_codec_from("pkg\n\"x\"");

		let module = pairs.render(&options);
		let imports: Vec<&str> = module.lines().filter(|line| line.starts_with("import")).collect();
		assert_eq!(
			imports,
			[
				r#"import type { MessageCodec } from "pkg\n\"x\"";"#,
				r#"import type * as Asn from "./a\"b\\c.js";"#
			]
		);
		Ok(())
	}

	#[test]
	fn a_specifier_escapes_each_line_terminator_and_control_character() -> Result<(), EmitError> {
		let pairs: CodecPairs =
			"export function decodeDoc(bytes: Uint8Array): Doc;\nexport function encodeDoc(value: Doc): Uint8Array;\n"
				.parse()?;
		let options = EmitOptions::new("a\r\u{2028}\u{2029}\u{1}b");

		let module = pairs.render(&options);
		assert!(module.contains(r#"import type * as Asn from "a\r\u2028\u2029\u0001b";"#));
		Ok(())
	}
}
