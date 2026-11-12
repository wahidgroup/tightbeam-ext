//! The TypeScript name of a codec.

use syn::ext::IdentExt;
use syn::{Error, Ident, LitStr, Result};
use tightbeam_asn_names::{Export, TypeName};

/// The TypeScript name of a codec: the basename of its `encode` and `decode`
/// exports, and the name of a type it declares. It is a [`TypeName`].
pub(crate) struct JsName(TypeName);

impl TryFrom<LitStr> for JsName {
	type Error = Error;

	/// Admit a name that TypeScript can declare a type under.
	///
	/// # Errors
	///
	/// - The [`Error`] of a name that is no [`TypeName`], at the span of `literal`.
	fn try_from(literal: LitStr) -> Result<Self> {
		let name = literal.value();
		let parsed = name.parse::<TypeName>();
		let name = parsed.map_err(|refusal| Error::new(literal.span(), format!("AsnCodec: {refusal}")))?;
		Ok(Self(name))
	}
}

impl JsName {
	/// The name of `ident`, the Rust name of a deriving type, without the `r#`
	/// of a raw identifier.
	///
	/// # Errors
	///
	/// - The errors of [`JsName::try_from`].
	pub(crate) fn of(ident: &Ident) -> Result<Self> {
		let literal = LitStr::new(&ident.unraw().to_string(), ident.span());
		Self::try_from(literal)
	}

	pub(crate) fn as_str(&self) -> &str {
		self.0.as_str()
	}

	/// The name of the wasm export `export` of the codec.
	pub(crate) fn export(&self, export: Export) -> String {
		export.name(&self.0)
	}
}
