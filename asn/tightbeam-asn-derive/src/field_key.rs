//! The JS key of a Sequence field or a Choice variant.

use core::fmt;

use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::ext::IdentExt;
use syn::{Error, Ident, Result};

/// The refusal of a Sequence field or a Choice variant named `__proto__`.
pub(crate) const PROTO_KEY_HELP: &str =
	"AsnCodec refuses a Sequence field or a Choice variant named __proto__, which sets the prototype of a JS object";

/// The JS key of a Sequence field or a Choice variant: the name of its Rust
/// identifier, without the `r#` of a raw identifier. It quotes as a string
/// literal.
pub(crate) struct FieldKey(String);

impl TryFrom<&Ident> for FieldKey {
	type Error = Error;

	/// Admit the name of `ident` as an own key of a JS object.
	///
	/// # Errors
	///
	/// - The [`Error`] of the name `__proto__`, at the span of `ident`.
	fn try_from(ident: &Ident) -> Result<Self> {
		let key = ident.unraw().to_string();
		if key == "__proto__" {
			return Err(Error::new(ident.span(), PROTO_KEY_HELP));
		}

		Ok(Self(key))
	}
}

impl fmt::Display for FieldKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

impl ToTokens for FieldKey {
	fn to_tokens(&self, tokens: &mut TokenStream) {
		self.0.to_tokens(tokens);
	}
}
