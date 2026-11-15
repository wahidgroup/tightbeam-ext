//! The `#[derive(AsnCodec)]` macro of [`tightbeam-asn`]: [docs/asn.md][derive].
//!
//! [`tightbeam-asn`]: https://docs.rs/tightbeam-asn
//! [derive]: https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/asn.md#derive

mod field_key;
mod js_name;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote, quote_spanned, ToTokens};
use syn::meta::ParseNestedMeta;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::token::Comma;
use syn::{
	parse_macro_input, Attribute, Data, DataEnum, DataStruct, DeriveInput, Error, Expr, ExprLit, ExprPath, Field,
	Fields, GenericArgument, Ident, Lit, LitStr, Path, PathArguments, Result, Type,
};

use tightbeam_asn_names::Export;

use crate::field_key::FieldKey;
use crate::js_name::JsName;

/// Marks a `der` type as a codec for TypeScript.
///
/// Optional `#[asn_codec(js_name = "...")]` on the type sets the wasm export
/// basename and the name of the declared type. That name, or the Rust name
/// without it, is an ASCII TypeScript identifier that can name a type.
#[proc_macro_derive(AsnCodec, attributes(asn_codec))]
pub fn derive_asn_codec(input: TokenStream) -> TokenStream {
	let input = parse_macro_input!(input as DeriveInput);
	let codec = Codec::try_from(&input);
	match codec {
		Ok(codec) => codec.expand(&input.ident).into(),
		Err(error) => error.to_compile_error().into(),
	}
}

/// One DER type's conversions and its TypeScript declaration.
struct Codec {
	js_name: JsName,
	ts_section: TsText,
	from_js: TokenStream2,
	to_js: TokenStream2,
	asserts: TokenStream2,
}

impl TryFrom<&DeriveInput> for Codec {
	type Error = Error;

	fn try_from(input: &DeriveInput) -> Result<Self> {
		if !input.generics.params.is_empty() {
			let refusal = "AsnCodec DER types take no generic parameters";
			return Err(Error::new(input.generics.span(), refusal));
		}

		let options = CodecOptions::try_from(input)?;
		let js_name = options.into_js_name(&input.ident)?;
		match &input.data {
			Data::Struct(data) => Self::sequence(input, data, js_name),
			Data::Enum(data) => Shape::classify(data)?.codec(input, js_name),
			Data::Union(_) => Err(Error::new(input.span(), "AsnCodec supports structs and enums")),
		}
	}
}

impl Codec {
	fn sequence(input: &DeriveInput, data: &DataStruct, js_name: JsName) -> Result<Self> {
		let Fields::Named(fields) = &data.fields else {
			return Err(Error::new(input.span(), "AsnCodec supports structs with named fields"));
		};

		let FieldEmit { reads, writes, names, ts_fields, asserts } = FieldEmit::collect(&fields.named)?;

		let mut ts_section = TsText::from(format!("export interface {} {{\n", js_name.as_str()));
		for (index, ts_field) in ts_fields.into_iter().enumerate() {
			if index > 0 {
				ts_section.push_str("\n");
			}

			ts_section.append(ts_field);
		}

		ts_section.push_str("\n}");

		let from_js = quote! {
			let __fields = ::tightbeam_asn::__private::JsField::from(__source).object()?;
			#(#reads)*
			::core::result::Result::Ok(Self { #(#names),* })
		};
		let to_js = quote! {
			let __object = ::tightbeam_asn::__private::JsRecord::default();
			#(#writes)*
			::core::result::Result::Ok(::wasm_bindgen::JsValue::from(__object))
		};

		Ok(Self { js_name, ts_section, from_js, to_js, asserts: quote! { #(#asserts)* } })
	}

	fn enumerated(input: &DeriveInput, discriminants: &[u8], js_name: JsName) -> Result<Self> {
		Self::require_repr_u8(input)?;

		let literals: Vec<String> = discriminants.iter().map(u8::to_string).collect();
		let ts_section = TsText::from(format!("export type {} = {};", js_name.as_str(), literals.join(" | ")));
		let from_js = quote! {
			let discriminant = <::core::primitive::u8 as ::tightbeam_asn::__private::JsLeaf>::read(__source)?;
			::core::convert::TryFrom::try_from(discriminant).map_err(::tightbeam_asn::FieldError::from)
		};
		let to_js = quote! {
			<::core::primitive::u8 as ::tightbeam_asn::__private::JsLeaf>::project(&(*self as ::core::primitive::u8))
		};

		Ok(Self { js_name, ts_section, from_js, to_js, asserts: quote! {} })
	}

	fn choice(alternatives: &[(Ident, Type)], js_name: JsName) -> Result<Self> {
		let mut from_arms = Vec::new();
		let mut to_arms = Vec::new();
		let mut ts_section = TsText::from(format!("export type {} =", js_name.as_str()));

		for (variant_ident, ty) in alternatives {
			let variant_name = FieldKey::try_from(variant_ident)?;
			let kind = FieldKind::try_from(ty)?;
			let present = format_ident!("present");
			let from_present = kind.quote_from_value(&present);
			let value = format_ident!("payload");
			let to_value = kind.quote_to_value(&value);

			from_arms.push(quote! {
				#variant_name => {
					let payload = (#from_present).map_err(|error| error.within(#variant_name))?;
					::core::result::Result::Ok(Self::#variant_ident(payload))
				}
			});
			to_arms.push(quote! {
				Self::#variant_ident(#value) => {
					let nested = #to_value;
					__object.set(#variant_name, &nested)?;
				}
			});
			ts_section.push_str(&format!("\n\t| {{ {variant_name}: "));
			ts_section.append(kind.ts_type());
			ts_section.push_str(" }");
		}

		ts_section.push_str(";");

		let from_js = quote! {
			let ::tightbeam_asn::__private::ChoiceEntry { variant, value: present } =
				::tightbeam_asn::__private::JsField::from(__source).single_entry()?;
			match variant.as_str() {
				#(#from_arms)*
				_ => ::core::result::Result::Err(::tightbeam_asn::FieldError::new("a known Choice variant")),
			}
		};
		let to_js = quote! {
			let __object = ::tightbeam_asn::__private::JsRecord::default();
			match self {
				#(#to_arms)*
			}

			::core::result::Result::Ok(::wasm_bindgen::JsValue::from(__object))
		};

		Ok(Self { js_name, ts_section, from_js, to_js, asserts: quote! {} })
	}

	/// Refuse an Enumerated type without `#[repr(u8)]`.
	fn require_repr_u8(input: &DeriveInput) -> Result<()> {
		for attr in &input.attrs {
			if !attr.path().is_ident("repr") {
				continue;
			}

			let mut is_u8 = false;

			attr.parse_nested_meta(|meta| {
				if meta.path.is_ident("u8") {
					is_u8 = true;
					return Ok(());
				}
				Err(meta.error("AsnCodec Enumerated requires #[repr(u8)]"))
			})?;

			if is_u8 {
				return Ok(());
			}
		}

		Err(Error::new(input.span(), "AsnCodec Enumerated requires #[repr(u8)]"))
	}

	/// The `AsnCodec` and `JsLeaf` implementations and the TypeScript
	/// declaration on every target, and on `wasm32` the JS conversions and the
	/// typed `encode` and `decode` exports.
	fn expand(self, name: &Ident) -> TokenStream2 {
		let Self { js_name, ts_section, from_js, to_js, asserts } = self;
		let encode_js_name = js_name.export(Export::Encode);
		let decode_js_name = js_name.export(Export::Decode);
		let value = format_ident!("{}", Export::Encode.parameter());
		let bytes = format_ident!("{}", Export::Decode.parameter());
		let js_name = js_name.as_str();
		let encode_fn = format_ident!("__asn_encode_{name}");
		let decode_fn = format_ident!("__asn_decode_{name}");
		let carrier = format_ident!("__AsnJs{name}");
		let parts = ts_section.quote();

		quote! {
			impl ::tightbeam_asn::__private::Sealed for #name {}

			#[automatically_derived]
			impl ::tightbeam_asn::AsnCodec for #name {}

			#[automatically_derived]
			impl ::tightbeam_asn::__private::JsLeaf for #name {
				const TS_TYPE: &'static str = #js_name;
				const CONTRACT: &'static str = #NESTED_CONTRACT;

				#[cfg(target_arch = "wasm32")]
				fn read(
					__source: &::wasm_bindgen::JsValue,
				) -> ::core::result::Result<Self, ::tightbeam_asn::FieldError> {
					#from_js
				}

				#[cfg(target_arch = "wasm32")]
				fn project(&self) -> ::core::result::Result<::wasm_bindgen::JsValue, ::tightbeam_asn::FieldError> {
					#to_js
				}
			}

			const _: () = {
				const TEXT: &str = ::tightbeam_asn::__ts_section!(#parts);

				#[cfg(target_arch = "wasm32")]
				#[::wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
				const SECTION: &'static str = TEXT;

				#asserts
			};

			#[cfg(target_arch = "wasm32")]
			const _: () = {
				use ::der::{Decode, Encode};
				use ::wasm_bindgen::prelude::*;
				use ::wasm_bindgen::JsCast;

				#[wasm_bindgen]
				extern "C" {
					#[wasm_bindgen(typescript_type = #js_name)]
					pub type #carrier;
				}

				#[wasm_bindgen(js_name = #encode_js_name)]
				pub fn #encode_fn(
					#value: #carrier,
				) -> ::core::result::Result<::std::vec::Vec<u8>, ::wasm_bindgen::JsValue> {
					let message = <#name as ::tightbeam_asn::AsnCodec>::from_js(&#value).map_err(::wasm_bindgen::JsValue::from)?;
					message.to_der().map_err(|error| ::wasm_bindgen::JsValue::from(::tightbeam_asn::__private::WireError(error)))
				}

				#[wasm_bindgen(js_name = #decode_js_name)]
				pub fn #decode_fn(
					#bytes: &[u8],
				) -> ::core::result::Result<#carrier, ::wasm_bindgen::JsValue> {
					let message = <#name as ::der::Decode>::from_der(#bytes).map_err(|error| ::wasm_bindgen::JsValue::from(::tightbeam_asn::__private::WireError(error)))?;
					let value = <#name as ::tightbeam_asn::AsnCodec>::to_js(&message).map_err(::wasm_bindgen::JsValue::from)?;
					::core::result::Result::Ok(value.unchecked_into())
				}
			};
		}
	}
}

/// The refusal of an `asn_codec` attribute on a field or a variant.
const MEMBER_OPTIONS_HELP: &str = "AsnCodec reads asn_codec only on the deriving type, not on a field or a variant";

/// The options of a deriving type, parsed from every `#[asn_codec(...)]`
/// attribute it carries.
#[derive(Default)]
struct CodecOptions {
	js_name: Option<JsName>,
}

impl TryFrom<&DeriveInput> for CodecOptions {
	type Error = Error;

	/// Parse each `asn_codec` attribute of the deriving type `input`, and
	/// refuse one on any field or variant of `input`.
	///
	/// # Errors
	///
	/// - The [`Error`] of a key other than `js_name`, at the span of the key.
	/// - The [`Error`] of a second `js_name`, in the same attribute or another one.
	/// - The [`Error`] of a `js_name` that is no [`JsName`].
	/// - The [`Error`] of an `asn_codec` attribute on a field or a variant, at its span.
	fn try_from(input: &DeriveInput) -> Result<Self> {
		let mut options = Self::default();
		for attr in &input.attrs {
			if !attr.path().is_ident("asn_codec") {
				continue;
			}

			attr.parse_nested_meta(|meta| options.admit(&meta))?;
		}

		let members: Vec<&Attribute> = match &input.data {
			Data::Struct(data) => data.fields.iter().flat_map(|field| &field.attrs).collect(),
			Data::Enum(data) => data
				.variants
				.iter()
				.flat_map(|variant| variant.attrs.iter().chain(variant.fields.iter().flat_map(|field| &field.attrs)))
				.collect(),
			Data::Union(data) => data.fields.named.iter().flat_map(|field| &field.attrs).collect(),
		};
		if let Some(attr) = members.into_iter().find(|attr| attr.path().is_ident("asn_codec")) {
			return Err(Error::new(attr.span(), MEMBER_OPTIONS_HELP));
		}

		Ok(options)
	}
}

impl CodecOptions {
	/// Admit one `key = value` of an `asn_codec` attribute.
	fn admit(&mut self, meta: &ParseNestedMeta) -> Result<()> {
		if !meta.path.is_ident("js_name") {
			return Err(meta.error("unsupported asn_codec attribute"));
		}
		if self.js_name.is_some() {
			return Err(meta.error("AsnCodec takes one js_name"));
		}

		let literal: LitStr = meta.value()?.parse()?;
		self.js_name = Some(JsName::try_from(literal)?);
		Ok(())
	}

	/// The name of the codec: the `js_name`, or the Rust name `ident`.
	fn into_js_name(self, ident: &Ident) -> Result<JsName> {
		match self.js_name {
			Some(js_name) => Ok(js_name),
			None => JsName::of(ident),
		}
	}
}

/// The pieces of the expansion that each field of a Sequence contributes.
struct FieldEmit {
	reads: Vec<TokenStream2>,
	writes: Vec<TokenStream2>,
	names: Vec<TokenStream2>,
	ts_fields: Vec<TsText>,
	asserts: Vec<TokenStream2>,
}

impl FieldEmit {
	fn collect(fields: &Punctuated<Field, Comma>) -> Result<Self> {
		let mut emit = Self {
			reads: Vec::new(),
			writes: Vec::new(),
			names: Vec::new(),
			ts_fields: Vec::new(),
			asserts: Vec::new(),
		};

		for field in fields {
			let field_name = field
				.ident
				.as_ref()
				.ok_or_else(|| Error::new(field.span(), "expected named field"))?;

			let field_key = FieldKey::try_from(field_name)?;
			let slot = Slot::try_from(&field.ty)?;
			let doc = DocLines::from(field.attrs.as_slice()).or(slot.contract());

			emit.reads.push(slot.quote_read(field_name, &field.ty, &field_key));
			emit.writes.push(slot.quote_write(field_name, &field_key));
			emit.names.push(quote! { #field_name });
			emit.ts_fields.push(slot.ts_property(&field_key, doc));
			emit.asserts.push(slot.quote_assert(&field.ty));
		}

		Ok(emit)
	}
}

/// The text of a TypeScript declaration: literal text, and the `JsLeaf`
/// constants of the field types, which the build of the deriving crate joins.
#[derive(Default)]
struct TsText(Vec<TsPart>);

/// One part of a [`TsText`].
enum TsPart {
	Text(String),
	Const(TokenStream2),
}

impl TsPart {
	/// This part as a `&'static str` expression.
	fn quote(&self) -> TokenStream2 {
		match self {
			Self::Text(text) => quote! { #text },
			Self::Const(expr) => expr.clone(),
		}
	}
}

impl From<String> for TsText {
	fn from(text: String) -> Self {
		Self(vec![TsPart::Text(text)])
	}
}

impl TsText {
	/// The text of the constant `expr`, a `&'static str`.
	fn of_const(expr: TokenStream2) -> Self {
		Self(vec![TsPart::Const(expr)])
	}

	fn push_str(&mut self, text: &str) {
		self.0.push(TsPart::Text(text.to_owned()));
	}

	fn append(&mut self, other: Self) {
		self.0.extend(other.0);
	}

	/// The parts as a `&[&str]` expression.
	fn quote(&self) -> TokenStream2 {
		let parts = self.0.iter().map(TsPart::quote);

		quote! { &[#(#parts),*] }
	}
}

/// The doc lines of a field, which its TypeScript declaration carries.
struct DocLines(Vec<TsText>);

impl From<&[Attribute]> for DocLines {
	/// Each non-empty `///` line of `attrs`, with its one leading space
	/// removed. Each `*/` is written as `*\/`, so the line stays inside its
	/// JSDoc block.
	fn from(attrs: &[Attribute]) -> Self {
		let mut lines = Vec::new();
		for attr in attrs {
			if !attr.path().is_ident("doc") {
				continue;
			}
			let Ok(meta) = attr.meta.require_name_value() else {
				continue;
			};
			let Expr::Lit(ExprLit { lit: Lit::Str(lit), .. }) = &meta.value else {
				continue;
			};
			let value = lit.value();
			let text = match value.strip_prefix(' ') {
				Some(stripped) => stripped,
				None => value.as_str(),
			};
			if !text.is_empty() {
				lines.push(TsText::from(text.replace("*/", "*\\/")));
			}
		}

		Self(lines)
	}
}

impl DocLines {
	/// These lines, or the one line `contract` when there are none.
	fn or(self, contract: TsText) -> Self {
		if self.0.is_empty() {
			return Self(vec![contract]);
		}

		self
	}

	/// The JSDoc block of these lines, indented by one tab.
	fn jsdoc(self) -> TsText {
		let mut out = TsText::from(String::from("\t/**\n"));
		for line in self.0 {
			out.push_str("\t * ");
			out.append(line);
			out.push_str("\n");
		}

		out.push_str("\t */\n");
		out
	}
}

/// How a Sequence field carries its [`FieldKind`].
///
/// OPTIONAL lives here and not on [`FieldKind`], because der encodes `None` as
/// zero bytes. Inside a collection or another OPTIONAL an absent value would
/// leave no trace in the encoding, so those shapes have no representation.
enum Slot {
	Required(FieldKind),
	Optional(FieldKind),
}

impl TryFrom<&Type> for Slot {
	type Error = Error;

	fn try_from(ty: &Type) -> Result<Self> {
		let path = TypePath::try_from(ty)?;
		let Some(inner_ty) = path.wrapped("Option") else {
			return Ok(Self::Required(FieldKind::try_from(ty)?));
		};

		Ok(Self::Optional(FieldKind::try_from(inner_ty)?))
	}
}

impl Slot {
	fn kind(&self) -> &FieldKind {
		match self {
			Self::Required(kind) | Self::Optional(kind) => kind,
		}
	}

	fn ts_property(&self, field_key: &FieldKey, doc: DocLines) -> TsText {
		let mut property = doc.jsdoc();
		match self {
			Self::Required(kind) => {
				property.push_str(&format!("\t{field_key}: "));
				property.append(kind.ts_type());
			}
			Self::Optional(kind) => {
				property.push_str(&format!("\t{field_key}?: "));
				property.append(kind.ts_type());
				property.push_str(" | null");
			}
		}

		property.push_str(";");
		property
	}

	fn contract(&self) -> TsText {
		match self {
			Self::Required(kind) => kind.contract(),
			Self::Optional(_) => TsText::from(String::from(
				"Carries an OPTIONAL Sequence field. Nullish JS values map to None, and a present value maps to Some.",
			)),
		}
	}

	/// The compile-time refusal of an OPTIONAL whose present value JavaScript
	/// reads back as absent, at the span of the field type `ty`.
	fn quote_assert(&self, ty: &Type) -> TokenStream2 {
		match self {
			Self::Required(_) => quote! {},
			Self::Optional(kind) => kind.quote_absent_assert(ty),
		}
	}

	/// Read one field. Every kind passes through
	/// [`FieldKind::quote_from_value`], so a missing key fails as a wrong
	/// value.
	fn quote_read(&self, field_name: &Ident, ty: &Type, field_key: &FieldKey) -> TokenStream2 {
		let present = format_ident!("present");
		let from_present = self.kind().quote_from_value(&present);
		let converted = match self {
			Self::Required(_) => from_present,
			Self::Optional(_) => quote! {
				if #present.is_undefined() || #present.is_null() {
					::core::result::Result::Ok(::core::option::Option::None)
				} else {
					(#from_present).map(::core::option::Option::Some)
				}
			},
		};

		quote! {
			let #field_name: #ty = {
				let #present = __fields.get(#field_key)?;
				(#converted).map_err(|error| error.within(#field_key))?
			};
		}
	}

	/// Write one field. An absent OPTIONAL leaves its key off the object.
	fn quote_write(&self, field_name: &Ident, field_key: &FieldKey) -> TokenStream2 {
		let value = format_ident!("value");
		let to_value = self.kind().quote_to_value(&value);
		let write = quote! {
			let nested = #to_value;
			__object.set(#field_key, &nested)?;
		};

		match self {
			Self::Required(_) => quote! {
				{
					let #value = &self.#field_name;
					#write
				}
			},
			Self::Optional(_) => quote! {
				if let ::core::option::Option::Some(#value) = &self.#field_name {
					#write
				}
			},
		}
	}
}

/// The JSDoc of a field of a DER type that derives `AsnCodec`.
const NESTED_CONTRACT: &str = "Carries a nested AsnCodec value for this Sequence field.";

enum FieldKind {
	/// A type that converts through its `JsLeaf` impl: a `der` leaf, or
	/// another DER type.
	Value(TypePath),
	Vec(Box<FieldKind>),
	SetOfVec(Box<FieldKind>),
	SequenceOf {
		inner: Box<FieldKind>,
		len: Expr,
	},
	SetOf {
		inner: Box<FieldKind>,
		len: Expr,
	},
}

const FIELD_KIND_HELP: &str = "AsnCodec Sequence fields must be a plain type path: a der leaf, a nested AsnCodec, or Vec/SetOfVec/SequenceOf/SetOf over those types, optionally wrapped once in Option";

const NESTED_OPTION_HELP: &str = "AsnCodec takes Option only on a Sequence field: der encodes None as zero bytes, so it leaves no trace inside a collection, another Option, or a Choice";

const UNTRACEABLE_OPTION_HELP: &str =
	"AsnCodec refuses Option<Null>: JS null is both NULL and absent, so Some(Null) reads back as None";

impl TryFrom<&Type> for FieldKind {
	type Error = Error;

	fn try_from(ty: &Type) -> Result<Self> {
		let path = TypePath::try_from(ty)?;
		if path.wrapped("Option").is_some() {
			return Err(Error::new(ty.span(), NESTED_OPTION_HELP));
		}
		if let Some(inner_ty) = path.wrapped("Vec") {
			return Ok(Self::Vec(Box::new(Self::try_from(inner_ty)?)));
		}
		if let Some(inner_ty) = path.wrapped("SetOfVec") {
			return Ok(Self::SetOfVec(Box::new(Self::try_from(inner_ty)?)));
		}
		if let Some((inner_ty, len)) = path.bounded("SequenceOf") {
			return Ok(Self::SequenceOf { inner: Box::new(Self::try_from(inner_ty)?), len });
		}
		if let Some((inner_ty, len)) = path.bounded("SetOf") {
			return Ok(Self::SetOf { inner: Box::new(Self::try_from(inner_ty)?), len });
		}
		if path.has_generics() {
			return Err(Error::new(ty.span(), FIELD_KIND_HELP));
		}

		Ok(Self::Value(path))
	}
}

impl FieldKind {
	fn ts_type(&self) -> TsText {
		match self {
			Self::Value(path) => TsText::of_const(quote! { <#path as ::tightbeam_asn::__private::JsLeaf>::TS_TYPE }),
			Self::Vec(inner) | Self::SetOfVec(inner) | Self::SequenceOf { inner, .. } | Self::SetOf { inner, .. } => {
				let mut ts_type = inner.ts_type();
				ts_type.push_str("[]");
				ts_type
			}
		}
	}

	/// The compile-time refusal of this kind inside an OPTIONAL when JavaScript
	/// reads its present value back as absent, at the span of the field type
	/// `ty`. A collection reads back as an `Array`, so the refusal holds for a
	/// `Value` alone.
	fn quote_absent_assert(&self, ty: &Type) -> TokenStream2 {
		match self {
			Self::Value(path) => quote_spanned! {ty.span()=>
				::core::assert!(
					!<#path as ::tightbeam_asn::__private::JsLeaf>::READS_AS_ABSENT,
					#UNTRACEABLE_OPTION_HELP,
				);
			},
			Self::Vec(_) | Self::SetOfVec(_) | Self::SequenceOf { .. } | Self::SetOf { .. } => quote! {},
		}
	}

	fn contract(&self) -> TsText {
		let collection = match self {
			Self::Value(path) => {
				let contract = quote! { <#path as ::tightbeam_asn::__private::JsLeaf>::CONTRACT };
				return TsText::of_const(quote! { ::tightbeam_asn::__private::TsSection::doc_line(#contract) });
			}
			Self::Vec(_) => "Carries a SEQUENCE OF Sequence field as a JavaScript Array.",
			Self::SetOfVec(_) => "Carries a SET OF Sequence field as a JavaScript Array.",
			Self::SequenceOf { .. } => "Carries a bounded SEQUENCE OF Sequence field as a JavaScript Array.",
			Self::SetOf { .. } => "Carries a bounded SET OF Sequence field as a JavaScript Array.",
		};

		TsText::from(String::from(collection))
	}

	/// The one conversion from a `JsValue` local named `value`, as an
	/// expression of type `Result<T, FieldError>`.
	fn quote_from_value(&self, value: &Ident) -> TokenStream2 {
		match self {
			Self::Value(path) => quote! { <#path as ::tightbeam_asn::__private::JsLeaf>::read(&#value) },
			Self::Vec(inner) => {
				let empty = quote! { ::std::vec::Vec::new() };
				let collection = Collection { empty, add: quote! { collection.push(item) } };
				Self::quote_collect(inner, value, &collection)
			}
			Self::SetOfVec(inner) => {
				let empty = quote! { ::std::vec::Vec::new() };
				let collection = Collection { empty, add: quote! { collection.push(item) } };
				let items = Self::quote_collect(inner, value, &collection);
				quote! {
					(#items).and_then(|items| {
						::core::convert::TryFrom::try_from(items).map_err(::tightbeam_asn::FieldError::from)
					})
				}
			}
			Self::SequenceOf { inner, len } => {
				let empty = quote! { ::der::asn1::SequenceOf::<_, #len>::new() };
				let collection = Collection { empty, add: quote! { collection.add(item)? } };
				Self::quote_collect(inner, value, &collection)
			}
			Self::SetOf { inner, len } => {
				let empty = quote! { ::der::asn1::SetOf::<_, #len>::new() };
				let collection = Collection { empty, add: quote! { collection.insert(item)? } };
				Self::quote_collect(inner, value, &collection)
			}
		}
	}

	/// Fill a collection from a JS `Array`, as an expression of type
	/// `Result<T, FieldError>`. The collection itself decides what it holds, so
	/// a bounded one refuses overflow as der does.
	fn quote_collect(inner: &Self, value: &Ident, collection: &Collection) -> TokenStream2 {
		let Collection { empty, add } = collection;
		let entry = format_ident!("entry");
		let from_entry = inner.quote_from_value(&entry);
		quote! {
			{
				let collect = || -> ::core::result::Result<_, ::tightbeam_asn::FieldError> {
					let array = ::tightbeam_asn::__private::JsField::from(&#value).array()?;
					let mut collection = #empty;
					for index in 0..array.length() {
						let #entry = array.get(index);
						let item = (#from_entry).map_err(|error| error.at(index))?;
						#add;
					}

					::core::result::Result::Ok(collection)
				};

				collect()
			}
		}
	}

	/// The one conversion from a reference local named `value` to a `JsValue`.
	fn quote_to_value(&self, value: &Ident) -> TokenStream2 {
		match self {
			Self::Value(path) => quote! { <#path as ::tightbeam_asn::__private::JsLeaf>::project(#value)? },
			Self::Vec(inner) | Self::SetOfVec(inner) | Self::SequenceOf { inner, .. } | Self::SetOf { inner, .. } => {
				let item = format_ident!("item");
				let to_item = inner.quote_to_value(&item);
				quote! {
					{
						let array = ::tightbeam_asn::__private::JsList::default();
						for #item in #value.iter() {
							let nested = #to_item;
							array.push(&nested);
						}

						::wasm_bindgen::JsValue::from(array)
					}
				}
			}
		}
	}
}

/// How the read of one collection kind starts it and adds an item to it.
struct Collection {
	/// The expression of the empty collection.
	empty: TokenStream2,
	/// The statement that adds `item` to `collection`.
	add: TokenStream2,
}

/// The path of a field type, the one form of type a field kind is read from.
struct TypePath(Path);

impl TryFrom<&Type> for TypePath {
	type Error = Error;

	/// Refuse a type that is no plain path, such as a tuple or a qualified
	/// path.
	fn try_from(ty: &Type) -> Result<Self> {
		let Type::Path(type_path) = ty else {
			return Err(Error::new(ty.span(), FIELD_KIND_HELP));
		};
		if type_path.qself.is_some() {
			return Err(Error::new(ty.span(), FIELD_KIND_HELP));
		}

		Ok(Self(type_path.path.clone()))
	}
}

impl ToTokens for TypePath {
	fn to_tokens(&self, tokens: &mut TokenStream2) {
		self.0.to_tokens(tokens);
	}
}

impl TypePath {
	/// The one type argument of the last segment, when that segment is `name`.
	fn wrapped(&self, name: &str) -> Option<&Type> {
		let segment = self.0.segments.last()?;
		if segment.ident != name {
			return None;
		}

		let PathArguments::AngleBracketed(args) = &segment.arguments else {
			return None;
		};
		if args.args.len() != 1 {
			return None;
		}

		match &args.args[0] {
			GenericArgument::Type(ty) => Some(ty),
			_ => None,
		}
	}

	/// The type and the length argument of the last segment, when that
	/// segment is `name`.
	fn bounded(&self, name: &str) -> Option<(&Type, Expr)> {
		let segment = self.0.segments.last()?;
		if segment.ident != name {
			return None;
		}

		let PathArguments::AngleBracketed(args) = &segment.arguments else {
			return None;
		};
		if args.args.len() != 2 {
			return None;
		}

		let GenericArgument::Type(inner) = &args.args[0] else {
			return None;
		};

		let len = Self::length(&args.args[1])?;
		Some((inner, len))
	}

	/// The length expression of `argument`, from a const argument or a const
	/// parameter name.
	fn length(argument: &GenericArgument) -> Option<Expr> {
		match argument {
			GenericArgument::Const(expr) => Some(expr.clone()),
			GenericArgument::Type(Type::Path(type_path)) => {
				let ident = type_path.path.get_ident()?;
				Some(Expr::Path(ExprPath {
					attrs: Vec::new(),
					qself: None,
					path: ident.clone().into(),
				}))
			}
			_ => None,
		}
	}

	/// Whether a segment carries generic arguments.
	fn has_generics(&self) -> bool {
		self.0
			.segments
			.iter()
			.any(|segment| !matches!(segment.arguments, PathArguments::None))
	}
}

/// The help that a refused enum shape names.
const ENUM_SHAPE_HELP: &str =
	"AsnCodec enums must be #[repr(u8)] Enumerated unit variants or Choice single-field tuple variants";

/// The kind of enum the derive expands, read once from its variants.
enum Shape {
	/// Every variant is a unit, as an ASN.1 ENUMERATED. Each discriminant
	/// sits in declaration order, and an implicit one follows its
	/// predecessor, as in Rust.
	Enumerated(Vec<u8>),
	/// Every variant carries one value, as an ASN.1 CHOICE: the name of each
	/// variant and the type of its value.
	Choice(Vec<(Ident, Type)>),
}

impl Shape {
	/// Classify `data` by its first variant, and refuse a variant of another
	/// form than the first.
	///
	/// # Errors
	///
	/// - The [`Error`] of an enum with no variant, or of a variant that breaks the form of the first.
	/// - The [`Error`] of an Enumerated discriminant that is no integer literal, or that falls past `u8`.
	fn classify(data: &DataEnum) -> Result<Self> {
		let Some(first) = data.variants.first() else {
			return Err(Error::new(data.enum_token.span(), ENUM_SHAPE_HELP));
		};

		if matches!(first.fields, Fields::Unit) {
			return Self::enumerated(data);
		}

		Self::choice(data)
	}

	/// The discriminant of each unit variant of `data`.
	fn enumerated(data: &DataEnum) -> Result<Self> {
		let mut discriminants = Vec::with_capacity(data.variants.len());
		let mut next = Some(0_u8);
		for variant in &data.variants {
			if !matches!(variant.fields, Fields::Unit) {
				return Err(Error::new(variant.span(), ENUM_SHAPE_HELP));
			}

			let value = match &variant.discriminant {
				None => {
					next.ok_or_else(|| Error::new(variant.span(), "AsnCodec Enumerated discriminants must fit u8"))?
				}
				Some((_, Expr::Lit(ExprLit { lit: Lit::Int(int), .. }))) => int.base10_parse::<u8>()?,
				Some((_, expr)) => {
					return Err(Error::new(
						expr.span(),
						"AsnCodec Enumerated discriminants must be integer literals",
					));
				}
			};

			discriminants.push(value);
			next = value.checked_add(1);
		}

		Ok(Self::Enumerated(discriminants))
	}

	/// The name and the value type of each single-field tuple variant of
	/// `data`.
	fn choice(data: &DataEnum) -> Result<Self> {
		let mut alternatives = Vec::with_capacity(data.variants.len());
		for variant in &data.variants {
			let Fields::Unnamed(fields) = &variant.fields else {
				return Err(Error::new(variant.span(), ENUM_SHAPE_HELP));
			};
			let mut values = fields.unnamed.iter();
			let (Some(value), None) = (values.next(), values.next()) else {
				return Err(Error::new(variant.span(), ENUM_SHAPE_HELP));
			};

			alternatives.push((variant.ident.clone(), value.ty.clone()));
		}

		Ok(Self::Choice(alternatives))
	}

	/// The codec of an enum of this shape.
	fn codec(self, input: &DeriveInput, js_name: JsName) -> Result<Codec> {
		match self {
			Self::Enumerated(discriminants) => Codec::enumerated(input, &discriminants, js_name),
			Self::Choice(alternatives) => Codec::choice(&alternatives, js_name),
		}
	}
}

#[cfg(test)]
mod tests {
	use syn::parse_quote;

	use super::*;
	use crate::field_key::PROTO_KEY_HELP;

	/// The expansion of `input`, as the derive entry builds it.
	fn expand(input: DeriveInput) -> Result<TokenStream2> {
		let codec = Codec::try_from(&input)?;
		Ok(codec.expand(&input.ident))
	}

	/// The variants of `input`, an enum.
	fn enum_data(input: DeriveInput) -> DataEnum {
		match input.data {
			Data::Enum(data) => data,
			_ => panic!("the input should be an enum"),
		}
	}

	/// The message of the refusal of the shape of `input`, an enum.
	fn shape_refusal(input: DeriveInput) -> Option<String> {
		let shape = Shape::classify(&enum_data(input));
		shape.err().map(|error| error.to_string())
	}

	/// Whether the TypeScript name rule refuses `name`.
	fn refuses_js_name(name: &str) -> bool {
		let literal = LitStr::new(name, proc_macro2::Span::call_site());
		JsName::try_from(literal).is_err()
	}

	#[test]
	fn a_sequence_field_takes_one_option() {
		let ty: Type = parse_quote!(Option<Vec<u8>>);
		assert!(matches!(Slot::try_from(&ty), Ok(Slot::Optional(FieldKind::Vec(_)))));
	}

	/// `shape` has no trace in the encoding when a value is absent.
	fn assert_untraceable(shape: Type) {
		let refusal = Slot::try_from(&shape).err().map(|error| error.to_string());
		assert_eq!(refusal.as_deref(), Some(NESTED_OPTION_HELP));
	}

	#[test]
	fn an_option_of_an_option_is_refused() {
		assert_untraceable(parse_quote!(Option<Option<u8>>));
	}

	#[test]
	fn a_vec_of_options_is_refused() {
		assert_untraceable(parse_quote!(Vec<Option<u8>>));
	}

	#[test]
	fn a_set_of_vec_of_options_is_refused() {
		assert_untraceable(parse_quote!(SetOfVec<Option<u8>>));
	}

	#[test]
	fn a_sequence_of_options_is_refused() {
		assert_untraceable(parse_quote!(SequenceOf<Option<u8>, 3>));
	}

	#[test]
	fn a_set_of_options_is_refused() {
		assert_untraceable(parse_quote!(SetOf<Option<u8>, 2>));
	}

	#[test]
	fn an_option_deep_inside_an_option_is_refused() {
		assert_untraceable(parse_quote!(Option<Vec<Option<u8>>>));
	}

	#[test]
	fn a_qualified_field_type_is_refused() {
		let ty: Type = parse_quote!(<Doc as Wire>::Body);
		let refusal = FieldKind::try_from(&ty).err().map(|error| error.to_string());
		assert_eq!(refusal.as_deref(), Some(FIELD_KIND_HELP));
	}

	#[test]
	fn a_generic_field_type_is_refused() {
		let ty: Type = parse_quote!(Box<Doc>);
		let refusal = FieldKind::try_from(&ty).err().map(|error| error.to_string());
		assert_eq!(refusal.as_deref(), Some(FIELD_KIND_HELP));
	}

	#[test]
	fn a_choice_payload_takes_no_option() {
		let ty: Type = parse_quote!(Option<u8>);
		assert!(FieldKind::try_from(&ty).is_err());
	}

	#[test]
	fn an_enum_mixing_unit_and_tuple_variants_is_refused() {
		let unit_first = shape_refusal(parse_quote! { enum Request { Ping, List(Body) } });
		let tuple_first = shape_refusal(parse_quote! { enum Request { List(Body), Ping } });

		let refusals = [unit_first.as_deref(), tuple_first.as_deref()];
		assert_eq!(refusals, [Some(ENUM_SHAPE_HELP); 2]);
	}

	#[test]
	fn a_choice_variant_of_two_values_is_refused() {
		let refusal = shape_refusal(parse_quote! { enum Request { List(Body, Pad) } });
		assert_eq!(refusal.as_deref(), Some(ENUM_SHAPE_HELP));
	}

	#[test]
	fn a_js_name_that_is_no_typescript_identifier_is_refused() {
		let refused = [
			refuses_js_name(""),
			refuses_js_name("9Lives"),
			refuses_js_name("Two Words"),
			refuses_js_name("Kebab-Case"),
			refuses_js_name("Café"),
			refuses_js_name("class"),
			refuses_js_name("string"),
		];
		assert_eq!(refused, [true; 7]);
	}

	#[test]
	fn a_rust_name_that_names_no_typescript_type_is_refused() {
		let input: DeriveInput = parse_quote! { struct string { title: String } };
		assert!(Codec::try_from(&input).is_err());
	}

	#[test]
	fn a_raw_rust_name_declares_the_name_without_its_prefix() {
		let input: DeriveInput = parse_quote! { struct r#Doc { title: String } };
		let name = Codec::try_from(&input).map(|codec| codec.js_name.as_str().to_owned());
		assert_eq!(name.ok().as_deref(), Some("Doc"));
	}

	#[test]
	fn a_tuple_choice_payload_is_refused() {
		let input: DeriveInput = parse_quote! { enum Request { List((u8, u8)) } };
		assert!(expand(input).is_err());
	}

	#[test]
	fn a_generic_type_is_refused_at_derive() {
		let input: DeriveInput = parse_quote! { struct Wrapper<T> { value: T } };
		assert!(expand(input).is_err());
	}

	#[test]
	fn an_enumerated_union_lists_each_discriminant() {
		let data = enum_data(parse_quote! { enum Status { Ok, Late = 4, Next } });
		let shape = Shape::classify(&data);
		assert!(matches!(shape, Ok(Shape::Enumerated(discriminants)) if discriminants == [0, 4, 5]));
	}

	#[test]
	fn a_discriminant_past_u8_is_refused() {
		let data = enum_data(parse_quote! { enum Status { Top = 255, Over } });
		assert!(Shape::classify(&data).is_err());
	}

	#[test]
	fn a_js_name_in_a_second_attribute_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[asn_codec(js_name = "First")]
			#[asn_codec(js_name = "Second")]
			struct Doc { title: String }
		};
		assert!(Codec::try_from(&input).is_err());
	}

	#[test]
	fn a_js_name_set_twice_in_one_attribute_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[asn_codec(js_name = "First", js_name = "Second")]
			struct Doc { title: String }
		};
		assert!(Codec::try_from(&input).is_err());
	}

	#[test]
	fn an_unknown_key_in_a_later_attribute_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[asn_codec(js_name = "Doc")]
			#[asn_codec(unknown = "value")]
			struct Doc { title: String }
		};
		assert!(Codec::try_from(&input).is_err());
	}

	#[test]
	fn a_computed_discriminant_is_refused() {
		let data = enum_data(parse_quote! { enum Status { Ok = 1 + 1 } });
		assert!(Shape::classify(&data).is_err());
	}

	/// The message of the refusal of `input`.
	fn refusal(input: DeriveInput) -> Option<String> {
		Codec::try_from(&input).err().map(|error| error.to_string())
	}

	#[test]
	fn an_asn_codec_attribute_on_a_member_is_refused() {
		let field = refusal(parse_quote! {
			struct Doc {
				#[asn_codec(js_name = "Heading")]
				title: String,
			}
		});
		let unit_variant = refusal(parse_quote! {
			#[repr(u8)]
			enum Status {
				#[asn_codec(js_name = "Done")]
				Ok,
			}
		});
		let choice_variant = refusal(parse_quote! {
			enum Request {
				#[asn_codec(unknown = "value")]
				List(Body),
			}
		});
		let choice_value = refusal(parse_quote! {
			enum Request {
				List(#[asn_codec(js_name = "Page")] Body),
			}
		});
		let tuple_field = refusal(parse_quote! {
			struct Doc(#[asn_codec(js_name = "Heading")] String);
		});
		let variant_field = refusal(parse_quote! {
			enum Request {
				List {
					#[asn_codec(js_name = "Page")]
					body: Body,
				},
			}
		});
		let union_field = refusal(parse_quote! {
			union Word {
				#[asn_codec(js_name = "Byte")]
				byte: u8,
			}
		});

		let refusals = [
			field,
			unit_variant,
			choice_variant,
			choice_value,
			tuple_field,
			variant_field,
			union_field,
		];
		assert_eq!(refusals.each_ref().map(Option::as_deref), [Some(MEMBER_OPTIONS_HELP); 7]);
	}

	#[test]
	fn a_member_named_proto_is_refused() {
		let field = refusal(parse_quote! { struct Doc { __proto__: String } });
		let raw_field = refusal(parse_quote! { struct Doc { r#__proto__: String } });
		let variant = refusal(parse_quote! { enum Request { __proto__(Body) } });

		let refusals = [field, raw_field, variant];
		assert_eq!(refusals.each_ref().map(Option::as_deref), [Some(PROTO_KEY_HELP); 3]);
	}
}
