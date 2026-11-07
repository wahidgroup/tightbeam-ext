//! Derive macros for [`tightbeam-asn`](https://docs.rs/tightbeam-asn).
//!
//! `#[derive(AsnCodec)]` implements JS conversion for Sequence structs,
//! `#[repr(u8)]` Enumerated enums, and Choice enums. On `wasm32`, the derive
//! also emits `encode{Name}` and `decode{Name}` wasm-bindgen exports, typed by
//! the TypeScript shape the same expansion declares.

mod js_name;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::token::Comma;
use syn::{
	parse_macro_input, Data, DataEnum, DataStruct, DeriveInput, Error, Expr, ExprLit, Field, Fields, GenericArgument,
	Ident, Lit, LitStr, Path, PathArguments, Result, Type,
};

use crate::js_name::JsName;

/// Marks a `der` wire type as an ASN codec endpoint for TypeScript.
///
/// Optional `#[asn_codec(js_name = "...")]` sets the wasm export basename and
/// the name of the declared type. That name, or the Rust name without it, is
/// an ASCII TypeScript identifier that can name a type.
#[proc_macro_derive(AsnCodec, attributes(asn_codec))]
pub fn derive_asn_codec(input: TokenStream) -> TokenStream {
	let input = parse_macro_input!(input as DeriveInput);
	let codec = Codec::try_from(&input);
	match codec {
		Ok(codec) => codec.expand(&input.ident).into(),
		Err(error) => error.to_compile_error().into(),
	}
}

/// One wire type's conversions and its TypeScript declaration.
struct Codec {
	js_name: JsName,
	ts_section: String,
	from_js: TokenStream2,
	to_js: TokenStream2,
	checks: TokenStream2,
}

impl TryFrom<&DeriveInput> for Codec {
	type Error = Error;

	fn try_from(input: &DeriveInput) -> Result<Self> {
		if !input.generics.params.is_empty() {
			let refusal = "AsnCodec wire types take no generic parameters";
			return Err(Error::new(input.generics.span(), refusal));
		}

		let js_name = match input.js_name()? {
			Some(js_name) => js_name,
			None => JsName::of(&input.ident)?,
		};
		let mut codec = match &input.data {
			Data::Struct(data) => Self::sequence(input, data, js_name)?,
			Data::Enum(data) => Shape::classify(data)?.codec(input, js_name)?,
			Data::Union(_) => return Err(Error::new(input.span(), "AsnCodec supports structs and enums")),
		};

		// A field names its nested type by the Rust ident, so a renamed type
		// answers to both names.
		let rust_name = input.ident.to_string();
		if codec.js_name.as_str() != rust_name {
			let alias_name = JsName::of(&input.ident)?;
			let alias = format!("\n\nexport type {} = {};", alias_name.as_str(), codec.js_name.as_str());
			codec.ts_section.push_str(&alias);
		}

		Ok(codec)
	}
}

impl Codec {
	fn sequence(input: &DeriveInput, data: &DataStruct, js_name: JsName) -> Result<Self> {
		let Fields::Named(fields) = &data.fields else {
			return Err(Error::new(input.span(), "AsnCodec supports structs with named fields"));
		};

		let FieldEmit { reads, writes, names, ts_fields, checks } = FieldEmit::collect(&fields.named)?;

		let ts_section = format!("export interface {} {{\n{}\n}}", js_name.as_str(), ts_fields.join("\n"));
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

		Ok(Self { js_name, ts_section, from_js, to_js, checks: quote! { #(#checks)* } })
	}

	fn enumerated(input: &DeriveInput, discriminants: &[u8], js_name: JsName) -> Result<Self> {
		input.ensure_repr_u8()?;

		let literals: Vec<String> = discriminants.iter().map(u8::to_string).collect();
		let ts_section = format!("export type {} = {};", js_name.as_str(), literals.join(" | "));
		let from_js = quote! {
			let discriminant = ::tightbeam_asn::__private::JsField::from(__source).u8()?;
			::core::result::Result::Ok(::core::convert::TryFrom::try_from(discriminant)?)
		};
		let to_js = quote! {
			::tightbeam_asn::__private::JsProjection::project(&(*self as ::core::primitive::u8))
		};

		Ok(Self { js_name, ts_section, from_js, to_js, checks: quote! {} })
	}

	fn choice(alternatives: &[(Ident, Type)], js_name: JsName) -> Result<Self> {
		let mut from_arms = Vec::new();
		let mut to_arms = Vec::new();
		let mut ts_variants = Vec::new();
		let mut checks = Vec::new();

		for (variant_ident, ty) in alternatives {
			let variant_name = variant_ident.to_string();
			let kind = FieldKind::try_from(ty)?;
			let present = format_ident!("present");
			let from_present = kind.quote_from_value(&present);
			let value = format_ident!("payload");
			let to_value = kind.quote_to_value(&value);

			from_arms.push(quote! {
				#variant_name => {
					let convert = || -> ::core::result::Result<#ty, ::tightbeam_asn::FieldError> {
						::core::result::Result::Ok(#from_present)
					};
					let payload = convert().map_err(|error| error.within(#variant_name))?;
					::core::result::Result::Ok(Self::#variant_ident(payload))
				}
			});
			to_arms.push(quote! {
				Self::#variant_ident(#value) => {
					let nested = #to_value;
					__object.set(#variant_name, &nested)?;
				}
			});
			ts_variants.push(format!("{{ {variant_name}: {} }}", kind.ts_type()?));
			checks.push(kind.quote_checks());
		}

		let ts_section = format!("export type {} =\n\t| {};", js_name.as_str(), ts_variants.join("\n\t| "));
		let from_js = quote! {
			let (key, present) = ::tightbeam_asn::__private::JsField::from(__source).single_entry()?;
			match key.as_str() {
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

		Ok(Self { js_name, ts_section, from_js, to_js, checks: quote! { #(#checks)* } })
	}

	/// The sealed `AsnCodec` impl on every target, and on `wasm32` the JS
	/// conversions and the typed `encode` and `decode` exports.
	fn expand(self, name: &Ident) -> TokenStream2 {
		let Self { js_name, ts_section, from_js, to_js, checks } = self;
		let js_name = js_name.as_str();
		let encode_js_name = format!("encode{js_name}");
		let decode_js_name = format!("decode{js_name}");
		let encode_fn = format_ident!("__asn_encode_{name}");
		let decode_fn = format_ident!("__asn_decode_{name}");
		let section_ident = format_ident!("__ASN_TS_{name}");
		let carrier = format_ident!("__AsnJs{name}");

		quote! {
			impl ::tightbeam_asn::__private::Sealed for #name {}

			#checks

			#[cfg(not(target_arch = "wasm32"))]
			impl ::tightbeam_asn::AsnCodec for #name {}

			#[cfg(target_arch = "wasm32")]
			#[automatically_derived]
			#[allow(clippy::needless_question_mark)]
			impl ::tightbeam_asn::AsnCodec for #name {
				fn from_js(
					__source: &::wasm_bindgen::JsValue,
				) -> ::core::result::Result<Self, ::tightbeam_asn::FieldError> {
					#from_js
				}

				fn to_js(&self) -> ::core::result::Result<::wasm_bindgen::JsValue, ::tightbeam_asn::FieldError> {
					#to_js
				}
			}

			#[cfg(target_arch = "wasm32")]
			const _: () = {
				use ::der::{Decode, Encode};
				use ::wasm_bindgen::prelude::*;
				use ::wasm_bindgen::JsCast;

				#[wasm_bindgen(typescript_custom_section)]
				const #section_ident: &'static str = #ts_section;

				#[wasm_bindgen]
				extern "C" {
					#[wasm_bindgen(typescript_type = #js_name)]
					pub type #carrier;
				}

				#[wasm_bindgen(js_name = #encode_js_name)]
				pub fn #encode_fn(
					value: #carrier,
				) -> ::core::result::Result<::std::vec::Vec<u8>, ::wasm_bindgen::JsValue> {
					let message = <#name as ::tightbeam_asn::AsnCodec>::from_js(&value).map_err(::wasm_bindgen::JsValue::from)?;
					message.to_der().map_err(|error| ::wasm_bindgen::JsValue::from(::tightbeam_asn::__private::WireError(error)))
				}

				#[wasm_bindgen(js_name = #decode_js_name)]
				pub fn #decode_fn(
					bytes: &[u8],
				) -> ::core::result::Result<#carrier, ::wasm_bindgen::JsValue> {
					let message = <#name as ::der::Decode>::from_der(bytes).map_err(|error| ::wasm_bindgen::JsValue::from(::tightbeam_asn::__private::WireError(error)))?;
					let value = <#name as ::tightbeam_asn::AsnCodec>::to_js(&message).map_err(::wasm_bindgen::JsValue::from)?;
					::core::result::Result::Ok(value.unchecked_into())
				}
			};
		}
	}
}

struct FieldEmit {
	reads: Vec<TokenStream2>,
	writes: Vec<TokenStream2>,
	names: Vec<TokenStream2>,
	ts_fields: Vec<String>,
	checks: Vec<TokenStream2>,
}

impl FieldEmit {
	fn collect(fields: &Punctuated<Field, Comma>) -> Result<Self> {
		let mut emit = Self {
			reads: Vec::new(),
			writes: Vec::new(),
			names: Vec::new(),
			ts_fields: Vec::new(),
			checks: Vec::new(),
		};

		for field in fields {
			let field_name = field
				.ident
				.as_ref()
				.ok_or_else(|| Error::new(field.span(), "expected named field"))?;
			let field_key = field_name.to_string();
			let slot = Slot::try_from(&field.ty)?;
			let mut doc_lines = field.doc_lines();
			if doc_lines.is_empty() {
				doc_lines.push(slot.jsdoc_contract().to_owned());
			}

			emit.reads.push(slot.quote_read(field_name, &field.ty, &field_key));
			emit.writes.push(slot.quote_write(field_name, &field_key));
			emit.names.push(quote! { #field_name });
			emit.ts_fields.push(slot.ts_property(&field_key, &doc_lines)?);
			emit.checks.push(slot.kind().quote_checks());
		}

		Ok(emit)
	}
}

/// The doc lines of a field, which its TypeScript declaration carries.
trait DocLines {
	/// Each `///` line, with its one leading space removed.
	fn doc_lines(&self) -> Vec<String>;
}

impl DocLines for Field {
	fn doc_lines(&self) -> Vec<String> {
		let mut lines = Vec::new();
		for attr in &self.attrs {
			if !attr.path().is_ident("doc") {
				continue;
			}
			let Ok(meta) = attr.meta.require_name_value() else {
				continue;
			};
			let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(lit), .. }) = &meta.value else {
				continue;
			};
			let value = lit.value();
			let text = match value.strip_prefix(' ') {
				Some(stripped) => stripped,
				None => value.as_str(),
			};
			if !text.is_empty() {
				lines.push(text.to_owned());
			}
		}
		lines
	}
}

/// How a Sequence field carries its [`FieldKind`].
///
/// OPTIONAL lives here and not on [`FieldKind`], because der encodes `None` as
/// zero bytes. Inside a collection or another OPTIONAL an absent value would
/// leave no trace on the wire, so those shapes have no representation.
enum Slot {
	Required(FieldKind),
	Optional(FieldKind),
}

impl TryFrom<&Type> for Slot {
	type Error = Error;

	fn try_from(ty: &Type) -> Result<Self> {
		let Type::Path(type_path) = ty else {
			return Err(Error::new(ty.span(), FIELD_KIND_HELP));
		};

		let Some(inner_ty) = type_path.path.single_type_arg("Option") else {
			return Ok(Self::Required(FieldKind::try_from(ty)?));
		};

		match FieldKind::try_from(inner_ty)? {
			// JS `null` is both NULL and absent, so `Some(Null)` reads back as
			// `None`.
			FieldKind::Null => Err(Error::new(ty.span(), UNTRACEABLE_OPTION_HELP)),
			kind => Ok(Self::Optional(kind)),
		}
	}
}

impl Slot {
	fn kind(&self) -> &FieldKind {
		match self {
			Self::Required(kind) | Self::Optional(kind) => kind,
		}
	}

	fn ts_property(&self, field_key: &str, doc_lines: &[String]) -> Result<String> {
		let field_decl = match self {
			Self::Required(kind) => format!("{field_key}: {}", kind.ts_type()?),
			Self::Optional(kind) => format!("{field_key}?: {} | null", kind.ts_type()?),
		};

		let mut out = String::from("\t/**\n");
		for line in doc_lines {
			out.push_str("\t * ");
			out.push_str(line);
			out.push('\n');
		}
		out.push_str("\t */\n\t");
		out.push_str(&field_decl);
		out.push(';');

		Ok(out)
	}

	fn jsdoc_contract(&self) -> &'static str {
		match self {
			Self::Required(kind) => kind.jsdoc_contract(),
			Self::Optional(_) => {
				"Carries an OPTIONAL Sequence field. Nullish JS values map to None, and a present value maps to Some."
			}
		}
	}

	/// Read one field. Every kind passes through
	/// [`FieldKind::quote_from_value`], so a missing key fails as a wrong
	/// value.
	fn quote_read(&self, field_name: &Ident, ty: &Type, field_key: &str) -> TokenStream2 {
		let present = format_ident!("present");
		let from_present = self.kind().quote_from_value(&present);
		let converted = match self {
			Self::Required(_) => from_present,
			Self::Optional(_) => quote! {
				if #present.is_undefined() || #present.is_null() {
					::core::option::Option::None
				} else {
					::core::option::Option::Some(#from_present)
				}
			},
		};

		quote! {
			let #field_name: #ty = {
				let #present = __fields.get(#field_key)?;
				let convert = || -> ::core::result::Result<#ty, ::tightbeam_asn::FieldError> {
					::core::result::Result::Ok(#converted)
				};
				convert().map_err(|error| error.within(#field_key))?
			};
		}
	}

	/// Write one field. An absent OPTIONAL leaves its key off the object.
	fn quote_write(&self, field_name: &Ident, field_key: &str) -> TokenStream2 {
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

enum FieldKind {
	Bool,
	Null,
	U8,
	U16,
	U32,
	U64,
	I8,
	I16,
	I32,
	I64,
	String,
	Ia5String,
	PrintableString,
	TeletexString,
	BmpString,
	OctetString,
	BitString,
	ObjectIdentifier,
	Any,
	UtcTime,
	GeneralizedTime,
	Nested(Path),
	Vec(Box<FieldKind>),
	SetOfVec(Box<FieldKind>),
	SequenceOf { inner: Box<FieldKind>, len: Expr },
	SetOf { inner: Box<FieldKind>, len: Expr },
}

const FIELD_KIND_HELP: &str = "AsnCodec Sequence fields must be der-owned leaves (bool, Null, integers, string zoo, OctetString, BitString, ObjectIdentifier, Any, UtcTime, GeneralizedTime), nested AsnCodec, or Vec/SetOfVec/SequenceOf/SetOf over those types, optionally wrapped once in Option";

const NESTED_OPTION_HELP: &str = "AsnCodec takes Option only on a Sequence field: der encodes None as zero bytes, so it leaves no trace inside a collection, another Option, or a Choice";

const UNTRACEABLE_OPTION_HELP: &str =
	"AsnCodec refuses Option<Null>: JS null is both NULL and absent, so Some(Null) reads back as None";

impl TryFrom<&Type> for FieldKind {
	type Error = Error;

	fn try_from(ty: &Type) -> Result<Self> {
		let Type::Path(type_path) = ty else {
			return Err(Error::new(ty.span(), FIELD_KIND_HELP));
		};

		let path = &type_path.path;
		if path.single_type_arg("Option").is_some() {
			return Err(Error::new(ty.span(), NESTED_OPTION_HELP));
		}
		if let Some(inner_ty) = path.single_type_arg("Vec") {
			return Ok(Self::Vec(Box::new(Self::try_from(inner_ty)?)));
		}
		if let Some(inner_ty) = path.single_type_arg("SetOfVec") {
			return Ok(Self::SetOfVec(Box::new(Self::try_from(inner_ty)?)));
		}
		if let Some((inner_ty, len)) = path.type_and_const_args("SequenceOf") {
			return Ok(Self::SequenceOf { inner: Box::new(Self::try_from(inner_ty)?), len });
		}
		if let Some((inner_ty, len)) = path.type_and_const_args("SetOf") {
			return Ok(Self::SetOf { inner: Box::new(Self::try_from(inner_ty)?), len });
		}

		Self::leaf(ty, path)
	}
}

impl FieldKind {
	fn leaf(ty: &Type, path: &Path) -> Result<Self> {
		if path.has_generics() {
			return Err(Error::new(ty.span(), FIELD_KIND_HELP));
		}

		let name = path.ts_name()?;
		let kind = match name.as_str() {
			"bool" => Self::Bool,
			"Null" => Self::Null,
			"u8" => Self::U8,
			"u16" => Self::U16,
			"u32" => Self::U32,
			"u64" => Self::U64,
			"i8" => Self::I8,
			"i16" => Self::I16,
			"i32" => Self::I32,
			"i64" => Self::I64,
			"String" => Self::String,
			"Ia5String" => Self::Ia5String,
			"PrintableString" => Self::PrintableString,
			"TeletexString" => Self::TeletexString,
			"BmpString" => Self::BmpString,
			"OctetString" => Self::OctetString,
			"BitString" => Self::BitString,
			"ObjectIdentifier" => Self::ObjectIdentifier,
			"Any" => Self::Any,
			"UtcTime" => Self::UtcTime,
			"GeneralizedTime" => Self::GeneralizedTime,
			_ => Self::Nested(path.clone()),
		};

		Ok(kind)
	}

	fn ts_type(&self) -> Result<String> {
		match self {
			Self::Bool => Ok("boolean".into()),
			Self::Null => Ok("null".into()),
			Self::U8 | Self::U16 | Self::U32 | Self::I8 | Self::I16 | Self::I32 => Ok("number".into()),
			Self::U64 | Self::I64 => Ok("bigint".into()),
			Self::String
			| Self::Ia5String
			| Self::PrintableString
			| Self::TeletexString
			| Self::BmpString
			| Self::ObjectIdentifier
			| Self::UtcTime
			| Self::GeneralizedTime => Ok("string".into()),
			Self::OctetString | Self::Any => Ok("Uint8Array".into()),
			Self::BitString => Ok("{ unusedBits: number; bytes: Uint8Array }".into()),
			Self::Nested(path) => path.ts_name(),
			Self::Vec(inner) | Self::SetOfVec(inner) | Self::SequenceOf { inner, .. } | Self::SetOf { inner, .. } => {
				let inner_ts = inner.ts_type()?;
				Ok(format!("{inner_ts}[]"))
			}
		}
	}

	fn jsdoc_contract(&self) -> &'static str {
		match self {
			Self::Bool => "Carries a BOOLEAN Sequence field as a JavaScript boolean.",
			Self::Null => "Carries a NULL Sequence field as JavaScript null.",
			Self::U8 => "Carries an INTEGER field in the inclusive u8 range.",
			Self::U16 => "Carries an INTEGER field in the inclusive u16 range.",
			Self::U32 => "Carries an INTEGER field in the inclusive u32 range.",
			Self::U64 => "Carries an INTEGER field as a JavaScript bigint in the inclusive u64 range.",
			Self::I8 => "Carries an INTEGER field in the inclusive i8 range.",
			Self::I16 => "Carries an INTEGER field in the inclusive i16 range.",
			Self::I32 => "Carries an INTEGER field in the inclusive i32 range.",
			Self::I64 => "Carries an INTEGER field as a JavaScript bigint in the inclusive i64 range.",
			Self::String => "Carries a UTF-8 string Sequence field.",
			Self::Ia5String => "Carries an IA5String Sequence field validated by der.",
			Self::PrintableString => "Carries a PrintableString Sequence field validated by der.",
			Self::TeletexString => "Carries a TeletexString Sequence field validated by der.",
			Self::BmpString => "Carries a BmpString Sequence field validated by der.",
			Self::OctetString => "Carries an octet string Sequence field as Uint8Array.",
			Self::BitString => "Carries a BIT STRING Sequence field as unusedBits plus bytes.",
			Self::ObjectIdentifier => "Carries an OBJECT IDENTIFIER Sequence field as a dotted string.",
			Self::Any => "Carries an ANY Sequence field as opaque DER bytes.",
			Self::UtcTime => "Carries a UTCTime Sequence field as a YYYY-MM-DDTHH:MM:SSZ string, from 1970 to 2049.",
			Self::GeneralizedTime => {
				"Carries a GeneralizedTime Sequence field as a YYYY-MM-DDTHH:MM:SSZ string, from 1970 to 9999."
			}
			Self::Nested(_) => "Carries a nested AsnCodec value for this Sequence field.",
			Self::Vec(_) => "Carries a SEQUENCE OF Sequence field as a JavaScript Array.",
			Self::SetOfVec(_) => "Carries a SET OF Sequence field as a JavaScript Array.",
			Self::SequenceOf { .. } => "Carries a bounded SEQUENCE OF Sequence field as a JavaScript Array.",
			Self::SetOf { .. } => "Carries a bounded SET OF Sequence field as a JavaScript Array.",
		}
	}

	/// Compile-time proof that each nested type carries the derive, on every
	/// target, so a wrong field fails where it is written.
	fn quote_checks(&self) -> TokenStream2 {
		match self {
			Self::Nested(path) => quote! {
				const _: () = ::tightbeam_asn::__private::assert_codec::<#path>();
			},
			Self::Vec(inner) | Self::SetOfVec(inner) | Self::SequenceOf { inner, .. } | Self::SetOf { inner, .. } => {
				inner.quote_checks()
			}
			_ => quote! {},
		}
	}

	/// The one conversion from a `JsValue` local named `value`. Each failure
	/// returns a [`FieldError`] through `?`.
	fn quote_from_value(&self, value: &Ident) -> TokenStream2 {
		match self {
			Self::Bool => quote! { ::tightbeam_asn::__private::JsField::from(&#value).bool()? },
			Self::Null => quote! { ::tightbeam_asn::__private::JsField::from(&#value).null()? },
			Self::U8 => quote! { ::tightbeam_asn::__private::JsField::from(&#value).u8()? },
			Self::U16 => quote! { ::tightbeam_asn::__private::JsField::from(&#value).u16()? },
			Self::U32 => quote! { ::tightbeam_asn::__private::JsField::from(&#value).u32()? },
			Self::U64 => quote! { ::tightbeam_asn::__private::JsField::from(&#value).u64()? },
			Self::I8 => quote! { ::tightbeam_asn::__private::JsField::from(&#value).i8()? },
			Self::I16 => quote! { ::tightbeam_asn::__private::JsField::from(&#value).i16()? },
			Self::I32 => quote! { ::tightbeam_asn::__private::JsField::from(&#value).i32()? },
			Self::I64 => quote! { ::tightbeam_asn::__private::JsField::from(&#value).i64()? },
			Self::String => quote! { ::tightbeam_asn::__private::JsField::from(&#value).string()? },
			Self::Ia5String => quote! { ::tightbeam_asn::__private::JsField::from(&#value).ia5_string()? },
			Self::PrintableString => quote! { ::tightbeam_asn::__private::JsField::from(&#value).printable_string()? },
			Self::TeletexString => quote! { ::tightbeam_asn::__private::JsField::from(&#value).teletex_string()? },
			Self::BmpString => quote! { ::tightbeam_asn::__private::JsField::from(&#value).bmp_string()? },
			Self::OctetString => quote! { ::tightbeam_asn::__private::JsField::from(&#value).octet_string()? },
			Self::BitString => quote! { ::tightbeam_asn::__private::JsField::from(&#value).bitstring()? },
			Self::ObjectIdentifier => quote! { ::tightbeam_asn::__private::JsField::from(&#value).oid()? },
			Self::Any => quote! { ::tightbeam_asn::__private::JsField::from(&#value).any()? },
			Self::UtcTime => quote! { ::tightbeam_asn::__private::JsField::from(&#value).utc_time()? },
			Self::GeneralizedTime => quote! { ::tightbeam_asn::__private::JsField::from(&#value).generalized_time()? },
			Self::Nested(path) => quote! { <#path as ::tightbeam_asn::AsnCodec>::from_js(&#value)? },
			Self::Vec(inner) => {
				let empty = quote! { ::std::vec::Vec::new() };
				Self::quote_collect(inner, value, &empty, &quote! { collection.push(item) })
			}
			Self::SetOfVec(inner) => {
				let empty = quote! { ::std::vec::Vec::new() };
				let items = Self::quote_collect(inner, value, &empty, &quote! { collection.push(item) });
				quote! { ::core::convert::TryFrom::try_from(#items)? }
			}
			Self::SequenceOf { inner, len } => {
				let empty = quote! { ::der::asn1::SequenceOf::<_, #len>::new() };
				Self::quote_collect(inner, value, &empty, &quote! { collection.add(item)? })
			}
			Self::SetOf { inner, len } => {
				let empty = quote! { ::der::asn1::SetOf::<_, #len>::new() };
				Self::quote_collect(inner, value, &empty, &quote! { collection.insert(item)? })
			}
		}
	}

	/// Fill a collection from a JS `Array`. The collection itself decides what
	/// it holds, so a bounded one refuses overflow as der does.
	fn quote_collect(inner: &Self, value: &Ident, empty: &TokenStream2, add: &TokenStream2) -> TokenStream2 {
		let entry = format_ident!("entry");
		let from_entry = inner.quote_from_value(&entry);

		quote! {
			{
				let array = ::tightbeam_asn::__private::JsField::from(&#value).array()?;
				let mut collection = #empty;
				for index in 0..array.length() {
					let #entry = array.get(index);
					let convert = || -> ::core::result::Result<_, ::tightbeam_asn::FieldError> {
						::core::result::Result::Ok(#from_entry)
					};
					let item = convert().map_err(|error| error.at(index))?;
					#add;
				}

				collection
			}
		}
	}

	/// The one conversion from a reference local named `value` to a `JsValue`.
	fn quote_to_value(&self, value: &Ident) -> TokenStream2 {
		match self {
			Self::Bool => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::Null => quote! { ::wasm_bindgen::JsValue::NULL },
			Self::U8 => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::U16 => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::U32 => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::U64 => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::I8 => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::I16 => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::I32 => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::I64 => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::String => quote! { ::wasm_bindgen::JsValue::from_str(#value.as_str()) },
			Self::Ia5String => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::PrintableString => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::TeletexString => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::BmpString => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::OctetString => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::BitString => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::ObjectIdentifier => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::Any => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::UtcTime => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::GeneralizedTime => quote! { ::tightbeam_asn::__private::JsProjection::project(#value)? },
			Self::Nested(path) => quote! { <#path as ::tightbeam_asn::AsnCodec>::to_js(#value)? },
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

/// What the derive reads from the path of a field type.
trait PathShape {
	/// The one type argument of the last segment, when that segment is `name`.
	fn single_type_arg(&self, name: &str) -> Option<&Type>;

	/// The type and the length argument of the last segment, when that
	/// segment is `name`.
	fn type_and_const_args(&self, name: &str) -> Option<(&Type, Expr)>;

	/// The TypeScript name of the type, its last segment.
	fn ts_name(&self) -> Result<String>;

	/// Whether a segment carries generic arguments.
	fn has_generics(&self) -> bool;
}

impl PathShape for Path {
	fn single_type_arg(&self, name: &str) -> Option<&Type> {
		let segment = self.segments.last()?;
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

	fn type_and_const_args(&self, name: &str) -> Option<(&Type, Expr)> {
		let segment = self.segments.last()?;
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

		let len = args.args[1].const_expr()?;
		Some((inner, len))
	}

	fn ts_name(&self) -> Result<String> {
		self.segments
			.last()
			.map(|segment| segment.ident.to_string())
			.ok_or_else(|| Error::new(self.span(), "expected type self"))
	}

	fn has_generics(&self) -> bool {
		self.segments
			.iter()
			.any(|segment| !matches!(segment.arguments, PathArguments::None))
	}
}

/// A generic argument the derive reads a length from.
trait ConstGeneric {
	/// The length expression, from a const argument or a const parameter name.
	fn const_expr(&self) -> Option<Expr>;
}

impl ConstGeneric for GenericArgument {
	fn const_expr(&self) -> Option<Expr> {
		match self {
			GenericArgument::Const(expr) => Some(expr.clone()),
			GenericArgument::Type(Type::Path(type_path)) => {
				let ident = type_path.path.get_ident()?;
				Some(Expr::Path(syn::ExprPath {
					attrs: Vec::new(),
					qself: None,
					path: ident.clone().into(),
				}))
			}
			_ => None,
		}
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
	/// - The enum has no variant, or a variant breaks the form of the first.
	/// - An Enumerated discriminant is no integer literal, or falls past `u8`.
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

/// The attributes of a deriving type that shape its codec.
trait CodecAttrs {
	/// Refuse an Enumerated type without `#[repr(u8)]`.
	fn ensure_repr_u8(&self) -> Result<()>;

	/// The wasm export basename that `#[asn_codec(js_name = "...")]` sets.
	fn js_name(&self) -> Result<Option<JsName>>;
}

impl CodecAttrs for DeriveInput {
	fn ensure_repr_u8(&self) -> Result<()> {
		for attr in &self.attrs {
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

		Err(Error::new(self.span(), "AsnCodec Enumerated requires #[repr(u8)]"))
	}

	fn js_name(&self) -> Result<Option<JsName>> {
		for attr in &self.attrs {
			let mut js_name = None;

			if !attr.path().is_ident("asn_codec") {
				continue;
			}

			attr.parse_nested_meta(|meta| {
				if meta.path.is_ident("js_name") {
					let value = meta.value()?;
					let literal: LitStr = value.parse()?;
					js_name = Some(JsName::try_from(literal)?);
					return Ok(());
				}

				Err(meta.error("unsupported asn_codec attribute"))
			})?;

			return Ok(js_name);
		}

		Ok(None)
	}
}

#[cfg(test)]
mod tests {
	use syn::parse_quote;

	use super::*;

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

	/// `shape` has no trace on the wire when a value is absent.
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
	fn an_option_of_null_is_refused() {
		let ty: Type = parse_quote!(Option<Null>);
		let refusal = Slot::try_from(&ty).err().map(|error| error.to_string());
		assert_eq!(refusal.as_deref(), Some(UNTRACEABLE_OPTION_HELP));
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
	fn a_renamed_rust_name_that_names_no_typescript_type_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[asn_codec(js_name = "Renamed")]
			struct string { title: String }
		};

		assert!(Codec::try_from(&input).is_err());
	}

	#[test]
	fn a_tuple_choice_payload_is_refused() {
		let input: DeriveInput = parse_quote! { enum Request { List((u8, u8)) } };
		assert!(expand(input).is_err());
	}

	#[test]
	fn a_choice_section_lists_each_variant() -> Result<()> {
		let input: DeriveInput = parse_quote! { enum Request { Register(RegisterBody), List(ListPad) } };
		let codec = Codec::try_from(&input)?;
		assert_eq!(
			codec.ts_section,
			"export type Request =\n\t| { Register: RegisterBody }\n\t| { List: ListPad };"
		);
		Ok(())
	}

	#[test]
	fn a_sequence_section_declares_each_field() -> Result<()> {
		let input: DeriveInput = parse_quote! {
			struct Doc {
				/// The title.
				title: String,
				/// The payload.
				body: OctetString,
				/// The tail.
				tail: BitString,
				/// The gap.
				gap: Null,
			}
		};

		let codec = Codec::try_from(&input)?;
		let expected = [
			"export interface Doc {",
			"\t/**\n\t * The title.\n\t */\n\ttitle: string;",
			"\t/**\n\t * The payload.\n\t */\n\tbody: Uint8Array;",
			"\t/**\n\t * The tail.\n\t */\n\ttail: { unusedBits: number; bytes: Uint8Array };",
			"\t/**\n\t * The gap.\n\t */\n\tgap: null;",
			"}",
		];
		assert_eq!(codec.ts_section, expected.join("\n"));
		Ok(())
	}

	#[test]
	fn an_export_carries_its_typescript_type() -> Result<()> {
		let input: DeriveInput = parse_quote! { struct Doc { title: String } };
		let expansion = expand(input)?.to_string();
		assert!(expansion.contains("typescript_type = \"Doc\""));
		Ok(())
	}

	#[test]
	fn a_generic_type_is_refused_at_derive() {
		let input: DeriveInput = parse_quote! { struct Wrapper<T> { value: T } };
		assert!(expand(input).is_err());
	}

	#[test]
	fn an_enumerated_union_lists_each_discriminant() {
		let data = enum_data(parse_quote! { enum Status { Ok = 0, Late = 4, Next } });
		let shape = Shape::classify(&data);
		assert!(matches!(shape, Ok(Shape::Enumerated(discriminants)) if discriminants == [0, 4, 5]));
	}

	#[test]
	fn a_discriminant_past_u8_is_refused() {
		let data = enum_data(parse_quote! { enum Status { Top = 255, Over } });
		assert!(Shape::classify(&data).is_err());
	}

	#[test]
	fn a_renamed_type_answers_to_its_rust_name() -> Result<()> {
		let input: DeriveInput = parse_quote! {
			#[asn_codec(js_name = "Renamed")]
			struct Doc { title: String }
		};

		let codec = Codec::try_from(&input)?;
		assert!(codec.ts_section.starts_with("export interface Renamed {"));
		assert!(codec.ts_section.ends_with("export type Doc = Renamed;"));
		Ok(())
	}

	#[test]
	fn a_computed_discriminant_is_refused() {
		let data = enum_data(parse_quote! { enum Status { Ok = 1 + 1 } });
		assert!(Shape::classify(&data).is_err());
	}

	#[test]
	fn an_optional_property_admits_null() -> Result<()> {
		let ty: Type = parse_quote!(Option<Vec<Record>>);
		let property = Slot::try_from(&ty)?.ts_property("deeper", &[String::from("Rows.")])?;
		assert!(property.ends_with("deeper?: Record[] | null;"));
		Ok(())
	}

	#[test]
	fn a_collection_property_nests_its_element() -> Result<()> {
		let ty: Type = parse_quote!(SequenceOf<u64, 3>);
		let property = Slot::try_from(&ty)?.ts_property("ids", &[String::from("Ids.")])?;
		assert!(property.ends_with("ids: bigint[];"));
		Ok(())
	}
}
