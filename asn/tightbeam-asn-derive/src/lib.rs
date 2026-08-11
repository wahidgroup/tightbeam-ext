//! Derive macros for [`tightbeam-asn`](https://docs.rs/tightbeam-asn).
//!
//! `#[derive(AsnCodec)]` implements JS conversion for Sequence structs,
//! `#[repr(u8)]` Enumerated enums, and Choice enums. On `wasm32`, the derive
//! emits `encode{Name}` / `decode{Name}` wasm-bindgen exports, TypeScript
//! shape sections, and a per-type `ASN_CODEC_TS` MessageCodec source fragment.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{
	parse_macro_input, Data, DataEnum, DeriveInput, Error, Expr, Field, Fields, GenericArgument, Ident, LitStr, Path,
	PathArguments, Result, Type,
};

/// Marks a `der` wire type as an ASN codec endpoint for TypeScript.
///
/// Optional `#[asn_codec(js_name = "...")]` sets the wasm export basename.
#[proc_macro_derive(AsnCodec, attributes(asn_codec))]
pub fn derive_asn_codec(input: TokenStream) -> TokenStream {
	let input = parse_macro_input!(input as DeriveInput);
	match expand(input) {
		Ok(tokens) => tokens.into(),
		Err(error) => error.to_compile_error().into(),
	}
}

fn expand(input: DeriveInput) -> Result<proc_macro2::TokenStream> {
	let js_name = js_name_attr(&input)?.unwrap_or_else(|| input.ident.to_string());
	match &input.data {
		Data::Struct(data) => expand_sequence(&input, data, &js_name),
		Data::Enum(data) => {
			if is_enumerated(data)? {
				expand_enumerated(&input, data, &js_name)
			} else if is_choice(data)? {
				expand_choice(&input, data, &js_name)
			} else {
				Err(Error::new(
					input.span(),
					"AsnCodec enums must be #[repr(u8)] Enumerated or Choice tuple variants",
				))
			}
		}
		Data::Union(_) => Err(Error::new(input.span(), "AsnCodec supports structs and enums")),
	}
}

fn expand_sequence(input: &DeriveInput, data: &syn::DataStruct, js_name: &str) -> Result<proc_macro2::TokenStream> {
	let Fields::Named(fields) = &data.fields else {
		return Err(Error::new(input.span(), "AsnCodec supports structs with named fields"));
	};

	let FieldEmit { from_fields, to_fields, init_fields, ts_fields, dts_fields } = emit_fields(&fields.named)?;

	let name = &input.ident;
	let generics = &input.generics;
	let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
	let ts_type = quote_ts_interface(js_name, &ts_fields);
	let dts_type = quote_ts_interface(js_name, &dts_fields);
	let ts_codec = quote_ts_codec(js_name);
	let asn_codec_ts = format!("{ts_type}\n\n{ts_codec}\n");
	let exports = quote_exports(name, js_name, &dts_type);
	let impl_block = quote_sequence_impl(
		name,
		&impl_generics,
		&ty_generics,
		where_clause,
		&from_fields,
		&to_fields,
		&init_fields,
	);
	let ts_const = quote_asn_codec_ts(name, &asn_codec_ts);

	Ok(quote! {
		#impl_block
		#ts_const
		#exports
	})
}

fn expand_enumerated(input: &DeriveInput, _data: &DataEnum, js_name: &str) -> Result<proc_macro2::TokenStream> {
	ensure_repr_u8(input)?;
	let name = &input.ident;
	let generics = &input.generics;
	let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

	let ts_type = format!("export type {js_name} = number;");
	let ts_codec = quote_ts_codec(js_name);
	let asn_codec_ts = format!("{ts_type}\n\n{ts_codec}\n");
	let exports = quote_exports(name, js_name, &ts_type);
	let ts_const = quote_asn_codec_ts(name, &asn_codec_ts);

	let impl_block = quote! {
		#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
		impl #impl_generics ::tightbeam_asn::AsnCodec for #name #ty_generics #where_clause {
			fn from_js(value: &::wasm_bindgen::JsValue) -> ::tightbeam_asn::Result<Self> {
				let discriminant = ::tightbeam_asn::js::as_u8(value)?;
				::core::convert::TryFrom::try_from(discriminant)
			}

			fn to_js(&self) -> ::tightbeam_asn::Result<::wasm_bindgen::JsValue> {
				Ok(::tightbeam_asn::js::from_u8(*self as u8))
			}
		}

		#[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
		impl #impl_generics ::tightbeam_asn::AsnCodec for #name #ty_generics #where_clause {}
	};

	Ok(quote! {
		#impl_block
		#ts_const
		#exports
	})
}

fn expand_choice(input: &DeriveInput, data: &DataEnum, js_name: &str) -> Result<proc_macro2::TokenStream> {
	let name = &input.ident;
	let generics = &input.generics;
	let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

	let mut from_arms = Vec::new();
	let mut to_arms = Vec::new();
	let mut ts_variants = Vec::new();

	for variant in &data.variants {
		let variant_ident = &variant.ident;
		let variant_name = variant_ident.to_string();
		let Fields::Unnamed(fields) = &variant.fields else {
			return Err(Error::new(
				variant.span(),
				"AsnCodec Choice variants must be single-field tuples",
			));
		};
		if fields.unnamed.len() != 1 {
			return Err(Error::new(
				variant.span(),
				"AsnCodec Choice variants must be single-field tuples",
			));
		}
		let Type::Path(type_path) = &fields.unnamed[0].ty else {
			return Err(Error::new(
				fields.unnamed[0].ty.span(),
				"AsnCodec Choice payloads must be AsnCodec types",
			));
		};
		let payload = &type_path.path;
		let payload_ts = path_ts_name(payload)?;

		from_arms.push(quote! {
			#variant_name => {
				let payload = <#payload as ::tightbeam_asn::AsnCodec>::from_js(&entry)?;
				Ok(Self::#variant_ident(payload))
			}
		});
		to_arms.push(quote! {
			Self::#variant_ident(payload) => {
				let nested = <#payload as ::tightbeam_asn::AsnCodec>::to_js(payload)?;
				::tightbeam_asn::js::set_object(&object, #variant_name, &nested)?;
			}
		});
		ts_variants.push(format!("{{ {variant_name}: {payload_ts} }}"));
	}

	let ts_type = format!("export type {js_name} =\n\t| {};", ts_variants.join("\n\t| "));
	let ts_codec = quote_ts_codec(js_name);
	let asn_codec_ts = format!("{ts_type}\n\n{ts_codec}\n");
	let exports = quote_exports(name, js_name, &ts_type);
	let ts_const = quote_asn_codec_ts(name, &asn_codec_ts);

	let impl_block = quote! {
		#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
		impl #impl_generics ::tightbeam_asn::AsnCodec for #name #ty_generics #where_clause {
			fn from_js(value: &::wasm_bindgen::JsValue) -> ::tightbeam_asn::Result<Self> {
				let (key, entry) = ::tightbeam_asn::js::single_entry(value)?;
				match key.as_str() {
					#(#from_arms)*
					_ => Err(::der::Error::from(::der::ErrorKind::Failed)),
				}
			}

			fn to_js(&self) -> ::tightbeam_asn::Result<::wasm_bindgen::JsValue> {
				let object = ::tightbeam_asn::js::object()?;
				match self {
					#(#to_arms)*
				}
				Ok(object)
			}
		}

		#[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
		impl #impl_generics ::tightbeam_asn::AsnCodec for #name #ty_generics #where_clause {}
	};

	Ok(quote! {
		#impl_block
		#ts_const
		#exports
	})
}

struct FieldEmit {
	from_fields: Vec<proc_macro2::TokenStream>,
	to_fields: Vec<proc_macro2::TokenStream>,
	init_fields: Vec<proc_macro2::TokenStream>,
	ts_fields: Vec<String>,
	dts_fields: Vec<String>,
}

fn emit_fields(fields: &syn::punctuated::Punctuated<Field, syn::token::Comma>) -> Result<FieldEmit> {
	let mut from_fields = Vec::new();
	let mut to_fields = Vec::new();
	let mut init_fields = Vec::new();
	let mut ts_fields = Vec::new();
	let mut dts_fields = Vec::new();

	for field in fields {
		let field_name = field
			.ident
			.as_ref()
			.ok_or_else(|| Error::new(field.span(), "expected named field"))?;
		let field_key = field_name.to_string();
		let kind = field_kind(&field.ty)?;
		let mut doc_lines = field_doc_lines(field);
		if doc_lines.is_empty() {
			doc_lines.push(kind.jsdoc_contract().to_owned());
		}
		let property = kind.quote_ts_property(&field_key, &doc_lines)?;

		from_fields.push(kind.quote_from(field_name, &field_key));
		to_fields.push(kind.quote_to(field_name, &field_key));
		init_fields.push(quote! { #field_name });
		ts_fields.push(property.clone());
		dts_fields.push(property);
	}

	Ok(FieldEmit { from_fields, to_fields, init_fields, ts_fields, dts_fields })
}

fn field_doc_lines(field: &Field) -> Vec<String> {
	let mut lines = Vec::new();
	for attr in &field.attrs {
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

fn quote_ts_property(field_decl: &str, doc_lines: &[String]) -> String {
	let mut out = String::from("\t/**\n");
	for line in doc_lines {
		out.push_str("\t * ");
		out.push_str(line);
		out.push('\n');
	}
	out.push_str("\t */\n");
	out.push('\t');
	out.push_str(field_decl);
	out.push(';');
	out
}

fn quote_sequence_impl(
	name: &Ident,
	impl_generics: &syn::ImplGenerics<'_>,
	ty_generics: &syn::TypeGenerics<'_>,
	where_clause: Option<&syn::WhereClause>,
	from_fields: &[proc_macro2::TokenStream],
	to_fields: &[proc_macro2::TokenStream],
	init_fields: &[proc_macro2::TokenStream],
) -> proc_macro2::TokenStream {
	quote! {
		#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
		impl #impl_generics ::tightbeam_asn::AsnCodec for #name #ty_generics #where_clause {
			fn from_js(value: &::wasm_bindgen::JsValue) -> ::tightbeam_asn::Result<Self> {
				#(#from_fields)*
				Ok(Self {
					#(#init_fields),*
				})
			}

			fn to_js(&self) -> ::tightbeam_asn::Result<::wasm_bindgen::JsValue> {
				let object = ::tightbeam_asn::js::object()?;
				#(#to_fields)*
				Ok(object)
			}
		}

		#[cfg(not(all(feature = "wasm", target_arch = "wasm32")))]
		impl #impl_generics ::tightbeam_asn::AsnCodec for #name #ty_generics #where_clause {}
	}
}

fn quote_exports(name: &Ident, js_name: &str, ts_section: &str) -> proc_macro2::TokenStream {
	let encode_js_name = format!("encode{js_name}");
	let decode_js_name = format!("decode{js_name}");
	let encode_fn = format_ident!("__asn_encode_{name}");
	let decode_fn = format_ident!("__asn_decode_{name}");
	let section_ident = format_ident!("__ASN_TS_{name}");

	quote! {
		#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
		const _: () = {
			use ::der::{Decode, Encode};
			use ::wasm_bindgen::prelude::*;

			#[wasm_bindgen(typescript_custom_section)]
			const #section_ident: &'static str = #ts_section;

			#[wasm_bindgen(js_name = #encode_js_name)]
			pub fn #encode_fn(
				value: ::wasm_bindgen::JsValue,
			) -> core::result::Result<::std::vec::Vec<u8>, ::wasm_bindgen::JsValue> {
				let message = <#name as ::tightbeam_asn::AsnCodec>::from_js(&value)
					.map_err(::tightbeam_asn::js::to_js_error)?;
				message
					.to_der()
					.map_err(::tightbeam_asn::js::to_js_error)
			}

			#[wasm_bindgen(js_name = #decode_js_name)]
			pub fn #decode_fn(
				bytes: &[u8],
			) -> core::result::Result<::wasm_bindgen::JsValue, ::wasm_bindgen::JsValue> {
				let message = <#name as ::der::Decode>::from_der(bytes)
					.map_err(::tightbeam_asn::js::to_js_error)?;
				<#name as ::tightbeam_asn::AsnCodec>::to_js(&message)
					.map_err(::tightbeam_asn::js::to_js_error)
			}
		};
	}
}

fn quote_asn_codec_ts(name: &Ident, source: &str) -> proc_macro2::TokenStream {
	quote! {
		impl #name {
			/// Thin TypeScript `MessageCodec` source for this wire type.
			pub const ASN_CODEC_TS: &'static str = #source;
		}
	}
}

fn quote_ts_interface(js_name: &str, fields: &[String]) -> String {
	format!("export interface {js_name} {{\n{}\n}}", fields.join("\n"))
}

fn quote_ts_codec(js_name: &str) -> String {
	format!(
		"export const {js_name}: MessageCodec<{js_name}> = {{\n\tencode(value) {{\n\t\treturn encode{js_name}(value);\n\t}},\n\tdecode(bodyDer) {{\n\t\treturn decode{js_name}(bodyDer);\n\t}},\n}};"
	)
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
	Option(Box<FieldKind>),
	Vec(Box<FieldKind>),
	SetOfVec(Box<FieldKind>),
	SequenceOf { inner: Box<FieldKind>, len: Expr },
	SetOf { inner: Box<FieldKind>, len: Expr },
}

impl FieldKind {
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
			Self::Nested(path) => path_ts_name(path),
			Self::Option(inner) => {
				let inner_ts = inner.ts_type()?;
				Ok(format!("{inner_ts} | null"))
			}
			Self::Vec(inner) | Self::SetOfVec(inner) | Self::SequenceOf { inner, .. } | Self::SetOf { inner, .. } => {
				let inner_ts = inner.ts_type()?;
				Ok(format!("{inner_ts}[]"))
			}
		}
	}

	fn quote_ts_property(&self, field_key: &str, doc_lines: &[String]) -> Result<String> {
		let ts_ty = self.ts_type()?;
		let field_decl = match self {
			Self::Option(_) => format!("{field_key}?: {ts_ty}"),
			_ => format!("{field_key}: {ts_ty}"),
		};
		Ok(quote_ts_property(&field_decl, doc_lines))
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
			Self::UtcTime => "Carries a UTCTime Sequence field as an RFC 3339 string.",
			Self::GeneralizedTime => "Carries a GeneralizedTime Sequence field as an RFC 3339 string.",
			Self::Nested(_) => "Carries a nested AsnCodec value for this Sequence field.",
			Self::Option(_) => {
				"Carries an OPTIONAL Sequence field. Nullish JS values map to None, and a present value maps to Some."
			}
			Self::Vec(_) => "Carries a SEQUENCE OF Sequence field as a JavaScript Array.",
			Self::SetOfVec(_) => "Carries a SET OF Sequence field as a JavaScript Array.",
			Self::SequenceOf { .. } => "Carries a fixed-length SEQUENCE OF Sequence field as a JavaScript Array.",
			Self::SetOf { .. } => "Carries a fixed-length SET OF Sequence field as a JavaScript Array.",
		}
	}

	fn quote_from_value(&self, value: &Ident) -> proc_macro2::TokenStream {
		match self {
			Self::Bool => quote! { ::tightbeam_asn::js::as_bool(&#value)? },
			Self::Null => quote! { ::tightbeam_asn::js::as_null(&#value)? },
			Self::U8 => quote! { ::tightbeam_asn::js::as_u8(&#value)? },
			Self::U16 => quote! { ::tightbeam_asn::js::as_u16(&#value)? },
			Self::U32 => quote! { ::tightbeam_asn::js::as_u32(&#value)? },
			Self::U64 => quote! { ::tightbeam_asn::js::as_u64(&#value)? },
			Self::I8 => quote! { ::tightbeam_asn::js::as_i8(&#value)? },
			Self::I16 => quote! { ::tightbeam_asn::js::as_i16(&#value)? },
			Self::I32 => quote! { ::tightbeam_asn::js::as_i32(&#value)? },
			Self::I64 => quote! { ::tightbeam_asn::js::as_i64(&#value)? },
			Self::String => quote! { ::tightbeam_asn::js::as_string(&#value)? },
			Self::Ia5String => quote! { ::tightbeam_asn::js::as_ia5_string(&#value)? },
			Self::PrintableString => quote! { ::tightbeam_asn::js::as_printable_string(&#value)? },
			Self::TeletexString => quote! { ::tightbeam_asn::js::as_teletex_string(&#value)? },
			Self::BmpString => quote! { ::tightbeam_asn::js::as_bmp_string(&#value)? },
			Self::OctetString => quote! {
				::der::asn1::OctetString::new(::tightbeam_asn::js::as_octets(&#value)?)?
			},
			Self::BitString => quote! { ::tightbeam_asn::js::as_bitstring(&#value)? },
			Self::ObjectIdentifier => quote! { ::tightbeam_asn::js::as_oid(&#value)? },
			Self::Any => quote! { ::tightbeam_asn::js::as_any(&#value)? },
			Self::UtcTime => quote! { ::tightbeam_asn::js::as_utc_time(&#value)? },
			Self::GeneralizedTime => quote! { ::tightbeam_asn::js::as_generalized_time(&#value)? },
			Self::Nested(path) => quote! {
				<#path as ::tightbeam_asn::AsnCodec>::from_js(&#value)?
			},
			Self::Option(inner) => {
				let present = format_ident!("present");
				let from_present = inner.quote_from_value(&present);
				quote! {
					{
						if #value.is_undefined() || #value.is_null() {
							::core::option::Option::None
						} else {
							let #present = #value.clone();
							::core::option::Option::Some(#from_present)
						}
					}
				}
			}
			Self::Vec(inner) => quote_vec_from_value(inner, value),
			Self::SetOfVec(inner) => {
				let items = format_ident!("items");
				let build_vec = quote_vec_from_value(inner, value);
				quote! {
					{
						let #items = #build_vec;
						::core::convert::TryFrom::try_from(#items)?
					}
				}
			}
			Self::SequenceOf { inner, len } => quote_sequence_of_from_value(inner, len, value),
			Self::SetOf { inner, len } => quote_set_of_from_value(inner, len, value),
		}
	}

	fn quote_to_value(&self, rust_value: &proc_macro2::TokenStream) -> proc_macro2::TokenStream {
		match self {
			Self::Bool => quote! { ::tightbeam_asn::js::from_bool(*#rust_value) },
			Self::Null => quote! { ::tightbeam_asn::js::from_null(*#rust_value) },
			Self::U8 => quote! { ::tightbeam_asn::js::from_u8(*#rust_value) },
			Self::U16 => quote! { ::tightbeam_asn::js::from_u16(*#rust_value) },
			Self::U32 => quote! { ::tightbeam_asn::js::from_u32(*#rust_value) },
			Self::U64 => quote! { ::tightbeam_asn::js::from_u64(*#rust_value) },
			Self::I8 => quote! { ::tightbeam_asn::js::from_i8(*#rust_value) },
			Self::I16 => quote! { ::tightbeam_asn::js::from_i16(*#rust_value) },
			Self::I32 => quote! { ::tightbeam_asn::js::from_i32(*#rust_value) },
			Self::I64 => quote! { ::tightbeam_asn::js::from_i64(*#rust_value) },
			Self::String => quote! { ::wasm_bindgen::JsValue::from_str(#rust_value.as_str()) },
			Self::Ia5String => quote! { ::tightbeam_asn::js::from_ia5_string(#rust_value) },
			Self::PrintableString => quote! { ::tightbeam_asn::js::from_printable_string(#rust_value) },
			Self::TeletexString => quote! { ::tightbeam_asn::js::from_teletex_string(#rust_value) },
			Self::BmpString => quote! { ::tightbeam_asn::js::from_bmp_string(#rust_value) },
			Self::OctetString => quote! { ::tightbeam_asn::js::from_octets(#rust_value.as_bytes()) },
			Self::BitString => quote! { ::tightbeam_asn::js::from_bitstring(#rust_value)? },
			Self::ObjectIdentifier => quote! { ::tightbeam_asn::js::from_oid(#rust_value) },
			Self::Any => quote! { ::tightbeam_asn::js::from_any(#rust_value)? },
			Self::UtcTime => quote! { ::tightbeam_asn::js::from_utc_time(#rust_value) },
			Self::GeneralizedTime => quote! { ::tightbeam_asn::js::from_generalized_time(#rust_value) },
			Self::Nested(path) => quote! {
				<#path as ::tightbeam_asn::AsnCodec>::to_js(#rust_value)?
			},
			Self::Option(inner) => {
				let present = quote! { present };
				let to_present = inner.quote_to_value(&present);
				quote! {
					match #rust_value {
						::core::option::Option::Some(present) => #to_present,
						::core::option::Option::None => ::wasm_bindgen::JsValue::NULL,
					}
				}
			}
			Self::Vec(inner) => quote_vec_to_value(inner, rust_value),
			Self::SetOfVec(inner) => {
				let slice = quote! { (#rust_value).as_slice() };
				quote_iter_to_array(inner, &slice)
			}
			Self::SequenceOf { inner, .. } | Self::SetOf { inner, .. } => {
				let iter = quote! { (#rust_value).iter() };
				quote_iter_to_array(inner, &iter)
			}
		}
	}

	fn quote_from(&self, field_name: &Ident, field_key: &str) -> proc_macro2::TokenStream {
		match self {
			Self::Bool => quote! {
				let #field_name = ::tightbeam_asn::js::bool_field(value, #field_key)?;
			},
			Self::Null => quote! {
				let #field_name = ::tightbeam_asn::js::null_field(value, #field_key)?;
			},
			Self::U8 => quote! {
				let #field_name = ::tightbeam_asn::js::u8_field(value, #field_key)?;
			},
			Self::U16 => quote! {
				let #field_name = ::tightbeam_asn::js::u16_field(value, #field_key)?;
			},
			Self::U32 => quote! {
				let #field_name = ::tightbeam_asn::js::u32_field(value, #field_key)?;
			},
			Self::U64 => quote! {
				let #field_name = ::tightbeam_asn::js::u64_field(value, #field_key)?;
			},
			Self::I8 => quote! {
				let #field_name = ::tightbeam_asn::js::i8_field(value, #field_key)?;
			},
			Self::I16 => quote! {
				let #field_name = ::tightbeam_asn::js::i16_field(value, #field_key)?;
			},
			Self::I32 => quote! {
				let #field_name = ::tightbeam_asn::js::i32_field(value, #field_key)?;
			},
			Self::I64 => quote! {
				let #field_name = ::tightbeam_asn::js::i64_field(value, #field_key)?;
			},
			Self::String => quote! {
				let #field_name = ::tightbeam_asn::js::string_field(value, #field_key)?;
			},
			Self::Ia5String => quote! {
				let #field_name = ::tightbeam_asn::js::ia5_string_field(value, #field_key)?;
			},
			Self::PrintableString => quote! {
				let #field_name = ::tightbeam_asn::js::printable_string_field(value, #field_key)?;
			},
			Self::TeletexString => quote! {
				let #field_name = ::tightbeam_asn::js::teletex_string_field(value, #field_key)?;
			},
			Self::BmpString => quote! {
				let #field_name = ::tightbeam_asn::js::bmp_string_field(value, #field_key)?;
			},
			Self::OctetString => quote! {
				let #field_name = ::der::asn1::OctetString::new(
					::tightbeam_asn::js::octet_field(value, #field_key)?,
				)?;
			},
			Self::BitString => quote! {
				let #field_name = ::tightbeam_asn::js::bitstring_field(value, #field_key)?;
			},
			Self::ObjectIdentifier => quote! {
				let #field_name = ::tightbeam_asn::js::oid_field(value, #field_key)?;
			},
			Self::Any => quote! {
				let #field_name = ::tightbeam_asn::js::any_field(value, #field_key)?;
			},
			Self::UtcTime => quote! {
				let #field_name = ::tightbeam_asn::js::utc_time_field(value, #field_key)?;
			},
			Self::GeneralizedTime => quote! {
				let #field_name = ::tightbeam_asn::js::generalized_time_field(value, #field_key)?;
			},
			Self::Nested(path) => quote! {
				let #field_name = {
					let nested = ::tightbeam_asn::js::object_field(value, #field_key)?;
					<#path as ::tightbeam_asn::AsnCodec>::from_js(&nested)?
				};
			},
			Self::Option(inner) => {
				let present = format_ident!("present");
				let from_present = inner.quote_from_value(&present);
				quote! {
					let #field_name = match ::tightbeam_asn::js::optional_field(value, #field_key)? {
						::core::option::Option::Some(#present) => {
							::core::option::Option::Some(#from_present)
						}
						::core::option::Option::None => ::core::option::Option::None,
					};
				}
			}
			Self::Vec(inner) => {
				let array = format_ident!("array_value");
				let from_array = quote_vec_from_array(inner, &array);
				quote! {
					let #field_name = {
						let #array = ::tightbeam_asn::js::array_field(value, #field_key)?;
						#from_array
					};
				}
			}
			Self::SetOfVec(inner) => {
				let array = format_ident!("array_value");
				let from_array = quote_vec_from_array(inner, &array);
				quote! {
					let #field_name = {
						let #array = ::tightbeam_asn::js::array_field(value, #field_key)?;
						let items = #from_array;
						::core::convert::TryFrom::try_from(items)?
					};
				}
			}
			Self::SequenceOf { inner, len } => {
				let array = format_ident!("array_value");
				let build = quote_sequence_of_from_array(inner, len, &array);
				quote! {
					let #field_name = {
						let #array = ::tightbeam_asn::js::array_field(value, #field_key)?;
						#build
					};
				}
			}
			Self::SetOf { inner, len } => {
				let array = format_ident!("array_value");
				let build = quote_set_of_from_array(inner, len, &array);
				quote! {
					let #field_name = {
						let #array = ::tightbeam_asn::js::array_field(value, #field_key)?;
						#build
					};
				}
			}
		}
	}

	fn quote_to(&self, field_name: &Ident, field_key: &str) -> proc_macro2::TokenStream {
		match self {
			Self::Bool => quote! {
				::tightbeam_asn::js::set_bool(&object, #field_key, self.#field_name)?;
			},
			Self::Null => quote! {
				::tightbeam_asn::js::set_null(&object, #field_key, self.#field_name)?;
			},
			Self::U8 => quote! {
				::tightbeam_asn::js::set_u8(&object, #field_key, self.#field_name)?;
			},
			Self::U16 => quote! {
				::tightbeam_asn::js::set_u16(&object, #field_key, self.#field_name)?;
			},
			Self::U32 => quote! {
				::tightbeam_asn::js::set_u32(&object, #field_key, self.#field_name)?;
			},
			Self::U64 => quote! {
				::tightbeam_asn::js::set_u64(&object, #field_key, self.#field_name)?;
			},
			Self::I8 => quote! {
				::tightbeam_asn::js::set_i8(&object, #field_key, self.#field_name)?;
			},
			Self::I16 => quote! {
				::tightbeam_asn::js::set_i16(&object, #field_key, self.#field_name)?;
			},
			Self::I32 => quote! {
				::tightbeam_asn::js::set_i32(&object, #field_key, self.#field_name)?;
			},
			Self::I64 => quote! {
				::tightbeam_asn::js::set_i64(&object, #field_key, self.#field_name)?;
			},
			Self::String => quote! {
				::tightbeam_asn::js::set_string(&object, #field_key, &self.#field_name)?;
			},
			Self::Ia5String => quote! {
				::tightbeam_asn::js::set_ia5_string(&object, #field_key, &self.#field_name)?;
			},
			Self::PrintableString => quote! {
				::tightbeam_asn::js::set_printable_string(&object, #field_key, &self.#field_name)?;
			},
			Self::TeletexString => quote! {
				::tightbeam_asn::js::set_teletex_string(&object, #field_key, &self.#field_name)?;
			},
			Self::BmpString => quote! {
				::tightbeam_asn::js::set_bmp_string(&object, #field_key, &self.#field_name)?;
			},
			Self::OctetString => quote! {
				::tightbeam_asn::js::set_octets(
					&object,
					#field_key,
					self.#field_name.as_bytes(),
				)?;
			},
			Self::BitString => quote! {
				::tightbeam_asn::js::set_bitstring(&object, #field_key, &self.#field_name)?;
			},
			Self::ObjectIdentifier => quote! {
				::tightbeam_asn::js::set_oid(&object, #field_key, &self.#field_name)?;
			},
			Self::Any => quote! {
				::tightbeam_asn::js::set_any(&object, #field_key, &self.#field_name)?;
			},
			Self::UtcTime => quote! {
				::tightbeam_asn::js::set_utc_time(&object, #field_key, &self.#field_name)?;
			},
			Self::GeneralizedTime => quote! {
				::tightbeam_asn::js::set_generalized_time(&object, #field_key, &self.#field_name)?;
			},
			Self::Nested(path) => quote! {
				{
					let nested = <#path as ::tightbeam_asn::AsnCodec>::to_js(&self.#field_name)?;
					::tightbeam_asn::js::set_object(&object, #field_key, &nested)?;
				}
			},
			Self::Option(inner) => {
				let present = quote! { present };
				let to_present = inner.quote_to_value(&present);
				quote! {
					if let ::core::option::Option::Some(present) = &self.#field_name {
						let nested = #to_present;
						::tightbeam_asn::js::set_object(&object, #field_key, &nested)?;
					}
				}
			}
			Self::Vec(inner) => {
				let item = quote! { item };
				let to_item = inner.quote_to_value(&item);
				quote! {
					{
						let array = ::tightbeam_asn::js::array();
						for item in &self.#field_name {
							let nested = #to_item;
							array.push(&nested);
						}
						::tightbeam_asn::js::set_array(&object, #field_key, &array)?;
					}
				}
			}
			Self::SetOfVec(inner) => {
				let item = quote! { item };
				let to_item = inner.quote_to_value(&item);
				quote! {
					{
						let array = ::tightbeam_asn::js::array();
						for item in self.#field_name.as_slice() {
							let nested = #to_item;
							array.push(&nested);
						}
						::tightbeam_asn::js::set_array(&object, #field_key, &array)?;
					}
				}
			}
			Self::SequenceOf { inner, .. } | Self::SetOf { inner, .. } => {
				let item = quote! { item };
				let to_item = inner.quote_to_value(&item);
				quote! {
					{
						let array = ::tightbeam_asn::js::array();
						for item in self.#field_name.iter() {
							let nested = #to_item;
							array.push(&nested);
						}
						::tightbeam_asn::js::set_array(&object, #field_key, &array)?;
					}
				}
			}
		}
	}
}

fn quote_vec_from_value(inner: &FieldKind, value: &Ident) -> proc_macro2::TokenStream {
	let array = format_ident!("array_value");
	let from_array = quote_vec_from_array(inner, &array);
	quote! {
		{
			let #array = ::tightbeam_asn::js::as_array(&#value)?;
			#from_array
		}
	}
}

fn quote_vec_from_array(inner: &FieldKind, array: &Ident) -> proc_macro2::TokenStream {
	let entry = format_ident!("entry");
	let from_entry = inner.quote_from_value(&entry);
	quote! {
		{
			let length = #array.length();
			let mut items = ::std::vec::Vec::with_capacity(length as ::core::primitive::usize);
			let mut index = 0_u32;
			while index < length {
				let #entry = #array.get(index);
				items.push(#from_entry);
				index += 1;
			}
			items
		}
	}
}

fn quote_sequence_of_from_value(inner: &FieldKind, len: &Expr, value: &Ident) -> proc_macro2::TokenStream {
	let array = format_ident!("array_value");
	let build = quote_sequence_of_from_array(inner, len, &array);
	quote! {
		{
			let #array = ::tightbeam_asn::js::as_array_len(&#value, #len)?;
			#build
		}
	}
}

fn quote_sequence_of_from_array(inner: &FieldKind, len: &Expr, array: &Ident) -> proc_macro2::TokenStream {
	let entry = format_ident!("entry");
	let from_entry = inner.quote_from_value(&entry);
	quote! {
		{
			if (#array.length() as ::core::primitive::usize) != (#len as ::core::primitive::usize) {
				return ::core::result::Result::Err(::der::Error::from(::der::ErrorKind::Failed));
			}
			let mut seq = ::der::asn1::SequenceOf::<_, #len>::new();
			let mut index = 0_u32;
			while index < #array.length() {
				let #entry = #array.get(index);
				seq.add(#from_entry)?;
				index += 1;
			}
			seq
		}
	}
}

fn quote_set_of_from_value(inner: &FieldKind, len: &Expr, value: &Ident) -> proc_macro2::TokenStream {
	let array = format_ident!("array_value");
	let build = quote_set_of_from_array(inner, len, &array);
	quote! {
		{
			let #array = ::tightbeam_asn::js::as_array_len(&#value, #len)?;
			#build
		}
	}
}

fn quote_set_of_from_array(inner: &FieldKind, len: &Expr, array: &Ident) -> proc_macro2::TokenStream {
	let entry = format_ident!("entry");
	let from_entry = inner.quote_from_value(&entry);
	quote! {
		{
			if (#array.length() as ::core::primitive::usize) != (#len as ::core::primitive::usize) {
				return ::core::result::Result::Err(::der::Error::from(::der::ErrorKind::Failed));
			}
			let mut set = ::der::asn1::SetOf::<_, #len>::new();
			let mut index = 0_u32;
			while index < #array.length() {
				let #entry = #array.get(index);
				set.insert(#from_entry)?;
				index += 1;
			}
			set
		}
	}
}

fn quote_vec_to_value(inner: &FieldKind, rust_value: &proc_macro2::TokenStream) -> proc_macro2::TokenStream {
	let item = quote! { item };
	let to_item = inner.quote_to_value(&item);
	quote! {
		{
			let array = ::tightbeam_asn::js::array();
			for item in #rust_value {
				let nested = #to_item;
				array.push(&nested);
			}
			::wasm_bindgen::JsValue::from(array)
		}
	}
}

fn quote_iter_to_array(inner: &FieldKind, iter_expr: &proc_macro2::TokenStream) -> proc_macro2::TokenStream {
	let item = quote! { item };
	let to_item = inner.quote_to_value(&item);
	quote! {
		{
			let array = ::tightbeam_asn::js::array();
			for item in #iter_expr {
				let nested = #to_item;
				array.push(&nested);
			}
			::wasm_bindgen::JsValue::from(array)
		}
	}
}

const FIELD_KIND_HELP: &str = "AsnCodec Sequence fields must be der-owned leaves (bool, Null, integers, string zoo, OctetString, BitString, ObjectIdentifier, Any, UtcTime, GeneralizedTime), nested AsnCodec, or recursive Option/Vec/SetOfVec/SequenceOf/SetOf over those types";

fn field_kind(ty: &Type) -> Result<FieldKind> {
	let Type::Path(type_path) = ty else {
		return Err(Error::new(ty.span(), FIELD_KIND_HELP));
	};
	let path = &type_path.path;

	if let Some(inner_ty) = single_type_arg(path, "Option") {
		return Ok(FieldKind::Option(Box::new(field_kind(inner_ty)?)));
	}
	if let Some(inner_ty) = single_type_arg(path, "Vec") {
		return Ok(FieldKind::Vec(Box::new(field_kind(inner_ty)?)));
	}
	if let Some(inner_ty) = single_type_arg(path, "SetOfVec") {
		return Ok(FieldKind::SetOfVec(Box::new(field_kind(inner_ty)?)));
	}
	if let Some((inner_ty, len)) = type_and_const_args(path, "SequenceOf") {
		return Ok(FieldKind::SequenceOf { inner: Box::new(field_kind(inner_ty)?), len });
	}
	if let Some((inner_ty, len)) = type_and_const_args(path, "SetOf") {
		return Ok(FieldKind::SetOf { inner: Box::new(field_kind(inner_ty)?), len });
	}

	leaf_field_kind(ty)
}

fn leaf_field_kind(ty: &Type) -> Result<FieldKind> {
	let Type::Path(type_path) = ty else {
		return Err(Error::new(ty.span(), FIELD_KIND_HELP));
	};

	let path = &type_path.path;
	if path_has_generics(path) {
		return Err(Error::new(ty.span(), FIELD_KIND_HELP));
	}

	if path.is_ident("bool") {
		return Ok(FieldKind::Bool);
	}
	if path.is_ident("u8") {
		return Ok(FieldKind::U8);
	}
	if path.is_ident("u16") {
		return Ok(FieldKind::U16);
	}
	if path.is_ident("u32") {
		return Ok(FieldKind::U32);
	}
	if path.is_ident("u64") {
		return Ok(FieldKind::U64);
	}
	if path.is_ident("i8") {
		return Ok(FieldKind::I8);
	}
	if path.is_ident("i16") {
		return Ok(FieldKind::I16);
	}
	if path.is_ident("i32") {
		return Ok(FieldKind::I32);
	}
	if path.is_ident("i64") {
		return Ok(FieldKind::I64);
	}
	if path.is_ident("String") || path_ends_with(path, "Utf8String") {
		return Ok(FieldKind::String);
	}
	if path.is_ident("Null") || path_ends_with(path, "Null") {
		return Ok(FieldKind::Null);
	}
	if path.is_ident("Ia5String") || path_ends_with(path, "Ia5String") {
		return Ok(FieldKind::Ia5String);
	}
	if path.is_ident("PrintableString") || path_ends_with(path, "PrintableString") {
		return Ok(FieldKind::PrintableString);
	}
	if path.is_ident("TeletexString") || path_ends_with(path, "TeletexString") {
		return Ok(FieldKind::TeletexString);
	}
	if path.is_ident("BmpString") || path_ends_with(path, "BmpString") {
		return Ok(FieldKind::BmpString);
	}
	if path.is_ident("OctetString") || path_ends_with(path, "OctetString") {
		return Ok(FieldKind::OctetString);
	}
	if path.is_ident("BitString") || path_ends_with(path, "BitString") {
		return Ok(FieldKind::BitString);
	}
	if path.is_ident("ObjectIdentifier") || path_ends_with(path, "ObjectIdentifier") {
		return Ok(FieldKind::ObjectIdentifier);
	}
	if path.is_ident("Any") || path_ends_with(path, "Any") {
		return Ok(FieldKind::Any);
	}
	if path.is_ident("UtcTime") || path_ends_with(path, "UtcTime") {
		return Ok(FieldKind::UtcTime);
	}
	if path.is_ident("GeneralizedTime") || path_ends_with(path, "GeneralizedTime") {
		return Ok(FieldKind::GeneralizedTime);
	}

	Ok(FieldKind::Nested(path.clone()))
}

fn single_type_arg<'a>(path: &'a Path, name: &str) -> Option<&'a Type> {
	let segment = path.segments.last()?;
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

fn type_and_const_args<'a>(path: &'a Path, name: &str) -> Option<(&'a Type, Expr)> {
	let segment = path.segments.last()?;
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
	let len = const_generic_expr(&args.args[1])?;
	Some((inner, len))
}

fn const_generic_expr(arg: &GenericArgument) -> Option<Expr> {
	match arg {
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

fn path_ts_name(path: &Path) -> Result<String> {
	path.segments
		.last()
		.map(|segment| segment.ident.to_string())
		.ok_or_else(|| Error::new(path.span(), "expected type path"))
}

fn path_has_generics(path: &Path) -> bool {
	path.segments
		.iter()
		.any(|segment| !matches!(segment.arguments, PathArguments::None))
}

fn path_ends_with(path: &Path, name: &str) -> bool {
	path.segments.last().is_some_and(|segment| segment.ident == name)
}

fn is_enumerated(data: &DataEnum) -> Result<bool> {
	if data.variants.is_empty() {
		return Ok(false);
	}

	for variant in &data.variants {
		if !matches!(variant.fields, Fields::Unit) {
			return Ok(false);
		}
		if variant.discriminant.is_none() {
			return Err(Error::new(
				variant.span(),
				"AsnCodec Enumerated variants require explicit discriminants",
			));
		}
	}

	Ok(true)
}

fn is_choice(data: &DataEnum) -> Result<bool> {
	if data.variants.is_empty() {
		return Ok(false);
	}

	for variant in &data.variants {
		match &variant.fields {
			Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {}
			_ => return Ok(false),
		}
	}

	Ok(true)
}

fn ensure_repr_u8(input: &DeriveInput) -> Result<()> {
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

fn js_name_attr(input: &DeriveInput) -> Result<Option<String>> {
	for attr in &input.attrs {
		let mut js_name = None;

		if !attr.path().is_ident("asn_codec") {
			continue;
		}

		attr.parse_nested_meta(|meta| {
			if meta.path.is_ident("js_name") {
				let value = meta.value()?;
				let lit: LitStr = value.parse()?;
				js_name = Some(lit.value());
				return Ok(());
			}

			Err(meta.error("unsupported asn_codec attribute"))
		})?;

		return Ok(js_name);
	}

	Ok(None)
}
