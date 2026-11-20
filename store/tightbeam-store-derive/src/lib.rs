//! The `#[derive(Storable)]` and `#[derive(Catalog)]` macros of [`tightbeam-store`]: [docs/store.md][derive].
//!
//! [`tightbeam-store`]: https://docs.rs/tightbeam-store
//! [derive]: https://github.com/wahidgroup/tightbeam-ext/blob/master/docs/store.md#declare-a-type

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, quote_spanned, ToTokens};
use syn::ext::IdentExt;
use syn::meta::ParseNestedMeta;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::token::Comma;
use syn::{parse_macro_input, Attribute, Data, DeriveInput, Error, Fields, Ident, LitStr, Result, Type};

/// The refusal of a generic `Storable` type.
const STORABLE_GENERIC: &str = "Storable types take no generic parameters, since each one fills one table";

/// The refusal of a `Storable` type that is no struct with named fields.
const STORABLE_SHAPE: &str = "Storable supports structs with named fields";

/// The refusal of a struct with no `frame_type`.
const NO_FRAME_TYPE: &str = "Storable needs #[storable(frame_type = \"...\")] on the struct";

/// The refusal of a second `frame_type`.
const SECOND_FRAME_TYPE: &str = "Storable takes one frame_type";

/// The refusal of a `storable` key on a struct other than `frame_type`.
const UNKNOWN_STRUCT_KEY: &str = "unsupported storable key, expected frame_type";

/// The refusal of an `id` on the struct.
const ID_ON_STRUCT: &str = "#[storable(id)] marks a field, not the struct";

/// The refusal of a struct with no `id` field.
const NO_ID_FIELD: &str = "Storable needs one field marked #[storable(id)]";

/// The refusal of a second `id` field.
const SECOND_ID_FIELD: &str = "Storable takes one #[storable(id)] field";

/// The refusal of a second `id` on one field.
const SECOND_ID_ON_FIELD: &str = "a field takes one #[storable(id)]";

/// The refusal of a `frame_type` on a field.
const FRAME_TYPE_ON_FIELD: &str = "frame_type names the table on the struct, not on a field";

/// The refusal of a `storable` key on a field other than `id`.
const UNKNOWN_FIELD_KEY: &str = "unsupported storable key on a field, expected id";

/// The refusal of a generic catalog.
const CATALOG_GENERIC: &str = "a Catalog takes no generic parameters";

/// The refusal of a catalog that is no unit struct.
const CATALOG_SHAPE: &str = "Catalog supports unit structs";

/// The refusal of a catalog with no list.
const NO_LIST: &str = "Catalog needs #[catalog(TypeA, TypeB, ...)]";

/// The refusal of a second list.
const SECOND_LIST: &str = "a Catalog takes one #[catalog(...)] list";

/// The refusal of an empty list.
const EMPTY_LIST: &str = "a Catalog lists one Storable type or more";

/// The refusal of one type listed twice.
const TYPE_TWICE: &str = "a Catalog lists each type once";

/// Implements `Storable` on a struct with named fields.
///
/// `#[storable(frame_type = "...")]` on the struct names its table, and
/// `#[storable(id)]` marks the one `RowId` field.
#[proc_macro_derive(Storable, attributes(storable))]
pub fn derive_storable(input: TokenStream) -> TokenStream {
	let input = parse_macro_input!(input as DeriveInput);
	let derived = StorableImpl::try_from(&input);
	match derived {
		Ok(derived) => derived.expand().into(),
		Err(error) => error.to_compile_error().into(),
	}
}

/// Implements `Catalog` on a unit struct, and `Holds` for each listed type.
///
/// `#[catalog(TypeA, TypeB)]` on the struct lists the `Storable` types of one
/// store.
#[proc_macro_derive(Catalog, attributes(catalog))]
pub fn derive_catalog(input: TokenStream) -> TokenStream {
	let input = parse_macro_input!(input as DeriveInput);
	let derived = CatalogImpl::try_from(&input);
	match derived {
		Ok(derived) => derived.expand().into(),
		Err(error) => error.to_compile_error().into(),
	}
}

/// The parts of one `Storable` impl.
struct StorableImpl {
	ident: Ident,
	/// The type name that `Owner` records, without a raw `r#` prefix.
	name: LitStr,
	frame_type: LitStr,
	id: Ident,
	id_type: Type,
}

impl TryFrom<&DeriveInput> for StorableImpl {
	type Error = Error;

	/// Read the struct `input`, its `frame_type`, and its one `id` field.
	///
	/// # Errors
	///
	/// - The [`Error`] of generic parameters, of an enum or a union, or of fields without names.
	/// - The [`Error`] of a missing, second, or malformed `frame_type`.
	/// - The [`Error`] of no `id` field, a second one, or an `id` on the struct.
	/// - The [`Error`] of an unknown `storable` key.
	fn try_from(input: &DeriveInput) -> Result<Self> {
		if !input.generics.params.is_empty() {
			return Err(Error::new(input.generics.span(), STORABLE_GENERIC));
		}

		let Data::Struct(data) = &input.data else {
			return Err(Error::new(input.span(), STORABLE_SHAPE));
		};
		let Fields::Named(fields) = &data.fields else {
			return Err(Error::new(input.span(), STORABLE_SHAPE));
		};

		let frame_type = TypeOptions::try_from(input.attrs.as_slice())?.into_frame_type(input)?;

		let mut id = None;
		for field in &fields.named {
			if !FieldOptions::try_from(field.attrs.as_slice())?.id {
				continue;
			}
			if id.is_some() {
				return Err(Error::new(field.span(), SECOND_ID_FIELD));
			}

			id = Some((field.ident.clone(), field.ty.clone()));
		}

		let Some((Some(id), id_type)) = id else {
			return Err(Error::new(input.span(), NO_ID_FIELD));
		};

		let name = LitStr::new(&input.ident.unraw().to_string(), input.ident.span());
		Ok(Self { ident: input.ident.clone(), name, frame_type, id, id_type })
	}
}

impl StorableImpl {
	fn expand(&self) -> TokenStream2 {
		let Self { ident, name, frame_type, id, id_type } = self;
		let frame_type_const = quote_spanned! { frame_type.span() =>
			::tightbeam_store::FrameType::from_static(#frame_type)
		};
		let id_read = quote_spanned! { id_type.span() =>
			let id: &::tightbeam_store::RowId = &self.#id;
		};

		quote! {
			impl ::tightbeam_store::Storable for #ident {
				const FRAME_TYPE: ::tightbeam_store::FrameType = #frame_type_const;
				const OWNER: ::tightbeam_store::Owner = ::tightbeam_store::Owner::from_static(
					::core::concat!(::core::env!("CARGO_PKG_NAME"), "::", #name)
				);

				fn row_id(&self) -> ::tightbeam_store::RowId {
					#id_read
					::core::clone::Clone::clone(id)
				}
			}

			const _: ::tightbeam_store::FrameType = <#ident as ::tightbeam_store::Storable>::FRAME_TYPE;
			const _: ::tightbeam_store::Owner = <#ident as ::tightbeam_store::Storable>::OWNER;
		}
	}
}

/// The `storable` options of a struct.
#[derive(Default)]
struct TypeOptions {
	frame_type: Option<LitStr>,
}

impl TryFrom<&[Attribute]> for TypeOptions {
	type Error = Error;

	/// Read each `storable` attribute of a struct.
	///
	/// # Errors
	///
	/// - The [`Error`] of a second `frame_type`, an `id` on the struct, or an unknown key.
	fn try_from(attrs: &[Attribute]) -> Result<Self> {
		let mut options = Self::default();
		for attr in attrs.iter().filter(|attr| attr.path().is_ident("storable")) {
			attr.parse_nested_meta(|meta| options.admit(&meta))?;
		}

		Ok(options)
	}
}

impl TypeOptions {
	/// Admit one key of a `storable` attribute of a struct.
	fn admit(&mut self, meta: &ParseNestedMeta) -> Result<()> {
		if meta.path.is_ident("id") {
			return Err(meta.error(ID_ON_STRUCT));
		}
		if !meta.path.is_ident("frame_type") {
			return Err(meta.error(UNKNOWN_STRUCT_KEY));
		}
		if self.frame_type.is_some() {
			return Err(meta.error(SECOND_FRAME_TYPE));
		}

		let frame_type: LitStr = meta.value()?.parse()?;
		self.frame_type = Some(frame_type);
		Ok(())
	}

	/// The `frame_type` of the struct `input`.
	///
	/// # Errors
	///
	/// - The [`Error`] of a struct with no `frame_type`.
	fn into_frame_type(self, input: &DeriveInput) -> Result<LitStr> {
		self.frame_type.ok_or_else(|| Error::new(input.span(), NO_FRAME_TYPE))
	}
}

/// The `storable` options of a field.
#[derive(Default)]
struct FieldOptions {
	id: bool,
}

impl TryFrom<&[Attribute]> for FieldOptions {
	type Error = Error;

	/// Read each `storable` attribute of a field.
	///
	/// # Errors
	///
	/// - The [`Error`] of a second `id`, a `frame_type` on a field, or an unknown key.
	fn try_from(attrs: &[Attribute]) -> Result<Self> {
		let mut options = Self::default();
		for attr in attrs.iter().filter(|attr| attr.path().is_ident("storable")) {
			attr.parse_nested_meta(|meta| options.admit(&meta))?;
		}

		Ok(options)
	}
}

impl FieldOptions {
	/// Admit one key of a `storable` attribute of a field.
	fn admit(&mut self, meta: &ParseNestedMeta) -> Result<()> {
		if meta.path.is_ident("frame_type") {
			return Err(meta.error(FRAME_TYPE_ON_FIELD));
		}
		if !meta.path.is_ident("id") {
			return Err(meta.error(UNKNOWN_FIELD_KEY));
		}
		if self.id {
			return Err(meta.error(SECOND_ID_ON_FIELD));
		}

		self.id = true;
		Ok(())
	}
}

/// The parts of one `Catalog` impl.
struct CatalogImpl {
	ident: Ident,
	types: Vec<Type>,
}

impl TryFrom<&DeriveInput> for CatalogImpl {
	type Error = Error;

	/// Read the unit struct `input` and the types its `catalog` attribute lists.
	///
	/// # Errors
	///
	/// - The [`Error`] of generic parameters, or of a struct with fields, an enum, or a union.
	/// - The [`Error`] of no `catalog` attribute, a second one, an empty list, or one type listed twice.
	fn try_from(input: &DeriveInput) -> Result<Self> {
		if !input.generics.params.is_empty() {
			return Err(Error::new(input.generics.span(), CATALOG_GENERIC));
		}

		let is_unit = matches!(&input.data, Data::Struct(data) if matches!(data.fields, Fields::Unit));
		if !is_unit {
			return Err(Error::new(input.span(), CATALOG_SHAPE));
		}

		let mut lists = input.attrs.iter().filter(|attr| attr.path().is_ident("catalog"));
		let Some(list) = lists.next() else {
			return Err(Error::new(input.span(), NO_LIST));
		};
		if let Some(second) = lists.next() {
			return Err(Error::new(second.span(), SECOND_LIST));
		}

		let types = list.parse_args_with(Punctuated::<Type, Comma>::parse_terminated)?;
		if types.is_empty() {
			return Err(Error::new(list.span(), EMPTY_LIST));
		}

		let mut seen: Vec<String> = Vec::new();
		for listed in &types {
			let spelled = listed.to_token_stream().to_string();
			if seen.contains(&spelled) {
				return Err(Error::new(listed.span(), TYPE_TWICE));
			}

			seen.push(spelled);
		}

		Ok(Self { ident: input.ident.clone(), types: types.into_iter().collect() })
	}
}

impl CatalogImpl {
	fn expand(&self) -> TokenStream2 {
		let Self { ident, types } = self;

		quote! {
			impl ::tightbeam_store::Catalog for #ident {
				const TABLES: ::tightbeam_store::Tables = ::tightbeam_store::Tables::new(&[
					#((
						<#types as ::tightbeam_store::Storable>::FRAME_TYPE,
						<#types as ::tightbeam_store::Storable>::OWNER,
					)),*
				]);
			}

			#(impl ::tightbeam_store::Holds<#types> for #ident {})*

			const _: ::tightbeam_store::Tables = <#ident as ::tightbeam_store::Catalog>::TABLES;
		}
	}
}

#[cfg(test)]
mod tests {
	use syn::parse_quote;

	use super::*;

	tightbeam::tb_cases! {
		fn a_struct_with_a_frame_type_and_an_id_is_read(input: DeriveInput) -> Result<()> {
			let derived = StorableImpl::try_from(&input)?;
			let frame_type = derived.frame_type.value();
			let id = derived.id.to_string();
			assert_eq!((frame_type.as_str(), id.as_str()), ("colony-leaf", "key"));
			Ok(())
		}
		cases {
			id_first => parse_quote! {
				#[storable(frame_type = "colony-leaf")]
				struct Leaf { #[storable(id)] key: RowId, colony: String }
			},
			/// Other attributes stay out of the read, and an id may follow a plain field.
			id_after_a_documented_field => parse_quote! {
				/// A leaf.
				#[derive(Clone)]
				#[storable(frame_type = "colony-leaf")]
				#[allow(dead_code)]
				struct Leaf {
					/// The colony.
					#[allow(dead_code)]
					colony: String,
					/// The key.
					#[storable(id)]
					#[allow(dead_code)]
					key: RowId,
				}
			},
		}
	}

	#[test]
	fn a_raw_type_name_records_its_name_without_the_prefix() -> Result<()> {
		let input: DeriveInput = parse_quote! {
			#[storable(frame_type = "colony-leaf")]
			struct r#Leaf {
				#[storable(id)]
				id: RowId,
			}
		};

		let derived = StorableImpl::try_from(&input)?;
		assert_eq!(derived.name.value(), "Leaf");
		Ok(())
	}

	tightbeam::tb_cases! {
		fn a_storable_outside_the_grammar_is_refused((input, message): (DeriveInput, &'static str)) {
			let refusal = StorableImpl::try_from(&input).err().map(|error| error.to_string());
			assert_eq!(refusal.as_deref(), Some(message));
		}
		cases {
			generic => (
				parse_quote! { #[storable(frame_type = "colony-leaf")] struct Leaf<T> { #[storable(id)] id: RowId, value: T } },
				STORABLE_GENERIC,
			),
			an_enum => (
				parse_quote! { #[storable(frame_type = "colony-leaf")] enum Leaf { One } },
				STORABLE_SHAPE,
			),
			a_union => (
				parse_quote! { #[storable(frame_type = "colony-leaf")] union Leaf { id: u8 } },
				STORABLE_SHAPE,
			),
			tuple_struct => (
				parse_quote! { #[storable(frame_type = "colony-leaf")] struct Leaf(RowId); },
				STORABLE_SHAPE,
			),
			unit_struct => (
				parse_quote! { #[storable(frame_type = "colony-leaf")] struct Leaf; },
				STORABLE_SHAPE,
			),
			no_frame_type => (
				parse_quote! { struct Leaf { #[storable(id)] id: RowId } },
				NO_FRAME_TYPE,
			),
			second_frame_type => (
				parse_quote! {
					#[storable(frame_type = "colony-leaf")]
					#[storable(frame_type = "colony-seed")]
					struct Leaf { #[storable(id)] id: RowId }
				},
				SECOND_FRAME_TYPE,
			),
			frame_type_no_string => (
				parse_quote! { #[storable(frame_type = 7)] struct Leaf { #[storable(id)] id: RowId } },
				"expected string literal",
			),
			unknown_struct_key => (
				parse_quote! { #[storable(frame_type = "colony-leaf", chained)] struct Leaf { #[storable(id)] id: RowId } },
				UNKNOWN_STRUCT_KEY,
			),
			id_on_the_struct => (
				parse_quote! { #[storable(frame_type = "colony-leaf", id)] struct Leaf { #[storable(id)] id: RowId } },
				ID_ON_STRUCT,
			),
			no_id_field => (
				parse_quote! { #[storable(frame_type = "colony-leaf")] struct Leaf { id: RowId } },
				NO_ID_FIELD,
			),
			two_id_fields => (
				parse_quote! {
					#[storable(frame_type = "colony-leaf")]
					struct Leaf { #[storable(id)] id: RowId, #[storable(id)] other: RowId }
				},
				SECOND_ID_FIELD,
			),
			second_id_on_one_field => (
				parse_quote! { #[storable(frame_type = "colony-leaf")] struct Leaf { #[storable(id, id)] id: RowId } },
				SECOND_ID_ON_FIELD,
			),
			frame_type_on_a_field => (
				parse_quote! {
					#[storable(frame_type = "colony-leaf")]
					struct Leaf { #[storable(id, frame_type = "colony-seed")] id: RowId }
				},
				FRAME_TYPE_ON_FIELD,
			),
			unknown_field_key => (
				parse_quote! { #[storable(frame_type = "colony-leaf")] struct Leaf { #[storable(key)] id: RowId } },
				UNKNOWN_FIELD_KEY,
			),
		}
	}

	tightbeam::tb_cases! {
		fn a_unit_struct_with_a_list_is_a_catalog(input: DeriveInput) -> Result<()> {
			let derived = CatalogImpl::try_from(&input)?;
			let spelled: Vec<String> = derived.types.iter().map(|listed| listed.to_token_stream().to_string()).collect();
			assert_eq!(spelled, ["Leaf", "crate :: Seed"]);
			Ok(())
		}
		cases {
			list_alone => parse_quote! { #[catalog(Leaf, crate::Seed)] struct Colony; },
			/// Other attributes stay out of the read.
			among_other_attributes => parse_quote! {
				/// A colony.
				#[derive(Clone)]
				#[catalog(Leaf, crate::Seed)]
				#[allow(dead_code)]
				struct Colony;
			},
		}
	}

	tightbeam::tb_cases! {
		fn a_catalog_outside_the_grammar_is_refused((input, message): (DeriveInput, &'static str)) {
			let refusal = CatalogImpl::try_from(&input).err().map(|error| error.to_string());
			assert_eq!(refusal.as_deref(), Some(message));
		}
		cases {
			generic => (
				parse_quote! { #[catalog(Leaf)] struct Colony<const N: usize>; },
				CATALOG_GENERIC,
			),
			named_fields => (
				parse_quote! { #[catalog(Leaf)] struct Colony { inner: u8 } },
				CATALOG_SHAPE,
			),
			tuple_struct => (
				parse_quote! { #[catalog(Leaf)] struct Colony(u8); },
				CATALOG_SHAPE,
			),
			an_enum => (
				parse_quote! { #[catalog(Leaf)] enum Colony { One } },
				CATALOG_SHAPE,
			),
			no_list => (
				parse_quote! { struct Colony; },
				NO_LIST,
			),
			second_list => (
				parse_quote! { #[catalog(Leaf)] #[catalog(Seed)] struct Colony; },
				SECOND_LIST,
			),
			empty_list => (
				parse_quote! { #[catalog()] struct Colony; },
				EMPTY_LIST,
			),
			type_listed_twice => (
				parse_quote! { #[catalog(Leaf, Seed, Leaf)] struct Colony; },
				TYPE_TWICE,
			),
		}
	}
}
