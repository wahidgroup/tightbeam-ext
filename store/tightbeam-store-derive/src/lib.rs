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
			let refusal = "Storable types take no generic parameters, since each one fills one table";
			return Err(Error::new(input.generics.span(), refusal));
		}

		let Data::Struct(data) = &input.data else {
			return Err(Error::new(input.span(), "Storable supports structs with named fields"));
		};
		let Fields::Named(fields) = &data.fields else {
			return Err(Error::new(input.span(), "Storable supports structs with named fields"));
		};

		let frame_type = TypeOptions::try_from(input.attrs.as_slice())?.into_frame_type(input)?;

		let mut id = None;
		for field in &fields.named {
			if !FieldOptions::try_from(field.attrs.as_slice())?.id {
				continue;
			}
			if id.is_some() {
				return Err(Error::new(field.span(), "Storable takes one #[storable(id)] field"));
			}

			id = Some((field.ident.clone(), field.ty.clone()));
		}

		let Some((Some(id), id_type)) = id else {
			return Err(Error::new(input.span(), "Storable needs one field marked #[storable(id)]"));
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
			return Err(meta.error("#[storable(id)] marks a field, not the struct"));
		}
		if !meta.path.is_ident("frame_type") {
			return Err(meta.error("unsupported storable key, expected frame_type"));
		}
		if self.frame_type.is_some() {
			return Err(meta.error("Storable takes one frame_type"));
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
		let refusal = "Storable needs #[storable(frame_type = \"...\")] on the struct";
		self.frame_type.ok_or_else(|| Error::new(input.span(), refusal))
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
			return Err(meta.error("frame_type names the table on the struct, not on a field"));
		}
		if !meta.path.is_ident("id") {
			return Err(meta.error("unsupported storable key on a field, expected id"));
		}
		if self.id {
			return Err(meta.error("a field takes one #[storable(id)]"));
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
			return Err(Error::new(input.generics.span(), "a Catalog takes no generic parameters"));
		}

		let is_unit = matches!(&input.data, Data::Struct(data) if matches!(data.fields, Fields::Unit));
		if !is_unit {
			return Err(Error::new(input.span(), "Catalog supports unit structs"));
		}

		let mut lists = input.attrs.iter().filter(|attr| attr.path().is_ident("catalog"));
		let Some(list) = lists.next() else {
			return Err(Error::new(input.span(), "Catalog needs #[catalog(TypeA, TypeB, ...)]"));
		};
		if let Some(second) = lists.next() {
			return Err(Error::new(second.span(), "a Catalog takes one #[catalog(...)] list"));
		}

		let types = list.parse_args_with(Punctuated::<Type, Comma>::parse_terminated)?;
		if types.is_empty() {
			return Err(Error::new(list.span(), "a Catalog lists one Storable type or more"));
		}

		let mut seen: Vec<String> = Vec::new();
		for listed in &types {
			let spelled = listed.to_token_stream().to_string();
			if seen.contains(&spelled) {
				return Err(Error::new(listed.span(), "a Catalog lists each type once"));
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

	#[test]
	fn a_struct_with_a_frame_type_and_an_id_is_read() -> Result<()> {
		let input: DeriveInput = parse_quote! {
			#[storable(frame_type = "colony-leaf")]
			struct Leaf {
				#[storable(id)]
				key: RowId,
				colony: String,
			}
		};

		let derived = StorableImpl::try_from(&input)?;
		let frame_type = derived.frame_type.value();
		let id = derived.id.to_string();
		assert_eq!((frame_type.as_str(), id.as_str()), ("colony-leaf", "key"));
		Ok(())
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

	#[test]
	fn a_generic_struct_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[storable(frame_type = "colony-leaf")]
			struct Leaf<T> { #[storable(id)] id: RowId, value: T }
		};
		assert!(StorableImpl::try_from(&input).is_err());
	}

	#[test]
	fn an_enum_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[storable(frame_type = "colony-leaf")]
			enum Leaf { One }
		};
		assert!(StorableImpl::try_from(&input).is_err());
	}

	#[test]
	fn a_tuple_struct_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[storable(frame_type = "colony-leaf")]
			struct Leaf(RowId);
		};
		assert!(StorableImpl::try_from(&input).is_err());
	}

	#[test]
	fn a_struct_without_a_frame_type_is_refused() {
		let input: DeriveInput = parse_quote! {
			struct Leaf { #[storable(id)] id: RowId }
		};
		assert!(StorableImpl::try_from(&input).is_err());
	}

	#[test]
	fn a_second_frame_type_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[storable(frame_type = "colony-leaf")]
			#[storable(frame_type = "colony-seed")]
			struct Leaf { #[storable(id)] id: RowId }
		};
		assert!(StorableImpl::try_from(&input).is_err());
	}

	#[test]
	fn a_frame_type_that_is_no_string_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[storable(frame_type = 7)]
			struct Leaf { #[storable(id)] id: RowId }
		};
		assert!(StorableImpl::try_from(&input).is_err());
	}

	#[test]
	fn an_unknown_struct_key_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[storable(frame_type = "colony-leaf", chained)]
			struct Leaf { #[storable(id)] id: RowId }
		};
		assert!(StorableImpl::try_from(&input).is_err());
	}

	#[test]
	fn an_id_on_the_struct_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[storable(frame_type = "colony-leaf", id)]
			struct Leaf { #[storable(id)] id: RowId }
		};
		assert!(StorableImpl::try_from(&input).is_err());
	}

	#[test]
	fn a_struct_without_an_id_field_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[storable(frame_type = "colony-leaf")]
			struct Leaf { id: RowId }
		};
		assert!(StorableImpl::try_from(&input).is_err());
	}

	#[test]
	fn two_id_fields_are_refused() {
		let input: DeriveInput = parse_quote! {
			#[storable(frame_type = "colony-leaf")]
			struct Leaf { #[storable(id)] id: RowId, #[storable(id)] other: RowId }
		};
		assert!(StorableImpl::try_from(&input).is_err());
	}

	#[test]
	fn a_second_id_on_one_field_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[storable(frame_type = "colony-leaf")]
			struct Leaf { #[storable(id, id)] id: RowId }
		};
		assert!(StorableImpl::try_from(&input).is_err());
	}

	#[test]
	fn a_frame_type_on_a_field_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[storable(frame_type = "colony-leaf")]
			struct Leaf { #[storable(id, frame_type = "colony-seed")] id: RowId }
		};
		assert!(StorableImpl::try_from(&input).is_err());
	}

	#[test]
	fn a_unit_struct_with_a_list_is_a_catalog() -> Result<()> {
		let input: DeriveInput = parse_quote! {
			#[catalog(Leaf, crate::Seed)]
			struct Colony;
		};

		let derived = CatalogImpl::try_from(&input)?;
		assert_eq!(derived.types.len(), 2);
		Ok(())
	}

	#[test]
	fn a_catalog_without_a_list_is_refused() {
		let input: DeriveInput = parse_quote! {
			struct Colony;
		};
		assert!(CatalogImpl::try_from(&input).is_err());
	}

	#[test]
	fn an_empty_catalog_list_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[catalog()]
			struct Colony;
		};
		assert!(CatalogImpl::try_from(&input).is_err());
	}

	#[test]
	fn a_second_catalog_list_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[catalog(Leaf)]
			#[catalog(Seed)]
			struct Colony;
		};
		assert!(CatalogImpl::try_from(&input).is_err());
	}

	#[test]
	fn a_type_listed_twice_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[catalog(Leaf, Seed, Leaf)]
			struct Colony;
		};
		assert!(CatalogImpl::try_from(&input).is_err());
	}

	#[test]
	fn a_catalog_with_fields_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[catalog(Leaf)]
			struct Colony { inner: u8 }
		};
		assert!(CatalogImpl::try_from(&input).is_err());
	}

	#[test]
	fn a_generic_catalog_is_refused() {
		let input: DeriveInput = parse_quote! {
			#[catalog(Leaf)]
			struct Colony<const N: usize>;
		};
		assert!(CatalogImpl::try_from(&input).is_err());
	}
}
