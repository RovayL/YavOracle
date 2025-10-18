use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::{
    parse_macro_input, spanned::Spanned, Attribute, Data, DeriveInput, Fields, LitInt, LitStr, Path, DataStruct, ItemFn, Macro
};
use syn::visit::{self, Visit};

/// We purposely name the derive macro **FsrBindable** to avoid any name collision
/// with the runtime trait `fsr_core::Bindable`.
///
/// Usage:
///   #[derive(FsrBindable)]
///   #[bind(prefix = "Commit", core = "fsr_core")]   // optional (defaults shown)
///   struct Commit {
///       #[bind(ob = 0)] t: G1,                      // contributes obligation bit (1<<0)
///       #[bind(label = "commit.t")]                 // optional, default is "Commit.t"
///       #[bind(skip)]                               // optional: do not bind this field
///   }
#[proc_macro_derive(FsrBindable, attributes(bind))]
pub fn derive_fsr_bindable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match do_derive(input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}


fn do_derive(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let type_ident = input.ident.clone();
    let type_name = type_ident.to_string();

    // ---- struct-level options: #[bind(prefix="...")] and #[bind(core="path::to::crate")]
    let mut prefix: Option<String> = None;
    let mut core_path: Option<Path> = None;

    for attr in input.attrs.iter().filter(|a| a.path().is_ident("bind")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("prefix") {
                let v: LitStr = meta.value()?.parse()?;
                prefix = Some(v.value());
                return Ok(());
            }
            if meta.path.is_ident("core") {
                let v: LitStr = meta.value()?.parse()?;
                let p: Path = syn::parse_str(&v.value())
                    .map_err(|e| syn::Error::new(v.span(), format!("bad core path: {e}")))?;
                core_path = Some(p);
                return Ok(());
            }
            // ignore unknown keys at struct level
            Ok(())
        })?;
    }

    let core = core_path.unwrap_or_else(|| syn::parse_str("fsr_core").unwrap());
    let prefix_str = prefix.unwrap_or_else(|| type_name.clone());

    // ---- per-field: gather bind statements + OBLIG_MASK terms
    let (bind_stmts, mask_terms) = match &input.data {
        Data::Struct(ds) => match &ds.fields {
            Fields::Named(fields) => {
                let mut stmts = Vec::new();
                let mut masks = Vec::new();
                for f in &fields.named {
                    let fname = f
                        .ident
                        .as_ref()
                        .ok_or_else(|| syn::Error::new(f.span(), "expected named field"))?;
                    let default_label = format!("{prefix_str}.{fname}");
                    let FieldCfg { include, label, ob_bit } = parse_field_cfg(&f.attrs, &default_label)?;
                    if include {
                        let label_lit = LitStr::new(&label, f.span());
                        stmts.push(quote! {
                            {
                                let mut __v = ::std::vec::Vec::new();
                                #core::CanonicalEncode::encode(&self.#fname, &mut __v);
                                #core::Absorb::absorb_bytes(a, #label_lit, &__v);
                            }
                        });
                    }
                    if let Some(bit) = ob_bit {
                        let lit = LitInt::new(&bit.to_string(), f.span());
                        masks.push(quote! { (1u128 << #lit) });
                    }
                }
                (stmts, masks)
            }
            Fields::Unnamed(fields) => {
                let mut stmts = Vec::new();
                let mut masks = Vec::new();
                for (i, f) in fields.unnamed.iter().enumerate() {
                    let idx = syn::Index::from(i);
                    let default_label = format!("{prefix_str}.{i}");
                    let FieldCfg { include, label, ob_bit } = parse_field_cfg(&f.attrs, &default_label)?;
                    if include {
                        let label_lit = LitStr::new(&label, f.span());
                        stmts.push(quote! {
                            {
                                let mut __v = ::std::vec::Vec::new();
                                #core::CanonicalEncode::encode(&self.#idx, &mut __v);
                                #core::Absorb::absorb_bytes(a, #label_lit, &__v);
                            }
                        });
                    }
                    if let Some(bit) = ob_bit {
                        let lit = LitInt::new(&bit.to_string(), f.span());
                        masks.push(quote! { (1u128 << #lit) });
                    }
                }
                (stmts, masks)
            }
            Fields::Unit => (Vec::new(), Vec::new()),
        },
        _ => {
            return Err(syn::Error::new(
                input.span(),
                "FsrBindable can only be derived for structs",
            ))
        }
    };



    // =========================================================================================

    // Determine prefix string for labels (e.g., "Commit")
    // If one already parsed #[bind(prefix="...")], use that value. Otherwise default to the type name.
    // let prefix_str: String = match parsed_prefix_opt {
    //     Some(s) => s,                     // the parsed prefix string
    //     None    => type_ident.to_string() // fallback to type name
    // };
    let prefix_lit = LitStr::new(&prefix_str, Span::call_site());

    // Build per-field label consts for all *named* fields that are NOT #[bind(skip)]
    let mut field_label_consts = Vec::new();

    match &input.data {
        Data::Struct(DataStruct { fields: Fields::Named(named), .. }) => {
            for field in &named.named {
                // Check if this field has #[bind(skip)]
                let mut skip = false;
                for attr in &field.attrs {
                    if attr.path().is_ident("bind") {
                        // syn v2 API
                        let _ = attr.parse_nested_meta(|meta| {
                            if meta.path.is_ident("skip") {
                                skip = true;
                            }
                            Ok(())
                        });
                    }
                }
                if skip { continue; }

                // Field ident (e.g., `t`, `z`)
                let fname_ident = field.ident.as_ref()
                    .expect("FsrBindable expects named fields");

                // LABEL_<field> const name, e.g., LABEL_t
                let const_ident = format_ident!("LABEL_{}", fname_ident);

                // "Type.field" string, e.g., "Commit.t"
                let label_lit = LitStr::new(
                    &format!("{}.{}", prefix_str, fname_ident),
                    Span::call_site()
                );

                field_label_consts.push(quote! {
                    pub const #const_ident: &'static str = #label_lit;
                });
            }
        }
        _ => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "FsrBindable only supports structs with named fields",
            ));
        }
    }

    // Add an inherent impl that exports MSG_LABEL and LABEL_<field> for the struct
    let labels_impl = quote! {
        impl #type_ident {
            pub const MSG_LABEL: &'static str = #prefix_lit;
            #( #field_label_consts )*
        }
    };

    // ========================================================================================================

    let mask_expr = if mask_terms.is_empty() {
        quote! { 0u128 }
    } else {
        quote! { 0u128 #(| #mask_terms)* }
    };

    // NOTE: we implement the *runtime* trait `fsr_core::Bindable`
    let expanded = quote! {
        impl #core::Bindable for #type_ident {
            const OBLIG_MASK: u128 = #mask_expr;

            fn bind<A: #core::Absorb>(&self, a: &mut A) {
                #(#bind_stmts)*
            }
        }

        #labels_impl
    };

    Ok(expanded)
}

struct FieldCfg {
    include: bool,
    label: String,
    ob_bit: Option<u32>,
}

fn parse_field_cfg(attrs: &[Attribute], default_label: &str) -> syn::Result<FieldCfg> {
    let mut include = true;                 // coverage-by-default
    let mut label = default_label.to_string();
    let mut ob_bit: Option<u32> = None;

    for attr in attrs.iter().filter(|a| a.path().is_ident("bind")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                include = false;
                return Ok(());
            }
            if meta.path.is_ident("label") {
                let v: LitStr = meta.value()?.parse()?;
                label = v.value();
                return Ok(());
            }
            if meta.path.is_ident("ob") {
                let v: LitInt = meta.value()?.parse()?;
                ob_bit = Some(v.base10_parse::<u32>()?);
                return Ok(());
            }
            // unknown per-field key: ignore
            Ok(())
        })?;
    }

    Ok(FieldCfg { include, label, ob_bit })
}




// -------------------------------------    BARRIER LINT FOR FISCHLIN TRANSFORM    -------------------------------------


#[proc_macro_attribute]
pub fn enforce_fischlin_barrier(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as ItemFn);
    let mut v = BarrierVisitor::default();
    v.visit_item_fn(&func);

    if v.first_prove_round_pos.is_some()
        && (v.first_seal_pos.is_none() || v.first_seal_pos > v.first_prove_round_pos)
    {
        let msg = "Fischlin: missing `seal_first_messages!()` BEFORE any `fischlin_*prove*round*()`.\n\
                   Ensure the entire vector of first messages is sealed into the oracle (common_h) \
                   before starting the e-search.";
        let err = syn::Error::new_spanned(&func.sig.ident, msg).to_compile_error();
        return quote!(#err #func).into();
    }

    quote!(#func).into()
}

#[derive(Default)]
struct BarrierVisitor {
    first_seal_pos: Option<usize>,
    first_prove_round_pos: Option<usize>,
    idx: usize,
}

impl<'ast> Visit<'ast> for BarrierVisitor {
    fn visit_macro(&mut self, m: &'ast Macro) {
        // detect macro names like seal_first_messages, fischlin_prove_round, etc.
        if let Some(ident) = m.path.segments.last().map(|s| s.ident.to_string()) {
            match ident.as_str() {
                "seal_first_messages" => {
                    if self.first_seal_pos.is_none() {
                        self.first_seal_pos = Some(self.idx);
                    }
                }
                // cover both spellings we used
                "fischlin_prove_round" | "fischlin_prove_round_stream" | "fischlin_search_round" => {
                    if self.first_prove_round_pos.is_none() {
                        self.first_prove_round_pos = Some(self.idx);
                    }
                }
                _ => {}
            }
        }
        self.idx += 1;

        // call the default traversal (requires `syn` feature = "visit")
        visit::visit_macro(self, m);
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        visit::visit_item_fn(self, i);
    }
}




