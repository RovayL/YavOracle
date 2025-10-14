use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2, Literal};
use quote::{format_ident, quote};
use syn::{
    braced, parse::Parse, parse::ParseStream, parse_macro_input, Expr, Ident, LitBool, LitInt,
    LitStr, Result, Stmt, Token, Type, Error, ExprLit, ExprPath, Lit,
};


// Parse a label expression limited to either a string literal or a path like Commit::LABEL_t
fn parse_label_expr(input: syn::parse::ParseStream) -> syn::Result<Expr> {
    if input.peek(LitStr) {
        let lit: LitStr = input.parse()?;
        Ok(Expr::Lit(ExprLit { attrs: Vec::new(), lit: Lit::Str(lit) }))
    } else {
        // Path only (no operators), e.g., Commit::LABEL_t
        let path: ExprPath = input.parse()?;
        Ok(Expr::Path(path))
    }
}


#[proc_macro]
pub fn proof(input: TokenStream) -> TokenStream {
    let spec = parse_macro_input!(input as ProofSpec);
    expand(spec).into()
}

// ----------------- AST -----------------

struct ProofSpec {
    name: Ident,
    domain: LitStr,
    public_ty: Type,
    header: Option<HeaderSpec>,
    fields: Vec<FieldSpec>,
    replay: ReplayBlock,
    check: CheckBlock,
}

struct HeaderSpec {
    schema:  Option<syn::LitStr>,  // string
    domain:  Option<syn::LitBool>, // true/false
    version: Option<syn::LitInt>,  // u8
}


struct FieldSpec {
    ident: Ident,
    ty: Type,
    src: FieldSrc,
}

// label: now Expr (supports "literal" or Commit::LABEL_t)
enum FieldSrc {
    Challenge { label: Expr },
    Absorb    { label: Expr },
}

struct ReplayBlock { stmts: Vec<ReplayStmt> }
enum ReplayStmt {
    Let(Stmt),
    BindValue { label: Expr, expr: Expr },
    BindLabel { label: Expr },
}
struct CheckBlock { body: TokenStream2 }

// ----------------- Parse -----------------

impl Parse for ProofSpec {
    fn parse(input: ParseStream) -> Result<Self> {
        // name
        expect_kw(input, "name")?;
        input.parse::<Token![:]>()?;
        let name: Ident = input.parse()?;
        input.parse::<Token![;]>()?;

        // domain
        expect_kw(input, "domain")?;
        input.parse::<Token![:]>()?;
        let domain: LitStr = input.parse()?;
        input.parse::<Token![;]>()?;

        // public
        expect_kw(input, "public")?;
        input.parse::<Token![:]>()?;
        let public_ty: Type = input.parse()?;
        input.parse::<Token![;]>()?;

        // optional header { ... }
        let header = if input.peek(Ident) {
            let fork = input.fork();
            let kw: Ident = fork.parse()?;
            if kw == "header" {
                let _ = input.parse::<Ident>()?;
                Some(HeaderSpec::parse_block(input)?)
            } else { None }
        } else { None };

        // fields { ... }
        expect_kw(input, "fields")?;
        let content;
        braced!(content in input);
        let mut fields = Vec::new();
        while !content.is_empty() {
            let ident: Ident = content.parse()?;
            content.parse::<Token![:]>()?;
            let ty: Type = content.parse()?;
            content.parse::<Token![<=]>()?;
            let which: Ident = content.parse()?;
            let label: Expr  = parse_label_expr(&content)?;
            content.parse::<Token![;]>()?;
            let src = match which.to_string().as_str() {
                "challenge" => FieldSrc::Challenge { label },
                "absorb"    => FieldSrc::Absorb    { label },
                _ => return Err(Error::new(which.span(), "expected `challenge` or `absorb`")),
            };
            fields.push(FieldSpec { ident, ty, src });
        }

        // replay { ... }
        expect_kw(input, "replay")?;
        let replay = ReplayBlock::parse_block(input)?;

        // check { ... }
        expect_kw(input, "check")?;
        let check = CheckBlock::parse_block(input)?;

        if !input.is_empty() {
            return Err(Error::new(input.span(), "unexpected tokens after proof spec"));
        }

        Ok(ProofSpec { name, domain, public_ty, header, fields, replay, check })
    }
}

impl HeaderSpec {
    fn parse_block(input: ParseStream) -> Result<Self> {
        let content;
        braced!(content in input);
        let mut schema = None;
        let mut domain = None;
        let mut version = None;
        while !content.is_empty() {
            let key: Ident = content.parse()?;
            content.parse::<Token![:]>()?;
            match key.to_string().as_str() {
                "schema" => { schema = Some(content.parse::<LitStr>()?); }
                "version" => { version = Some(content.parse::<LitInt>()?); }
                "domain" | "include_domain" => { domain = Some(content.parse::<LitBool>()?); }
                other => return Err(Error::new(key.span(), format!("unknown header key `{other}` (expected schema, version, domain/include_domain)"))),
            }
            content.parse::<Token![;]>()?;
        }
        Ok(HeaderSpec { schema, domain, version })
    }
}

impl ReplayBlock {
    fn parse_block(input: ParseStream) -> Result<Self> {
        let content;
        braced!(content in input);
        let mut stmts = Vec::new();
        while !content.is_empty() {
            // bind ...
            if content.peek(Ident) {
                let fork = content.fork();
                let kw: Ident = fork.parse()?;
                if kw == "bind" {
                    let _ = content.parse::<Ident>()?;
                    let label: Expr = parse_label_expr(&content)?;
                    if content.peek(Token![;]) {
                        content.parse::<Token![;]>()?;
                        stmts.push(ReplayStmt::BindLabel { label });
                        continue;
                    } else {
                        content.parse::<Token![<]>()?;
                        content.parse::<Token![-]>()?;
                        let expr: Expr = content.parse()?;
                        content.parse::<Token![;]>()?;
                        stmts.push(ReplayStmt::BindValue { label, expr });
                        continue;
                    }
                }
            }
            // else: any Rust stmt
            let stmt: Stmt = content.parse()?;
            stmts.push(ReplayStmt::Let(stmt));
        }
        Ok(ReplayBlock { stmts })
    }
}

impl CheckBlock {
    fn parse_block(input: ParseStream) -> Result<Self> {
        let content;
        braced!(content in input);
        let body: TokenStream2 = content.parse()?;
        Ok(CheckBlock { body })
    }
}

fn expect_kw(input: ParseStream, s: &str) -> Result<()> {
    let id: Ident = input.parse()?;
    if id == s { Ok(()) } else { Err(Error::new(id.span(), format!("expected `{s}`"))) }
}

// ----------------- Expand -----------------

fn expand(spec: ProofSpec) -> TokenStream2 {
    let ProofSpec { name, domain, public_ty, header, fields, replay, check } = spec;
    let check_body = check.body;

    // Names
    let proof_name     = format_ident!("{}Proof", name);
    let snake          = to_snake(&name.to_string());
    let mod_name       = format_ident!("{}_proof_mod", snake);
    let fn_prove       = format_ident!("{}_prove", snake);
    let fn_verify      = format_ident!("{}_verify", snake);
    let fn_verify_b    = format_ident!("{}_verify_bytes", snake);
    let fn_src         = format_ident!("{}_verifier_source", snake);

    // Header config (compile-time)
    let header_schema  = header.as_ref().and_then(|h| h.schema.as_ref()).cloned();
    let header_domain  = header.as_ref().and_then(|h| h.domain.as_ref()).cloned();
    let header_version = header.as_ref().and_then(|h| h.version.as_ref()).cloned();

    let version_u8: u8 = header_version.map(|n| n.base10_parse::<u8>().unwrap_or(1)).unwrap_or(1);
    // let schema_u8:  u8 = header_schema .map(|n| n.base10_parse::<u8>().unwrap_or(0)).unwrap_or(0);
    let include_domain: bool = header_domain.map(|b| b.value()).unwrap_or(false);

    // Fields
    let f_ids: Vec<_> = fields.iter().map(|f| &f.ident).collect();
    let f_tys: Vec<_> = fields.iter().map(|f| &f.ty).collect();

    // Prover extraction arms
    let ext: Vec<_> = fields.iter().map(|f| {
        let id = &f.ident; let ty = &f.ty;
        match &f.src {
            FieldSrc::Absorb{label} => quote! {
                let #id: #ty = {
                    let __lbl: &'static str = #label;
                    let bytes = events.iter().rev().find_map(|ev| match ev {
                        fsr_core::RecEvent::Absorb { label, bytes } if *label == __lbl => Some(bytes.as_slice()),
                        _ => None
                    })?;
                    let mut slice = &bytes[..];
                    <#ty as fsr_core::CanonicalDecode>::decode(&mut slice)?
                };
            },
            FieldSrc::Challenge{label} => quote! {
                let #id: #ty = {
                    let __lbl: &'static str = #label;
                    let bytes = events.iter().rev().find_map(|ev| match ev {
                        fsr_core::RecEvent::Challenge { label, bytes } if *label == __lbl => Some(bytes.as_slice()),
                        _ => None
                    })?;
                    let mut slice = &bytes[..];
                    <#ty as fsr_core::CanonicalDecode>::decode(&mut slice)?
                };
            },
        }
    }).collect();

    // Replay → oracle absorbs
    let replay_emit: Vec<_> = replay.stmts.iter().map(|s| match s {
        ReplayStmt::Let(stmt) => quote! { #stmt },
        ReplayStmt::BindValue { label, expr } => quote! {
            {
                let __lbl: &'static str = #label;
                let mut __v = ::std::vec::Vec::new();
                <_ as fsr_core::CanonicalEncode>::encode(&(#expr), &mut __v);
                h.absorb_bytes(__lbl, &__v);
            }
        },
        ReplayStmt::BindLabel { label } => quote! {
            { let __lbl: &'static str = #label; h.absorb_bytes(__lbl, &[]); }
        },
    }).collect();

    // Challenge recompute/compare
    let chall_checks: Vec<_> = fields.iter().filter_map(|f| {
        if let FieldSrc::Challenge{label} = &f.src {
            let id = &f.ident; let ty = &f.ty;
            let prime = format_ident!("{}_prime", id);
            Some(quote! {
                {
                    let __lbl: &'static str = #label;
                    let #prime: #ty = h.challenge::<#ty>(__lbl);
                    let __eq = {
                        let mut a = ::std::vec::Vec::new(); <#ty as fsr_core::CanonicalEncode>::encode(&#prime, &mut a);
                        let mut b = ::std::vec::Vec::new(); <#ty as fsr_core::CanonicalEncode>::encode(&proof.#id, &mut b);
                        a == b
                    };
                    if !__eq { return false; }
                    let #id: #ty = #prime;
                }
            })
        } else { None }
    }).collect();

    // Codec for fields only
    let enc_fields: Vec<_> = f_ids.iter().zip(f_tys.iter())
        .map(|(id,ty)| quote!{ <#ty as fsr_core::CanonicalEncode>::encode(&self.#id, &mut out); })
        .collect();
    let dec_fields: Vec<_> = f_ids.iter().zip(f_tys.iter())
        .map(|(id,ty)| quote!{ let #id: #ty = <#ty as fsr_core::CanonicalDecode>::decode(&mut input)?; })
        .collect();

    // Header encode/decode
    let schema_bytes_len = header_schema.as_ref().map(|s| s.value().len()).unwrap_or(0);
    let schema_bytes = header_schema.as_ref()
        .map(|s| {
            let b = s.value().into_bytes();
            let lits: Vec<_> = b.into_iter().map(|v| Literal::u8_suffixed(v)).collect();
            quote! { [ #( #lits ),* ] }
        })
        .unwrap_or(quote!{ [] });

    let header_encode = quote! {
        out.extend_from_slice(b"FSR\0");           // magic
        out.push(#version_u8);
        // schema (u8 len + bytes)
        out.push(#schema_bytes_len as u8);
        out.extend_from_slice(&#schema_bytes);
        // optional domain (u8 len + bytes)
        if #include_domain {
            out.push(__DOMAIN.len() as u8);
            out.extend_from_slice(__DOMAIN);
        } else {
            out.push(0u8);
        }
    };

    let header_decode = quote! {
        if input.len() < 6 { return None; }
        if &input[..4] != b"FSR\0" { return None; }
        input = &input[4..];
        let _ver = input[0]; input = &input[1..];
        let slen = input[0] as usize; input = &input[1..];
        if input.len() < slen { return None; }
        let _schema = &input[..slen]; input = &input[slen..];
        let dlen = input[0] as usize; input = &input[1..];
        if input.len() < dlen { return None; }
        let _domain = &input[..dlen]; input = &input[dlen..];
    };

    // Verifier source export (string)
    let verifier_src = {
        // Not pretty-printed, but enough to share.
        let src = quote! {
            pub fn verify(pub_in: &#public_ty, bytes: &[u8]) -> bool
            where #( #f_tys: fsr_core::CanonicalEncode + fsr_core::CanonicalDecode + Clone ),*
            {
                let mut input = bytes;
                // header
                #header_decode
                // fields
                #( #dec_fields )*
                // reconstruct
                let mut h = fsr_core::HashOracle::new(__DOMAIN);
                { #( #replay_emit )* }
                { #( #chall_checks )* }
                let __ok: bool = { #check_body };
                __ok
            }
        };
        let s = src.to_string();
        let lit = LitStr::new(&s, Span::call_site());
        quote! { #lit }
    };

    quote! {
        #[allow(non_snake_case)]
        mod #mod_name {
            use super::*;
            pub const __DOMAIN: &'static [u8] = #domain.as_bytes();

            #[derive(Clone, Debug)]
            pub struct #proof_name { #(pub #f_ids: #f_tys,)* }

            impl #proof_name {
                pub fn encode(&self) -> ::std::vec::Vec<u8> {
                    let mut out = ::std::vec::Vec::new();
                    #header_encode
                    #( #enc_fields )*
                    out
                }
                pub fn decode(mut input: &[u8]) -> ::std::option::Option<Self> {
                    #header_decode
                    #( #dec_fields )*
                    ::std::option::Option::Some(Self { #( #f_ids, )* })
                }
            }

            pub fn #fn_prove(events: &[fsr_core::RecEvent]) -> ::std::option::Option<#proof_name>
            where #( #f_tys: fsr_core::CanonicalDecode ),*
            {
                #( #ext )*
                ::std::option::Option::Some(#proof_name { #( #f_ids, )* })
            }

            pub fn #fn_verify(pub_in: &#public_ty, proof: &#proof_name) -> bool
            where #( #f_tys: fsr_core::CanonicalEncode + fsr_core::CanonicalDecode + Clone ),*
            {
                #( let #f_ids: #f_tys = proof.#f_ids.clone(); )*
                let mut h = fsr_core::HashOracle::new(__DOMAIN);
                { #( #replay_emit )* }
                { #( #chall_checks )* }
                let __ok: bool = { #check_body };
                __ok
            }

            pub fn #fn_verify_b(pub_in: &#public_ty, bytes: &[u8]) -> bool
            where #( #f_tys: fsr_core::CanonicalEncode + fsr_core::CanonicalDecode + Clone ),*
            {
                match #proof_name::decode(bytes) {
                    ::std::option::Option::Some(p) => #fn_verify(pub_in, &p),
                    ::std::option::Option::None => false,
                }
            }

            pub fn #fn_src() -> &'static str { #verifier_src }

            pub use #proof_name as Proof;
            pub use #fn_prove as prove;
            pub use #fn_verify as verify;
            pub use #fn_verify_b as verify_bytes;
            pub use #fn_src as verifier_source;
        }

        pub use #mod_name::{Proof as #proof_name, prove as #fn_prove, verify as #fn_verify, verify_bytes as #fn_verify_b, verifier_source as #fn_src};
    }
}

fn to_snake(name: &str) -> Ident {
    let mut out = String::new();
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() {
            if i != 0 { out.push('_'); }
            for c in ch.to_lowercase() { out.push(c); }
        } else { out.push(ch); }
    }
    Ident::new(&out, Span::call_site())
}
