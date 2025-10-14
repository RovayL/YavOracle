use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2, };
use quote::{format_ident, quote, quote_spanned};
use syn::{
    braced, parse::Parse, parse::ParseStream, parse_macro_input, Expr, Ident, LitBool, LitInt,
    LitStr, Result, Stmt, Token, Type, Error, ExprLit, ExprPath, Lit, LitByteStr, spanned::Spanned,
};


// Parse a label expression limited to either a string literal or a path like Commit::LABEL_t
fn parse_label_expr(input: ParseStream) -> syn::Result<Expr> {
    if input.peek(LitStr) {
        let lit: LitStr = input.parse()?;
        Ok(Expr::Lit(ExprLit { attrs: Vec::new(), lit: Lit::Str(lit) }))
    } else {
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
    body: SpecBody,
}

enum SpecBody {
    Single {
        fields: Vec<FieldSpec>,
        replay: ReplayBlock,
        check:  CheckBlock,
    },
    Multi(Vec<RoundSpec>),
}

struct RoundSpec {
    name: Ident,
    fields: Vec<FieldSpec>,
    replay: ReplayBlock,
    check:  CheckBlock,
}

struct HeaderSpec {
    schema: Option<LitStr>,
    domain: Option<LitBool>,
    version: Option<LitInt>,
}

struct FieldSpec {
    ident: Ident,
    ty: Type,
    src: FieldSrc,
}

// Label is kept as Expr (supports "literal" or Commit::LABEL_t path)
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
            if kw == "header" { let _ = input.parse::<Ident>()?; Some(HeaderSpec::parse_block(input)?) } else { None }
        } else { None };

        // Either: one or more "round" blocks, or legacy single blocks
        let body = if input.peek(Ident) {
            let fork = input.fork();
            let kw: Ident = fork.parse()?;
            if kw == "round" {
                let mut rounds = Vec::new();
                while input.peek(Ident) {
                    let probe = input.fork();
                    let k: Ident = probe.parse()?;
                    if k != "round" { break; }
                    // round NAME { fields{} replay{} check{} }
                    let _ = input.parse::<Ident>()?;        // round
                    let rname: Ident = input.parse()?;
                    let content;
                    braced!(content in input);

                    // fields
                    expect_kw(&content, "fields")?;
                    let fblk; braced!(fblk in content);
                    let mut fields = Vec::new();
                    while !fblk.is_empty() {
                        let ident: Ident = fblk.parse()?;
                        fblk.parse::<Token![:]>()?;
                        let ty: Type = fblk.parse()?;
                        fblk.parse::<Token![<=]>()?;
                        let which: Ident = fblk.parse()?;
                        let label: Expr  = parse_label_expr(&fblk)?;
                        fblk.parse::<Token![;]>()?;
                        let src = match which.to_string().as_str() {
                            "challenge" => FieldSrc::Challenge { label },
                            "absorb"    => FieldSrc::Absorb    { label },
                            _ => return Err(Error::new(which.span(), "expected `challenge` or `absorb`")),
                        };
                        fields.push(FieldSpec { ident, ty, src });
                    }

                    // replay
                    expect_kw(&content, "replay")?;
                    let replay = ReplayBlock::parse_block(&content)?;

                    // check
                    expect_kw(&content, "check")?;
                    let check = CheckBlock::parse_block(&content)?;

                    rounds.push(RoundSpec { name: rname, fields, replay, check });
                }
                SpecBody::Multi(rounds)
            } else {
                let (fields, replay, check) = parse_single_body(input)?;
                SpecBody::Single { fields, replay, check }
            }
        } else {
            let (fields, replay, check) = parse_single_body(input)?;
            SpecBody::Single { fields, replay, check }
        };

        if !input.is_empty() {
            return Err(Error::new(input.span(), "unexpected tokens after proof spec"));
        }
        Ok(ProofSpec { name, domain, public_ty, header, body })
    }
}

fn parse_single_body(input: ParseStream) -> Result<(Vec<FieldSpec>, ReplayBlock, CheckBlock)> {
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
    Ok((fields, replay, check))
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



// helper: collect labels from fields, necessary for the multiround protocol
fn labels_in_fields(fs: &[FieldSpec]) -> Vec<syn::Expr> {
    let mut acc = Vec::new();
    for f in fs {
        match &f.src {
            FieldSrc::Absorb { label } | FieldSrc::Challenge { label } => acc.push(label.clone()),
        }
    }
    acc
}

// helper: collect labels from replay block
fn labels_in_replay(rb: &ReplayBlock) -> Vec<syn::Expr> {
    let mut acc = Vec::new();
    for s in &rb.stmts {
        match s {
            ReplayStmt::BindValue { label, .. } | ReplayStmt::BindLabel { label } => {
                acc.push(label.clone())
            }
            _ => {}
        }
    }
    acc
}

// ----------------- Expand -----------------

fn expand(spec: ProofSpec) -> TokenStream2 {
    let ProofSpec { name, domain, public_ty, header, body } = spec;

    // names reused
    let proof_name     = format_ident!("{}Proof", name);
    let snake          = to_snake(&name.to_string());
    let mod_name       = format_ident!("{}_proof_mod", snake);
    let fn_prove       = format_ident!("{}_prove", snake);
    let fn_verify      = format_ident!("{}_verify", snake);
    let fn_verify_b    = format_ident!("{}_verify_bytes", snake);
    let fn_src         = format_ident!("{}_verifier_source", snake);

    // header compile-time config (use existing code)
    // ... (version_u8, include_domain, schema string bytes or the simple header) ...
    // reuse the #header_encode and #header_decode snippets

    // (helper to build replay emission for a block)
    let emit_replay = |rb: &ReplayBlock| -> Vec<TokenStream2> {
        rb.stmts.iter().map(|s| match s {
            ReplayStmt::Let(stmt) => quote!{ #stmt },
            ReplayStmt::BindValue { label, expr } => quote!{
                {
                    let __lbl: &'static str = #label;
                    let mut __v = ::std::vec::Vec::new();
                    <_ as fsr_core::CanonicalEncode>::encode(&(#expr), &mut __v);
                    h.absorb_bytes(__lbl, &__v);
                }
            },
            ReplayStmt::BindLabel { label } => quote!{
                { let __lbl: &'static str = #label; h.absorb_bytes(__lbl, &[]); }
            },
        }).collect()
    };

    // collect label exprs for compile-time type checks (&'static str)
    fn labels_in_fields(fs: &[FieldSpec]) -> Vec<syn::Expr> {
        let mut acc = Vec::new();
        for f in fs {
            match &f.src {
                FieldSrc::Absorb { label } | FieldSrc::Challenge { label } => acc.push(label.clone()),
            }
        }
        acc
    }
    fn labels_in_replay(rb: &ReplayBlock) -> Vec<Expr> {
        let mut acc = Vec::new();
        for s in &rb.stmts {
            match s {
                ReplayStmt::BindValue{label,..} | ReplayStmt::BindLabel{label} => acc.push(label.clone()),
                _ => {}
            }
        }
        acc
    }

    let domain_bytes = LitByteStr::new(domain.value().as_bytes(), proc_macro2::Span::call_site());

    // Pull options
    let (schema_opt, version_opt, domflag_opt) = if let Some(h) = &header {
        (h.schema.clone(), h.version.clone(), h.domain.clone())
    } else {
        (None, None, None)
    };

    // Version
    let version_u8: u8 = version_opt
        .as_ref()
        .and_then(|n| n.base10_parse::<u8>().ok())
        .unwrap_or(1);

    // Include domain?
    let include_domain: bool = domflag_opt
        .as_ref()
        .map(|b| b.value())
        .unwrap_or(false);

    // Schema emit (string)
    let schema_encode = if let Some(s) = &schema_opt {
        quote!({
            const __SCHEMA: &str = #s;
            out.push(__SCHEMA.len() as u8);
            out.extend_from_slice(__SCHEMA.as_bytes());
        })
    } else {
        quote!( { out.push(0u8); } )
    };

    // Header encode/decode tokens
    let header_encode = quote! {
        out.extend_from_slice(b"FSR\0");
        out.push(#version_u8);
        #schema_encode
        if #include_domain {
            let dlen: u8 = __DOMAIN.len() as u8;
            out.push(dlen);
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

        if input.is_empty() { return None; }
        let slen = input[0] as usize; input = &input[1..];
        if input.len() < slen { return None; }
        let _schema = &input[..slen]; input = &input[slen..];

        if input.is_empty() { return None; }
        let dlen = input[0] as usize; input = &input[1..];
        if input.len() < dlen { return None; }
        let _domain = &input[..dlen]; input = &input[dlen..];
    };

    match body {
        SpecBody::Single { fields, replay, check } => {
            // --- collect field idents/types ---
            let f_ids: Vec<Ident> = fields.iter().map(|f| f.ident.clone()).collect();
            let f_tys: Vec<Type>  = fields.iter().map(|f| f.ty.clone()).collect();

            // --- enc/dec for all fields ---
            let enc_fields: Vec<_> = f_ids.iter().zip(f_tys.iter())
                .map(|(id,ty)| quote! { <#ty as fsr_core::CanonicalEncode>::encode(&self.#id, &mut out); })
                .collect();

            let dec_fields: Vec<_> = f_ids.iter().zip(f_tys.iter())
                .map(|(id,ty)| quote! { let #id: #ty = <#ty as fsr_core::CanonicalDecode>::decode(&mut input)?; })
                .collect();

            // --- compile-time label checks (types of labels must coerce to &'static str) ---
            let mut label_checks: Vec<TokenStream2> = Vec::new();
            for e in fields.iter().filter_map(|f| match &f.src {
                FieldSrc::Absorb{label} | FieldSrc::Challenge{label} => Some(label.clone()),
            }) {
                label_checks.push(quote_spanned! { e.span()=> { let _: &'static str = #e; } });
            }
            for e in replay.stmts.iter().filter_map(|s| match s {
                ReplayStmt::BindValue{label,..} | ReplayStmt::BindLabel{label} => Some(label.clone()),
                _ => None,
            }) {
                label_checks.push(quote_spanned! { e.span()=> { let _: &'static str = #e; } });
            }

            // --- prove: extract each field by scanning events forward (cursor), then return Proof ---
            let prove_extracts: Vec<_> = fields.iter().map(|f| {
                let id = &f.ident;
                let ty = &f.ty;
                match &f.src {
                    FieldSrc::Absorb{label} => quote! {
                        let #id: #ty = {
                            let __lbl: &'static str = #label;
                            let bytes = next_absorb(events, &mut __cur, __lbl)?;
                            let mut s = bytes;
                            <#ty as fsr_core::CanonicalDecode>::decode(&mut s)?
                        };
                    },
                    FieldSrc::Challenge{label} => quote! {
                        let #id: #ty = {
                            let __lbl: &'static str = #label;
                            let bytes = next_challenge(events, &mut __cur, __lbl)?;
                            let mut s = bytes;
                            <#ty as fsr_core::CanonicalDecode>::decode(&mut s)?
                        };
                    },
                }
            }).collect();

            // --- verify: replay bindings, re-derive challenges, run final check ---
            let replay_emit = emit_replay(&replay);

            let chall_checks: Vec<_> = fields.iter().filter_map(|f| {
                if let FieldSrc::Challenge{label} = &f.src {
                    let id = &f.ident;
                    let ty = &f.ty;
                    let prime = format_ident!("{}_prime", id);
                    Some(quote! {
                        {
                            let __lbl: &'static str = #label;
                            let #prime: #ty = h.challenge::<#ty>(__lbl);
                            let __eq = {
                                let mut a = ::std::vec::Vec::new(); <#ty as fsr_core::CanonicalEncode>::encode(&#prime, &mut a);
                                let mut b = ::std::vec::Vec::new(); <#ty as fsr_core::CanonicalEncode>::encode(&#id, &mut b);
                                a == b
                            };
                            if !__eq { return false; }
                            // shadow with the re-derived value if one wants to use `id` later
                            let #id: #ty = #prime;
                        }
                    })
                } else { None }
            }).collect();

            let body_ts = &check.body;

            // --- verifier-source (pretty-printed verify function) ---
            let verifier_src = {
                let src = quote! {
                    pub fn verify(pub_in: &#public_ty, bytes: &[u8]) -> bool
                    where #( #f_tys: fsr_core::CanonicalEncode + fsr_core::CanonicalDecode + Clone ),*
                    {
                        let mut input = bytes;
                        #header_decode
                        #( #dec_fields )*
                        let proof = #proof_name { #( #f_ids, )* };
                        let mut h = fsr_core::HashOracle::new(__DOMAIN);
                        // bring fields into locals
                        #( let #f_ids: #f_tys = proof.#f_ids.clone(); )*
                        { #( #replay_emit )* }
                        { #( #chall_checks )* }
                        let __ok: bool = { #body_ts };
                        __ok
                    }
                };
                let s = src.to_string();
                let lit = syn::LitStr::new(&s, proc_macro2::Span::call_site());
                quote! { #lit }
            };

            quote! {
                #[allow(non_snake_case)]
                mod #mod_name {
                    use super::*;
                    pub const __DOMAIN: &'static [u8] = #domain_bytes;

                    // compile-time label type checks
                    const _: () = { #( #label_checks )* };

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

                    // forward-scanning helpers shared with multi-round
                    fn next_absorb<'a>(events: &'a [fsr_core::RecEvent], cur: &mut usize, lbl: &'static str) -> Option<&'a [u8]> {
                        for i in *cur..events.len() {
                            if let fsr_core::RecEvent::Absorb{ label, bytes } = &events[i] {
                                if *label == lbl { *cur = i+1; return Some(bytes.as_slice()); }
                            }
                        }
                        None
                    }
                    fn next_challenge<'a>(events: &'a [fsr_core::RecEvent], cur: &mut usize, lbl: &'static str) -> Option<&'a [u8]> {
                        for i in *cur..events.len() {
                            if let fsr_core::RecEvent::Challenge{ label, bytes } = &events[i] {
                                if *label == lbl { *cur = i+1; return Some(bytes.as_slice()); }
                            }
                        }
                        None
                    }

                    pub fn #fn_prove(events: &[fsr_core::RecEvent]) -> ::std::option::Option<#proof_name>
                    where #( #f_tys: fsr_core::CanonicalDecode ),*
                    {
                        let mut __cur: usize = 0;
                        #( #prove_extracts )*
                        ::std::option::Option::Some(#proof_name { #( #f_ids, )* })
                    }

                    pub fn #fn_verify(pub_in: &#public_ty, proof: &#proof_name) -> bool
                    where #( #f_tys: fsr_core::CanonicalEncode + fsr_core::CanonicalDecode + Clone ),*
                    {
                        let mut h = fsr_core::HashOracle::new(__DOMAIN);
                        // bring fields into locals
                        #( let #f_ids: #f_tys = proof.#f_ids.clone(); )*
                        { #( #replay_emit )* }
                        { #( #chall_checks )* }
                        let __ok: bool = { #body_ts };
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

                pub use #mod_name::{
                    Proof as #proof_name,
                    #fn_prove, #fn_verify, #fn_verify_b, #fn_src
                };
            }
        }


        SpecBody::Multi(rounds) => {
            // Flatten fields in order (for the Proof struct and encode/decode)
            let mut all_ids = Vec::<Ident>::new();
            let mut all_tys = Vec::<Type>::new();

            for r in &rounds {
                for f in &r.fields {
                    all_ids.push(f.ident.clone());
                    all_tys.push(f.ty.clone());
                }
            }

            // enc/dec for all fields
            let enc_fields: Vec<_> = all_ids.iter().zip(all_tys.iter())
                .map(|(id,ty)| quote!{ <#ty as fsr_core::CanonicalEncode>::encode(&self.#id, &mut out); })
                .collect();
            let dec_fields: Vec<_> = all_ids.iter().zip(all_tys.iter())
                .map(|(id,ty)| quote!{ let #id: #ty = <#ty as fsr_core::CanonicalDecode>::decode(&mut input)?; })
                .collect();

            // label compile-time checks
            use quote::quote_spanned;
            use syn::spanned::Spanned;

            // Build compile-time label checks (types must be &'static str)
            let mut label_checks: Vec<TokenStream2> = Vec::new();
            for r in &rounds {
                // from round fields
                for f in &r.fields {
                    match &f.src {
                        FieldSrc::Absorb { label } | FieldSrc::Challenge { label } => {
                            let e = label.clone();
                            label_checks.push(quote_spanned! { e.span()=> {
                                let _: &'static str = #e;
                            }});
                        }
                    }
                }
                // from replay statements
                for s in &r.replay.stmts {
                    match s {
                        ReplayStmt::BindValue { label, .. } | ReplayStmt::BindLabel { label } => {
                            let e = label.clone();
                            label_checks.push(quote_spanned! { e.span()=> {
                                let _: &'static str = #e;
                            }});
                        }
                        _ => {}
                    }
                }
            }

            // per-round blocks for PROVE(): consume events in order
            let prove_rounds: Vec<_> = rounds.iter().map(|r| {
                // for each field, generate extraction with cursor
                let ext: Vec<_> = r.fields.iter().map(|f| {
                    let id = &f.ident;
                    let ty = &f.ty;
                    match &f.src {
                        FieldSrc::Absorb { label } => quote! {
                            let #id: #ty = {
                                let __lbl: &'static str = #label;
                                let bytes = next_absorb(events, &mut __cur, __lbl)?;
                                let mut s = bytes;
                                <#ty as fsr_core::CanonicalDecode>::decode(&mut s)?
                            };
                        },
                        FieldSrc::Challenge { label } => quote! {
                            let #id: #ty = {
                                let __lbl: &'static str = #label;
                                let bytes = next_challenge(events, &mut __cur, __lbl)?;
                                let mut s = bytes;
                                <#ty as fsr_core::CanonicalDecode>::decode(&mut s)?
                            };
                        },
                    }
                }).collect();
                quote!{
                    #( #ext )*
                }
            }).collect();

            // per-round blocks for VERIFY(): bind local copies, replay, recheck challenges, then check
            let verify_rounds: Vec<_> = rounds.iter().map(|r| {
                let f_ids: Vec<_> = r.fields.iter().map(|f| &f.ident).collect();
                let f_tys: Vec<_> = r.fields.iter().map(|f| &f.ty).collect();
                // replay emission
                let replay_emit = emit_replay(&r.replay);
                // challenge re-derivation compares
                let chall_checks: Vec<_> = r.fields.iter().filter_map(|f| {
                    if let FieldSrc::Challenge{label} = &f.src {
                        let id = &f.ident; let ty = &f.ty;
                        let prime = format_ident!("{}_prime", id);
                        Some(quote! {
                            {
                                let __lbl: &'static str = #label;
                                let #prime: #ty = h.challenge::<#ty>(__lbl);
                                let __eq = {
                                    let mut a = ::std::vec::Vec::new(); <#ty as fsr_core::CanonicalEncode>::encode(&#prime, &mut a);
                                    let mut b = ::std::vec::Vec::new(); <#ty as fsr_core::CanonicalEncode>::encode(&#id, &mut b);
                                    a == b
                                };
                                if !__eq { return false; }
                            }
                        })
                    } else { None }
                }).collect();

                // round check body
                let body = &r.check.body;

                quote!{
                    {
                        // bring round's proof fields into locals
                        #( let #f_ids: #f_tys = proof.#f_ids.clone(); )*
                        { #( #replay_emit )* }
                        { #( #chall_checks )* }
                        let __ok: bool = { #body };
                        if !__ok { return false; }
                    }
                }
            }).collect();

            // per-round verifier-source: same structure but reconstructed from tokens -> string
            let verifier_src = {
                let vr = verify_rounds.clone(); // reuse
                let src = quote! {
                    pub fn verify(pub_in: &#public_ty, bytes: &[u8]) -> bool
                    where #( #all_tys: fsr_core::CanonicalEncode + fsr_core::CanonicalDecode + Clone ),*
                    {
                        let mut input = bytes;
                        #header_decode
                        #( #dec_fields )*
                        let proof = #proof_name { #( #all_ids, )* };
                        let mut h = fsr_core::HashOracle::new(__DOMAIN);
                        #( #vr )*
                        true
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
                    pub const __DOMAIN: &'static [u8] = #domain_bytes;

                    // compile-time label type checks
                    const _: () = { #( #label_checks )* };

                    #[derive(Clone, Debug)]
                    pub struct #proof_name { #(pub #all_ids: #all_tys,)* }

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
                            ::std::option::Option::Some(Self { #( #all_ids, )* })
                        }
                    }

                    // forward-scanning helpers (consume next matching event)
                    fn next_absorb<'a>(events: &'a [fsr_core::RecEvent], cur: &mut usize, lbl: &'static str) -> Option<&'a [u8]> {
                        for i in *cur..events.len() {
                            if let fsr_core::RecEvent::Absorb{ label, bytes } = &events[i] {
                                if *label == lbl {
                                    *cur = i+1; return Some(bytes.as_slice());
                                }
                            }
                        }
                        None
                    }
                    fn next_challenge<'a>(events: &'a [fsr_core::RecEvent], cur: &mut usize, lbl: &'static str) -> Option<&'a [u8]> {
                        for i in *cur..events.len() {
                            if let fsr_core::RecEvent::Challenge{ label, bytes } = &events[i] {
                                if *label == lbl {
                                    *cur = i+1; return Some(bytes.as_slice());
                                }
                            }
                        }
                        None
                    }

                    pub fn #fn_prove(events: &[fsr_core::RecEvent]) -> ::std::option::Option<#proof_name>
                    where #( #all_tys: fsr_core::CanonicalDecode ),*
                    {
                        let mut __cur: usize = 0;
                        #( #prove_rounds )*
                        ::std::option::Option::Some(#proof_name { #( #all_ids, )* })
                    }

                    pub fn #fn_verify(pub_in: &#public_ty, proof: &#proof_name) -> bool
                    where #( #all_tys: fsr_core::CanonicalEncode + fsr_core::CanonicalDecode + Clone ),*
                    {
                        let mut h = fsr_core::HashOracle::new(__DOMAIN);
                        #( #verify_rounds )*
                        true
                    }

                    pub fn #fn_verify_b(pub_in: &#public_ty, bytes: &[u8]) -> bool
                    where #( #all_tys: fsr_core::CanonicalEncode + fsr_core::CanonicalDecode + Clone ),*
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
