use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2, };
use quote::{format_ident, quote, quote_spanned};
use syn::{
    braced, parse::Parse, parse::ParseStream, parse_macro_input, Expr, ExprClosure, Ident, LitBool, LitInt,
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
    Single {                        // legacy (your current shape)
        fields: Vec<FieldSpec>,
        replay: ReplayBlock,
        check:  CheckBlock,
    },
    Multi(Vec<RoundSpec>),          // NEW: multi-round
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

    // header compile-time config (use your existing code)
    // ... (version_u8, include_domain, schema string bytes or your simple header) ...
    // reuse your #header_encode and #header_decode snippets
    // (omitted here for brevity; keep exactly what’s working for you)

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
                            let #prime: #ty = match h.challenge::<#ty>(__lbl) {
                                ::core::result::Result::Ok(c) => c,
                                ::core::result::Result::Err(_) => return false,
                            };
                            let __eq = {
                                let mut a = ::std::vec::Vec::new(); <#ty as fsr_core::CanonicalEncode>::encode(&#prime, &mut a);
                                let mut b = ::std::vec::Vec::new(); <#ty as fsr_core::CanonicalEncode>::encode(&#id, &mut b);
                                a == b
                            };
                            if !__eq { return false; }
                            // shadow with the re-derived value if you want to use `id` later
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
                                let #prime: #ty = match h.challenge::<#ty>(__lbl) {
                                    ::core::result::Result::Ok(c) => c,
                                    ::core::result::Result::Err(_) => return false,
                                };
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


// === Fischlin prover/verifier macros ========================================

struct ProveArgs {
    transform: Option<String>,
    oracle: Expr,
    rho: Expr,
    b: Expr,
    statement: Expr,
    sid: Expr,
    first: ExprClosure,
    respond: ExprClosure,
    respond_stream: Option<ExprClosure>,
}

impl Parse for ProveArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut transform = None;
        let mut oracle = None;
        let mut rho = None;
        let mut b = None;
        let mut statement = None;
        let mut sid = None;
        let mut first = None;
        let mut respond = None;
        let mut respond_stream = None;
        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let key = ident.to_string();
            match key.as_str() {
                "transform" => {
                    let lit: LitStr = input.parse()?;
                    transform = Some(lit.value());
                }
                "oracle" => oracle = Some(input.parse()?),
                "rho" => rho = Some(input.parse()?),
                "b" => b = Some(input.parse()?),
                "statement" => statement = Some(input.parse()?),
                "sid" => sid = Some(input.parse()?),
                "first" => first = Some(input.parse()?),
                "respond" => respond = Some(input.parse()?),
                "respond_stream" => respond_stream = Some(input.parse()?),
                other => return Err(Error::new(ident.span(), format!("unknown key `{other}`"))),
            }
            let _ = input.parse::<Token![,]>();
        }

        Ok(ProveArgs {
            transform,
            oracle: oracle.ok_or_else(|| Error::new(Span::call_site(), "missing `oracle`"))?,
            rho: rho.ok_or_else(|| Error::new(Span::call_site(), "missing `rho`"))?,
            b: b.ok_or_else(|| Error::new(Span::call_site(), "missing `b`"))?,
            statement: statement.ok_or_else(|| Error::new(Span::call_site(), "missing `statement`"))?,
            sid: sid.ok_or_else(|| Error::new(Span::call_site(), "missing `sid`"))?,
            first: first.ok_or_else(|| Error::new(Span::call_site(), "missing `first`"))?,
            respond: respond.ok_or_else(|| Error::new(Span::call_site(), "missing `respond`"))?,
            respond_stream,
        })
    }
}

fn expand_prove_fischlin(args: ProveArgs) -> TokenStream2 {
    let ProveArgs {
        oracle,
        rho,
        b,
        statement,
        sid,
        first,
        respond,
        respond_stream,
        ..
    } = args;

    let search_loop = if let Some(rs) = respond_stream {
        quote! {
            let mut __respond_stream = (#rs);
            for __i in 0..(__rho_u16 as usize) {
                let mut __z_stream = __respond_stream(__i, &__sigmas[__i]);
                let (__e_out, __z_out) = __oracle.search_round_stream(__i as u32, || __z_stream())?;
                __e_vec.push(__e_out);
                __z_vec.push(__z_out);
            }
        }
    } else {
        quote! {
            let mut __respond = (#respond);
            for __i in 0..(__rho_u16 as usize) {
                let (__e_out, __z_out) = __oracle.search_round(__i as u32, |__e_try: &[u8]| {
                    __respond(__i, __e_try, &__sigmas[__i])
                })?;
                __e_vec.push(__e_out);
                __z_vec.push(__z_out);
            }
        }
    };
    quote!({
        use fsr_core::FischlinProof;
        let __result: fsr_core::Result<FischlinProof> = (|| {
            let mut __oracle = #oracle;
            let __rho_u16: u16 = (#rho);
            let mut __first = (#first);
            let __stmt_owned = (#statement);
            let __sid_owned = (#sid);
            let __stmt: &[u8] = ::core::convert::AsRef::<[u8]>::as_ref(&__stmt_owned);
            let __sid: &[u8] = ::core::convert::AsRef::<[u8]>::as_ref(&__sid_owned);

            __oracle.begin(__stmt, __sid);

            let mut __first_msgs = ::std::vec::Vec::with_capacity(__rho_u16 as usize);
            let mut __sigmas = ::std::vec::Vec::with_capacity(__rho_u16 as usize);
            for __i in 0..(__rho_u16 as usize) {
                let (__m_bytes, __sigma) = __first(__i);
                __oracle.push_first_message(&__m_bytes)?;
                __first_msgs.push(__m_bytes);
                __sigmas.push(__sigma);
            }

            __oracle.seal_first_messages()?;

            let mut __e_vec = ::std::vec::Vec::with_capacity(__rho_u16 as usize);
            let mut __z_vec = ::std::vec::Vec::with_capacity(__rho_u16 as usize);

            #search_loop

            Ok(FischlinProof { m: __first_msgs, e: __e_vec, z: __z_vec, b: (#b), rho: (#rho) })
        })();
        __result
    })
}

fn expand_prove_fs(args: ProveArgs) -> TokenStream2 {
    let ProveArgs {
        oracle,
        rho: _rho_unused,
        b: _b_unused,
        statement,
        sid,
        first,
        respond,
        respond_stream,
        ..
    } = args;

    if let Some(rs) = respond_stream {
        return Error::new(rs.span(), "`respond_stream` is only supported for transform = \"fischlin\"")
            .to_compile_error();
    }

    // FS variant: ignore rho and b; sample a single challenge after absorbing inputs.
    quote!({
        use fsr_core::TranscriptRuntime;
        let __result: fsr_core::Result<fsr_core::FsProof> = (|| {
            let mut __fs_ro = #oracle;
            let mut __oracle = fsr_core::FSOracle::new(__fs_ro);

            let __stmt_owned = (#statement);
            let __sid_owned = (#sid);
            let __stmt: &[u8] = ::core::convert::AsRef::<[u8]>::as_ref(&__stmt_owned);
            let __sid: &[u8] = ::core::convert::AsRef::<[u8]>::as_ref(&__sid_owned);

            // Commit common inputs
            __oracle.absorb("mode", b"FS");
            __oracle.absorb("x", __stmt);
            __oracle.absorb("sid", __sid);

            // First message (single round for FS)
            let mut __first = (#first);
            let (__m_bytes, __sigma) = __first(0usize);
            __oracle.absorb("m_i", &__m_bytes);

            // Derive one challenge based on transcript state
            let __challenge_len = 32usize; // fixed-size challenge, independent of b
            let __challenge = __oracle.derive_challenge("e_i", &[], __challenge_len);

            // Respond once
            let mut __respond = (#respond);
            let __z_bytes = __respond(0usize, &__challenge, &__sigma);
            __oracle.absorb("e_i", &__challenge);
            __oracle.absorb("z_i", &__z_bytes);

            // Build compact FS proof (single round)
            Ok(fsr_core::FsProof { m: ::std::vec![__m_bytes], z: ::std::vec![__z_bytes], rho: 1u16, b: 0u8 })
        })();
        __result
    })
}

// fn expand_prove_fs(args: ProveArgs) -> proc_macro2::TokenStream {
//     use quote::{format_ident, quote};

//     let ProveArgs {
//         oracle,
//         rho, b,                 // ignored in FS
//         statement, sid,
//         first, respond,
//         respond_stream,         // ignored in FS
//         ..
//     } = args;

//     let tr_oracle     = format_ident!("__oracle");
//     let tr_first      = format_ident!("__first");
//     let tr_respond    = format_ident!("__respond");
//     let tr_t          = format_ident!("__t");
//     let tr_r          = format_ident!("__r");
//     let tr_sid_bytes  = format_ident!("__sid_bytes");
//     let tr_stmt_bytes = format_ident!("__stmt_bytes");
//     let tr_buf        = format_ident!("__buf");
//     let tr_e_bytes    = format_ident!("__e_bytes");
//     let tr_z          = format_ident!("__z");
//     let tr_proof      = format_ident!("__proof");
//     let _unused       = format_ident!("__unused");

//     quote! {{
//         // Keep signature parity with Fischlin
//         let #_unused = (&#rho, &#b, &#respond_stream);

//         // Oracle
//         let mut #tr_oracle = { #oracle };

//         // First round -> (T, r)
//         let mut #tr_first = #first;
//         let (#tr_t, #tr_r) = (#tr_first)(0usize);

//         // &[u8] views
//         let #tr_sid_bytes: &[u8] = { let __tmp = #sid; &__tmp[..] };
//         let #tr_stmt_bytes: &[u8] = { let __tmp = #statement; &__tmp[..] };

//         // sid || statement || T
//         let mut #tr_buf = ::std::vec::Vec::<u8>::with_capacity(
//             #tr_sid_bytes.len() + #tr_stmt_bytes.len() + #tr_t.len()
//         );
//         #tr_buf.extend_from_slice(#tr_sid_bytes);
//         #tr_buf.extend_from_slice(#tr_stmt_bytes);
//         #tr_buf.extend_from_slice(&#tr_t[..]);

//         // One-shot FS challenge (UFCS so the trait needn't be imported at call site)
//         let #tr_e_bytes = fsr_core::RandomOracle::H_full(&mut #tr_oracle, "e", &#tr_buf);

//         // z = respond(i, e_bytes, &r_i)   <-- pass &r, not r
//         let mut #tr_respond = #respond;
//         let #tr_z = (#tr_respond)(0usize, &#tr_e_bytes[..], &#tr_r);

//         // FS proof: wrap single round as Vec<Vec<u8>>; neutral Fischlin fields
//         let #tr_proof = fsr_core::FsProof {
//             m: ::std::vec![#tr_t],
//             z: ::std::vec![#tr_z],
//             rho: 0u16,               // <-- u16, not Vec<u16>
//             b: 0u8,
//         };

//         Ok::<_, _>(#tr_proof)
//     }}
// }







#[proc_macro]
pub fn prove(input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(input as ProveArgs);
    let transform = args.transform.clone().unwrap_or_else(|| "fischlin".to_string());
    match transform.as_str() {
        "fischlin" => expand_prove_fischlin(args).into(),
        "fs" => expand_prove_fs(args).into(),
        other => Error::new(Span::call_site(), format!("unknown transform `{other}`")).to_compile_error().into(),
    }
}

struct VerifyArgs {
    transform: Option<String>,
    oracle: Expr,
    statement: Expr,
    sid: Expr,
    proof: Expr,
    sigma_verify: ExprClosure,
}

impl Parse for VerifyArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut transform = None;
        let mut oracle = None;
        let mut statement = None;
        let mut sid = None;
        let mut proof = None;
        let mut sigma_verify = None;

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let key = ident.to_string();
            match key.as_str() {
                "transform" => {
                    let lit: LitStr = input.parse()?;
                    transform = Some(lit.value());
                }
                "oracle" => oracle = Some(input.parse()?),
                "statement" => statement = Some(input.parse()?),
                "sid" => sid = Some(input.parse()?),
                "proof" => proof = Some(input.parse()?),
                "sigma_verify" => sigma_verify = Some(input.parse()?),
                other => return Err(Error::new(ident.span(), format!("unknown key `{other}`"))),
            }
            let _ = input.parse::<Token![,]>();
        }

        Ok(VerifyArgs {
            transform,
            oracle: oracle.ok_or_else(|| Error::new(Span::call_site(), "missing `oracle`"))?,
            statement: statement.ok_or_else(|| Error::new(Span::call_site(), "missing `statement`"))?,
            sid: sid.ok_or_else(|| Error::new(Span::call_site(), "missing `sid`"))?,
            proof: proof.ok_or_else(|| Error::new(Span::call_site(), "missing `proof`"))?,
            sigma_verify: sigma_verify.ok_or_else(|| Error::new(Span::call_site(), "missing `sigma_verify`"))?,
        })
    }
}

fn expand_verify_fs(args: VerifyArgs) -> TokenStream2 {
    let oracle = args.oracle;
    let statement = args.statement;
    let sid = args.sid;
    let proof = args.proof;
    let sigma_verify = args.sigma_verify;

    quote!({
        fsr_core::fs_proof::verify_fs(
            fsr_core::FSOracle::new(#oracle),
            #statement,
            #sid,
            #proof,
            #sigma_verify,
        )
    })
}

fn expand_verify_fischlin(args: VerifyArgs) -> TokenStream2 {
    let oracle = args.oracle;
    let statement = args.statement;
    let sid = args.sid;
    let proof = args.proof;
    let sigma_verify = args.sigma_verify;

    quote!({
        let mut __oracle = #oracle;
        let __proof = #proof;

        let __stmt_owned = (#statement);
        let __sid_owned  = (#sid);
        let __stmt: &[u8] = ::core::convert::AsRef::<[u8]>::as_ref(&__stmt_owned);
        let __sidb: &[u8] = ::core::convert::AsRef::<[u8]>::as_ref(&__sid_owned);

        __oracle.begin_verifier(__stmt, __sidb);

        if __proof.m.len() != __proof.e.len() || __proof.e.len() != __proof.z.len() {
            false
        } else {
            let mut __setup_ok = true;
            for __m in &__proof.m {
                if __oracle.push_first_message_verifier(__m).is_err() {
                    __setup_ok = false;
                    break;
                }
            }
            if __setup_ok {
                if __oracle.verifier_finalize_common_h().is_err() {
                    __setup_ok = false;
                }
            }

            if !__setup_ok {
                false
            } else {
                let __check = #sigma_verify;
                let mut __ok_all = true;
                for __i in 0..__proof.m.len() {
                    if !__check(__i, &__proof.m[__i], &__proof.e[__i], &__proof.z[__i]) {
                        __ok_all = false;
                        break;
                    }
                    let __prefix = match __oracle.predicate_prefix(__i as u32) {
                        Ok(p) => p,
                        Err(_) => {
                            __ok_all = false;
                            break;
                        }
                    };
                    if !__oracle.hb_zero_from_prefix(&__prefix, &__proof.e[__i], &__proof.z[__i]) {
                        __ok_all = false;
                        break;
                    }
                }
                __ok_all
            }
        }
    })
}

#[proc_macro]
pub fn verify(input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(input as VerifyArgs);
    let transform = args.transform.clone().unwrap_or_else(|| "fischlin".to_string());
    match transform.as_str() {
        "fischlin" => expand_verify_fischlin(args).into(),
        "fs" => expand_verify_fs(args).into(),
        other => Error::new(Span::call_site(), format!("unknown transform `{other}`")).to_compile_error().into(),
    }
}

#[proc_macro]
pub fn verify_source(input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(input as VerifyArgs);
    let stream = expand_verify_fischlin(args);
    let lit = LitStr::new(&stream.to_string(), Span::call_site());
    quote!(#lit).into()
}
