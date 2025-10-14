pub fn verify(pub_in : & Public, bytes : & [u8]) -> bool where Scalar :
fsr_core :: CanonicalEncode + fsr_core :: CanonicalDecode + Clone, Scalar :
fsr_core :: CanonicalEncode + fsr_core :: CanonicalDecode + Clone
{
    let mut input = bytes; if input.len() < 6 { return None; } if & input
    [.. 4] != b"FSR\0" { return None; } input = & input [4 ..]; let _ver =
    input [0]; input = & input [1 ..]; if input.is_empty() { return None; }
    let slen = input [0] as usize; input = & input [1 ..]; if input.len() <
    slen { return None; } let _schema = & input [.. slen]; input = & input
    [slen ..]; if input.is_empty() { return None; } let dlen = input [0] as
    usize; input = & input [1 ..]; if input.len() < dlen { return None; } let
    _domain = & input [.. dlen]; input = & input [dlen ..]; let e : Scalar = <
    Scalar as fsr_core :: CanonicalDecode > :: decode(& mut input) ? ; let z :
    Scalar = < Scalar as fsr_core :: CanonicalDecode > :: decode(& mut input)
    ? ; let proof = SchnorrOptimizedProof { e, z, }; let mut h = fsr_core ::
    HashOracle :: new(__DOMAIN); let e : Scalar = proof.e.clone(); let z :
    Scalar = proof.z.clone();
    {
        let T : G1 = pub_in.g.smul(z).sub(pub_in.y.smul(e));
        {
            let __lbl : & 'static str = Commit :: LABEL_t; let mut __v = ::
            std :: vec :: Vec :: new(); < _ as fsr_core :: CanonicalEncode >
            :: encode(& (T), & mut __v); h.absorb_bytes(__lbl, & __v);
        }
        {
            let __lbl : & 'static str = Commit :: MSG_LABEL;
            h.absorb_bytes(__lbl, & []);
        }
    }
    {
        {
            let __lbl : & 'static str = "e"; let e_prime : Scalar =
            h.challenge :: < Scalar > (__lbl); let __eq =
            {
                let mut a = :: std :: vec :: Vec :: new(); < Scalar as
                fsr_core :: CanonicalEncode > :: encode(& e_prime, & mut a);
                let mut b = :: std :: vec :: Vec :: new(); < Scalar as
                fsr_core :: CanonicalEncode > :: encode(& e, & mut b); a == b
            }; if ! __eq { return false; } let e : Scalar = e_prime;
        }
    } let __ok : bool =
    {
        let T : G1 = pub_in.g.smul(z).sub(pub_in.y.smul(e)); let lhs =
        pub_in.g.smul(z); let rhs = T.add(pub_in.y.smul(e)); lhs == rhs
    }; __ok
}