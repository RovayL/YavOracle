pub fn verify(pub_in : & Public, bytes : & [u8]) -> bool where G1 : fsr_core
:: CanonicalEncode + fsr_core :: CanonicalDecode + Clone, Scalar : fsr_core ::
CanonicalEncode + fsr_core :: CanonicalDecode + Clone
{
    let mut input = bytes; if input.len() < 6 { return None; } if & input
    [.. 4] != b"FSR\0" { return None; } input = & input [4 ..]; let _ver =
    input [0]; input = & input [1 ..]; if input.is_empty() { return None; }
    let slen = input [0] as usize; input = & input [1 ..]; if input.len() <
    slen { return None; } let _schema = & input [.. slen]; input = & input
    [slen ..]; if input.is_empty() { return None; } let dlen = input [0] as
    usize; input = & input [1 ..]; if input.len() < dlen { return None; } let
    _domain = & input [.. dlen]; input = & input [dlen ..]; let t : G1 = < G1
    as fsr_core :: CanonicalDecode > :: decode(& mut input) ? ; let z : Scalar
    = < Scalar as fsr_core :: CanonicalDecode > :: decode(& mut input) ? ; let
    proof = SchnorrNaiveProof { t, z, }; let mut h = fsr_core :: HashOracle ::
    new(__DOMAIN); let t : G1 = proof.t.clone(); let z : Scalar =
    proof.z.clone();
    {
        {
            let __lbl : & 'static str = Commit :: LABEL_t; let mut __v = ::
            std :: vec :: Vec :: new(); < _ as fsr_core :: CanonicalEncode >
            :: encode(& (t), & mut __v); h.absorb_bytes(__lbl, & __v);
        }
        {
            let __lbl : & 'static str = Commit :: MSG_LABEL;
            h.absorb_bytes(__lbl, & []);
        }
    } {} let __ok : bool =
    {
        let e = h.challenge ::< Scalar > ("e"); let lhs = pub_in.g.smul(z);
        let rhs = t.add(pub_in.y.smul(e)); lhs == rhs
    }; __ok
}