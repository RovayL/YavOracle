use crate::fischlin::{FischlinParams, FischlinOracle};
use crate::runtime::RandomOracle;

#[derive(Clone, Debug)]
pub struct FischlinProof {
    pub m: Vec<Vec<u8>>,
    pub e: Vec<Vec<u8>>,
    pub z: Vec<Vec<u8>>,
    pub b: u8,
    pub rho: u16,
}
impl FischlinProof {
    pub fn len(&self) -> usize { self.m.len() }
    pub fn is_well_formed(&self) -> bool {
        self.m.len() == self.e.len() && self.e.len() == self.z.len() && self.m.len() == self.rho as usize
    }
}

pub fn verify_fischlin<RO, SigmaV>(
    ro: RO,
    params: FischlinParams,
    x_bytes: &[u8],
    sid: &[u8],
    proof: &FischlinProof,
    mut sigma_verify: SigmaV,
) -> bool
where
    RO: RandomOracle,
    SigmaV: FnMut(usize, &[u8], &[u8], &[u8]) -> bool,
{
    if !proof.is_well_formed() { return false; }
    if proof.b != params.b || proof.rho != params.rho { return false; }
    if (params.rho as u32) * (params.b as u32) < params.kappa_c as u32 { return false; }

    let mut oracle = FischlinOracle::new(ro, params);
    oracle.begin_verifier(x_bytes, sid);
    for m_i in &proof.m { oracle.push_first_message_verifier(m_i); }
    oracle.verifier_finalize_common_h();

    for i in 0..proof.m.len() {
        let (m_i, e_i, z_i) = (&proof.m[i], &proof.e[i], &proof.z[i]);
        let ok_sigma = sigma_verify(i, m_i, e_i, z_i);
        if !ok_sigma { return false; }

        // precompute prefix once for this i
        let prefix = oracle.predicate_prefix(i as u32);
        if !oracle.hb_zero_from_prefix(&prefix, e_i, z_i) { return false; }
    }
    true
}
