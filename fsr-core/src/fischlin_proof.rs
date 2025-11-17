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

    /// Simple byte encoding for demo/debugging purposes.
    pub fn encode(&self) -> Vec<u8> {
        fn push_list(dst: &mut Vec<u8>, list: &[Vec<u8>]) {
            dst.extend_from_slice(&(list.len() as u32).to_le_bytes());
            for item in list {
                dst.extend_from_slice(&(item.len() as u32).to_le_bytes());
                dst.extend_from_slice(item);
            }
        }

        const TAG: &[u8] = b"FISCHLIN\0";
        let mut out = Vec::new();
        out.extend_from_slice(TAG);
        out.extend_from_slice(&self.rho.to_le_bytes());
        out.push(self.b);
        push_list(&mut out, &self.m);
        push_list(&mut out, &self.e);
        push_list(&mut out, &self.z);
        out
    }

    /// Decode the format emitted by `encode`.
    pub fn decode(mut input: &[u8]) -> Option<Self> {
        fn read_list(input: &mut &[u8]) -> Option<Vec<Vec<u8>>> {
            if input.len() < 4 { return None; }
            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&input[..4]);
            let count = u32::from_le_bytes(len_bytes) as usize;
            *input = &input[4..];
            let mut out = Vec::with_capacity(count);
            for _ in 0..count {
                if input.len() < 4 { return None; }
                let mut lbytes = [0u8; 4];
                lbytes.copy_from_slice(&input[..4]);
                let len = u32::from_le_bytes(lbytes) as usize;
                *input = &input[4..];
                if input.len() < len { return None; }
                out.push(input[..len].to_vec());
                *input = &input[len..];
            }
            Some(out)
        }

        const TAG: &[u8] = b"FISCHLIN\0";
        if input.len() < TAG.len() + 2 + 1 { return None; }
        if &input[..TAG.len()] != TAG { return None; }
        input = &input[TAG.len()..];

        let mut rho_bytes = [0u8; 2];
        rho_bytes.copy_from_slice(&input[..2]);
        let rho = u16::from_le_bytes(rho_bytes);
        input = &input[2..];

        let b = *input.get(0)?; input = &input[1..];
        let m = read_list(&mut input)?;
        let e = read_list(&mut input)?;
        let z = read_list(&mut input)?;

        Some(Self { m, e, z, b, rho })
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
    // n-special: require rho * (b - ceil_log2(n-1)) >= kappa_c
    let loss = if params.n_special <= 2 { 0 } else { 32u32.saturating_sub(((params.n_special as u32 - 1)).leading_zeros()) };
    if (params.b as u32) < loss { return false; }
    if (params.rho as u32) * ((params.b as u32) - loss) < params.kappa_c as u32 { return false; }

    let mut oracle = FischlinOracle::new(ro, params);
    oracle.begin_verifier(x_bytes, sid);
    for m_i in &proof.m {
        if oracle.push_first_message_verifier(m_i).is_err() {
            return false;
        }
    }
    if oracle.verifier_finalize_common_h().is_err() {
        return false;
    }

    for i in 0..proof.m.len() {
        let (m_i, e_i, z_i) = (&proof.m[i], &proof.e[i], &proof.z[i]);
        let ok_sigma = sigma_verify(i, m_i, e_i, z_i);
        if !ok_sigma { return false; }

        // precompute prefix once for this i
        let prefix = match oracle.predicate_prefix(i as u32) {
            Ok(p) => p,
            Err(_) => return false,
        };
        if !oracle.hb_zero_from_prefix(&prefix, e_i, z_i) { return false; }
    }
    true
}
