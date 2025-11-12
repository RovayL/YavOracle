#[derive(Clone, Debug)]
pub struct FsProof {
    pub m: Vec<Vec<u8>>,
    pub z: Vec<Vec<u8>>,
    pub rho: u16,
    pub b: u8,
}

impl FsProof {
    pub fn len(&self) -> usize { self.m.len() }

    pub fn is_well_formed(&self) -> bool {
        self.m.len() == self.z.len()
            && self.m.len() == self.rho as usize
            && self.b > 0
    }

    pub fn encode(&self) -> Vec<u8> {
        fn push_list(dst: &mut Vec<u8>, list: &[Vec<u8>]) {
            dst.extend_from_slice(&(list.len() as u32).to_le_bytes());
            for item in list {
                dst.extend_from_slice(&(item.len() as u32).to_le_bytes());
                dst.extend_from_slice(item);
            }
        }

        const TAG: &[u8] = b"FS\0";
        let mut out = Vec::new();
        out.extend_from_slice(TAG);
        out.extend_from_slice(&self.rho.to_le_bytes());
        out.push(self.b);
        push_list(&mut out, &self.m);
        push_list(&mut out, &self.z);
        out
    }

    pub fn decode(mut input: &[u8]) -> Option<Self> {
        fn read_list(input: &mut &[u8]) -> Option<Vec<Vec<u8>>> {
            if input.len() < 4 { return None; }
            let mut len_buf = [0u8; 4];
            len_buf.copy_from_slice(&input[..4]);
            let count = u32::from_le_bytes(len_buf) as usize;
            *input = &input[4..];
            let mut out = Vec::with_capacity(count);
            for _ in 0..count {
                if input.len() < 4 { return None; }
                let mut lbuf = [0u8; 4];
                lbuf.copy_from_slice(&input[..4]);
                let len = u32::from_le_bytes(lbuf) as usize;
                *input = &input[4..];
                if input.len() < len { return None; }
                out.push(input[..len].to_vec());
                *input = &input[len..];
            }
            Some(out)
        }

        const TAG: &[u8] = b"FS\0";
        if input.len() < TAG.len() + 3 { return None; }
        if &input[..TAG.len()] != TAG { return None; }
        input = &input[TAG.len()..];

        let mut rho_buf = [0u8; 2];
        rho_buf.copy_from_slice(&input[..2]);
        let rho = u16::from_le_bytes(rho_buf);
        input = &input[2..];

        let b = input[0];
        input = &input[1..];

        let m = read_list(&mut input)?;
        let z = read_list(&mut input)?;

        Some(Self { m, z, rho, b })
    }
}

use crate::{fs_runtime::FSOracle, runtime::TranscriptRuntime, RandomOracle};

pub fn verify_fs<RO, F>(
    mut oracle: FSOracle<RO>,
    statement: impl AsRef<[u8]>,
    sid: impl AsRef<[u8]>,
    proof: &FsProof,
    mut sigma_verify: F,
) -> bool
where
    RO: RandomOracle,
    F: FnMut(usize, &[u8], &[u8], &[u8]) -> bool,
{
    if !proof.is_well_formed() {
        return false;
    }

    let stmt = statement.as_ref();
    let sidb = sid.as_ref();

    oracle.absorb("mode", b"FS");
    oracle.absorb("x", stmt);
    oracle.absorb("sid", sidb);

    for m_i in &proof.m {
        oracle.absorb("m_i", m_i);
    }

    let b_bits = proof.b;
    let chal_len = ((usize::from(b_bits) + 7) / 8).max(1);
    let mask_bits = b_bits & 7;

    for (i, (m_i, z_i)) in proof.m.iter().zip(proof.z.iter()).enumerate() {
        let mut e_bytes = oracle.derive_challenge("e_i", &[], chal_len);
        if mask_bits != 0 {
            if let Some(last) = e_bytes.last_mut() {
                let mask = (1u8 << mask_bits) - 1;
                *last &= mask;
            }
        }
        oracle.absorb("e_i", &e_bytes);
        oracle.absorb("z_i", z_i);
        if !sigma_verify(i, m_i, &e_bytes, z_i) {
            return false;
        }
    }
    true
}
