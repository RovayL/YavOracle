#[derive(Clone, Debug)]
pub struct FsProof {
    pub m: Vec<Vec<u8>>,
    pub z: Vec<Vec<u8>>,
    pub rho: u16,
}

impl FsProof {
    pub fn len(&self) -> usize { self.m.len() }

    pub fn is_well_formed(&self) -> bool {
        self.m.len() == self.z.len() && self.m.len() == self.rho as usize
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
        if input.len() < TAG.len() + 2 { return None; }
        if &input[..TAG.len()] != TAG { return None; }
        input = &input[TAG.len()..];

        let mut rho_buf = [0u8; 2];
        rho_buf.copy_from_slice(&input[..2]);
        let rho = u16::from_le_bytes(rho_buf);
        input = &input[2..];

        let m = read_list(&mut input)?;
        let z = read_list(&mut input)?;

        Some(Self { m, z, rho })
    }
}
