use fsr_core::*;
use fsr_bind_derive::FsrBindable;

fn le_u64(bytes: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(a)
}
fn put_le_u64(v: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

fn main() -> fsr_core::Result<()> {
    // ------------------- Toy additive group Z_p -------------------
    const MOD_P: u64 = 2_147_483_647; // 2^31 - 1

    #[inline] fn modp_u64(x: u128) -> u64 { (x % (MOD_P as u128)) as u64 }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct G1(pub u64);
    impl G1 {
        #[inline] fn add(self, other: G1) -> G1 { G1(modp_u64(self.0 as u128 + other.0 as u128)) }
        #[inline] fn sub(self, other: G1) -> G1 { G1(modp_u64((MOD_P as u128 + self.0 as u128 - other.0 as u128) % MOD_P as u128)) }
        #[inline] fn smul(self, s: Scalar) -> G1 { G1(modp_u64(self.0 as u128 * s.0 as u128)) }
    }
    impl CanonicalEncode for G1 { fn encode(&self, out: &mut Vec<u8>) { put_le_u64(self.0, out) } }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Scalar(pub u64);
    impl Scalar {
        #[inline] fn add(self, other: Scalar) -> Scalar { Scalar(modp_u64(self.0 as u128 + other.0 as u128)) }
        #[inline] fn mul(self, other: Scalar) -> Scalar { Scalar(modp_u64(self.0 as u128 * other.0 as u128)) }
    }
    impl CanonicalEncode for Scalar { fn encode(&self, out: &mut Vec<u8>) { put_le_u64(self.0, out) } }
    impl Challenge for Scalar {
        fn from_oracle_bytes(_label: &str, bytes: &[u8]) -> Self {
            use core::hash::{Hash, Hasher};
            let mut s = std::collections::hash_map::DefaultHasher::new();
            bytes.hash(&mut s);
            Scalar(modp_u64(s.finish() as u128))
        }
        const BYTES: usize = 32;
    }

    #[derive(Clone, Debug)]
    pub struct Public { pub G: G1, pub Y: G1 }
    impl CanonicalEncode for Public {
        fn encode(&self, out: &mut Vec<u8>) { self.G.encode(out); self.Y.encode(out); }
    }

    // ------------------- Messages -------------------
    #[derive(Clone, Debug, FsrBindable)]
    #[bind(prefix = "Commit")]
    pub struct Commit { #[bind(ob = 0)] pub T: G1 }
    impl Message for Commit {
        const DIR: Direction = Direction::ProverToVerifier;
        const LABEL: &'static str = "Commit";
    }

    #[derive(Clone, Debug, FsrBindable)]
    #[bind(prefix = "Response")]
    pub struct Response { pub z: Scalar }
    impl Message for Response {
        const DIR: Direction = Direction::ProverToVerifier;
        const LABEL: &'static str = "Response";
    }

    declare_round!(R1 = [Commit]);

    // ------------------- Prover side (FS with recording) -------------------
    const DST: &[u8] = b"schnorr-toy";
    let oracle = RecordingHashOracle::new(HashOracle::new(DST));
    let tr: R1<_> = Transcript::new(oracle);

    // public key Y = x·G
    let G = G1(7);
    let x = Scalar(5);
    let Y = G.smul(x);
    let public = Public { G, Y };

    // nonce r, commit T = r·G
    let r = Scalar(11);
    let T = G.smul(r);

    // run the boundary
    let tr = tr.absorb::<{ Commit::OBLIG_MASK }, _>(Commit::LABEL, &Commit { T });
    let (e, tr) = tr.challenge::<Scalar>("e")?;
    let z = r.add(e.mul(x));
    let tr = tr.absorb::<{ Response::OBLIG_MASK }, _>(Response::LABEL, &Response { z });

    // pull out the recording
    let oracle_rec = tr.into_oracle(); // Transcript<0, RecordingHashOracle<_>> -> RecordingHashOracle<_>
    let (_inner, events) = oracle_rec.into_parts();
    // convenience: pick bytes we need from the timeline
    let t_bytes = events.iter().find_map(|ev| match ev {
        RecEvent::Absorb { label, bytes } if *label == "Commit.T" => Some(bytes.as_slice()),
        _ => None,
    }).expect("T not recorded");
    let e_bytes = events.iter().find_map(|ev| match ev {
        RecEvent::Challenge { label, bytes } if *label == "e" => Some(bytes.as_slice()),
        _ => None,
    }).expect("e not recorded");
    let z_bytes = events.iter().find_map(|ev| match ev {
        RecEvent::Absorb { label, bytes } if *label == "Response.z" => Some(bytes.as_slice()),
        _ => None,
    }).expect("z not recorded");

    // We’ll build both proofs:
    // (A) Naive proof: {T, z}
    let mut proof_naive = Vec::new();
    proof_naive.push(1u8); // version tag
    proof_naive.push(0u8); // schema: 0 = naive {T,z}
    proof_naive.extend_from_slice(&public.G.0.to_le_bytes()); // optional: commit to params? (kept separate here)
    proof_naive.extend_from_slice(&public.Y.0.to_le_bytes()); // (in real schemes, public inputs are given separately)
    proof_naive.extend_from_slice(&t_bytes[..8]); // T (u64 LE)
    proof_naive.extend_from_slice(&z_bytes[..8]); // z (u64 LE)

    // (B) Optimized proof: {e, z}
    let mut proof_opt = Vec::new();
    proof_opt.push(1u8); // version
    proof_opt.push(1u8); // schema: 1 = optimized {e,z}
    proof_opt.extend_from_slice(&public.G.0.to_le_bytes());
    proof_opt.extend_from_slice(&public.Y.0.to_le_bytes());
    proof_opt.extend_from_slice(&e_bytes[..8]); // e (u64 LE)
    proof_opt.extend_from_slice(&z_bytes[..8]); // z (u64 LE)

    println!("proof_naive  (len={}): 0x{}", proof_naive.len(), hex(&proof_naive));
    println!("proof_opt    (len={}): 0x{}", proof_opt.len(),   hex(&proof_opt));

    // ------------------- Verifier side -------------------
    fn verify_naive(proof: &[u8]) -> bool {
        if proof.len() != 1+1 + 8+8 + 8+8 { return false; }
        let version = proof[0]; let schema = proof[1];
        if version != 1 || schema != 0 { return false; }
        let G = G1(le_u64(&proof[2..10]));
        let Y = G1(le_u64(&proof[10..18]));
        let T = G1(le_u64(&proof[18..26]));
        let z = Scalar(le_u64(&proof[26..34]));

        // Recompute e' under FS by replaying the *exact* pre-challenge transcript:
        let mut h = HashOracle::new(DST);

        // 1) Field-level binding (what Bindable emitted):
        let mut v = Vec::new(); T.encode(&mut v);
        h.absorb_bytes("Commit.T", &v);

        // 2) Message-sentinel binding that Transcript::absorb() adds:
        h.absorb_bytes("Commit", &[]);

        let e_prime = match h.challenge::<Scalar>("e") {
            Ok(v) => v,
            Err(_) => return false,
        };

        // Algebraic check: z·G ?= T + e'·Y
        let lhs = G.smul(z);
        let rhs = T.add(Y.smul(e_prime));
        lhs == rhs
    }

    fn verify_optimized(proof: &[u8]) -> bool {
        if proof.len() != 1+1 + 8+8 + 8+8 { return false; }
        let version = proof[0]; let schema = proof[1];
        if version != 1 || schema != 1 { return false; }
        let G = G1(le_u64(&proof[2..10]));
        let Y = G1(le_u64(&proof[10..18]));
        let e = Scalar(le_u64(&proof[18..26]));
        let z = Scalar(le_u64(&proof[26..34]));

        // Reconstruct T = z·G − e·Y (the optimized encoding doesn’t carry T)
        let T = G.smul(z).sub(Y.smul(e));

        // Replay the exact pre-challenge transcript:
        let mut h = HashOracle::new(DST);

        // 1) Field-level binding of T…
        let mut v = Vec::new(); T.encode(&mut v);
        h.absorb_bytes("Commit.T", &v);

        // 2) …and the message-sentinel:
        h.absorb_bytes("Commit", &[]);

        let e_prime = match h.challenge::<Scalar>("e") {
            Ok(v) => v,
            Err(_) => return false,
        };

        // FS consistency check:
        if e_prime != e { return false; }

        // (Optional) algebraic check:
        let lhs = G.smul(z);
        let rhs = T.add(Y.smul(e));
        lhs == rhs
    }

    println!("verify_naive:     {}", verify_naive(&proof_naive));
    println!("verify_optimized: {}", verify_optimized(&proof_opt));
    Ok(())
}
