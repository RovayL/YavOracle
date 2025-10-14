use fsr_core::*;
use fsr_bind_derive::FsrBindable;
use fsr_proof_dsl::proof;

// ------------ toy additive group Z_p & codec helpers ------------
const MOD_P: u64 = 2_147_483_647;
#[inline] fn modp_u64(x: u128) -> u64 { (x % (MOD_P as u128)) as u64 }
fn le_u64(input: &mut &[u8]) -> Option<u64> {
    if input.len() < 8 { return None; }
    let mut a = [0u8; 8]; a.copy_from_slice(&input[..8]); *input = &input[8..]; Some(u64::from_le_bytes(a))
}
fn put_le_u64(v: u64, out: &mut Vec<u8>) { out.extend_from_slice(&v.to_le_bytes()); }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1(pub u64);
impl G1 {
    #[inline] fn add(self, other: G1) -> G1 { G1(modp_u64(self.0 as u128 + other.0 as u128)) }
    #[inline] fn sub(self, other: G1) -> G1 { G1(modp_u64((MOD_P as u128 + self.0 as u128 - other.0 as u128) % MOD_P as u128)) }
    #[inline] fn smul(self, s: Scalar) -> G1 { G1(modp_u64(self.0 as u128 * s.0 as u128)) }
}
impl CanonicalEncode for G1 { fn encode(&self, out: &mut Vec<u8>) { put_le_u64(self.0, out) } }
impl CanonicalDecode for G1 { fn decode(input: &mut &[u8]) -> Option<Self> { le_u64(input).map(G1) } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar(pub u64);
impl Scalar {
    #[inline] fn add(self, other: Scalar) -> Scalar { Scalar(modp_u64(self.0 as u128 + other.0 as u128)) }
    #[inline] fn mul(self, other: Scalar) -> Scalar { Scalar(modp_u64(self.0 as u128 * other.0 as u128)) }
}
impl CanonicalEncode for Scalar { fn encode(&self, out: &mut Vec<u8>) { put_le_u64(self.0, out) } }
impl CanonicalDecode for Scalar { fn decode(input: &mut &[u8]) -> Option<Self> { le_u64(input).map(Scalar) } }

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
pub struct Public { pub g: G1, pub y: G1 }
impl CanonicalEncode for Public {
    fn encode(&self, out: &mut Vec<u8>) { self.g.encode(out); self.y.encode(out); }
}

// ------------------- Messages -------------------
#[derive(Clone, Debug, FsrBindable)]
#[bind(prefix = "Commit")]
pub struct Commit { #[bind(ob = 0)] pub t: G1 }
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

// ------------------- PROOF SPECS (new DSL) -------------------

// Naive proof {t,z}, with header and label guard.
proof! {
  name: SchnorrNaive;
  domain: "schnorr-toy";
  public: Public;

  header { schema: "schnorr-naive"; domain: true; version: 1; }

  fields {
    t: G1     <= absorb   Commit::LABEL_t;
    z: Scalar <= absorb   Response::LABEL_z;
  }

  replay {
    bind Commit::LABEL_t <- t;
    bind Commit::MSG_LABEL;
  }

  check {
    let e = h.challenge::<Scalar>("e");
    let lhs = pub_in.g.smul(z);
    let rhs = t.add(pub_in.y.smul(e));
    lhs == rhs
  }
}

// Optimized proof {e,z}; recompute T = z*g - e*y in replay.
proof! {
  name: SchnorrOptimized;
  domain: "schnorr-toy";
  public: Public;

  header { schema: "schnorr-opt"; domain: true; version: 1; }

  fields {
    e: Scalar <= challenge "e";
    z: Scalar <= absorb    Response::LABEL_z;
  }

  replay {
    let T: G1 = pub_in.g.smul(z).sub(pub_in.y.smul(e));
    bind Commit::LABEL_t <- T;
    bind Commit::MSG_LABEL;
  }

  check {
    let T: G1 = pub_in.g.smul(z).sub(pub_in.y.smul(e));
    let lhs = pub_in.g.smul(z);
    let rhs = T.add(pub_in.y.smul(e));
    lhs == rhs
  }
}

// ------------------- Demo driver -------------------

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{:02x}", b)).collect() }

fn main() {
    const DST: &[u8] = b"schnorr-toy";

    // Prover setup
    let g = G1(7);
    let x = Scalar(5);
    let y = g.smul(x);
    let public = Public { g, y };

    // FS with recording
    let oracle = RecordingHashOracle::new(HashOracle::new(DST));
    let tr: R1<_> = Transcript::new(oracle);

    // Prover nonce + commit
    let r = Scalar(11);
    let t = g.smul(r);

    // Run boundary
    let tr = tr.absorb::<{ Commit::OBLIG_MASK }, _>(Commit::LABEL, &Commit { t });
    let (e, tr) = tr.challenge::<Scalar>("e");
    let z = r.add(e.mul(x));
    let tr = tr.absorb::<{ Response::OBLIG_MASK }, _>(Response::LABEL, &Response { z });

    // Extract recorded events
    let oracle_rec = tr.into_oracle();
    let (_inner, events) = oracle_rec.into_parts();

    // Build both proofs via the macro-generated helpers
    let naive = schnorr_naive_prove(&events).expect("build naive proof");
    let opt   = schnorr_optimized_prove(&events).expect("build optimized proof");


    let naive_bytes = naive.encode();
    let opt_bytes   = opt.encode();

    println!("naive bytes ({}): 0x{}", naive_bytes.len(), hex(&naive_bytes));
    println!("opt   bytes ({}): 0x{}", opt_bytes.len(),   hex(&opt_bytes));

    // Verify (typed and bytes versions)
    assert!(schnorr_naive_verify(&public, &naive));
    assert!(schnorr_naive_verify_bytes(&public, &naive.encode()));
    assert!(schnorr_optimized_verify(&public, &opt));
    assert!(schnorr_optimized_verify_bytes(&public, &opt.encode()));

    // print the verifier source
    println!("--- SchnorrNaive verifier ---\n{}\n", schnorr_naive_verifier_source());
    println!("--- SchnorrOptimized verifier ---\n{}\n", schnorr_optimized_verifier_source());

    // or write it to files:
    use std::fs;
    let _ = fs::write("verifier_schnorr_naive.rs", schnorr_naive_verifier_source());
    let _ = fs::write("verifier_schnorr_optimized.rs", schnorr_optimized_verifier_source());

    println!("All verifications passed.");
}
