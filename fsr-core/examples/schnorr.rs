// schnorr.rs (example – compile this in the same crate for now)
use fsr_core::*;
use fsr_bind_derive::FsrBindable;

// ---- Minimal placeholder domain types ----

#[derive(Clone, Debug)]
pub struct G1(pub [u8; 32]);

impl CanonicalEncode for G1 {
    fn encode(&self, out: &mut Vec<u8>) { out.extend_from_slice(&self.0); }
}

#[derive(Clone, Copy, Debug)]
pub struct Scalar(pub u64);

impl CanonicalEncode for Scalar {
    fn encode(&self, out: &mut Vec<u8>) { out.extend_from_slice(&self.0.to_le_bytes()); }
}

// NOTE: label now &str (not &'static str)
impl Challenge for Scalar {
    fn from_oracle_bytes(_label: &str, input: &[u8]) -> Self {
        use core::hash::{Hash, Hasher};
        let mut s = std::collections::hash_map::DefaultHasher::new();
        input.hash(&mut s);
        Scalar(s.finish())
    }
    const BYTES: usize = 32;
}

#[derive(Clone, Debug)]
pub struct Public { pub g: G1, pub y: G1 }
impl CanonicalEncode for Public {
    fn encode(&self, out: &mut Vec<u8>) { self.g.encode(out); self.y.encode(out); }
}

// ---- Messages ----

// Pre-challenge: t must be bound; mark with ob=0 to gate the challenge boundary.
#[derive(Clone, Debug, FsrBindable)]
#[bind(prefix = "Commit")]
pub struct Commit {
    #[bind(ob = 0)]
    pub t: G1,
    #[bind(skip)]
    pub scratch: Option<u64>,
}
impl Message for Commit {
    const DIR: Direction = Direction::ProverToVerifier;
    const LABEL: &'static str = "Commit";
}

// Post-challenge response; verification-relevant but does not gate `e`.
#[derive(Clone, Debug, FsrBindable)]
#[bind(prefix = "Response")]
pub struct Response {
    pub z: Scalar, // bound by default; no obligation bit
}
impl Message for Response {
    const DIR: Direction = Direction::ProverToVerifier;
    const LABEL: &'static str = "Response";
}

// Pending mask for Round 1 is derived from the message types
declare_round!(R1 = [Commit]);

fn main() {
    let public = Public { g: G1([1; 32]), y: G1([2; 32]) };

    // FS oracle for this protocol
    let oracle = HashOracle::new(b"schnorr");

    // Begin Round 1 with pending obligation(s) from `Commit`
    let tr: R1<HashOracle> = Transcript::new(oracle);

    // Prover computes commitment t
    let commit = Commit { t: G1([42; 32]), scratch: None };

    // IMPORTANT: use shadowing because typestate changes (1 -> 0)
    let tr = tr.absorb::<{ Commit::OBLIG_MASK }, _>(Commit::LABEL, &commit);

    // Now challenge is available because pending mask == 0
    let (e, tr) = tr.challenge::<Scalar>("e");

    // Prover computes response z (demo)
    let z = Response { z: Scalar(e.0.wrapping_add(7)) };

    // Absorb post-challenge data (mask == 0; typestate stays 0)
    let _tr_done: Transcript<0, HashOracle> =
        tr.absorb::<{ Response::OBLIG_MASK }, Response>(Response::LABEL, &z);

    // (Optional) bind public input deterministically (both roles would do this)
    let mut pubbytes = Vec::new();
    public.encode(&mut pubbytes);
    // _tr_done.oracle_mut().absorb_bytes("public", &pubbytes);
}
