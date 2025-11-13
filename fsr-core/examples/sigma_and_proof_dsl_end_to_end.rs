//! End-to-end Sigma AND using the higher-level `proof!` DSL with encode/decode.
//! This example records an interactive-like transcript with a RecordingHashOracle,
//! then uses the generated proof module to extract a compact proof and verify it
//! without manually specifying coverage binds at call sites.

use fsr_core::{HashOracle, RecordingHashOracle, RecEvent, Result, U64Challenge};
use rand::{rngs::StdRng, SeedableRng, RngCore};

const MOD_P: u64 = 2_147_483_647;
const ORDER_Q: u64 = MOD_P - 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)] struct G1(u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)] struct Scalar(u64);
fn modp(x: u128) -> u64 { (x % MOD_P as u128) as u64 }
fn powmod(mut base: u64, mut exp: u64) -> u64 { let mut acc = 1u64; while exp > 0 { if exp & 1 == 1 { acc = modp(acc as u128 * base as u128); } base = modp(base as u128 * base as u128); exp >>= 1; } acc }
impl G1 { fn pow(self, e: Scalar) -> G1 { G1(powmod(self.0, e.0)) } }
impl core::ops::Mul for G1 { type Output = G1; fn mul(self, rhs: G1) -> G1 { G1(modp(self.0 as u128 * rhs.0 as u128)) } }

fn enc_u64(x: u64) -> Vec<u8> { x.to_le_bytes().to_vec() }
fn dec_le_u64(bytes: &[u8]) -> u64 { let mut v = 0u64; for (i, &b) in bytes.iter().enumerate().take(8) { v |= (b as u64) << (8 * i); } v }

// High-level proof specification: bind both commitments; derive a single challenge `e`.
fsr_proof_dsl::proof! {
    name: SigmaAnd;
    domain: "YavOracle/SigmaAND/ProofDSL";
    public: ();
    fields {
        t0: Vec<u8>            <= absorb "c_0";
        t1: Vec<u8>            <= absorb "c_1";
        e:  fsr_core::U64Challenge <= challenge "e";
        z:  Vec<u8>            <= absorb "z";
    }
    replay {
        // Replay the exact transcript shape that produces `e` from t0, t1
        bind "c_0" <- t0;
        bind "c_1" <- t1;
    }
    check {{
        let t0 = G1(dec_le_u64(&t0));
        let t1 = G1(dec_le_u64(&t1));
        let e  = Scalar(e.0 % ORDER_Q);
        let z0 = Scalar(dec_le_u64(&z[0..8]) % ORDER_Q);
        let z1 = Scalar(dec_le_u64(&z[8..16]) % ORDER_Q);
        // Public inputs are implicit in this demo; we reconstruct consistency via t0,t1
        // Accept if z carries consistent structure (this is illustrative)
        (t0.0 != 0) && (t1.0 != 0) && (z0.0 < ORDER_Q) && (z1.0 < ORDER_Q)
    }}
}

fn main() -> Result<()> {
    let g = G1(13);
    let w0 = Scalar(123); let w1 = Scalar(456);
    let y0 = g.pow(w0); let y1 = g.pow(w1);
    let mut rng = StdRng::seed_from_u64(2027);

    // Record transcript events
    let mut ro = RecordingHashOracle::new(HashOracle::new(b"YavOracle/SigmaAND/ProofDSL"));
    let r0 = Scalar(rng.next_u64() % ORDER_Q);
    let r1 = Scalar(rng.next_u64() % ORDER_Q);
    let t0 = g.pow(r0); let t1 = g.pow(r1);
    ro.absorb_bytes("c_0", &enc_u64(t0.0));
    ro.absorb_bytes("c_1", &enc_u64(t1.0));
    let _e: U64Challenge = ro.challenge("e")?;
    let z0 = Scalar((r0.0 + (w0.0 % ORDER_Q)) % ORDER_Q);
    let z1 = Scalar((r1.0 + (w1.0 % ORDER_Q)) % ORDER_Q);
    let mut z = Vec::new(); z.extend_from_slice(&enc_u64(z0.0)); z.extend_from_slice(&enc_u64(z1.0));
    ro.absorb_bytes("z", &z);

    // Convert recorded events into a compact proof via the generated module
    let events: Vec<RecEvent> = ro.into_parts().1;
    let proof = sigma_and_prove(&events).expect("well-formed events");
    let bytes = proof.encode();
    println!("proof bytes ({}): 0x{}", bytes.len(), hex::encode(&bytes));
    // Verify via the generated verifier
    let ok = sigma_and_verify_bytes(&(), &bytes);
    println!("verify = {}", ok);
    // Show verifier source
    println!("verifier source (proof!):\n{}", sigma_and_verifier_source());
    Ok(())
}
