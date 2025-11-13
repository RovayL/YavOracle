//! Schnorr end-to-end using the higher-level `proof!` DSL.
//! Records a transcript with a RecordingHashOracle, emits a compact proof via
//! the generated module (no manual bind/require at call sites), verifies, and
//! prints the full verifier source.

use fsr_core::{Absorb, Oracle, CanonicalEncode, HashOracle, RecordingHashOracle, RecEvent, Result, U64Challenge};
use rand::{rngs::StdRng, SeedableRng, RngCore};

const MOD_P: u64 = 2_147_483_647; // toy prime
const ORDER_Q: u64 = MOD_P - 1;   // toy order

#[derive(Clone, Copy, Debug, PartialEq, Eq)] struct G1(u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)] struct Scalar(u64);

fn modp(x: u128) -> u64 { (x % MOD_P as u128) as u64 }
fn powmod(mut base: u64, mut exp: u64) -> u64 {
    let mut acc = 1u64;
    while exp > 0 {
        if exp & 1 == 1 { acc = modp(acc as u128 * base as u128); }
        base = modp(base as u128 * base as u128);
        exp >>= 1;
    }
    acc
}
impl G1 { fn pow(self, e: Scalar) -> G1 { G1(powmod(self.0, e.0)) } }
impl core::ops::Mul for G1 { type Output = G1; fn mul(self, rhs: G1) -> G1 { G1(modp(self.0 as u128 * rhs.0 as u128)) } }

fn enc_u64(x: u64) -> Vec<u8> { x.to_le_bytes().to_vec() }
fn dec_le_u64(bytes: &[u8]) -> u64 { let mut v = 0u64; for (i, &b) in bytes.iter().enumerate().take(8) { v |= (b as u64) << (8 * i); } v }

#[derive(Clone, Copy, Debug)] struct Public { g: G1, y: G1 }

// High-level Schnorr proof: commit t, derive challenge e, respond z.
fsr_proof_dsl::proof! {
    name: Schnorr;
    domain: "YavOracle/Schnorr/ProofDSL";
    public: Public;
    fields {
        t: Vec<u8>                 <= absorb   "commit.t";
        e: fsr_core::U64Challenge  <= challenge "e";
        z: Vec<u8>                 <= absorb   "resp.z";
    }
    replay {
        bind "commit.t" <- t;
    }
    check {{
        // Recompute check: g^z == t * y^e
        let t = G1(dec_le_u64(&t));
        let e = Scalar(e.0 % ORDER_Q);
        let z = Scalar(dec_le_u64(&z) % ORDER_Q);
        let lhs = pub_in.g.pow(z);
        let rhs = t * pub_in.y.pow(e);
        lhs == rhs
    }}
}

fn main() -> Result<()> {
    // Public setup
    let g = G1(5);
    let w = Scalar(424242);
    let y = g.pow(w);
    let pubc = Public { g, y };

    // Prover record of transcript
    let mut rng = StdRng::seed_from_u64(2028);
    let mut ro = RecordingHashOracle::new(HashOracle::new(b"YavOracle/Schnorr/ProofDSL"));
    let r = Scalar(rng.next_u64() % ORDER_Q);
    let t = g.pow(r);
    let mut t_bytes = Vec::new();
    CanonicalEncode::encode(&enc_u64(t.0), &mut t_bytes); // Vec<u8> canonical bytes
    ro.absorb_bytes("commit.t", &t_bytes);
    let e: U64Challenge = ro.challenge("e")?;
    let e_mod = Scalar(e.0 % ORDER_Q);
    let z = Scalar((r.0 + (e_mod.0 * (w.0 % ORDER_Q)) % ORDER_Q) % ORDER_Q);
    let mut z_bytes = Vec::new();
    CanonicalEncode::encode(&enc_u64(z.0), &mut z_bytes); // Vec<u8> canonical bytes
    ro.absorb_bytes("resp.z", &z_bytes);

    // Emit compact proof from events via the generated module
    let events: Vec<RecEvent> = ro.into_parts().1;
    let proof = schnorr_prove(&events).expect("events decode");
    let bytes = proof.encode();
    println!("Schnorr(ProofDSL) bytes ({}): 0x{}", bytes.len(), hex::encode(&bytes));

    // Verify via generated verifier
    let ok = schnorr_verify(&pubc, &proof);
    println!("Schnorr(ProofDSL) verify = {}", ok);
    let ok_b = schnorr_verify_bytes(&pubc, &bytes);
    println!("Schnorr(ProofDSL) verify(bytes) = {}", ok_b);

    // Print full verifier source
    println!("Verifier source (proof!):\n{}", schnorr_verifier_source());
    Ok(())
}
