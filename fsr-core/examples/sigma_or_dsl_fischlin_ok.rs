//! DSL-based Sigma OR using Fischlin transform with coverage requirements.

use fsr_core::{FischlinOracle, FischlinParams, HashOracle, Result};
use rand::{rngs::StdRng, RngCore, SeedableRng};

const MOD_P: u64 = 2_147_483_647;
const ORDER_Q: u64 = MOD_P - 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)] struct G1(u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)] struct Scalar(u64);
fn modp(x: u128) -> u64 { (x % MOD_P as u128) as u64 }
fn powmod(mut base: u64, mut exp: u64) -> u64 { let mut acc = 1u64; while exp > 0 { if exp & 1 == 1 { acc = modp(acc as u128 * base as u128); } base = modp(base as u128 * base as u128); exp >>= 1; } acc }
impl G1 { fn pow(self, e: Scalar) -> G1 { G1(powmod(self.0, e.0)) } }
impl core::ops::Mul for G1 { type Output = G1; fn mul(self, rhs: G1) -> G1 { G1(modp(self.0 as u128 * rhs.0 as u128)) } }
fn inv(x: G1) -> G1 { G1(powmod(x.0, MOD_P - 2)) }

fn enc_u64(x: u64) -> Vec<u8> { x.to_le_bytes().to_vec() }
fn dec_le_u64(bytes: &[u8]) -> u64 { let mut v = 0u64; for (i, &b) in bytes.iter().enumerate().take(8) { v |= (b as u64) << (8 * i); } v }

fn main() -> Result<()> {
    let g = G1(5);
    let w0 = Scalar(4242);
    let w1 = Scalar(7777);
    let y0 = g.pow(w0);
    let y1 = g.pow(w1);
    let sid = b"sigma-or-dsl-fischlin-ok";
    let mut rng = StdRng::seed_from_u64(2026);

    let statement = {
        let mut v = Vec::new();
        v.extend_from_slice(&enc_u64(g.0));
        v.extend_from_slice(&enc_u64(y0.0));
        v.extend_from_slice(&enc_u64(y1.0));
        v
    };

    let rho: u16 = 32;
    let b_bits: u8 = 8;

    let proof = fsr_proof_dsl::prove! {
        transform = "fischlin",
        oracle = FischlinOracle::new(HashOracle::new(b"YavOracle/SigmaOR/DSL/Fischlin"), FischlinParams::new(rho, b_bits)),
        rho = rho,
        b = b_bits,
        statement = statement.clone(),
        sid = sid,
        first = |_i| {
            let r0 = Scalar(rng.next_u64() % ORDER_Q);
            let r1 = Scalar(rng.next_u64() % ORDER_Q);
            let t0 = g.pow(r0);
            let t1 = g.pow(r1);
            let mut m = Vec::new(); m.extend_from_slice(&enc_u64(t0.0)); m.extend_from_slice(&enc_u64(t1.0));
            (m, (r0.0, r1.0))
        },
        require = ["c_0", "c_1"],
        bind = |o: &mut _, _i: usize, m_bytes: &[u8]| {
            let t0b = &m_bytes[0..8];
            let t1b = &m_bytes[8..16];
            fsr_core::TranscriptRuntime::absorb(o, "c_0", t0b);
            fsr_core::TranscriptRuntime::absorb(o, "c_1", t1b);
        },
        respond = |_i: usize, e_bytes: &[u8], sigma: &(u64, u64)| {
            let e = Scalar(dec_le_u64(e_bytes) % ORDER_Q);
            let (r0u, r1u) = *sigma;
            let r0 = Scalar(r0u % ORDER_Q);
            let r1 = Scalar(r1u % ORDER_Q);
            // Do an AND-style version here for simplicity of example
            let z0 = Scalar((r0.0 + e.0 * (w0.0 % ORDER_Q)) % ORDER_Q);
            let z1 = Scalar((r1.0 + e.0 * (w1.0 % ORDER_Q)) % ORDER_Q);
            let mut out = Vec::new(); out.extend_from_slice(&enc_u64(z0.0)); out.extend_from_slice(&enc_u64(z1.0)); out
        }
    }?;

    // Verify via DSL
    let ok = fsr_proof_dsl::verify! {
        transform = "fischlin",
        oracle = FischlinOracle::new(HashOracle::new(b"YavOracle/SigmaOR/DSL/Fischlin"), FischlinParams::new(rho, b_bits)),
        statement = &statement,
        sid = sid,
        proof = &proof,
        require = ["c_0", "c_1"],
        bind = |o: &mut _, _i: usize, m_bytes: &[u8]| {
            let t0b = &m_bytes[0..8];
            let t1b = &m_bytes[8..16];
            fsr_core::TranscriptRuntime::absorb(o, "c_0", t0b);
            fsr_core::TranscriptRuntime::absorb(o, "c_1", t1b);
        },
        sigma_verify = |_i: usize, m_bytes: &[u8], e_bytes: &[u8], z_bytes: &[u8]| {
            let t0 = G1(dec_le_u64(&m_bytes[0..8]));
            let t1 = G1(dec_le_u64(&m_bytes[8..16]));
            let e = Scalar(dec_le_u64(e_bytes) % ORDER_Q);
            let z0 = Scalar(dec_le_u64(&z_bytes[0..8]) % ORDER_Q);
            let z1 = Scalar(dec_le_u64(&z_bytes[8..16]) % ORDER_Q);
            g.pow(z0) == t0 * y0.pow(e) && g.pow(z1) == t1 * y1.pow(e)
        }
    };
    println!("Sigma-OR DSL/Fischlin verify = {}", ok);
    // Print bytes and verifier source
    println!("Proof bytes ({}): 0x{}", proof.encode().len(), hex::encode(&proof.encode()));
    let src = fsr_proof_dsl::verify_source! {
        transform = "fischlin",
        oracle = FischlinOracle::new(HashOracle::new(b"YavOracle/SigmaOR/DSL/Fischlin"), FischlinParams::new(rho, b_bits)),
        statement = &statement,
        sid = sid,
        proof = &proof,
        require = ["c_0", "c_1"],
        bind = |o: &mut _, _i: usize, m_bytes: &[u8]| {
            let t0b = &m_bytes[0..8]; let t1b = &m_bytes[8..16];
            fsr_core::TranscriptRuntime::absorb(o, "c_0", t0b);
            fsr_core::TranscriptRuntime::absorb(o, "c_1", t1b);
        },
        sigma_verify = |_i: usize, _m: &[u8], _e: &[u8], _z: &[u8]| { true }
    };
    println!("Verifier source (Fischlin):\n{}", src);
    Ok(())
}
