//! DSL-based Sigma OR using fsr_proof_dsl::prove!/verify! with coverage requirements.

use fsr_core::{FsProof, HashOracle, Result};
use rand::{rngs::StdRng, SeedableRng, RngCore};

const MOD_P: u64 = 2_147_483_647;
const ORDER_Q: u64 = MOD_P - 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)] struct G1(u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)] struct Scalar(u64);
fn modp(x: u128) -> u64 { (x % MOD_P as u128) as u64 }
fn powmod(mut base: u64, mut exp: u64) -> u64 { let mut acc = 1u64; while exp > 0 { if exp & 1 == 1 { acc = modp(acc as u128 * base as u128); } base = modp(base as u128 * base as u128); exp >>= 1; } acc }
impl G1 { fn pow(self, e: Scalar) -> G1 { G1(powmod(self.0, e.0)) } }
impl core::ops::Mul for G1 { type Output = G1; fn mul(self, rhs: G1) -> G1 { G1(modp(self.0 as u128 * rhs.0 as u128)) } }
fn inv(x: G1) -> G1 { G1(powmod(x.0, MOD_P - 2)) }

#[derive(Clone, Copy, Debug)] struct Public { g: G1, y0: G1, y1: G1 }
#[derive(Clone, Copy, Debug)] struct Witness { b: u8, w: Scalar }
fn enc_u64(x: u64) -> Vec<u8> { x.to_le_bytes().to_vec() }
fn dec_le_u64(bytes: &[u8]) -> u64 { let mut v = 0u64; for (i, &b) in bytes.iter().enumerate().take(8) { v |= (b as u64) << (8 * i); } v }

fn main() -> Result<()> {
    let g = G1(5);
    let w0 = Scalar(4242);
    let w1 = Scalar(7777);
    let y0 = g.pow(w0);
    let y1 = g.pow(w1);
    let pubc = Public { g, y0, y1 };
    let wit = Witness { b: 0, w: w0 };
    let sid = b"sigma-or-dsl-fs-ok";
    let mut rng = StdRng::seed_from_u64(2025);

    let statement = {
        let mut v = Vec::new();
        v.extend_from_slice(&enc_u64(pubc.g.0));
        v.extend_from_slice(&enc_u64(pubc.y0.0));
        v.extend_from_slice(&enc_u64(pubc.y1.0));
        v
    };

    let proof: FsProof = fsr_proof_dsl::prove! {
        transform = "fs",
        oracle = HashOracle::new(b"YavOracle/SigmaOR/DSL/FS"),
        rho = 1u16,
        b = 0u8,
        statement = statement.clone(),
        sid = sid,
        first = |_i| {
            // Build commitments
            let (t0, t1, sig_b, sig_r, sig_e_fake, sig_z_fake) = if wit.b == 0 {
                let r0 = Scalar(rng.next_u64() % ORDER_Q);
                let t0 = pubc.g.pow(r0);
                // fake branch for 1
                let e1 = Scalar(rng.next_u64() % ORDER_Q);
                let z1 = Scalar(rng.next_u64() % ORDER_Q);
                let t1 = pubc.g.pow(z1) * inv(pubc.y1.pow(e1));
                (t0, t1, 0u8, r0.0, e1.0, z1.0)
            } else {
                let r1 = Scalar(rng.next_u64() % ORDER_Q);
                let t1 = pubc.g.pow(r1);
                // fake branch for 0
                let e0 = Scalar(rng.next_u64() % ORDER_Q);
                let z0 = Scalar(rng.next_u64() % ORDER_Q);
                let t0 = pubc.g.pow(z0) * inv(pubc.y0.pow(e0));
                (t0, t1, 1u8, r1.0, e0.0, z0.0)
            };
            let mut m = Vec::new(); m.extend_from_slice(&enc_u64(t0.0)); m.extend_from_slice(&enc_u64(t1.0));
            // sigma carries branch, r_real, e_fake, z_fake as u64s
            (m, (sig_b, sig_r, sig_e_fake, sig_z_fake))
        },
        // Ensure coverage: absorb both commitments with exact labels before challenge
        require = ["c_0", "c_1"],
        bind = |o: &mut _, _i: usize, m_bytes: &[u8]| {
            let t0b = &m_bytes[0..8];
            let t1b = &m_bytes[8..16];
            fsr_core::TranscriptRuntime::absorb(o, "c_0", t0b);
            fsr_core::TranscriptRuntime::absorb(o, "c_1", t1b);
        },
        respond = |_i: usize, e_bytes: &[u8], sigma: &(u8, u64, u64, u64)| {
            let e = Scalar(dec_le_u64(e_bytes) % ORDER_Q);
            let (b_bit, r_real_u64, e_fake_u64, z_fake_u64) = *sigma;
            let r_real = Scalar(r_real_u64 % ORDER_Q);
            let e_fake = Scalar(e_fake_u64 % ORDER_Q);
            let z_fake = Scalar(z_fake_u64 % ORDER_Q);
            let (e0, z0, z1) = if b_bit == 0 {
                let e0 = Scalar((e.0 + ORDER_Q - (e_fake.0 % ORDER_Q)) % ORDER_Q);
                let z0 = Scalar((r_real.0 + (e0.0) * (w0.0 % ORDER_Q)) % ORDER_Q);
                (e0, z0, z_fake)
            } else {
                let e1 = Scalar((e.0 + ORDER_Q - (e_fake.0 % ORDER_Q)) % ORDER_Q);
                let z1 = Scalar((r_real.0 + (e1.0) * (w1.0 % ORDER_Q)) % ORDER_Q);
                (e_fake, z_fake, z1)
            };
            let mut out = Vec::new();
            out.extend_from_slice(&enc_u64(e0.0));
            out.extend_from_slice(&enc_u64(z0.0));
            out.extend_from_slice(&enc_u64(z1.0));
            out
        }
    }?;

    // Verify with DSL verify!
    let ok = fsr_proof_dsl::verify! {
        transform = "fs",
        oracle = HashOracle::new(b"YavOracle/SigmaOR/DSL/FS"),
        statement = &statement,
        sid = sid,
        proof = &proof,
        // replay bind on verifier side as well
        require = ["c_0", "c_1"],
        bind = |o: &mut _, i: usize, m_bytes: &[u8]| {
            let t0b = &m_bytes[0..8];
            let t1b = &m_bytes[8..16];
            fsr_core::TranscriptRuntime::absorb(o, "c_0", t0b);
            fsr_core::TranscriptRuntime::absorb(o, "c_1", t1b);
        },
        sigma_verify = |_i: usize, m_bytes: &[u8], e_bytes: &[u8], z_bytes: &[u8]| {
            let t0 = G1(dec_le_u64(&m_bytes[0..8]));
            let t1 = G1(dec_le_u64(&m_bytes[8..16]));
            let e = Scalar(dec_le_u64(e_bytes) % ORDER_Q);
            let e0 = Scalar(dec_le_u64(&z_bytes[0..8]) % ORDER_Q);
            let z0 = Scalar(dec_le_u64(&z_bytes[8..16]) % ORDER_Q);
            let z1 = Scalar(dec_le_u64(&z_bytes[16..24]) % ORDER_Q);
            let e1 = Scalar((e.0 + ORDER_Q - (e0.0 % ORDER_Q)) % ORDER_Q);
            // This example doesn’t reconstruct secrets; just check form holds for a degenerate case
            pubc.g.pow(z0) == t0 * pubc.y0.pow(e0) && pubc.g.pow(z1) == t1 * pubc.y1.pow(e1)
        }
    };

    println!("Sigma-OR DSL/FS verify = {}", ok);
    assert!(ok);
    // Proof bytes
    println!("Proof bytes ({}): 0x{}", proof.encode().len(), hex::encode(&proof.encode()));
    // Verifier source (FS)
    let src = fsr_proof_dsl::verify_source! {
        transform = "fs",
        oracle = HashOracle::new(b"YavOracle/SigmaOR/DSL/FS"),
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
        sigma_verify = |_i: usize, _m: &[u8], _e: &[u8], _z: &[u8]| { true }
    };
    println!("Verifier source (FS):\n{}", src);
    Ok(())
}
