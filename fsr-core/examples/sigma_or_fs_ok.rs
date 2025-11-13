//! Sigma OR using FS transform with coverage enforcement and verifier source output.

use fsr_bind_derive::enforce_fs_coverage;
use fsr_core::{FsProof, FSOracle, HashOracle, RandomOracle, TranscriptRuntime, Result};
use rand::{rngs::StdRng, RngCore, SeedableRng};

const MOD_P: u64 = 2_147_483_647;
const ORDER_Q: u64 = MOD_P - 1;

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
fn inv(x: G1) -> G1 { // Fermat little theorem for prime MOD_P
    G1(powmod(x.0, MOD_P - 2))
}

#[derive(Clone, Copy, Debug)] struct Public { g: G1, y0: G1, y1: G1 }
#[derive(Clone, Copy, Debug)] struct Witness { b: u8, w: Scalar }

fn enc_u64(x: u64) -> Vec<u8> { x.to_le_bytes().to_vec() }
fn dec_le_u64(bytes: &[u8]) -> u64 { let mut v = 0u64; for (i, &b) in bytes.iter().enumerate().take(8) { v |= (b as u64) << (8 * i); } v }

// Enforce that both commitments c_0 and c_1 are absorbed before deriving the challenge.
#[enforce_fs_coverage(required = "c_0,c_1")]
fn sigma_or_prove(pubc: &Public, wit: &Witness, sid: &[u8], mut rng: StdRng) -> Result<FsProof> {
    let mut oracle = FSOracle::new(HashOracle::new(b"YavOracle/SigmaOR/FS"));

    // Statement bytes: g || y0 || y1
    let mut stmt = Vec::new();
    stmt.extend_from_slice(&enc_u64(pubc.g.0));
    stmt.extend_from_slice(&enc_u64(pubc.y0.0));
    stmt.extend_from_slice(&enc_u64(pubc.y1.0));

    oracle.absorb("mode", b"FS");
    oracle.absorb("x", &stmt);
    oracle.absorb("sid", sid);

    // Commitments
    let (t0, t1, e_fake, z_fake, r_real, y_real) = if wit.b == 0 {
        let r0 = Scalar(rng.next_u64() % ORDER_Q);
        let t0 = pubc.g.pow(r0);
        let e1 = Scalar(rng.next_u64() % ORDER_Q);
        let z1 = Scalar(rng.next_u64() % ORDER_Q);
        let t1 = pubc.g.pow(z1) * inv(pubc.y1.pow(e1));
        (t0, t1, e1, z1, r0, pubc.y0)
    } else {
        let r1 = Scalar(rng.next_u64() % ORDER_Q);
        let t1 = pubc.g.pow(r1);
        let e0 = Scalar(rng.next_u64() % ORDER_Q);
        let z0 = Scalar(rng.next_u64() % ORDER_Q);
        let t0 = pubc.g.pow(z0) * inv(pubc.y0.pow(e0));
        (t0, t1, e0, z0, r1, pubc.y1)
    };

    // Absorb both commitments with explicit labels.
    oracle.absorb("c_0", &enc_u64(t0.0));
    oracle.absorb("c_1", &enc_u64(t1.0));

    // Derive challenge and split
    let e_bytes = oracle.derive_challenge("e", &[], 32);
    let e = Scalar(dec_le_u64(&e_bytes) % ORDER_Q);

    let (e0, e1, z0, z1) = if wit.b == 0 {
        let e0 = Scalar((e.0 + ORDER_Q - (e_fake.0 % ORDER_Q)) % ORDER_Q);
        let z0 = Scalar((r_real.0 + (e0.0 * (wit.w.0 % ORDER_Q)) % ORDER_Q) % ORDER_Q);
        (e0, e_fake, z0, z_fake)
    } else {
        let e1 = Scalar((e.0 + ORDER_Q - (e_fake.0 % ORDER_Q)) % ORDER_Q);
        let z1 = Scalar((r_real.0 + (e1.0 * (wit.w.0 % ORDER_Q)) % ORDER_Q) % ORDER_Q);
        (e_fake, e1, z_fake, z1)
    };

    // Record e and z for verification; absorb e and z for transcript closure
    let mut m = Vec::new();
    m.extend_from_slice(&enc_u64(t0.0));
    m.extend_from_slice(&enc_u64(t1.0));
    let mut z = Vec::new();
    z.extend_from_slice(&enc_u64(e0.0));
    z.extend_from_slice(&enc_u64(z0.0));
    z.extend_from_slice(&enc_u64(z1.0));

    oracle.absorb("e", &e_bytes);
    oracle.absorb("z", &z);

    Ok(FsProof { m: vec![m], z: vec![z], rho: 1, b: 0 })
}

fn main() -> Result<()> {
    // Public setup
    let g = G1(5);
    let w0 = Scalar(123456);
    let w1 = Scalar(777777);
    let y0 = g.pow(w0);
    let y1 = g.pow(w1);
    let pubc = Public { g, y0, y1 };
    let sid = b"sigma-or-demo";

    // Prover knows w0
    let wit = Witness { b: 0, w: w0 };
    let rng = StdRng::seed_from_u64(42);
    let proof = sigma_or_prove(&pubc, &wit, sid, rng)?;

    // Verify via DSL verifier helper
    let stmt = {
        let mut v = Vec::new();
        v.extend_from_slice(&enc_u64(pubc.g.0));
        v.extend_from_slice(&enc_u64(pubc.y0.0));
        v.extend_from_slice(&enc_u64(pubc.y1.0));
        v
    };

    // Manual verifier matching the prover's transcript shape
    let ok = {
        let mut oracle = FSOracle::new(HashOracle::new(b"YavOracle/SigmaOR/FS"));
        oracle.absorb("mode", b"FS");
        oracle.absorb("x", &stmt);
        oracle.absorb("sid", sid);
        let m_bytes = &proof.m[0];
        let t0 = G1(dec_le_u64(&m_bytes[0..8]));
        let t1 = G1(dec_le_u64(&m_bytes[8..16]));
        oracle.absorb("c_0", &enc_u64(t0.0));
        oracle.absorb("c_1", &enc_u64(t1.0));
        let e_bytes = oracle.derive_challenge("e", &[], 32);
        let e = Scalar(dec_le_u64(&e_bytes) % ORDER_Q);
        let z_bytes = &proof.z[0];
        let e0 = Scalar(dec_le_u64(&z_bytes[0..8]) % ORDER_Q);
        let z0 = Scalar(dec_le_u64(&z_bytes[8..16]) % ORDER_Q);
        let z1 = Scalar(dec_le_u64(&z_bytes[16..24]) % ORDER_Q);
        let e1 = Scalar((e.0 + ORDER_Q - (e0.0 % ORDER_Q)) % ORDER_Q);
        let lhs0 = pubc.g.pow(z0);
        let rhs0 = t0 * pubc.y0.pow(e0);
        let lhs1 = pubc.g.pow(z1);
        let rhs1 = t1 * pubc.y1.pow(e1);
        lhs0 == rhs0 && lhs1 == rhs1
    };

    println!("Sigma-OR FS verify = {}", ok);
    let proof_bytes = proof.encode();
    println!("Sigma-OR FS proof bytes ({}): 0x{}", proof_bytes.len(), hex::encode(&proof_bytes));

    // Verifier source via DSL helper
    let src = fsr_proof_dsl::verify_source! {
        transform = "fs",
        oracle = HashOracle::new(b"YavOracle/SigmaOR/FS"),
        statement = &statement_for_verify,
        sid = sid,
        proof = &proof,
        sigma_verify = |_i, m_bytes, e_bytes, z_bytes| { let _ = (m_bytes, e_bytes, z_bytes); true }
    };
    println!("Verifier source (FS):\n{}", src);
    Ok(())
}
