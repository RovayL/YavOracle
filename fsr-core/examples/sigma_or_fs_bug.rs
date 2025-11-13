//! Sigma OR FS example with an intentional coverage bug: missing absorb("c_0", ...).
//! This should fail to compile due to the enforce_fs_coverage attribute.

use fsr_bind_derive::enforce_fs_coverage;
use fsr_core::{FsProof, FSOracle, HashOracle, TranscriptRuntime, Result};
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

// Require both c_0 and c_1, but we intentionally do NOT absorb c_0.
#[enforce_fs_coverage(required = "c_0,c_1")]
fn sigma_or_prove_bug(pubc: &Public, wit: &Witness, sid: &[u8], mut rng: StdRng) -> Result<FsProof> {
    let mut oracle = FSOracle::new(HashOracle::new(b"YavOracle/SigmaOR/Bug"));

    let mut stmt = Vec::new();
    stmt.extend_from_slice(&enc_u64(pubc.g.0));
    stmt.extend_from_slice(&enc_u64(pubc.y0.0));
    stmt.extend_from_slice(&enc_u64(pubc.y1.0));

    oracle.absorb("mode", b"FS");
    oracle.absorb("x", &stmt);
    oracle.absorb("sid", sid);

    // Build commitments as in the OK example
    let (t0, t1, e_fake, z_fake, r_real) = if wit.b == 0 {
        let r0 = Scalar(rng.next_u64() % ORDER_Q);
        let t0 = pubc.g.pow(r0);
        let e1 = Scalar(rng.next_u64() % ORDER_Q);
        let z1 = Scalar(rng.next_u64() % ORDER_Q);
        let t1 = pubc.g.pow(z1) * inv(pubc.y1.pow(e1));
        (t0, t1, e1, z1, r0)
    } else {
        let r1 = Scalar(rng.next_u64() % ORDER_Q);
        let t1 = pubc.g.pow(r1);
        let e0 = Scalar(rng.next_u64() % ORDER_Q);
        let z0 = Scalar(rng.next_u64() % ORDER_Q);
        let t0 = pubc.g.pow(z0) * inv(pubc.y0.pow(e0));
        (t0, t1, e0, z0, r1)
    };

    // BUG: only absorb c_1, omit c_0
    // oracle.absorb("c_0", &enc_u64(t0.0));  // intentionally omitted
    oracle.absorb("c_1", &enc_u64(t1.0));

    // This should trigger compile-time error due to missing c_0 before derive_challenge
    let e_bytes = oracle.derive_challenge("e", &[], 32);
    let _ = (e_bytes, e_fake, z_fake, r_real, t0); // silence unused warnings

    Ok(FsProof { m: vec![], z: vec![], rho: 1, b: 0 })
}

fn main() -> Result<()> {
    let g = G1(5);
    let w0 = Scalar(123);
    let w1 = Scalar(456);
    let y0 = g.pow(w0);
    let y1 = g.pow(w1);
    let pubc = Public { g, y0, y1 };
    let sid = b"sigma-or-bug";
    let wit = Witness { b: 0, w: w0 };
    let rng = StdRng::seed_from_u64(99);
    let _ = sigma_or_prove_bug(&pubc, &wit, sid, rng)?;
    Ok(())
}

