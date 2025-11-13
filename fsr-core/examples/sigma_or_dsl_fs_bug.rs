//! DSL-based Sigma OR with missing c_0 bind, should fail at compile time.

use fsr_core::{HashOracle, Result};
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

fn main() -> Result<()> {
    let g = G1(5);
    let y0 = g.pow(Scalar(1));
    let y1 = g.pow(Scalar(2));
    let sid = b"sigma-or-dsl-fs-bug";
    let mut rng = StdRng::seed_from_u64(7);
    let statement = {
        let mut v = Vec::new();
        v.extend_from_slice(&enc_u64(g.0));
        v.extend_from_slice(&enc_u64(y0.0));
        v.extend_from_slice(&enc_u64(y1.0));
        v
    };

    let _ = fsr_proof_dsl::prove! {
        transform = "fs",
        oracle = HashOracle::new(b"YavOracle/SigmaOR/DSL/FS/Bug"),
        rho = 1u16,
        b = 0u8,
        statement = statement.clone(),
        sid = sid,
        first = |_i| {
            let t0 = g.pow(Scalar(rng.next_u64() % ORDER_Q));
            let t1 = g.pow(Scalar(rng.next_u64() % ORDER_Q));
            let mut m = Vec::new(); m.extend_from_slice(&enc_u64(t0.0)); m.extend_from_slice(&enc_u64(t1.0));
            (m, ())
        },
        require = ["c_0", "c_1"],
        bind = |o: &mut _, _i: usize, m_bytes: &[u8]| {
            // BUG: forget to absorb c_0
            let _t0b = &m_bytes[0..8];
            let t1b = &m_bytes[8..16];
            fsr_core::TranscriptRuntime::absorb(o, "c_1", t1b);
        },
        respond = |_i: usize, _e_bytes: &[u8], _sigma: &()| { vec![0u8; 24] }
    }?;

    Ok(())
}
