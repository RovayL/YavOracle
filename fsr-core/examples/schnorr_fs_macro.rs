//! Schnorr proof using the `proof!`/`verify!` DSL with the FS transform.

use fsr_core::{Absorb, Oracle, FsProof, HashOracle, Result};
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

impl G1 {
    fn pow(self, e: Scalar) -> G1 { G1(powmod(self.0, e.0)) }
    fn mul(self, other: G1) -> G1 { G1(modp(self.0 as u128 * other.0 as u128)) }
}

#[derive(Clone, Debug)] struct FirstMsg { t: G1 }
#[derive(Clone, Debug)] struct Resp { z: Scalar }
#[derive(Clone, Copy, Debug)] struct Public { g: G1, y: G1 }
#[derive(Clone, Copy, Debug)] struct Witness { w: Scalar }

fn enc_u64(x: u64) -> Vec<u8> { x.to_le_bytes().to_vec() }
fn dec_le_u64(bytes: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, &b) in bytes.iter().enumerate().take(8) { v |= (b as u64) << (8 * i); }
    v
}

fn schnorr_prover_first(pubc: &Public, r: Scalar) -> FirstMsg { FirstMsg { t: pubc.g.pow(r) } }
fn schnorr_prover_second(_pubc: &Public, r: Scalar, e: Scalar, w: Scalar) -> Resp {
    Resp { z: Scalar((r.0 + (e.0 % ORDER_Q) * (w.0 % ORDER_Q)) % ORDER_Q) }
}
fn schnorr_verify(pubc: &Public, m: &FirstMsg, e: Scalar, z: &Resp) -> bool {
    pubc.g.pow(z.z) == m.t.mul(pubc.y.pow(e))
}

fn main() -> Result<()> {
    let g = G1(5);
    let w = Scalar(424242);
    let y = g.pow(w);
    let pubc = Public { g, y };
    let wit = Witness { w };

    let statement = {
        let mut v = Vec::new();
        v.extend_from_slice(&enc_u64(pubc.g.0));
        v.extend_from_slice(&enc_u64(pubc.y.0));
        v
    };
    let sid = b"fs-macro-demo";
    let rho: u16 = 16;
    let b_bits: u8 = 4;

    let mut rng = StdRng::seed_from_u64(7);

    let proof: FsProof = fsr_proof_dsl::prove! {
        transform = "fs",
        oracle = HashOracle::new(b"YavOracle/FS-Macro"),
        rho = rho,
        b = b_bits,
        statement = statement.clone(),
        sid = sid,
        first = |_i| {
            let r = Scalar(rng.next_u64() % ORDER_Q);
            let m = schnorr_prover_first(&pubc, r);
            (enc_u64(m.t.0), r)
        },
        respond = |_i: usize, e_bytes: &[u8], r_i: &Scalar| {
            let e = Scalar(dec_le_u64(e_bytes) % ORDER_Q);
            let z = schnorr_prover_second(&pubc, *r_i, e, wit.w);
            enc_u64(z.z.0)
        }
    }?;

    let statement_for_verify = statement.clone();
    let ok = fsr_proof_dsl::verify! {
        transform = "fs",
        oracle = HashOracle::new(b"YavOracle/FS-Macro"),
        statement = &statement_for_verify,
        sid = sid,
        proof = &proof,
        sigma_verify = |_i, m_bytes, e_bytes, z_bytes| {
            let m = FirstMsg { t: G1(dec_le_u64(m_bytes)) };
            let e = Scalar(dec_le_u64(e_bytes) % ORDER_Q);
            let z = Resp { z: Scalar(dec_le_u64(z_bytes) % ORDER_Q) };
            schnorr_verify(&pubc, &m, e, &z)
        }
    };

    println!("FS verify = {}", ok);
    let proof_bytes = proof.encode();
    println!("FS proof bytes ({}): 0x{}", proof_bytes.len(), hex::encode(&proof_bytes));

    let verifier_src = fsr_proof_dsl::verify_source! {
        transform = "fs",
        oracle = HashOracle::new(b"YavOracle/FS-Macro"),
        statement = &statement_for_verify,
        sid = sid,
        proof = &proof,
        sigma_verify = |_i, m_bytes, e_bytes, z_bytes| {
            let m = FirstMsg { t: G1(dec_le_u64(m_bytes)) };
            let e = Scalar(dec_le_u64(e_bytes) % ORDER_Q);
            let z = Resp { z: Scalar(dec_le_u64(z_bytes) % ORDER_Q) };
            schnorr_verify(&pubc, &m, e, &z)
        }
    };

    println!("--- Schnorr FS verifier ---\n{}\n", verifier_src);

    Ok(())
}
