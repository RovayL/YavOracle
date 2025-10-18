//! fsr-core/examples/schnorr_fischlin.rs
//! Minimal Schnorr + Fischlin example over a toy prime field (NOT cryptographically secure).
//! This exercise shows how to drive `FischlinOracle` directly (Milestone 1).
//! Later, the DSL will expand to these calls automatically.

use fsr_core::{FischlinOracle, FischlinParams, FischlinProof};
use fsr_core::fischlin_proof::verify_fischlin;
use fsr_core::runtime::{RandomOracle, TranscriptRuntime, trunc_b_to_u64};

// ---------------- Toy field / group (prime modulus) ----------------
const MOD_P: u64 = 2_147_483_647; // 2^31-1 (Mersenne) - toy only
const ORDER_Q: u64 = MOD_P - 1;   // assume g has order q (toy)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct G1(u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Scalar(u64);

fn modp(x: u128) -> u64 { (x % MOD_P as u128) as u64 }
fn modq(x: u128) -> u64 { (x % ORDER_Q as u128) as u64 }

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
    fn mul(self, other: G1) -> G1 { G1(modp(self.0 as u128 * other.0 as u128)) }
    fn pow(self, e: Scalar) -> G1 { G1(powmod(self.0, e.0)) }
}

impl Scalar {
    fn add(self, other: Scalar) -> Scalar { Scalar(modq(self.0 as u128 + other.0 as u128)) }
    fn mul(self, other: Scalar) -> Scalar { Scalar(modq(self.0 as u128 * other.0 as u128)) }
}

// --------------- Byte encoding helpers (very simple) ---------------
fn enc_u64(x: u64) -> Vec<u8> { x.to_le_bytes().to_vec() }
fn dec_le_u64(bytes: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, &b) in bytes.iter().enumerate().take(8) {
        v |= (b as u64) << (8 * i);
    }
    v
}

// Public statement and witness
#[derive(Clone, Copy, Debug)]
struct Public { g: G1, y: G1 }
#[derive(Clone, Copy, Debug)]
struct Witness { w: Scalar }

// ---------------- Random Oracle (example-only, NOT crypto) ---------
/// A stub RO based on std's DefaultHasher just to make the example runnable.
/// Replace with your existing `HashOracle` adapter that implements `RandomOracle`.
#[derive(Default)]
struct StdRO;
impl RandomOracle for StdRO {
    fn H_full(&mut self, label: &'static str, data: &[u8]) -> Vec<u8> {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        label.as_bytes().hash(&mut h);
        data.hash(&mut h);
        // Expand to 32 bytes deterministically
        let mut out = Vec::with_capacity(32);
        let mut seed = h.finish();
        for _ in 0..4 {
            out.extend_from_slice(&seed.to_le_bytes());
            // mix
            seed = seed.rotate_left(13) ^ 0x9E3779B97F4A7C15u64;
        }
        out
    }
    fn H(&mut self, label: &'static str, data: &[u8]) -> Vec<u8> {
        self.H_full(label, data)
    }
}

// ---------------- Tiny deterministic RNG (avoid external deps) -----
#[derive(Clone)]
struct XorShift64 { state: u64 }
impl XorShift64 {
    fn new(seed: u64) -> Self { Self { state: seed } }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

// ---------------- Schnorr Sigma protocol (typed but byte-encoded) --
#[derive(Clone, Debug)]
struct FirstMsg { t: G1 }
#[derive(Clone, Debug)]
struct Resp { z: Scalar }

fn schnorr_prover_first(pubc: &Public, r: Scalar) -> FirstMsg {
    FirstMsg { t: pubc.g.pow(r) }
}

fn schnorr_prover_second(r: Scalar, e: Scalar, w: Scalar) -> Resp {
    // z = r + e*w  (mod q)
    Resp { z: r.add(e.mul(w)) }
}

fn schnorr_verify(pubc: &Public, m: &FirstMsg, e: Scalar, z: &Resp) -> bool {
    // check g^z == t * y^e
    let lhs = pubc.g.pow(z.z);
    let rhs = m.t.mul(pubc.y.pow(e));
    lhs == rhs
}

// ---------------- Fischlin proof produce/verify --------------------

fn fischlin_schnorr_prove(pubc: &Public, wit: &Witness, rho: u16, b: u8) -> FischlinProof {
    let params = FischlinParams::new(rho, b);
    let ro = StdRO::default();
    let mut oracle = FischlinOracle::new(ro, params);

    let x_bytes = {
        let mut v = Vec::new();
        v.extend_from_slice(&enc_u64(pubc.g.0));
        v.extend_from_slice(&enc_u64(pubc.y.0));
        v
    };
    let sid = b"demo-session-1";

    let mut rng = XorShift64::new(42);

    loop {
        // fresh first messages each attempt
        oracle.begin(&x_bytes, sid);

        let mut r_vec: Vec<Scalar> = Vec::with_capacity(rho as usize);
        let mut m_bytes: Vec<Vec<u8>> = Vec::with_capacity(rho as usize);

        for _i in 0..rho {
            let r = Scalar(rng.next_u64() % ORDER_Q);
            let m = schnorr_prover_first(pubc, r);
            let mut enc = Vec::new();
            enc.extend_from_slice(&enc_u64(m.t.0));
            oracle.push_first_message(&enc);
            r_vec.push(r);
            m_bytes.push(enc);
        }

        oracle.seal_first_messages();

        let mut e_bytes_vec: Vec<Vec<u8>> = Vec::with_capacity(rho as usize);
        let mut z_bytes_vec: Vec<Vec<u8>> = Vec::with_capacity(rho as usize);

        let mut success = true;

        for i in 0..rho {
            let r_i = r_vec[i as usize];
            let w = wit.w;

            // z_stream: z_0 = r_i; then z_{k+1} = z_k + w (mod q)
            let mut z_running = r_i.0 % ORDER_Q;
            let next_z = || -> Vec<u8> {
                let out = enc_u64(z_running);
                // advance for next try
                z_running = (z_running + w.0) % ORDER_Q;
                out
            };

            if let Some((e_i_bytes, z_i_bytes)) = oracle.search_round_stream(i as u32, next_z) {
                e_bytes_vec.push(e_i_bytes.clone());
                z_bytes_vec.push(z_i_bytes.clone());
                debug_assert!({
                    let t = G1(dec_le_u64(&m_bytes[i as usize]));
                    let e_chk = Scalar(dec_le_u64(&e_i_bytes) % ORDER_Q);
                    let z_chk = Scalar(dec_le_u64(&z_i_bytes) % ORDER_Q);
                    schnorr_verify(pubc, &FirstMsg { t }, e_chk, &Resp { z: z_chk })
                });
            } else {
                // one repetition failed all tries; restart entire proof with fresh randomness
                success = false;
                break;
            }
        }

        if success {
            return FischlinProof { m: m_bytes, e: e_bytes_vec, z: z_bytes_vec, b, rho };
        }
        // else: loop and try again with fresh m⃗/r⃗
    }
}

fn fischlin_schnorr_verify(pubc: &Public, proof: &FischlinProof) -> bool {
    let params = FischlinParams::new(proof.rho, proof.b);
    let ro = StdRO::default();

    // Serialize statement
    let x_bytes = {
        let mut v = Vec::new();
        v.extend_from_slice(&enc_u64(pubc.g.0));
        v.extend_from_slice(&enc_u64(pubc.y.0));
        v
    };
    let sid = b"demo-session-1";

    // Inject Sigma verifier callback on bytes
    let sigma_verify = |_: usize, m_i_bytes: &[u8], e_i_bytes: &[u8], z_i_bytes: &[u8]| -> bool {
        // parse FirstMsg, e, z
        let t = G1(dec_le_u64(m_i_bytes));        // m_i_bytes are 8 bytes from enc_u64, still ok
        let e = Scalar(dec_le_u64(e_i_bytes) % ORDER_Q);  // <- variable-length works here
        let z = Scalar(dec_le_u64(z_i_bytes) % ORDER_Q);  // z_i_bytes are 8 bytes; also fine
        schnorr_verify(pubc, &FirstMsg { t }, e, &Resp { z })
    };

    verify_fischlin(ro, params, &x_bytes, sid, proof, sigma_verify)
}

fn main() {
    // Setup Schnorr public/witness
    let g = G1(5);                 // toy base
    let w = Scalar(1234567);       // secret
    let y = g.pow(w);              // public key
    let pubc = Public { g, y };
    let wit = Witness { w };

    // Produce a Fischlin proof
    let rho = 32;
    let b = 4; // 32*4 = 128-bit core cost
    let proof = fischlin_schnorr_prove(&pubc, &wit, rho, b);

    // Verify
    let ok = fischlin_schnorr_verify(&pubc, &proof);
    println!("Fischlin Schnorr verify = {}", ok);
    assert!(ok);
}
