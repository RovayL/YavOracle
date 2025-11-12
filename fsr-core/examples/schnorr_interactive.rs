use fsr_core::*;
use fsr_bind_derive::FsrBindable;

#[cfg(feature = "interactive")]
fn main() -> fsr_core::Result<()> {
    use rand::{rngs::StdRng, SeedableRng};

    // ------------------- Toy additive group Z_p -------------------
    // Group operation:     P + Q   := (p + q) mod P
    // Scalar multiplication: s * G := (s * g) mod P
    // Schnorr over additive group:
    //   commit:  T = r*G
    //   chall:   e
    //   resp:    z = r + e*x           (mod P)
    //   verify:  z*G ?= T + e*Y        (mod P), where Y = x*G
    const MOD_P: u64 = 2_147_483_647; // Mersenne prime (2^31 - 1), fits in u64

    #[inline] fn modp_u64(x: u128) -> u64 { (x % (MOD_P as u128)) as u64 }

    #[derive(Clone, Copy, Debug)]
    pub struct G1(pub u64); // "point" in Z_p (toy group)

    impl G1 {
        #[inline] fn add(self, other: G1) -> G1 { G1(modp_u64(self.0 as u128 + other.0 as u128)) }
        #[inline] fn smul(self, s: Scalar) -> G1 { G1(modp_u64(self.0 as u128 * s.0 as u128)) }
    }

    impl CanonicalEncode for G1 {
        fn encode(&self, out: &mut Vec<u8>) { out.extend_from_slice(&self.0.to_le_bytes()); }
    }

    #[derive(Clone, Copy, Debug)]
    pub struct Scalar(pub u64); // scalars modulo p (toy)

    impl Scalar {
        #[inline] fn add(self, other: Scalar) -> Scalar { Scalar(modp_u64(self.0 as u128 + other.0 as u128)) }
        #[inline] fn mul(self, other: Scalar) -> Scalar { Scalar(modp_u64(self.0 as u128 * other.0 as u128)) }
    }

    impl CanonicalEncode for Scalar {
        fn encode(&self, out: &mut Vec<u8>) { out.extend_from_slice(&self.0.to_le_bytes()); }
    }

    // NOTE: label is &str (not &'static str) to match fsr_core::Challenge
    impl Challenge for Scalar {
        fn from_oracle_bytes(_label: &str, bytes: &[u8]) -> Self {
            // hash bytes → u64 → reduce mod p
            use core::hash::{Hash, Hasher};
            let mut s = std::collections::hash_map::DefaultHasher::new();
            bytes.hash(&mut s);
            Scalar(modp_u64(s.finish() as u128))
        }
        const BYTES: usize = 32;
    }

    #[derive(Clone, Debug)]
    pub struct Public {
        pub G: G1,
        pub Y: G1, // Y = x*G
    }

    impl CanonicalEncode for Public {
        fn encode(&self, out: &mut Vec<u8>) { self.G.encode(out); self.Y.encode(out); }
    }

    // ------------------- Messages -------------------
    #[derive(Clone, Debug, FsrBindable)]
    #[bind(prefix = "Commit")]
    pub struct Commit {
        #[bind(ob = 0)]           // pre-challenge obligation: T must be bound before sampling e
        pub T: G1,                // T = r*G
    }
    impl Message for Commit {
        const DIR: Direction = Direction::ProverToVerifier;
        const LABEL: &'static str = "Commit";
    }

    #[derive(Clone, Debug, FsrBindable)]
    #[bind(prefix = "Response")]
    pub struct Response {
        pub z: Scalar,            // z = r + e*x (mod p)
    }
    impl Message for Response {
        const DIR: Direction = Direction::ProverToVerifier;
        const LABEL: &'static str = "Response";
    }

    declare_round!(R1 = [Commit]);

    // ------------------- Setup interactive oracles -------------------
    let (p_chan, v_chan) = mem_duplex_pair();
    let prover_oracle   = InteractiveProverOracle::new(p_chan, b"schnorr-toy");
    let verifier_oracle = InteractiveVerifierOracle::new(v_chan, StdRng::from_entropy(), b"schnorr-toy");
    // let prover_oracle   = HashOracle::new(b"schnorr");
    // let verifier_oracle = HashOracle::new(b"schnorr");
    
    let tr_p: R1<_> = Transcript::new(prover_oracle);
    let tr_v: R1<_> = Transcript::new(verifier_oracle);

    // ------------------- Public params & witness -------------------
    let G = G1(7);                 // generator (toy)
    let x = Scalar(5);             // secret witness
    let Y = G.smul(x);             // public key
    let _public = Public { G, Y };

    // Prover nonce (demo: fixed; could be RNG). In real systems r must be secret & fresh.
    let r = Scalar(11);
    let T = G.smul(r);             // commitment

    // ------------------- Round 1: commit -------------------
    let commit = Commit { T };
    let tr_v = tr_v.absorb::<{ Commit::OBLIG_MASK }, _>(Commit::LABEL, &commit);
    let tr_p = tr_p.absorb::<{ Commit::OBLIG_MASK }, _>(Commit::LABEL, &commit);

    // ------------------- Challenge -------------------
    let (e_v, tr_v) = tr_v.challenge::<Scalar>("e")?;
    let (e_p, tr_p) = tr_p.challenge::<Scalar>("e")?;
    assert_eq!(e_v.0, e_p.0, "prover and verifier must see the same e");
    let e = e_v;

    // ------------------- Response -------------------
    let z = r.add(e.mul(x));       // z = r + e*x (mod p)
    let resp = Response { z };

    let tr_v = tr_v.absorb::<{ Response::OBLIG_MASK }, Response>(Response::LABEL, &resp);
    let _tr_p = tr_p.absorb::<{ Response::OBLIG_MASK }, Response>(Response::LABEL, &resp);

    // ------------------- Verify: z*G ?= T + e*Y -------------------
    let lhs = G.smul(z);               // z*G
    let rhs = T.add(Y.smul(e));        // T + e*Y
    let ok  = lhs.0 == rhs.0;

    println!("Interactive Schnorr (toy) demo:");
    println!("  G = {}", G.0);
    println!("  x = {}", x.0);
    println!("  Y = x*G = {}", Y.0);
    println!("  r = {}", r.0);
    println!("  T = r*G = {}", T.0);
    println!("  e = {}", e.0);
    println!("  z = r + e*x (mod p) = {}", z.0);
    println!("  Check: z*G = {}  vs  T + e*Y = {}  -> {}", lhs.0, rhs.0, ok);
    assert!(ok, "verification failed in toy group");
    Ok(())
}

#[cfg(not(feature = "interactive"))]
fn main() {
    eprintln!("Enable the `interactive` feature to run this example:\n  cargo +nightly run --features interactive --example schnorr_interactive");
}
