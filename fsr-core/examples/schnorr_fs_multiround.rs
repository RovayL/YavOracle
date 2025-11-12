use fsr_core::*;
use fsr_proof_dsl::proof;

// ===== toy group & scalar (same as the single-round) =====
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1(pub u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar(pub u64);

// Canonical codec
impl CanonicalEncode for G1 { fn encode(&self, out: &mut Vec<u8>) { out.extend_from_slice(&self.0.to_le_bytes()); } }
impl CanonicalDecode for G1 {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        if input.len() < 8 { return None; }
        let mut b=[0u8;8]; b.copy_from_slice(&input[..8]); *input=&input[8..]; Some(G1(u64::from_le_bytes(b)))
    }
}
impl CanonicalEncode for Scalar { fn encode(&self, out: &mut Vec<u8>) { out.extend_from_slice(&self.0.to_le_bytes()); } }
impl CanonicalDecode for Scalar {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        if input.len() < 8 { return None; }
        let mut b=[0u8;8]; b.copy_from_slice(&input[..8]); *input=&input[8..]; Some(Scalar(u64::from_le_bytes(b)))
    }
}
// Challenge
impl fsr_core::Challenge for Scalar {
    const BYTES: usize = 8;
    fn from_oracle_bytes(_label: &str, input: &[u8]) -> Self {
        let mut b = [0u8; 8]; b.copy_from_slice(&input[..8]); Scalar(u64::from_le_bytes(b))
    }
}

// group ops
impl G1 {
    pub fn add(self, o: G1) -> G1 { G1(self.0.wrapping_add(o.0)) }
    pub fn sub(self, o: G1) -> G1 { G1(self.0.wrapping_sub(o.0)) }
    pub fn smul(self, s: Scalar) -> G1 { G1(self.0.wrapping_mul(s.0)) }
}

// ===== messages =====
#[derive(Clone, Debug, FsrBindable)]
#[bind(prefix="Commit")]
pub struct Commit { #[bind(ob=0)] pub t: G1 }

#[derive(Clone, Debug, FsrBindable)]
#[bind(prefix="Response")]
pub struct Response { #[bind(ob=1)] pub z: Scalar }

impl Message for Commit   { const DIR: Direction = Direction::ProverToVerifier; const LABEL: &'static str = "Commit"; }
impl Message for Response { const DIR: Direction = Direction::ProverToVerifier; const LABEL: &'static str = "Response"; }

// public input
#[derive(Clone, Debug)]
pub struct Public { pub g: G1, pub y: G1 }

// ===== A small RecordingOracle that wraps HashOracle and captures RecEvent =====
struct RecordingOracle<H> {
    inner: H,
    events: Vec<RecEvent>,
}
impl RecordingOracle<HashOracle> {
    fn new(domain: &'static [u8]) -> Self {
        Self { inner: HashOracle::new(domain), events: Vec::new() }
    }
    fn into_events(self) -> Vec<RecEvent> { self.events }
}

impl fsr_core::IntoEvents for RecordingOracle<HashOracle> {
    fn into_events(self) -> Vec<RecEvent> { self.events }
}

// Implement Absorb separately
impl fsr_core::Absorb for RecordingOracle<HashOracle> {
    fn absorb_bytes(&mut self, label: &'static str, bytes: &[u8]) {
        // record
        self.events.push(RecEvent::Absorb { label, bytes: bytes.to_vec() });
        // delegate
        self.inner.absorb_bytes(label, bytes);
    }
}

// Implement Oracle (challenge) and also record the challenge bytes
impl fsr_core::Oracle for RecordingOracle<HashOracle> {
    fn challenge<C: Challenge + CanonicalEncode>(&mut self, label: &'static str) -> fsr_core::Result<C> {
        let c: C = self.inner.challenge(label)?;
        let mut buf = Vec::new(); <C as CanonicalEncode>::encode(&c, &mut buf);
        self.events.push(RecEvent::Challenge { label, bytes: buf });
        Ok(c)
    }
}


// For round typing ergonomics
macro_rules! declare_round {
    ($Rn:ident = [$($M:ty),* $(,)?]) => {
        pub type $Rn<O> = fsr_core::Transcript<{ 0 $(| <$M as fsr_core::Bindable>::OBLIG_MASK)* }, O>;
    }
}
declare_round!(R1 = [Commit]);
declare_round!(R2 = [Commit]);

fn enc<T: CanonicalEncode>(x: &T) -> Vec<u8> { let mut v=Vec::new(); x.encode(&mut v); v }

// ===== Multi-round Schnorr proof (two sequential rounds) =====
proof! {
  name: SchnorrTwo;
  domain: "schnorr-toy";
  public: Public;

  header { version: 1; schema: "schnorr-2"; domain: false; }

  round R1 {
    fields {
      t1: G1     <= absorb   Commit::LABEL_t;
      e1: Scalar <= challenge "e1";
      z1: Scalar <= absorb   Response::LABEL_z;
    }
    replay {
      bind Commit::LABEL_t <- t1;
      bind Commit::MSG_LABEL;
    }
    check {
      let lhs = pub_in.g.smul(z1);
      let rhs = t1.add(pub_in.y.smul(e1));
      Ok(lhs == rhs)
    }
  }

  round R2 {
    fields {
      t2: G1     <= absorb   Commit::LABEL_t;
      e2: Scalar <= challenge "e2";
      z2: Scalar <= absorb   Response::LABEL_z;
    }
    replay {
      bind Commit::LABEL_t <- t2;
      bind Commit::MSG_LABEL;
    }
    check {
      let lhs = pub_in.g.smul(z2);
      let rhs = t2.add(pub_in.y.smul(e2));
      Ok(lhs == rhs)
    }
  }
}

fn main() -> fsr_core::Result<()> {
    // secret/public
    let x = Scalar(0x23);
    let g = G1(7);
    let y = g.smul(x);
    let public = Public { g, y };

    // Prover randomness
    let r1 = Scalar(0x1111);
    let r2 = Scalar(0x2222);

    // Start transcript over a recording FS oracle
    let tr0: R1<_> = Transcript::new(RecordingOracle::new(b"schnorr-toy"));

    // ---- Round 1 ----
    let t1 = g.smul(r1);
    let commit1 = Commit { t: t1 };

    // absorb commit (typed bind) + shape label via absorb_bytes
    let tr1 = tr0
        .absorb::<{ Commit::OBLIG_MASK }, _>(Commit::LABEL, &commit1)
        .absorb_bytes(Commit::MSG_LABEL, &[]);

    // challenge and response
    let (e1, tr1c) = tr1.challenge::<Scalar>("e1")?;
    let z1 = Scalar(r1.0.wrapping_add(e1.0.wrapping_mul(x.0)));

    // absorb response
    let tr1done = tr1c.absorb::<{ Response::OBLIG_MASK }, _>(Response::LABEL, &Response { z: z1 });

    // ---- Round 2 ----
    let tr2start: R2<_> = tr1done.retag::<{ Commit::OBLIG_MASK }>(); // start next round obligations

    let t2 = g.smul(r2);
    let commit2 = Commit { t: t2 };

    let tr2 = tr2start
        .absorb::<{ Commit::OBLIG_MASK }, _>(Commit::LABEL, &commit2)
        .absorb_bytes(Commit::MSG_LABEL, &[]);

    let (e2, tr2c) = tr2.challenge::<Scalar>("e2")?;
    let z2 = Scalar(r2.0.wrapping_add(e2.0.wrapping_mul(x.0)));
    let tr_done = tr2c.absorb::<{ Response::OBLIG_MASK }, _>(Response::LABEL, &Response { z: z2 });

    // Extract recorded events from the oracle
    let events = tr_done.into_events();

    // Build proof from events and verify
    let proof = schnorr_two_prove(&events).expect("build multi-round proof");
    let bytes = proof.encode();

    assert!(schnorr_two_verify(&public, &proof));
    assert!(schnorr_two_verify_bytes(&public, &bytes));

    // Output the proof bytes as well as the verifier code
    println!("multi-round proof bytes ({}): 0x{}", bytes.len(), hex::encode(bytes));
    println!("--- SchnorrTwo verifier ---\n{}\n", schnorr_two_verifier_source());
    Ok(())
}
