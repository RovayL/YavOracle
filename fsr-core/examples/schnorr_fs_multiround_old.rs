use fsr_core::*;
use fsr_proof_dsl::proof;

// --- toy group & scalar ---
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar(pub u64);

// Canonical codec
impl CanonicalEncode for G1 { fn encode(&self, out: &mut Vec<u8>) { out.extend_from_slice(&self.0.to_le_bytes()); } }
impl CanonicalDecode for G1 { fn decode(input: &mut &[u8]) -> Option<Self> { if input.len()<8 {return None}; let mut b=[0u8;8]; b.copy_from_slice(&input[..8]); *input=&input[8..]; Some(G1(u64::from_le_bytes(b))) } }
impl CanonicalEncode for Scalar { fn encode(&self, out: &mut Vec<u8>) { out.extend_from_slice(&self.0.to_le_bytes()); } }
impl CanonicalDecode for Scalar { fn decode(input: &mut &[u8]) -> Option<Self> { if input.len()<8 {return None}; let mut b=[0u8;8]; b.copy_from_slice(&input[..8]); *input=&input[8..]; Some(Scalar(u64::from_le_bytes(b))) } }
impl fsr_core::Challenge for Scalar {
    const BYTES: usize = 8;

    fn from_oracle_bytes(_label: &str, input: &[u8]) -> Self {
        let mut b = [0u8; 8];
        b.copy_from_slice(&input[..8]);
        Scalar(u64::from_le_bytes(b))
    }
}


// ops
impl G1 {
    pub fn add(self, o: G1) -> G1 { G1(self.0.wrapping_add(o.0)) }
    pub fn sub(self, o: G1) -> G1 { G1(self.0.wrapping_sub(o.0)) }
    pub fn smul(self, s: Scalar) -> G1 { G1(self.0.wrapping_mul(s.0)) }
}

// messages
#[derive(Clone, Debug, FsrBindable)]
#[bind(prefix="Commit")]
pub struct Commit { #[bind(ob=0)] pub t: G1 }

#[derive(Clone, Debug, FsrBindable)]
#[bind(prefix="Response")]
pub struct Response { #[bind(ob=1)] pub z: Scalar }

// message dirs/labels
impl Message for Commit { const DIR: Direction = Direction::ProverToVerifier; const LABEL: &'static str = "Commit"; }
impl Message for Response { const DIR: Direction = Direction::ProverToVerifier; const LABEL: &'static str = "Response"; }

// public input
#[derive(Clone, Debug)]
pub struct Public { pub g: G1, pub y: G1 }

// --- Multi-round Schnorr: two sequential rounds with labels "e1" and "e2" ---
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
      lhs == rhs
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
      lhs == rhs
    }
  }
}

fn le_u64(x: u64) -> [u8;8] { x.to_le_bytes() }

fn main() {
    // secret/public
    let x = Scalar(0x23);
    let g = G1(7);
    let y = g.smul(x);
    let public = Public { g, y };

    // Prover sim: two round Schnorr
    let r1 = Scalar(0x1111);
    let t1 = g.smul(r1);
    let mut h = HashOracle::new(b"schnorr-toy");
    // R1
    h.absorb_bytes(Commit::LABEL_t, &le_u64(t1.0));
    h.absorb_bytes(Commit::MSG_LABEL, &[]);
    let e1: Scalar = h.challenge("e1");
    let z1 = Scalar(r1.0.wrapping_add(e1.0.wrapping_mul(x.0)));

    // R2
    let r2 = Scalar(0x2222);
    let t2 = g.smul(r2);
    h.absorb_bytes(Commit::LABEL_t, &le_u64(t2.0));
    h.absorb_bytes(Commit::MSG_LABEL, &[]);
    let e2: Scalar = h.challenge("e2");
    let z2 = Scalar(r2.0.wrapping_add(e2.0.wrapping_mul(x.0)));

    // record the transcript events in order
    let mut events = Vec::new();
    events.push(RecEvent::Absorb { label: Commit::LABEL_t, bytes: le_u64(t1.0).to_vec() });
    events.push(RecEvent::Absorb { label: Commit::MSG_LABEL, bytes: Vec::new() });
    // note: challenges are recorded by the oracle runtime; for FS we also list them here:
    // (if you already captured from a RecorderOracle, reuse that)
    let mut tmp = Vec::new(); <Scalar as CanonicalEncode>::encode(&e1, &mut tmp);
    events.push(RecEvent::Challenge { label: "e1", bytes: tmp });
    let mut tmp = Vec::new(); <Scalar as CanonicalEncode>::encode(&z1, &mut tmp);
    events.push(RecEvent::Absorb { label: Response::LABEL_z, bytes: tmp });

    events.push(RecEvent::Absorb { label: Commit::LABEL_t, bytes: le_u64(t2.0).to_vec() });
    events.push(RecEvent::Absorb { label: Commit::MSG_LABEL, bytes: Vec::new() });
    let mut tmp = Vec::new(); <Scalar as CanonicalEncode>::encode(&e2, &mut tmp);
    events.push(RecEvent::Challenge { label: "e2", bytes: tmp });
    let mut tmp = Vec::new(); <Scalar as CanonicalEncode>::encode(&z2, &mut tmp);
    events.push(RecEvent::Absorb { label: Response::LABEL_z, bytes: tmp });

    // Build proof from events and verify
    let proof = schnorr_two_prove(&events).expect("build multi-round proof");
    let bytes = proof.encode();

    assert!(schnorr_two_verify(&public, &proof));
    assert!(schnorr_two_verify_bytes(&public, &bytes));
    println!("multi-round proof bytes ({}): 0x{}", bytes.len(), hex::encode(bytes));

    // print the verifier source
    println!("--- Schnorr_two verifier ---\n{}\n", schnorr_two_verifier_source());
}
