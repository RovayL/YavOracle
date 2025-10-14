#![forbid(unsafe_code)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

// users can write #[derive(fsr_core::bind_derive::Bindable)]
pub use fsr_bind_derive::FsrBindable;

// ---------------- Canonical encoding & absorption ----------------

pub trait CanonicalEncode {
    fn encode(&self, out: &mut Vec<u8>);
}

pub trait CanonicalDecode: Sized {
    fn decode(input: &mut &[u8]) -> Option<Self>;
}

impl CanonicalEncode for u64 {
    fn encode(&self, out: &mut Vec<u8>) { out.extend_from_slice(&self.to_le_bytes()); }
}
impl CanonicalEncode for [u8] {
    fn encode(&self, out: &mut Vec<u8>) { out.extend_from_slice(self); }
}
impl CanonicalEncode for Vec<u8> {
    fn encode(&self, out: &mut Vec<u8>) { out.extend_from_slice(self); }
}

pub trait Absorb {
    fn absorb_bytes(&mut self, label: &'static str, bytes: &[u8]);
}

pub trait Challenge: Sized {
    fn from_oracle_bytes(domain_label: &str, input: &[u8]) -> Self;
    const BYTES: usize;
}

#[derive(Clone, Copy, Debug)]
pub struct U64Challenge(pub u64);
impl Challenge for U64Challenge {
    fn from_oracle_bytes(_label: &str, input: &[u8]) -> Self {
        use core::hash::{Hash, Hasher};
        let mut s = std::collections::hash_map::DefaultHasher::new();
        input.hash(&mut s);
        U64Challenge(s.finish())
    }
    const BYTES: usize = 32;
}

// ---------------- Oracle abstraction (FS or interactive) ----------------

pub trait Oracle: Absorb {
    fn challenge<C: Challenge + CanonicalEncode>(&mut self, label: &'static str) -> C;
}

pub struct HashOracle {
    buf: Vec<u8>,
    domain: &'static [u8],
}
impl HashOracle {
    pub fn new(domain: &'static [u8]) -> Self { Self { buf: Vec::new(), domain } }
}
impl Absorb for HashOracle {
    fn absorb_bytes(&mut self, label: &'static str, bytes: &[u8]) {
        self.buf.extend_from_slice(self.domain);
        self.buf.extend_from_slice(label.as_bytes());
        self.buf.extend_from_slice(bytes);
    }
}
impl Oracle for HashOracle {
    fn challenge<C: Challenge + CanonicalEncode>(&mut self, label: &'static str) -> C {
        let mut material = Vec::with_capacity(self.buf.len() + label.len() + self.domain.len());
        material.extend_from_slice(self.domain);
        material.extend_from_slice(label.as_bytes());
        material.extend_from_slice(&self.buf);
        C::from_oracle_bytes(label, &material)
    }
}


// ---- FS proof recording (works with HashOracle) ----

/// A single recorded transcript event (label + bytes) for FS proof emission.
#[derive(Clone, Debug)]
pub enum RecEvent {
    Absorb { label: &'static str, bytes: Vec<u8> },
    Challenge { label: &'static str, bytes: Vec<u8> },
}

/// Helper to allow for private data in transcript to be accessed for proof generation.
pub trait IntoEvents {
    fn into_events(self) -> Vec<RecEvent>;
}

/// Wraps an Absorb/Oracle and records the FS transcript timeline.
/// Typical use: `RecordingHashOracle::new(HashOracle::new(DST))`.
pub struct RecordingHashOracle<H = HashOracle> {
    inner: H,
    events: Vec<RecEvent>,
}

impl<H> RecordingHashOracle<H> {
    pub fn new(inner: H) -> Self { Self { inner, events: Vec::new() } }
    pub fn events(&self) -> &[RecEvent] { &self.events }
    pub fn into_parts(self) -> (H, Vec<RecEvent>) { (self.inner, self.events) }

    /// Find the latest absorbed bytes for a label (useful for proof emission).
    pub fn find_absorb(&self, label: &str) -> Option<&[u8]> {
        self.events.iter().rev().find_map(|e| match e {
            RecEvent::Absorb { label: l, bytes } if *l == label => Some(bytes.as_slice()),
            _ => None,
        })
    }
    /// Find the latest challenge bytes for a label.
    pub fn find_challenge(&self, label: &str) -> Option<&[u8]> {
        self.events.iter().rev().find_map(|e| match e {
            RecEvent::Challenge { label: l, bytes } if *l == label => Some(bytes.as_slice()),
            _ => None,
        })
    }
}

impl<H: Absorb> Absorb for RecordingHashOracle<H> {
    fn absorb_bytes(&mut self, label: &'static str, bytes: &[u8]) {
        self.inner.absorb_bytes(label, bytes);
        self.events.push(RecEvent::Absorb { label, bytes: bytes.to_vec() });
    }
}

impl<H: Oracle> Oracle for RecordingHashOracle<H> {
    fn challenge<C: Challenge>(&mut self, label: &'static str) -> C
    where
        C: Challenge + CanonicalEncode, // we need to encode C to record it
    {
        let c = self.inner.challenge::<C>(label);
        let mut v = Vec::new();
        c.encode(&mut v);
        self.events.push(RecEvent::Challenge { label, bytes: v });
        c
    }
}

// Small quality-of-life helper so you can pull the oracle out after proving.
impl<const PENDING: u128, O: Oracle> Transcript<PENDING, O> {
    pub fn into_oracle(self) -> O { self.oracle }
}



// ---------------- Messages & obligations (bitmask) ----------------

#[derive(Clone, Copy, Debug)]
pub enum Direction { ProverToVerifier, VerifierToProver }

pub trait Bindable {
    /// Bitmask of obligations this message discharges in the *current* boundary.
    const OBLIG_MASK: u128;
    fn bind<A: Absorb>(&self, a: &mut A);
}

pub trait Message: Bindable {
    const DIR: Direction;
    const LABEL: &'static str;
}

// ---------------- Typed transcript over a pending bitmask ----------------

pub struct Transcript<const PENDING: u128, O: Oracle> {
    oracle: O,
}

impl<const PENDING: u128, O: Oracle> Transcript<PENDING, O> {
    pub fn new(oracle: O) -> Self { Self { oracle } }

    /// Absorb a message and *clear* its obligations: PENDING' = PENDING & !MASK
    pub fn absorb<const MASK: u128, M: Bindable>(
        mut self,
        label: &'static str,
        m: &M,
    ) -> Transcript<{ PENDING & !MASK }, O> {
        m.bind(&mut self.oracle);
        self.oracle.absorb_bytes(label, &[]);
        Transcript { oracle: self.oracle }
    }

    pub fn oracle_mut(&mut self) -> &mut O { &mut self.oracle }
}

// Challenge is only available when PENDING == 0
impl<O: Oracle> Transcript<0, O> {
    pub fn challenge<C: Challenge + CanonicalEncode>(mut self, label: &'static str) -> (C, Self) {
        let c = self.oracle.challenge::<C>(label);
        (c, self)
    }
}

// Helper
pub fn start_round<const PENDING: u128, O: Oracle>(oracle: O) -> Transcript<PENDING, O> {
    Transcript::<PENDING, O>::new(oracle)
}

// More Helpers
impl<const PENDING: u128, O: Oracle> Transcript<PENDING, O> {
    pub fn absorb_bytes(mut self, label: &'static str, bytes: &[u8]) -> Self {
        self.oracle.absorb_bytes(label, bytes);
        self
    }

    pub fn retag<const NEW: u128>(self) -> Transcript<NEW, O> {
        Transcript { oracle: self.oracle }
    }
}

impl<const PENDING: u128, O: Oracle> Transcript<PENDING, O> {
    /// Move out the inner oracle (rarely needed; prefer `into_events`).
    pub fn into_inner(self) -> O {
        self.oracle
    }

    /// Drain recorded events if the oracle supports it.
    pub fn into_events(self) -> Vec<RecEvent>
    where
        O: IntoEvents,
    {
        self.oracle.into_events()
    }
}



// ----------------- Macros -----------------

#[macro_export]
macro_rules! round_mask {
    // Use commas: round_mask!(A, B, C)
    ( $( $e:expr ),+ $(,)? ) => { 0u128 $(| ($e as u128))+ };
}

#[macro_export]
macro_rules! declare_round {
    // Usage: declare_round!(R1 = [Commit, OtherMsg]);
    ($name:ident = [$($msg_ty:ty),+ $(,)?]) => {
        pub type $name<O> = $crate::Transcript<
            { 0u128 $(| <$msg_ty as $crate::Bindable>::OBLIG_MASK)+ },
            O
        >;
    };
}


// ======== Interactive runtime (feature-gated) ========
#[cfg(feature = "interactive")]
mod interactive_runtime {
    use super::{Absorb, Challenge, Oracle};

    // --- Transport abstraction ---
    pub trait Channel: Send + 'static {
        fn send(&mut self, bytes: Vec<u8>);
        fn recv(&mut self) -> Option<Vec<u8>>;
    }

    // In-memory duplex channel (single-process demo; thread-safe)
    pub struct MemDuplex {
        tx: std::sync::mpsc::Sender<Vec<u8>>,
        rx: std::sync::mpsc::Receiver<Vec<u8>>,
    }
    impl Channel for MemDuplex {
        fn send(&mut self, bytes: Vec<u8>) { let _ = self.tx.send(bytes); }
        fn recv(&mut self) -> Option<Vec<u8>> { self.rx.recv().ok() }
    }
    /// Create a connected (prover, verifier) channel pair.
    pub fn mem_duplex_pair() -> (MemDuplex, MemDuplex) {
        let (tx_p, rx_v) = std::sync::mpsc::channel::<Vec<u8>>();
        let (tx_v, rx_p) = std::sync::mpsc::channel::<Vec<u8>>();
        let prover = MemDuplex { tx: tx_p, rx: rx_p };
        let verifier = MemDuplex { tx: tx_v, rx: rx_v };
        (prover, verifier)
    }

    // --- Simple length-prefixed frames for challenges ---
    // Frame: [ tag: u8 ][ lab_len: u16 LE ][ label bytes ][ pay_len: u16 LE ][ payload bytes ]
    const TAG_CHALLENGE: u8 = 1;

    fn encode_frame(label: &str, payload: &[u8]) -> Vec<u8> {
        let lb = label.as_bytes();
        let mut v = Vec::with_capacity(1 + 2 + lb.len() + 2 + payload.len());
        v.push(TAG_CHALLENGE);
        v.extend_from_slice(&(lb.len() as u16).to_le_bytes());
        v.extend_from_slice(lb);
        v.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        v.extend_from_slice(payload);
        v
    }
    fn decode_frame(bytes: &[u8]) -> Option<(&str, &[u8])> {
        if bytes.len() < 1 + 2 { return None; }
        if bytes[0] != TAG_CHALLENGE { return None; }
        let mut i = 1;
        let ll = u16::from_le_bytes([bytes[i], bytes[i+1]]) as usize; i += 2;
        if bytes.len() < i + ll + 2 { return None; }
        let label = std::str::from_utf8(&bytes[i..i+ll]).ok()?; i += ll;
        let pl = u16::from_le_bytes([bytes[i], bytes[i+1]]) as usize; i += 2;
        if bytes.len() < i + pl { return None; }
        Some((label, &bytes[i..i+pl]))
    }

    // --- Verifier-side oracle: samples and sends challenges ---
    #[cfg(feature = "interactive")]
    pub struct InteractiveVerifierOracle<C, R> {
        chan: C,
        rng: R,
        domain: &'static [u8],
        draw_ctr: u64,
    }

    #[cfg(feature = "interactive")]
    impl<C: Channel, R: rand::RngCore> InteractiveVerifierOracle<C, R> {
        pub fn new(chan: C, rng: R, domain: &'static [u8]) -> Self {
            Self { chan, rng, domain, draw_ctr: 0 }
        }
    }

    #[cfg(feature = "interactive")]
    impl<C: Channel, R: rand::RngCore> Absorb for InteractiveVerifierOracle<C, R> {
        fn absorb_bytes(&mut self, _label: &'static str, _bytes: &[u8]) {
            // Interactive verifier doesn't need to absorb bytes to *compute* challenges;
            // it samples randomness independently. We keep hook for logging if desired.
        }
    }

    #[cfg(feature = "interactive")]
    impl<C: Channel, R: rand::RngCore> Oracle for InteractiveVerifierOracle<C, R> {
        fn challenge<T: Challenge + CanonicalEncode>(&mut self, label: &'static str) -> T {
            // Produce pseudorandom bytes (uniform) and send them to prover.
            let mut buf = vec![0u8; T::BYTES];
            // self.rng.fill_bytes(&mut buf);
            rand::RngCore::fill_bytes(&mut self.rng, &mut buf);
            // Domain separation (optional): prepend domain + counter before sending.
            // Here we just send raw bytes; both sides reduce via T::from_oracle_bytes(label, bytes).
            let frame = encode_frame(label, &buf);
            self.chan.send(frame);
            self.draw_ctr = self.draw_ctr.wrapping_add(1);
            T::from_oracle_bytes(label, &buf)
        }
    }

    // --- Prover-side oracle: receives challenges from verifier ---
    #[cfg(feature = "interactive")]
    pub struct InteractiveProverOracle<C> {
        chan: C,
        domain: &'static [u8],
        recv_ctr: u64,
    }

    #[cfg(feature = "interactive")]
    impl<C: Channel> InteractiveProverOracle<C> {
        pub fn new(chan: C, domain: &'static [u8]) -> Self {
            Self { chan, domain, recv_ctr: 0 }
        }
    }

    #[cfg(feature = "interactive")]
    impl<C: Channel> Absorb for InteractiveProverOracle<C> {
        fn absorb_bytes(&mut self, _label: &'static str, _bytes: &[u8]) {
            // Prover-side absorb is local (the *protocol* code already sends messages over the app channel).
        }
    }

    #[cfg(feature = "interactive")]
    impl<C: Channel> Oracle for InteractiveProverOracle<C> {
        fn challenge<T: Challenge + CanonicalEncode>(&mut self, expect_label: &'static str) -> T {
            // Block until a challenge frame arrives; check label; derive T.
            let bytes = self.chan.recv().expect("interactive: channel closed");
            let (label, payload) = decode_frame(&bytes).expect("interactive: bad frame");
            assert_eq!(label, expect_label, "interactive: label mismatch");
            self.recv_ctr = self.recv_ctr.wrapping_add(1);
            T::from_oracle_bytes(label, payload)
        }
    }
}

// Publicly re-export when the feature is on.
#[cfg(feature = "interactive")]
pub use interactive_runtime::*;

