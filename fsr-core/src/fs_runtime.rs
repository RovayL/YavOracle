//! Fiat–Shamir runtime that shares the TranscriptRuntime base.

use crate::runtime::{TranscriptRuntime, RandomOracle};

pub struct FSOracle<RO: RandomOracle> {
    ro: RO,
    // internal transcript buffer or state accumulator
    buf: Vec<u8>,
}

impl<RO: RandomOracle> FSOracle<RO> {
    pub fn new(ro: RO) -> Self {
        Self { ro, buf: Vec::new() }
    }

    /// Derive a challenge from the current transcript state (+ optional extra).
    /// `out_len` is the number of bytes you want (your DSL/codec will parse it).
    pub fn derive_challenge(&mut self, label: &'static str, extra: &[u8], out_len: usize) -> Vec<u8> {
        let mut m = Vec::with_capacity(self.buf.len() + 32 + extra.len());
        m.extend_from_slice(b"mode:FS|");
        m.extend_from_slice(&self.buf);
        if !extra.is_empty() {
            m.extend_from_slice(b"|extra|");
            m.extend_from_slice(extra);
        }
        let h = self.ro.H_full(label, &m);
        h[..out_len.min(h.len())].to_vec()
    }

    /// Optional: reset between proofs.
    pub fn reset(&mut self) { self.buf.clear(); }
}

impl<RO: RandomOracle> TranscriptRuntime for FSOracle<RO> {
    fn absorb(&mut self, label: &'static str, bytes: &[u8]) {
        // Domain-separated monotone absorption.
        self.buf.extend_from_slice(b"|label|");
        self.buf.extend_from_slice(label.as_bytes());
        self.buf.extend_from_slice(b"|data|");
        self.buf.extend_from_slice(bytes);
    }
}
