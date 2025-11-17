//! Fischlin's transform runtime (prover & predicate helper) — optimized

use core::marker::PhantomData;
use crate::runtime::{TranscriptRuntime, RandomOracle, trunc_b_to_u64};
use crate::{Result, ProveError, TranscriptOracle};

#[derive(Clone, Copy, Debug)]
pub struct FischlinParams {
    pub rho: u16,
    pub b: u8,
    pub t: u8,
    pub kappa_c: u16,
    /// n in "n-special soundness" (default 2)
    pub n_special: u16,
}
impl FischlinParams {
    pub fn new(rho: u16, b: u8) -> Self {
        let t = if rho <= 64 { b.saturating_add(5) } else { b.saturating_add(6) };
        Self { rho, b, t, kappa_c: 128, n_special: 2 }
    }
    pub fn with_t(mut self, t: u8) -> Self { self.t = t; self }
    pub fn with_kappa(mut self, k: u16) -> Self { self.kappa_c = k; self }
    /// Set n in n-special soundness (n >= 2). When n > 2, the effective
    /// security per repetition loses roughly ceil(log2(n-1)) bits.
    pub fn with_n_special(mut self, n: u16) -> Self { self.n_special = n.max(2); self }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { Init, CollectingFirstMsgs, Sealed }

pub struct FischlinOracle<RO: RandomOracle> {
    params: FischlinParams,
    ro: RO,
    phase: Phase,

    // coverage/DS transcript (mode-agnostic)
    transcript_buf: Vec<u8>,

    // bound inputs for common_h
    statement_bytes: Vec<u8>,
    sid_bytes: Vec<u8>,
    m_vec: Vec<Vec<u8>>,

    // common hash H_full(mode|x|m⃗|sid)
    common_h: Option<Vec<u8>>,

    // reusable scratch buffer to minimize per-try allocations
    scratch: Vec<u8>,

    _pd: PhantomData<()>,
}

impl<RO: RandomOracle> FischlinOracle<RO> {
    pub fn new(ro: RO, params: FischlinParams) -> Self {
        Self {
            params, ro, phase: Phase::Init,
            transcript_buf: Vec::new(),
            statement_bytes: Vec::new(), sid_bytes: Vec::new(),
            m_vec: Vec::new(), common_h: None,
            scratch: Vec::new(),
            _pd: PhantomData,
        }
    }

    pub fn begin(&mut self, statement: &[u8], sid: &[u8]) {
        self.phase = Phase::CollectingFirstMsgs;
        self.statement_bytes.clear();
        self.statement_bytes.extend_from_slice(statement);
        self.sid_bytes.clear();
        self.sid_bytes.extend_from_slice(sid);
        self.m_vec.clear();
        self.common_h = None;
        self.scratch.clear();

        self.absorb("mode", b"FISCHLIN");
        self.absorb("x", statement);
        self.absorb("sid", sid);
    }

    pub fn push_first_message(&mut self, m_i: &[u8]) -> Result<()> {
        if !matches!(self.phase, Phase::CollectingFirstMsgs) {
            return Err(ProveError::Malformed("fischlin: push_first_message before begin"));
        }
        self.m_vec.push(m_i.to_vec());
        self.absorb("m_i", m_i);
        Ok(())
    }

    pub fn seal_first_messages(&mut self) -> Result<()> {
        if !matches!(self.phase, Phase::CollectingFirstMsgs) {
            return Err(ProveError::Malformed("fischlin: seal called before begin"));
        }
        if self.m_vec.len() as u16 != self.params.rho {
            return Err(ProveError::Malformed("fischlin: m_vec len != rho"));
        }
        // n-special soundness parameter check: rho * (b - ceil_log2(n-1)) >= kappa_c
        let loss = ceil_log2_n_minus_1(self.params.n_special as u32);
        if (self.params.b as u32) < loss {
            return Err(ProveError::UnsoundParams("fischlin: b too small for n-special soundness"));
        }
        let eff_b = (self.params.b as u32) - loss;
        let lhs = (self.params.rho as u32) * eff_b;
        if lhs < self.params.kappa_c as u32 {
            return Err(ProveError::UnsoundParams("fischlin: rho*(b - log2(n-1)) < kappa_c"));
        }

        let mut buf = Vec::new();
        buf.extend_from_slice(b"mode:FISCHLIN|x|"); buf.extend_from_slice(&self.statement_bytes);
        buf.extend_from_slice(b"|m_vec|");
        for (i, m) in self.m_vec.iter().enumerate() {
            buf.extend_from_slice(b"i="); buf.extend_from_slice(&(i as u32).to_le_bytes());
            buf.extend_from_slice(b":m="); buf.extend_from_slice(m); buf.push(0xff);
        }
        buf.extend_from_slice(b"|sid|"); buf.extend_from_slice(&self.sid_bytes);

        let ch = self.ro.H_full("fischlin.common", &buf);
        self.common_h = Some(ch);
        self.phase = Phase::Sealed;
        Ok(())
    }

    /// NEW: Build the per-repetition predicate prefix once: "pred|common_h|i=<i>"
    pub fn predicate_prefix(&self, i: u32) -> Result<Vec<u8>> {
        let common = self
            .common_h
            .as_ref()
            .ok_or(ProveError::Malformed("fischlin: common_h missing"))?
            .clone();
        let mut prefix = Vec::with_capacity(common.len() + 16);
        prefix.extend_from_slice(b"pred|");
        prefix.extend_from_slice(&common);
        prefix.extend_from_slice(b"|i=");
        prefix.extend_from_slice(&i.to_le_bytes());
        Ok(prefix)
    }

    /// NEW: Predicate check using a precomputed prefix; only (e,z) vary.
    pub fn hb_zero_from_prefix(&mut self, prefix: &[u8], e: &[u8], z: &[u8]) -> bool {
        self.scratch.clear();
        self.scratch.extend_from_slice(prefix);
        self.scratch.extend_from_slice(b"|e="); self.scratch.extend_from_slice(e);
        self.scratch.extend_from_slice(b"|z="); self.scratch.extend_from_slice(z);
        let hb = self.ro.H("fischlin.H_b", &self.scratch);
        trunc_b_to_u64(&hb, self.params.b) == 0
    }

    /// Backwards-compatible predicate (now implemented via prefix)
    fn hb_predicate_zero(&mut self, common_h: &[u8], i: u32, e: &[u8], z: &[u8]) -> bool {
        let mut prefix = Vec::with_capacity(common_h.len() + 16);
        prefix.extend_from_slice(b"pred|");
        prefix.extend_from_slice(common_h);
        prefix.extend_from_slice(b"|i=");
        prefix.extend_from_slice(&i.to_le_bytes());
        self.hb_zero_from_prefix(&prefix, e, z)
    }

    /// EXISTING: search using gen_z(e) — kept for compatibility.
    pub fn search_round<F>(&mut self, i: u32, mut gen_z: F) -> Result<(Vec<u8>, Vec<u8>)>
    where
        F: FnMut(&[u8]) -> Vec<u8>,
    {
        if !matches!(self.phase, Phase::Sealed) {
            return Err(ProveError::Malformed("fischlin: seal_first_messages missing"));
        }
        let common = self
            .common_h
            .as_ref()
            .ok_or(ProveError::Malformed("fischlin: common_h missing"))?
            .clone();
        let t = self.params.t.min(56);
        let bound = 1u64.checked_shl(t as u32).unwrap_or(0);

        // Precompute prefix once
        let mut prefix = Vec::with_capacity(common.len() + 16);
        prefix.extend_from_slice(b"pred|");
        prefix.extend_from_slice(&common);
        prefix.extend_from_slice(b"|i=");
        prefix.extend_from_slice(&i.to_le_bytes());

        // Reusable e buffer
        let mut e_bytes = vec![0u8; ((t as usize + 7) / 8).max(1)];

        for e_val in 0..bound {
            write_e_bytes(e_val, &mut e_bytes);
            let z_bytes = gen_z(&e_bytes);

            if self.hb_zero_from_prefix(&prefix, &e_bytes, &z_bytes) {
                self.absorb("e_i", &e_bytes);
                self.absorb("z_i", &z_bytes);
                return Ok((e_bytes, z_bytes));
            }
        }
        Err(ProveError::RetryNeeded)
    }

    /// NEW: search using a z-stream (z_0 = r, z_{e+1}= z_e + w), i.e., **one modular add per try**.
    pub fn search_round_stream<F>(&mut self, i: u32, mut next_z: F) -> Result<(Vec<u8>, Vec<u8>)>
    where
        F: FnMut() -> Vec<u8>,
    {
        if !matches!(self.phase, Phase::Sealed) {
            return Err(ProveError::Malformed("fischlin: seal_first_messages missing"));
        }
        let common = self
            .common_h
            .as_ref()
            .ok_or(ProveError::Malformed("fischlin: common_h missing"))?
            .clone();
        let t = self.params.t.min(56);
        let bound = 1u64.checked_shl(t as u32).unwrap_or(0);

        // Precompute prefix once
        let mut prefix = Vec::with_capacity(common.len() + 16);
        prefix.extend_from_slice(b"pred|");
        prefix.extend_from_slice(&common);
        prefix.extend_from_slice(b"|i=");
        prefix.extend_from_slice(&i.to_le_bytes());

        // Reusable e buffer
        let mut e_bytes = vec![0u8; ((t as usize + 7) / 8).max(1)];

        for e_val in 0..bound {
            write_e_bytes(e_val, &mut e_bytes);

            // **One-add** per step happens inside `next_z()`, which updates z_running += w.
            let z_bytes = next_z();

            if self.hb_zero_from_prefix(&prefix, &e_bytes, &z_bytes) {
                self.absorb("e_i", &e_bytes);
                self.absorb("z_i", &z_bytes);
                return Ok((e_bytes, z_bytes));
            }
        }
        Err(ProveError::RetryNeeded)
    }

    pub fn verify_predicate(&mut self, i: u32, m_i: &[u8], e_i: &[u8], z_i: &[u8]) -> bool {
        self.absorb("m_i", m_i);
        self.absorb("e_i", e_i);
        self.absorb("z_i", z_i);

        let common: Vec<u8> = match &self.common_h {
            Some(h) => h.clone(),
            None => return false,
        };
        let mut prefix = Vec::with_capacity(common.len() + 16);
        prefix.extend_from_slice(b"pred|");
        prefix.extend_from_slice(&common);
        prefix.extend_from_slice(b"|i=");
        prefix.extend_from_slice(&(i as u32).to_le_bytes());

        self.hb_zero_from_prefix(&prefix, e_i, z_i)
    }

    pub fn verifier_finalize_common_h(&mut self) -> Result<()> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"mode:FISCHLIN|x|"); buf.extend_from_slice(&self.statement_bytes);
        buf.extend_from_slice(b"|m_vec|");
        for (i, m) in self.m_vec.iter().enumerate() {
            buf.extend_from_slice(b"i="); buf.extend_from_slice(&(i as u32).to_le_bytes());
            buf.extend_from_slice(b":m="); buf.extend_from_slice(m); buf.push(0xff);
        }
        buf.extend_from_slice(b"|sid|"); buf.extend_from_slice(&self.sid_bytes);
        self.common_h = Some(self.ro.H_full("fischlin.common", &buf));
        Ok(())
    }
    pub fn begin_verifier(&mut self, statement: &[u8], sid: &[u8]) {
        self.phase = Phase::CollectingFirstMsgs;
        self.statement_bytes = statement.to_vec();
        self.sid_bytes = sid.to_vec();
        self.m_vec.clear();
        self.common_h = None;
        self.scratch.clear();
        self.absorb("mode", b"FISCHLIN");
        self.absorb("x", statement);
        self.absorb("sid", sid);
    }
    pub fn push_first_message_verifier(&mut self, m_i: &[u8]) -> Result<()> {
        if !matches!(self.phase, Phase::CollectingFirstMsgs) {
            return Err(ProveError::Malformed("fischlin: verifier push_first_message before begin"));
        }
        self.m_vec.push(m_i.to_vec());
        self.absorb("m_i", m_i);
        Ok(())
    }
}

impl<RO: RandomOracle> TranscriptRuntime for FischlinOracle<RO> {
    fn absorb(&mut self, label: &'static str, bytes: &[u8]) {
        self.transcript_buf.extend_from_slice(b"|label|");
        self.transcript_buf.extend_from_slice(label.as_bytes());
        self.transcript_buf.extend_from_slice(b"|data|");
        self.transcript_buf.extend_from_slice(bytes);
    }
}

#[inline]
fn encode_e(e_val: u64, t: u8) -> Vec<u8> {
    let blen = ((t as usize + 7) / 8).max(1);
    e_val.to_le_bytes()[..blen].to_vec()
}

// write e_val into an existing little-endian buffer (avoids alloc)
#[inline]
fn write_e_bytes(e_val: u64, dst: &mut [u8]) {
    let bytes = e_val.to_le_bytes();
    let n = dst.len().min(bytes.len());
    dst[..n].copy_from_slice(&bytes[..n]);
}

#[inline]
fn ceil_log2_u32(x: u32) -> u32 {
    if x <= 1 { return 0; }
    32u32.saturating_sub((x - 1).leading_zeros())
}

#[inline]
fn ceil_log2_n_minus_1(n: u32) -> u32 {
    if n <= 2 { return 0; }
    ceil_log2_u32(n - 1)
}


/// Generic retry/search harness used by the macro expansion in Fischlin mode.
/// - `try_once` should do exactly one attempt (one accepting-transcript search step).
/// - If `try_once` returns `Err(ProveError::RetryNeeded)`, we keep looping.
/// - Any other error aborts immediately.
/// - `on_stream` (optional) lets the caller "add one more thing per try" before `try_once`.
pub fn search_with_retry<O, TryOnce, Hook, R>(
    mut oracle: O,
    retries: usize,
    mut try_once: TryOnce,
    mut on_stream: Option<Hook>,
) -> Result<R>
where
    O: TranscriptOracle,
    TryOnce: FnMut(&mut O, usize) -> Result<R>,
    Hook: FnMut(&mut O, usize) -> Result<()>,
{
    let max = retries.max(1);
    for i in 0..max {
        if let Some(h) = on_stream.as_mut() {
            h(&mut oracle, i)?;
        }
        match try_once(&mut oracle, i) {
            Ok(r) => return Ok(r),
            Err(ProveError::RetryNeeded) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(ProveError::RetryNeeded)
}
