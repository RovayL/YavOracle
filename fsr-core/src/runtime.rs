//! Shared transcript runtime surface.

/// Minimal, mode-agnostic runtime surface used by the DSL/derive.
/// - `absorb` is your taint/coverage sink with domain separation.
/// - FS and Fischlin expose *extra* methods (e.g., derive_challenge vs seal/search) on their types.
pub trait TranscriptRuntime {
    /// Absorb bytes under a domain-separated label (monotone absorption).
    fn absorb(&mut self, label: &'static str, bytes: &[u8]);
}

/// A pluggable Random Oracle facade (FS & Fischlin both rely on it).
/// You’ll back this with your existing hash (e.g., SHA-256/512 or Blake2s/b).
pub trait RandomOracle {
    /// Full hash used for transcript steps or Fischlin's `common_h`.
    fn H_full(&mut self, label: &'static str, data: &[u8]) -> Vec<u8>;

    /// A regular hash you can truncate for `H_b` (Fischlin predicate).
    fn H(&mut self, label: &'static str, data: &[u8]) -> Vec<u8>;
}

/// Helper: truncate a hash to `b` bits, return as `u64` (supports b ≤ 56 here).
#[inline]
pub fn trunc_b_to_u64(bytes: &[u8], b: u8) -> u64 {
    debug_assert!(b <= 56, "adjust packing if you need b > 56");
    let take = ((b as usize + 7) / 8).max(1).min(8);
    let mut buf = [0u8; 8];
    buf[..take].copy_from_slice(&bytes[..take]);
    let v = u64::from_le_bytes(buf);
    if b == 64 { v } else { v & ((1u64 << b) - 1) }
}
