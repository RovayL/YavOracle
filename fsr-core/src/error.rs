//! Common error surface across FS & Fischlin.
#![allow(missing_docs)]

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProveError {
    /// The attempt failed only because the Fischlin predicate was not met.
    RetryNeeded,
    /// Inputs / message contents are invalid for the protocol.
    Malformed(&'static str),
    /// Parameters that would break soundness (e.g., zero group order).
    UnsoundParams(&'static str),
}

pub type Result<T> = core::result::Result<T, ProveError>;
