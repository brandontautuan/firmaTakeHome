//! Action classifier: maps `(method, host, path)` to an action class.
//!
//! See `README.md` for the specification. The two public functions below are
//! the fixed API; everything else in this crate is yours to design.

/// Action classes a rule may name. A rule naming anything else is invalid.
pub const ACTION_CLASSES: &[&str] = &[
    "payment.read",
    "payment.create",
    "payment.refund",
    "repo.read",
    "repo.write",
    "communication.external.send",
    "llm.inference",
];

/// Why a set of mapping files was rejected. Replace this freely; it only has
/// to implement `std::error::Error`.
#[derive(Debug, thiserror::Error)]
#[error("not implemented")]
pub struct LoadError;

/// A validated, ready-to-query collection of mapping sets.
pub struct Classifier {}

/// Parse, validate and combine mapping sets. Each item is the text of one
/// user-provided mapping file.
pub async fn load(sets: &[&str]) -> Result<Classifier, LoadError> {
    let _ = sets;
    todo!()
}

impl Classifier {
    /// Classify one request. Returns `None` when it is unclassified.
    pub async fn classify(&self, method: &str, host: &str, path: &str) -> Option<&str> {
        let _ = (method, host, path);
        todo!()
    }
}
