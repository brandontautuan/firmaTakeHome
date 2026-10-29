//! Action classifier: maps `(method, host, path)` to an action class.
//!
//! Mapping configuration is compiled once. Requests are accepted only when
//! their method, authority, and path have an unambiguous ASCII interpretation.

mod config;
mod matcher;
mod normalize;

use config::parse;
use matcher::{CompileError, CompiledRule, find_conflict};

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

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("unsupported format version {0}; expected 1")]
    UnsupportedFormatVersion(u32),
    #[error("{0} must not be empty or malformed")]
    InvalidField(&'static str),
    #[error("rule {rule} has an invalid {field}")]
    InvalidRule { rule: usize, field: &'static str },
    #[error("rule {rule} names unsupported action class {action_class:?}")]
    UnknownActionClass { rule: usize, action_class: String },
    #[error(
        "rules {first} and {second} overlap with equal specificity but different action classes"
    )]
    ConflictingRules { first: usize, second: usize },
}

/// An immutable, precompiled collection of mapping rules. Its contents are
/// owned strings and therefore it is `Send + Sync` without special handling.
pub struct Classifier {
    rules: Vec<CompiledRule>,
}

/// Parse, validate, compile, and combine mapping sets. Configuration conflicts
/// are rejected here, so mapping-file ordering never affects classification.
pub async fn load(sets: &[&str]) -> Result<Classifier, LoadError> {
    let mut rules = Vec::new();
    for input in sets {
        let set = parse(input)?;
        for rule in set.rules {
            let index = rules.len();
            let compiled = CompiledRule::new(
                rule.method.as_deref(),
                &set.host,
                rule.subdomain.as_deref(),
                rule.path.as_deref(),
                rule.action_class,
            )
            .map_err(|error| match error {
                CompileError::Host => LoadError::InvalidRule {
                    rule: index,
                    field: "subdomain",
                },
                CompileError::Method => LoadError::InvalidRule {
                    rule: index,
                    field: "method",
                },
                CompileError::Path => LoadError::InvalidRule {
                    rule: index,
                    field: "path",
                },
            })?;
            rules.push(compiled);
        }
    }
    if let Some((first, second)) = find_conflict(&rules) {
        return Err(LoadError::ConflictingRules { first, second });
    }
    Ok(Classifier { rules })
}

impl Classifier {
    /// Classifies a request. Malformed input is deliberately unclassified
    /// rather than coerced into a potentially broader rule.
    pub async fn classify(&self, method: &str, host: &str, path: &str) -> Option<&str> {
        let method = normalize::method(method)?;
        let host = normalize::host(host)?;
        let path = normalize::request_path(path)?;
        let class = self.best_match(&method, &host, &path);

        // Many servers route `/x/` and `/x` to the same handler. If the two
        // spellings classify differently we cannot know which action runs, so
        // the request is left unclassified (and therefore denied).
        if let Some(stripped) = path.strip_suffix('/').filter(|rest| !rest.is_empty()) {
            let alternative = self.best_match(&method, &host, stripped);
            if alternative.is_some() && alternative != class {
                return None;
            }
        }
        class
    }

    fn best_match(&self, method: &str, host: &str, path: &str) -> Option<&str> {
        self.rules
            .iter()
            .filter(|rule| rule.matches(method, host, path))
            .max_by(|left, right| left.compare_specificity(right))
            .map(|rule| rule.action_class.as_str())
    }
}
