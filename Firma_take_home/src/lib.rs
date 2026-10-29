//! Action classifier: maps `(method, host, path)` to an action class.
//!
//! Mapping configuration is compiled once. Requests are accepted only when
//! their method, authority, and path have an unambiguous ASCII interpretation.

mod config;
mod matcher;
mod normalize;

use std::fmt;

use config::parse;
use matcher::{CompileError, CompiledRule, ConflictCheckError, find_conflict};

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

/// Why a set of mapping files was rejected. Set and rule indexes are 0-based
/// positions in the `sets` slice and the set's `rules` array.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// One mapping set is invalid on its own. `name` is absent when the set
    /// could not be parsed far enough to read it.
    #[error("mapping set {set}{}: {error}", display_name(.name))]
    InvalidSet {
        set: usize,
        name: Option<String>,
        #[source]
        error: SetError,
    },
    /// Two rules, possibly from different sets, can match the same request
    /// with equal specificity but name different action classes.
    #[error("{first} and {second} overlap with equal specificity but different action classes")]
    ConflictingRules {
        first: RuleLocation,
        second: RuleLocation,
    },
    /// Two wildcard patterns require more overlap-analysis state than the
    /// loader safely permits. Rejecting prevents configuration-driven memory
    /// exhaustion without silently accepting an unresolved ambiguity.
    #[error("{first} and {second} require excessive conflict analysis")]
    ConflictAnalysisTooComplex {
        first: RuleLocation,
        second: RuleLocation,
    },
}

/// The reason a single mapping set is invalid.
#[derive(Debug, thiserror::Error)]
pub enum SetError {
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
}

/// Where a rule came from, for conflict diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleLocation {
    pub set: usize,
    pub name: String,
    pub rule: usize,
}

impl fmt::Display for RuleLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "mapping set {} {:?} rule {}",
            self.set, self.name, self.rule
        )
    }
}

fn display_name(name: &Option<String>) -> String {
    name.as_ref()
        .map(|name| format!(" {name:?}"))
        .unwrap_or_default()
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
    let mut locations = Vec::new();
    for (set_index, input) in sets.iter().enumerate() {
        let set = parse(input).map_err(|(name, error)| LoadError::InvalidSet {
            set: set_index,
            name,
            error,
        })?;
        for (rule_index, rule) in set.rules.into_iter().enumerate() {
            // Validation already ran these checks, so this mapping only
            // guards against the two modules drifting apart.
            let compiled = CompiledRule::new(
                rule.method.as_deref(),
                &set.host,
                rule.subdomain.as_deref(),
                rule.path.as_deref(),
                rule.action_class,
            )
            .map_err(|error| {
                let error = match error {
                    CompileError::Host => SetError::InvalidRule {
                        rule: rule_index,
                        field: "subdomain",
                    },
                    CompileError::Method => SetError::InvalidRule {
                        rule: rule_index,
                        field: "method",
                    },
                    CompileError::Path => SetError::InvalidRule {
                        rule: rule_index,
                        field: "path",
                    },
                    CompileError::ActionClass(action_class) => SetError::UnknownActionClass {
                        rule: rule_index,
                        action_class,
                    },
                };
                LoadError::InvalidSet {
                    set: set_index,
                    name: Some(set.name.clone()),
                    error,
                }
            })?;
            rules.push(compiled);
            locations.push(RuleLocation {
                set: set_index,
                name: set.name.clone(),
                rule: rule_index,
            });
        }
    }
    match find_conflict(&rules) {
        Ok(Some((first, second))) => {
            return Err(LoadError::ConflictingRules {
                first: locations[first].clone(),
                second: locations[second].clone(),
            });
        }
        Ok(None) => {}
        Err(ConflictCheckError::TooComplex { first, second }) => {
            return Err(LoadError::ConflictAnalysisTooComplex {
                first: locations[first].clone(),
                second: locations[second].clone(),
            });
        }
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

        // A server may strip a trailing slash and route to a more sensitive
        // handler. A request sent without one is classified as sent, so only
        // the trailing-slash spelling needs this conservative comparison.
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
            .map(|rule| rule.action_class)
    }
}
