//! Action classifier: maps `(method, host, path)` to an action class.
//!
//! Mapping configuration is compiled once. Requests are accepted only when
//! their method, authority, and path have an unambiguous ASCII interpretation.

mod config;
mod matcher;
mod normalize;

use std::cmp::Ordering;
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

const MAX_TOTAL_RULES: usize = 10_000;
const MAX_DIAGNOSTIC_VALUE_BYTES: usize = 256;

pub(crate) fn diagnostic_value(value: &str) -> String {
    if value.len() <= MAX_DIAGNOSTIC_VALUE_BYTES {
        return value.into();
    }
    let mut end = MAX_DIAGNOSTIC_VALUE_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… [truncated]", &value[..end])
}

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
    /// Checking the configuration for conflicts needs more comparison work than
    /// the loader permits; the two rules are where the budget ran out. Rejecting
    /// keeps `load` responsive without silently accepting an unchecked ambiguity.
    #[error("{first} and {second} require excessive conflict analysis")]
    ConflictAnalysisTooComplex {
        first: RuleLocation,
        second: RuleLocation,
    },
    #[error("mapping configuration contains more than {limit} rules")]
    TooManyRules { limit: usize },
}

/// The reason a single mapping set is invalid.
#[derive(Debug, thiserror::Error)]
pub enum SetError {
    /// The document is not valid TOML or does not have the mapping-set shape.
    /// The message gives the line and column and is bounded in length.
    #[error("invalid TOML: {0}")]
    Toml(String),
    #[error("unsupported format version {0}; expected 1")]
    UnsupportedFormatVersion(u32),
    #[error("{0} must not be empty or malformed")]
    InvalidField(&'static str),
    #[error("rule {rule} has invalid {field} value {value:?}")]
    InvalidRule {
        rule: usize,
        field: &'static str,
        value: String,
    },
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

/// Equally specific rules with different classes match one reading of a request.
struct AmbiguousMatch;

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
            if rules.len() == MAX_TOTAL_RULES {
                return Err(LoadError::TooManyRules {
                    limit: MAX_TOTAL_RULES,
                });
            }
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
                        value: diagnostic_value(rule.subdomain.as_deref().unwrap_or_default()),
                    },
                    CompileError::Method => SetError::InvalidRule {
                        rule: rule_index,
                        field: "method",
                        value: diagnostic_value(rule.method.as_deref().unwrap_or_default()),
                    },
                    CompileError::Path => SetError::InvalidRule {
                        rule: rule_index,
                        field: "path",
                        value: diagnostic_value(rule.path.as_deref().unwrap_or_default()),
                    },
                    CompileError::ActionClass(action_class) => SetError::UnknownActionClass {
                        rule: rule_index,
                        action_class: diagnostic_value(&action_class),
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
    ///
    /// Servers differ on case and trailing slashes, so one request can have
    /// several readings. The path as sent and the uppercase method select the
    /// class; any other reading that names a different class denies the request.
    pub async fn classify(&self, method: &str, host: &str, path: &str) -> Option<&str> {
        let folded_method = normalize::method(method)?;
        let host = normalize::host(host)?;
        let path = normalize::request_path(path)?;
        let class = self.best_match(&folded_method, &host, &path, false).ok()?;

        let lowercase = normalize::lowercase_path_outside_escapes(&path);
        let mut spellings = vec![(path.as_str(), false), (lowercase.as_str(), true)];
        if let Some(stripped) = path.strip_suffix('/').filter(|rest| !rest.is_empty()) {
            spellings.push((stripped, false));
        }
        if let Some(stripped) = lowercase.strip_suffix('/').filter(|rest| !rest.is_empty()) {
            spellings.push((stripped, true));
        }
        // Rule methods are uppercase, so passing a differently cased method
        // through unchanged gives its case-sensitive reading (RFC 9110): only
        // method-less rules can match it.
        let mut methods = vec![folded_method.as_str()];
        if method != folded_method {
            methods.push(method);
        }
        let readings = methods
            .iter()
            .flat_map(|method| spellings.iter().map(move |spelling| (*method, *spelling)))
            .skip(1); // The reading that selected `class` above.
        for (method, (path, case_folded_path)) in readings {
            let other = self
                .best_match(method, &host, path, case_folded_path)
                .ok()?;
            if other.is_some() && other != class {
                return None;
            }
        }
        class
    }

    /// Returns the class of the most specific matching rule. `load` rejects
    /// equal-specificity conflicts for paths as written, but patterns that
    /// differ only by case tie once they are folded. Reporting that tie, rather
    /// than choosing a winner, keeps the result independent of rule order.
    fn best_match(
        &self,
        method: &str,
        host: &str,
        path: &str,
        case_folded_path: bool,
    ) -> Result<Option<&str>, AmbiguousMatch> {
        let mut best: Option<&CompiledRule> = None;
        let mut tied = false;
        for rule in self
            .rules
            .iter()
            .filter(|rule| rule.matches(method, host, path, case_folded_path))
        {
            match best.map(|best| (rule.compare_specificity(best), best.action_class)) {
                None | Some((Ordering::Greater, _)) => {
                    best = Some(rule);
                    tied = false;
                }
                Some((Ordering::Equal, class)) if class != rule.action_class => tied = true,
                Some(_) => {}
            }
        }
        if tied {
            return Err(AmbiguousMatch);
        }
        Ok(best.map(|rule| rule.action_class))
    }
}
