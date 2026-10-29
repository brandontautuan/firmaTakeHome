//! Action classifier: maps `(method, host, path)` to an action class.
//!
//! See `README.md` for the specification. The two public functions below are
//! the fixed API; everything else in this crate is yours to design.

mod config;

use config::parse;

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
    #[error("ambiguous rules match the same request with different action classes")]
    AmbiguousRules,
}

/// A validated, ready-to-query collection of mapping sets.
pub struct Classifier {
    rules: Vec<CompiledRule>,
}

struct CompiledRule {
    method: Option<String>,
    host: String,
    path: Option<String>,
    action_class: String,
}

/// Parse, validate and combine mapping sets. Each item is the text of one
/// user-provided mapping file.
pub async fn load(sets: &[&str]) -> Result<Classifier, LoadError> {
    let mut rules = Vec::new();
    for input in sets {
        let set = parse(input)?;
        for rule in set.rules {
            let host = match rule.subdomain.as_deref() {
                None => set.host.clone(),
                Some("*") => format!("*.{}", set.host),
                Some(subdomain) => format!("{subdomain}.{}", set.host),
            }
            .to_ascii_lowercase();
            rules.push(CompiledRule {
                method: rule.method,
                host,
                path: rule.path,
                action_class: rule.action_class,
            });
        }
    }
    Ok(Classifier { rules })
}

impl Classifier {
    /// Classify one request. Returns `None` when it is unclassified.
    pub async fn classify(&self, method: &str, host: &str, path: &str) -> Option<&str> {
        let normalized_host = host.trim_end_matches('.').to_ascii_lowercase();
        self.rules
            .iter()
            .filter(|rule| matches(rule, method, &normalized_host, path))
            .max_by_key(|rule| specificity(rule))
            .map(|rule| rule.action_class.as_str())
    }
}

fn matches(rule: &CompiledRule, method: &str, host: &str, path: &str) -> bool {
    rule.method
        .as_deref()
        .is_none_or(|expected| expected == method)
        && host_matches(&rule.host, host)
        && rule
            .path
            .as_deref()
            .is_none_or(|pattern| glob_matches(pattern, path))
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
    } else {
        pattern.eq_ignore_ascii_case(host)
    }
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let mut remainder = value;
    let mut first = true;
    for part in pattern.split('*') {
        if part.is_empty() {
            continue;
        }
        let Some(index) = remainder.find(part) else {
            return false;
        };
        if first && !pattern.starts_with('*') && index != 0 {
            return false;
        }
        remainder = &remainder[index + part.len()..];
        first = false;
    }
    pattern.ends_with('*') || remainder.is_empty()
}

fn specificity(rule: &CompiledRule) -> (u8, u8, usize, usize) {
    let host = if rule.host.starts_with("*.") { 1 } else { 2 };
    let method = u8::from(rule.method.is_some());
    let path = rule.path.as_ref().map_or((0, 0), |path| {
        (u8::from(!path.contains('*')), path.replace('*', "").len())
    });
    (host, method, path.0 as usize, path.1)
}
