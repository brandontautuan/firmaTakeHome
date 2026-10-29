//! Compiled-rule matching, lexicographic specificity, and load-time conflicts.

use std::cmp::Ordering;

use crate::{ACTION_CLASSES, normalize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostPattern {
    Bare(String),
    Exact(String),
    AnySubdomain(String),
}

#[derive(Debug, Clone)]
pub(crate) struct CompiledRule {
    pub(crate) method: Option<String>,
    pub(crate) host: HostPattern,
    pub(crate) path: Option<String>,
    folded_path: Option<String>,
    pub(crate) action_class: &'static str,
    specificity: Specificity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Specificity {
    host_kind: u8,
    host_labels: usize,
    path_kind: u8,
    literal_count: usize,
    inverted_wildcard_count: usize,
    literal_prefix: usize,
    method: u8,
}

impl Ord for Specificity {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.host_kind,
            self.host_labels,
            self.path_kind,
            self.literal_count,
            self.inverted_wildcard_count,
            self.literal_prefix,
            self.method,
        )
            .cmp(&(
                other.host_kind,
                other.host_labels,
                other.path_kind,
                other.literal_count,
                other.inverted_wildcard_count,
                other.literal_prefix,
                other.method,
            ))
    }
}

impl PartialOrd for Specificity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
pub(crate) enum CompileError {
    Host,
    Method,
    Path,
    ActionClass(String),
}

#[derive(Debug)]
pub(crate) enum ConflictCheckError {
    TooComplex { first: usize, second: usize },
}

impl CompiledRule {
    pub(crate) fn new(
        method: Option<&str>,
        base_host: &str,
        subdomain: Option<&str>,
        path: Option<&str>,
        action_class: String,
    ) -> Result<Self, CompileError> {
        let base_host = normalize::host(base_host).ok_or(CompileError::Host)?;
        let host = match subdomain {
            None => HostPattern::Bare(base_host),
            Some("*") => HostPattern::AnySubdomain(base_host),
            Some(value) => {
                let host = format!("{value}.{base_host}");
                HostPattern::Exact(normalize::host(&host).ok_or(CompileError::Host)?)
            }
        };
        let method = match method {
            Some(value) => Some(normalize::method(value).ok_or(CompileError::Method)?),
            None => None,
        };
        let path = match path {
            Some(value) => {
                let normalized = normalize::pattern_path(value).ok_or(CompileError::Path)?;
                (normalized.len() <= normalize::MAX_PATTERN_BYTES)
                    .then_some(normalized)
                    .ok_or(CompileError::Path)
                    .map(Some)?
            }
            None => None,
        };
        let folded_path = path
            .as_deref()
            .map(normalize::lowercase_path_outside_escapes);
        let action_class = ACTION_CLASSES
            .iter()
            .copied()
            .find(|known| *known == action_class)
            .ok_or(CompileError::ActionClass(action_class))?;
        let specificity = specificity(&host, method.is_some(), path.as_deref());
        Ok(Self {
            method,
            host,
            path,
            folded_path,
            action_class,
            specificity,
        })
    }

    pub(crate) fn matches(
        &self,
        method: &str,
        host: &str,
        path: &str,
        case_folded_path: bool,
    ) -> bool {
        self.method
            .as_deref()
            .is_none_or(|expected| expected == method)
            && host_matches(&self.host, host)
            && self
                .folded_path
                .as_deref()
                .filter(|_| case_folded_path)
                .or(self.path.as_deref())
                .is_none_or(|pattern| glob_matches(pattern, path))
    }

    pub(crate) fn compare_specificity(&self, other: &Self) -> Ordering {
        self.specificity.cmp(&other.specificity)
    }
}

pub(crate) fn find_conflict(
    rules: &[CompiledRule],
) -> Result<Option<(usize, usize)>, ConflictCheckError> {
    let mut remaining_glob_overlap_states = MAX_TOTAL_GLOB_OVERLAP_STATES;
    for (right_index, right) in rules.iter().enumerate() {
        for (left_index, left) in rules[..right_index].iter().enumerate() {
            if left.action_class != right.action_class
                && left.specificity == right.specificity
                && methods_overlap(left.method.as_deref(), right.method.as_deref())
                && hosts_overlap(&left.host, &right.host)
            {
                match paths_overlap(
                    left.path.as_deref(),
                    right.path.as_deref(),
                    &mut remaining_glob_overlap_states,
                ) {
                    Ok(true) => return Ok(Some((left_index, right_index))),
                    Ok(false) => {}
                    Err(()) => {
                        return Err(ConflictCheckError::TooComplex {
                            first: left_index,
                            second: right_index,
                        });
                    }
                }
            }
        }
    }
    Ok(None)
}

fn specificity(host: &HostPattern, has_method: bool, path: Option<&str>) -> Specificity {
    let host_kind = u8::from(!matches!(host, HostPattern::AnySubdomain(_)));
    let host_labels = match host {
        HostPattern::Bare(value) | HostPattern::Exact(value) | HostPattern::AnySubdomain(value) => {
            value.split('.').count()
        }
    };
    let (path_kind, literal_count, wildcard_count, literal_prefix) = match path {
        None => (0, 0, 0, 0),
        Some(value) if !value.contains('*') => (2, value.len(), 0, value.len()),
        Some(value) => (
            1,
            value.bytes().filter(|byte| *byte != b'*').count(),
            value.bytes().filter(|byte| *byte == b'*').count(),
            value.find('*').unwrap_or(0),
        ),
    };
    Specificity {
        host_kind,
        host_labels,
        path_kind,
        literal_count,
        inverted_wildcard_count: usize::MAX - wildcard_count,
        literal_prefix,
        method: u8::from(has_method),
    }
}

fn host_matches(pattern: &HostPattern, host: &str) -> bool {
    match pattern {
        HostPattern::Bare(expected) | HostPattern::Exact(expected) => expected == host,
        HostPattern::AnySubdomain(base) => host
            .strip_suffix(base)
            .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1),
    }
}

fn methods_overlap(left: Option<&str>, right: Option<&str>) -> bool {
    left.is_none() || right.is_none() || left == right
}

fn hosts_overlap(left: &HostPattern, right: &HostPattern) -> bool {
    match (left, right) {
        (HostPattern::Bare(a), HostPattern::Bare(b))
        | (HostPattern::Bare(a), HostPattern::Exact(b))
        | (HostPattern::Exact(a), HostPattern::Bare(b))
        | (HostPattern::Exact(a), HostPattern::Exact(b)) => a == b,
        // These pairs cannot have equal host specificity, but retain correct
        // overlap semantics for callers that want them.
        (HostPattern::AnySubdomain(base), HostPattern::Bare(host))
        | (HostPattern::Bare(host), HostPattern::AnySubdomain(base))
        | (HostPattern::AnySubdomain(base), HostPattern::Exact(host))
        | (HostPattern::Exact(host), HostPattern::AnySubdomain(base)) => {
            host_matches(&HostPattern::AnySubdomain(base.clone()), host)
        }
        (HostPattern::AnySubdomain(a), HostPattern::AnySubdomain(b)) => {
            a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
        }
    }
}

fn paths_overlap(
    left: Option<&str>,
    right: Option<&str>,
    remaining_states: &mut usize,
) -> Result<bool, ()> {
    // Equal patterns always overlap. More importantly, this check must happen
    // before spending the bounded wildcard-analysis budget: an identical pair
    // is an unambiguous conflict, not an analysis failure.
    if left == right {
        return Ok(true);
    }
    match (left, right) {
        (None, _) | (_, None) => Ok(true),
        (Some(left), Some(right)) if !left.contains('*') && !right.contains('*') => Ok(false),
        (Some(left), Some(right)) if !left.contains('*') => Ok(glob_matches(right, left)),
        (Some(left), Some(right)) if !right.contains('*') => Ok(glob_matches(left, right)),
        (Some(left), Some(right)) => globs_overlap(left, right, remaining_states),
    }
}

pub(crate) fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    while v < value.len() {
        while p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = v;
        }
        if p < pattern.len() && pattern[p] == value[v] {
            p += 1;
            v += 1;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            retry += 1;
            v = retry;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Product traversal of two `*` glob NFAs. The sentinel represents any byte
/// not currently present as a literal and keeps the alphabet finite.
const MAX_TOTAL_GLOB_OVERLAP_STATES: usize = 4_000_000;

fn globs_overlap(left: &str, right: &str, remaining_states: &mut usize) -> Result<bool, ()> {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    let width = right.len().checked_add(1).ok_or(())?;
    let states = left
        .len()
        .checked_add(1)
        .and_then(|height| height.checked_mul(width))
        .ok_or(())?;
    if states > *remaining_states {
        return Err(());
    }
    *remaining_states -= states;
    let mut seen = vec![false; states];
    let mut queue = std::collections::VecDeque::from([(0usize, 0usize)]);
    while let Some((i, j)) = queue.pop_front() {
        let state = i * width + j;
        if seen[state] {
            continue;
        }
        seen[state] = true;
        if i == left.len() && j == right.len() {
            return Ok(true);
        }
        if left.get(i) == Some(&b'*') {
            queue.push_back((i + 1, j));
        }
        if right.get(j) == Some(&b'*') {
            queue.push_back((i, j + 1));
        }
        let mut alphabet = vec![0];
        if let Some(&byte) = left.get(i).filter(|&&byte| byte != b'*') {
            alphabet.push(byte);
        }
        if let Some(&byte) = right.get(j).filter(|&&byte| byte != b'*') {
            alphabet.push(byte);
        }
        for byte in alphabet {
            let next_left = transition(left, i, byte);
            let next_right = transition(right, j, byte);
            if let (Some(next_left), Some(next_right)) = (next_left, next_right) {
                queue.push_back((next_left, next_right));
            }
        }
    }
    Ok(false)
}

fn transition(pattern: &[u8], index: usize, byte: u8) -> Option<usize> {
    match pattern.get(index) {
        Some(b'*') => Some(index),
        Some(&literal) if literal == byte => Some(index + 1),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{CompileError, CompiledRule, ConflictCheckError, find_conflict, glob_matches};

    fn rule(
        subdomain: Option<&str>,
        method: Option<&str>,
        path: Option<&str>,
        action: &str,
    ) -> CompiledRule {
        CompiledRule::new(method, "acme.com", subdomain, path, action.into()).unwrap()
    }

    #[test]
    fn wildcard_hosts_respect_boundaries_and_nested_subdomains() {
        let rule = rule(Some("*"), None, None, "payment.read");
        assert!(rule.matches("GET", "a.b.acme.com", "/", false));
        assert!(!rule.matches("GET", "acme.com", "/", false));
        assert!(!rule.matches("GET", "evilacme.com", "/", false));
    }

    #[test]
    fn globs_match_zero_or_more_characters() {
        assert!(glob_matches("/v1/refunds/*", "/v1/refunds/"));
        assert!(glob_matches("/v1/*/x/*", "/v1/a/b/x/c"));
        assert!(!glob_matches("/v1/refunds/*", "/v1/refunds"));
        assert!(glob_matches("/**/**/**", "/a/b/c/d"));
    }

    #[test]
    fn specificity_is_lexicographic() {
        let exact_host = rule(Some("api"), None, Some("/v1/*"), "payment.read");
        let wildcard_host = rule(
            Some("*"),
            Some("GET"),
            Some("/v1/payments"),
            "payment.create",
        );
        assert!(exact_host.compare_specificity(&wildcard_host).is_gt());
        let exact_path = rule(Some("api"), None, Some("/v1/payments"), "payment.read");
        assert!(exact_path.compare_specificity(&exact_host).is_gt());
    }

    #[test]
    fn detects_equal_specificity_overlaps_only() {
        let conflicting = vec![
            rule(Some("api"), None, Some("/v1/*a*bc"), "payment.read"),
            rule(Some("api"), None, Some("/v1/*ab*c"), "payment.refund"),
        ];
        assert_eq!(find_conflict(&conflicting).unwrap(), Some((0, 1)));
        let ordered = vec![
            rule(Some("api"), None, Some("/v1/*"), "payment.read"),
            rule(Some("api"), None, Some("/v1/payments"), "payment.refund"),
        ];
        assert_eq!(find_conflict(&ordered).unwrap(), None);
    }

    #[test]
    fn identical_complex_patterns_conflict_before_spending_budget() {
        let pattern = format!("/{}", "*".repeat(1_000));
        let rules = vec![
            rule(Some("api"), None, Some(&pattern), "payment.read"),
            rule(Some("api"), None, Some(&pattern), "payment.refund"),
        ];
        assert_eq!(find_conflict(&rules).unwrap(), Some((0, 1)));
    }

    #[test]
    fn rejects_configurations_that_exceed_total_overlap_budget() {
        let rules = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                let path = format!("/{}{}", "*".repeat(1_022), char::from(*byte));
                let class = if index % 2 == 0 {
                    "payment.read"
                } else {
                    "payment.refund"
                };
                rule(Some("api"), None, Some(&path), class)
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            find_conflict(&rules),
            Err(ConflictCheckError::TooComplex { .. })
        ));
    }

    #[test]
    fn explicit_methods_win_only_after_host_and_path_ties() {
        let any_method = rule(Some("api"), None, Some("/v1/*"), "payment.read");
        let get = rule(Some("api"), Some("GET"), Some("/v1/*"), "payment.create");
        assert!(get.compare_specificity(&any_method).is_gt());
        assert!(get.matches("GET", "api.acme.com", "/v1/x", false));
        // `matches` receives normalized method tokens from `classify`.
        assert!(!get.matches("get", "api.acme.com", "/v1/x", false));
        assert!(!get.matches("POST", "api.acme.com", "/v1/x", false));
        let lower = rule(Some("api"), Some("get"), Some("/v1/*"), "payment.create");
        assert_eq!(lower.method.as_deref(), Some("GET"));
    }

    #[test]
    fn compiled_rules_only_retain_known_action_classes() {
        assert!(matches!(
            CompiledRule::new(None, "acme.com", None, None, "unknown.class".into()),
            Err(CompileError::ActionClass(_))
        ));
    }

    #[test]
    fn compiler_enforces_the_pattern_length_limit() {
        let path = format!("/{}", "a".repeat(1_024));
        assert!(matches!(
            CompiledRule::new(None, "acme.com", None, Some(&path), "repo.read".into()),
            Err(CompileError::Path)
        ));
    }
}
