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

/// Total bytes conflict analysis may read across all eligible path pairs. The
/// amount charged depends only on the two patterns, so whether a configuration
/// fits does not depend on rule order or on the machine.
const MAX_CONFLICT_WORK_BYTES: u64 = 4_000_000_000;

pub(crate) fn find_conflict(
    rules: &[CompiledRule],
) -> Result<Option<(usize, usize)>, ConflictCheckError> {
    find_conflict_within(rules, MAX_CONFLICT_WORK_BYTES)
}

fn find_conflict_within(
    rules: &[CompiledRule],
    mut remaining_work: u64,
) -> Result<Option<(usize, usize)>, ConflictCheckError> {
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
                    &mut remaining_work,
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
            a == b || is_subdomain_of(a, b) || is_subdomain_of(b, a)
        }
    }
}

fn is_subdomain_of(host: &str, base: &str) -> bool {
    host.strip_suffix(base)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

fn paths_overlap(
    left: Option<&str>,
    right: Option<&str>,
    remaining_work: &mut u64,
) -> Result<bool, ()> {
    // Equal patterns always overlap. More importantly, this check must happen
    // before spending the bounded analysis budget: an identical pair is an
    // unambiguous conflict, not an analysis failure.
    if left == right {
        return Ok(true);
    }
    let (Some(left), Some(right)) = (left, right) else {
        return Ok(true);
    };
    match (literal_ends(left), literal_ends(right)) {
        (None, None) => {
            charge_work(remaining_work, left.len() + right.len())?;
            Ok(false)
        }
        (None, Some(_)) | (Some(_), None) => {
            charge_work(remaining_work, left.len().saturating_mul(right.len()))?;
            let (pattern, literal) = if left.contains('*') {
                (left, right)
            } else {
                (right, left)
            };
            Ok(glob_matches(pattern, literal))
        }
        (Some((left_prefix, left_suffix)), Some((right_prefix, right_suffix))) => {
            charge_work(
                remaining_work,
                left_prefix.len() + left_suffix.len() + right_prefix.len() + right_suffix.len(),
            )?;
            Ok(
                (left_prefix.starts_with(right_prefix) || right_prefix.starts_with(left_prefix))
                    && (left_suffix.ends_with(right_suffix) || right_suffix.ends_with(left_suffix)),
            )
        }
    }
}

/// The literal text before a pattern's first `*` and after its last `*`, or
/// `None` for a pattern without a wildcard.
///
/// These ends decide overlap between two wildcard patterns exactly. Every match
/// starts with the prefix and ends with the suffix, so a disagreement within the
/// shorter length rules out a common match. If both ends agree, the longer
/// prefix, each pattern's middle literals, then the longer suffix match both,
/// because each `*` can absorb what the other pattern added.
fn literal_ends(pattern: &str) -> Option<(&str, &str)> {
    let (prefix, _) = pattern.split_once('*')?;
    let (_, suffix) = pattern.rsplit_once('*')?;
    Some((prefix, suffix))
}

fn charge_work(remaining_work: &mut u64, bytes: usize) -> Result<(), ()> {
    *remaining_work = remaining_work.checked_sub(bytes as u64).ok_or(())?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::{
        CompileError, CompiledRule, ConflictCheckError, HostPattern, find_conflict,
        find_conflict_within, glob_matches, hosts_overlap, paths_overlap,
    };

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

    /// Asserts that `paths` fit in exactly `cost` bytes of work, in either order,
    /// and report `expected` then; one byte less fails closed.
    fn assert_exact_work(paths: [&str; 2], cost: u64, expected: Option<(usize, usize)>) {
        for [first, second] in [paths, [paths[1], paths[0]]] {
            let rules = vec![
                rule(Some("api"), None, Some(first), "payment.read"),
                rule(Some("api"), None, Some(second), "payment.refund"),
            ];
            assert_eq!(
                find_conflict_within(&rules, cost).unwrap(),
                expected,
                "{first} {second}"
            );
            assert!(
                matches!(
                    find_conflict_within(&rules, cost - 1),
                    Err(ConflictCheckError::TooComplex {
                        first: 0,
                        second: 1
                    })
                ),
                "{first} {second}"
            );
        }
    }

    #[test]
    fn conflict_work_is_charged_for_every_eligible_comparison() {
        // Literal ends that disagree, at the prefix and at the suffix.
        assert_exact_work(["/ab*", "/ac*"], 6, None);
        assert_exact_work(["/*ab", "/*ac"], 6, None);
        // Literal ends that agree establish the conflict at the same price.
        assert_exact_work(["/v*a*bc", "/v*ab*c"], 7, Some((0, 1)));
        // Exact paths read both patterns in full.
        assert_exact_work(["/a", "/b"], 4, None);
    }

    #[test]
    fn conflict_work_is_not_charged_for_pairs_that_need_no_comparison() {
        let long = format!("/{}/*", "a".repeat(1_000));
        let cases = [
            // Identical patterns are a conflict, not an analysis failure.
            (
                rule(Some("api"), None, Some(&long), "payment.read"),
                rule(Some("api"), None, Some(&long), "payment.refund"),
                Some((0, 1)),
            ),
            // Same class.
            (
                rule(Some("api"), None, Some("/a*"), "payment.read"),
                rule(Some("api"), None, Some("/b*"), "payment.read"),
                None,
            ),
            // Different specificity.
            (
                rule(Some("api"), None, Some("/ab*"), "payment.read"),
                rule(Some("api"), None, Some("/b*"), "payment.refund"),
                None,
            ),
            // Different host.
            (
                rule(Some("api"), None, Some("/a*"), "payment.read"),
                rule(Some("www"), None, Some("/b*"), "payment.refund"),
                None,
            ),
            // Different method.
            (
                rule(Some("api"), Some("GET"), Some("/a*"), "payment.read"),
                rule(Some("api"), Some("POST"), Some("/b*"), "payment.refund"),
                None,
            ),
        ];
        for (first, second, expected) in cases {
            assert_eq!(find_conflict_within(&[first, second], 0).unwrap(), expected);
        }
    }

    #[test]
    fn exhausted_work_budget_rejects_the_same_configurations_in_any_order() {
        let mut rules = (0..6)
            .map(|index| {
                let class = if index % 2 == 0 {
                    "payment.read"
                } else {
                    "payment.refund"
                };
                rule(None, None, Some(&format!("/p{index}/*")), class)
            })
            .collect::<Vec<_>>();
        // Three rules of each class form nine eligible pairs at 8 bytes each.
        let total = 9 * 8;
        for _ in 0..2 {
            assert_eq!(find_conflict_within(&rules, total).unwrap(), None);
            assert!(find_conflict_within(&rules, total - 1).is_err());
            rules.reverse();
        }
    }

    #[test]
    fn wildcard_host_overlap_respects_label_boundaries() {
        let any = |base: &str| HostPattern::AnySubdomain(base.into());
        assert!(hosts_overlap(&any("acme.com"), &any("acme.com")));
        assert!(hosts_overlap(&any("x.acme.com"), &any("acme.com")));
        assert!(hosts_overlap(&any("acme.com"), &any("x.acme.com")));
        assert!(!hosts_overlap(&any("evilacme.com"), &any("acme.com")));
        assert!(!hosts_overlap(&any("acme.com"), &any("evilacme.com")));
        assert!(!hosts_overlap(&any("a.acme.com"), &any("b.acme.com")));
    }

    #[test]
    fn wildcards_with_different_literal_ends_do_not_conflict() {
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
        assert_eq!(find_conflict(&rules).unwrap(), None);
    }

    /// Any overlap has a witness no longer than the two patterns' literals
    /// combined, so short strings decide every pair exhaustively.
    #[test]
    fn overlap_analysis_agrees_with_exhaustive_search() {
        let mut words = vec![String::new()];
        for start in 0.. {
            let Some(word) = words.get(start).cloned() else {
                break;
            };
            if word.len() < 6 {
                words.extend(["a", "b"].map(|letter| format!("{word}{letter}")));
            }
        }
        let patterns = words
            .iter()
            .filter(|word| word.len() <= 3)
            .flat_map(|word| {
                (0..=word.len()).flat_map(move |at| {
                    (at..=word.len()).flat_map(move |end| {
                        let (head, rest) = word.split_at(at);
                        let (middle, tail) = rest.split_at(end - at);
                        [
                            format!("{head}{middle}*{tail}"),
                            format!("*{head}{middle}*{tail}"),
                            format!("{head}*{middle}*{tail}"),
                            format!("{head}*{middle}*{tail}*"),
                        ]
                    })
                })
            })
            .collect::<Vec<_>>();
        for left in &patterns {
            for right in &patterns {
                let witness = words
                    .iter()
                    .any(|word| glob_matches(left, word) && glob_matches(right, word));
                let mut budget = u64::MAX;
                assert_eq!(
                    paths_overlap(Some(left), Some(right), &mut budget),
                    Ok(witness),
                    "{left} {right}"
                );
            }
        }
    }

    #[test]
    fn explicit_methods_win_only_after_host_and_path_ties() {
        let any_method = rule(Some("api"), None, Some("/v1/*"), "payment.read");
        let get = rule(Some("api"), Some("GET"), Some("/v1/*"), "payment.create");
        assert!(get.compare_specificity(&any_method).is_gt());
        assert!(get.matches("GET", "api.acme.com", "/v1/x", false));
        // Comparison is exact: `classify` chooses which reading to pass in.
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
