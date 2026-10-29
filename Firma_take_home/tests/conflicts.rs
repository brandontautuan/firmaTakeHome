//! Load-time conflict detection and set-order independence.

use action_classifier::{LoadError, RuleLocation, SetError, load};

fn set(name: &str, host: &str, rules: &str) -> String {
    format!("format_version = 1\nname = {name:?}\ndescription = \"test\"\nhost = {host:?}\n{rules}")
}

fn rule(subdomain: Option<&str>, method: Option<&str>, path: Option<&str>, class: &str) -> String {
    let mut out = String::from("\n[[rules]]\n");
    for (key, value) in [("subdomain", subdomain), ("method", method), ("path", path)] {
        if let Some(value) = value {
            out.push_str(&format!("{key} = {value:?}\n"));
        }
    }
    out.push_str(&format!("action_class = {class:?}\n"));
    out
}

fn location(set: usize, name: &str, rule: usize) -> RuleLocation {
    RuleLocation {
        set,
        name: name.into(),
        rule,
    }
}

#[tokio::test]
async fn identical_rules_with_different_classes_conflict_across_sets() {
    let a = set(
        "A",
        "acme.com",
        &rule(
            Some("api"),
            Some("POST"),
            Some("/v1/refunds/*"),
            "payment.refund",
        ),
    );
    let b = set(
        "B",
        "acme.com",
        &format!(
            "{}{}",
            rule(None, None, Some("/pricing"), "payment.read"),
            rule(
                Some("api"),
                Some("POST"),
                Some("/v1/refunds/*"),
                "payment.read"
            ),
        ),
    );
    match load(&[&a, &b]).await {
        Err(LoadError::ConflictingRules { first, second }) => {
            assert_eq!(first, location(0, "A", 0));
            assert_eq!(second, location(1, "B", 1));
        }
        other => panic!("expected conflict, got {:?}", other.err()),
    }
}

#[tokio::test]
async fn conflict_message_names_both_rules() {
    let a = set("A", "acme.com", &rule(None, None, Some("/x"), "repo.read"));
    let b = set("B", "acme.com", &rule(None, None, Some("/x"), "repo.write"));
    let message = load(&[&a, &b]).await.err().unwrap().to_string();
    assert!(message.contains(r#"mapping set 0 "A" rule 0"#), "{message}");
    assert!(message.contains(r#"mapping set 1 "B" rule 0"#), "{message}");
}

#[tokio::test]
async fn conflicts_are_detected_within_one_set() {
    let a = set(
        "A",
        "acme.com",
        &format!(
            "{}{}",
            rule(None, None, Some("/x"), "repo.read"),
            rule(None, None, Some("/x"), "repo.write"),
        ),
    );
    assert!(matches!(
        load(&[&a]).await,
        Err(LoadError::ConflictingRules { .. })
    ));
}

#[tokio::test]
async fn overlapping_wildcards_with_equal_specificity_conflict() {
    // `/v1/xy` matches both patterns, and both have the same literal count,
    // wildcard count and literal prefix.
    let a = set(
        "A",
        "acme.com",
        &rule(None, None, Some("/v1/*x*"), "repo.read"),
    );
    let b = set(
        "B",
        "acme.com",
        &rule(None, None, Some("/v1/*y*"), "repo.write"),
    );
    assert!(matches!(
        load(&[&a, &b]).await,
        Err(LoadError::ConflictingRules { .. })
    ));
}

#[tokio::test]
async fn excessively_complex_wildcard_overlap_is_rejected() {
    let path = format!("/{}", "*".repeat(1_000));
    let a = set("A", "acme.com", &rule(None, None, Some(&path), "repo.read"));
    let b = set(
        "B",
        "acme.com",
        &rule(None, None, Some(&path), "repo.write"),
    );
    assert!(matches!(
        load(&[&a, &b]).await,
        Err(LoadError::ConflictingRules { .. })
    ));
}

#[tokio::test]
async fn conflict_analysis_only_charges_eligible_pairs() {
    let sets = (0..1_000)
        .map(|index| {
            set(
                &format!("Host {index}"),
                &format!("h{index}.example.com"),
                &rule(None, None, Some("/x"), "repo.read"),
            )
        })
        .collect::<Vec<_>>();
    let inputs = sets.iter().map(String::as_str).collect::<Vec<_>>();
    assert!(load(&inputs).await.is_ok());
}

#[tokio::test]
async fn same_class_rules_do_not_consume_overlap_budget() {
    let rules = (0..600)
        .map(|index| rule(None, None, Some(&format!("/rule/{index}")), "repo.read"))
        .collect::<String>();
    let input = set("Many exact paths", "acme.com", &rules);
    assert!(load(&[&input]).await.is_ok());
}

#[tokio::test]
async fn distinct_exact_paths_do_not_consume_wildcard_overlap_budget() {
    let rules = (0..1_000)
        .map(|index| {
            rule(
                None,
                None,
                Some(&format!("/path-{index:04}")),
                if index % 2 == 0 {
                    "repo.read"
                } else {
                    "repo.write"
                },
            )
        })
        .collect::<String>();
    let input = set("Exact paths", "acme.com", &rules);
    assert!(load(&[&input]).await.is_ok());
}

#[tokio::test]
async fn adversarial_wildcard_pairs_exhaust_total_overlap_budget() {
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
            rule(None, None, Some(&path), class)
        })
        .collect::<String>();
    let input = set("Adversarial", "acme.com", &rules);
    assert!(matches!(
        load(&[&input]).await,
        Err(LoadError::ConflictAnalysisTooComplex { .. })
    ));
}

#[tokio::test]
async fn rule_count_limit_has_a_dedicated_error() {
    let rules = (0..10_001)
        .map(|_| rule(None, None, None, "repo.read"))
        .collect::<String>();
    let input = set("Too many rules", "acme.com", &rules);
    assert!(matches!(
        load(&[&input]).await,
        Err(LoadError::TooManyRules { limit: 10_000 })
    ));
}

#[tokio::test]
async fn same_class_duplicates_are_harmless() {
    let a = set("A", "acme.com", &rule(None, None, Some("/x"), "repo.read"));
    let c = load(&[&a, &a]).await.unwrap();
    assert_eq!(c.classify("GET", "acme.com", "/x").await, Some("repo.read"));
}

#[tokio::test]
async fn overlaps_with_different_specificity_are_allowed() {
    let a = set("A", "acme.com", &rule(Some("*"), None, None, "repo.read"));
    let b = set(
        "B",
        "acme.com",
        &rule(Some("api"), Some("PUT"), Some("/repos/*"), "repo.write"),
    );
    let c = load(&[&a, &b]).await.unwrap();
    assert_eq!(
        c.classify("PUT", "api.acme.com", "/repos/x").await,
        Some("repo.write")
    );
    assert_eq!(
        c.classify("PUT", "www.acme.com", "/repos/x").await,
        Some("repo.read")
    );
}

#[tokio::test]
async fn rules_for_different_hosts_never_conflict() {
    let a = set("A", "acme.com", &rule(None, None, Some("/x"), "repo.read"));
    let b = set(
        "B",
        "other.com",
        &rule(None, None, Some("/x"), "repo.write"),
    );
    let c = rule(Some("api"), None, Some("/x"), "repo.write");
    let c = set("C", "acme.com", &c);
    assert!(load(&[&a, &b, &c]).await.is_ok());
}

#[tokio::test]
async fn exact_subdomain_and_bare_rule_on_the_same_host_conflict() {
    // These rules name the same origin and must be checked against each other.
    let a = set(
        "A",
        "eu.acme.com",
        &rule(Some("api"), None, None, "repo.read"),
    );
    let b = set(
        "B",
        "api.eu.acme.com",
        &rule(None, None, None, "repo.write"),
    );
    assert!(matches!(
        load(&[&a, &b]).await,
        Err(LoadError::ConflictingRules { .. })
    ));
}

#[tokio::test]
async fn set_order_does_not_change_classification() {
    let payments = set(
        "Payments",
        "acme.com",
        &format!(
            "{}{}{}",
            rule(Some("api"), None, Some("/v1/*"), "payment.read"),
            rule(Some("api"), None, Some("/v1/refunds/*"), "payment.refund"),
            rule(
                Some("api"),
                Some("POST"),
                Some("/v1/charges"),
                "payment.create"
            ),
        ),
    );
    let repos = set(
        "Repos",
        "acme.com",
        &format!(
            "{}{}",
            rule(Some("*"), None, None, "repo.read"),
            rule(Some("git"), Some("POST"), Some("/*"), "repo.write"),
        ),
    );
    let forward = load(&[&payments, &repos]).await.unwrap();
    let reverse = load(&[&repos, &payments]).await.unwrap();
    for (method, host, path) in [
        ("GET", "api.acme.com", "/v1/charges"),
        ("POST", "api.acme.com", "/v1/charges"),
        ("POST", "api.acme.com", "/v1/refunds/r1"),
        ("POST", "git.acme.com", "/org/repo"),
        ("GET", "git.acme.com", "/org/repo"),
        ("GET", "x.y.acme.com", "/"),
        ("GET", "acme.com", "/"),
    ] {
        assert_eq!(
            forward.classify(method, host, path).await,
            reverse.classify(method, host, path).await,
            "{method} {host}{path}"
        );
    }
}

#[tokio::test]
async fn invalid_set_errors_identify_set_name_and_rule() {
    let good = set("Good", "acme.com", &rule(None, None, None, "repo.read"));
    let bad = set(
        "Bad",
        "acme.com",
        &format!(
            "{}{}",
            rule(None, None, None, "repo.read"),
            rule(None, None, None, "payment.delete"),
        ),
    );
    match load(&[&good, &bad]).await {
        Err(LoadError::InvalidSet {
            set: 1,
            name: Some(name),
            error: SetError::UnknownActionClass { rule: 1, .. },
        }) => assert_eq!(name, "Bad"),
        other => panic!("unexpected {:?}", other.err()),
    }

    let unparsable = "format_version = 1\nnme = \"typo\"";
    match load(&[&good, unparsable]).await {
        Err(
            error @ LoadError::InvalidSet {
                set: 1, name: None, ..
            },
        ) => assert!(error.to_string().starts_with("mapping set 1: invalid TOML")),
        other => panic!("unexpected {:?}", other.err()),
    }

    let invalid_method = set(
        "Bad method",
        "acme.com",
        &rule(None, Some("GET /"), None, "repo.read"),
    );
    match load(&[&invalid_method]).await {
        Err(LoadError::InvalidSet {
            error:
                SetError::InvalidRule {
                    rule: 0,
                    field: "method",
                    value,
                },
            ..
        }) => assert_eq!(value, "GET /"),
        other => panic!("unexpected {:?}", other.err()),
    }
}
