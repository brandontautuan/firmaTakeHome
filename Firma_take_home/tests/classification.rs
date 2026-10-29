//! Host matching, precedence, and concurrent use through the public API.

use std::sync::Arc;

use action_classifier::{Classifier, load};

const ACME: &str = r#"
format_version = 1
name = "Acme"
description = "Acme API"
host = "acme.com"

[[rules]]
subdomain = "*"
action_class = "repo.read"

[[rules]]
subdomain = "api"
path = "/v1/*"
action_class = "payment.read"

[[rules]]
subdomain = "api"
method = "POST"
path = "/v1/*"
action_class = "payment.create"

[[rules]]
subdomain = "api"
path = "/v1/refunds/*"
action_class = "payment.refund"

[[rules]]
subdomain = "api"
path = "/v1/*/send"
action_class = "communication.external.send"

[[rules]]
path = "/pricing"
action_class = "payment.read"
"#;

#[tokio::test]
async fn host_patterns_respect_label_boundaries() {
    let c = load(&[ACME]).await.unwrap();
    let cases = [
        ("API.Acme.COM", Some("payment.read")),
        ("api.acme.com.", Some("payment.read")),
        ("api.acme.com:8443", Some("payment.read")),
        ("a.b.acme.com", Some("repo.read")),
        ("evilacme.com", None),
        ("api.acme.com.evil.com", None),
        ("acme.com.evil.com", None),
        ("user@api.acme.com", None),
        ("192.0.2.1", None),
    ];
    for (host, expected) in cases {
        assert_eq!(c.classify("GET", host, "/v1/x").await, expected, "{host}");
    }
    // `*` does not cover the bare host, and the bare-host rule only covers it.
    assert_eq!(c.classify("GET", "acme.com", "/v1/x").await, None);
    assert_eq!(
        c.classify("GET", "acme.com", "/pricing").await,
        Some("payment.read")
    );
    assert_eq!(
        c.classify("GET", "www.acme.com", "/pricing").await,
        Some("repo.read")
    );
}

#[tokio::test]
async fn most_specific_rule_wins() {
    let c = load(&[ACME]).await.unwrap();
    let cases = [
        // Exact subdomain beats wildcard subdomain even with a broader path.
        ("GET", "/v1/x", Some("payment.read")),
        // Explicit method beats omitted method once host and path tie.
        ("POST", "/v1/x", Some("payment.create")),
        // More literal characters beat a method on a broader pattern.
        ("POST", "/v1/refunds/r1", Some("payment.refund")),
        ("GET", "/v1/msg/send", Some("communication.external.send")),
        // A path no exact-host rule covers falls back to the wildcard host.
        ("GET", "/v2/x", Some("repo.read")),
    ];
    for (method, path, expected) in cases {
        assert_eq!(
            c.classify(method, "api.acme.com", path).await,
            expected,
            "{method} {path}"
        );
    }
}

#[tokio::test]
async fn malformed_requests_never_panic_or_classify() {
    let c = load(&[ACME]).await.unwrap();
    let long = "a".repeat(64 * 1024);
    let inputs: [(&str, &str, &str); 8] = [
        ("", "api.acme.com", "/v1/x"),
        ("GE T", "api.acme.com", "/v1/x"),
        ("GET", "", "/v1/x"),
        ("GET", "api.acme.com:", "/v1/x"),
        ("GET", "api.acme.com:99999", "/v1/x"),
        ("GET", "аpi.acme.com", "/v1/x"),
        ("GET", "api.acme.com", "/v1/\u{1F600}"),
        ("GET", "api.acme.com", "v1/x"),
    ];
    for (method, host, path) in inputs {
        assert_eq!(
            c.classify(method, host, path).await,
            None,
            "{method:?} {host:?} {path:?}"
        );
    }
    for value in [long.as_str(), "%", "%%%", "\0", "\u{10FFFF}"] {
        let _ = c.classify(value, value, value).await;
        let _ = c.classify("GET", "api.acme.com", value).await;
    }
}

#[test]
fn classifier_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Classifier>();
}

#[test]
fn concurrent_classification_is_consistent() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let classifier = Arc::new(runtime.block_on(load(&[ACME])).unwrap());
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let classifier = Arc::clone(&classifier);
            scope.spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap();
                for _ in 0..1_000 {
                    let (create, refund) = runtime.block_on(async {
                        (
                            classifier.classify("POST", "api.acme.com", "/v1/x").await,
                            classifier
                                .classify("POST", "api.acme.com", "/v1/refunds/r")
                                .await,
                        )
                    });
                    assert_eq!(create, Some("payment.create"));
                    assert_eq!(refund, Some("payment.refund"));
                }
            });
        }
    });
}

#[tokio::test]
async fn deeper_wildcard_base_host_wins_before_path_specificity() {
    let broad = r#"
format_version = 1
name = "Broad"
host = "co.uk"

[[rules]]
subdomain = "*"
path = "/v1/*"
action_class = "llm.inference"
"#;
    let stripe = r#"
format_version = 1
name = "Stripe"
host = "stripe.co.uk"

[[rules]]
subdomain = "*"
path = "/v1/*"
action_class = "payment.read"
"#;
    let classifier = load(&[broad, stripe]).await.unwrap();
    assert_eq!(
        classifier
            .classify("POST", "api.stripe.co.uk", "/v1/refunds/x")
            .await,
        Some("payment.read")
    );
}

#[tokio::test]
async fn request_size_limits_fail_closed_at_the_boundary() {
    let classifier = load(&[ACME]).await.unwrap();
    let accepted = format!("/v1/{}", "a".repeat(8_188));
    let rejected = format!("/v1/{}", "a".repeat(8_189));
    assert_eq!(accepted.len(), 8_192);
    assert_eq!(
        classifier.classify("GET", "api.acme.com", &accepted).await,
        Some("payment.read")
    );
    assert_eq!(
        classifier.classify("GET", "api.acme.com", &rejected).await,
        None
    );
    assert_eq!(
        classifier
            .classify(&"G".repeat(33), "api.acme.com", "/v1/x")
            .await,
        None
    );
}
