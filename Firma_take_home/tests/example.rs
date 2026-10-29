//! Example tests that ship with the starter. They show the API in use.

use action_classifier::load;

const ACME: &str = r#"
format_version = 1
name = "Acme Payments"
description = "Acme payments API"
host = "acme.com"

[[rules]]
method = "GET"
subdomain = "api"
path = "/v1/payment_intents"
action_class = "payment.read"

[[rules]]
subdomain = "api"
path = "/v1/refunds/*"
action_class = "payment.refund"

[[rules]]
path = "/pricing"
action_class = "payment.read"
"#;

#[tokio::test]
async fn exact_rule_matches() {
    let c = load(&[ACME]).await.unwrap();
    assert_eq!(
        c.classify("GET", "api.acme.com", "/v1/payment_intents")
            .await,
        Some("payment.read")
    );
}

#[tokio::test]
async fn method_less_rule_matches_any_method() {
    let c = load(&[ACME]).await.unwrap();
    assert_eq!(
        c.classify("DELETE", "api.acme.com", "/v1/refunds/re_1")
            .await,
        Some("payment.refund")
    );
}

#[tokio::test]
async fn rule_without_subdomain_applies_to_the_host_itself() {
    let c = load(&[ACME]).await.unwrap();
    assert_eq!(
        c.classify("GET", "acme.com", "/pricing").await,
        Some("payment.read")
    );
}

#[tokio::test]
async fn unmatched_request_is_unclassified() {
    let c = load(&[ACME]).await.unwrap();
    assert_eq!(
        c.classify("GET", "api.acme.com", "/v2/anything").await,
        None
    );
}
