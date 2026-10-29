//! Requests that spell the same operation differently must not reach a
//! broader, less sensitive rule than the canonical spelling does.

use action_classifier::load;

const ACME: &str = r#"
format_version = 1
name = "Acme Payments"
description = "Acme payments API"
host = "acme.com"

[[rules]]
subdomain = "api"
path = "/v1/*"
action_class = "payment.read"

[[rules]]
subdomain = "api"
path = "/v1/refunds/*"
action_class = "payment.refund"

[[rules]]
subdomain = "api"
method = "DELETE"
path = "/v1/charges/*"
action_class = "payment.refund"

[[rules]]
subdomain = "api"
path = "/v1/payouts"
action_class = "payment.create"
"#;

#[tokio::test]
async fn percent_encoded_unreserved_characters_match_their_decoded_form() {
    let c = load(&[ACME]).await.unwrap();
    for path in [
        "/v1/%72efunds/x",
        "/v1/%72%65%66%75%6E%64%73/x",
        "/v1/refunds/%78",
    ] {
        assert_eq!(
            c.classify("POST", "api.acme.com", path).await,
            Some("payment.refund"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn method_case_does_not_fall_through_to_method_less_rule() {
    let c = load(&[ACME]).await.unwrap();
    for method in ["DELETE", "delete", "Delete"] {
        assert_eq!(
            c.classify(method, "api.acme.com", "/v1/charges/ch_1").await,
            Some("payment.refund"),
            "{method}"
        );
    }
}

#[tokio::test]
async fn empty_path_segments_are_unclassified() {
    let c = load(&[ACME]).await.unwrap();
    for path in ["/v1//refunds/x", "//v1/refunds/x", "/v1/refunds//x"] {
        assert_eq!(
            c.classify("POST", "api.acme.com", path).await,
            None,
            "{path}"
        );
    }
}

#[tokio::test]
async fn trailing_slash_that_changes_the_class_is_unclassified() {
    let c = load(&[ACME]).await.unwrap();
    assert_eq!(
        c.classify("POST", "api.acme.com", "/v1/payouts").await,
        Some("payment.create")
    );
    // `/v1/payouts/` alone would match `/v1/*` (payment.read).
    assert_eq!(
        c.classify("POST", "api.acme.com", "/v1/payouts/").await,
        None
    );
    // No disagreement: both spellings are payment.read.
    assert_eq!(
        c.classify("GET", "api.acme.com", "/v1/balance/").await,
        Some("payment.read")
    );
}

#[tokio::test]
async fn dot_segments_resolve_before_matching() {
    let c = load(&[ACME]).await.unwrap();
    assert_eq!(
        c.classify("POST", "api.acme.com", "/v1/balance/../refunds/x")
            .await,
        Some("payment.refund")
    );
    assert_eq!(
        c.classify("POST", "api.acme.com", "/v1/balance/%2e%2e/refunds/x")
            .await,
        Some("payment.refund")
    );
}

#[tokio::test]
async fn ambiguous_or_malformed_paths_are_unclassified() {
    let c = load(&[ACME]).await.unwrap();
    for path in [
        "/v1/refunds%2fx",
        "/v1\\refunds\\x",
        "/v1/refunds/%zz",
        "/v1/re funds/x",
    ] {
        assert_eq!(
            c.classify("POST", "api.acme.com", path).await,
            None,
            "{path:?}"
        );
    }
}

#[tokio::test]
async fn empty_rules_list_is_rejected() {
    let empty = r#"
format_version = 1
name = "Empty"
description = "No rules"
host = "acme.com"
rules = []
"#;
    assert!(load(&[empty]).await.is_err());
}
