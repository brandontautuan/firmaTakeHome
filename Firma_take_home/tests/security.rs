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
    assert_eq!(
        c.classify("DELETE", "api.acme.com", "/v1/charges/ch_1")
            .await,
        Some("payment.refund")
    );
    // Folded, these are a refund; read case-sensitively they reach only the
    // method-less payment.read rule. Neither reading may be assumed.
    for method in ["delete", "Delete"] {
        assert_eq!(
            c.classify(method, "api.acme.com", "/v1/charges/ch_1").await,
            None,
            "{method}"
        );
    }
}

#[tokio::test]
async fn method_case_cannot_reach_a_less_sensitive_method_specific_rule() {
    // A case-sensitive router (Go's `ServeMux`, for one) sends `get` to the
    // catch-all refund handler, while folding would report it as a read.
    let c = load(&[r#"
format_version = 1
name = "Method specific read"
host = "acme.com"

[[rules]]
path = "/x"
action_class = "payment.refund"

[[rules]]
method = "GET"
path = "/x"
action_class = "payment.read"
"#])
    .await
    .unwrap();
    assert_eq!(
        c.classify("GET", "acme.com", "/x").await,
        Some("payment.read")
    );
    assert_eq!(
        c.classify("POST", "acme.com", "/x").await,
        Some("payment.refund")
    );
    for method in ["get", "Get", "gEt"] {
        assert_eq!(c.classify(method, "acme.com", "/x").await, None, "{method}");
    }
    // Both readings agree when no method-specific rule is involved.
    assert_eq!(
        c.classify("post", "acme.com", "/x").await,
        Some("payment.refund")
    );
}

#[tokio::test]
async fn method_case_classifies_when_both_readings_agree() {
    let c = load(&[r#"
format_version = 1
name = "Exact method only"
host = "acme.com"

[[rules]]
method = "PATCH"
path = "/x"
action_class = "repo.write"

[[rules]]
method = "POST"
path = "/y"
action_class = "repo.write"

[[rules]]
path = "/y"
action_class = "repo.write"
"#])
    .await
    .unwrap();
    // Fetch leaves `patch` lowercase. Nothing else claims this request.
    assert_eq!(
        c.classify("patch", "acme.com", "/x").await,
        Some("repo.write")
    );
    assert_eq!(
        c.classify("post", "acme.com", "/y").await,
        Some("repo.write")
    );
    assert_eq!(c.classify("get", "acme.com", "/x").await, None);
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
    // The wildcard must not absorb the empty segment either.
    let c = load(&[&ACME.replace("/v1/payouts", "/a/*/b")])
        .await
        .unwrap();
    assert_eq!(
        c.classify("GET", "api.acme.com", "/a/x/b").await,
        Some("payment.create")
    );
    assert_eq!(c.classify("GET", "api.acme.com", "/a//b").await, None);
}

#[tokio::test]
async fn configured_patterns_follow_the_request_path_rules() {
    for pattern in [
        "//x",
        "/v1//x",
        "/x//",
        "/v1/*//x",
        "/v1/%2e//x",
        "/v1/%2fx",
        "/v1/%5Cx",
        "/v1\\\\x",
        "/v1/x;y",
        "/v1/x?y",
        "/v1/x#y",
        "/v1/../x",
        "/v1/./x",
        "/v1/%2E%2E/x",
        "/v1/%zz",
        "/v1/x y",
        "relative",
    ] {
        let set = ACME.replace("/v1/payouts", pattern);
        assert!(load(&[&set]).await.is_err(), "{pattern}");
    }
}

#[tokio::test]
async fn trailing_slash_that_changes_the_class_is_unclassified() {
    let c = load(&[ACME]).await.unwrap();
    // A request without a slash is classified as sent.
    assert_eq!(
        c.classify("POST", "api.acme.com", "/v1/payouts").await,
        Some("payment.create")
    );
    assert_eq!(
        c.classify("POST", "api.acme.com", "/v1/payouts/").await,
        None
    );
    // No disagreement: both spellings are payment.read.
    assert_eq!(
        c.classify("GET", "api.acme.com", "/v1/balance").await,
        Some("payment.read")
    );
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
async fn path_parameters_are_unclassified() {
    let c = load(&[ACME]).await.unwrap();
    for path in ["/v1/refunds;x/re_1", "/v1/refunds;/re_1"] {
        assert_eq!(
            c.classify("POST", "api.acme.com", path).await,
            None,
            "{path:?}"
        );
    }

    let invalid_pattern = ACME.replace("path = \"/v1/payouts\"", "path = \"/v1/payouts;v=1\"");
    assert!(load(&[&invalid_pattern]).await.is_err());
}

#[tokio::test]
async fn case_insensitive_routing_disagreements_are_unclassified() {
    let c = load(&[ACME]).await.unwrap();
    assert_eq!(
        c.classify("POST", "api.acme.com", "/v1/REFUNDS/re_1").await,
        None
    );
    // Check combinations of case and trailing-slash ambiguity too.
    assert_eq!(
        c.classify("POST", "api.acme.com", "/v1/PAYOUTS/").await,
        None
    );

    let capitalized_refunds = ACME.replace("/v1/refunds/*", "/v1/Refunds/*");
    let c = load(&[&capitalized_refunds]).await.unwrap();
    assert_eq!(
        c.classify("POST", "api.acme.com", "/v1/Refunds/r1").await,
        Some("payment.refund")
    );
    assert_eq!(
        c.classify("POST", "api.acme.com", "/v1/refunds/r1").await,
        None
    );

    let uppercase_id_route = r#"
format_version = 1
name = "Case sensitive IDs"
host = "acme.com"

[[rules]]
subdomain = "api"
path = "/v1/IDs/*"
action_class = "repo.read"
"#;
    let c = load(&[uppercase_id_route]).await.unwrap();
    assert_eq!(
        c.classify("GET", "api.acme.com", "/v1/IDs/AbC").await,
        Some("repo.read")
    );

    let twilio_style = r#"
format_version = 1
name = "Twilio style"
host = "example.com"

[[rules]]
subdomain = "api"
method = "GET"
path = "/2010-04-01/*"
action_class = "repo.read"

[[rules]]
subdomain = "api"
method = "GET"
path = "/2010-04-01/Accounts/*/Messages.json"
action_class = "communication.external.send"
"#;
    let c = load(&[twilio_style]).await.unwrap();
    assert_eq!(
        c.classify(
            "GET",
            "api.example.com",
            "/2010-04-01/Accounts/AC1/Messages.json"
        )
        .await,
        Some("communication.external.send")
    );
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

#[tokio::test]
async fn patterns_differing_only_by_case_do_not_depend_on_rule_order() {
    let set = |first: (&str, &str), second: (&str, &str)| {
        format!(
            "format_version = 1\nname = \"Case\"\nhost = \"acme.com\"\n\
             [[rules]]\npath = \"{}\"\naction_class = \"{}\"\n\
             [[rules]]\npath = \"{}\"\naction_class = \"{}\"\n",
            first.0, first.1, second.0, second.1
        )
    };
    let upper = ("/v1/Refunds", "payment.refund");
    let lower = ("/v1/refunds", "payment.read");
    let forward = load(&[&set(upper, lower)]).await.unwrap();
    let reverse = load(&[&set(lower, upper)]).await.unwrap();
    for path in ["/v1/Refunds", "/v1/refunds", "/V1/REFUNDS"] {
        // A case-insensitive router cannot tell these rules apart.
        assert_eq!(
            forward.classify("GET", "acme.com", path).await,
            None,
            "{path}"
        );
        assert_eq!(
            reverse.classify("GET", "acme.com", path).await,
            None,
            "{path}"
        );
    }
}

#[tokio::test]
async fn hosts_ending_in_an_ipv4_number_are_rejected_in_configuration() {
    for host in ["0x7f.0x1", "x.0X7F000001", "acme.0x", "acme.0xAB", "acme.1"] {
        let set = ACME.replace("acme.com", host);
        assert!(load(&[&set]).await.is_err(), "{host}");
    }
    // A hex-looking label is an ordinary name anywhere but the final position.
    let set = ACME.replace("acme.com", "0x7f.acme.com");
    assert!(load(&[&set]).await.is_ok());
}
