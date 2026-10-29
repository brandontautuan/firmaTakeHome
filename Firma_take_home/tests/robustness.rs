//! Deterministic generated-input checks for the public API.

use action_classifier::load;

const PAYMENTS: &str = r#"
format_version = 1
name = "Payments"
host = "acme.com"

[[rules]]
subdomain = "api"
path = "/v1/*"
action_class = "payment.read"

[[rules]]
subdomain = "api"
method = "POST"
path = "/v1/refunds/*"
action_class = "payment.refund"
"#;

const REPOS: &str = r#"
format_version = 1
name = "Repos"
host = "acme.com"

[[rules]]
subdomain = "*"
action_class = "repo.read"
"#;

/// A small, repeatable generator keeps this robustness coverage dependency-free.
fn generated_text(state: &mut u64, maximum_length: usize) -> String {
    const ALPHABET: &[char] = &[
        'a', 'Z', '0', '/', '.', '*', '%', ':', '@', ' ', '\\', '\0', '\n', 'é', '🦀',
    ];
    let length = usize::try_from(next(state)).unwrap_or(0) % (maximum_length + 1);
    (0..length)
        .map(|_| ALPHABET[usize::try_from(next(state)).unwrap_or(0) % ALPHABET.len()])
        .collect()
}

fn generated_request(state: &mut u64) -> (String, String, String) {
    let method =
        ["GET", "POST", "DELETE", "get"][usize::try_from(next(state)).unwrap_or(0) % 4].to_owned();
    let host = ["api.acme.com", "x.acme.com", "a.b.acme.com", "acme.com"]
        [usize::try_from(next(state)).unwrap_or(0) % 4]
        .to_owned();
    let path = [
        "/v1/x",
        "/v1/refunds/r1",
        "/v1/%72efunds/r1",
        "/v1/../v1/x",
        "/",
    ][usize::try_from(next(state)).unwrap_or(0) % 5]
        .to_owned();
    if next(state) % 5 == 0 {
        (
            generated_text(state, 32),
            generated_text(state, 128),
            generated_text(state, 256),
        )
    } else {
        (method, host, path)
    }
}

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[tokio::test]
async fn generated_inputs_never_panic_and_are_deterministic() {
    let classifier = load(&[PAYMENTS, REPOS]).await.unwrap();
    let mut state = 0x5EED_CAFE_BAAD_F00D;
    let mut classified = 0;

    for _ in 0..2_000 {
        let (method, host, path) = generated_request(&mut state);
        let first = classifier.classify(&method, &host, &path).await;
        let second = classifier.classify(&method, &host, &path).await;
        assert_eq!(first, second, "{method:?} {host:?} {path:?}");
        assert!(first.is_none() || action_classifier::ACTION_CLASSES.contains(&first.unwrap()));
        classified += usize::from(first.is_some());
    }
    assert!(
        classified >= 500,
        "only {classified} generated requests matched"
    );
}

#[tokio::test]
async fn generated_inputs_are_independent_of_mapping_set_order() {
    let forward = load(&[PAYMENTS, REPOS]).await.unwrap();
    let reverse = load(&[REPOS, PAYMENTS]).await.unwrap();
    let mut state = 0x1234_5678_9ABC_DEF0;

    for _ in 0..2_000 {
        let (method, host, path) = generated_request(&mut state);
        assert_eq!(
            forward.classify(&method, &host, &path).await,
            reverse.classify(&method, &host, &path).await,
            "{method:?} {host:?} {path:?}"
        );
    }
}
