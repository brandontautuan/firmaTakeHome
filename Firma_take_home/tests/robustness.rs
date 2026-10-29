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

    for _ in 0..2_000 {
        let method = generated_text(&mut state, 32);
        let host = generated_text(&mut state, 128);
        let path = generated_text(&mut state, 256);
        let first = classifier.classify(&method, &host, &path).await;
        let second = classifier.classify(&method, &host, &path).await;
        assert_eq!(first, second, "{method:?} {host:?} {path:?}");
    }
}

#[tokio::test]
async fn generated_inputs_are_independent_of_mapping_set_order() {
    let forward = load(&[PAYMENTS, REPOS]).await.unwrap();
    let reverse = load(&[REPOS, PAYMENTS]).await.unwrap();
    let mut state = 0x1234_5678_9ABC_DEF0;

    for _ in 0..2_000 {
        let method = generated_text(&mut state, 32);
        let host = generated_text(&mut state, 128);
        let path = generated_text(&mut state, 256);
        assert_eq!(
            forward.classify(&method, &host, &path).await,
            reverse.classify(&method, &host, &path).await,
            "{method:?} {host:?} {path:?}"
        );
    }
}
