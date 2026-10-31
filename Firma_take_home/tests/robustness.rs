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

/// Classifies every well-formed request, so a `None` below can only come from
/// rejecting the malformed component rather than from a missing rule.
const CATCH_ALL: &str = r#"
format_version = 1
name = "Catch all"
host = "acme.com"

[[rules]]
action_class = "repo.read"

[[rules]]
subdomain = "*"
action_class = "repo.read"
"#;

fn pick<T: Copy>(state: &mut u64, values: &[T]) -> T {
    values[usize::try_from(next(state)).unwrap_or(0) % values.len()]
}

fn below(state: &mut u64, limit: usize) -> usize {
    usize::try_from(next(state)).unwrap_or(0) % limit
}

fn chance(state: &mut u64, one_in: u64) -> bool {
    next(state) % one_in == 0
}

/// Inserts `value` at a random character boundary of `text`.
fn insert_at_random(state: &mut u64, text: &str, value: &str) -> String {
    let boundaries = text
        .char_indices()
        .map(|(index, _)| index)
        .chain([text.len()])
        .collect::<Vec<_>>();
    let at = boundaries[below(state, boundaries.len())];
    format!("{}{value}{}", &text[..at], &text[at..])
}

fn generated_token(state: &mut u64, minimum: usize, maximum: usize) -> String {
    const TOKEN: &[u8] = b"abcXYZ019!#$%&'*+-.^_`|~";
    let length = minimum + below(state, maximum - minimum + 1);
    (0..length)
        .map(|_| char::from(TOKEN[below(state, TOKEN.len())]))
        .collect()
}

fn generated_label(state: &mut u64) -> String {
    const LABEL: &[u8] = b"abcxyzABC019";
    let length = 1 + below(state, 8);
    (0..length)
        .map(|_| char::from(LABEL[below(state, LABEL.len())]))
        .collect()
}

/// A path of non-empty segments that normalizes to itself. Segments avoid hex
/// digits so an inserted `%` cannot accidentally form a valid escape.
fn generated_path(state: &mut u64) -> String {
    let segments = 1 + below(state, 5);
    (0..segments)
        .map(|_| {
            format!(
                "/{}",
                pick(state, &["v1", "x", "y", "zz", "items", "um_1", "~t", "s-u"])
            )
        })
        .collect()
}

#[tokio::test]
async fn generated_methods_classify_only_when_they_are_valid_tokens() {
    let c = load(&[CATCH_ALL]).await.unwrap();
    let mut state = 0x0BAD_C0DE_0000_0001;
    for _ in 0..2_000 {
        let valid = generated_token(&mut state, 1, 32);
        assert_eq!(
            c.classify(&valid, "acme.com", "/").await,
            Some("repo.read"),
            "{valid:?}"
        );

        let invalid = pick(
            &mut state,
            &[" ", "\t", "\n", "\r", "\0", "/", ":", "(", "\"", "é", "🦀"],
        );
        let malformed = insert_at_random(&mut state, &valid, invalid);
        assert_eq!(
            c.classify(&malformed, "acme.com", "/").await,
            None,
            "{malformed:?}"
        );

        let too_long = generated_token(&mut state, 33, 64);
        assert_eq!(c.classify(&too_long, "acme.com", "/").await, None);
    }
    assert_eq!(c.classify("", "acme.com", "/").await, None);
}

#[tokio::test]
async fn generated_hosts_classify_only_when_they_are_dns_names_under_the_base() {
    let c = load(&[CATCH_ALL]).await.unwrap();
    let mut state = 0x0BAD_C0DE_0000_0002;
    for _ in 0..2_000 {
        let label = generated_label(&mut state);
        let suffix = pick(&mut state, &["", ":443", ":0", ":65535", ".", ".:8443"]);
        let valid = format!("{label}.ACME.com{suffix}");
        assert_eq!(
            c.classify("GET", &valid, "/").await,
            Some("repo.read"),
            "{valid:?}"
        );

        let malformed = match below(&mut state, 8) {
            0 => {
                let invalid = pick(&mut state, &[" ", "_", "\0", "é", "/", "%", "*", "\\"]);
                let name = insert_at_random(&mut state, &label, invalid);
                format!("{name}.acme.com")
            }
            1 => format!("{label}..acme.com"),
            2 => format!("-{label}.acme.com"),
            3 => format!("{label}-.acme.com"),
            4 => format!("{label}@acme.com"),
            5 => format!(
                "{label}.acme.com{}",
                pick(
                    &mut state,
                    &[":", ":65536", ":x", ":-1", ":+1", "..", ":1:2"]
                )
            ),
            6 => format!("{}.{label}.acme.com", "a".repeat(64)),
            _ => format!("{}.acme.com", format!("{label}.").repeat(64)),
        };
        assert_eq!(
            c.classify("GET", &malformed, "/").await,
            None,
            "{malformed:?}"
        );

        // Well-formed names that are outside the configured base.
        for outside in [
            format!("{label}acme.com"),
            format!("acme.com.{label}.net"),
            format!("{label}.acme.co"),
        ] {
            assert_eq!(c.classify("GET", &outside, "/").await, None, "{outside:?}");
        }
    }
}

#[tokio::test]
async fn generated_paths_classify_only_when_they_are_unambiguous() {
    let c = load(&[CATCH_ALL]).await.unwrap();
    let mut state = 0x0BAD_C0DE_0000_0003;
    for _ in 0..2_000 {
        let valid = generated_path(&mut state);
        assert_eq!(
            c.classify("GET", "acme.com", &valid).await,
            Some("repo.read"),
            "{valid:?}"
        );

        let invalid = pick(
            &mut state,
            &[
                "\\", ";", "%2f", "%2F", "%5c", "%5C", "%zz", "%g1", " ", "\t", "\n", "\0", "é",
                "🦀", "\u{7f}",
            ],
        );
        let malformed = insert_at_random(&mut state, &valid, invalid);
        assert_eq!(
            c.classify("GET", "acme.com", &malformed).await,
            None,
            "{malformed:?}"
        );

        let truncated = format!("{valid}{}", pick(&mut state, &["%", "%a", "%2"]));
        assert_eq!(c.classify("GET", "acme.com", &truncated).await, None);

        let relative = valid.trim_start_matches('/');
        assert_eq!(c.classify("GET", "acme.com", relative).await, None);

        let duplicated = valid.replacen('/', "//", 1 + below(&mut state, 3));
        assert_eq!(
            c.classify("GET", "acme.com", &duplicated).await,
            None,
            "{duplicated:?}"
        );
    }
}

#[tokio::test]
async fn generated_arbitrary_text_near_the_size_limit_never_panics() {
    let c = load(&[CATCH_ALL]).await.unwrap();
    let mut state = 0x0BAD_C0DE_0000_0004;
    for _ in 0..500 {
        // Multi-byte characters straddling the 8 KiB boundary must not split.
        let filler = pick(&mut state, &["a", "é", "🦀", "/a", "%", "/.."]);
        let mut path = format!("/{}", filler.repeat(8_192 / filler.len()));
        let mut end = 8_185 + below(&mut state, 16);
        while !path.is_char_boundary(end) {
            end -= 1;
        }
        path.truncate(end);
        let path = format!("{path}{}", generated_text(&mut state, 8));
        let method = generated_text(&mut state, 40);
        let host = generated_text(&mut state, 300);
        if let Some(class) = c.classify(&method, &host, &path).await {
            assert!(action_classifier::ACTION_CLASSES.contains(&class));
        }
        let _ = c.classify("GET", "acme.com", &path).await;
    }
}

/// Independent reference for the `*` contract: zero or more of any byte.
fn wildcard_oracle(pattern: &[u8], value: &[u8]) -> bool {
    let mut reachable = vec![false; value.len() + 1];
    reachable[0] = true;
    for &byte in pattern {
        if byte == b'*' {
            for index in 1..reachable.len() {
                reachable[index] |= reachable[index - 1];
            }
        } else {
            for index in (1..reachable.len()).rev() {
                reachable[index] = reachable[index - 1] && value[index - 1] == byte;
            }
            reachable[0] = false;
        }
    }
    reachable[value.len()]
}

#[tokio::test]
async fn generated_wildcards_agree_with_a_reference_matcher() {
    const SET: &str = "format_version = 1\nname = \"W\"\nhost = \"acme.com\"\n";
    let mut state = 0x0BAD_C0DE_0000_0005;
    let (mut matched, mut unmatched) = (0, 0);
    for _ in 0..1_000 {
        let pattern: String = (0..1 + below(&mut state, 4))
            .map(|_| {
                let segment: String = (0..1 + below(&mut state, 3))
                    .map(|_| pick(&mut state, &["a", "b", "A", "*", "**"]))
                    .collect();
                format!("/{segment}")
            })
            .collect();
        let pattern = if chance(&mut state, 4) {
            format!("{pattern}/")
        } else {
            pattern
        };
        let set = format!("{SET}[[rules]]\npath = {pattern:?}\naction_class = \"repo.read\"\n");
        let c = load(&[&set]).await.unwrap();

        for _ in 0..8 {
            // Half of the requests instantiate the pattern, so both outcomes
            // stay well represented. Fills may legitimately create `//`.
            let path = if chance(&mut state, 2) {
                let mut filled = String::new();
                for character in pattern.chars() {
                    if character == '*' {
                        filled.push_str(pick(&mut state, &["", "a", "b", "ab", "a/b", "/b", "a/"]));
                    } else {
                        filled.push(character);
                    }
                }
                filled
            } else {
                (0..1 + below(&mut state, 4))
                    .map(|_| format!("/{}", pick(&mut state, &["a", "b", "A", "ab", "ba"])))
                    .collect()
            };
            let expected = (!path.contains("//")
                && wildcard_oracle(pattern.as_bytes(), path.as_bytes()))
            .then_some("repo.read");
            assert_eq!(
                c.classify("GET", "acme.com", &path).await,
                expected,
                "pattern {pattern:?} path {path:?}"
            );
            if expected.is_some() {
                matched += 1;
            } else {
                unmatched += 1;
            }
        }
    }
    assert!(
        matched >= 1_000 && unmatched >= 1_000,
        "{matched}/{unmatched}"
    );
}

/// A rule as TOML. `method` and `path` may be omitted; the pool deliberately
/// includes spellings that differ only by case or a trailing slash.
fn generated_rule(state: &mut u64) -> String {
    let mut rule = String::from("[[rules]]\n");
    if let Some(method) = pick(state, &[None, None, Some("GET"), Some("POST"), Some("get")]) {
        rule += &format!("method = \"{method}\"\n");
    }
    if let Some(subdomain) = pick(state, &[None, Some("api"), Some("api"), Some("*")]) {
        rule += &format!("subdomain = \"{subdomain}\"\n");
    }
    if let Some(path) = pick(
        state,
        &[
            None,
            Some("/v1/x"),
            Some("/v1/X"),
            Some("/V1/x"),
            Some("/v1/x/"),
            Some("/v1/*"),
            Some("/V1/*"),
            Some("/v1/x/*"),
            Some("/v1/*/y"),
            Some("/v1/*/Y"),
        ],
    ) {
        rule += &format!("path = \"{path}\"\n");
    }
    let class =
        action_classifier::ACTION_CLASSES[below(state, action_classifier::ACTION_CLASSES.len())];
    rule + &format!("action_class = \"{class}\"\n")
}

fn mapping_set(index: usize, rules: &[String]) -> String {
    format!(
        "format_version = 1\nname = \"S{index}\"\nhost = \"acme.com\"\n{}",
        rules.concat()
    )
}

const REQUEST_METHODS: &[&str] = &["GET", "get", "Get", "POST", "post", "DELETE", "delete"];
const REQUEST_HOSTS: &[&str] = &["api.acme.com", "API.acme.com:443", "x.acme.com", "acme.com"];
const REQUEST_PATHS: &[&str] = &[
    "/", "/v1/x", "/v1/X", "/V1/x", "/V1/X", "/v1/x/", "/v1/X/", "/v1/x/y", "/v1/x/Y", "/v1/q/y",
    "/V1/q/Y", "/v2",
];

#[tokio::test]
async fn generated_rule_sets_classify_identically_in_every_order() {
    let mut state = 0x0BAD_C0DE_0000_0006;
    let mut loaded = 0;
    for _ in 0..400 {
        let mut rules = (0..2 + below(&mut state, 6))
            .map(|_| generated_rule(&mut state))
            .collect::<Vec<_>>();
        let forward = load(&[&mapping_set(0, &rules)]).await;

        // Fisher-Yates over the rules, then split them across two sets.
        for index in (1..rules.len()).rev() {
            rules.swap(index, below(&mut state, index + 1));
        }
        let (first, second) = rules.split_at(1 + below(&mut state, rules.len() - 1));
        let (first, second) = (mapping_set(1, first), mapping_set(2, second));
        let reordered = load(&[&second, &first]).await;

        let (forward, reordered) = match (forward, reordered) {
            (Ok(forward), Ok(reordered)) => (forward, reordered),
            (Err(_), Err(_)) => continue,
            (forward, reordered) => panic!(
                "load outcome depends on order: {} vs {}\n{first}\n{second}",
                forward.is_ok(),
                reordered.is_ok()
            ),
        };
        loaded += 1;
        for method in REQUEST_METHODS {
            for host in REQUEST_HOSTS {
                for path in REQUEST_PATHS {
                    let result = forward.classify(method, host, path).await;
                    assert_eq!(result, forward.classify(method, host, path).await);
                    assert_eq!(
                        result,
                        reordered.classify(method, host, path).await,
                        "{method} {host} {path}\n{first}\n{second}"
                    );
                }
            }
        }
    }
    assert!(loaded >= 100, "only {loaded} generated rule sets loaded");
}

/// A non-uppercase method has two readings: folded (`get` is `GET`) and
/// case-sensitive per RFC 9110 (`get` is a different method, which only
/// method-less rules can match). A classification must hold under both.
#[tokio::test]
async fn generated_method_case_never_selects_a_class_one_reading_contradicts() {
    let mut state = 0x0BAD_C0DE_0000_0007;
    let (mut checked, mut denied) = (0, 0);
    for _ in 0..400 {
        let rules = (0..2 + below(&mut state, 6))
            .map(|_| generated_rule(&mut state))
            .collect::<Vec<_>>();
        let Ok(classifier) = load(&[&mapping_set(0, &rules)]).await else {
            continue;
        };
        // The case-sensitive reading, built independently of `classify`.
        let method_less = rules
            .iter()
            .filter(|rule| !rule.contains("method = "))
            .cloned()
            .collect::<Vec<_>>();
        let strict = load(&[&mapping_set(1, &method_less)]).await.ok();

        for (sent, canonical) in [
            ("get", "GET"),
            ("Get", "GET"),
            ("post", "POST"),
            ("pOsT", "POST"),
        ] {
            for host in REQUEST_HOSTS {
                for path in REQUEST_PATHS {
                    let result = classifier.classify(sent, host, path).await;
                    let folded = classifier.classify(canonical, host, path).await;
                    let case_sensitive = match &strict {
                        Some(strict) => strict.classify(canonical, host, path).await,
                        None => None,
                    };
                    checked += 1;
                    let Some(class) = result else {
                        denied += usize::from(folded.is_some() || case_sensitive.is_some());
                        continue;
                    };
                    let context = format!("{sent} {host} {path}\n{}", rules.concat());
                    assert_eq!(result, folded, "{context}");
                    assert!(
                        case_sensitive.is_none() || case_sensitive == Some(class),
                        "{context}"
                    );
                }
            }
        }
    }
    assert!(
        checked >= 10_000 && denied > 0,
        "{checked} checked, {denied} denied"
    );
}

/// Spellings RFC 3986 and the host contract define as equivalent must agree
/// exactly, across requests generated from a valid tuple.
#[tokio::test]
async fn generated_equivalent_spellings_classify_identically() {
    let mut state = 0x0BAD_C0DE_0000_0008;
    let mut classified = 0;
    let classifier = load(&[PAYMENTS, REPOS]).await.unwrap();
    for _ in 0..2_000 {
        let method = pick(&mut state, &["GET", "POST", "DELETE"]);
        let host = pick(
            &mut state,
            &["api.acme.com", "x.acme.com", "a.b.acme.com", "acme.com"],
        );
        let path = format!(
            "/v1{}{}",
            pick(&mut state, &["", "/refunds"]),
            generated_path(&mut state)
        );
        let base = classifier.classify(method, host, &path).await;
        classified += usize::from(base.is_some());

        let spellings = [
            (method.to_owned(), host.to_ascii_uppercase(), path.clone()),
            (method.to_owned(), format!("{host}:443"), path.clone()),
            (method.to_owned(), format!("{host}."), path.clone()),
            (
                method.to_owned(),
                host.to_owned(),
                format!("{path}?q=/..//;"),
            ),
            (method.to_owned(), host.to_owned(), format!("{path}#//")),
            (
                method.to_owned(),
                host.to_owned(),
                format!("/./{}", &path[1..]),
            ),
            (
                method.to_owned(),
                host.to_owned(),
                format!("/zz/../{}", &path[1..]),
            ),
            (
                method.to_owned(),
                host.to_owned(),
                format!("/%2E/{}", &path[1..]),
            ),
            (
                method.to_owned(),
                host.to_owned(),
                path.replacen("v1", "%761", 1),
            ),
        ];
        for (method, host, path) in spellings {
            assert_eq!(
                classifier.classify(&method, &host, &path).await,
                base,
                "{method} {host} {path}"
            );
        }

        // Adding a trailing slash may fail closed, but never picks a new class.
        if base.is_some() {
            let slashed = classifier.classify(method, host, &format!("{path}/")).await;
            assert!(
                slashed.is_none() || slashed == base,
                "{method} {host} {path}/"
            );
        }
    }
    assert!(
        classified >= 500,
        "only {classified} generated requests matched"
    );
}
