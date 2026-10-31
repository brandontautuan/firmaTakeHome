//! Canonicalization for the three request components accepted by the classifier.
//!
//! This module deliberately accepts only the unambiguous ASCII subset of HTTP
//! authority and path syntax. In particular, IP literals, userinfo, encoded
//! separators, malformed percent escapes, and non-ASCII text are rejected.

const MAX_METHOD_BYTES: usize = 32;
const MAX_REQUEST_PATH_BYTES: usize = 8 * 1024;
pub(crate) const MAX_PATTERN_BYTES: usize = 1_024;

/// Returns a lowercase DNS hostname without one optional trailing dot or port.
pub(crate) fn host(input: &str) -> Option<String> {
    if input.is_empty() || !input.is_ascii() || input.contains('@') {
        return None;
    }

    let (name, port) = match input.rsplit_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (input, None),
    };
    // Parsing also rejects values outside the TCP/UDP port range.
    if let Some(port) = port
        && (!port.bytes().all(|byte| byte.is_ascii_digit()) || port.parse::<u16>().is_err())
    {
        return None;
    }

    let name = name.strip_suffix('.').unwrap_or(name);
    let final_label = name.rsplit_once('.').map_or(name, |(_, label)| label);
    if !is_dns_name(name) || is_ipv4_number(final_label) {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

/// WHATWG URL parsers treat a host as IPv4 when its final label is a number:
/// all decimal digits, or `0x` followed by zero or more hex digits.
fn is_ipv4_number(label: &str) -> bool {
    let digits = label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"));
    match digits {
        Some(digits) => digits.bytes().all(|byte| byte.is_ascii_hexdigit()),
        None => label.bytes().all(|byte| byte.is_ascii_digit()),
    }
}

/// Validates an HTTP token and folds it to uppercase. HTTP methods are
/// case-sensitive on the wire (RFC 9110), but clients and servers commonly
/// normalize them. `classify` therefore also checks the case-sensitive reading
/// of a method that folding changed, and denies the request on disagreement.
pub(crate) fn method(input: &str) -> Option<String> {
    (1..=MAX_METHOD_BYTES)
        .contains(&input.len())
        .then_some(())
        .filter(|()| input.bytes().all(is_http_token))
        .map(|()| input.to_ascii_uppercase())
}

/// Normalizes a request path. Empty input represents the origin-form `/`.
pub(crate) fn request_path(input: &str) -> Option<String> {
    let end = input.find(['?', '#']).unwrap_or(input.len());
    let path = &input[..end];
    if path.len() > MAX_REQUEST_PATH_BYTES {
        return None;
    }
    if path.is_empty() {
        return Some("/".into());
    }
    normalize_path(path, false)
}

/// Normalizes a configuration path pattern while retaining literal `*`
/// wildcards. Query strings and fragments never reach the matcher, so a
/// pattern containing one is a configuration mistake.
pub(crate) fn pattern_path(input: &str) -> Option<String> {
    if input.contains(['?', '#']) {
        return None;
    }
    normalize_path(input, true)
}

/// Lowercases ASCII letters in a normalized path without changing percent
/// escapes. This is used only to detect disagreement with common
/// case-insensitive server routers; it never changes the path being matched.
pub(crate) fn lowercase_path_outside_escapes(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut output = String::with_capacity(path.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            output.push('%');
            if let Some(&byte) = bytes.get(index + 1) {
                output.push(char::from(byte));
            }
            if let Some(&byte) = bytes.get(index + 2) {
                output.push(char::from(byte));
            }
            index = index.saturating_add(3);
        } else {
            output.push(char::from(bytes[index].to_ascii_lowercase()));
            index += 1;
        }
    }
    output
}

/// Canonical form shared by requests and patterns: unreserved percent escapes
/// decoded, other escapes upper-cased, and dot segments removed. Empty path
/// segments, backslashes, and encoded separators are rejected because servers
/// disagree on what they mean.
fn normalize_path(input: &str, pattern: bool) -> Option<String> {
    if !input.starts_with('/') {
        return None;
    }
    let decoded = decode_unreserved(input)?;
    if decoded.contains("//") || decoded.contains(';') {
        return None;
    }

    // Configuration must describe its path literally. Silently rewriting a
    // configured dot segment would make its displayed value disagree with the
    // route the matcher actually evaluates.
    if pattern
        && decoded
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return None;
    }
    Some(remove_dot_segments(&decoded))
}

/// RFC 3986 section 6.2.2 normalization: `%72` and `r` are the same path, so
/// decode escaped unreserved bytes and upper-case the rest. Decoding happens
/// once; `%25` stays `%25`.
fn decode_unreserved(input: &str) -> Option<String> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let hi = hex(*bytes.get(index + 1)?)?;
            let lo = hex(*bytes.get(index + 2)?)?;
            let value = (hi << 4) | lo;
            if matches!(value, b'/' | b'\\') {
                return None;
            }
            if value.is_ascii_alphanumeric() || matches!(value, b'-' | b'.' | b'_' | b'~') {
                output.push(char::from(value));
            } else {
                output.push('%');
                output.push(char::from(HEX[usize::from(hi)]));
                output.push(char::from(HEX[usize::from(lo)]));
            }
            index += 3;
        } else {
            if !byte.is_ascii_graphic() || byte == b'\\' {
                return None;
            }
            output.push(char::from(byte));
            index += 1;
        }
    }
    Some(output)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// RFC 3986 dot-segment removal for an absolute path without empty segments.
/// A stack keeps this linear in the path length.
fn remove_dot_segments(input: &str) -> String {
    let mut segments = Vec::new();
    // A path ending in `.` or `..` names a directory, as `/a/b/..` -> `/a/`.
    let mut trailing_slash = false;
    for segment in input.split('/').skip(1) {
        match segment {
            "." => trailing_slash = true,
            ".." => {
                segments.pop();
                trailing_slash = true;
            }
            _ => {
                segments.push(segment);
                trailing_slash = false;
            }
        }
    }
    let mut output = format!("/{}", segments.join("/"));
    if trailing_slash && !output.ends_with('/') {
        output.push('/');
    }
    output
}

fn is_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn is_http_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[cfg(test)]
mod tests {
    use super::{
        host, lowercase_path_outside_escapes, method, normalize_path, pattern_path, request_path,
    };

    #[test]
    fn normalizes_hosts_and_rejects_ambiguous_authorities() {
        assert_eq!(host("API.Acme.COM.:443"), Some("api.acme.com".into()));
        for value in [
            "",
            "acme.com:",
            "acme.com:99999",
            "u@acme.com",
            "192.0.2.1",
            "010.0.0.1",
            "127.1",
            "1.2.3.4.5",
            "0x7f000001",
            "0X7F000001",
            "0x7f.0x1",
            "0x7f.0.0.0X1",
            "acme.0x",
            "[::1]",
            "acme..com",
            "é.com",
            "acme.com..",
        ] {
            assert_eq!(host(value), None, "{value}");
        }
    }

    #[test]
    fn hex_looking_labels_are_only_rejected_in_the_final_position() {
        assert_eq!(host("0x7f.acme.com"), Some("0x7f.acme.com".into()));
        assert_eq!(host("0xg.com"), Some("0xg.com".into()));
        assert_eq!(host("acme.0xg"), Some("acme.0xg".into()));
    }

    #[test]
    fn methods_are_tokens_folded_to_upper_case() {
        assert_eq!(method("GET"), Some("GET".into()));
        assert_eq!(method("delete"), Some("DELETE".into()));
        assert_eq!(method("Patch"), Some("PATCH".into()));
        for value in ["", "GET ", "GET\n", "é", &"G".repeat(33)] {
            assert_eq!(method(value), None, "{value:?}");
        }
    }

    #[test]
    fn paths_strip_query_and_normalize_dot_segments() {
        assert_eq!(request_path(""), Some("/".into()));
        assert_eq!(request_path("/v1/../admin?q=1#x"), Some("/admin".into()));
        assert_eq!(request_path("/v1/%2e%2e/admin"), Some("/admin".into()));
        assert_eq!(request_path("/a/b/.."), Some("/a/".into()));
        assert_eq!(request_path("/a/./b/."), Some("/a/b/".into()));
        assert_eq!(request_path("/../../x"), Some("/x".into()));
        assert_eq!(request_path("/v1/payments/"), Some("/v1/payments/".into()));
        for value in [
            "relative", "/x%ZZ", "/x%2f", "/x%5C", "/x\\y", "/é", "/a b", "/a\0", "/v1//x", "//",
            "/x;y",
        ] {
            assert_eq!(request_path(value), None, "{value:?}");
        }
    }

    #[test]
    fn paths_decode_unreserved_escapes_only() {
        assert_eq!(request_path("/v1/%72efunds"), Some("/v1/refunds".into()));
        assert_eq!(request_path("/%7Euser/%5f"), Some("/~user/_".into()));
        assert_eq!(request_path("/a%3a%2A"), Some("/a%3A%2A".into()));
        assert_eq!(request_path("/a%3Bb"), Some("/a%3Bb".into()));
        // No double decoding: `%252e` is a literal `%2e`, not a dot segment.
        assert_eq!(
            request_path("/a/%252e%252e/b"),
            Some("/a/%252e%252e/b".into())
        );
    }

    #[test]
    fn lowercases_paths_without_touching_percent_escapes() {
        assert_eq!(
            lowercase_path_outside_escapes("/V1/%3ARefunds"),
            "/v1/%3Arefunds"
        );
    }

    #[test]
    fn patterns_retain_wildcards_but_reject_ambiguous_dot_patterns() {
        assert_eq!(
            pattern_path("/v1/*/refunds/**"),
            Some("/v1/*/refunds/**".into())
        );
        assert_eq!(
            pattern_path("/v1/%72efunds/*"),
            Some("/v1/refunds/*".into())
        );
        assert_eq!(pattern_path("/v1/*/../admin"), None);
        assert_eq!(pattern_path("/v1/../admin"), None);
        assert_eq!(pattern_path("/v1/./admin"), None);
        assert_eq!(pattern_path("/v1/*?debug=true"), None);
        assert_eq!(pattern_path("/v1//x"), None);
        assert_eq!(pattern_path("/v1/refunds;v=1"), None);
    }

    /// Guards against the buffer-shifting implementation this replaced, which
    /// took O(segments * length). `normalize_path` has no size cap, so this runs
    /// at 512 times the request limit, where that version shifts terabytes.
    #[test]
    fn normalization_stays_linear_well_beyond_the_request_limit() {
        for (segment, expected_len) in [("/a/..", 1), ("/..", 1), ("/.", 1), ("/a", 1 << 22)] {
            let input = segment.repeat((1 << 22) / segment.len());
            let started = std::time::Instant::now();
            let output = normalize_path(&input, false).unwrap();
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "{segment} took {:?}",
                started.elapsed()
            );
            assert!(output.len() <= expected_len, "{segment}");
            assert!(output.starts_with('/'));
        }
    }

    #[test]
    fn long_and_arbitrary_utf8_request_inputs_never_panic() {
        assert!(request_path(&format!("/{}", "a".repeat(8_191))).is_some());
        assert_eq!(request_path(&format!("/{}", "a".repeat(8_192))), None);
        for value in ["\0", "\u{10ffff}", "/\u{10ffff}", "/%"] {
            assert_eq!(request_path(value), None, "{value:?}");
        }
    }
}
