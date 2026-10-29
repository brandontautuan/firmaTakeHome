//! Canonicalization for the three request components accepted by the classifier.
//!
//! This module deliberately accepts only the unambiguous ASCII subset of HTTP
//! authority and path syntax. In particular, IP literals, userinfo, encoded
//! separators, malformed percent escapes, and non-ASCII text are rejected.

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
    if !is_dns_name(name) || name.parse::<std::net::Ipv4Addr>().is_ok() {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

/// Validates an HTTP token without changing its case. HTTP method tokens are
/// case-sensitive, so `GET` and `get` are distinct matcher values.
pub(crate) fn method(input: &str) -> Option<String> {
    (!input.is_empty() && input.bytes().all(is_http_token)).then(|| input.into())
}

/// Normalizes a request path. Empty input represents the origin-form `/`.
pub(crate) fn request_path(input: &str) -> Option<String> {
    let end = input.find(['?', '#']).unwrap_or(input.len());
    let path = &input[..end];
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

/// Canonical form shared by requests and patterns: unreserved percent escapes
/// decoded, other escapes upper-cased, and dot segments removed. Empty path
/// segments and trailing slashes are preserved; backslashes and encoded
/// separators are rejected because servers disagree on what they mean.
fn normalize_path(input: &str, pattern: bool) -> Option<String> {
    if !input.starts_with('/') {
        return None;
    }
    let decoded = decode_unreserved(input)?;

    // A dot segment next to a wildcard cannot be canonicalized soundly: the
    // wildcard can span an unknown number of path segments. Reject rather than
    // assigning it a meaning that a URL client or server may not share.
    if pattern
        && decoded.contains('*')
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

/// RFC 3986 dot-segment removal for a validated absolute path. Empty path
/// segments are copied verbatim, so duplicate and trailing slashes retain
/// their meaning for the matcher.
fn remove_dot_segments(input: &str) -> String {
    let mut remaining = input.to_owned();
    let mut output = String::with_capacity(input.len());
    while !remaining.is_empty() {
        if remaining.starts_with("../") {
            remaining.drain(..3);
        } else if remaining.starts_with("./") {
            remaining.drain(..2);
        } else if remaining == "/." {
            remaining.replace_range(.., "/");
        } else if remaining.starts_with("/./") {
            remaining.replace_range(..3, "/");
        } else if remaining == "/.." {
            remaining.replace_range(.., "/");
            pop_last_segment(&mut output);
        } else if remaining.starts_with("/../") {
            remaining.replace_range(..4, "/");
            pop_last_segment(&mut output);
        } else if remaining == "." || remaining == ".." {
            remaining.clear();
        } else {
            let end = if let Some(stripped) = remaining.strip_prefix('/') {
                stripped
                    .find('/')
                    .map_or(remaining.len(), |index| index + 1)
            } else {
                remaining.find('/').unwrap_or(remaining.len())
            };
            output.push_str(&remaining[..end]);
            remaining.drain(..end);
        }
    }
    output
}

fn pop_last_segment(output: &mut String) {
    if let Some(index) = output.rfind('/') {
        output.truncate(index);
    } else {
        output.clear();
    }
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
    use super::{host, method, pattern_path, request_path};

    #[test]
    fn normalizes_hosts_and_rejects_ambiguous_authorities() {
        assert_eq!(host("API.Acme.COM.:443"), Some("api.acme.com".into()));
        for value in [
            "",
            "acme.com:",
            "acme.com:99999",
            "u@acme.com",
            "192.0.2.1",
            "[::1]",
            "acme..com",
            "é.com",
            "acme.com..",
        ] {
            assert_eq!(host(value), None, "{value}");
        }
    }

    #[test]
    fn methods_are_case_sensitive_tokens() {
        assert_eq!(method("GET"), Some("GET".into()));
        assert_eq!(method("delete"), Some("delete".into()));
        assert_eq!(method("Patch"), Some("Patch".into()));
        for value in ["", "GET ", "GET\n", "é"] {
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
        assert_eq!(request_path("/v1//payments"), Some("/v1//payments".into()));
        assert_eq!(
            request_path("//v1/payments/"),
            Some("//v1/payments/".into())
        );
        for value in [
            "relative", "/x%ZZ", "/x%2f", "/x%5C", "/x\\y", "/é", "/a b", "/a\0",
        ] {
            assert_eq!(request_path(value), None, "{value:?}");
        }
    }

    #[test]
    fn paths_decode_unreserved_escapes_only() {
        assert_eq!(request_path("/v1/%72efunds"), Some("/v1/refunds".into()));
        assert_eq!(request_path("/%7Euser/%5f"), Some("/~user/_".into()));
        assert_eq!(request_path("/a%3a%2A"), Some("/a%3A%2A".into()));
        // No double decoding: `%252e` is a literal `%2e`, not a dot segment.
        assert_eq!(
            request_path("/a/%252e%252e/b"),
            Some("/a/%252e%252e/b".into())
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
        assert_eq!(pattern_path("/v1/*?debug=true"), None);
        assert_eq!(pattern_path("/v1//x"), Some("/v1//x".into()));
    }

    #[test]
    fn long_and_arbitrary_utf8_request_inputs_never_panic() {
        assert!(request_path(&format!("/{}", "a".repeat(32 * 1024))).is_some());
        for value in ["\0", "\u{10ffff}", "/\u{10ffff}", "/%"] {
            assert_eq!(request_path(value), None, "{value:?}");
        }
    }
}
