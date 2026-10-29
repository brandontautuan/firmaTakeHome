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
    if let Some(port) = port {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        // Parsing also rejects values outside the TCP/UDP port range.
        if port.parse::<u16>().is_err() {
            return None;
        }
    }

    let name = name.strip_suffix('.').unwrap_or(name);
    if !is_dns_name(name) || name.parse::<std::net::Ipv4Addr>().is_ok() {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

/// Validates an HTTP token. HTTP methods are intentionally not case folded.
pub(crate) fn method(input: &str) -> bool {
    !input.is_empty() && input.bytes().all(is_http_token)
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

/// Normalizes a configuration path pattern while retaining literal `*` wildcards.
pub(crate) fn pattern_path(input: &str) -> Option<String> {
    let end = input.find(['?', '#']).unwrap_or(input.len());
    normalize_path(&input[..end], true)
}

fn normalize_path(input: &str, pattern: bool) -> Option<String> {
    if input.is_empty() || !input.is_ascii() || !input.starts_with('/') {
        return None;
    }
    validate_percent_escapes(input)?;

    // A dot segment next to a wildcard cannot be canonicalized soundly: the
    // wildcard can span an unknown number of path segments. Reject rather than
    // assigning it a meaning that a URL client or server may not share.
    if pattern
        && input.contains('*')
        && input
            .split('/')
            .any(|segment| dot_segment_len(segment).is_some())
    {
        return None;
    }
    let canonical = input
        .split('/')
        .map(|segment| match dot_segment_len(segment) {
            Some(1) => ".",
            Some(2) => "..",
            _ => segment,
        })
        .collect::<Vec<_>>()
        .join("/");
    remove_dot_segments(&canonical)
}

fn validate_percent_escapes(input: &str) -> Option<()> {
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hi = *bytes.get(index + 1)?;
            let lo = *bytes.get(index + 2)?;
            let value = (hex(hi)? << 4) | hex(lo)?;
            if matches!(value, b'/' | b'\\') {
                return None;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Some(())
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn dot_segment_len(segment: &str) -> Option<usize> {
    let mut bytes = Vec::with_capacity(segment.len());
    let raw = segment.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'%' {
            let (&hi, &lo) = raw.get(index + 1).zip(raw.get(index + 2))?;
            let value = hex(hi).zip(hex(lo)).map(|(hi, lo)| (hi << 4) | lo)?;
            bytes.push(value);
            index += 3;
        } else {
            bytes.push(raw[index]);
            index += 1;
        }
    }
    match bytes.as_slice() {
        b"." => Some(1),
        b".." => Some(2),
        _ => None,
    }
}

/// RFC 3986's dot-segment algorithm, operating on validated ASCII text.
fn remove_dot_segments(input: &str) -> Option<String> {
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
                stripped.find('/').map_or(remaining.len(), |i| i + 1)
            } else {
                remaining.find('/').unwrap_or(remaining.len())
            };
            output.push_str(&remaining[..end]);
            remaining.drain(..end);
        }
    }
    Some(output)
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
        assert!(method("GET"));
        assert!(method("get"));
        for value in ["", "GET ", "GET\n", "é"] {
            assert!(!method(value), "{value:?}");
        }
    }

    #[test]
    fn paths_strip_query_and_normalize_dot_segments() {
        assert_eq!(request_path(""), Some("/".into()));
        assert_eq!(request_path("/v1/../admin?q=1#x"), Some("/admin".into()));
        assert_eq!(request_path("/v1/%2e%2e/admin"), Some("/admin".into()));
        assert_eq!(
            request_path("/v1//payments/"),
            Some("/v1//payments/".into())
        );
        for value in ["relative", "/x%ZZ", "/x%2f", "/x%5C", "/é"] {
            assert_eq!(request_path(value), None, "{value}");
        }
    }

    #[test]
    fn patterns_retain_wildcards_but_reject_ambiguous_dot_patterns() {
        assert_eq!(
            pattern_path("/v1/*/refunds/**"),
            Some("/v1/*/refunds/**".into())
        );
        assert_eq!(pattern_path("/v1/*/../admin"), None);
        assert_eq!(pattern_path("/v1/*?debug=true"), Some("/v1/*".into()));
    }

    #[test]
    fn long_and_arbitrary_utf8_request_inputs_never_panic() {
        assert!(request_path(&format!("/{}", "a".repeat(32 * 1024))).is_some());
        for value in ["\0", "\u{10ffff}", "/\u{10ffff}", "/%"] {
            assert_eq!(request_path(value), None, "{value:?}");
        }
    }
}
