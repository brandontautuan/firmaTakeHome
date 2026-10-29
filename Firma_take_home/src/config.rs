//! Parsing and validation for mapping-set TOML documents.

use serde::Deserialize;

use crate::{ACTION_CLASSES, SetError, normalize};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MappingSet {
    pub(crate) format_version: u32,
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) host: String,
    pub(crate) rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rule {
    pub(crate) method: Option<String>,
    pub(crate) subdomain: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) action_class: String,
}

/// Converts one TOML document to a checked mapping set. Errors carry the
/// set's declared name when the document parsed far enough to have one.
pub(crate) fn parse(input: &str) -> Result<MappingSet, (Option<String>, SetError)> {
    let set: MappingSet = toml::from_str(input).map_err(|error| (None, SetError::Toml(error)))?;
    match validate(&set) {
        Ok(()) => Ok(set),
        Err(error) => Err((Some(set.name), error)),
    }
}

fn validate(set: &MappingSet) -> Result<(), SetError> {
    if set.format_version != 1 {
        return Err(SetError::UnsupportedFormatVersion(set.format_version));
    }
    required_text("name", &set.name)?;
    if set
        .description
        .as_deref()
        .is_some_and(|description| description.chars().any(char::is_control))
    {
        return Err(SetError::InvalidField("description"));
    }
    validate_host(&set.host)?;
    if set.rules.is_empty() {
        return Err(SetError::InvalidField("rules"));
    }

    for (index, rule) in set.rules.iter().enumerate() {
        if !ACTION_CLASSES.contains(&rule.action_class.as_str()) {
            return Err(SetError::UnknownActionClass {
                rule: index,
                action_class: rule.action_class.clone(),
            });
        }
        if let Some(method) = &rule.method
            && normalize::method(method).is_none()
        {
            return Err(SetError::InvalidRule {
                rule: index,
                field: "method",
            });
        }
        if let Some(subdomain) = &rule.subdomain
            && subdomain != "*"
            && (!is_dns_label(subdomain) || normalize::host(subdomain).is_none())
        {
            return Err(SetError::InvalidRule {
                rule: index,
                field: "subdomain",
            });
        }
        if let Some(path) = &rule.path
            && normalize::pattern_path(path).is_none()
        {
            return Err(SetError::InvalidRule {
                rule: index,
                field: "path",
            });
        }
    }
    Ok(())
}

fn required_text(field: &'static str, value: &str) -> Result<(), SetError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(SetError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_host(host: &str) -> Result<(), SetError> {
    // Mapping hosts name an origin, not an HTTP authority. Ports and trailing
    // dots are accepted for request authorities but create duplicate mapping
    // identities, so reject them here.
    if !host.contains(':')
        && !host.ends_with('.')
        && normalize::host(host).is_some()
        && is_dns_name(host)
    {
        Ok(())
    } else {
        Err(SetError::InvalidField("host"))
    }
}

fn is_dns_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value.split('.').all(is_dns_label)
}

fn is_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::parse;

    const VALID: &str = r#"
format_version = 1
name = "Acme"
description = "Acme API"
host = "acme.com"

[[rules]]
action_class = "payment.read"
"#;

    #[test]
    fn parses_a_valid_mapping_set() {
        let set = parse(VALID).unwrap();
        assert_eq!(set.host, "acme.com");
        assert_eq!(set.rules.len(), 1);
    }

    #[test]
    fn rejects_missing_required_top_level_fields() {
        for field in [
            "format_version = 1\n",
            "name = \"Acme\"\n",
            "host = \"acme.com\"\n",
        ] {
            let input = VALID.replace(field, "");
            assert!(parse(&input).is_err(), "expected {field:?} to be required");
        }
        assert!(
            parse(
                r#"
format_version = 1
name = "Acme"
description = "Acme API"
host = "acme.com"
"#
            )
            .is_err()
        );
        assert!(
            parse(
                r#"
format_version = 1
name = "Acme"
description = "Acme API"
host = "acme.com"
rules = []
"#
            )
            .is_err()
        );
    }

    #[test]
    fn accepts_an_omitted_or_empty_description() {
        let omitted = VALID.replace("description = \"Acme API\"\n", "");
        assert_eq!(parse(&omitted).unwrap().description, None);

        let empty = VALID.replace("description = \"Acme API\"", "description = \"\"");
        assert_eq!(parse(&empty).unwrap().description.as_deref(), Some(""));
    }

    #[test]
    fn rejects_unknown_top_level_and_rule_keys() {
        for key in ["owner", "format_versoin", "descriptin", "hosts"] {
            assert!(
                parse(&format!("{VALID}\n{key} = \"value\"\n")).is_err(),
                "{key}"
            );
        }
        for key in ["action_clas", "actionclass", "methd", "subdomian", "paths"] {
            assert!(parse(&VALID.replace("action_class", key)).is_err(), "{key}");
        }
    }

    #[test]
    fn rejects_unknown_action_classes_and_invalid_values() {
        assert!(parse(&VALID.replace("payment.read", "payments.delete")).is_err());
        assert!(
            parse(&VALID.replace("host = \"acme.com\"", "host = \"https://acme.com\"")).is_err()
        );
        assert!(
            parse(&VALID.replace(
                "action_class = \"payment.read\"",
                "path = \"relative\"\naction_class = \"payment.read\""
            ))
            .is_err()
        );
        assert!(parse(&VALID.replace("host = \"acme.com\"", "host = \"acme.com:443\"")).is_err());
        assert!(parse(&VALID.replace("host = \"acme.com\"", "host = \"192.0.2.1\"")).is_err());
    }

    #[test]
    fn rejects_unsupported_versions_and_missing_rule_action_classes() {
        assert!(parse(&VALID.replace("format_version = 1", "format_version = 2")).is_err());
        assert!(
            parse(&VALID.replace("action_class = \"payment.read\"", "path = \"/v1\"")).is_err()
        );
    }

    #[test]
    fn rejects_empty_and_malformed_matcher_values() {
        assert!(parse(&VALID.replace("name = \"Acme\"", "name = \"  \"")).is_err());
        assert!(
            parse(&VALID.replace(
                "action_class = \"payment.read\"",
                "method = \"GET /\"\naction_class = \"payment.read\""
            ))
            .is_err()
        );
        assert!(
            parse(&VALID.replace(
                "action_class = \"payment.read\"",
                "subdomain = \"api..internal\"\naction_class = \"payment.read\""
            ))
            .is_err()
        );
        assert!(
            parse(&VALID.replace(
                "action_class = \"payment.read\"",
                "subdomain = \"192.0.2.1\"\naction_class = \"payment.read\""
            ))
            .is_err()
        );
        assert!(
            parse(&VALID.replace(
                "action_class = \"payment.read\"",
                "path = \"/v1/%2fadmin\"\naction_class = \"payment.read\""
            ))
            .is_err()
        );
    }

    #[test]
    fn rejects_malformed_hostnames_and_subdomains() {
        for host in [
            "-acme.com",
            "acme-.com",
            "acme..com",
            "acme_com",
            "acme.com.",
            "acme.com:443",
            "  acme.com",
        ] {
            let input = VALID.replace("host = \"acme.com\"", &format!("host = \"{host}\""));
            assert!(parse(&input).is_err(), "host {host:?}");
        }

        for subdomain in [
            "-api",
            "api-",
            "api..internal",
            "api.eu",
            "api_internal",
            "api:443",
        ] {
            let input = VALID.replace(
                "action_class = \"payment.read\"",
                &format!("subdomain = \"{subdomain}\"\naction_class = \"payment.read\""),
            );
            assert!(parse(&input).is_err(), "subdomain {subdomain:?}");
        }
    }

    #[test]
    fn accepts_optional_rule_matchers() {
        let input = VALID.replace("action_class = \"payment.read\"", "method = \"PATCH\"\nsubdomain = \"*\"\npath = \"/v1/*\"\naction_class = \"payment.read\"");
        assert!(parse(&input).is_ok());
    }
}
