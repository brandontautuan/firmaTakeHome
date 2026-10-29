//! Parsing and validation for mapping-set TOML documents.

use serde::Deserialize;

use crate::{ACTION_CLASSES, LoadError};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MappingSet {
    pub(crate) format_version: u32,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) host: String,
    #[serde(default)]
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

/// Converts one TOML document to a checked mapping set.
pub(crate) fn parse(input: &str) -> Result<MappingSet, LoadError> {
    let set: MappingSet = toml::from_str(input).map_err(LoadError::Toml)?;
    validate(&set)?;
    Ok(set)
}

fn validate(set: &MappingSet) -> Result<(), LoadError> {
    if set.format_version != 1 {
        return Err(LoadError::UnsupportedFormatVersion(set.format_version));
    }
    required_text("name", &set.name)?;
    required_text("description", &set.description)?;
    validate_host(&set.host)?;

    for (index, rule) in set.rules.iter().enumerate() {
        if !ACTION_CLASSES.contains(&rule.action_class.as_str()) {
            return Err(LoadError::UnknownActionClass {
                rule: index,
                action_class: rule.action_class.clone(),
            });
        }
        if let Some(method) = &rule.method {
            if method.is_empty() || !method.bytes().all(is_http_token) {
                return Err(LoadError::InvalidRule {
                    rule: index,
                    field: "method",
                });
            }
        }
        if let Some(subdomain) = &rule.subdomain {
            if subdomain != "*" && !is_dns_name(subdomain) {
                return Err(LoadError::InvalidRule {
                    rule: index,
                    field: "subdomain",
                });
            }
        }
        if let Some(path) = &rule.path {
            if !path.starts_with('/') {
                return Err(LoadError::InvalidRule {
                    rule: index,
                    field: "path",
                });
            }
        }
    }
    Ok(())
}

fn required_text(field: &'static str, value: &str) -> Result<(), LoadError> {
    if value.trim().is_empty() {
        Err(LoadError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_host(host: &str) -> Result<(), LoadError> {
    if is_dns_name(host) {
        Ok(())
    } else {
        Err(LoadError::InvalidField("host"))
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
            "description = \"Acme API\"\n",
            "host = \"acme.com\"\n",
        ] {
            let input = VALID.replace(field, "");
            assert!(parse(&input).is_err(), "expected {field:?} to be required");
        }
    }

    #[test]
    fn rejects_unknown_top_level_and_rule_keys() {
        assert!(parse(&format!("{VALID}\nowner = \"ops\"\n")).is_err());
        assert!(parse(&VALID.replace("action_class", "action_clas")).is_err());
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
    }

    #[test]
    fn accepts_optional_rule_matchers() {
        let input = VALID.replace("action_class = \"payment.read\"", "method = \"PATCH\"\nsubdomain = \"*\"\npath = \"/v1/*\"\naction_class = \"payment.read\"");
        assert!(parse(&input).is_ok());
    }
}
