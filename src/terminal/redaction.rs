use std::sync::OnceLock;

use regex::{Captures, Regex};
use serde_json::Value;

pub const REDACTED: &str = "<redacted>";

const SECRET_FIELDS: &[&str] = &[
    "connect_proxy_password",
    "password",
    "api_key",
    "apikey",
    "vault_passphrase",
    "passphrase",
    "mfa",
    "mfa_code",
    "sid",
    "session_id",
    "master_key",
    "aes_key",
    "file_key",
    "token",
    "access_token",
    "secret",
];

struct Patterns {
    link: Regex,
    query: Regex,
    credentials: Regex,
    schemeless: Regex,
    header: Regex,
    digest: Regex,
    bearer: Regex,
    secret: Regex,
    option: Regex,
    code: Regex,
}

fn patterns() -> Option<&'static Patterns> {
    static PATTERNS: OnceLock<Option<Patterns>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        Some(Patterns {
            link: Regex::new(r#"(?i)((?:mega(?:\.co)?\.nz/|mega://)[^\s#]*)#[^\s\"']+"#).ok()?,
            query: Regex::new(r#"(?i)\b(sid|token|access_token|api_key|apikey|password|passphrase|mfa)=([^&\s\"'#]+)"#).ok()?,
            credentials: Regex::new(r#"(?i)\b([a-z][a-z0-9+.\-]*://)[^\s/:@\"']+:[^\s/@\"']+@"#).ok()?,
            schemeless: Regex::new(r#"\b[^\s/:@\"']+:[^\s/@\"']+@([^\s/@\"']+:\d+)"#).ok()?,
            header: Regex::new(r"(?i)\b((?:proxy-)?authorization)(\s*[:=]\s*)[^\r\n]*").ok()?,
            // The key= is consumed instead of Python's unsupported lookahead.
            digest: Regex::new(r"(?i)\b(digest)\s+[a-z]+\s*=[^\r\n]*").ok()?,
            bearer: Regex::new(r"(?i)\b(bearer)\s+[A-Za-z0-9\-._~+/=]+").ok()?,
            secret: Regex::new(concat!(
                r"(?i)\b(passwords?|passphrases?|api[ _-]?keys?|access[ _-]?tokens?|",
                r"auth[ _-]?tokens?|bearer[ _-]?tokens?|tokens?|sids?|session[ _-]?ids?|",
                r"mfa(?:[ _-]?codes?)?|otps?|2fa(?:[ _-]?codes?)?|",
                r"vault[ _-]?(?:passphrases?|secrets?)|secrets?)",
                r#"(\s*[:=]\s*|\s+(?:is|was)\s+)(\"[^\"]*\"|'[^']*'|[^\s\"'&]+)"#,
            )).ok()?,
            option: Regex::new(concat!(
                r"(?i)(--(?:share-password|elc-api-key|passwords?|passphrases?|api[ _-]?keys?|access[ _-]?tokens?|",
                r"auth[ _-]?tokens?|bearer[ _-]?tokens?|tokens?|sids?|session[ _-]?ids?|",
                r"mfa(?:[ _-]?codes?)?|otps?|2fa(?:[ _-]?codes?)?|",
                r"vault[ _-]?(?:passphrases?|secrets?)|secrets?)|-p)",
                r#"(\s*=\s*|\s+)(\"[^\"]*\"|'[^']*'|[^\s\"'&]+)"#,
            )).ok()?,
            code: Regex::new(r"(?i)\b((?:mfa|otp|2fa)(?:[ _-]?code)?)\s+(\d{4,12})\b").ok()?,
        })
    }).as_ref()
}

fn capture<'a>(matched: &Captures<'a>, index: usize) -> &'a str {
    matched.get(index).map_or("", |value| value.as_str())
}

pub fn text(value: &str) -> String {
    let Some(p) = patterns() else {
        return REDACTED.to_owned();
    };
    let mut value = p.link.replace_all(value, "${1}#<key>").into_owned();
    value = p
        .credentials
        .replace_all(&value, "${1}<redacted>@")
        .into_owned();
    value = p
        .schemeless
        .replace_all(&value, "<redacted>@${1}")
        .into_owned();
    value = p
        .header
        .replace_all(&value, "${1}${2}<redacted>")
        .into_owned();
    value = p.digest.replace_all(&value, "${1} <redacted>").into_owned();
    value = p.bearer.replace_all(&value, "${1} <redacted>").into_owned();
    for pattern in [&p.secret, &p.option] {
        value = pattern
            .replace_all(&value, |matched: &Captures<'_>| {
                let secret = capture(matched, 3);
                if secret == REDACTED {
                    return capture(matched, 0).to_owned();
                }
                let tail = if secret.starts_with(['\'', '"']) {
                    ""
                } else {
                    let trimmed =
                        secret.trim_end_matches([',', ';', '.', ':', '!', '?', ')', ']', '}']);
                    &secret[trimmed.len()..]
                };
                format!(
                    "{}{}{REDACTED}{tail}",
                    capture(matched, 1),
                    capture(matched, 2)
                )
            })
            .into_owned();
    }
    value = p.code.replace_all(&value, "${1} <redacted>").into_owned();
    p.query.replace_all(&value, "${1}=<redacted>").into_owned()
}

/// Logs hide account identifiers and wire metadata beyond the user-facing secret policy.
pub fn log_text(value: &str) -> String {
    struct LogPatterns {
        url: Regex,
        api: Regex,
        fields: Regex,
        email: Regex,
    }
    static LOG: OnceLock<Option<LogPatterns>> = OnceLock::new();
    let Some(patterns) = LOG.get_or_init(|| Some(LogPatterns {
        url: Regex::new(r#"(?i)https?://(?:<redacted>|<key>|[^\s'\"\]\)>,])+"#).ok()?,
        api: Regex::new(r#"(?i)/cs\?(?:<redacted-query>|<redacted>|[^\s'\"\]\)>,])+"#).ok()?,
        fields: Regex::new(concat!(
            r#"(?i)((?:'|\")(?:k|at|g|fa|uh|mfa|sid|key|attr|api_key|apikey|password|"#,
            r#"passphrase|token|cookie|session|privk|csid|tsid|user|email)(?:'|\")\s*:\s*)(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"#
        )).ok()?,
        email: Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").ok()?,
    })).as_ref() else { return REDACTED.to_owned() };
    let value = text(value);
    let value = patterns.url.replace_all(&value, |captures: &Captures<'_>| {
        let raw = capture(captures, 0);
        let lower = raw.to_ascii_lowercase();
        if lower.contains("mega.nz")
            || lower.contains("mega.co.nz")
            || lower.contains("userstorage.mega")
        {
            return "<redacted-url>".to_owned();
        }
        let Ok(mut url) = url::Url::parse(raw) else {
            return raw.to_owned();
        };
        const KEYS: &[&str] = &[
            "ak", "api_key", "apikey", "auth", "at", "email", "fa", "g", "k", "key", "mfa", "n",
            "password", "sid", "session", "token", "uh", "user",
        ];
        let mut changed = false;
        let pairs: Vec<_> = url
            .query_pairs()
            .map(|(key, value)| {
                let value = if KEYS.contains(&key.to_ascii_lowercase().as_str()) {
                    changed = true;
                    REDACTED.to_owned()
                } else {
                    value.into_owned()
                };
                (key.into_owned(), value)
            })
            .collect();
        if changed {
            url.query_pairs_mut().clear().extend_pairs(pairs);
            url.to_string()
        } else {
            raw.to_owned()
        }
    });
    let value = patterns.api.replace_all(&value, "/cs?<redacted-query>");
    let value = patterns
        .fields
        .replace_all(&value, |captures: &Captures<'_>| {
            let quote = if capture(captures, 2).starts_with('"') {
                '"'
            } else {
                '\''
            };
            format!("{}{quote}<redacted>{quote}", capture(captures, 1))
        });
    patterns
        .email
        .replace_all(&value, "<redacted-email>")
        .into_owned()
}

/// Intentional public links are preserved only on explicit machine-output surfaces, never logs.
pub fn sanitize(value: &Value, public_links: bool) -> Value {
    fn walk(value: &Value, field: &str, public_links: bool) -> Value {
        let field = field.to_ascii_lowercase();
        if SECRET_FIELDS.contains(&field.as_str()) && !value.is_null() {
            if public_links
                && field == "file_key"
                && matches!(value.as_str(), Some("available" | "missing"))
            {
                return value.clone();
            }
            return Value::String(REDACTED.to_owned());
        }
        match value {
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, value)| (key.clone(), walk(value, key, public_links)))
                    .collect(),
            ),
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|item| walk(item, "", public_links))
                    .collect(),
            ),
            Value::String(input)
                if public_links && matches!(field.as_str(), "share_link" | "public_link") =>
            {
                let cleaned = patterns().map_or_else(
                    || REDACTED.to_owned(),
                    |p| p.query.replace_all(input, "${1}=<redacted>").into_owned(),
                );
                Value::String(cleaned)
            }
            Value::String(input) => Value::String(text(input)),
            _ => value.clone(),
        }
    }
    walk(value, "", public_links)
}

pub fn literal(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}
