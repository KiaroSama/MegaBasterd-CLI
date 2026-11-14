use megabasterd_cli::terminal::redaction::{REDACTED, sanitize, text};
use serde_json::json;

#[test]
fn secrets_are_removed_without_destroying_ordinary_diagnostics() {
    for (input, secret) in [
        ("password: invented-pass", "invented-pass"),
        ("first --password SENTINEL-PW-8842", "SENTINEL-PW-8842"),
        ("--password=\"two words\" --workers 8", "two words"),
        ("--vault-passphrase 'two words'", "two words"),
        ("--api_key secret-api", "secret-api"),
        ("--mfa-code 123456", "123456"),
        ("SID was invented-sid", "invented-sid"),
        ("user:invented-pass@proxy.example:8080", "invented-pass"),
        (
            "proxy list user:invented-pass@127.0.0.1:80",
            "invented-pass",
        ),
        ("MFA code 123456", "123456"),
        ("2fa code was 123456", "123456"),
        (
            "http://user:invented-pass@proxy.example:8080",
            "invented-pass",
        ),
        (
            "Authorization: Digest username=\"test\", response=\"invented-response\"",
            "invented-response",
        ),
        (
            "Digest username=\"test\", response=\"invented-response\"",
            "invented-response",
        ),
        ("sent Bearer invented-token upstream", "invented-token"),
        (
            "GET /x?password=invented-pass&token=invented-token",
            "invented-token",
        ),
        ("https://mega.nz/file/ABCDEFGH#INVENTEDKEY", "INVENTEDKEY"),
        ("mega://elc/abc#INVENTEDKEY", "INVENTEDKEY"),
    ] {
        let cleaned = text(input);
        assert!(!cleaned.contains(secret), "Secret escaped redaction");
        assert_eq!(text(&cleaned), cleaned, "Redaction must be idempotent");
    }
    for normal in [
        "Uploaded quarterly-report.pdf successfully",
        "Could not open C:\\Users\\me\\secret_plans.txt",
        "Basic authentication failed for the proxy",
        "Digest authentication failed",
        "password required but not provided",
        "mb download --workers 8 --output reports",
        "Use --password, not a public plaintext log",
        "Retrying chunk 4 of 12 after a timeout",
        "MEGA rejected that 2FA code. Codes expire every 30 seconds - take the current one from your authenticator app and retry.",
    ] {
        assert_eq!(text(normal), normal);
    }
    assert_eq!(
        text("failed (password: invented-pass), retrying"),
        format!("failed (password: {REDACTED}), retrying")
    );
    let multiline =
        "POST /api\nAuthorization: Digest response=\"invented\"\nContent-Type: application/json";
    assert_eq!(
        text(multiline),
        "POST /api\nAuthorization: <redacted>\nContent-Type: application/json"
    );
}

#[test]
fn log_redaction_hides_account_and_wire_metadata_without_changing_console_contracts() {
    use megabasterd_cli::terminal::redaction::log_text;
    let diagnostic = "MEGA API response: [{'g': 'http://gfs204n301.userstorage.mega.co.nz/dl/token', 'k': 'folder:file-key', 'fa': 'thumbnail-token', 'a': 'f'}] https://mega.nz/folder/abc#secret /cs?id=1&ak=key&n=folder";
    let clean = log_text(diagnostic);
    for secret in [
        "userstorage.mega",
        "https://mega.nz",
        "n=folder",
        "folder:file-key",
        "thumbnail-token",
    ] {
        assert!(!clean.contains(secret));
    }
    assert!(clean.contains("'a': 'f'") && clean.contains("<redacted-url>"));
    assert!(clean.contains("/cs?<redacted-query>"));
    assert_eq!(log_text(&clean), clean);
    for query in ["/cs?id=1&sid=synthetic&n=folder", "/cs?sid=synthetic"] {
        assert_eq!(log_text(query), "/cs?<redacted-query>");
    }
    for value in [
        "Login failed for user alice.smith@example.com today",
        "MEGA API request: [{'a': 'us', 'user': 'me@example.org', 'uh': 'h'}]",
        "Traceback: ValueError: bad login for carol@example.com",
    ] {
        let clean = log_text(value);
        assert!(!clean.contains("@example."));
        assert!(clean.contains("<redacted"));
        if !value.contains("'user':") {
            assert!(clean.contains("<redacted-email>"));
        }
    }
    let clean = log_text("GET https://example.invalid/api?token=secret&safe=value&password=pw");
    assert!(!clean.contains("secret") && !clean.contains("password=pw"));
    assert!(clean.contains("safe=value") && clean.contains("token=%3Credacted%3E"));
    assert_eq!(
        log_text("Downloaded chunk 5 of 12 (speed=10MB/s)"),
        "Downloaded chunk 5 of 12 (speed=10MB/s)"
    );
    assert_eq!(
        text("Selected account alice.smith@example.com"),
        "Selected account alice.smith@example.com"
    );
    assert_eq!(log_text(&clean), clean, "log masking is idempotent");
    for document in [
        r#"{"k":"part'one-SECRET","safe":"preserved"}"#,
        "{'k':'part\"two-SECRET','safe':'preserved'}",
        r#"{"k":"part\"three-SECRET","safe":"preserved"}"#,
    ] {
        let clean = log_text(document);
        assert!(!clean.contains("SECRET"));
        assert!(clean.contains("preserved"));
    }
}

#[test]
fn public_links_are_intentional_only_in_machine_output_not_logs() {
    let input = json!({
        "password": "invented-pass", "sid": null,
        "details": {"items": ["SID was invented-sid", {"api_key": "invented-key"}]},
        "share_link": "https://mega.nz/file/ABCDEFGH?sid=invented-sid#PUBLICKEY",
        "name": "report.pdf"
    });
    let output = sanitize(&input, true);
    assert_eq!(output["password"], REDACTED);
    assert!(output["sid"].is_null());
    assert_eq!(output["name"], "report.pdf");
    assert_eq!(
        output["share_link"],
        "https://mega.nz/file/ABCDEFGH?sid=<redacted>#PUBLICKEY"
    );
    let log = sanitize(&input, false).to_string();
    for secret in ["invented-pass", "invented-sid", "invented-key", "PUBLICKEY"] {
        assert!(!log.contains(secret));
    }
    assert_eq!(sanitize(&output, true), output);
    assert_eq!(
        sanitize(&json!({"file_key":"available"}), true)["file_key"],
        "available"
    );
    assert_eq!(
        sanitize(&json!({"file_key":"invented-key-material"}), true)["file_key"],
        REDACTED
    );
}

const DIGEST_HEADER: &str = concat!(
    "Authorization: Digest username=\"alice\", realm=\"mega\", ",
    "nonce=\"dcd98b7102dd2f0e10a3\", uri=\"/api\", ",
    "response=\"6629fae49393a05397450978507c4ef1\", ",
    "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\", qop=auth, ",
    "nc=00000001, cnonce=\"0a4f113b8fa5\""
);

#[test]
fn exact_source_free_text_shapes_are_masked_while_ordinary_sentences_stay_unchanged() {
    for (input, secret) in [
        ("password: hunter2-fake", "hunter2-fake"),
        ("Password = hunter2-fake", "hunter2-fake"),
        ("the password is hunter2-fake", "hunter2-fake"),
        ("password: \"quoted fake value\"", "quoted fake value"),
        ("password: 'single fake value'", "single fake value"),
        ("PASSPHRASE: vault-fake-phrase", "vault-fake-phrase"),
        ("vault passphrase = vault-fake-phrase", "vault-fake-phrase"),
        ("SID was abc123fakesid", "abc123fakesid"),
        ("sid: abc123fakesid", "abc123fakesid"),
        ("session id is abc123fakesid", "abc123fakesid"),
        ("MFA code 123456", "123456"),
        ("mfa_code: 123456", "123456"),
        ("OTP 987654", "987654"),
        ("2FA code 445566", "445566"),
        ("API key: fake-api-key-value", "fake-api-key-value"),
        ("api_key=fake-api-key-value", "fake-api-key-value"),
        ("Api Key is fake-api-key-value", "fake-api-key-value"),
        ("token is fake-token-value", "fake-token-value"),
        ("access_token=fake-token-value", "fake-token-value"),
        ("Authorization: Bearer fake.jwt.value", "fake.jwt.value"),
        ("authorization=fake-header-value", "fake-header-value"),
        ("sent Bearer fake.jwt.value upstream", "fake.jwt.value"),
        (
            "proxy http://user:fakepass@proxy.example:8080 failed",
            "fakepass",
        ),
        ("socks5://someone:fakepass@10.0.0.1:1080", "fakepass"),
        ("secret: fake-secret-value", "fake-secret-value"),
    ] {
        let clean = text(input);
        assert!(
            !clean.contains(secret),
            "synthetic secret escaped redaction"
        );
        assert!(clean.contains(REDACTED) || clean.contains("#<key>"));
    }
    for ordinary in [
        "Uploaded quarterly-report.pdf successfully",
        "Could not open C:\\Users\\me\\secret_plans.txt",
        "Basic authentication failed for the proxy",
        "password required but not provided",
        "Retrying chunk 4 of 12 after a timeout",
        "Destination /srv/backups/2026 already exists",
    ] {
        assert_eq!(text(ordinary), ordinary);
    }
}

#[test]
fn exact_auth_headers_punctuation_and_repeated_redaction_preserve_surrounding_text() {
    let clean = text(DIGEST_HEADER);
    assert_eq!(clean, "Authorization: <redacted>");
    assert_eq!(text(&clean), clean);
    for secret in [
        "alice",
        "dcd98b7102dd2f0e10a3",
        "6629fae49393a05397450978507c4ef1",
        "5ccc069c403ebaf9f0171e9517f40e41",
        "0a4f113b8fa5",
    ] {
        assert!(!clean.contains(secret));
    }
    assert_eq!(
        text("Digest username=\"alice\", response=\"6629fae49393a05397450978507c4ef1\""),
        "Digest <redacted>"
    );
    assert_eq!(
        text("Digest authentication failed"),
        "Digest authentication failed"
    );
    for header in [
        "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==",
        "proxy-authorization: Bearer proxy-fake-token",
        "Proxy-Authorization: Digest username=\"bob\", response=\"deadbeefcafe\"",
        "PROXY-AUTHORIZATION=Basic dXNlcjpwYXNzd29yZA==",
    ] {
        let clean = text(header);
        for secret in [
            "dXNlcjpwYXNzd29yZA==",
            "proxy-fake-token",
            "deadbeefcafe",
            "bob",
        ] {
            assert!(!clean.contains(secret));
        }
        assert!(clean.contains(REDACTED));
    }
    let multiline = concat!(
        "POST /api HTTP/1.1\n",
        "Authorization: Digest username=\"alice\", response=\"deadbeefcafe\"\n",
        "Content-Type: application/json\n",
        "the transfer then failed for an unrelated reason"
    );
    assert_eq!(
        text(multiline),
        concat!(
            "POST /api HTTP/1.1\nAuthorization: <redacted>\n",
            "Content-Type: application/json\nthe transfer then failed for an unrelated reason"
        )
    );
    let many = text("password: p1-fake and sid: s2-fake and token: t3-fake");
    assert_eq!(
        many,
        "password: <redacted> and sid: <redacted> and token: <redacted>"
    );
    assert_eq!(many.matches(REDACTED).count(), 3);
    assert_eq!(text(&many), many);
    assert_eq!(
        text("failed (password: hunter2-fake), retrying now"),
        "failed (password: <redacted>), retrying now"
    );
    assert_eq!(text("the sid was abc123fake."), "the sid was <redacted>.");
}

#[test]
fn exact_recursive_fields_and_intentional_links_preserve_only_the_allowed_public_material() {
    let link = "https://mega.nz/folder/ABCD1234#PUBLICKEYVALUE";
    assert_eq!(
        sanitize(&json!({"event":"result","share_link":link}), true)["share_link"],
        link
    );
    assert_eq!(
        sanitize(
            &json!({"share_link":"https://mega.nz/folder/ABCD1234?sid=fakesid#PUBLICKEYVALUE"}),
            true
        )["share_link"],
        "https://mega.nz/folder/ABCD1234?sid=<redacted>#PUBLICKEYVALUE"
    );
    let record = json!({"event":"result","status":"failed",
        "error":"login rejected: password: fake-nested-value",
        "details":{"cause":["SID was fake-nested-sid",{"note":"api key: fake-nested-key"}]}});
    let clean = sanitize(&record, true);
    assert_eq!(clean["status"], "failed");
    let serialized = clean.to_string();
    for secret in ["fake-nested-value", "fake-nested-sid", "fake-nested-key"] {
        assert!(!serialized.contains(secret));
    }
    for field in ["password", "api_key"] {
        assert_eq!(
            sanitize(&json!({(field):"anything"}), true)[field],
            REDACTED
        );
    }
    let once = text("password: fake-value and sid: fake-sid");
    assert_eq!(text(&once), once);
}

#[test]
fn quoted_cli_secret_options_hide_the_whole_value_and_preserve_unrelated_arguments() {
    use megabasterd_cli::terminal::redaction::log_text;

    for option in [
        "--token",
        "--password",
        "--share-password",
        "--vault-passphrase",
        "--mfa-code",
        "--elc-api-key",
    ] {
        for quote in ['"', '\''] {
            let input =
                format!("download L {option} {quote}hunter2 TAIL_MUST_NOT_LEAK{quote} -o out");
            let expected = format!("download L {option} <redacted> -o out");
            assert_eq!(text(&input), expected);
            assert_eq!(log_text(&input), expected);
            assert_eq!(
                sanitize(&json!({"message":input}), false)["message"],
                expected
            );
            assert_eq!(text(&expected), expected);
            assert_eq!(log_text(&expected), expected);
        }
    }
}

#[test]
fn bounded_pathological_header_finishes_without_catastrophic_backtracking() {
    use std::time::{Duration, Instant};

    // Warm static patterns separately: the source assertion measures redaction, not lazy setup.
    assert_eq!(text("ordinary"), "ordinary");
    let hostile = format!(
        "Authorization: {} {}",
        "a".repeat(20_000),
        "b=c, ".repeat(4_000)
    );
    let started = Instant::now();
    let clean = text(&hostile);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(clean, "Authorization: <redacted>");
}
