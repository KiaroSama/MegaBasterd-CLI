//! Only approved DLC service aliases can relax exact URL-origin equality.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn dlc_redirects_accept_only_the_approved_normalized_https_origin() {
    let initial = Url::parse(super::super::containers::DLC_SERVICE_URL).unwrap();
    for (status, location, expected) in [
        (302, "/mirror", "https://service.jdownloader.org/mirror"),
        (
            307,
            "/elsewhere/service.php",
            "https://service.jdownloader.org/elsewhere/service.php",
        ),
        (
            302,
            "https://service.jdownloader.org/mirror",
            "https://service.jdownloader.org/mirror",
        ),
        (
            302,
            "https://Service.JDownloader.ORG:443/mirror",
            "https://service.jdownloader.org/mirror",
        ),
        (
            302,
            "https://service.jdownloader.org./mirror",
            "https://service.jdownloader.org./mirror",
        ),
    ] {
        let next = redirect_target(
            &initial,
            &initial,
            &Method::POST,
            Redirects::Service { same_origin: true },
            status,
            Some(location),
            0,
        )
        .unwrap()
        .unwrap();
        assert_eq!(next.as_str(), expected);
        super::super::link_services::validate_dlc_endpoint(&next).unwrap();
    }
    for location in [
        "https://evil.example/dlcrypt",
        "//evil.example/x",
        "https://service.jdownloader.org:8443/x",
        "https://user:pass@service.jdownloader.org/x",
        "http://service.jdownloader.org/x",
        "ftp://service.jdownloader.org/x",
        "https://localhost/x",
        "https://127.0.0.1/x",
        "https://[::1]/x",
        "https://10.0.0.1/x",
        "https://192.168.1.5/x",
        "https://169.254.0.1/x",
        "https://[fd00::1]/x",
        "https://[fe80::1]/x",
    ] {
        assert!(
            redirect_target(
                &initial,
                &initial,
                &Method::POST,
                Redirects::Service { same_origin: true },
                302,
                Some(location),
                0,
            )
            .is_err()
        );
    }
    assert!(matches!(
        redirect_target(
            &initial,
            &initial,
            &Method::POST,
            Redirects::Service { same_origin: true },
            302,
            Some("https://service.jdownloader.org:8443/x"),
            0,
        ),
        Err(Error::Protocol(message)) if message.contains("cross-origin")
    ));
    // Credentialed API reads retain exact web-origin equality, even for these service aliases.
    assert!(
        redirect_target(
            &initial,
            &initial,
            &Method::GET,
            Redirects::Reads { credentialed: true },
            302,
            Some("https://service.jdownloader.org./mirror"),
            0,
        )
        .is_err()
    );
    let arbitrary = Url::parse("https://service.example/api").unwrap();
    assert!(
        redirect_target(
            &arbitrary,
            &arbitrary,
            &Method::POST,
            Redirects::Service { same_origin: true },
            302,
            Some("https://service.example./mirror"),
            0,
        )
        .is_err()
    );
}
