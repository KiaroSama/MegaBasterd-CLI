#![allow(clippy::unwrap_used)]

use megabasterd_cli::{
    error::Error,
    storage::{
        accounts::{Account, AccountData, Accounts},
        files::Store,
        vault::Vault,
    },
};

#[test]
fn duplicate_account_preserves_credentials_metadata_and_default_under_the_same_vault_lock() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/account-selection");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("private/accounts.json");
    let accounts = Accounts::new(&path);
    let vault = Vault::new("right-pass");
    assert!(
        accounts
            .add(
                "u@example.com",
                "topsecret",
                Some("primary".into()),
                false,
                &vault
            )
            .unwrap()
    );
    assert_eq!(
        accounts.list().unwrap().default_email.as_deref(),
        Some("u@example.com")
    );
    accounts.quota("u@example.com", 8192, 2048).unwrap();
    assert!(
        accounts
            .add("other@example.com", "other-password", None, false, &vault)
            .unwrap()
    );
    let reloaded = Accounts::new(&path).list().unwrap();
    let mut emails: Vec<_> = reloaded.accounts.iter().map(|a| a.email.as_str()).collect();
    emails.sort_unstable();
    assert_eq!(emails, ["other@example.com", "u@example.com"]);
    assert_eq!(reloaded.default_email.as_deref(), Some("u@example.com"));
    accounts.set_default("other@example.com").unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(
        !accounts
            .add(
                "U@Example.Com",
                "replacement",
                Some("new label".into()),
                true,
                &vault
            )
            .unwrap()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let stored = accounts.find(Some("PRIMARY")).unwrap();
    assert_eq!(&*Accounts::password(&stored, &vault).unwrap(), "topsecret");
    let encoded = String::from_utf8(before.clone()).unwrap();
    assert!(!encoded.contains("topsecret") && !encoded.contains("other-password"));
    let mut entry = serde_json::to_value(&stored).unwrap();
    entry["email"] = serde_json::json!("changed@example.com");
    let rebound: Account = serde_json::from_value(entry).unwrap();
    assert!(matches!(
        Accounts::password(&rebound, &vault),
        Err(Error::Auth(_))
    ));
    assert_eq!(stored.label.as_deref(), Some("primary"));
    assert_eq!(
        (stored.quota_total, stored.quota_used),
        (Some(8192), Some(2048))
    );
    assert_eq!(
        accounts.list().unwrap().default_email.as_deref(),
        Some("other@example.com")
    );
    let wrong = Vault::new("wrong-pass");
    assert!(
        matches!(Accounts::password(&stored, &wrong), Err(Error::Auth(message)) if message.contains("passphrase") && !message.contains("wrong-pass"))
    );
    for email in ["u@example.com", "new@example.com"] {
        assert!(matches!(
            accounts.add(email, "replacement", None, true, &wrong),
            Err(Error::Auth(message)) if message.contains("Wrong vault passphrase") && !message.contains("wrong-pass")
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    let reopened = Accounts::new(&path);
    assert_eq!(reopened.list().unwrap().accounts.len(), 2);
    assert_eq!(
        &*Accounts::password(&reopened.find(Some("u@example.com")).unwrap(), &vault).unwrap(),
        "topsecret"
    );
    accounts.set_default("primary").unwrap();
    assert_eq!(
        accounts.list().unwrap().default_email.as_deref(),
        Some("u@example.com")
    );
    assert_eq!(accounts.remove("primary").unwrap(), "u@example.com");
    assert!(matches!(
        accounts.find(Some("u@example.com")),
        Err(Error::Auth(_))
    ));
    assert_eq!(
        accounts.list().unwrap().default_email.as_deref(),
        Some("other@example.com")
    );
}

#[test]
fn explicit_account_then_vault_default_then_configuration_fallback_selects_the_same_account() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/account-selection");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("private/accounts.json");
    // Selection needs a plausible envelope, not a KDF or decryptable credential.
    let mut envelope = b"MBV2\x0f\x08\x01".to_vec();
    envelope.extend_from_slice(&[0; 44]);
    let encoded = megabasterd_cli::crypto::wire::b64_url_encode(&envelope);
    let account = |email: &str, label: &str| Account {
        email: email.into(),
        enc_password: encoded.clone(),
        label: Some(label.into()),
        quota_total: None,
        quota_used: None,
        last_used_iso: None,
        notes: None,
    };
    let mut data = AccountData {
        accounts: vec![
            account("one@example.invalid", "first"),
            account("two@example.invalid", "second"),
        ],
        default_email: Some("one@example.invalid".into()),
    };
    let locked = Store::new(&path).lock().unwrap();
    locked.save(&data).unwrap();
    drop(locked);
    let accounts = Accounts::new(path.clone());
    assert_eq!(
        accounts.resolve(None, Some("second")).unwrap().email,
        "one@example.invalid"
    );
    assert_eq!(
        accounts
            .resolve(Some("second"), Some("first"))
            .unwrap()
            .email,
        "two@example.invalid"
    );
    assert!(accounts.resolve(Some("missing"), Some("first")).is_err());
    for default in [None, Some(String::new())] {
        data.default_email = default;
        let locked = Store::new(&path).lock().unwrap();
        locked.save(&data).unwrap();
        drop(locked);
        assert_eq!(
            accounts.resolve(None, Some("second")).unwrap().email,
            "two@example.invalid"
        );
        assert_eq!(
            accounts.resolve(Some(""), Some("second")).unwrap().email,
            "two@example.invalid"
        );
        assert!(accounts.resolve(None, None).is_err());
    }
}
