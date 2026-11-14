use serde_json::{Value, json};

#[cfg(test)]
#[path = "account_info_peer_tests.rs"]
mod info_tests;

use super::{
    args::{Account, AccountOptions, VaultOptions},
    context::Context,
};
use crate::error::{Error, Result};
use crate::protocol::{api::field, auth};
use crate::storage::{accounts::Accounts, sessions::Sessions};
use crate::terminal::prompts;

pub fn quota(user: &Value) -> Result<(u64, u64)> {
    let total = field(user, "mstrg")?
        .as_u64()
        .ok_or_else(|| Error::protocol("Account quota total is invalid"))?;
    let used = field(user, "cstrg")?
        .as_u64()
        .ok_or_else(|| Error::protocol("Account quota usage is invalid"))?;
    Ok((total, used))
}

pub fn dispatch(context: &mut Context, command: Account) -> Result<()> {
    dispatch_with_confirmation(context, command, || {
        prompts::confirmed("Add account anyway?", false)
    })
}

pub(super) fn dispatch_with_confirmation(
    context: &mut Context,
    command: Account,
    add_anyway: impl FnMut() -> Result<bool>,
) -> Result<()> {
    dispatch_with_mfa(context, command, add_anyway, |context| {
        context
            .secret("Current six-digit 2FA code:", None, "--mfa-code")
            .map(|answer| answer.to_string())
    })
}

pub(super) fn dispatch_with_mfa(
    context: &mut Context,
    command: Account,
    mut add_anyway: impl FnMut() -> Result<bool>,
    mut read_mfa: impl FnMut(&Context) -> Result<String>,
) -> Result<()> {
    match command {
        Account::List => {
            let data = context.accounts().list()?;
            let rows = data
                .accounts
                .iter()
                .map(|account| {
                    vec![
                        if data.default_email.as_deref() == Some(&account.email) {
                            "Y".into()
                        } else {
                            "".into()
                        },
                        account.email.clone(),
                        account.label.clone().unwrap_or_default(),
                        account
                            .quota_total
                            .map(crate::terminal::progress::format_bytes)
                            .unwrap_or_else(|| "Unknown".into()),
                        account
                            .quota_used
                            .map(crate::terminal::progress::format_bytes)
                            .unwrap_or_else(|| "Unknown".into()),
                    ]
                })
                .collect::<Vec<_>>();
            if rows.is_empty() {
                context
                    .output
                    .message("INFO", "No accounts found. Use mb account add first.")
            } else {
                context
                    .output
                    .table(&["Default", "Account", "Label", "Total", "Used"], &rows)
            }
        }
        Account::Add {
            email,
            password,
            label,
            default,
            vault_passphrase,
            verify: _,
            no_verify,
            mfa_code,
        } => {
            let password =
                context.secret("Account password:", password.as_deref(), "--password")?;
            let mut authenticated = None;
            if !no_verify {
                let mut api = context.api(None)?;
                let mut input_failed = false;
                match auth::login(&mut api, &email, &password, mfa_code.as_deref(), || {
                    let answer = read_mfa(context);
                    input_failed = answer.is_err();
                    answer
                }) {
                    Ok(session) => authenticated = Some(session),
                    Err(error) if input_failed => return Err(error),
                    Err(error @ (Error::Mega { .. } | Error::Auth(_))) => {
                        context
                            .output
                            .message("ERROR", &format!("Login verification failed: {error}"))?;
                        context.control.checkpoint()?;
                        if !add_anyway()? {
                            return Ok(());
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            context.control.checkpoint()?;
            let vault = context.vault(vault_passphrase.as_deref())?;
            let inserted = context
                .accounts()
                .add(&email, &password, label, default, &vault)?;
            let verified = authenticated.is_some();
            let cached = authenticated
                .as_ref()
                .is_some_and(|session| context.remember_session(session, &vault));
            if !verified && !inserted {
                return Err(Error::invalid("Account already exists"));
            }
            if inserted {
                context.event(
                    "ACCOUNT",
                    "Account saved",
                    &json!({"verified":verified,"session_cached":cached}),
                );
                context.output.message("INFO", "Account saved.")
            } else {
                context.event(
                    "ACCOUNT",
                    "Stored account signed in",
                    &json!({"verified":true,"session_cached":cached}),
                );
                context.output.message(
                    "SUCCESS",
                    if cached {
                        "Signed in (already stored; session refreshed)."
                    } else {
                        "Signed in (already stored; session was not cached)."
                    },
                )
            }
        }
        Account::Remove { email_or_label } => {
            let account = context.accounts().find(Some(&email_or_label))?;
            if !prompts::confirmed("Remove this stored account?", false)? {
                return Ok(());
            }
            context.accounts().remove(&email_or_label)?;
            Sessions::new(context.paths.session(&account.email)).forget()?;
            context
                .output
                .message("INFO", "Stored account and local session removed.")
        }
        Account::Default { email_or_label } => {
            context.accounts().set_default(&email_or_label)?;
            context.output.message("INFO", "Default account saved.")
        }
        Account::Info {
            email_or_label,
            auth,
        } => {
            let options = AccountOptions {
                account: email_or_label,
                vault_passphrase: auth.vault_passphrase,
                mfa_code: auth.mfa_code,
            };
            let (mut cloud, _) = context.cloud(&options)?;
            let user = cloud.api.request(json!({"a":"ug"}), &[])?;
            let (total, used) = match cloud.api.request(json!({"a":"uq","strg":1,"xfer":1}), &[]) {
                Ok(usage) => {
                    let (total, used) = quota(&usage)?;
                    context
                        .accounts()
                        .quota(&cloud.session.email, total, used)?;
                    (total, used)
                }
                Err(
                    error @ (Error::Canceled
                    | Error::Auth(_)
                    | Error::Mega {
                        code: -15 | -26, ..
                    }),
                ) => {
                    return Err(error);
                }
                Err(_) => {
                    context.output.message(
                        "ERROR",
                        "Could not fetch quota; saved account information was kept.",
                    )?;
                    return Ok(());
                }
            };
            let name = user.get("name").and_then(Value::as_str).unwrap_or("");
            context.output.table(
                &["Field", "Value"],
                &[
                    vec!["Email".into(), cloud.session.email.clone()],
                    vec!["Name".into(), name.to_owned()],
                    vec![
                        "Total storage".into(),
                        crate::terminal::progress::format_bytes(total),
                    ],
                    vec![
                        "Used storage".into(),
                        crate::terminal::progress::format_bytes(used),
                    ],
                ],
            )
        }
        Account::RefreshAll { auth } => refresh_all(context, auth),
        Account::Logout {
            email_or_label,
            all,
            vault_passphrase,
        } => {
            let accounts = if all {
                context.accounts().list()?.accounts
            } else {
                vec![context.selected_account(email_or_label.as_deref())?]
            };
            let mut cached = Vec::new();
            for account in accounts {
                context.control.checkpoint()?;
                if Sessions::new(context.paths.session(&account.email)).has_cached()? {
                    cached.push(account);
                }
            }
            if cached.is_empty() {
                return context.output.message("INFO", "No stored session to end. The account and its stored credential are untouched; mb account remove deletes those.");
            }
            let vault = context.vault(vault_passphrase.as_deref())?;
            let mut failures = 0;
            let mut ended = 0;
            for account in cached {
                context.control.checkpoint()?;
                let sessions = Sessions::new(context.paths.session(&account.email));
                let result = (|| {
                    use crate::storage::sessions::LogoutOutcome;
                    let outcome = sessions.end_cached(&account.email, &vault, |session| {
                        let mut api = context.api(None)?;
                        api.set_session(&session.sid);
                        context.control.checkpoint()?;
                        let result = api.request(json!({"a":"sml"}), &[]).map(|_| ());
                        api.clear_session();
                        result
                    })?;
                    match outcome {
                        LogoutOutcome::Missing => (),
                        LogoutOutcome::Unreadable => context.output.message("WARNING", "Cached session could not be read; file removed only. Remote logout was not confirmed.")?,
                        LogoutOutcome::Ended => ended += 1,
                        LogoutOutcome::Rejected(error) => context.output.message("WARNING", &format!("{error}; cached session removed. Remote logout was not confirmed."))?,
                    }
                    Ok(())
                })();
                if let Err(error) = result {
                    if matches!(
                        error,
                        Error::Canceled | Error::AmbiguousMutation(_) | Error::Corrupt(_)
                    ) {
                        return Err(error);
                    }
                    failures += 1;
                    context.output.message("ERROR", &error.to_string())?;
                }
            }
            if failures > 0 {
                return Err(Error::Auth("Some sessions could not be invalidated; uncertain local session files were preserved".into()));
            }
            if ended > 0 {
                context
                    .output
                    .message("INFO", "Sessions logged out. Stored accounts were kept.")?;
            }
            Ok(())
        }
    }
}

fn refresh_all(context: &mut Context, auth: VaultOptions) -> Result<()> {
    let accounts = context.accounts().list()?.accounts;
    if accounts.is_empty() {
        return Err(Error::Auth(
            "No accounts found. Use mb account add first.".into(),
        ));
    }
    let vault = context.vault(auth.vault_passphrase.as_deref())?;
    let mut failures = 0;
    for account in accounts {
        context.control.checkpoint()?;
        let result = (|| {
            let mut api = context.api(None)?;
            let sessions = Sessions::new(context.paths.session(&account.email));
            let session = match sessions.restore(&account.email, &vault, &mut api)? {
                Some(session) => session,
                None => {
                    let password = Accounts::password(&account, &vault)?;
                    let session = auth::login(
                        &mut api,
                        &account.email,
                        &password,
                        auth.mfa_code.as_deref(),
                        || {
                            Ok(context
                                .secret("Current six-digit 2FA code:", None, "--mfa-code")?
                                .to_string())
                        },
                    )?;
                    context.remember_session(&session, &vault);
                    session
                }
            };
            context.control.checkpoint()?;
            let usage = api.request(json!({"a":"uq","strg":1,"xfer":1}), &[])?;
            let (total, used) = quota(&usage)?;
            context.control.checkpoint()?;
            context.accounts().quota(&session.email, total, used)
        })();
        if let Err(error) = result {
            if matches!(error, Error::Canceled) {
                return Err(error);
            }
            failures += 1;
            context.output.message("ERROR", &error.to_string())?;
        }
    }
    if failures > 0 {
        Err(Error::Auth("Some account quota refreshes failed".into()))
    } else {
        context
            .output
            .message("INFO", "All account quotas refreshed.")
    }
}
