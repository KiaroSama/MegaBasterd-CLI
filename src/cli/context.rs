use std::sync::Arc;
use std::time::Duration;

use super::args::AccountOptions;
use crate::error::{Error, Result};
use crate::protocol::{api::Api, auth, cloud::Cloud, transport::Transport};
use crate::storage::{
    accounts::Accounts,
    config::Config,
    config_store::ConfigStore,
    paths::Paths,
    proxies::{Pool, ProxyStore, Routing},
    sessions::Sessions,
    vault::Vault,
};
use crate::terminal::{logging::Logger, output::Output, prompts};
use crate::transfers::control::Control;

#[cfg(test)]
#[path = "context_startup_tests.rs"]
mod startup_tests;

pub struct Context {
    pub paths: Paths,
    pub config: Config,
    pub config_store: ConfigStore,
    pub config_error: Option<Error>,
    pub output: Output,
    pub control: Control,
    pub logger: Option<Arc<Logger>>,
    pool: Option<Arc<Pool>>,
    #[cfg(test)]
    peer_api: Option<Api>,
}

impl Context {
    pub fn start(json: bool, quiet: bool, logging: Option<bool>) -> Result<Self> {
        Self::start_for_command(json, quiet, logging, "unknown")
    }

    pub(crate) fn start_for_command(
        json: bool,
        quiet: bool,
        logging: Option<bool>,
        command: &'static str,
    ) -> Result<Self> {
        Self::start_with_output(
            Paths::discover()?,
            Output::new(json, quiet),
            logging,
            command,
        )
    }

    pub(crate) fn start_with_output(
        paths: Paths,
        output: Output,
        logging: Option<bool>,
        command: &'static str,
    ) -> Result<Self> {
        let config_store = ConfigStore::new(paths.config());
        let (config, warnings, config_error) = match config_store.load_for_command() {
            Ok((config, warnings)) => (config, warnings, None),
            Err(error) => (Config::default(), Vec::new(), Some(error)),
        };
        output.set_diagnostic_level(if output.quiet {
            "ERROR"
        } else {
            &config.log_level
        })?;
        let logger = if logging.unwrap_or(config.log_to_file) {
            match Logger::configured_for_command(
                &paths.logs,
                config.log_max_bytes,
                config.log_backups,
                command,
            ) {
                Ok(logger) => Some(Arc::new(logger)),
                Err(_) => {
                    output.logging_init_warning()?;
                    None
                }
            }
        } else {
            None
        };
        if let Some(logger) = &logger {
            output.attach_logger(logger.clone())?;
        }
        for warning in warnings {
            output.message("WARNING", &warning)?;
        }
        Ok(Self {
            paths,
            config,
            config_store,
            config_error,
            output,
            control: Control::new(),
            logger,
            pool: None,
            #[cfg(test)]
            peer_api: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn test_context(root: &std::path::Path) -> Self {
        let paths = Paths {
            root: root.to_owned(),
            user: root.join("private user"),
            logs: root.join("private logs"),
            output: root.join("output"),
        };
        Self {
            config_store: ConfigStore::new(paths.config()),
            paths,
            config: Config::default(),
            config_error: None,
            output: Output::new(true, true),
            control: Control::new(),
            logger: None,
            pool: None,
            peer_api: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_peer(root: &std::path::Path, api: Api, output: Output) -> Self {
        let mut context = Self::test_context(root);
        context.control = api.control.clone();
        context.output = output;
        context.peer_api = Some(api);
        context
    }

    pub fn require_config(&self) -> Result<()> {
        if let Some(error) = &self.config_error {
            return Err(Error::Corrupt(format!(
                "{}; inspect or explicitly recover configuration before continuing",
                error
            )));
        }
        Ok(())
    }

    pub fn accounts(&self) -> Accounts {
        Accounts::new(self.paths.accounts())
    }

    pub fn selected_account(
        &self,
        explicit: Option<&str>,
    ) -> Result<crate::storage::accounts::Account> {
        static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        let accounts = self.accounts();
        if explicit.is_none_or(str::is_empty) {
            let data = accounts.list()?;
            if data
                .default_email
                .as_deref()
                .filter(|value| !value.is_empty())
                .zip(
                    self.config
                        .default_account
                        .as_deref()
                        .filter(|value| !value.is_empty()),
                )
                .is_some_and(|(vault, configured)| !vault.eq_ignore_ascii_case(configured))
                && !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                self.output.message("WARNING", "Account-vault default and config default_account disagree; using the vault default.")?;
            }
        }
        accounts.resolve(explicit, self.config.default_account.as_deref())
    }

    pub(crate) fn secret(
        &self,
        question: &str,
        supplied: Option<&str>,
        flag: &str,
    ) -> Result<zeroize::Zeroizing<String>> {
        use std::io::IsTerminal;

        self.secret_with(
            question,
            supplied,
            flag,
            std::io::stdin().is_terminal(),
            prompts::secret,
        )
    }

    fn secret_with(
        &self,
        question: &str,
        supplied: Option<&str>,
        flag: &str,
        interactive: bool,
        read: impl FnOnce(&str, Option<&str>) -> Result<zeroize::Zeroizing<String>>,
    ) -> Result<zeroize::Zeroizing<String>> {
        if supplied.is_none() && (self.output.json || !interactive) {
            return Err(Error::Auth(format!(
                "Secret input is required: pass {flag} in noninteractive or JSON mode."
            )));
        }
        read(question, supplied)
    }

    pub fn vault(&self, supplied: Option<&str>) -> Result<Vault> {
        let supplied_env = std::env::var("MEGABASTERD_VAULT_PASSPHRASE")
            .ok()
            .map(zeroize::Zeroizing::new);
        let passphrase = self.secret(
            "Vault passphrase:",
            supplied.or(supplied_env.as_deref().map(String::as_str)),
            "--vault-passphrase",
        )?;
        let vault = Vault::new(&passphrase);
        vault.require_passphrase()?;
        Ok(vault)
    }

    pub fn api(&mut self, explicit: Option<&str>) -> Result<Api> {
        self.require_config()?;
        #[cfg(test)]
        if let Some(api) = &self.peer_api {
            if explicit.is_some() {
                return Err(Error::invalid("Fixture API cannot use a configured proxy"));
            }
            return api.fork();
        }
        if self.config.smart_proxy_enabled && explicit.is_none() && self.pool.is_none() {
            let urls = ProxyStore::new(self.paths.proxies()).list()?;
            let configured = self
                .config
                .smart_proxy_url
                .as_deref()
                .unwrap_or("")
                .split(|character: char| {
                    character.is_whitespace() || matches!(character, ',' | ';')
                })
                .filter(|url| !url.is_empty())
                .map(str::to_owned)
                .collect();
            self.pool = Some(Pool::new(urls, configured, Some(self.paths.proxies()))?);
        }
        let routing = Routing {
            explicit: explicit.map(str::to_owned),
            pool: self.pool.clone(),
            force: self.config.force_smart_proxy,
        };
        let agent = if self.config.user_agent.is_empty() {
            format!("MegaBasterd-CLI/{}", env!("CARGO_PKG_VERSION"))
        } else {
            self.config.user_agent.clone()
        };
        let transport = Transport::new(
            routing,
            Duration::from_secs(self.config.timeout_seconds),
            agent,
            self.control.clone(),
        )?;
        Api::new(transport, self.control.clone())
    }

    pub fn cloud(&mut self, options: &AccountOptions) -> Result<(Cloud, Vault)> {
        let (api, session, vault) = self.authenticated_api(options, None)?;
        Ok((Cloud::new(api, session), vault))
    }

    pub fn authenticated_api(
        &mut self,
        options: &AccountOptions,
        explicit: Option<&str>,
    ) -> Result<(Api, auth::Session, Vault)> {
        self.require_config()?;
        if self.accounts().list()?.accounts.is_empty() {
            return Err(Error::Auth(
                "No accounts found. Use mb account add first.".into(),
            ));
        }
        let account = self.selected_account(options.account.as_deref())?;
        let vault = self.vault(options.vault_passphrase.as_deref())?;
        let (api, session) =
            self.session(&account, &vault, options.mfa_code.as_deref(), explicit)?;
        Ok((api, session, vault))
    }

    pub fn session(
        &mut self,
        account: &crate::storage::accounts::Account,
        vault: &Vault,
        mfa_code: Option<&str>,
        explicit: Option<&str>,
    ) -> Result<(Api, auth::Session)> {
        let mut api = self.api(explicit)?;
        let sessions = Sessions::new(self.paths.session(&account.email));
        let session = match sessions.restore(&account.email, vault, &mut api)? {
            Some(session) => session,
            None => {
                let password = Accounts::password(account, vault)?;
                let session = auth::login(&mut api, &account.email, &password, mfa_code, || {
                    Ok(self
                        .secret("Current six-digit 2FA code:", None, "--mfa-code")?
                        .to_string())
                })?;
                self.remember_session(&session, vault);
                session
            }
        };
        Ok((api, session))
    }

    /// Optional cache failure must not discard an authenticated session or fail its command.
    pub fn remember_session(&self, session: &auth::Session, vault: &Vault) -> bool {
        match Sessions::new(self.paths.session(&session.email)).remember(session, vault) {
            Ok(()) => true,
            Err(_) => {
                self.diagnostic(
                    "WARNING",
                    "AUTH",
                    "The authenticated session could not be cached; the next command may require signing in again.",
                    &serde_json::json!({}),
                );
                false
            }
        }
    }

    pub fn event(&self, component: &str, message: &str, fields: &serde_json::Value) {
        self.diagnostic("INFO", component, message, fields);
    }

    pub fn diagnostic(
        &self,
        level: &str,
        component: &str,
        message: &str,
        fields: &serde_json::Value,
    ) {
        let _ = self.output.diagnostic_console(level, message);
        if let Some(logger) = &self.logger
            && logger.write(level, component, message, fields).is_err()
        {
            let _ = self.output.logging_warning(logger);
        }
    }

    pub fn report_error(&self, error: &Error) {
        let _ = self.output.error(error);
    }

    pub fn finish(&self, code: i32) {
        if let Some(logger) = &self.logger
            && logger.finish(code).is_err()
        {
            let _ = self.output.logging_warning(logger);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn machine_or_headless_secret_policy_refuses_before_any_reader_but_keeps_supplied_input() {
        for json in [false, true] {
            for interactive in [false, true] {
                let mut context = Context::test_context(std::path::Path::new("unused"));
                context.output = Output::with_writers(json, false, Vec::new(), Vec::new());
                for flag in ["--password", "--vault-passphrase", "--mfa-code"] {
                    if json || !interactive {
                        let result =
                            context.secret_with("Secret:", None, flag, interactive, |_, _| {
                                panic!("a forbidden secret reader was reached")
                            });
                        assert!(
                            matches!(result, Err(Error::Auth(message)) if message.contains(flag))
                        );
                    } else {
                        let result = context
                            .secret_with(
                                "Secret:",
                                None,
                                flag,
                                interactive,
                                |question, supplied| {
                                    assert_eq!(question, "Secret:");
                                    assert!(supplied.is_none());
                                    Ok(Zeroizing::new("local answer".into()))
                                },
                            )
                            .unwrap();
                        assert_eq!(&*result, "local answer");
                    }
                    let result = context
                        .secret_with(
                            "Secret:",
                            Some(" supplied  value "),
                            flag,
                            interactive,
                            |_, supplied| Ok(Zeroizing::new(supplied.unwrap().to_owned())),
                        )
                        .unwrap();
                    assert_eq!(&*result, " supplied  value ");
                }
            }
        }
    }
}
