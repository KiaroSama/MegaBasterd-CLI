use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "mb",
    version,
    about = "MegaBasterd CLI - native MEGA.nz command-line transfers",
    disable_help_flag = true,
    disable_help_subcommand = true,
    disable_version_flag = true,
    args_override_self = true
)]
pub struct Cli {
    #[arg(short='h',long,action=clap::ArgAction::Help,global=true)]
    pub help: Option<bool>,
    #[arg(long = "version", action = clap::ArgAction::Version)]
    pub version: Option<bool>,
    #[arg(short='v',long,action=clap::ArgAction::Count)]
    pub verbose: u8,
    #[arg(short = 'q', long)]
    pub quiet: bool,
    #[arg(long, overrides_with = "no_log_file")]
    pub log_file: bool,
    #[arg(long)]
    pub no_log_file: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Args, Clone)]
pub struct AccountOptions {
    #[arg(short = 'a', long)]
    pub account: Option<String>,
    #[arg(long, hide_env_values = true)]
    pub vault_passphrase: Option<String>,
    #[arg(long, hide_env_values = true)]
    pub mfa_code: Option<String>,
}

#[derive(Args, Clone)]
pub struct VaultOptions {
    #[arg(long, hide_env_values = true)]
    pub vault_passphrase: Option<String>,
    #[arg(long, hide_env_values = true)]
    pub mfa_code: Option<String>,
}

#[derive(Subcommand)]
pub enum Command {
    Download(Download),
    Upload(Upload),
    Stream(Stream),
    #[command(about = "Inspect a public link; no account or MFA needed")]
    Info(Info),
    Share {
        target: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        remove: bool,
        #[command(flatten)]
        auth: AccountOptions,
    },
    Ls {
        #[arg(default_value = "")]
        path: String,
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        auth: AccountOptions,
    },
    Mkdir {
        name: String,
        #[arg(long)]
        parent: Option<String>,
        #[command(flatten)]
        auth: AccountOptions,
    },
    Rm {
        target: String,
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        auth: AccountOptions,
    },
    Mv {
        source: String,
        destination: String,
        #[command(flatten)]
        auth: AccountOptions,
    },
    Rename {
        target: String,
        new_name: String,
        #[command(flatten)]
        auth: AccountOptions,
    },
    Search {
        pattern: String,
        #[arg(long)]
        regex: bool,
        #[command(flatten)]
        auth: AccountOptions,
    },
    Import {
        share_url: String,
        #[arg(long)]
        target: Option<String>,
        #[command(flatten)]
        auth: AccountOptions,
    },
    #[command(subcommand)]
    Trash(Trash),
    #[command(subcommand)]
    Account(Account),
    #[command(subcommand)]
    Queue(Queue),
    #[command(subcommand)]
    Proxy(Proxy),
    #[command(subcommand)]
    Crypter(Crypter),
    Split {
        #[arg(value_parser = super::values::existing_file())]
        source: PathBuf,
        part_size_mb: u64,
        #[arg(short = 'o', long, value_parser = super::values::output_directory())]
        output_dir: Option<PathBuf>,
    },
    Merge {
        #[arg(value_parser = super::values::existing_file())]
        any_part: PathBuf,
        #[arg(short = 'o', long, value_parser = super::values::output_file())]
        output: Option<PathBuf>,
        #[arg(long)]
        no_verify: bool,
        #[arg(long)]
        delete_parts: bool,
    },
    Thumbnail {
        #[arg(value_parser = super::values::existing_file())]
        source: PathBuf,
        #[arg(value_parser = super::values::output_file())]
        destination: PathBuf,
    },
    Watch {
        #[arg(long, default_value = "1.5", value_parser = super::values::watch_interval)]
        interval: f64,
        #[arg(short = 'o', long, value_parser = super::values::output_directory())]
        output: Option<PathBuf>,
        #[arg(long)]
        run: bool,
        #[command(flatten)]
        auth: VaultOptions,
    },
    #[command(subcommand)]
    Config(Config),
}

impl Command {
    pub(crate) fn log_name(&self) -> &'static str {
        match self {
            Self::Download(_) => "download",
            Self::Upload(_) => "upload",
            Self::Stream(_) => "stream",
            Self::Info(_) => "info",
            Self::Share { .. } => "share",
            Self::Ls { .. } => "ls",
            Self::Mkdir { .. } => "mkdir",
            Self::Rm { .. } => "rm",
            Self::Mv { .. } => "mv",
            Self::Rename { .. } => "rename",
            Self::Search { .. } => "search",
            Self::Import { .. } => "import",
            Self::Trash(_) => "trash",
            Self::Account(_) => "account",
            Self::Queue(_) => "queue",
            Self::Proxy(_) => "proxy",
            Self::Crypter(_) => "crypter",
            Self::Split { .. } => "split",
            Self::Merge { .. } => "merge",
            Self::Thumbnail { .. } => "thumbnail",
            Self::Watch { .. } => "watch",
            Self::Config(_) => "config",
        }
    }
}

#[derive(Args)]
pub struct Download {
    pub urls: Vec<String>,
    #[arg(short = 'o', long, value_parser = super::values::output_directory())]
    pub output: Option<PathBuf>,
    #[arg(short = 'w', long)]
    pub workers: Option<u32>,
    #[arg(short = 'l', long)]
    pub limit: Option<f64>,
    #[arg(short = 'p', long)]
    pub password: Option<String>,
    #[arg(long)]
    pub no_verify: bool,
    #[arg(long, alias = "force")]
    pub overwrite: bool,
    #[arg(long)]
    pub rename: Option<String>,
    #[arg(long)]
    pub proxy: Option<String>,
    #[arg(short = 'i', long, value_parser = super::values::existing_file())]
    pub input_file: Option<PathBuf>,
    #[arg(long)]
    pub elc_user: Option<String>,
    #[arg(long)]
    pub elc_api_key: Option<String>,
    #[arg(short = 'P', long)]
    pub parallel: Option<u32>,
    #[arg(short = 'I', long)]
    pub include: Vec<String>,
    #[arg(short = 'X', long)]
    pub exclude: Vec<String>,
    #[arg(long)]
    pub select: bool,
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub auth: AccountOptions,
}

#[derive(Args)]
pub struct Upload {
    #[arg(required = true, value_parser = super::values::existing_path())]
    pub paths: Vec<PathBuf>,
    #[command(flatten)]
    pub auth: AccountOptions,
    #[arg(short = 'w', long)]
    pub workers: Option<u32>,
    #[arg(short = 'l', long)]
    pub limit: Option<f64>,
    #[arg(long)]
    pub rename: Option<String>,
    #[arg(long)]
    pub target: Option<String>,
    #[arg(long)]
    pub keep_structure: bool,
    #[arg(long)]
    pub keep_going: bool,
    #[arg(long)]
    pub auto_account: bool,
    #[arg(short = 'P', long)]
    pub parallel: Option<u32>,
    #[arg(long)]
    pub share: bool,
    #[arg(long)]
    pub share_password: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct Stream {
    pub url: String,
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
    #[arg(short = 'H', long)]
    pub host: Option<String>,
    #[arg(long)]
    pub password: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
    #[arg(long)]
    pub allow_query_token: bool,
    #[arg(long)]
    pub proxy: Option<String>,
    #[arg(long)]
    pub elc_user: Option<String>,
    #[arg(long)]
    pub elc_api_key: Option<String>,
}

#[derive(Args)]
pub struct Info {
    pub url: String,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub password: Option<String>,
    #[arg(long)]
    pub elc_user: Option<String>,
    #[arg(long)]
    pub elc_api_key: Option<String>,
}

#[derive(Subcommand)]
pub enum Trash {
    List {
        #[command(flatten)]
        auth: AccountOptions,
    },
    Empty {
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        auth: AccountOptions,
    },
}

#[derive(Subcommand)]
pub enum Account {
    List,
    Add {
        email: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        default: bool,
        #[arg(long)]
        vault_passphrase: Option<String>,
        #[arg(long,action=clap::ArgAction::SetTrue,overrides_with="no_verify")]
        verify: bool,
        #[arg(long)]
        no_verify: bool,
        #[arg(long)]
        mfa_code: Option<String>,
    },
    Remove {
        email_or_label: String,
    },
    Logout {
        email_or_label: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        vault_passphrase: Option<String>,
    },
    Default {
        email_or_label: String,
    },
    Info {
        email_or_label: Option<String>,
        #[command(flatten)]
        auth: VaultOptions,
    },
    RefreshAll {
        #[command(flatten)]
        auth: VaultOptions,
    },
}

#[derive(Subcommand)]
pub enum Queue {
    List,
    AddDownload {
        url: String,
        #[arg(short = 'o', long, default_value = "")]
        output: String,
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
    AddUpload {
        #[arg(value_parser = super::values::existing_file())]
        path: PathBuf,
        #[arg(short = 'a', long)]
        account: Option<String>,
    },
    Remove {
        item_id: String,
    },
    Retry {
        item_id: String,
    },
    Clear,
    Reset,
    Run {
        #[command(flatten)]
        auth: VaultOptions,
    },
}

#[derive(Subcommand)]
pub enum Proxy {
    List {
        #[arg(long, overrides_with = "no_config_urls")]
        config_urls: bool,
        #[arg(long)]
        no_config_urls: bool,
    },
    Add {
        #[arg(required = true)]
        urls: Vec<String>,
    },
    Remove {
        url: String,
    },
    Clear,
    Import {
        #[arg(value_parser = super::values::existing_file())]
        path: PathBuf,
    },
    Fetch {
        #[arg(long,default_value="http",value_parser=["http","socks4","socks5"])]
        protocol: String,
        #[arg(long)]
        source: Option<String>,
        #[arg(long, default_value = "200")]
        limit: u32,
        #[arg(long, default_value = "20")]
        timeout: u64,
    },
    Test,
    Serve {
        #[arg(short = 'p', long)]
        port: Option<u16>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        any_port: bool,
    },
}

#[derive(Subcommand)]
pub enum Crypter {
    Encrypt {
        #[arg(value_parser = super::values::existing_file())]
        source: PathBuf,
        #[arg(value_parser = super::values::output_file())]
        destination: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, default_value = "64")]
        chunk_size_kb: u32,
    },
    Decrypt {
        #[arg(value_parser = super::values::existing_file())]
        source: PathBuf,
        #[arg(value_parser = super::values::output_file())]
        destination: PathBuf,
        #[arg(long)]
        password: Option<String>,
    },
    MakeLink {
        mega_url: String,
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        no_expire: bool,
        #[arg(long)]
        reverse: bool,
        #[arg(long)]
        max_downloads: Option<u32>,
    },
    Resolve {
        mc_url: String,
        #[arg(long)]
        password: Option<String>,
    },
    ElcResolve {
        elc_url: String,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
    },
    DlcResolve {
        #[arg(value_parser = super::values::existing_file())]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum Config {
    Show,
    Get {
        key: String,
    },
    Set {
        key: String,
        value: String,
    },
    Unset {
        key: String,
    },
    Reset,
    Recover {
        #[arg(long)]
        reset: bool,
    },
    Path,
    Migrate,
}
