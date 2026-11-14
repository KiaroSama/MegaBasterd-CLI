//! Stable source menu positions; additional native shortcuts follow the original entries.

pub(super) struct Entry {
    pub label: &'static str,
    pub command: &'static [&'static str],
    pub arguments: bool,
}

pub(super) const MAIN: &[&str] = &[
    "Download MEGA link/file",
    "Show link info",
    "Upload file/folder",
    "Account and cloud operations",
    "Queue and proxy",
    "Tools",
    "Settings",
    "Advanced CLI command",
];

pub(super) const ACCOUNTS: &[Entry] = &[
    Entry {
        label: "Add/login account",
        command: &["account", "add"],
        arguments: true,
    },
    Entry {
        label: "List stored accounts",
        command: &["account", "list"],
        arguments: false,
    },
    Entry {
        label: "Log out (end session, keep account)",
        command: &["account", "logout"],
        arguments: true,
    },
    Entry {
        label: "Remove account (delete stored credential)",
        command: &["account", "remove"],
        arguments: true,
    },
    Entry {
        label: "Set default account",
        command: &["account", "default"],
        arguments: true,
    },
    Entry {
        label: "Show account quota",
        command: &["account", "info"],
        arguments: true,
    },
    Entry {
        label: "Refresh every account's quota",
        command: &["account", "refresh-all"],
        arguments: false,
    },
    Entry {
        label: "List cloud files",
        command: &["ls"],
        arguments: true,
    },
    Entry {
        label: "Search cloud",
        command: &["search"],
        arguments: true,
    },
    Entry {
        label: "Create remote folder",
        command: &["mkdir"],
        arguments: true,
    },
    Entry {
        label: "Rename remote node",
        command: &["rename"],
        arguments: true,
    },
    Entry {
        label: "Move remote node",
        command: &["mv"],
        arguments: true,
    },
    Entry {
        label: "Remove remote node",
        command: &["rm"],
        arguments: true,
    },
    Entry {
        label: "Trash operations",
        command: &["trash"],
        arguments: true,
    },
    Entry {
        label: "Share remote node",
        command: &["share"],
        arguments: true,
    },
    Entry {
        label: "Import public folder to account",
        command: &["import"],
        arguments: true,
    },
    Entry {
        label: "List Trash",
        command: &["trash", "list"],
        arguments: false,
    },
    Entry {
        label: "Empty Trash",
        command: &["trash", "empty"],
        arguments: false,
    },
];

pub(super) const QUEUE: &[Entry] = &[
    Entry {
        label: "Queue: add download",
        command: &["queue", "add-download"],
        arguments: true,
    },
    Entry {
        label: "Queue: add upload",
        command: &["queue", "add-upload"],
        arguments: true,
    },
    Entry {
        label: "Queue: list",
        command: &["queue", "list"],
        arguments: false,
    },
    Entry {
        label: "Queue: run",
        command: &["queue", "run"],
        arguments: true,
    },
    Entry {
        label: "Queue: remove",
        command: &["queue", "remove"],
        arguments: true,
    },
    Entry {
        label: "Queue: clear completed/canceled",
        command: &["queue", "clear"],
        arguments: false,
    },
    Entry {
        label: "Proxy: list",
        command: &["proxy", "list"],
        arguments: false,
    },
    Entry {
        label: "Proxy: add",
        command: &["proxy", "add"],
        arguments: true,
    },
    Entry {
        label: "Proxy: remove",
        command: &["proxy", "remove"],
        arguments: true,
    },
    Entry {
        label: "Proxy: import from file",
        command: &["proxy", "import"],
        arguments: true,
    },
    Entry {
        label: "Proxy: fetch public list",
        command: &["proxy", "fetch"],
        arguments: true,
    },
    Entry {
        label: "Proxy: clear",
        command: &["proxy", "clear"],
        arguments: false,
    },
    Entry {
        label: "Watch clipboard and queue links",
        command: &["watch"],
        arguments: true,
    },
    Entry {
        label: "Queue retry",
        command: &["queue", "retry"],
        arguments: true,
    },
    Entry {
        label: "Queue reset",
        command: &["queue", "reset"],
        arguments: false,
    },
    Entry {
        label: "Proxy TCP test",
        command: &["proxy", "test"],
        arguments: false,
    },
    Entry {
        label: "Local MEGA CONNECT proxy",
        command: &["proxy", "serve"],
        arguments: true,
    },
];

pub(super) const TOOLS: &[Entry] = &[
    Entry {
        label: "Split file",
        command: &["split"],
        arguments: true,
    },
    Entry {
        label: "Merge parts",
        command: &["merge"],
        arguments: true,
    },
    Entry {
        label: "Encrypt local file",
        command: &["crypter", "encrypt"],
        arguments: true,
    },
    Entry {
        label: "Decrypt local file",
        command: &["crypter", "decrypt"],
        arguments: true,
    },
    Entry {
        label: "Resolve MegaCrypter link",
        command: &["crypter", "resolve"],
        arguments: true,
    },
    Entry {
        label: "Resolve ELC container",
        command: &["crypter", "elc-resolve"],
        arguments: true,
    },
    Entry {
        label: "Resolve DLC container",
        command: &["crypter", "dlc-resolve"],
        arguments: true,
    },
    Entry {
        label: "Create thumbnail",
        command: &["thumbnail"],
        arguments: true,
    },
    Entry {
        label: "Stream MEGA file",
        command: &["stream"],
        arguments: true,
    },
    Entry {
        label: "Create MegaCrypter link",
        command: &["crypter", "make-link"],
        arguments: true,
    },
];

pub(super) const SETTINGS: &[Entry] = &[
    Entry {
        label: "Show current configuration",
        command: &["config", "show"],
        arguments: false,
    },
    Entry {
        label: "Set default download folder",
        command: &["config", "set", "download_path"],
        arguments: true,
    },
    Entry {
        label: "Set download workers",
        command: &["config", "set", "max_workers"],
        arguments: true,
    },
    Entry {
        label: "Set speed limit",
        command: &["config", "set", "speed_limit_kbps"],
        arguments: true,
    },
    Entry {
        label: "Set ELC API credentials",
        command: &["config", "set", "elc_accounts"],
        arguments: true,
    },
    Entry {
        label: "Add/login MEGA account",
        command: &["account", "add"],
        arguments: true,
    },
    Entry {
        label: "List accounts",
        command: &["account", "list"],
        arguments: false,
    },
    Entry {
        label: "Log out (end session, keep account)",
        command: &["account", "logout"],
        arguments: true,
    },
    Entry {
        label: "Remove account (delete stored credential)",
        command: &["account", "remove"],
        arguments: true,
    },
    Entry {
        label: "Set default account",
        command: &["account", "default"],
        arguments: true,
    },
    Entry {
        label: "Show config path",
        command: &["config", "path"],
        arguments: false,
    },
    Entry {
        label: "Reset config",
        command: &["config", "reset"],
        arguments: false,
    },
    Entry {
        label: "Set configuration value",
        command: &["config", "set"],
        arguments: true,
    },
    Entry {
        label: "Unset configuration value",
        command: &["config", "unset"],
        arguments: true,
    },
    Entry {
        label: "Recover configuration",
        command: &["config", "recover"],
        arguments: true,
    },
];
