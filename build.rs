fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=.cargo_vcs_info.json");
    let archived = std::fs::read_to_string(".cargo_vcs_info.json")
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|value| value["git"]["sha1"].as_str().map(str::to_owned));
    let revision = if let Some(value) = archived {
        value
    } else {
        let git = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output();
        match git {
            Ok(output) if output.status.success() => {
                String::from_utf8(output.stdout)?.trim().to_owned()
            }
            _ => "unversioned".to_owned(),
        }
    };
    if revision != "unversioned"
        && (revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err("Build source commit is invalid".into());
    }
    if let Ok(expected) = std::env::var("GITHUB_SHA")
        && revision != expected
    {
        return Err("CI build source commit does not match checkout".into());
    }
    println!("cargo:rustc-env=MBCLI_SOURCE_COMMIT={revision}");
    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut resource = winresource::WindowsResource::new();
        resource
            .set("CompanyName", env!("CARGO_PKG_AUTHORS"))
            .set("ProductName", "MegaBasterd CLI")
            .set("FileDescription", env!("CARGO_PKG_DESCRIPTION"))
            .set("FileVersion", env!("CARGO_PKG_VERSION"))
            .set("ProductVersion", env!("CARGO_PKG_VERSION"))
            .set(
                "LegalCopyright",
                "Copyright (c) 2026 Kiaro Sama; GPL-3.0-or-later",
            )
            .set("Comments", &format!("Source commit: {revision}"));
        for binary in ["mb", "mbcli", "megabasterd-cli"] {
            resource.compile_for(binary)?;
        }
    }
    Ok(())
}
