//! Lexical wiring contracts complement real private-file and rotation fixtures, not syscall traces.
#![allow(clippy::unwrap_used)]

fn code(source: &str) -> String {
    assert!(!source.contains("/*") && !source.contains("*/"));
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    assert_eq!(source.matches(start).count(), 1, "ambiguous start: {start}");
    let body = source.split_once(start).unwrap().1;
    assert_eq!(body.matches(end).count(), 1, "ambiguous end: {end}");
    body.split_once(end).unwrap().0
}

#[test]
fn logger_creation_and_rotation_use_the_shared_private_directory_without_a_path_open_fallback() {
    let logger = code(include_str!("../src/terminal/logging.rs"));
    let shared = code(include_str!("../src/platform/secure_files.rs"));
    assert!(logger.contains("use crate::platform::secure_files::PrivateDirectory;"));
    assert_eq!(logger.matches(".open_private(").count(), 2);
    for forbidden in [
        "OpenOptions",
        "File::open(",
        "File::create(",
        "std::fs::OpenOptions",
        "libc::",
        "CreateFileW(",
    ] {
        assert!(
            !logger.contains(forbidden),
            "unreviewed logger file opener: {forbidden}"
        );
    }
    let wrapper = section(
        &logger,
        "pub(crate) fn configured_for_command(",
        "fn configured_with_opener(",
    );
    assert!(wrapper.contains(concat!(
        "Self::configured_with_opener(directory, max_bytes, backups, command, |directory, name| {\n",
        "            directory.open_private(name, true)\n",
        "        })",
    )));
    let create = section(&logger, "fn configured_with_opener(", "pub fn name(");
    assert!(create.contains("let directory = PrivateDirectory::ensure(directory)?;"));
    assert!(create.contains("match open(&directory, &name) {"));
    assert!(
        create.contains(
            "Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists =>"
        )
    );
    assert!(create.contains("Err(error) => return Err(error),"));
    let rotate = section(&logger, "fn rotate(", "pub fn write(");
    assert!(rotate.contains("active.file = Some(self.directory.open_private(&self.name, true)?);"));
    let write = section(&logger, "pub fn write(", "pub fn finish(");
    let write_at = write.find("file.write_all(record.as_bytes())?;").unwrap();
    for sanitizer in [
        "let fields = sanitize(fields, false);",
        "literal(&text(message))",
        "let record = log_text(&record);",
    ] {
        assert!(write.find(sanitizer).unwrap() < write_at);
    }
    assert!(write.find("self.directory.verify_private(file)?;").unwrap() < write_at);
    assert!(write.contains("if result.is_err() {\n            active.file = None;\n        }"));
    for forbidden in [".remove(", "remove_file(", "remove_dir(", "unlink("] {
        assert!(
            !logger.contains(forbidden),
            "logger deletes an entry: {forbidden}"
        );
    }
    let open = section(
        &shared,
        "pub fn open_private(",
        "pub fn verify_private(&self, file: &File) -> Result<()> {\n        self.inner.verify_private(file)",
    );
    assert!(open.contains("validate_name(name)?;"));
    assert!(open.contains("self.inner.open_file(name, create_new, false)"));
    for forbidden in [".remove(", "remove_file(", "remove_dir(", "unlink("] {
        assert!(
            !open.contains(forbidden),
            "private opener deletes an entry: {forbidden}"
        );
    }
}

#[test]
fn a_failed_file_sink_warns_with_only_the_fixed_category_never_its_raw_error() {
    let output = code(include_str!("../src/terminal/output.rs"));
    let dispatch = section(&output, "fn log_message(", "pub fn logging_warning(");
    assert!(dispatch.contains(
        "if logger\n                .write(level, \"OUTPUT\", message, &serde_json::json!({}))\n                .is_err()\n            {\n                let _ = self.logging_warning(logger);\n            }"
    ));
    for forbidden in [
        "to_string",
        "format!",
        "error(",
        "console_message",
        "record(",
    ] {
        assert!(!dispatch.contains(forbidden));
    }
    let warning = section(
        &output,
        "pub fn logging_warning(",
        "pub(crate) fn logging_init_warning(",
    );
    assert_eq!(
        warning.trim(),
        concat!(
            "&self, logger: &Logger) -> Result<()> {\n",
            "        if logger.take_failure_warning() {\n",
            "            let mut stderr = self.stderr.lock().map_err(poisoned)?;\n",
            "            writeln!(stderr, \"[WARNING] Private runtime log write failed.\")?;\n",
            "            stderr.flush()?;\n",
            "        }\n",
            "        Ok(())\n",
            "    }"
        )
    );
}

#[test]
fn controlled_native_file_refusals_use_only_fixed_noninterpolated_string_literals() {
    for source in [
        include_str!("../src/platform/secure_files.rs"),
        include_str!("../src/platform/windows_files.rs"),
    ] {
        let source = code(source);
        let mut count = 0;
        for marker in ["Error::protocol(", "Error::invalid("] {
            for tail in source.split(marker).skip(1) {
                let argument = tail.split_once(')').unwrap().0.trim();
                let literal = argument
                    .trim_end_matches(',')
                    .trim()
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .unwrap_or_else(|| panic!("Controlled native-file refusal is not a literal"));
                assert!(!literal.is_empty());
                assert!(!literal.contains(['"', '\\', '{', '}']));
                count += 1;
            }
        }
        assert!(count > 0, "native provider has no controlled refusals");
    }
}

#[test]
fn unix_private_create_keeps_exclusive_nofollow_flags_and_verifies_before_returning_the_file() {
    let shared = code(include_str!("../src/platform/secure_files.rs"));
    let verify = section(&shared, "fn verify(", "impl Directory {");
    assert!(verify.contains("let meta = file.metadata()?;"));
    assert!(verify.contains("meta.uid() != owner || meta.mode() & 0o7777 != wanted"));
    let retained = section(
        &shared,
        "pub fn verify_private(&self, file: &File) -> Result<()> {\n            ",
        "pub fn open_file(&self, name: &OsStr, create_new: bool, read_only: bool)",
    );
    assert_eq!(
        retained.trim(),
        concat!(
            "verify(self.leaf()?, true, LeafPolicy::Private)?;\n",
            "            verify(file, false, LeafPolicy::Private)\n",
            "        }"
        )
    );
    let open_at = section(&shared, "fn open_at(", "fn verify(");
    assert_eq!(open_at.matches("libc::openat(").count(), 1);
    assert!(open_at.contains("flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,"));
    let open = section(
        &shared,
        "pub fn open_file(&self, name: &OsStr, create_new: bool, read_only: bool)",
        "pub fn child(",
    );
    assert!(open.contains("libc::O_NONBLOCK"));
    assert!(open.contains("if create_new {\n                    libc::O_CREAT | libc::O_EXCL"));
    assert!(open.contains("let file = open_at(self.leaf()?, &component(name)?, flags, 0o600)?;"));
    assert!(open.contains("if create_new {\n                    LeafPolicy::Private"));
    assert!(open.find("verify(\n            &file,").unwrap() < open.find("Ok(file)").unwrap());
    for forbidden in [
        "O_TRUNC",
        "O_APPEND",
        "File::open(",
        "File::create(",
        "set_permissions",
        "fchmod",
        "unlink",
        "remove_file",
        "remove_dir",
    ] {
        assert!(
            !open.contains(forbidden),
            "unreviewed private-open alternative: {forbidden}"
        );
    }
}

#[test]
fn windows_private_create_supplies_the_descriptor_and_validates_both_open_outcomes_before_return() {
    let native = code(include_str!("../src/platform/windows_files.rs"));
    let descriptor = section(&native, "fn descriptor(", "fn attributes(");
    assert!(descriptor.contains("O:{sid_text}G:{sid_text}D:P(A;;FA;;;{sid_text})"));
    assert!(descriptor.contains("ConvertStringSecurityDescriptorToSecurityDescriptorW("));
    let attributes = section(&native, "fn attributes(", "fn open_path(");
    assert!(attributes.contains("lpSecurityDescriptor: sd.0,"));
    assert!(attributes.contains("bInheritHandle: 0,"));
    let open_path = section(&native, "fn open_path(", "pub(crate) fn file_identity(");
    assert!(open_path.contains("let flags = FILE_FLAG_OPEN_REPARSE_POINT"));
    assert!(open_path.contains("attrs.map_or(ptr::null(), |a| a),"));
    let file = section(&native, "fn file(\n", "pub fn verify_private(");
    assert!(file.contains(concat!(
        "let sd = descriptor(sid)?;\n",
        "        #[cfg(test)]\n",
        "        let sd = creation_tests::descriptor_for_creation(&self.path, create_new, sd)?;\n",
        "        let attrs = attributes(&sd);",
    )));
    assert!(file.contains("if create_new {\n                CREATE_NEW\n            } else {\n                OPEN_EXISTING"));
    assert!(file.contains("if create_new { Some(&attrs) } else { None }"));
    assert!(file.contains("verify_kind(handle.as_raw_handle(), false)?;"));
    assert!(file.contains("if self.policy == LeafPolicy::Private || create_new {\n            verify_security(handle.as_raw_handle(), sid)?;\n        }\n        Ok(handle)"));
    let retained = section(&native, "pub fn verify_private(", "pub fn open_file(");
    assert_eq!(
        retained.trim(),
        concat!(
            "&self, file: &File) -> Result<()> {\n",
            "        let token = token_user()?;\n",
            "        let sid = sid_from_token(&token)?;\n",
            "        verify_kind(self.leaf()?, true)?;\n",
            "        verify_security(self.leaf()?, sid)?;\n",
            "        verify_kind(file.as_raw_handle(), false)?;\n",
            "        verify_security(file.as_raw_handle(), sid)\n",
            "    }"
        )
    );
    for forbidden in [
        ".remove(",
        "remove_file(",
        "DeleteFile",
        "SetFileInformationByHandle",
    ] {
        assert!(
            !file.contains(forbidden),
            "private opener deletes an entry: {forbidden}"
        );
    }
    let public = section(&native, "pub fn open_file(", "pub fn child(");
    assert!(public.contains("self.file(name, create_new, false, false, read_only)?"));
    assert!(file.contains(
        "FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 }"
    ));
    for forbidden in [
        "SetFileSecurity",
        "SetNamedSecurityInfo",
        "SetSecurityInfo",
        "OpenOptions",
        "File::open(",
        "File::create(",
    ] {
        assert!(!file.contains(forbidden));
    }
}
