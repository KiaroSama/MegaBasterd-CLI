//! Both retained platform grammars exercise the actual configured-command tokenizer.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn exact_source_windows_and_posix_command_arguments_preserve_their_platform_grammar() {
    let appended = OsString::from("C:/dir with space/file name.bin");
    for (windows, command, expected_program, expected_arguments) in [
        (
            true,
            r#"C:\Tools\notify.exe --path "C:\My Files""#,
            r"C:\Tools\notify.exe",
            vec!["--path", r#""C:\My Files""#],
        ),
        (
            false,
            "/usr/bin/notify --msg 'hello world'",
            "/usr/bin/notify",
            vec!["--msg", "hello world"],
        ),
    ] {
        let (program, arguments) =
            command_args_for(command, std::slice::from_ref(&appended), windows).unwrap();
        assert_eq!(program, OsString::from(expected_program));
        let mut expected: Vec<_> = expected_arguments.into_iter().map(OsString::from).collect();
        expected.push(appended.clone());
        assert_eq!(arguments, expected);
        if windows == cfg!(windows) {
            assert_eq!(
                command_args(command, std::slice::from_ref(&appended)).unwrap(),
                (program, arguments)
            );
        }
        for invalid in ["", "notify 'unterminated", "notify\0bad"] {
            assert!(matches!(
                command_args_for(invalid, &[], windows),
                Err(Error::Invalid(_))
            ));
        }
    }
}
