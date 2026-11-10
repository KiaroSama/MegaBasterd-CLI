#![allow(clippy::unwrap_used)]
use megabasterd_cli::terminal::output::Output;

#[test]
fn configured_console_level_filters_diagnostics_not_machine_or_command_messages() {
    let output = Output::new(true, false);
    assert!(!output.diagnostic_enabled("INFO"));
    assert!(output.diagnostic_enabled("WARNING"));
    output.set_diagnostic_level("debug").unwrap();
    assert!(output.diagnostic_enabled("DEBUG"));
    assert!(output.json);
    output.set_diagnostic_level("ERROR").unwrap();
    assert!(!output.diagnostic_enabled("WARNING"));
    assert!(output.diagnostic_enabled("ERROR"));
    assert!(output.set_diagnostic_level("invented").is_err());
    assert!(!output.diagnostic_enabled("WARNING"));
    let quiet = Output::new(false, true);
    quiet.set_diagnostic_level("DEBUG").unwrap();
    assert!(!quiet.diagnostic_enabled("INFO"));
    assert!(quiet.diagnostic_enabled("CRITICAL"));
}
