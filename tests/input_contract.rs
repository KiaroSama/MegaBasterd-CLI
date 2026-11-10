#![allow(clippy::unwrap_used)]

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use megabasterd_cli::{
    terminal::input::{self, KeyAction},
    transfers::control::Control,
};

#[test]
fn pause_keys_ignore_release_repeat_and_modified_shortcuts() {
    for character in ['p', 'P'] {
        assert_eq!(
            input::key_action(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE)),
            KeyAction::Pause
        );
    }
    assert_eq!(
        input::key_action(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
        KeyAction::Cancel
    );
    assert_eq!(
        input::key_action(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::ALT)),
        KeyAction::Ignore
    );
    for kind in [KeyEventKind::Repeat, KeyEventKind::Release] {
        assert_eq!(
            input::key_action(KeyEvent::new_with_kind(
                KeyCode::Char('p'),
                KeyModifiers::NONE,
                kind
            )),
            KeyAction::Ignore
        );
    }
}

#[test]
fn json_or_either_nonterminal_stream_disables_the_keyboard_listener() {
    assert!(input::enabled(false, true, true));
    for (json, stdin, stderr) in [
        (true, true, true),
        (false, false, true),
        (false, true, false),
        (false, false, false),
    ] {
        assert!(!input::enabled(json, stdin, stderr));
    }
    let control = Control::new();
    assert!(control.toggle_pause().unwrap());
    control.cancel();
    assert_eq!(control.checkpoint().unwrap_err().exit_code(), 130);
}
