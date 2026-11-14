#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn console_abort_is_cancellation_even_when_the_api_reports_zero_success() {
    for success in [false, true] {
        let control = Control::new();
        assert!(matches!(
            read_result(success, 0, 995, &control),
            Err(Error::Canceled)
        ));
        assert!(control.is_canceled());
    }
    let control = Control::new();
    assert!(read_result(true, 2, 0, &control).is_ok());
    assert!(read_result(true, 0, 0, &control).is_ok());
    assert!(!control.is_canceled());
    assert!(
        matches!(read_result(false, 0, 5, &control), Err(Error::Io(error)) if error.raw_os_error() == Some(5))
    );
    assert!(!control.is_canceled());
    control.cancel();
    assert!(matches!(
        read_result(true, 2, 0, &control),
        Err(Error::Canceled)
    ));
}

#[test]
fn console_utf16_preserves_split_surrogates_and_rejects_invalid_input() {
    let text = "نام  file 🙂\r\n";
    let units: Vec<_> = text.encode_utf16().collect();
    for split in 0..=units.len() {
        let mut bytes = Vec::new();
        let mut pending = None;
        decode(&units[..split], &mut pending, &mut bytes).unwrap();
        decode(&units[split..], &mut pending, &mut bytes).unwrap();
        assert!(pending.is_none());
        assert_eq!(bytes, text.as_bytes());
    }
    for invalid in [&[0xdc00][..], &[0xd800, b'x' as u16], &[0xd800, 0xd800]] {
        assert!(
            matches!(decode(invalid, &mut None, &mut Vec::new()), Err(Error::Invalid(message)) if message == "Prompt input is not valid Unicode")
        );
    }
    let mut pending = None;
    let mut bytes = Vec::new();
    decode(&[0xd800], &mut pending, &mut bytes).unwrap();
    assert_eq!(pending, Some(0xd800));
    assert!(bytes.is_empty());
}
