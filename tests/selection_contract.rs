#[path = "../src/transfers/selection.rs"]
mod selection;

#[test]
fn selection_accepts_source_decimal_grammar() {
    assert_eq!(selection::parse("۱,٣-４", 4), Ok(vec![1, 3, 4]));
    assert_eq!(selection::parse("+01,0_2", 4), Ok(vec![1, 2]));
    assert!(selection::parse("_1", 4).is_err());
    assert!(selection::parse("1__0", 20).is_err());
    assert!(selection::parse("1_", 4).is_err());
}

#[test]
fn selection_preserves_explicit_skip_default_and_invalid_retry_contract() {
    assert_eq!(selection::parse("", 4), Ok(vec![1, 2, 3, 4]));
    assert_eq!(selection::parse("none", 4), Ok(Vec::new()));
    assert_eq!(selection::parse("1,3-4", 4), Ok(vec![1, 3, 4]));
    assert_eq!(selection::parse("4,1 3-4", 4), Ok(vec![1, 3, 4]));
    assert!(selection::parse("0", 4).is_err());
    assert!(selection::parse("2-1", 4).is_err());
    assert!(selection::parse("²", 4).is_err());
    assert!(selection::parse("999999999999999999999999", 4).is_err());
    assert_eq!(selection::parse("all", 0), Ok(Vec::new()));
}

#[test]
fn exact_source_keywords_ranges_and_invalid_variants_remain_supported() {
    for (answer, count, expected) in [
        ("all", 4, vec![1, 2, 3, 4]),
        ("", 3, vec![1, 2, 3]),
        ("  a  ", 2, vec![1, 2]),
        ("none", 4, vec![]),
        ("n", 4, vec![]),
        ("1,3-5", 6, vec![1, 3, 4, 5]),
        ("2 4", 5, vec![2, 4]),
        ("1, 2-2", 3, vec![1, 2]),
    ] {
        assert_eq!(selection::parse(answer, count), Ok(expected), "{answer}");
    }
    for bad in ["junk", "0", "7", "2-9", "5-3", "1,,x"] {
        assert!(selection::parse(bad, 6).is_err(), "{bad}");
    }
}
