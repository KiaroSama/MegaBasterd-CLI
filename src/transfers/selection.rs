use std::collections::BTreeSet;

// Unicode 14 decimal ranges match the pinned source interpreter, including non-ASCII input.
const DECIMAL_ZEROS: [u32; 66] = [
    0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66,
    0xde6, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90,
    0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0, 0xff10,
    0x104a0, 0x10d30, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450, 0x114d0, 0x11650,
    0x116c0, 0x11730, 0x118e0, 0x11950, 0x11c50, 0x11d50, 0x11da0, 0x16a60, 0x16ac0, 0x16b50,
    0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e140, 0x1e2f0, 0x1e950, 0x1fbf0,
];

pub fn decimal(character: char) -> Option<u32> {
    let code = character as u32;
    let index = DECIMAL_ZEROS.partition_point(|zero| *zero <= code);
    index.checked_sub(1).and_then(|i| {
        let digit = code - DECIMAL_ZEROS[i];
        (digit < 10).then_some(digit)
    })
}

fn index(text: &str) -> Result<usize, String> {
    let text = text.strip_prefix('+').unwrap_or(text);
    let mut value = 0usize;
    let mut previous_digit = false;
    for character in text.chars() {
        if character == '_' && previous_digit {
            previous_digit = false;
            continue;
        }
        let digit = decimal(character).ok_or("Invalid selection token")?;
        value = value
            .checked_mul(10)
            .and_then(|n| n.checked_add(digit as usize))
            .ok_or("Selection index is too large")?;
        previous_digit = true;
    }
    if !previous_digit {
        return Err("Invalid selection token".to_owned());
    }
    Ok(value)
}

/// Parse the public one-based file selection grammar without reading stdin.
pub fn parse(answer: &str, count: usize) -> Result<Vec<usize>, String> {
    let answer = answer.trim().to_lowercase();
    if matches!(answer.as_str(), "" | "all" | "a" | "*") {
        return Ok((1..=count).collect());
    }
    if matches!(answer.as_str(), "none" | "n") {
        return Ok(Vec::new());
    }
    let mut selected = BTreeSet::new();
    for token in answer.split(|c: char| c == ',' || c.is_whitespace()) {
        if token.is_empty() {
            continue;
        }
        let (first, last) = token.split_once('-').unwrap_or((token, token));
        let low = index(first)?;
        let high = index(last)?;
        if low == 0 || high > count || low > high {
            return Err(format!("Selection is outside 1-{count}"));
        }
        selected.extend(low..=high);
    }
    Ok(selected.into_iter().collect())
}
