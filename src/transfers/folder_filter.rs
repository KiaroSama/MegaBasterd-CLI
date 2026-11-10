//! Source-compatible filename wildcards: Unicode14 full folding and Python fnmatch grammar.

use regex::{RegexSet, RegexSetBuilder};

use super::{planner::Job, unicode_fold::casefold};
use crate::error::{Error, Result};

const MAX_PATTERNS: usize = 1024;
const MAX_PATTERN_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: usize = 1024 * 1024;
const MAX_REGEX_BYTES: usize = 16 * 1024 * 1024;

pub struct Filter {
    include: RegexSet,
    exclude: RegexSet,
    has_include: bool,
}

fn literal(output: &mut String, character: char) {
    // Explicit scalar escapes keep regex operators, set operations and braces literal.
    use std::fmt::Write;
    let _ = write!(output, "\\x{{{:x}}}", u32::from(character));
}

fn class(output: &mut String, chars: &[char]) {
    let (negated, chars) = match chars.split_first() {
        Some((&'!', rest)) => (true, rest),
        _ => (false, chars),
    };
    let mut ranges = String::new();
    let mut index = 0;
    let mut negated = negated;
    while index < chars.len() {
        let first = chars[index];
        let interval = index + 2 < chars.len() && chars[index + 1] == '-';
        let last = if interval { chars[index + 2] } else { first };
        index += if interval { 3 } else { 1 };
        if first > last {
            continue;
        }
        // Python interprets the initial ! after discarding reversed ranges.
        if ranges.is_empty() && !negated && first == '!' {
            negated = true;
            if interval {
                literal(&mut ranges, '-');
                literal(&mut ranges, last);
            }
            continue;
        }
        literal(&mut ranges, first);
        if interval {
            ranges.push('-');
            literal(&mut ranges, last);
        }
    }
    if ranges.is_empty() {
        output.push_str(if negated { "." } else { "[^\\s\\S]" });
    } else {
        output.push('[');
        if negated {
            output.push('^');
        }
        output.push_str(&ranges);
        output.push(']');
    }
}

fn translate(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut output = String::from("(?s)\\A");
    let mut index = 0;
    let mut unclosed_class = false;
    while index < chars.len() {
        match chars[index] {
            '*' => {
                output.push_str(".*");
                while index + 1 < chars.len() && chars[index + 1] == '*' {
                    index += 1;
                }
            }
            '?' => output.push('.'),
            '[' if !unclosed_class => {
                let start = index + 1;
                let mut end = start;
                if chars.get(end) == Some(&'!') {
                    end += 1;
                }
                if chars.get(end) == Some(&']') {
                    end += 1;
                }
                while end < chars.len() && chars[end] != ']' {
                    end += 1;
                }
                if end == chars.len() {
                    // No later bracket can close either; avoid quadratic rescans of long literal input.
                    unclosed_class = true;
                    literal(&mut output, '[');
                } else {
                    class(&mut output, &chars[start..end]);
                    index = end;
                }
            }
            character => literal(&mut output, character),
        }
        index += 1;
    }
    output.push_str("\\z");
    output
}

fn patterns(input: &[String]) -> Result<RegexSet> {
    if input.len() > MAX_PATTERNS {
        return Err(Error::invalid(
            "Include/exclude filters exceed 1024 patterns",
        ));
    }
    let mut total = 0usize;
    for pattern in input {
        total = total
            .checked_add(pattern.len())
            .ok_or_else(|| Error::invalid("Filter size overflows"))?;
        if pattern.len() > MAX_PATTERN_BYTES || total > MAX_TOTAL_BYTES {
            return Err(Error::invalid(
                "Include/exclude patterns exceed their size limit",
            ));
        }
    }
    let mut expressions = Vec::new();
    for pattern in input.iter().filter(|pattern| !pattern.is_empty()) {
        let pattern = casefold(&pattern.replace('\\', "/"));
        expressions.push(translate(&pattern));
        expressions.push(translate(&format!("*/{pattern}")));
    }
    RegexSetBuilder::new(expressions)
        .size_limit(MAX_REGEX_BYTES)
        .dfa_size_limit(2 * 1024 * 1024)
        .build()
        .map_err(|_| Error::invalid("Include/exclude filters exceed the compiled size limit"))
}

impl Filter {
    pub fn new(include: &[String], exclude: &[String]) -> Result<Self> {
        Ok(Self {
            include: patterns(include)?,
            exclude: patterns(exclude)?,
            has_include: include.iter().any(|pattern| !pattern.is_empty()),
        })
    }

    pub fn accepts(&self, job: &Job) -> bool {
        let path = casefold(&job.relative.to_string_lossy().replace('\\', "/"));
        let name = casefold(
            &job.relative
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
        );
        let original = casefold(&job.node.name);
        let subjects = [&path, &name, &original];
        (!self.has_include
            || subjects
                .iter()
                .any(|subject| self.include.is_match(subject)))
            && !subjects
                .iter()
                .any(|subject| self.exclude.is_match(subject))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn wildcard_grammar_and_full_fold_match_the_independent_python_oracle() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/selection/filter-oracle.json"
        ))
        .unwrap();
        assert_eq!(fixture["python"], "3.11.9");
        assert_eq!(fixture["unicode"], "14.0.0");
        assert_eq!(fixture["fold_mappings"], 1530);
        // Clippy stores this large immutable array as static; pin the original
        // generated table bytes independently of its Rust storage qualifier.
        let table = include_str!("unicode_fold.rs")
            .replace("\r\n", "\n")
            .replacen("static FOLD:", "const FOLD:", 1);
        assert_eq!(
            hex::encode(Sha256::digest(table.as_bytes())),
            fixture["fold_table_sha256"]
        );
        let subjects: Vec<String> = fixture["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|subject| casefold(subject.as_str().unwrap()))
            .collect();
        assert_eq!(fixture["cases"].as_array().unwrap().len(), 360);
        for case in fixture["cases"].as_array().unwrap() {
            let pattern = casefold(&case["pattern"].as_str().unwrap().replace('\\', "/"));
            let expression = regex::RegexBuilder::new(&translate(&pattern))
                .size_limit(MAX_REGEX_BYTES)
                .build()
                .unwrap();
            let actual: Vec<usize> = subjects
                .iter()
                .enumerate()
                .filter(|(_, subject)| expression.is_match(subject))
                .map(|(index, _)| index)
                .collect();
            let expected: Vec<usize> = case["matches"]
                .as_array()
                .unwrap()
                .iter()
                .map(|index| index.as_u64().unwrap() as usize)
                .collect();
            assert_eq!(actual, expected, "{}", case["pattern"]);
        }
    }
}
