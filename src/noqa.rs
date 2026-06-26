use std::collections::HashMap;

pub enum Noqa {
    All,
    Codes(Vec<String>),
}

impl Noqa {
    /// A bare `# noqa` suppresses anything; a coded one matches the rule's code or name.
    pub fn suppresses(&self, rule: &str, code: &str) -> bool {
        match self {
            Noqa::All => true,
            Noqa::Codes(codes) => codes
                .iter()
                .any(|c| c.eq_ignore_ascii_case(rule) || c.eq_ignore_ascii_case(code)),
        }
    }
}

/// 1-based line number -> the `# noqa` directive on that line, if any.
/// `# noqa` alone covers the whole line; `# noqa: BAL007, guard-fallback` covers the
/// listed codes or rule names (ruff/flake8 convention).
pub fn directives(source: &str) -> HashMap<usize, Noqa> {
    let mut map = HashMap::new();
    for (index, line) in source.lines().enumerate() {
        if let Some(noqa) = parse_line(line) {
            map.insert(index + 1, noqa);
        }
    }
    map
}

/// A `noqa` directive is `#` then optional whitespace then the word `noqa` (a passing
/// mention like `# the noqa convention` is not one). Scans every `#` so a trailing
/// `code  # noqa` or `# comment  # noqa` is still found.
fn parse_line(line: &str) -> Option<Noqa> {
    for (offset, _) in line.match_indices('#') {
        let after = line[offset + 1..].trim_start();
        if let Some(tail) = strip_noqa(after) {
            return Some(parse_codes(tail));
        }
    }
    None
}

/// If `text` begins with the directive token `noqa` (followed by end, `:`, or whitespace),
/// returns the remainder after it; otherwise None (so `noqacat` does not match).
fn strip_noqa(text: &str) -> Option<&str> {
    let head = text.get(..4)?;
    if !head.eq_ignore_ascii_case("noqa") {
        return None;
    }
    let tail = &text[4..];
    match tail.chars().next() {
        None | Some(':') => Some(tail),
        Some(c) if c.is_whitespace() => Some(tail),
        Some(_) => None,
    }
}

fn parse_codes(tail: &str) -> Noqa {
    let Some(rest) = tail.trim_start().strip_prefix(':') else {
        return Noqa::All;
    };
    let codes: Vec<String> = rest
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if codes.is_empty() {
        Noqa::All
    } else {
        Noqa::Codes(codes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_noqa_suppresses_all() {
        let directives = directives("x = fallback()  # noqa\n");
        assert!(directives
            .get(&1)
            .unwrap()
            .suppresses("guard-fallback", "BAL007"));
    }

    #[test]
    fn coded_noqa_suppresses_only_that_code() {
        let directives = directives("x = 1  # noqa: BAL007\n");
        let noqa = directives.get(&1).unwrap();
        assert!(noqa.suppresses("guard-fallback", "BAL007"));
        assert!(!noqa.suppresses("test-weak", "BAL010"));
    }

    #[test]
    fn noqa_accepts_the_rule_name_too() {
        let directives = directives("x = 1  # noqa: guard-fallback\n");
        assert!(directives
            .get(&1)
            .unwrap()
            .suppresses("guard-fallback", "BAL007"));
    }

    #[test]
    fn no_directive_for_ordinary_comment() {
        assert!(directives("x = 1  # ordinary comment\n").is_empty());
    }

    #[test]
    fn mention_of_noqa_is_not_a_directive() {
        // a comment that merely contains "noqa" must not suppress the line
        assert!(directives("def f():  # the noqa convention is unrelated\n").is_empty());
        assert!(directives("x = 1  # noqacat\n").is_empty());
    }

    #[test]
    fn trailing_noqa_after_code_or_comment() {
        assert!(directives("x = fallback()  # noqa\n").contains_key(&1));
        // a noqa as a later comment segment is still found
        let d = directives("x = 1  # type: ignore  # noqa: BAL007\n");
        assert!(d.get(&1).unwrap().suppresses("guard-fallback", "BAL007"));
        assert!(!d.get(&1).unwrap().suppresses("test-weak", "BAL010"));
    }
}
