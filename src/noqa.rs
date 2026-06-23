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
/// `# noqa` alone covers the whole line; `# noqa: BAL007, GUARD-FALLBACK` covers the
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

fn parse_line(line: &str) -> Option<Noqa> {
    let hash = line.find('#')?;
    let comment = &line[hash..];
    let pos = comment.to_ascii_lowercase().find("noqa")?;
    let after = comment[pos + 4..].trim_start();

    if let Some(rest) = after.strip_prefix(':') {
        let codes: Vec<String> = rest
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if codes.is_empty() {
            Some(Noqa::All)
        } else {
            Some(Noqa::Codes(codes))
        }
    } else {
        Some(Noqa::All)
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
            .suppresses("GUARD-FALLBACK", "BAL007"));
    }

    #[test]
    fn coded_noqa_suppresses_only_that_code() {
        let directives = directives("x = 1  # noqa: BAL007\n");
        let noqa = directives.get(&1).unwrap();
        assert!(noqa.suppresses("GUARD-FALLBACK", "BAL007"));
        assert!(!noqa.suppresses("TEST-WEAK", "BAL010"));
    }

    #[test]
    fn noqa_accepts_the_rule_name_too() {
        let directives = directives("x = 1  # noqa: GUARD-FALLBACK\n");
        assert!(directives
            .get(&1)
            .unwrap()
            .suppresses("GUARD-FALLBACK", "BAL007"));
    }

    #[test]
    fn no_directive_for_ordinary_comment() {
        assert!(directives("x = 1  # ordinary comment\n").is_empty());
    }
}
