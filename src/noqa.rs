use crate::finding::{Rule, SourceLocator};
use ruff_python_ast::token::{Token, TokenKind};
use ruff_text_size::Ranged;
use std::collections::HashMap;

pub enum Noqa {
    All,
    Rules(Vec<Rule>),
}

impl Noqa {
    pub fn suppresses(&self, rule: Rule) -> bool {
        match self {
            Noqa::All => true,
            Noqa::Rules(rules) => rules.contains(&rule),
        }
    }
}

pub fn directives(source: &str, tokens: &[Token], locator: &SourceLocator) -> HashMap<usize, Noqa> {
    let mut map = HashMap::new();
    for token in tokens {
        if token.kind() != TokenKind::Comment {
            continue;
        }
        let range = token.range();
        let text = &source[range.start().to_usize()..range.end().to_usize()];
        if let Some(noqa) = parse_comment(text) {
            let (line, _) = locator.location(range.start().to_usize());
            map.insert(line, noqa);
        }
    }
    map
}

fn parse_comment(comment: &str) -> Option<Noqa> {
    let mut found = false;
    let mut rules = Vec::new();
    for segment in comment.split('#').map(str::trim_start) {
        let Some(tail) = strip_noqa(segment) else {
            continue;
        };
        found = true;
        let Some(rest) = tail.trim_start().strip_prefix(':') else {
            return Some(Noqa::All);
        };
        if rest.trim().is_empty() {
            return Some(Noqa::All);
        }
        let selectors = rest
            .split(|character: char| character == ',' || character.is_whitespace())
            .filter(|selector| !selector.is_empty());
        rules.extend(selectors.filter_map(Rule::parse));
    }
    found.then_some(Noqa::Rules(rules))
}

fn strip_noqa(text: &str) -> Option<&str> {
    let head = text.get(..4)?;
    if !head.eq_ignore_ascii_case("noqa") {
        return None;
    }
    let tail = &text[4..];
    match tail.chars().next() {
        None | Some(':') => Some(tail),
        Some(character) if character.is_whitespace() => Some(tail),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruff_python_parser::parse_module;

    fn parse(source: &str) -> HashMap<usize, Noqa> {
        let parsed = parse_module(source).unwrap();
        directives(source, parsed.tokens(), &SourceLocator::new(source))
    }

    #[test]
    fn comments_are_parsed_and_strings_are_ignored() {
        let directives = parse("x = 1  # noqa: BAL007, test-weak\n");
        let directive = &directives[&1];
        assert!(directive.suppresses(Rule::GuardFallback));
        assert!(directive.suppresses(Rule::TestWeak));
        assert!(!directive.suppresses(Rule::Stub));

        let directives = parse("x = None  # type: ignore  # noqa: BAL008\n");
        assert!(directives[&1].suppresses(Rule::GuardSilentDefault));
        assert!(parse("seamless = \"# noqa \"\n").is_empty());
        for spacing in ["", " ", "  ", "\t"] {
            for selector in ["noqa", "NOQA", "noqa: BAL012", "noqa: guard-fallback"] {
                let source = format!("value = \"#{spacing}{selector} \"\n");
                assert!(parse(&source).is_empty(), "forged by {source:?}");
            }
        }
        let directives = parse("x = 1  # noqa: BAD999\n");
        assert!(!directives[&1].suppresses(Rule::BannedWord));
    }
}
