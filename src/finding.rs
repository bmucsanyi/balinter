use serde::{Deserialize, Serialize};
use std::path::Path;

pub fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

macro_rules! define_rules {
    ($(($variant:ident, $code:literal, $name:literal, $explanation:literal)),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        pub enum Rule { $($variant),+ }

        pub const ALL_RULES: [Rule; define_rules!(@count $($variant),+)] = [$(Rule::$variant),+];

        impl Rule {
            const fn metadata(self) -> (&'static str, &'static str, &'static str) {
                match self { $(Self::$variant => ($code, $name, $explanation)),+ }
            }
            pub const fn code(self) -> &'static str { self.metadata().0 }
            pub const fn name(self) -> &'static str { self.metadata().1 }
            pub const fn explanation(self) -> &'static str { self.metadata().2 }
            pub fn parse(value: &str) -> Option<Self> {
                ALL_RULES.iter().copied().find(|rule| {
                    value.eq_ignore_ascii_case(rule.code())
                        || value.eq_ignore_ascii_case(rule.name())
                })
            }
        }
    };
    (@count $($variant:ident),+) => { <[()]>::len(&[$(define_rules!(@unit $variant)),+]) };
    (@unit $variant:ident) => { () };
}

define_rules!(
    (BloatRepo, "BAL001", "bloat-repo", "Repository source exceeds the configured physical-line limit."),
    (BloatFile, "BAL002", "bloat-file", "A source file exceeds the configured physical-line limit."),
    (BloatDensity, "BAL003", "bloat-density", "Production code has too many top-level function definitions per thousand lines."),
    (DupFamily, "BAL004", "dup-family", "Too many functions share the same two-token name suffix."),
    (TestMock, "BAL005", "test-mock", "Tests use more mock calls per test than the configured limit."),
    (TestAbsent, "BAL006", "test-absent", "The test-to-production line ratio is below the configured floor."),
    (GuardFallback, "BAL007", "guard-fallback", "An exception handler substitutes an alternate result for a failed operation."),
    (GuardSilentDefault, "BAL008", "guard-silent-default", "Code replaces missing or invalid data without making the policy explicit at the API boundary."),
    (TestMockSut, "BAL009", "test-mock-sut", "A test replaces a first-party symbol belonging to its inferred subject."),
    (TestWeak, "BAL010", "test-weak", "A test has no behavioral value observation or checks metadata only."),
    (CommentNoise, "BAL011", "comment-noise", "A comment records history or adds a decorative divider without durable rationale."),
    (BannedWord, "BAL012", "banned-word", "Prose or identifiers contain configured low-information vocabulary or emoji."),
    (Stub, "BAL013", "stub", "A concrete Python function has a placeholder body."),
    (AbstractionSolo, "BAL014", "abstraction-solo", "An internal abstract base has one concrete implementation."),
    (DupBody, "BAL015", "dup-body", "Several top-level functions have the same normalized implementation."),
    (DocBloat, "BAL016", "doc-bloat", "A short function has a disproportionately long unstructured docstring."),
    (GodFunction, "BAL017", "god-function", "A function exceeds the configured statement or branch-depth limit."),
    (GodClass, "BAL018", "god-class", "A class exposes more methods than the configured limit."),
    (WrapperChain, "BAL019", "wrapper-chain", "A private helper only forwards its parameters to another callable."),
    (ModuleApi, "BAL020", "module-api", "A module exports more public symbols than the configured limit."),
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Span {
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub rule: Rule,
    pub file: String,
    pub span: Option<Span>,
    pub cell: Option<usize>,
    pub message: String,
}

impl Finding {
    pub fn project(rule: Rule, message: impl Into<String>) -> Self {
        Self {
            rule,
            file: ".".to_string(),
            span: None,
            cell: None,
            message: message.into(),
        }
    }

    pub fn file(rule: Rule, file: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            rule,
            file: file.into(),
            span: None,
            cell: None,
            message: message.into(),
        }
    }

    pub fn source(
        rule: Rule,
        file: impl Into<String>,
        span: Span,
        cell: Option<usize>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            rule,
            file: file.into(),
            span: Some(span),
            cell,
            message: message.into(),
        }
    }
}

pub struct SourceLocator<'a> {
    source: &'a str,
    line_starts: Vec<usize>,
}

impl<'a> SourceLocator<'a> {
    pub fn new(source: &'a str) -> Self {
        let mut line_starts = vec![0];
        line_starts.extend(
            source
                .bytes()
                .enumerate()
                .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
        );
        Self {
            source,
            line_starts,
        }
    }

    pub fn location(&self, offset: usize) -> (usize, usize) {
        let line_index = self.line_starts.partition_point(|&start| start <= offset) - 1;
        let line_start = self.line_starts[line_index];
        (
            line_index + 1,
            self.source[line_start..offset].chars().count() + 1,
        )
    }

    pub fn span(&self, start: usize, end: usize) -> Span {
        let (line, column) = self.location(start);
        let (end_line, end_column) = self.location(end);
        Span {
            line,
            column,
            end_line,
            end_column,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_and_locations() {
        for rule in ALL_RULES {
            assert_eq!(Rule::parse(rule.code()), Some(rule));
            assert_eq!(Rule::parse(rule.name()), Some(rule));
            assert!(!rule.explanation().is_empty());
        }
        let source = "abc\ndef\n";
        let locator = SourceLocator::new(source);
        let expected = [
            (1, 1),
            (1, 2),
            (1, 3),
            (1, 4),
            (2, 1),
            (2, 2),
            (2, 3),
            (2, 4),
            (3, 1),
        ];
        for (offset, location) in expected.into_iter().enumerate() {
            assert_eq!(locator.location(offset), location);
        }
        let source = "\u{3b1}\u{3b2} = value\n";
        let locator = SourceLocator::new(source);
        assert_eq!(locator.location(source.find("value").unwrap()), (1, 6));
    }
}
