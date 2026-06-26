#[derive(Clone)]
pub struct Finding {
    pub rule: &'static str,
    pub file: String,
    pub line: Option<usize>,
    pub message: String,
}

/// Stable short code for each rule, used in output and in `# noqa: BAL00X`.
pub fn rule_code(rule: &str) -> &'static str {
    match rule {
        "bloat-repo" => "BAL001",
        "bloat-file" => "BAL002",
        "bloat-density" => "BAL003",
        "dup-family" => "BAL004",
        "test-mock" => "BAL005",
        "test-absent" => "BAL006",
        "guard-fallback" => "BAL007",
        "guard-silent-default" => "BAL008",
        "test-mock-sut" => "BAL009",
        "test-weak" => "BAL010",
        "comment-noise" => "BAL011",
        "banned-word" => "BAL012",
        "stub" => "BAL013",
        "abstraction-solo" => "BAL014",
        "dup-body" => "BAL015",
        "doc-bloat" => "BAL016",
        _ => "BAL000",
    }
}
