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
        "BLOAT-REPO" => "BAL001",
        "BLOAT-FILE" => "BAL002",
        "BLOAT-DENSITY" => "BAL003",
        "DUP-FAMILY" => "BAL004",
        "TEST-MOCK" => "BAL005",
        "TEST-ABSENT" => "BAL006",
        "GUARD-FALLBACK" => "BAL007",
        "GUARD-SILENT-DEFAULT" => "BAL008",
        "TEST-MOCK-SUT" => "BAL009",
        "TEST-WEAK" => "BAL010",
        "COMMENT-NOISE" => "BAL011",
        _ => "BAL000",
    }
}
