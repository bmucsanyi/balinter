use crate::finding::Finding;
use ruff_python_ast::token::TokenKind;
use ruff_python_ast::visitor::{walk_expr, walk_stmt, Visitor};
use ruff_python_ast::{
    CmpOp, ExceptHandler, Expr, ExprCall, Parameters, Stmt, StmtFunctionDef, StmtIf, StmtTry,
};
use ruff_python_parser::parse_module;
use ruff_text_size::Ranged;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::Path;

/// A top-level function's name plus a hash of its body shape, for cross-file DUP-FAMILY.
pub struct FuncSig {
    pub name: String,
    pub body_sig: u64,
}

pub struct FileResult {
    pub findings: Vec<Finding>,
    pub func_sigs: Vec<FuncSig>,
}

/// Run every parser-based per-file rule. `package_dirs` is the set of the repo's own
/// directory names, used to tell a first-party mock target from an external one.
pub fn check_file(path: &Path, source: &str, package_dirs: &HashSet<String>) -> FileResult {
    let parsed = match parse_module(source) {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("balinter: parse error in {}: {err}", path.display());
            return FileResult {
                findings: Vec::new(),
                func_sigs: Vec::new(),
            };
        }
    };

    let module = parsed.syntax();
    let mut checker = Checker {
        source,
        path,
        package_dirs,
        findings: Vec::new(),
        func_sigs: Vec::new(),
    };

    for stmt in &module.body {
        if let Stmt::FunctionDef(func) = stmt {
            checker.func_sigs.push(FuncSig {
                name: func.name.as_str().to_string(),
                body_sig: body_signature(&func.body),
            });
        }
    }

    let no_params = HashSet::new();
    checker.walk(&module.body, &no_params);

    if !in_docs(path) {
        for token in parsed.tokens().iter() {
            if token.kind() != TokenKind::Comment {
                continue;
            }
            let range = token.range();
            let text = &source[range.start().to_usize()..range.end().to_usize()];
            let body = text.strip_prefix('#').unwrap_or(text).trim();
            let lower = body.to_ascii_lowercase();
            let changelog = [
                "used to",
                "previously",
                "formerly",
                "renamed",
                "no longer",
                "originally",
            ]
            .iter()
            .any(|phrase| lower.contains(phrase));
            let divider = has_divider_run(body);

            if changelog || divider {
                let line = line_at(source, range.start().to_usize());
                let what = if divider {
                    "decorative divider comment"
                } else {
                    "changelog comment"
                };
                checker.findings.push(Finding {
                    rule: "COMMENT-NOISE",
                    file: path.display().to_string(),
                    line: Some(line),
                    message: what.to_string(),
                });
            }
        }
    }

    FileResult {
        findings: checker.findings,
        func_sigs: checker.func_sigs,
    }
}

struct Checker<'a> {
    source: &'a str,
    path: &'a Path,
    package_dirs: &'a HashSet<String>,
    findings: Vec<Finding>,
    func_sigs: Vec<FuncSig>,
}

impl Checker<'_> {
    fn flag(&mut self, rule: &'static str, line: usize, what: &str) {
        self.findings.push(Finding {
            rule,
            file: self.path.display().to_string(),
            line: Some(line),
            message: what.to_string(),
        });
    }

    /// `none_params` is the set of the enclosing function's parameters that default to None,
    /// so GUARD-SILENT-DEFAULT can leave the optional-argument idiom alone.
    fn walk(&mut self, body: &[Stmt], none_params: &HashSet<String>) {
        for stmt in body {
            self.visit(stmt, none_params);
        }
    }

    fn visit(&mut self, stmt: &Stmt, none_params: &HashSet<String>) {
        match stmt {
            Stmt::FunctionDef(func) => {
                if is_test_name(func.name.as_str()) {
                    self.check_test_function(func);
                }
                let fn_none = none_default_params(&func.parameters);
                self.walk(&func.body, &fn_none);
            }
            Stmt::ClassDef(class) => self.walk(&class.body, none_params),
            Stmt::If(if_stmt) => {
                self.check_silent_none(if_stmt, none_params);
                self.walk(&if_stmt.body, none_params);
                for clause in &if_stmt.elif_else_clauses {
                    self.walk(&clause.body, none_params);
                }
            }
            Stmt::For(for_stmt) => {
                self.walk(&for_stmt.body, none_params);
                self.walk(&for_stmt.orelse, none_params);
            }
            Stmt::While(while_stmt) => {
                self.walk(&while_stmt.body, none_params);
                self.walk(&while_stmt.orelse, none_params);
            }
            Stmt::With(with_stmt) => self.walk(&with_stmt.body, none_params),
            Stmt::Try(try_stmt) => {
                self.check_fallback(try_stmt);
                self.walk(&try_stmt.body, none_params);
                for handler in &try_stmt.handlers {
                    let ExceptHandler::ExceptHandler(handler) = handler;
                    self.walk(&handler.body, none_params);
                }
                self.walk(&try_stmt.orelse, none_params);
                self.walk(&try_stmt.finalbody, none_params);
            }
            Stmt::Match(match_stmt) => {
                for case in &match_stmt.cases {
                    self.walk(&case.body, none_params);
                }
            }
            Stmt::Assign(assign) => self.check_nan_fill(&assign.value),
            Stmt::Return(ret) => {
                if let Some(value) = &ret.value {
                    self.check_nan_fill(value);
                }
            }
            Stmt::Expr(expr_stmt) => self.check_nan_fill(&expr_stmt.value),
            _ => {}
        }
    }

    fn check_fallback(&mut self, try_stmt: &StmtTry) {
        let try_subst = Subst::of(&try_stmt.body);

        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(handler) = handler;
            if contains_raise(&handler.body) {
                continue;
            }

            let handler_subst = Subst::of(&handler.body);
            let falls_back = (try_subst.imports && handler_subst.imports)
                || (try_subst.returns && handler_subst.returns)
                || try_subst
                    .assigns
                    .iter()
                    .any(|name| handler_subst.assigns.contains(name));

            if falls_back {
                let line = line_at(self.source, handler.range.start().to_usize());
                self.flag(
                    "GUARD-FALLBACK",
                    line,
                    "except falls back to an alternative instead of failing",
                );
            }
        }
    }

    fn check_silent_none(&mut self, if_stmt: &StmtIf, none_params: &HashSet<String>) {
        let Some(name) = is_none_test(&if_stmt.test) else {
            return;
        };
        let assigns_name = Subst::of(&if_stmt.body).assigns.contains(&name);
        if assigns_name && !none_params.contains(&name) {
            let line = line_at(self.source, if_stmt.range.start().to_usize());
            self.flag(
                "GUARD-SILENT-DEFAULT",
                line,
                &format!("`if {name} is None` defaults a value that should have been provided"),
            );
        }
    }

    fn check_nan_fill(&mut self, expr: &Expr) {
        if let Expr::Call(call) = expr {
            if let Some(name) = callee_name(&call.func) {
                if name == "nan_to_num" || name == "fillna" {
                    let line = line_at(self.source, call.range.start().to_usize());
                    self.flag(
                        "GUARD-SILENT-DEFAULT",
                        line,
                        &format!("`{name}` silently replaces NaN or missing values"),
                    );
                }
            }
        }
    }

    fn check_test_function(&mut self, func: &StmtFunctionDef) {
        let mut scan = TestScan {
            asserts: Vec::new(),
            has_raises: false,
            mock_lines: Vec::new(),
            source: self.source,
            package_dirs: self.package_dirs,
        };
        for decorator in &func.decorator_list {
            scan.visit_expr(&decorator.expression);
        }
        for stmt in &func.body {
            scan.visit_stmt(stmt);
        }

        for line in &scan.mock_lines {
            self.flag(
                "TEST-MOCK-SUT",
                *line,
                "test mocks a first-party symbol it should exercise",
            );
        }

        if !scan.asserts.is_empty()
            && !scan.has_raises
            && scan.asserts.iter().all(|&test| is_weak_assert(test))
        {
            let line = line_at(self.source, func.range.start().to_usize());
            self.flag(
                "TEST-WEAK",
                line,
                &format!(
                    "test `{}` asserts only types/shapes/None, never a value",
                    func.name.as_str()
                ),
            );
        }
    }
}

/// Collects what a test function asserts and mocks, recursing through its body and decorators.
struct TestScan<'a> {
    asserts: Vec<&'a Expr>,
    has_raises: bool,
    mock_lines: Vec<usize>,
    source: &'a str,
    package_dirs: &'a HashSet<String>,
}

impl<'a> Visitor<'a> for TestScan<'a> {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        if let Stmt::Assert(assert) = stmt {
            self.asserts.push(&assert.test);
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        if let Expr::Call(call) = expr {
            if let Some(name) = callee_name(&call.func) {
                if name == "raises" {
                    self.has_raises = true;
                }
                if matches!(name, "patch" | "setattr" | "setitem" | "object") {
                    if let Some(root) = mock_target_root(call) {
                        if self.package_dirs.contains(&root) {
                            self.mock_lines
                                .push(line_at(self.source, call.range.start().to_usize()));
                        }
                    }
                }
            }
        }
        walk_expr(self, expr);
    }
}

struct Subst {
    imports: bool,
    returns: bool,
    assigns: HashSet<String>,
}

impl Subst {
    fn of(body: &[Stmt]) -> Subst {
        let mut subst = Subst {
            imports: false,
            returns: false,
            assigns: HashSet::new(),
        };
        for stmt in body {
            match stmt {
                Stmt::Import(_) | Stmt::ImportFrom(_) => subst.imports = true,
                Stmt::Return(_) => subst.returns = true,
                Stmt::Assign(assign) => {
                    for target in &assign.targets {
                        if let Expr::Name(name) = target {
                            subst.assigns.insert(name.id.as_str().to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        subst
    }
}

fn contains_raise(body: &[Stmt]) -> bool {
    struct RaiseFinder {
        found: bool,
    }
    impl<'a> Visitor<'a> for RaiseFinder {
        fn visit_stmt(&mut self, stmt: &'a Stmt) {
            if matches!(stmt, Stmt::Raise(_)) {
                self.found = true;
            }
            walk_stmt(self, stmt);
        }
    }
    let mut finder = RaiseFinder { found: false };
    for stmt in body {
        finder.visit_stmt(stmt);
    }
    finder.found
}

fn none_default_params(params: &Parameters) -> HashSet<String> {
    let mut set = HashSet::new();
    for param in params
        .posonlyargs
        .iter()
        .chain(&params.args)
        .chain(&params.kwonlyargs)
    {
        if matches!(param.default.as_deref(), Some(Expr::NoneLiteral(_))) {
            set.insert(param.parameter.name.as_str().to_string());
        }
    }
    set
}

/// `<name> is None` -> Some(name); used to spot the silent-default pattern.
fn is_none_test(test: &Expr) -> Option<String> {
    let Expr::Compare(cmp) = test else {
        return None;
    };
    if cmp.ops.len() == 1
        && matches!(cmp.ops[0], CmpOp::Is)
        && cmp.comparators.len() == 1
        && matches!(cmp.comparators[0], Expr::NoneLiteral(_))
    {
        if let Expr::Name(name) = cmp.left.as_ref() {
            return Some(name.id.as_str().to_string());
        }
    }
    None
}

fn callee_name(func: &Expr) -> Option<&str> {
    match func {
        Expr::Attribute(attr) => Some(attr.attr.as_str()),
        Expr::Name(name) => Some(name.id.as_str()),
        _ => None,
    }
}

fn mock_target_root(call: &ExprCall) -> Option<String> {
    let first = call.arguments.args.first()?;
    match first {
        Expr::StringLiteral(string) => string.value.to_str().split('.').next().map(str::to_string),
        Expr::Name(name) => Some(name.id.as_str().to_string()),
        Expr::Attribute(_) => {
            let mut current = first;
            while let Expr::Attribute(attr) = current {
                current = attr.value.as_ref();
            }
            if let Expr::Name(name) = current {
                Some(name.id.as_str().to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn is_weak_assert(test: &Expr) -> bool {
    match test {
        Expr::Call(call) => matches!(callee_name(&call.func), Some("isinstance" | "hasattr")),
        Expr::Compare(cmp) => {
            let against_none = cmp
                .comparators
                .iter()
                .any(|c| matches!(c, Expr::NoneLiteral(_)))
                && cmp
                    .ops
                    .iter()
                    .all(|op| matches!(op, CmpOp::Is | CmpOp::IsNot));
            against_none || expr_is_shape_or_len(&cmp.left)
        }
        _ => false,
    }
}

fn expr_is_shape_or_len(expr: &Expr) -> bool {
    match expr {
        Expr::Attribute(attr) => attr.attr.as_str() == "shape",
        Expr::Call(call) => matches!(callee_name(&call.func), Some("len")),
        _ => false,
    }
}

fn body_signature(body: &[Stmt]) -> u64 {
    struct SigVisitor {
        tags: Vec<u8>,
    }
    impl<'a> Visitor<'a> for SigVisitor {
        fn visit_stmt(&mut self, stmt: &'a Stmt) {
            self.tags.push(stmt_tag(stmt));
            walk_stmt(self, stmt);
        }
    }
    let mut sig = SigVisitor { tags: Vec::new() };
    for stmt in body {
        sig.visit_stmt(stmt);
    }
    let mut hasher = DefaultHasher::new();
    sig.tags.hash(&mut hasher);
    hasher.finish()
}

fn stmt_tag(stmt: &Stmt) -> u8 {
    match stmt {
        Stmt::FunctionDef(_) => 1,
        Stmt::ClassDef(_) => 2,
        Stmt::Return(_) => 3,
        Stmt::Assign(_) => 4,
        Stmt::AugAssign(_) => 5,
        Stmt::AnnAssign(_) => 6,
        Stmt::For(_) => 7,
        Stmt::While(_) => 8,
        Stmt::If(_) => 9,
        Stmt::With(_) => 10,
        Stmt::Raise(_) => 11,
        Stmt::Try(_) => 12,
        Stmt::Assert(_) => 13,
        Stmt::Import(_) => 14,
        Stmt::ImportFrom(_) => 15,
        Stmt::Expr(_) => 16,
        Stmt::Match(_) => 17,
        _ => 0,
    }
}

fn is_test_name(name: &str) -> bool {
    name.starts_with("test_")
}

fn line_at(source: &str, offset: usize) -> usize {
    let offset = offset.min(source.len());
    source.as_bytes()[..offset]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

/// Doc trees are skipped for COMMENT-NOISE: their comments are reStructuredText
/// (sphinx-gallery section underlines like `# ------`), which are required, not noise.
fn in_docs(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component.as_os_str().to_str(), Some("docs" | "doc")))
}

/// A decorative divider: any run of 3+ rule characters, so `# ===`, `# ----`, and
/// `# --- Section ---` all count, while a single `- bullet` or `x = 1` does not.
fn has_divider_run(body: &str) -> bool {
    let mut run = 0u32;
    for c in body.chars() {
        if matches!(c, '=' | '-' | '#' | '*' | '~') {
            run += 1;
            if run >= 3 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(source: &str) -> Vec<String> {
        let pkgs: HashSet<String> = ["mypkg"].into_iter().map(str::to_string).collect();
        check_file(Path::new("t.py"), source, &pkgs)
            .findings
            .into_iter()
            .map(|f| f.rule.to_string())
            .collect()
    }

    fn count(source: &str, rule: &str) -> usize {
        run(source).iter().filter(|r| *r == rule).count()
    }

    #[test]
    fn fallback_import_and_assign() {
        assert_eq!(
            count(
                "try:\n    import a as m\nexcept ImportError:\n    import b as m\n",
                "GUARD-FALLBACK"
            ),
            1
        );
        assert_eq!(
            count(
                "try:\n    x = fast()\nexcept Exception:\n    x = slow()\n",
                "GUARD-FALLBACK"
            ),
            1
        );
        assert_eq!(
            count(
                "try:\n    x = fast()\nexcept Exception:\n    raise\n",
                "GUARD-FALLBACK"
            ),
            0
        );
    }

    #[test]
    fn silent_default_skips_optional_arg_idiom() {
        // masking a non-optional value: flagged
        assert_eq!(
            count(
                "def f():\n    if cfg is None:\n        cfg = default()\n",
                "GUARD-SILENT-DEFAULT"
            ),
            1
        );
        // the optional-argument idiom: not flagged
        assert_eq!(
            count(
                "def f(x=None):\n    if x is None:\n        x = []\n",
                "GUARD-SILENT-DEFAULT"
            ),
            0
        );
    }

    #[test]
    fn silent_default_nan_fill() {
        assert_eq!(
            count(
                "def f(x):\n    return torch.nan_to_num(x)\n",
                "GUARD-SILENT-DEFAULT"
            ),
            1
        );
    }

    #[test]
    fn test_weak_only_when_no_value_assert() {
        assert_eq!(
            count(
                "def test_a():\n    assert isinstance(x, int)\n",
                "TEST-WEAK"
            ),
            1
        );
        assert_eq!(
            count("def test_b():\n    assert x.shape == (3,)\n", "TEST-WEAK"),
            1
        );
        // a real value assert alongside a shape check: not weak
        assert_eq!(
            count(
                "def test_c():\n    assert x.shape == (3,)\n    assert y == 5\n",
                "TEST-WEAK"
            ),
            0
        );
    }

    #[test]
    fn mock_sut_first_party_only() {
        assert_eq!(
            count(
                "def test_a(monkeypatch):\n    monkeypatch.setattr('mypkg.mod.f', g)\n",
                "TEST-MOCK-SUT"
            ),
            1
        );
        assert_eq!(
            count(
                "def test_b(monkeypatch):\n    monkeypatch.setattr('requests.get', g)\n",
                "TEST-MOCK-SUT"
            ),
            0
        );
    }

    #[test]
    fn comment_noise_changelog_and_divider() {
        assert_eq!(count("x = 1  # used to be 2\n", "COMMENT-NOISE"), 1);
        assert_eq!(count("# ===\nx = 1\n", "COMMENT-NOISE"), 1);
        assert_eq!(count("# --- Section ---\nx = 1\n", "COMMENT-NOISE"), 1);
        assert_eq!(
            count("# explains why x is needed\nx = 1\n", "COMMENT-NOISE"),
            0
        );
        assert_eq!(
            count("# - a single-dash bullet\nx = 1\n", "COMMENT-NOISE"),
            0
        );
    }

    #[test]
    fn comment_noise_skips_docs() {
        let pkgs = HashSet::new();
        let result = check_file(
            Path::new("docs/examples/tour.py"),
            "# Title\n# ------\nx = 1\n",
            &pkgs,
        );
        assert!(result.findings.iter().all(|f| f.rule != "COMMENT-NOISE"));
    }
}
