use crate::finding::Finding;
use crate::rules::tokenize;
use ruff_python_ast::token::TokenKind;
use ruff_python_ast::visitor::{walk_expr, walk_stmt, Visitor};
use ruff_python_ast::{
    CmpOp, Decorator, ExceptHandler, Expr, ExprCall, Parameters, Stmt, StmtClassDef,
    StmtFunctionDef, StmtIf, StmtRaise, StmtTry,
};
use ruff_python_parser::parse_module;
use ruff_text_size::Ranged;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::Path;

/// A top-level function's name plus a hash of its body shape (statement kinds and the
/// names it calls), for the repo-level DUP rules. `body_len` is the statement count,
/// used to keep trivial one-liners out of the cross-name duplication check.
pub struct FuncSig {
    pub name: String,
    pub body_sig: u64,
    pub body_len: usize,
}

/// A class definition seen anywhere in a file, for the repo-level abstraction-solo rule.
pub struct ClassInfo {
    pub name: String,
    pub bases: Vec<String>,
    pub is_abstract: bool,
    pub is_protocol: bool,
    pub line: usize,
}

pub struct FileResult {
    pub findings: Vec<Finding>,
    pub func_sigs: Vec<FuncSig>,
    pub classes: Vec<ClassInfo>,
}

/// The lexical context threaded down the walk: the enclosing function's parameters (so
/// guard-silent-default leaves the optional-argument idiom — a `None`-checked parameter —
/// alone, while still flagging a defaulted local) and whether the immediately enclosing
/// class is a `Protocol` (so stub leaves its bodyless members alone). ABC abstract methods
/// are exempted per-method by their `@abstractmethod` decorator, so a plain `pass` method in
/// an ABC still fires.
#[derive(Clone, Copy)]
struct Scope<'a> {
    enclosing_params: &'a HashSet<String>,
    in_interface: bool,
}

/// Run every parser-based per-file rule. `package_dirs` is the set of the repo's own
/// directory names, used to tell a first-party mock target from an external one. `banned`
/// is the configured slop vocabulary for banned-word.
pub fn check_file(
    path: &Path,
    source: &str,
    package_dirs: &HashSet<String>,
    banned: &[String],
) -> FileResult {
    let parsed = match parse_module(source) {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("balinter: parse error in {}: {err}", path.display());
            return FileResult {
                findings: Vec::new(),
                func_sigs: Vec::new(),
                classes: Vec::new(),
            };
        }
    };

    let module = parsed.syntax();
    let mut checker = Checker {
        source,
        path,
        package_dirs,
        banned,
        findings: Vec::new(),
        func_sigs: Vec::new(),
        classes: Vec::new(),
    };

    for stmt in &module.body {
        if let Stmt::FunctionDef(func) = stmt {
            let (body_sig, body_len) = body_signature(&func.body);
            checker.func_sigs.push(FuncSig {
                name: func.name.as_str().to_string(),
                body_sig,
                body_len,
            });
        }
    }

    let no_params = HashSet::new();
    let root = Scope {
        enclosing_params: &no_params,
        in_interface: false,
    };
    checker.check_doc_prose(&module.body);
    checker.walk(&module.body, root);

    let in_docs_path = in_docs(path);
    for token in parsed.tokens().iter() {
        if token.kind() != TokenKind::Comment {
            continue;
        }
        let range = token.range();
        let text = &source[range.start().to_usize()..range.end().to_usize()];
        let body = text.strip_prefix('#').unwrap_or(text).trim();
        let line = line_at(source, range.start().to_usize());

        if !in_docs_path {
            let lower = body.to_ascii_lowercase();
            let changelog = ["used to be", "formerly", "renamed", "originally"]
                .iter()
                .any(|phrase| lower.contains(phrase));

            if changelog || has_divider_run(body) {
                let what = if changelog {
                    "changelog comment"
                } else {
                    "decorative divider comment"
                };
                checker.flag("comment-noise", line, what);
            }
        }

        checker.scan_prose(body, line);
    }

    let mut idents = IdentScan {
        source,
        path,
        banned,
        findings: Vec::new(),
    };
    for stmt in &module.body {
        idents.visit_stmt(stmt);
    }
    checker.findings.extend(idents.findings);

    let mut nan = NanFillScan {
        source,
        path,
        findings: Vec::new(),
    };
    for stmt in &module.body {
        nan.visit_stmt(stmt);
    }
    checker.findings.extend(nan.findings);

    FileResult {
        findings: checker.findings,
        func_sigs: checker.func_sigs,
        classes: checker.classes,
    }
}

struct Checker<'a> {
    source: &'a str,
    path: &'a Path,
    package_dirs: &'a HashSet<String>,
    banned: &'a [String],
    findings: Vec<Finding>,
    func_sigs: Vec<FuncSig>,
    classes: Vec<ClassInfo>,
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

    fn walk(&mut self, body: &[Stmt], scope: Scope<'_>) {
        for stmt in body {
            self.visit(stmt, scope);
        }
    }

    fn visit(&mut self, stmt: &Stmt, scope: Scope<'_>) {
        match stmt {
            Stmt::FunctionDef(func) => {
                self.check_stub(func, scope.in_interface);
                self.check_doc_bloat(func);
                self.check_doc_prose(&func.body);
                if is_test_name(func.name.as_str()) {
                    self.check_test_function(func);
                }
                let fn_params: HashSet<String> = all_param_names(&func.parameters)
                    .into_iter()
                    .map(str::to_string)
                    .collect();
                self.walk(
                    &func.body,
                    Scope {
                        enclosing_params: &fn_params,
                        in_interface: false,
                    },
                );
            }
            Stmt::ClassDef(class) => {
                let info = class_info(class, self.source);
                let in_interface = info.is_protocol;
                self.classes.push(info);
                self.check_doc_prose(&class.body);
                self.walk(
                    &class.body,
                    Scope {
                        enclosing_params: scope.enclosing_params,
                        in_interface,
                    },
                );
            }
            Stmt::If(if_stmt) => {
                self.check_silent_none(if_stmt, scope.enclosing_params);
                self.walk(&if_stmt.body, scope);
                for clause in &if_stmt.elif_else_clauses {
                    self.walk(&clause.body, scope);
                }
            }
            Stmt::For(for_stmt) => {
                self.walk(&for_stmt.body, scope);
                self.walk(&for_stmt.orelse, scope);
            }
            Stmt::While(while_stmt) => {
                self.walk(&while_stmt.body, scope);
                self.walk(&while_stmt.orelse, scope);
            }
            Stmt::With(with_stmt) => self.walk(&with_stmt.body, scope),
            Stmt::Try(try_stmt) => {
                self.check_fallback(try_stmt);
                self.walk(&try_stmt.body, scope);
                for handler in &try_stmt.handlers {
                    let ExceptHandler::ExceptHandler(handler) = handler;
                    self.walk(&handler.body, scope);
                }
                self.walk(&try_stmt.orelse, scope);
                self.walk(&try_stmt.finalbody, scope);
            }
            Stmt::Match(match_stmt) => {
                for case in &match_stmt.cases {
                    self.walk(&case.body, scope);
                }
            }
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
                    "guard-fallback",
                    line,
                    "except falls back to an alternative instead of failing",
                );
            }
        }
    }

    fn check_silent_none(&mut self, if_stmt: &StmtIf, enclosing_params: &HashSet<String>) {
        let Some(name) = is_none_test(&if_stmt.test) else {
            return;
        };
        let assigns_name = Subst::of(&if_stmt.body).assigns.contains(&name);
        if assigns_name && !enclosing_params.contains(&name) {
            let line = line_at(self.source, if_stmt.range.start().to_usize());
            self.flag(
                "guard-silent-default",
                line,
                &format!("`if {name} is None` defaults a value that should have been provided"),
            );
        }
    }

    /// A concrete function whose entire body is `pass`, `...`, or a bare
    /// `raise NotImplementedError` is scaffolding. Skipped: `@overload` and `@abstractmethod`
    /// methods, `Protocol` members, and `raise NotImplementedError("reason")` with a message
    /// (a real API boundary). A bodyless method in a plain class, or a non-abstract method in
    /// an ABC, is not skipped: if you mean "abstract", use `@abstractmethod`.
    fn check_stub(&mut self, func: &StmtFunctionDef, in_interface: bool) {
        if in_interface || has_stub_decorator(&func.decorator_list) {
            return;
        }
        if is_stub_body(&func.body) {
            let line = line_at(self.source, func.range.start().to_usize());
            self.flag(
                "stub",
                line,
                &format!(
                    "`{}` is a placeholder body, not an implementation",
                    func.name.as_str()
                ),
            );
        }
    }

    /// A docstring longer than the code it documents, on a tiny function, with no
    /// structured Parameters/Returns/Examples section, is padding.
    fn check_doc_bloat(&mut self, func: &StmtFunctionDef) {
        let Some(doc) = func.body.first() else {
            return;
        };
        if !is_docstring(doc) {
            return;
        }
        let doc_lines = line_span(self.source, doc.range());
        let code = &func.body[1..];
        let code_lines = match (code.first(), code.last()) {
            (Some(first), Some(last)) => {
                line_at(self.source, last.range().end().to_usize())
                    - line_at(self.source, first.range().start().to_usize())
                    + 1
            }
            _ => 0,
        };

        let Stmt::Expr(expr) = doc else { return };
        let Expr::StringLiteral(text) = expr.value.as_ref() else {
            return;
        };

        if code_lines <= 5
            && doc_lines >= 8
            && doc_lines > code_lines
            && !has_doc_section(text.value.to_str())
        {
            let line = line_at(self.source, doc.range().start().to_usize());
            self.flag(
                "doc-bloat",
                line,
                &format!(
                    "{doc_lines}-line docstring over {code_lines} lines of code, no Parameters/Returns section"
                ),
            );
        }
    }

    fn check_doc_prose(&mut self, body: &[Stmt]) {
        let Some(stmt) = body.first() else {
            return;
        };
        if !is_docstring(stmt) {
            return;
        }
        let Stmt::Expr(expr) = stmt else { return };
        let Expr::StringLiteral(text) = expr.value.as_ref() else {
            return;
        };
        let line = line_at(self.source, stmt.range().start().to_usize());
        self.scan_prose(text.value.to_str(), line);
    }

    fn scan_prose(&mut self, text: &str, line: usize) {
        let lower = text.to_ascii_lowercase();
        let banned = self.banned;
        for word in banned {
            if contains_word(&lower, word) {
                self.flag("banned-word", line, &format!("slop term \"{word}\""));
            }
        }
        if has_emoji(text) {
            self.flag("banned-word", line, "emoji in prose");
        }
    }

    fn check_test_function(&mut self, func: &StmtFunctionDef) {
        let mut scan = TestScan {
            asserts: Vec::new(),
            has_raises: false,
            has_strong_assert: false,
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
                "test-mock-sut",
                *line,
                "test mocks a first-party symbol it should exercise",
            );
        }

        if !scan.asserts.is_empty()
            && !scan.has_raises
            && !scan.has_strong_assert
            && scan.asserts.iter().all(|&test| is_weak_assert(test))
        {
            let line = line_at(self.source, func.range.start().to_usize());
            self.flag(
                "test-weak",
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
    has_strong_assert: bool,
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
                if is_strong_assert_call(name) {
                    self.has_strong_assert = true;
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

/// Scans every identifier in a module for banned tokens: function, class, parameter and
/// lambda-parameter names, plus every `Name` and attribute occurrence (so for-targets,
/// `with ... as`, comprehension variables and `self.attr` are all covered). Each name is
/// tokenized on underscores and camelCase, matched whole-token, so `seamless` fires in
/// `seamless_run` and `SeamlessRun` but not in `seamlessly`.
struct IdentScan<'a> {
    source: &'a str,
    path: &'a Path,
    banned: &'a [String],
    findings: Vec<Finding>,
}

impl IdentScan<'_> {
    fn check(&mut self, name: &str, line: usize) {
        let tokens = tokenize(name);
        let banned = self.banned;
        for word in banned {
            if tokens.iter().any(|token| token.as_str() == word.as_str()) {
                self.findings.push(Finding {
                    rule: "banned-word",
                    file: self.path.display().to_string(),
                    line: Some(line),
                    message: format!("slop term \"{word}\" in name `{name}`"),
                });
            }
        }
    }
}

impl<'a> Visitor<'a> for IdentScan<'a> {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        match stmt {
            Stmt::FunctionDef(func) => {
                let line = line_at(self.source, func.range.start().to_usize());
                self.check(func.name.as_str(), line);
                for name in all_param_names(&func.parameters) {
                    self.check(name, line);
                }
            }
            Stmt::ClassDef(class) => {
                let line = line_at(self.source, class.range.start().to_usize());
                self.check(class.name.as_str(), line);
            }
            _ => {}
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        match expr {
            Expr::Name(name) => {
                let line = line_at(self.source, name.range.start().to_usize());
                self.check(name.id.as_str(), line);
            }
            Expr::Attribute(attr) => {
                let line = line_at(self.source, attr.range.start().to_usize());
                self.check(attr.attr.as_str(), line);
            }
            Expr::Lambda(lambda) => {
                if let Some(params) = &lambda.parameters {
                    let line = line_at(self.source, lambda.range.start().to_usize());
                    for name in all_param_names(params) {
                        self.check(name, line);
                    }
                }
            }
            _ => {}
        }
        walk_expr(self, expr);
    }
}

/// Flags `nan_to_num` / `fillna` calls anywhere they appear — they silently replace
/// missing or NaN values instead of failing.
struct NanFillScan<'a> {
    source: &'a str,
    path: &'a Path,
    findings: Vec<Finding>,
}

impl<'a> Visitor<'a> for NanFillScan<'a> {
    fn visit_expr(&mut self, expr: &'a Expr) {
        if let Expr::Call(call) = expr {
            if let Some(name) = callee_name(&call.func) {
                if name == "nan_to_num" || name == "fillna" {
                    let line = line_at(self.source, call.range.start().to_usize());
                    self.findings.push(Finding {
                        rule: "guard-silent-default",
                        file: self.path.display().to_string(),
                        line: Some(line),
                        message: format!("`{name}` silently replaces NaN or missing values"),
                    });
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

fn all_param_names(params: &Parameters) -> Vec<&str> {
    let mut names: Vec<&str> = params
        .posonlyargs
        .iter()
        .chain(&params.args)
        .chain(&params.kwonlyargs)
        .map(|param| param.parameter.name.as_str())
        .collect();
    if let Some(vararg) = &params.vararg {
        names.push(vararg.name.as_str());
    }
    if let Some(kwarg) = &params.kwarg {
        names.push(kwarg.name.as_str());
    }
    names
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

/// A value-checking assertion call (`np.testing.assert_allclose`, `chex.assert_trees_all_close`,
/// `torch.testing.assert_close`, `self.assertEqual`, ...). The type/None/instance variants do
/// not count, since they pin no value.
fn is_strong_assert_call(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("assert")
        && !matches!(
            name,
            "assertIsInstance"
                | "assertNotIsInstance"
                | "assertIsNone"
                | "assertIsNotNone"
                | "assert_type"
        )
}

fn expr_is_shape_or_len(expr: &Expr) -> bool {
    match expr {
        Expr::Attribute(attr) => attr.attr.as_str() == "shape",
        Expr::Call(call) => matches!(callee_name(&call.func), Some("len")),
        _ => false,
    }
}

/// True when `stmt` is a string-literal expression standing alone, i.e. a docstring.
fn is_docstring(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Expr(e) if matches!(e.value.as_ref(), Expr::StringLiteral(_)))
}

fn is_stub_body(body: &[Stmt]) -> bool {
    let rest: &[Stmt] = match body.first() {
        Some(first) if is_docstring(first) => &body[1..],
        _ => body,
    };
    matches!(rest, [stmt] if is_stub_stmt(stmt))
}

fn is_stub_stmt(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Pass(_) => true,
        Stmt::Expr(expr) => matches!(expr.value.as_ref(), Expr::EllipsisLiteral(_)),
        Stmt::Raise(raise) => is_bare_notimplemented(raise),
        _ => false,
    }
}

fn is_bare_notimplemented(raise: &StmtRaise) -> bool {
    match raise.exc.as_deref() {
        Some(Expr::Name(name)) => name.id.as_str() == "NotImplementedError",
        Some(Expr::Call(call)) => {
            callee_name(&call.func) == Some("NotImplementedError")
                && call.arguments.args.is_empty()
                && call.arguments.keywords.is_empty()
        }
        _ => false,
    }
}

fn has_stub_decorator(decorators: &[Decorator]) -> bool {
    decorators.iter().any(|d| {
        matches!(
            decorator_name(&d.expression),
            Some(
                "overload"
                    | "abstractmethod"
                    | "abstractproperty"
                    | "abstractclassmethod"
                    | "abstractstaticmethod"
            )
        )
    })
}

fn has_abstractmethod(decorators: &[Decorator]) -> bool {
    decorators.iter().any(|d| {
        matches!(
            decorator_name(&d.expression),
            Some(
                "abstractmethod"
                    | "abstractproperty"
                    | "abstractclassmethod"
                    | "abstractstaticmethod"
            )
        )
    })
}

fn decorator_name(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Call(call) => callee_name(&call.func),
        other => callee_name(other),
    }
}

fn class_info(class: &StmtClassDef, source: &str) -> ClassInfo {
    let mut bases = Vec::new();
    let mut abstract_base = false;
    let mut protocol_base = false;
    let mut abc_meta = false;

    if let Some(arguments) = &class.arguments {
        for base in arguments.args.iter() {
            if let Some(name) = head_name(base) {
                if name == "Protocol" {
                    protocol_base = true;
                    abstract_base = true;
                } else if name == "ABC" {
                    abstract_base = true;
                }
                bases.push(name);
            }
        }
        for keyword in arguments.keywords.iter() {
            if keyword
                .arg
                .as_ref()
                .is_some_and(|a| a.as_str() == "metaclass")
                && head_name(&keyword.value).as_deref() == Some("ABCMeta")
            {
                abc_meta = true;
            }
        }
    }

    let has_abstract_method = class.body.iter().any(|stmt| match stmt {
        Stmt::FunctionDef(func) => has_abstractmethod(&func.decorator_list),
        _ => false,
    });

    ClassInfo {
        name: class.name.as_str().to_string(),
        bases,
        is_abstract: abstract_base || abc_meta || has_abstract_method,
        is_protocol: protocol_base,
        line: line_at(source, class.range.start().to_usize()),
    }
}

/// The leading name of a base-class expression: `Name` -> itself, `pkg.Base` -> `Base`,
/// `Generic[T]` -> `Generic`.
fn head_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(name) => Some(name.id.as_str().to_string()),
        Expr::Attribute(attr) => Some(attr.attr.as_str().to_string()),
        Expr::Subscript(sub) => head_name(&sub.value),
        _ => None,
    }
}

/// A structured docstring section (numpy or Google style) marks real API documentation,
/// which is never doc-bloat however long it is.
fn has_doc_section(text: &str) -> bool {
    const SECTIONS: [&str; 11] = [
        "Parameters",
        "Args:",
        "Arguments",
        "Returns",
        "Return:",
        "Yields",
        "Raises",
        "Examples",
        "Example:",
        "Attributes",
        "References",
    ];
    SECTIONS.iter().any(|s| text.contains(s)) || text.contains("----")
}

fn has_emoji(text: &str) -> bool {
    text.chars().any(|c| {
        let u = c as u32;
        (0x2600..=0x27BF).contains(&u)
            || (0x2B00..=0x2BFF).contains(&u)
            || (0x1F000..=0x1FAFF).contains(&u)
    })
}

/// Whole-word (or whole-phrase) match: the needle occurs with non-alphanumeric characters
/// on both sides, so "let me" does not fire inside "tablet me" and "clean" would not fire
/// inside "cleanly". Both arguments are already lowercased.
fn contains_word(hay: &str, needle: &str) -> bool {
    let mut from = 0;
    while let Some(rel) = hay[from..].find(needle) {
        let start = from + rel;
        let end = start + needle.len();
        let before_ok = start == 0
            || !hay[..start]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric());
        let after_ok = end >= hay.len()
            || !hay[end..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// A hash of a function body's shape: the sequence of statement kinds plus the names it
/// calls. Two bodies collide only when they have the same control-flow skeleton and call
/// the same functions, so a match is strong evidence of copy-paste. Returns the hash and
/// the statement count.
fn body_signature(body: &[Stmt]) -> (u64, usize) {
    struct SigVisitor {
        tags: Vec<u8>,
        calls: Vec<String>,
    }
    impl<'a> Visitor<'a> for SigVisitor {
        fn visit_stmt(&mut self, stmt: &'a Stmt) {
            self.tags.push(stmt_tag(stmt));
            walk_stmt(self, stmt);
        }
        fn visit_expr(&mut self, expr: &'a Expr) {
            if let Expr::Call(call) = expr {
                if let Some(name) = callee_name(&call.func) {
                    self.calls.push(name.to_string());
                }
            }
            walk_expr(self, expr);
        }
    }
    let mut sig = SigVisitor {
        tags: Vec::new(),
        calls: Vec::new(),
    };
    for stmt in body {
        sig.visit_stmt(stmt);
    }
    let len = sig.tags.len();
    let mut hasher = DefaultHasher::new();
    sig.tags.hash(&mut hasher);
    sig.calls.hash(&mut hasher);
    (hasher.finish(), len)
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

/// The number of source lines a node spans, inclusive.
fn line_span(source: &str, range: ruff_text_size::TextRange) -> usize {
    line_at(source, range.end().to_usize()) - line_at(source, range.start().to_usize()) + 1
}

/// comment-noise is off in `docs`/`doc` trees: their divider characters are reStructuredText
/// section underlines (a `# -----` under a heading), not hand-drawn separators, and the two
/// are byte-identical. Other rules still run there; whole paths can be excluded via config.
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
        let banned: Vec<String> = ["seamless", "feel free"]
            .into_iter()
            .map(str::to_string)
            .collect();
        check_file(Path::new("t.py"), source, &pkgs, &banned)
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
                "guard-fallback"
            ),
            1
        );
        assert_eq!(
            count(
                "try:\n    x = fast()\nexcept Exception:\n    x = slow()\n",
                "guard-fallback"
            ),
            1
        );
        assert_eq!(
            count(
                "try:\n    x = fast()\nexcept Exception:\n    raise\n",
                "guard-fallback"
            ),
            0
        );
    }

    #[test]
    fn silent_default_skips_optional_arg_idiom() {
        // cfg is a local, not a parameter: masking a value, flagged
        assert_eq!(
            count(
                "def f():\n    if cfg is None:\n        cfg = default()\n",
                "guard-silent-default"
            ),
            1
        );
        // a parameter with a literal =None default: the idiom, not flagged
        assert_eq!(
            count(
                "def f(x=None):\n    if x is None:\n        x = []\n",
                "guard-silent-default"
            ),
            0
        );
        // a parameter without a literal default (e.g. fed None by a decorator): also the idiom
        assert_eq!(
            count(
                "def f(x):\n    if x is None:\n        x = compute()\n",
                "guard-silent-default"
            ),
            0
        );
    }

    #[test]
    fn silent_default_nan_fill() {
        assert_eq!(
            count(
                "def f(x):\n    return torch.nan_to_num(x)\n",
                "guard-silent-default"
            ),
            1
        );
        // nested in a call argument: still caught (the statement-level check missed this)
        assert_eq!(
            count(
                "def f(x):\n    y = g(torch.nan_to_num(x))\n    return y\n",
                "guard-silent-default"
            ),
            1
        );
    }

    #[test]
    fn test_weak_only_when_no_value_assert() {
        assert_eq!(
            count(
                "def test_a():\n    assert isinstance(x, int)\n",
                "test-weak"
            ),
            1
        );
        assert_eq!(
            count("def test_b():\n    assert x.shape == (3,)\n", "test-weak"),
            1
        );
        assert_eq!(
            count(
                "def test_c():\n    assert x.shape == (3,)\n    assert y == 5\n",
                "test-weak"
            ),
            0
        );
        // a value-checking assertion CALL is strong, even beside a weak `assert`
        assert_eq!(
            count(
                "def test_d():\n    assert x.shape == (3,)\n    np.testing.assert_allclose(x, y)\n",
                "test-weak"
            ),
            0
        );
    }

    #[test]
    fn mock_sut_first_party_only() {
        assert_eq!(
            count(
                "def test_a(monkeypatch):\n    monkeypatch.setattr('mypkg.mod.f', g)\n",
                "test-mock-sut"
            ),
            1
        );
        assert_eq!(
            count(
                "def test_b(monkeypatch):\n    monkeypatch.setattr('requests.get', g)\n",
                "test-mock-sut"
            ),
            0
        );
    }

    #[test]
    fn comment_noise_changelog_and_divider() {
        assert_eq!(count("x = 1  # used to be 2\n", "comment-noise"), 1);
        assert_eq!(count("x = 1  # renamed from old_x\n", "comment-noise"), 1);
        // "used to" in the employed-to sense is not a changelog comment
        assert_eq!(
            count("y = f(x)  # used to derive the result\n", "comment-noise"),
            0
        );
        // dropped phrases: too loose, fired on runtime/algorithm descriptions
        assert_eq!(
            count("x = 1  # the previously cached value\n", "comment-noise"),
            0
        );
        assert_eq!(
            count("x = 1  # no longer pinned at runtime\n", "comment-noise"),
            0
        );
        assert_eq!(count("# ===\nx = 1\n", "comment-noise"), 1);
        assert_eq!(count("# --- Section ---\nx = 1\n", "comment-noise"), 1);
        assert_eq!(
            count("# explains why x is needed\nx = 1\n", "comment-noise"),
            0
        );
        assert_eq!(
            count("# - a single-dash bullet\nx = 1\n", "comment-noise"),
            0
        );
    }

    #[test]
    fn comment_noise_off_in_docs() {
        // a divider in a doc tree is an rST section underline, not noise
        let pkgs = HashSet::new();
        let result = check_file(
            Path::new("docs/examples/tour.py"),
            "# ---\nx = 1\n",
            &pkgs,
            &[],
        );
        assert!(result.findings.iter().all(|f| f.rule != "comment-noise"));
    }

    #[test]
    fn stub_bodies_flagged_concrete_only() {
        assert_eq!(count("def f():\n    pass\n", "stub"), 1);
        assert_eq!(count("def f():\n    ...\n", "stub"), 1);
        assert_eq!(
            count("def f():\n    raise NotImplementedError\n", "stub"),
            1
        );
        assert_eq!(
            count("def f():\n    raise NotImplementedError()\n", "stub"),
            1
        );
        // a message means a real boundary, not a stub
        assert_eq!(
            count(
                "def f():\n    raise NotImplementedError('no cuda')\n",
                "stub"
            ),
            0
        );
        // a real body is not a stub
        assert_eq!(count("def f():\n    return 1 + 1\n", "stub"), 0);
    }

    #[test]
    fn stub_skips_overload_abstract_and_protocol() {
        assert_eq!(count("@overload\ndef f(x): ...\n", "stub"), 0);
        assert_eq!(
            count(
                "class C(ABC):\n    @abstractmethod\n    def f(self): ...\n",
                "stub"
            ),
            0
        );
        assert_eq!(
            count("class P(Protocol):\n    def f(self): ...\n", "stub"),
            0
        );
        // a plain class with a stub method is still flagged
        assert_eq!(
            count("class C:\n    def f(self):\n        pass\n", "stub"),
            1
        );
        // a non-abstract `pass` method in an ABC is not exempt; only the @abstractmethod one is
        assert_eq!(
            count(
                "class C(ABC):\n    @abstractmethod\n    def a(self): ...\n    def b(self):\n        pass\n",
                "stub"
            ),
            1
        );
    }

    #[test]
    fn banned_word_in_docstring_and_comment() {
        assert_eq!(
            count(
                "def f():\n    \"\"\"A seamless helper.\"\"\"\n    return 1\n",
                "banned-word"
            ),
            1
        );
        assert_eq!(count("x = 1  # feel free to tweak\n", "banned-word"), 1);
        // a plain word that contains a banned substring is not matched
        assert_eq!(
            count(
                "def f():\n    \"\"\"Seamlessness aside.\"\"\"\n    return 1\n",
                "banned-word"
            ),
            0
        );
    }

    #[test]
    fn banned_word_emoji() {
        let n = run("def f():\n    \"\"\"Done \u{2705}\"\"\"\n    return 1\n")
            .iter()
            .filter(|r| *r == "banned-word")
            .count();
        assert_eq!(n, 1);
    }

    #[test]
    fn banned_word_in_identifiers() {
        // function name
        assert_eq!(
            count("def seamless_helper(x):\n    return x\n", "banned-word"),
            1
        );
        // class name (camelCase split)
        assert_eq!(count("class SeamlessThing:\n    pass\n", "banned-word"), 1);
        // for-loop target
        assert_eq!(count("for seamless in xs:\n    pass\n", "banned-word"), 1);
        // attribute name
        assert_eq!(count("obj.seamless = 1\n", "banned-word"), 1);
        // comprehension variable
        assert_eq!(
            count("ys = [seamless for seamless in xs]\n", "banned-word"),
            2
        );
        // whole-token only: 'seamlessly' is a different token, not a match
        assert_eq!(
            count("def seamlessly(x):\n    return x\n", "banned-word"),
            0
        );
    }

    #[test]
    fn banned_word_not_skipped_in_docs() {
        let pkgs = HashSet::new();
        let banned = vec!["seamless".to_string()];
        let result = check_file(
            Path::new("docs/examples/tour.py"),
            "\"\"\"A seamless tour.\"\"\"\n",
            &pkgs,
            &banned,
        );
        assert!(result.findings.iter().any(|f| f.rule == "banned-word"));
    }

    #[test]
    fn doc_bloat_only_padding_without_sections() {
        // tiny function, long sectionless docstring: padding
        let padded = "def f():\n    \"\"\"Line.\n    Line.\n    Line.\n    Line.\n    Line.\n    Line.\n    Line.\n    Line.\n    \"\"\"\n    return 1\n";
        assert_eq!(count(padded, "doc-bloat"), 1);
        // same length but with a Returns section: real API doc
        let sectioned = "def f():\n    \"\"\"Line.\n    Line.\n    Line.\n    Line.\n    Returns:\n        int: one.\n    Line.\n    Line.\n    \"\"\"\n    return 1\n";
        assert_eq!(count(sectioned, "doc-bloat"), 0);
    }

    #[test]
    fn contains_word_respects_boundaries() {
        assert!(contains_word("a seamless thing", "seamless"));
        assert!(!contains_word("seamlessness", "seamless"));
        assert!(contains_word("cutting-edge tech", "cutting-edge"));
        assert!(!contains_word("tablet me now", "let me"));
        assert!(contains_word("let me explain", "let me"));
    }

    #[test]
    fn body_signature_separates_calls() {
        let (a, _) = sig_of("x = foo()\n");
        let (b, _) = sig_of("x = bar()\n");
        let (c, _) = sig_of("x = foo()\n");
        assert_ne!(a, b, "different calls should differ");
        assert_eq!(a, c, "identical bodies should match");
    }

    fn sig_of(src: &str) -> (u64, usize) {
        let parsed = parse_module(src).unwrap();
        body_signature(&parsed.syntax().body)
    }

    #[test]
    fn class_info_detects_abstract() {
        let info = first_class("class P(Protocol):\n    def f(self): ...\n");
        assert!(info.is_abstract);
        let info = first_class("class C(ABC):\n    @abstractmethod\n    def f(self): ...\n");
        assert!(info.is_abstract);
        let info = first_class("class D(Base):\n    x = 1\n");
        assert!(!info.is_abstract);
        assert_eq!(info.bases, vec!["Base".to_string()]);
    }

    fn first_class(src: &str) -> ClassInfo {
        let pkgs = HashSet::new();
        check_file(Path::new("t.py"), src, &pkgs, &[])
            .classes
            .into_iter()
            .next()
            .unwrap()
    }
}
