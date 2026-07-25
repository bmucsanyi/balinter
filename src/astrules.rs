use crate::config::Config;
use crate::finding::{path_string, Finding, Rule, SourceLocator};
use crate::noqa;
use crate::rules::tokenize;
use ruff_python_ast::token::{Token, TokenKind};
use ruff_python_ast::visitor::{
    walk_except_handler, walk_expr, walk_pattern, walk_stmt, walk_with_item, Visitor,
};
use ruff_python_ast::{
    CmpOp, Comprehension, Decorator, ExceptHandler, Expr, ExprCall, Parameter, Parameters, Pattern,
    PySourceType, Stmt, StmtClassDef, StmtFunctionDef, StmtRaise, StmtTry, WithItem,
};
use ruff_python_parser::{parse, parse_module, ParseOptions};
use ruff_text_size::Ranged;
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub struct FuncSig {
    pub name: String,
    pub qualified_name: String,
    pub normalized_body: String,
    pub body_len: usize,
    pub is_forwarder: bool,
    pub line: usize,
    pub cell: Option<usize>,
}

pub struct ClassInfo {
    pub name: String,
    pub qualified_name: String,
    pub bases: Vec<String>,
    pub is_abstract: bool,
    pub is_protocol: bool,
    pub abstract_methods: Vec<String>,
    pub concrete_methods: Vec<String>,
    pub line: usize,
    pub cell: Option<usize>,
}

pub struct FileResult {
    pub findings: Vec<Finding>,
    pub func_sigs: Vec<FuncSig>,
    pub classes: Vec<ClassInfo>,
    pub callers: HashMap<String, HashSet<String>>,
    pub ambiguous_calls: HashSet<String>,
    pub test_fns: usize,
    pub mock_calls: usize,
    pub public_symbols: Option<usize>,
}

pub struct FileOptions<'a> {
    pub package_roots: &'a HashSet<String>,
    pub is_stub_file: bool,
    pub is_test_file: bool,
    pub cell: Option<usize>,
    pub config: &'a Config,
}

type LocalScope = (
    bool,
    HashMap<String, String>,
    HashSet<String>,
    HashSet<String>,
);

pub fn check_file(
    path: &Path,
    source: &str,
    options: &FileOptions<'_>,
) -> Result<FileResult, String> {
    let package_dirs = options.package_roots;
    let is_stub_file = options.is_stub_file;
    let is_test_file = options.is_test_file;
    let cell = options.cell;
    let config = options.config;
    let banned = &config.banned_words;
    let parsed = if cell.is_some() {
        parse(source, ParseOptions::from(PySourceType::Ipynb)).map(|parsed| {
            parsed
                .try_into_module()
                .expect("IPython mode produces a module")
        })
    } else {
        parse_module(source)
    }
    .map_err(|error| match cell {
        Some(cell) => format!("parse error in {} cell {cell}: {error}", path.display()),
        None => format!("parse error in {}: {error}", path.display()),
    })?;
    let locator = SourceLocator::new(source);
    let imports = import_map(&parsed.syntax().body, path);
    let module_functions = unshadowed_functions(&parsed.syntax().body);
    let postponed_annotations = parsed.syntax().body.iter().any(|statement| {
        matches!(statement, Stmt::ImportFrom(import) if import.module.as_ref().is_some_and(|module| module.as_str() == "__future__") && import.names.iter().any(|alias| alias.name.as_str() == "annotations"))
    });

    let module = parsed.syntax();
    let mut checker = Checker {
        path,
        package_dirs,
        banned,
        locator: &locator,
        imports: &imports,
        module_functions: &module_functions,
        postponed_annotations,
        cell,
        is_stub_file,
        is_test_file,
        config,
        findings: Vec::new(),
        func_sigs: Vec::new(),
        classes: Vec::new(),
        callers: HashMap::new(),
        ambiguous_calls: HashSet::new(),
        test_fns: 0,
        mock_calls: 0,
        enclosing_params: HashSet::new(),
        in_interface: false,
        scope: Vec::new(),
        local_scopes: Vec::new(),
        direct_callee: false,
        reported_identifiers: HashSet::new(),
    };
    if has_star_import(&module.body) {
        checker.ambiguous_calls.insert("*".to_string());
    }

    for stmt in &module.body {
        if let Stmt::FunctionDef(func) = stmt {
            checker.func_sigs.push(FuncSig {
                name: func.name.as_str().to_string(),
                qualified_name: format!("{}.{}", module_name(path), func.name.as_str()),
                normalized_body: normalized_body(parsed.tokens(), &func.body),
                body_len: statement_count(&func.body),
                is_forwarder: module_functions.contains(func.name.as_str())
                    && func.decorator_list.is_empty()
                    && is_forwarder(func),
                line: locator.location(func.range.start().to_usize()).0,
                cell,
            });
        }
    }

    checker.check_doc_prose(&module.body);
    for statement in &module.body {
        checker.visit_stmt(statement);
    }

    let in_docs_path = in_docs(path);
    let license_header = is_license_header(source);
    let mut previous_divider = None;
    for token in parsed.tokens().iter() {
        if token.kind() != TokenKind::Comment {
            continue;
        }
        let range = token.range();
        let text = &source[range.start().to_usize()..range.end().to_usize()];
        let body = text.strip_prefix('#').unwrap_or(text).trim();
        let line = locator.location(range.start().to_usize()).0;

        if !in_docs_path {
            let lower = body.to_ascii_lowercase();
            let changelog = ["used to be", "formerly", "renamed", "originally"]
                .iter()
                .any(|phrase| lower.contains(phrase));
            let divider = has_divider_run(body);
            let report_divider = divider
                && !(license_header && line <= 25)
                && previous_divider.is_none_or(|previous| line > previous + 2);
            if divider {
                previous_divider = Some(line);
            }

            if changelog || report_divider {
                let what = if changelog {
                    "changelog comment"
                } else {
                    "decorative divider comment"
                };
                checker.flag(Rule::CommentNoise, range, what);
            }
        }

        checker.scan_prose(body, line);
    }

    let directives = noqa::directives(source, parsed.tokens(), &locator);
    checker.findings.retain(|finding| {
        finding.span.is_none_or(|span| {
            directives
                .get(&span.line)
                .is_none_or(|directive| !directive.suppresses(finding.rule))
        })
    });

    Ok(FileResult {
        findings: checker.findings,
        func_sigs: checker.func_sigs,
        classes: checker.classes,
        callers: checker.callers,
        ambiguous_calls: checker.ambiguous_calls,
        test_fns: checker.test_fns,
        mock_calls: checker.mock_calls,
        public_symbols: module_public_symbols(&module.body),
    })
}

struct Checker<'a> {
    path: &'a Path,
    package_dirs: &'a HashSet<String>,
    banned: &'a [String],
    locator: &'a SourceLocator<'a>,
    imports: &'a HashMap<String, String>,
    module_functions: &'a HashSet<String>,
    postponed_annotations: bool,
    cell: Option<usize>,
    is_stub_file: bool,
    is_test_file: bool,
    config: &'a Config,
    findings: Vec<Finding>,
    func_sigs: Vec<FuncSig>,
    classes: Vec<ClassInfo>,
    callers: HashMap<String, HashSet<String>>,
    ambiguous_calls: HashSet<String>,
    test_fns: usize,
    mock_calls: usize,
    enclosing_params: HashSet<String>,
    in_interface: bool,
    scope: Vec<String>,
    local_scopes: Vec<LocalScope>,
    direct_callee: bool,
    reported_identifiers: HashSet<(usize, String)>,
}

impl<'a> Checker<'a> {
    fn flag(&mut self, rule: Rule, range: ruff_text_size::TextRange, what: &str) {
        self.findings.push(Finding::source(
            rule,
            path_string(self.path),
            self.locator
                .span(range.start().to_usize(), range.end().to_usize()),
            self.cell,
            what,
        ));
    }

    fn flag_line(&mut self, rule: Rule, line: usize, what: &str) {
        self.findings.push(Finding::source(
            rule,
            path_string(self.path),
            crate::finding::Span {
                line,
                column: 1,
                end_line: line,
                end_column: 1,
            },
            self.cell,
            what,
        ));
    }

    fn check_identifier(&mut self, name: &str, range: ruff_text_size::TextRange) {
        let tokens = tokenize(name);
        let word = self
            .banned
            .iter()
            .find(|word| {
                word.chars()
                    .all(|character| character.is_alphanumeric() || character == '_')
                    && tokens.iter().any(|token| token == *word)
            })
            .cloned();
        let start = range.start().to_usize();
        if let Some(word) = word {
            if self.reported_identifiers.insert((start, name.to_string())) {
                self.flag(
                    Rule::BannedWord,
                    range,
                    &format!("slop term \"{word}\" in name `{name}`"),
                );
            }
        }
    }

    fn check_fallback(&mut self, try_stmt: &StmtTry) {
        let try_subst = Subst::of(&try_stmt.body);

        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(handler) = handler;
            if body_always_raises(&handler.body) {
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
                self.flag(
                    Rule::GuardFallback,
                    handler.range,
                    "except falls back to an alternative instead of failing",
                );
            }
        }
    }

    fn check_silent_test(
        &mut self,
        test: &Expr,
        body: &[Stmt],
        enclosing_params: &HashSet<String>,
        range: ruff_text_size::TextRange,
    ) {
        let Some(name) = is_none_test(test) else {
            return;
        };
        let assigns_name = Subst::of(body).assigns.contains(&name);
        if assigns_name && !enclosing_params.contains(&name) {
            self.flag(
                Rule::GuardSilentDefault,
                range,
                &format!("`if {name} is None` defaults a value that should have been provided"),
            );
        }
    }

    fn check_god_function(&mut self, func: &StmtFunctionDef) {
        let statement_count = statement_count(&func.body);
        let depth = branch_depth(&func.body, 0);
        if statement_count > self.config.max_function_statements
            || depth > self.config.max_branch_depth
        {
            self.flag(
                Rule::GodFunction,
                func.range,
                &format!(
                    "function `{}` has {statement_count} statements and branch depth {depth} (limits {} and {})",
                    func.name.as_str(),
                    self.config.max_function_statements,
                    self.config.max_branch_depth
                ),
            );
        }
    }

    fn check_god_class(&mut self, class: &StmtClassDef) {
        let methods = class
            .body
            .iter()
            .filter(|statement| matches!(statement, Stmt::FunctionDef(_)))
            .count();
        if methods > self.config.max_class_methods {
            self.flag(
                Rule::GodClass,
                class.range,
                &format!(
                    "class `{}` defines {methods} methods (limit {})",
                    class.name.as_str(),
                    self.config.max_class_methods
                ),
            );
        }
    }

    fn check_stub(&mut self, func: &StmtFunctionDef, in_interface: bool) {
        if self.is_stub_file
            || in_interface
            || has_decorator(&func.decorator_list, self.imports, true)
        {
            return;
        }
        if is_stub_body(&func.body) {
            self.flag(
                Rule::Stub,
                func.range,
                &format!(
                    "`{}` is a placeholder body, not an implementation",
                    func.name.as_str()
                ),
            );
        }
    }

    fn check_doc_bloat(&mut self, func: &StmtFunctionDef) {
        let Some(doc) = func.body.first() else {
            return;
        };
        if !is_docstring(doc) {
            return;
        }
        let doc_lines = line_span(self.locator, doc.range());
        let code = &func.body[1..];
        let code_lines = match (code.first(), code.last()) {
            (Some(first), Some(last)) => {
                self.locator.location(last.range().end().to_usize()).0
                    - self.locator.location(first.range().start().to_usize()).0
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
            self.flag(Rule::DocBloat, doc.range(), &format!("{doc_lines}-line docstring over {code_lines} lines of code, no Parameters/Returns section"));
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
        let line = self.locator.location(stmt.range().start().to_usize()).0;
        self.scan_prose(text.value.to_str(), line);
    }

    fn scan_prose(&mut self, text: &str, line: usize) {
        let lower = text.to_ascii_lowercase();
        let banned = self.banned;
        for word in banned {
            if contains_word(&lower, word) {
                self.flag_line(Rule::BannedWord, line, &format!("slop term \"{word}\""));
            }
        }
        if has_emoji(text) {
            self.flag_line(Rule::BannedWord, line, "emoji in prose");
        }
    }

    fn check_test_function(&mut self, func: &StmtFunctionDef) {
        self.test_fns += 1;
        let subject = TestSubject::new(self.path, func.name.as_str());
        let mut scan = TestScan {
            asserts: Vec::new(),
            has_raises: false,
            has_strong_assert: false,
            sut_mocks: Vec::new(),
            mock_calls: 0,
            package_dirs: self.package_dirs,
            imports: self.imports.clone(),
            path: self.path,
            subject,
        };
        for decorator in &func.decorator_list {
            scan.visit_expr(&decorator.expression);
        }
        for stmt in &func.body {
            scan.visit_stmt(stmt);
        }

        self.mock_calls += scan.mock_calls;
        for (range, target) in &scan.sut_mocks {
            self.flag(
                Rule::TestMockSut,
                *range,
                &format!("test replaces first-party subject `{target}`"),
            );
        }

        if !scan.has_raises
            && !scan.has_strong_assert
            && (scan.asserts.is_empty() || scan.asserts.iter().all(|&test| is_weak_assert(test)))
        {
            let detail = if scan.asserts.is_empty() {
                "has no behavioral observation"
            } else {
                "asserts only metadata or None"
            };
            self.flag(
                Rule::TestWeak,
                func.range,
                &format!("test `{}` {detail}", func.name.as_str()),
            );
        }
    }

    fn check_comprehension(
        &mut self,
        generators: &'a [Comprehension],
        value: impl FnOnce(&mut Self),
    ) {
        let Some((first, rest)) = generators.split_first() else {
            return value(self);
        };
        self.visit_expr(&first.iter);
        let mut bindings = HashSet::new();
        generators
            .iter()
            .for_each(|generator| collect_targets(&generator.target, &mut bindings, false));
        self.local_scopes
            .push((false, HashMap::new(), bindings, HashSet::new()));
        self.visit_expr(&first.target);
        first
            .ifs
            .iter()
            .for_each(|condition| self.visit_expr(condition));
        for generator in rest {
            self.visit_expr(&generator.iter);
            self.visit_expr(&generator.target);
            generator
                .ifs
                .iter()
                .for_each(|condition| self.visit_expr(condition));
        }
        value(self);
        self.local_scopes.pop();
    }

    fn mark_ambiguous(&mut self, callee: String) {
        self.ambiguous_calls.insert(callee);
    }

    fn mark_reference_ambiguous(&mut self, raw: &str) {
        let root = raw.split('.').next().unwrap_or(raw);
        let mut targets = Vec::new();
        for (index, scope) in self.local_scopes.iter().rev().enumerate() {
            if scope.0 && index > 0 {
                continue;
            }
            if let Some(imported) = scope.1.get(root) {
                targets.extend([imported.clone(), resolve_name(raw, &scope.1)]);
                break;
            }
            if scope.3.contains(root) {
                break;
            }
            if scope.2.contains(root) {
                if self.module_functions.contains(root) {
                    targets.push(format!("{}.{}", module_name(self.path), root));
                }
                targets
                    .into_iter()
                    .for_each(|target| self.mark_ambiguous(target));
                return;
            }
        }
        if let Some(imported) = self.imports.get(root) {
            targets.extend([imported.clone(), resolve_name(raw, self.imports)]);
        } else if self.module_functions.contains(root) {
            targets.push(format!("{}.{}", module_name(self.path), root));
        }
        targets
            .into_iter()
            .for_each(|target| self.mark_ambiguous(target));
    }
}

impl<'a> Visitor<'a> for Checker<'a> {
    fn visit_stmt(&mut self, statement: &'a Stmt) {
        match statement {
            Stmt::FunctionDef(function) => {
                self.check_identifier(function.name.as_str(), function.name.range);
                for parameter in all_params(&function.parameters) {
                    self.check_identifier(parameter.name.as_str(), parameter.name.range);
                }
                self.check_stub(function, self.in_interface);
                self.check_doc_bloat(function);
                self.check_god_function(function);
                self.check_doc_prose(&function.body);
                if self.is_test_file && is_test_name(function.name.as_str()) {
                    self.check_test_function(function);
                }
                function
                    .decorator_list
                    .iter()
                    .for_each(|decorator| self.visit_expr(&decorator.expression));
                if let Some(type_params) = &function.type_params {
                    self.visit_type_params(type_params);
                }
                self.visit_parameters(&function.parameters);
                if let Some(returns) = &function.returns {
                    self.visit_annotation(returns);
                }
                let outer = std::mem::replace(
                    &mut self.enclosing_params,
                    all_param_names(&function.parameters)
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                );
                let outer_interface = std::mem::take(&mut self.in_interface);
                self.scope.push(function.name.as_str().to_string());
                let (bindings, globals) = binding_names(&function.body, Some(&function.parameters));
                self.local_scopes.push((
                    false,
                    import_map(&function.body, self.path),
                    bindings,
                    globals,
                ));
                function
                    .body
                    .iter()
                    .for_each(|statement| self.visit_stmt(statement));
                self.local_scopes.pop();
                self.scope.pop();
                self.in_interface = outer_interface;
                self.enclosing_params = outer;
                return;
            }
            Stmt::ClassDef(class) => {
                self.check_identifier(class.name.as_str(), class.name.range);
                let info = class_info(
                    class,
                    self.path,
                    self.imports,
                    self.locator,
                    self.cell,
                    &self.scope,
                );
                class
                    .decorator_list
                    .iter()
                    .for_each(|decorator| self.visit_expr(&decorator.expression));
                if let Some(type_params) = &class.type_params {
                    self.visit_type_params(type_params);
                }
                if let Some(arguments) = &class.arguments {
                    self.visit_arguments(arguments);
                }
                let outer = std::mem::replace(&mut self.in_interface, info.is_protocol);
                self.scope.push(class.name.as_str().to_string());
                let (bindings, globals) = binding_names(&class.body, None);
                self.local_scopes.push((
                    true,
                    import_map(&class.body, self.path),
                    bindings,
                    globals,
                ));
                self.classes.push(info);
                self.check_god_class(class);
                self.check_doc_prose(&class.body);
                class
                    .body
                    .iter()
                    .for_each(|statement| self.visit_stmt(statement));
                self.local_scopes.pop();
                self.scope.pop();
                self.in_interface = outer;
                return;
            }
            Stmt::If(statement) => {
                let params = std::mem::take(&mut self.enclosing_params);
                self.check_silent_test(&statement.test, &statement.body, &params, statement.range);
                for clause in &statement.elif_else_clauses {
                    if let Some(test) = &clause.test {
                        self.check_silent_test(test, &clause.body, &params, clause.range);
                    }
                }
                self.enclosing_params = params;
            }
            Stmt::Try(statement) => self.check_fallback(statement),
            _ => {}
        }
        walk_stmt(self, statement);
    }

    fn visit_expr(&mut self, expression: &'a Expr) {
        match expression {
            Expr::Name(name) => {
                self.check_identifier(name.id.as_str(), name.range);
                if !self.direct_callee {
                    self.mark_reference_ambiguous(name.id.as_str());
                }
            }
            Expr::Attribute(attribute) => {
                self.check_identifier(attribute.attr.as_str(), attribute.range);
                if !self.direct_callee {
                    if let Some(raw) = qualified_callee(expression) {
                        self.mark_reference_ambiguous(&raw);
                    }
                }
            }
            Expr::Lambda(lambda) => {
                if let Some(parameters) = &lambda.parameters {
                    for parameter in all_params(parameters) {
                        self.check_identifier(parameter.name.as_str(), parameter.name.range);
                    }
                    self.visit_parameters(parameters);
                }
                self.local_scopes.push((
                    false,
                    HashMap::new(),
                    lambda_bindings(&lambda.body, lambda.parameters.as_deref()),
                    HashSet::new(),
                ));
                self.visit_expr(&lambda.body);
                self.local_scopes.pop();
                return;
            }
            Expr::ListComp(comp) => {
                self.check_comprehension(&comp.generators, |checker| checker.visit_expr(&comp.elt));
                return;
            }
            Expr::SetComp(comp) => {
                self.check_comprehension(&comp.generators, |checker| checker.visit_expr(&comp.elt));
                return;
            }
            Expr::DictComp(comp) => {
                self.check_comprehension(&comp.generators, |checker| {
                    if let Some(key) = &comp.key {
                        checker.visit_expr(key);
                    }
                    checker.visit_expr(&comp.value);
                });
                return;
            }
            Expr::Generator(comp) => {
                self.check_comprehension(&comp.generators, |checker| checker.visit_expr(&comp.elt));
                return;
            }
            Expr::Call(call) => {
                if let Some(raw) = qualified_callee(&call.func) {
                    let root = raw.split('.').next().unwrap_or(&raw);
                    let mut local = None;
                    let mut shadowed = false;
                    let mut ambiguous = Vec::new();
                    for (index, scope) in self.local_scopes.iter().rev().enumerate() {
                        if scope.0 && index > 0 {
                            continue;
                        }
                        if let Some(resolved) =
                            scope.1.get(root).map(|_| resolve_name(&raw, &scope.1))
                        {
                            if scope.2.contains(root) {
                                ambiguous.push(resolved);
                                if self.module_functions.contains(root) {
                                    ambiguous.push(format!("{}.{}", module_name(self.path), raw));
                                }
                            } else {
                                local = Some(resolved);
                            }
                            break;
                        }
                        if scope.3.contains(root) {
                            break;
                        }
                        if scope.2.contains(root) {
                            if self.module_functions.contains(root) {
                                ambiguous.push(format!("{}.{}", module_name(self.path), raw));
                            } else {
                                shadowed = true;
                            }
                            break;
                        }
                    }
                    for callee in ambiguous.iter().cloned() {
                        self.mark_ambiguous(callee);
                    }
                    if ambiguous.is_empty() && !shadowed {
                        let resolved = local.unwrap_or_else(|| {
                            if !raw.contains('.') && self.module_functions.contains(root) {
                                format!("{}.{}", module_name(self.path), raw)
                            } else {
                                resolve_name(&raw, self.imports)
                            }
                        });
                        let name = if resolved == raw && !raw.contains('.') {
                            format!("{}.{}", module_name(self.path), raw)
                        } else {
                            resolved
                        };
                        let caller = format!("{}.{}", module_name(self.path), self.scope.join("."))
                            .trim_end_matches('.')
                            .to_string();
                        self.callers.entry(name).or_default().insert(caller);
                    }
                }
                if let Some(name @ ("nan_to_num" | "fillna")) = callee_name(&call.func) {
                    self.flag(
                        Rule::GuardSilentDefault,
                        call.range,
                        &format!("`{name}` silently replaces NaN or missing values"),
                    );
                }
                self.direct_callee = matches!(call.func.as_ref(), Expr::Name(_));
                self.visit_expr(&call.func);
                self.direct_callee = false;
                call.arguments
                    .args
                    .iter()
                    .for_each(|argument| self.visit_expr(argument));
                call.arguments
                    .keywords
                    .iter()
                    .for_each(|keyword| self.visit_expr(&keyword.value));
                return;
            }
            _ => {}
        }
        walk_expr(self, expression);
    }

    fn visit_annotation(&mut self, expression: &'a Expr) {
        if !self.postponed_annotations {
            self.visit_expr(expression);
        }
    }
}

struct TestScan<'a> {
    asserts: Vec<&'a Expr>,
    has_raises: bool,
    has_strong_assert: bool,
    sut_mocks: Vec<(ruff_text_size::TextRange, String)>,
    mock_calls: usize,
    package_dirs: &'a HashSet<String>,
    imports: HashMap<String, String>,
    path: &'a Path,
    subject: TestSubject,
}

impl<'a> Visitor<'a> for TestScan<'a> {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        if matches!(stmt, Stmt::FunctionDef(_) | Stmt::ClassDef(_)) {
            return;
        }
        update_imports(stmt, self.path, &mut self.imports);
        if let Stmt::Assert(assert) = stmt {
            self.asserts.push(&assert.test);
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        if let Expr::Call(call) = expr {
            if let Some(path) = qualified_callee(&call.func) {
                let resolved = resolve_name(&path, &self.imports);
                if matches!(resolved.as_str(), "pytest.raises" | "pytest.warns") {
                    self.has_raises = true;
                }
                let metadata = call.arguments.args.iter().any(expr_is_metadata)
                    || call
                        .arguments
                        .keywords
                        .iter()
                        .any(|arg| expr_is_metadata(&arg.value));
                if is_strong_assert_call(&resolved, self.package_dirs) && !metadata {
                    self.has_strong_assert = true;
                }
                if is_mock_call(&resolved) {
                    self.mock_calls += 1;
                    if let Some(target) = mock_target(call, &resolved, &self.imports) {
                        let mut segments = target.split('.');
                        let root = segments.next().unwrap_or("");
                        let is_subject = self.subject.matches(&target);
                        if self.package_dirs.contains(root) && is_subject {
                            self.sut_mocks.push((call.range, target));
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
        for statement in body {
            subst.collect(statement);
        }
        subst
    }

    fn collect(&mut self, statement: &Stmt) {
        match statement {
            Stmt::FunctionDef(function) => {
                self.assigns.extend([function.name.as_str().to_string()])
            }
            Stmt::ClassDef(class) => self.assigns.extend([class.name.as_str().to_string()]),
            Stmt::Import(_) | Stmt::ImportFrom(_) => self.imports = true,
            Stmt::Return(_) => self.returns = true,
            Stmt::Assign(assign) => {
                for target in &assign.targets {
                    collect_targets(target, &mut self.assigns, true);
                }
            }
            Stmt::AnnAssign(assign) => collect_targets(&assign.target, &mut self.assigns, true),
            Stmt::AugAssign(assign) => collect_targets(&assign.target, &mut self.assigns, true),
            Stmt::If(statement) => {
                self.collect_body(&statement.body);
                for clause in &statement.elif_else_clauses {
                    self.collect_body(&clause.body);
                }
            }
            Stmt::For(statement) => {
                collect_targets(&statement.target, &mut self.assigns, true);
                self.collect_body(&statement.body);
                self.collect_body(&statement.orelse);
            }
            Stmt::While(statement) => {
                self.collect_body(&statement.body);
                self.collect_body(&statement.orelse);
            }
            Stmt::With(statement) => self.collect_body(&statement.body),
            Stmt::Try(statement) => {
                self.collect_body(&statement.body);
                for handler in &statement.handlers {
                    let ExceptHandler::ExceptHandler(handler) = handler;
                    self.collect_body(&handler.body);
                }
                self.collect_body(&statement.orelse);
                self.collect_body(&statement.finalbody);
            }
            Stmt::Match(statement) => {
                for case in &statement.cases {
                    self.collect_body(&case.body);
                }
            }
            _ => {}
        }
    }

    fn collect_body(&mut self, body: &[Stmt]) {
        for statement in body {
            self.collect(statement);
        }
    }
}

fn binding_names(
    body: &[Stmt],
    parameters: Option<&Parameters>,
) -> (HashSet<String>, HashSet<String>) {
    #[derive(Default)]
    struct Scan(HashSet<String>, HashSet<String>, HashSet<String>);
    impl<'a> Visitor<'a> for Scan {
        fn visit_stmt(&mut self, statement: &'a Stmt) {
            match statement {
                Stmt::FunctionDef(function) => {
                    self.0.insert(function.name.as_str().to_string());
                    function
                        .decorator_list
                        .iter()
                        .for_each(|decorator| self.visit_expr(&decorator.expression));
                    if let Some(type_params) = &function.type_params {
                        self.visit_type_params(type_params);
                    }
                    self.visit_parameters(&function.parameters);
                    if let Some(returns) = &function.returns {
                        self.visit_expr(returns);
                    }
                    return;
                }
                Stmt::ClassDef(class) => {
                    self.0.insert(class.name.as_str().to_string());
                    class
                        .decorator_list
                        .iter()
                        .for_each(|decorator| self.visit_expr(&decorator.expression));
                    if let Some(type_params) = &class.type_params {
                        self.visit_type_params(type_params);
                    }
                    if let Some(arguments) = &class.arguments {
                        self.visit_arguments(arguments);
                    }
                    return;
                }
                Stmt::Assign(assign) => assign
                    .targets
                    .iter()
                    .for_each(|target| collect_targets(target, &mut self.0, false)),
                Stmt::AnnAssign(assign) => collect_targets(&assign.target, &mut self.0, false),
                Stmt::AugAssign(assign) => collect_targets(&assign.target, &mut self.0, false),
                Stmt::For(statement) => collect_targets(&statement.target, &mut self.0, false),
                Stmt::Delete(statement) => statement
                    .targets
                    .iter()
                    .for_each(|target| collect_targets(target, &mut self.0, false)),
                Stmt::TypeAlias(statement) => collect_targets(&statement.name, &mut self.0, false),
                Stmt::Global(statement) => self
                    .1
                    .extend(statement.names.iter().map(|name| name.as_str().to_string())),
                Stmt::Nonlocal(statement) => self
                    .2
                    .extend(statement.names.iter().map(|name| name.as_str().to_string())),
                Stmt::Import(import) => import.names.iter().for_each(|alias| {
                    let name = alias
                        .asname
                        .as_ref()
                        .map(|name| name.as_str())
                        .unwrap_or_else(|| alias.name.as_str().split('.').next().unwrap());
                    self.0.insert(name.to_string());
                }),
                Stmt::ImportFrom(import) => import
                    .names
                    .iter()
                    .filter(|alias| alias.name.as_str() != "*")
                    .for_each(|alias| {
                        self.0.insert(
                            alias
                                .asname
                                .as_ref()
                                .map(|name| name.as_str())
                                .unwrap_or_else(|| alias.name.as_str())
                                .to_string(),
                        );
                    }),
                _ => {}
            }
            walk_stmt(self, statement);
        }
        fn visit_expr(&mut self, expression: &'a Expr) {
            match expression {
                Expr::Named(named) => collect_targets(&named.target, &mut self.0, false),
                Expr::Lambda(lambda) => {
                    if let Some(parameters) = &lambda.parameters {
                        self.visit_parameters(parameters);
                    }
                    return;
                }
                _ => {}
            }
            walk_expr(self, expression);
        }
        fn visit_except_handler(&mut self, handler: &'a ExceptHandler) {
            let ExceptHandler::ExceptHandler(node) = handler;
            self.0
                .extend(node.name.iter().map(|name| name.as_str().to_string()));
            walk_except_handler(self, handler);
        }
        fn visit_with_item(&mut self, item: &'a WithItem) {
            if let Some(target) = &item.optional_vars {
                collect_targets(target, &mut self.0, false);
            }
            walk_with_item(self, item);
        }
        fn visit_pattern(&mut self, pattern: &'a Pattern) {
            match pattern {
                Pattern::MatchMapping(node) => self
                    .0
                    .extend(node.rest.iter().map(|name| name.as_str().to_string())),
                Pattern::MatchStar(node) => self
                    .0
                    .extend(node.name.iter().map(|name| name.as_str().to_string())),
                Pattern::MatchAs(node) => self
                    .0
                    .extend(node.name.iter().map(|name| name.as_str().to_string())),
                _ => {}
            }
            walk_pattern(self, pattern);
        }
    }
    let mut scan = Scan::default();
    scan.0.extend(
        parameters
            .into_iter()
            .flat_map(all_param_names)
            .map(str::to_string),
    );
    body.iter().for_each(|statement| scan.visit_stmt(statement));
    scan.1.retain(|name| !scan.0.contains(name));
    scan.0.retain(|name| !scan.2.contains(name));
    (scan.0, scan.1)
}

fn lambda_bindings(body: &Expr, parameters: Option<&Parameters>) -> HashSet<String> {
    #[derive(Default)]
    struct Scan(HashSet<String>);
    impl<'a> Visitor<'a> for Scan {
        fn visit_expr(&mut self, expression: &'a Expr) {
            match expression {
                Expr::Named(named) => collect_targets(&named.target, &mut self.0, false),
                Expr::Lambda(_) => return,
                _ => {}
            }
            walk_expr(self, expression);
        }
    }
    let mut scan = Scan::default();
    scan.0.extend(
        parameters
            .into_iter()
            .flat_map(all_param_names)
            .map(str::to_string),
    );
    scan.visit_expr(body);
    scan.0
}

fn body_always_raises(body: &[Stmt]) -> bool {
    body.iter().any(statement_always_raises)
}

fn statement_always_raises(statement: &Stmt) -> bool {
    match statement {
        Stmt::Raise(_) => true,
        Stmt::If(statement) => {
            !statement.elif_else_clauses.is_empty()
                && statement
                    .elif_else_clauses
                    .last()
                    .is_some_and(|clause| clause.test.is_none())
                && body_always_raises(&statement.body)
                && statement
                    .elif_else_clauses
                    .iter()
                    .all(|clause| body_always_raises(&clause.body))
        }
        _ => false,
    }
}

fn collect_targets(expression: &Expr, names: &mut HashSet<String>, qualified: bool) {
    match expression {
        Expr::Name(name) => {
            names.insert(name.id.as_str().to_string());
        }
        Expr::Attribute(_) if qualified => names.extend(qualified_callee(expression)),
        Expr::Subscript(subscript) if qualified => collect_targets(&subscript.value, names, true),
        Expr::Tuple(tuple) => tuple
            .elts
            .iter()
            .for_each(|item| collect_targets(item, names, qualified)),
        Expr::List(list) => list
            .elts
            .iter()
            .for_each(|item| collect_targets(item, names, qualified)),
        Expr::Starred(starred) => collect_targets(&starred.value, names, qualified),
        _ => (),
    }
}

fn all_param_names(params: &Parameters) -> Vec<&str> {
    all_params(params)
        .into_iter()
        .map(|parameter| parameter.name.as_str())
        .collect()
}

fn all_params(params: &Parameters) -> Vec<&Parameter> {
    let mut parameters: Vec<&Parameter> = params
        .posonlyargs
        .iter()
        .chain(&params.args)
        .chain(&params.kwonlyargs)
        .map(|parameter| &parameter.parameter)
        .collect();
    if let Some(vararg) = &params.vararg {
        parameters.push(vararg);
    }
    if let Some(kwarg) = &params.kwarg {
        parameters.push(kwarg);
    }
    parameters
}

fn is_none_test(test: &Expr) -> Option<String> {
    let Expr::Compare(cmp) = test else {
        return None;
    };
    if cmp.ops.len() != 1 || !matches!(cmp.ops[0], CmpOp::Is) || cmp.comparators.len() != 1 {
        return None;
    }
    if matches!(cmp.comparators[0], Expr::NoneLiteral(_)) {
        if let Expr::Name(name) = cmp.left.as_ref() {
            return Some(name.id.as_str().to_string());
        }
    } else if matches!(cmp.left.as_ref(), Expr::NoneLiteral(_)) {
        if let Expr::Name(name) = &cmp.comparators[0] {
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

fn qualified_callee(expression: &Expr) -> Option<String> {
    match expression {
        Expr::Name(name) => Some(name.id.as_str().to_string()),
        Expr::Attribute(attribute) => {
            let prefix = qualified_callee(&attribute.value)?;
            Some(format!("{prefix}.{}", attribute.attr.as_str()))
        }
        _ => None,
    }
}

fn import_map(body: &[Stmt], path: &Path) -> HashMap<String, String> {
    let mut imports = HashMap::new();
    for statement in body {
        update_imports(statement, path, &mut imports);
    }
    imports
}

fn unshadowed_functions(body: &[Stmt]) -> HashSet<String> {
    let mut functions = HashSet::new();
    let mut conflicts = HashSet::new();
    for statement in body {
        let (mut bindings, _) = binding_names(std::slice::from_ref(statement), None);
        if let Stmt::FunctionDef(function) = statement {
            if !functions.insert(function.name.as_str().to_string()) {
                conflicts.insert(function.name.as_str().to_string());
            }
            bindings.remove(function.name.as_str());
        }
        conflicts.extend(bindings);
    }
    functions.retain(|name| !conflicts.contains(name) && !has_star_import(body));
    functions
}

fn has_star_import(body: &[Stmt]) -> bool {
    #[derive(Default)]
    struct Scan(bool);
    impl<'a> Visitor<'a> for Scan {
        fn visit_stmt(&mut self, statement: &'a Stmt) {
            if matches!(statement, Stmt::FunctionDef(_) | Stmt::ClassDef(_)) {
                return;
            }
            self.0 |= matches!(statement, Stmt::ImportFrom(import) if import.names.iter().any(|alias| alias.name.as_str() == "*"));
            walk_stmt(self, statement);
        }
    }
    let mut scan = Scan::default();
    body.iter().for_each(|statement| scan.visit_stmt(statement));
    scan.0
}

fn update_imports(statement: &Stmt, path: &Path, imports: &mut HashMap<String, String>) {
    match statement {
        Stmt::Import(import) => {
            for alias in &import.names {
                let full = alias.name.as_str();
                if let Some(local) = &alias.asname {
                    imports.insert(local.as_str().to_string(), full.to_string());
                } else {
                    let root = full.split('.').next().unwrap_or(full);
                    imports.insert(root.to_string(), root.to_string());
                }
            }
        }
        Stmt::ImportFrom(import) => {
            let module = import
                .module
                .as_ref()
                .map(|name| name.as_str())
                .unwrap_or("");
            let module = if import.level > 0 {
                relative_module(path, import.level, module)
            } else {
                module.to_string()
            };
            for alias in &import.names {
                if alias.name.as_str() == "*" {
                    continue;
                }
                let local = alias
                    .asname
                    .as_ref()
                    .map(|name| name.as_str())
                    .unwrap_or_else(|| alias.name.as_str());
                let full = if module.is_empty() {
                    alias.name.as_str().to_string()
                } else {
                    format!("{module}.{}", alias.name.as_str())
                };
                imports.insert(local.to_string(), full);
            }
        }
        _ => {}
    }
}

fn resolve_name(path: &str, imports: &HashMap<String, String>) -> String {
    let mut parts = path.splitn(2, '.');
    let root = parts.next().unwrap_or(path);
    let Some(resolved) = imports.get(root) else {
        return path.to_string();
    };
    match parts.next() {
        Some(rest) => format!("{resolved}.{rest}"),
        None => resolved.clone(),
    }
}

fn is_mock_call(path: &str) -> bool {
    if let Some(method) = path
        .strip_prefix("unittest.mock.")
        .or_else(|| path.strip_prefix("mock."))
        .or_else(|| path.strip_prefix("mocker."))
    {
        return matches!(
            method,
            "AsyncMock"
                | "MagicMock"
                | "Mock"
                | "NonCallableMagicMock"
                | "NonCallableMock"
                | "PropertyMock"
                | "create_autospec"
                | "mock_open"
                | "patch"
                | "patch.dict"
                | "patch.multiple"
                | "patch.object"
                | "spy"
                | "stub"
                | "async_stub"
        );
    }
    matches!(
        path,
        "monkeypatch.setattr"
            | "monkeypatch.setitem"
            | "monkeypatch.delattr"
            | "monkeypatch.delitem"
            | "monkeypatch.setenv"
            | "monkeypatch.delenv"
    )
}

fn mock_target(call: &ExprCall, callee: &str, imports: &HashMap<String, String>) -> Option<String> {
    let first = call.arguments.args.first()?;
    let target = match first {
        Expr::StringLiteral(string) => string.value.to_str().to_string(),
        expression => qualified_callee(expression)?,
    };
    let mut resolved = resolve_name(&target, imports);
    if (callee.ends_with("setattr") || callee.ends_with("delattr"))
        && call.arguments.args.len() >= 2
    {
        if let Expr::StringLiteral(attribute) = &call.arguments.args[1] {
            resolved.push('.');
            resolved.push_str(attribute.value.to_str());
        }
    }
    Some(resolved)
}

struct TestSubject {
    module_suffix: Vec<String>,
    file_tokens: HashSet<String>,
    function_tokens: HashSet<String>,
}

impl TestSubject {
    fn new(path: &Path, function_name: &str) -> Self {
        let file = path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        let file_token_list: Vec<String> = tokenize(file)
            .into_iter()
            .filter(|token| !matches!(token.as_str(), "test" | "tests"))
            .collect();
        let file_tokens = file_token_list.iter().cloned().collect();
        let module_suffix = file_token_list;
        let function_tokens = tokenize(function_name)
            .into_iter()
            .filter(|token| !matches!(token.as_str(), "test" | "tests" | "when" | "should"))
            .collect();
        Self {
            module_suffix,
            file_tokens,
            function_tokens,
        }
    }

    fn matches(&self, target: &str) -> bool {
        let segments: Vec<&str> = target.split('.').collect();
        let Some(leaf) = segments.last() else {
            return false;
        };
        let leaf_tokens: HashSet<String> = tokenize(leaf).into_iter().collect();
        let full_tokens: Vec<String> = segments
            .iter()
            .flat_map(|segment| tokenize(segment))
            .collect();
        let parent_tokens: Vec<String> = segments[..segments.len() - 1]
            .iter()
            .flat_map(|segment| tokenize(segment))
            .collect();
        let module_matches = full_tokens.ends_with(&self.module_suffix)
            || parent_tokens.ends_with(&self.module_suffix);
        let leaf_matches_function = leaf_tokens
            .iter()
            .any(|token| self.function_tokens.contains(token));
        let leaf_matches_file = !self.file_tokens.is_empty()
            && self
                .file_tokens
                .iter()
                .all(|token| leaf_tokens.contains(token));
        module_matches && (leaf_matches_function || leaf_matches_file)
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
            against_none
                || expr_is_metadata(&cmp.left)
                || cmp.comparators.iter().any(expr_is_metadata)
        }
        _ => false,
    }
}

fn is_strong_assert_call(name: &str, package_roots: &HashSet<String>) -> bool {
    let leaf = name.rsplit('.').next().unwrap_or(name);
    let weak = matches!(
        leaf.to_ascii_lowercase().as_str(),
        "assertisinstance"
            | "assertnotisinstance"
            | "assertisnone"
            | "assertisnotnone"
            | "assert_type"
    );
    if weak || !leaf.to_ascii_lowercase().starts_with("assert") {
        return false;
    }
    let root = name.split('.').next().unwrap_or(name);
    let assertion_module = name
        .split('.')
        .any(|part| matches!(part, "asserts" | "testing" | "test_utils"));
    name.starts_with("self.assert")
        || name.contains(".testing.assert")
        || name.starts_with("chex.assert")
        || (package_roots.contains(root) && assertion_module)
        || !name.contains('.')
}

fn expr_is_metadata(expr: &Expr) -> bool {
    match expr {
        Expr::Attribute(attr) => {
            matches!(
                attr.attr.as_str(),
                "device" | "dtype" | "ndim" | "shape" | "size"
            ) || expr_is_metadata(&attr.value)
        }
        Expr::Subscript(subscript) => expr_is_metadata(&subscript.value),
        Expr::Call(call) => matches!(callee_name(&call.func), Some("len" | "size" | "dim")),
        _ => false,
    }
}

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

fn has_decorator(
    decorators: &[Decorator],
    imports: &HashMap<String, String>,
    overload: bool,
) -> bool {
    decorators.iter().any(|d| {
        let name = qualified_callee(&d.expression).map(|name| resolve_name(&name, imports));
        let leaf = name.as_deref().and_then(|name| name.rsplit('.').next());
        matches!(
            leaf,
            Some(
                "abstractmethod"
                    | "abstractproperty"
                    | "abstractclassmethod"
                    | "abstractstaticmethod"
            )
        ) || (overload && leaf == Some("overload"))
    })
}

fn class_info(
    class: &StmtClassDef,
    path: &Path,
    imports: &HashMap<String, String>,
    locator: &SourceLocator,
    cell: Option<usize>,
    scope: &[String],
) -> ClassInfo {
    let mut bases = Vec::new();
    let mut protocol_base = false;
    let module = module_name(path);
    let prefix = if scope.is_empty() {
        module
    } else {
        format!("{module}.{}", scope.join("."))
    };

    if let Some(arguments) = &class.arguments {
        for base in arguments.args.iter() {
            if let Some(raw_name) = base_name(base) {
                let mut name = resolve_name(&raw_name, imports);
                if !name.contains('.') && !matches!(name.as_str(), "ABC" | "Protocol") {
                    name = format!("{prefix}.{name}");
                }
                let leaf = name.rsplit('.').next().unwrap_or(&name);
                if leaf == "Protocol" {
                    protocol_base = true;
                }
                bases.push(name);
            }
        }
    }

    let mut abstract_methods = Vec::new();
    let mut concrete_methods = Vec::new();
    for statement in &class.body {
        let Stmt::FunctionDef(function) = statement else {
            continue;
        };
        if has_decorator(&function.decorator_list, imports, false)
            || (protocol_base && is_stub_body(&function.body))
        {
            abstract_methods.push(function.name.as_str().to_string());
        } else {
            concrete_methods.push(function.name.as_str().to_string());
        }
    }
    ClassInfo {
        name: class.name.as_str().to_string(),
        qualified_name: format!("{prefix}.{}", class.name.as_str()),
        bases,
        is_abstract: protocol_base || !abstract_methods.is_empty(),
        is_protocol: protocol_base,
        abstract_methods,
        concrete_methods,
        line: locator.location(class.range.start().to_usize()).0,
        cell,
    }
}

fn base_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(_) | Expr::Attribute(_) => qualified_callee(expr),
        Expr::Subscript(sub) => base_name(&sub.value),
        _ => None,
    }
}

fn module_name(path: &Path) -> String {
    let mut parts: Vec<String> = path
        .components()
        .filter_map(|component| component.as_os_str().to_str().map(str::to_string))
        .collect();
    let container = ["src", "python", "lib"]
        .into_iter()
        .find_map(|name| parts.iter().position(|part| part == name));
    if let Some(container) = container {
        parts.drain(..=container);
    }
    if let Some(last) = parts.last_mut() {
        *last = Path::new(last)
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or(last)
            .to_string();
    }
    if parts.last().is_some_and(|part| part == "__init__") {
        parts.pop();
    }
    if parts.is_empty() {
        "__root__".to_string()
    } else {
        parts.join(".")
    }
}

fn relative_module(path: &Path, level: u32, imported: &str) -> String {
    let module = module_name(path);
    let is_package = path.file_stem().and_then(|value| value.to_str()) == Some("__init__");
    let mut parts: Vec<&str> = module.split('.').collect();
    if !is_package {
        parts.pop();
    }
    for _ in 1..level {
        parts.pop();
    }
    if !imported.is_empty() {
        parts.push(imported);
    }
    parts.join(".")
}

fn module_public_symbols(body: &[Stmt]) -> Option<usize> {
    let mut symbols = HashSet::new();
    let mut explicit = None;
    let mut unknown_exports = false;
    for statement in body {
        match statement {
            Stmt::FunctionDef(function) if !function.name.as_str().starts_with('_') => {
                symbols.insert(function.name.as_str().to_string());
            }
            Stmt::ClassDef(class) if !class.name.as_str().starts_with('_') => {
                symbols.insert(class.name.as_str().to_string());
            }
            Stmt::Assign(assignment) => {
                if assignment.targets.iter().any(is_dunder_all) {
                    explicit = Some(static_string_set(&assignment.value)?);
                    continue;
                }
                for target in &assignment.targets {
                    let mut names = HashSet::new();
                    collect_targets(target, &mut names, false);
                    symbols.extend(names.into_iter().filter(|name| !name.starts_with('_')));
                }
            }
            Stmt::AnnAssign(assignment) => {
                if is_dunder_all(&assignment.target) {
                    explicit = Some(static_string_set(assignment.value.as_deref()?)?);
                    continue;
                }
                let mut names = HashSet::new();
                collect_targets(&assignment.target, &mut names, false);
                symbols.extend(names.into_iter().filter(|name| !name.starts_with('_')));
            }
            Stmt::AugAssign(assignment) if is_dunder_all(&assignment.target) => {
                let additions = static_string_set(&assignment.value)?;
                explicit.as_mut()?.extend(additions);
            }
            Stmt::Expr(statement) => {
                let Expr::Call(call) = statement.value.as_ref() else {
                    continue;
                };
                let Expr::Attribute(method) = call.func.as_ref() else {
                    continue;
                };
                if is_dunder_all(&method.value) {
                    return None;
                }
            }
            Stmt::Import(import) => {
                for alias in &import.names {
                    let local = alias.asname.as_ref().map_or_else(
                        || {
                            alias
                                .name
                                .as_str()
                                .split('.')
                                .next()
                                .unwrap_or(alias.name.as_str())
                        },
                        |name| name.as_str(),
                    );
                    if !local.starts_with('_') {
                        symbols.insert(local.to_string());
                    }
                }
            }
            Stmt::ImportFrom(import) => {
                if import
                    .module
                    .as_ref()
                    .is_some_and(|name| name == "__future__")
                {
                    continue;
                }
                for alias in &import.names {
                    if alias.name.as_str() == "*" {
                        unknown_exports = true;
                        continue;
                    }
                    let local = alias
                        .asname
                        .as_ref()
                        .map_or_else(|| alias.name.as_str(), |name| name.as_str());
                    if !local.starts_with('_') {
                        symbols.insert(local.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(explicit) = explicit {
        Some(explicit.len())
    } else if unknown_exports {
        None
    } else {
        Some(symbols.len())
    }
}

fn is_dunder_all(expression: &Expr) -> bool {
    matches!(expression, Expr::Name(name) if name.id.as_str() == "__all__")
}

fn static_string_set(expression: &Expr) -> Option<HashSet<String>> {
    let elements = match expression {
        Expr::List(list) => list.elts.as_slice(),
        Expr::Tuple(tuple) => tuple.elts.as_slice(),
        Expr::Set(set) => set.elts.as_slice(),
        _ => return None,
    };
    elements
        .iter()
        .map(|element| match element {
            Expr::StringLiteral(string) => Some(string.value.to_str().to_string()),
            _ => None,
        })
        .collect()
}

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

fn contains_word(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
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
        from = start + hay[start..].chars().next().unwrap().len_utf8();
    }
    false
}

fn normalized_body(tokens: &[Token], body: &[Stmt]) -> String {
    let (Some(first), Some(last)) = (body.first(), body.last()) else {
        return String::new();
    };
    let start = first.range().start().to_usize();
    let end = last.range().end().to_usize();
    let mut normalized = String::new();
    let first = tokens.partition_point(|token| token.range().end().to_usize() <= start);
    let last = tokens.partition_point(|token| token.range().start().to_usize() < end);
    for token in &tokens[first..last] {
        if matches!(
            token.kind(),
            TokenKind::Comment
                | TokenKind::Newline
                | TokenKind::NonLogicalNewline
                | TokenKind::EndOfFile
        ) {
            continue;
        }
        normalized.push_str(&format!("{:?}", token.kind()));
        normalized.push(';');
    }
    normalized
}

fn statement_count(body: &[Stmt]) -> usize {
    struct Counter(usize);
    impl<'a> Visitor<'a> for Counter {
        fn visit_stmt(&mut self, statement: &'a Stmt) {
            self.0 += 1;
            if !matches!(statement, Stmt::FunctionDef(_) | Stmt::ClassDef(_)) {
                walk_stmt(self, statement);
            }
        }
    }
    let mut counter = Counter(0);
    for statement in body {
        counter.visit_stmt(statement);
    }
    counter.0
}

fn is_forwarder(function: &StmtFunctionDef) -> bool {
    let body = &function.body[function.body.first().is_some_and(is_docstring) as usize..];
    let [Stmt::Return(statement)] = body else {
        return false;
    };
    let Some(Expr::Call(call)) = statement.value.as_deref() else {
        return false;
    };
    let mut forwarded = Vec::new();
    let vararg = function.parameters.vararg.as_ref().map(|p| p.name.as_str());
    let kwarg = function.parameters.kwarg.as_ref().map(|p| p.name.as_str());
    for argument in &call.arguments.args {
        let (expression, starred) = match argument {
            Expr::Starred(starred) => (starred.value.as_ref(), true),
            expression => (expression, false),
        };
        let Expr::Name(name) = expression else {
            return false;
        };
        let name = name.id.as_str();
        if starred != (Some(name) == vararg) || Some(name) == kwarg {
            return false;
        }
        forwarded.push(name);
    }
    for keyword in &call.arguments.keywords {
        let Expr::Name(name) = &keyword.value else {
            return false;
        };
        let name = name.id.as_str();
        if keyword.arg.is_none() != (Some(name) == kwarg) || Some(name) == vararg {
            return false;
        }
        forwarded.push(name);
    }
    let mut parameters = all_param_names(&function.parameters);
    parameters.sort_unstable();
    forwarded.sort_unstable();
    forwarded == parameters
}

fn branch_depth(body: &[Stmt], depth: usize) -> usize {
    let mut maximum = depth;
    for statement in body {
        let nested = match statement {
            Stmt::If(statement) => {
                let mut value = branch_depth(&statement.body, depth + 1);
                for clause in &statement.elif_else_clauses {
                    value = value.max(branch_depth(&clause.body, depth + 1));
                }
                value
            }
            Stmt::For(statement) => branch_depth(&statement.body, depth + 1)
                .max(branch_depth(&statement.orelse, depth + 1)),
            Stmt::While(statement) => branch_depth(&statement.body, depth + 1)
                .max(branch_depth(&statement.orelse, depth + 1)),
            Stmt::With(statement) => branch_depth(&statement.body, depth),
            Stmt::Try(statement) => {
                let mut value = branch_depth(&statement.body, depth + 1)
                    .max(branch_depth(&statement.orelse, depth + 1))
                    .max(branch_depth(&statement.finalbody, depth + 1));
                for handler in &statement.handlers {
                    let ExceptHandler::ExceptHandler(handler) = handler;
                    value = value.max(branch_depth(&handler.body, depth + 1));
                }
                value
            }
            Stmt::Match(statement) => statement
                .cases
                .iter()
                .map(|case| branch_depth(&case.body, depth + 1))
                .max()
                .unwrap_or(depth),
            _ => depth,
        };
        maximum = maximum.max(nested);
    }
    maximum
}

fn is_test_name(name: &str) -> bool {
    name.starts_with("test_")
}

fn line_span(locator: &SourceLocator, range: ruff_text_size::TextRange) -> usize {
    locator.location(range.end().to_usize()).0 - locator.location(range.start().to_usize()).0 + 1
}

fn in_docs(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component.as_os_str().to_str(), Some("docs" | "doc")))
}

fn is_license_header(source: &str) -> bool {
    let header = source
        .lines()
        .take(25)
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    header.contains("copyright")
        && (header.contains("licensed under") || header.contains("all rights reserved"))
}

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
        analyze(source)
            .findings
            .into_iter()
            .map(|finding| finding.rule.name().to_string())
            .collect()
    }

    fn analyze(source: &str) -> FileResult {
        analyze_at("test_t.py", source, &["seamless", "feel free"], true)
    }

    fn analyze_at(path: &str, source: &str, banned: &[&str], is_test_file: bool) -> FileResult {
        let pkgs: HashSet<String> = ["mypkg"].into_iter().map(str::to_string).collect();
        let mut config = Config::default();
        config.banned_words = banned.iter().map(|word| (*word).to_string()).collect();
        check_file(
            Path::new(path),
            source,
            &FileOptions {
                package_roots: &pkgs,
                is_stub_file: false,
                is_test_file,
                cell: None,
                config: &config,
            },
        )
        .unwrap()
    }

    fn count(source: &str, rule: &str) -> usize {
        run(source).iter().filter(|r| *r == rule).count()
    }

    fn check_counts(rule: &str, cases: &[(&str, usize)]) {
        for &(source, expected) in cases {
            assert_eq!(count(source, rule), expected, "{source:?}");
        }
    }

    #[test]
    fn behavioral_rules() {
        check_counts(
            "guard-fallback",
            &[
                ("try:\n    import a as m\nexcept ImportError:\n    import b as m\n", 1),
                ("try:\n    x = fast()\nexcept Exception:\n    x = slow()\n", 1),
                ("try:\n    self.x = fast()\nexcept Exception:\n    self.x = slow()\n", 1),
                ("try:\n    cache[key] = fast()\nexcept Exception:\n    cache[key] = slow()\n", 1),
                ("try:\n    x = fast()\nexcept Exception:\n    raise\n", 0),
                ("try:\n    x = fast()\nexcept Exception:\n    def fail_later():\n        raise RuntimeError\n    x = slow()\n", 1),
            ],
        );
        check_counts(
            "guard-silent-default",
            &[
                ("def f():\n    if cfg is None:\n        cfg = default()\n", 1),
                ("def f(x=None):\n    if x is None:\n        x = []\n", 0),
                ("def f(x):\n    if x is None:\n        x = compute()\n", 0),
                ("def f(x):\n    return torch.nan_to_num(x)\n", 1),
                ("def f(x):\n    y = g(torch.nan_to_num(x))\n    return y\n", 1),
                ("def f():\n    if ready:\n        return value\n    elif cfg is None:\n        cfg = default()\n    return cfg\n", 1),
            ],
        );
        check_counts(
            "test-weak",
            &[
                ("def test_a():\n    assert isinstance(x, int)\n", 1),
                ("def test_b():\n    assert x.shape == (3,)\n", 1),
                ("def test_dtype():\n    assert x.dtype == dtype\n", 1),
                ("def test_ndim():\n    assert x.ndim == 2\n", 1),
                ("def test_axis():\n    assert x.shape[0] == 3\n", 1),
                ("def test_method():\n    self.assertEqual(x.shape, expected)\n", 1),
                ("def test_c():\n    assert x.shape == (3,)\n    assert y == 5\n", 0),
                ("def test_d():\n    assert x.shape == (3,)\n    np.testing.assert_allclose(x, y)\n", 0),
                ("def test_nothing():\n    x = compute()\n", 1),
                ("def test_fake():\n    helper.raises()\n", 1),
                ("from pytest import raises\ndef test_error():\n    with raises(ValueError):\n        fail()\n", 0),
                ("def test_local():\n    from pytest import raises\n    with raises(ValueError):\n        fail()\n", 0),
                ("def test_unused():\n    def helper():\n        assert result == expected\n    compute()\n", 1),
            ],
        );
        let result = analyze(
            "import unittest.mock\ndef test_patch(mocker):\n    from unittest.mock import PropertyMock\n    unittest.mock.Mock()\n    PropertyMock()\n    mocker.spy(target, 'method')\n    unittest.mock.patch.dict(values, {})\n    with unittest.mock.patch('other.value'):\n        assert value == 1\n",
        );
        assert_eq!(result.mock_calls, 5);
        check_counts(
            "test-mock-sut",
            &[
                (
                    "def test_t(monkeypatch):\n    monkeypatch.setattr('mypkg.mod.t', g)\n",
                    1,
                ),
                (
                    "def test_b(monkeypatch):\n    monkeypatch.setattr('requests.get', g)\n",
                    0,
                ),
            ],
        );
        let result = analyze_at(
            "tests/unit/test_model.py",
            "def test_load(monkeypatch):\n    monkeypatch.setattr('mypkg.model.load', fake)\n",
            &[],
            true,
        );
        assert_eq!(
            result
                .findings
                .iter()
                .filter(|f| f.rule == Rule::TestMockSut)
                .count(),
            1
        );
    }

    #[test]
    fn source_rules() {
        check_counts(
            "comment-noise",
            &[
                ("x = 1  # used to be 2\n", 1),
                ("# ===\nx = 1\n", 1),
                ("# explains why x is needed\nx = 1\n", 0),
            ],
        );
        let result = analyze_at("docs/examples/tour.py", "# ---\nx = 1\n", &[], false);
        assert!(result.findings.iter().all(|f| f.rule != Rule::CommentNoise));
        let source = "# Copyright 2026 Example. All Rights Reserved.\n#\n# Licensed under the Apache License, Version 2.0.\n# ================================================\nx = 1\n";
        assert_eq!(count(source, "comment-noise"), 0);
        check_counts(
            "stub",
            &[
                ("def f():\n    pass\n", 1),
                ("def f():\n    raise NotImplementedError('no cuda')\n", 0),
                ("@overload\ndef f(x): ...\n", 0),
                ("class P(Protocol):\n    def f(self): ...\n", 0),
                ("class C:\n    def f(self):\n        pass\n", 1),
            ],
        );
        check_counts(
            "banned-word",
            &[
                (
                    "def f():\n    \"\"\"A seamless helper.\"\"\"\n    return 1\n",
                    1,
                ),
                (
                    "def f():\n    \"\"\"Seamlessness aside.\"\"\"\n    return 1\n",
                    0,
                ),
                ("def seamless_helper(x):\n    return x\n", 1),
            ],
        );
        let n = run("def f():\n    \"\"\"Done \u{2705}\"\"\"\n    return 1\n")
            .iter()
            .filter(|r| *r == "banned-word")
            .count();
        assert_eq!(n, 1);
        let result = analyze_at(
            "docs/examples/tour.py",
            "\"\"\"A seamless tour.\"\"\"\n",
            &["seamless"],
            false,
        );
        assert!(result.findings.iter().any(|f| f.rule == Rule::BannedWord));
        let padded = "def f():\n    \"\"\"Line.\n    Line.\n    Line.\n    Line.\n    Line.\n    Line.\n    Line.\n    Line.\n    \"\"\"\n    return 1\n";
        assert_eq!(count(padded, "doc-bloat"), 1);
        let sectioned = "def f():\n    \"\"\"Line.\n    Line.\n    Line.\n    Line.\n    Returns:\n        int: one.\n    Line.\n    Line.\n    \"\"\"\n    return 1\n";
        assert_eq!(count(sectioned, "doc-bloat"), 0);
        assert!(contains_word("a seamless thing", "seamless"));
        assert!(!contains_word("seamlessness", "seamless"));
        assert!(!contains_word("a\u{e9}x", "\u{e9}"));
    }

    #[test]
    fn repository_analysis() {
        let (add, _) = sig_of("x = 1\ny = 2\nz = 3\nq = 4\nreturn x + y\n");
        let (multiply, _) = sig_of("x = 10\ny = 20\nz = 30\nq = 40\nreturn x * y\n");
        assert_ne!(add, multiply);
        let key = sig_of("a = 1\nb = 2\nc = 3\nd = 4\nreturn sink(key=a)\n");
        let option = sig_of("a = 1\nb = 2\nc = 3\nd = 4\nreturn sink(option=a)\n");
        assert_eq!(key, option);
        let renamed = sig_of("p = 1\nq = 2\nr = 3\ns = 4\nreturn sink(key=p)\n");
        assert_eq!(key, renamed);
        let outside = sig_of("if x:\n    a()\nb()\n");
        let inside = sig_of("if x:\n    a()\n    b()\n");
        assert_ne!(outside, inside);
        let result = analyze_at(
            "m.py",
            "def _forward(x, *args, **kwargs):\n    \"\"\"Forward.\"\"\"\n    return target(x, *args, **kwargs)\ndef run(x):\n    _forward(x)\n    _forward(x)\nclass C:\n    def method(self, x):\n        _forward(x)\ndef shadow(x):\n    from other import _forward\n    _forward(x)\ndef assign(x):\n    _forward = other\n    _forward(x)\ndef context(ctx, x):\n    with ctx as _forward:\n        _forward(x)\ndef handle(x):\n    try:\n        fail()\n    except Exception as _forward:\n        _forward(x)\ndef lambdas(other, x):\n    return (lambda _forward: _forward(x))(other)\ndef lambda_outer(other, x):\n    (lambda _forward: 0)(other)\n    return _forward(x)\ndef comp(xs, x):\n    return [_forward(x) for _forward in xs]\ndef comp_outer(xs, x):\n    [_forward for _forward in xs]\n    return _forward(x)\ndef first(xs, x):\n    return [_forward for _forward in _forward(xs)]\ndef defaults(x):\n    def inner(_forward=_forward(x)):\n        pass\ndef decorators(x):\n    @_forward(x)\n    def inner():\n        pass\ndef named(other, x):\n    (_forward := other)\n    return _forward(x)\ndef matched(other, x):\n    match other:\n        case _ as _forward:\n            return _forward(x)\ndef outer():\n    _forward = other\n    def inner(x):\n        global _forward\n        return _forward(x)\ndef header_default(x):\n    def inner(value=(_forward := other)):\n        pass\n    return _forward(x)\ndef lambda_default(x):\n    fn = lambda value=(_forward := other): value\n    return _forward(x)\ndef class_base(x):\n    class Inner((_forward := Base)):\n        pass\n    return _forward(x)\nclass Plain:\n    value = _forward(x)\nclass Before:\n    value = _forward(x)\n    _forward = other\nclass After:\n    _forward = other\n    value = _forward(x)\nclass ImportBefore:\n    value = _forward(x)\n    from other import _forward\nclass ImportAfter:\n    from other import _forward\n    value = _forward(x)\n",
            &[],
            false,
        );
        assert!(result.func_sigs[0].is_forwarder);
        assert_eq!(
            result.callers["m._forward"],
            HashSet::from([
                "m.run".to_string(),
                "m.C.method".to_string(),
                "m.lambda_outer".to_string(),
                "m.comp_outer".to_string(),
                "m.first".to_string(),
                "m.defaults".to_string(),
                "m.decorators".to_string(),
                "m.outer.inner".to_string(),
                "m.Plain".to_string(),
            ])
        );
        assert!(result.ambiguous_calls.contains("m._forward"));
        let nonlocal = analyze_at("b.py", "def outer():\n    from a import _forward\n    def inner(x):\n        nonlocal _forward\n        return _forward(x)\n", &[], false);
        assert!(nonlocal.ambiguous_calls.contains("a._forward"));
        let star = analyze_at("m.py", "def _forward(x):\n    return target(x)\nfrom other import *\ndef run(x):\n    return _forward(x)\n", &[], false);
        assert!(!star.func_sigs[0].is_forwarder);
        assert!(star.ambiguous_calls.contains("*"));
        let postponed = analyze_at("m.py", "from __future__ import annotations\ndef _forward(x):\n    return target(x)\ndef run(x: _forward(T)):\n    pass\n", &[], false);
        assert!(!postponed.callers.contains_key("m._forward"));
        let escaped = analyze_at("m.py", "def _forward(x):\n    return target(x)\nalias = _forward\ndef run(x):\n    return _forward(x)\n", &[], false);
        assert!(escaped.ambiguous_calls.contains("m._forward"));
        let imported = analyze_at(
            "b.py",
            "from a import _forward\nalias = _forward\ndef direct(x):\n    return _forward(x)\n",
            &[],
            false,
        );
        assert!(imported.ambiguous_calls.contains("a._forward"));
        let qualified = analyze_at(
            "b.py",
            "import a\nalias = a._forward\ndef direct(x):\n    return a._forward(x)\n",
            &[],
            false,
        );
        assert!(qualified.ambiguous_calls.contains("a._forward"));
        let decorated = analyze_at("m.py", "@atexit.register\ndef _forward(*args, **kwargs):\n    return target(*args, **kwargs)\ndef run():\n    _forward()\n", &[], false);
        assert!(!decorated.func_sigs[0].is_forwarder);
        let parsed = parse_module(
            "from pkg import first\nimport other as second\ninternal = 1\n__all__ = ['first']\n",
        )
        .unwrap();
        assert_eq!(module_public_symbols(&parsed.syntax().body), Some(1));

        let parsed = parse_module("from pkg import first\nimport other as second\n").unwrap();
        assert_eq!(module_public_symbols(&parsed.syntax().body), Some(2));

        let parsed = parse_module("from pkg import *\n").unwrap();
        assert_eq!(module_public_symbols(&parsed.syntax().body), None);
        let parsed = parse_module("from __future__ import annotations\n").unwrap();
        assert_eq!(module_public_symbols(&parsed.syntax().body), Some(0));
        let parsed = parse_module("def f():\n    with a():\n        with b():\n            with c():\n                return value\n").unwrap();
        let Stmt::FunctionDef(function) = &parsed.syntax().body[0] else {
            unreachable!()
        };
        assert_eq!(branch_depth(&function.body, 0), 0);
        let result = analyze("def seamless():\n    return 1\n");
        let finding = result
            .findings
            .iter()
            .find(|finding| finding.rule == Rule::BannedWord)
            .unwrap();
        let span = finding.span.unwrap();
        assert_eq!((span.line, span.column, span.end_line), (1, 5, 1));
    }

    fn sig_of(src: &str) -> (String, usize) {
        let body = src
            .lines()
            .map(|line| format!("    {line}\n"))
            .collect::<String>();
        let wrapped = format!("def f():\n{body}");
        let parsed = parse_module(&wrapped).unwrap();
        let Stmt::FunctionDef(function) = &parsed.syntax().body[0] else {
            unreachable!()
        };
        (
            normalized_body(parsed.tokens(), &function.body),
            statement_count(&function.body),
        )
    }

    #[test]
    fn class_info_detects_abstract() {
        let info = first_class("class P(Protocol):\n    def f(self): ...\n");
        assert!(info.is_abstract);
        let info = first_class("class C(ABC):\n    @abstractmethod\n    def f(self): ...\n");
        assert!(info.is_abstract);
        let info = first_class("class C(ABC):\n    pass\n");
        assert!(!info.is_abstract);
        let info = first_class("class D(Base):\n    x = 1\n");
        assert!(!info.is_abstract);
        assert_eq!(info.bases, vec!["t.Base".to_string()]);
        assert_eq!(
            module_name(Path::new("packages/core/src/pkg/a.py")),
            "pkg.a"
        );
        let result = analyze_at(
            "t.py",
            "class Left:\n    class Base: pass\nclass Right:\n    class Base: pass\n",
            &[],
            false,
        );
        assert_eq!(result.classes[1].qualified_name, "t.Left.Base");
        assert_eq!(result.classes[3].qualified_name, "t.Right.Base");
    }

    fn first_class(src: &str) -> ClassInfo {
        analyze_at("t.py", src, &[], false)
            .classes
            .into_iter()
            .next()
            .unwrap()
    }
}
