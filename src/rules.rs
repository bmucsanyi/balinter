use crate::astrules::ClassInfo;
use crate::config::Config;
use crate::finding::{path_string, Finding, Rule, Span};
use crate::scan::Scan;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// A rate per thousand lines is measured once there are a thousand lines.
/// Below that, one function moves the rate by more than the limit allows.
const DENSITY_MIN_LOC: usize = 1000;

pub fn evaluate(scan: &Scan, cfg: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    let (mut total_loc, mut prod_loc, mut test_loc) = (0, 0, 0);
    let (mut function_count, mut test_fns, mut mock_hits) = (0, 0, 0);
    let mut stems: HashMap<String, Vec<&str>> = HashMap::new();
    for file in &scan.files {
        total_loc += file.loc;
        let path = path_string(&file.path);
        if cfg.rule_enabled(Rule::BloatFile, &path) && file.loc > cfg.file_max_loc {
            findings.push(Finding::file(
                Rule::BloatFile,
                path.clone(),
                format!("{} lines (limit {})", file.loc, cfg.file_max_loc),
            ));
        }
        if file.is_test {
            test_loc += file.loc;
            test_fns += file.test_fns;
            mock_hits += file.mock_hits;
            continue;
        }
        prod_loc += file.loc;
        for signature in &file.func_sigs {
            if signature.name.starts_with("test_") {
                continue;
            }
            function_count += 1;
            if let Some(stem) = name_stem(&signature.name) {
                stems
                    .entry(stem)
                    .or_default()
                    .push(&signature.normalized_body);
            }
        }
        if cfg.rule_enabled(Rule::ModuleApi, &path) {
            if let Some(count) = file
                .public_symbols
                .filter(|count| *count > cfg.max_public_symbols_per_module)
            {
                findings.push(Finding::file(
                    Rule::ModuleApi,
                    path,
                    format!(
                        "module exposes {count} public symbols (limit {})",
                        cfg.max_public_symbols_per_module
                    ),
                ));
            }
        }
    }

    if cfg.rule_enabled(Rule::BloatRepo, ".") && total_loc > cfg.repo_max_loc {
        findings.push(Finding::project(
            Rule::BloatRepo,
            format!("repo is {total_loc} lines (limit {})", cfg.repo_max_loc),
        ));
    }
    if cfg.rule_enabled(Rule::BloatDensity, ".") && prod_loc >= DENSITY_MIN_LOC {
        let density = 1000.0 * function_count as f64 / prod_loc as f64;
        if density > cfg.max_funcs_per_kloc {
            findings.push(Finding::project(
                Rule::BloatDensity,
                format!(
                    "{density:.1} top-level functions per 1k production lines (limit {:.0})",
                    cfg.max_funcs_per_kloc
                ),
            ));
        }
    }

    let mut families: Vec<_> = stems
        .iter()
        .filter(|(_, sigs)| sigs.len() > cfg.max_name_family)
        .collect();
    families.sort_by(|a, b| a.0.cmp(b.0));
    if cfg.rule_enabled(Rule::DupFamily, ".") {
        for (stem, sigs) in families {
            let mut by_body: HashMap<&str, usize> = HashMap::new();
            for body in sigs {
                *by_body.entry(body).or_insert(0) += 1;
            }
            let clones = by_body.values().copied().max().unwrap_or(0);
            findings.push(Finding::project(Rule::DupFamily, format!("{} functions share the name stem \"{stem}\" ({clones} with identical bodies, limit {})", sigs.len(), cfg.max_name_family)));
        }
    }

    if cfg.rule_enabled(Rule::AbstractionSolo, ".") {
        findings.extend(abstraction_solo(scan, cfg));
    }
    if cfg.rule_enabled(Rule::DupBody, ".") {
        findings.extend(dup_body(scan, cfg));
    }
    if cfg.rule_enabled(Rule::WrapperChain, ".") {
        findings.extend(wrapper_chains(scan, cfg));
    }
    if cfg.rule_enabled(Rule::TestMock, ".") && test_fns > 0 {
        let ratio = mock_hits as f64 / test_fns as f64;
        if ratio > cfg.max_mocks_per_test {
            findings.push(Finding::project(Rule::TestMock, format!("{ratio:.2} mock/patch calls per test ({mock_hits} mocks / {test_fns} tests, limit {:.2})", cfg.max_mocks_per_test)));
        }
    }

    if cfg.rule_enabled(Rule::TestAbsent, ".") && prod_loc > cfg.test_absent_min_prod_loc {
        let ratio = test_loc as f64 / prod_loc as f64;
        if ratio < cfg.min_test_ratio {
            findings.push(Finding::project(
                Rule::TestAbsent,
                format!(
                    "tests are {:.0}% of production lines (floor {:.0}%)",
                    ratio * 100.0,
                    cfg.min_test_ratio * 100.0
                ),
            ));
        }
    }

    for file in &scan.files {
        findings.extend(file.ast_findings.iter().cloned());
    }

    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.cell.cmp(&b.cell))
            .then(
                a.span
                    .map(|span| (span.line, span.column))
                    .cmp(&b.span.map(|span| (span.line, span.column))),
            )
            .then(a.rule.cmp(&b.rule))
    });
    findings
}

fn name_stem(name: &str) -> Option<String> {
    let tokens = tokenize(name);
    if tokens.len() >= 2 {
        Some(format!(
            "{} {}",
            tokens[tokens.len() - 2],
            tokens[tokens.len() - 1]
        ))
    } else {
        None
    }
}

pub(crate) fn tokenize(name: &str) -> Vec<String> {
    let mut spaced = String::new();
    let mut prev: Option<char> = None;

    for c in name.chars() {
        if c.is_ascii_uppercase() {
            if let Some(p) = prev {
                if p.is_ascii_lowercase() || p.is_ascii_digit() {
                    spaced.push(' ');
                }
            }
        }

        spaced.push(c);
        prev = Some(c);
    }

    spaced
        .to_ascii_lowercase()
        .split(|c: char| c == '_' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn abstraction_solo(scan: &Scan, cfg: &Config) -> Vec<Finding> {
    let classes: Vec<(&Path, &ClassInfo)> = scan
        .files
        .iter()
        .filter(|f| !f.is_test)
        .flat_map(|f| f.classes.iter().map(|c| (f.path.as_path(), c)))
        .collect();

    let mut name_counts = HashMap::new();
    for (_, class) in &classes {
        *name_counts
            .entry(class.qualified_name.as_str())
            .or_insert(0) += 1;
    }
    let by_name: HashMap<&str, &ClassInfo> = classes
        .iter()
        .filter(|(_, class)| name_counts[class.qualified_name.as_str()] == 1)
        .map(|(_, class)| (class.qualified_name.as_str(), *class))
        .collect();
    let mut concrete_impls: HashMap<&str, usize> = HashMap::new();
    let mut requirement_cache: HashMap<&str, HashSet<String>> = HashMap::new();
    for (_, class) in &classes {
        let unresolved = unresolved_abstract_methods(
            class,
            &by_name,
            &mut requirement_cache,
            &mut HashSet::new(),
        );
        if class.is_abstract || !unresolved.is_empty() {
            continue;
        }
        let mut ancestors = HashSet::new();
        collect_ancestors(class, &by_name, &mut ancestors);
        for ancestor in ancestors {
            *concrete_impls.entry(ancestor).or_insert(0) += 1;
        }
    }

    let mut findings = Vec::new();
    for (path, class) in &classes {
        if !class.is_abstract {
            continue;
        }
        let path = path_string(path);
        if cfg.rule_enabled(Rule::AbstractionSolo, &path)
            && concrete_impls.get(class.qualified_name.as_str()).copied() == Some(1)
        {
            findings.push(Finding::source(
                Rule::AbstractionSolo,
                path,
                line_span(class.line),
                class.cell,
                format!(
                    "abstract base `{}` has a single concrete implementation",
                    class.name
                ),
            ));
        }
    }
    findings
}

fn unresolved_abstract_methods<'a>(
    class: &'a ClassInfo,
    classes: &HashMap<&'a str, &'a ClassInfo>,
    cache: &mut HashMap<&'a str, HashSet<String>>,
    visiting: &mut HashSet<&'a str>,
) -> HashSet<String> {
    if let Some(methods) = cache.get(class.qualified_name.as_str()) {
        return methods.clone();
    }
    if !visiting.insert(class.qualified_name.as_str()) {
        return HashSet::new();
    }
    let mut methods: HashSet<String> = class.abstract_methods.iter().cloned().collect();
    for base in &class.bases {
        if let Some(parent) = classes.get(base.as_str()) {
            methods.extend(unresolved_abstract_methods(
                parent, classes, cache, visiting,
            ));
        }
    }
    for method in &class.concrete_methods {
        methods.remove(method);
    }
    visiting.remove(class.qualified_name.as_str());
    cache.insert(class.qualified_name.as_str(), methods.clone());
    methods
}

fn collect_ancestors<'a>(
    class: &'a ClassInfo,
    classes: &HashMap<&'a str, &'a ClassInfo>,
    ancestors: &mut HashSet<&'a str>,
) {
    for base in &class.bases {
        let base = base.as_str();
        if let Some(parent) = classes.get(base) {
            if ancestors.insert(base) {
                collect_ancestors(parent, classes, ancestors);
            }
        }
    }
}

fn dup_body(scan: &Scan, cfg: &Config) -> Vec<Finding> {
    const MIN_BODY_LEN: usize = 5;

    type FunctionLocation<'a> = (&'a Path, &'a str, usize, Option<usize>);
    let mut bodies: HashMap<&str, Vec<FunctionLocation>> = HashMap::new();
    for file in scan.files.iter().filter(|f| !f.is_test) {
        if !cfg.rule_enabled(Rule::DupBody, &path_string(&file.path)) {
            continue;
        }
        for sig in &file.func_sigs {
            if sig.name.starts_with("test_") || sig.body_len < MIN_BODY_LEN {
                continue;
            }
            bodies
                .entry(sig.normalized_body.as_str())
                .or_default()
                .push((&file.path, &sig.name, sig.line, sig.cell));
        }
    }

    let mut groups: Vec<Vec<FunctionLocation>> = bodies
        .into_values()
        .filter(|functions| functions.len() > cfg.max_body_clones)
        .collect();
    groups.sort();

    let mut findings = Vec::new();
    for functions in groups {
        let shown = functions
            .iter()
            .take(3)
            .map(|(_, name, _, _)| *name)
            .collect::<Vec<_>>()
            .join(", ");
        let first = &functions[0];
        findings.push(Finding::source(
            Rule::DupBody,
            path_string(first.0),
            line_span(first.2),
            first.3,
            format!(
                "{} functions share one identical body ({shown}), limit {}",
                functions.len(),
                cfg.max_body_clones
            ),
        ));
    }
    findings
}

fn wrapper_chains(scan: &Scan, cfg: &Config) -> Vec<Finding> {
    let mut callers: HashMap<&str, HashSet<&str>> = HashMap::new();
    let mut ambiguous_calls = HashSet::new();
    for file in scan.files.iter().filter(|file| !file.is_test) {
        ambiguous_calls.extend(file.ambiguous_calls.iter().map(String::as_str));
        for (name, file_callers) in &file.callers {
            callers
                .entry(name)
                .or_default()
                .extend(file_callers.iter().map(String::as_str));
        }
    }
    let mut definitions = HashMap::new();
    for file in scan.files.iter().filter(|file| !file.is_test) {
        for function in &file.func_sigs {
            if function.name.starts_with('_') && !function.name.starts_with("__") {
                definitions
                    .entry(function.qualified_name.as_str())
                    .or_insert_with(Vec::new)
                    .push((file, function));
            }
        }
    }
    definitions
        .into_iter()
        .filter(|(name, definitions)| {
            !ambiguous_calls.contains("*")
                && !ambiguous_calls.contains(name)
                && definitions.len() == 1
                && definitions[0].1.is_forwarder
                && callers.get(name).is_some_and(|callers| callers.len() == 1)
        })
        .filter_map(|(_, definitions)| {
            let (file, function) = definitions[0];
            let path = path_string(&file.path);
            cfg.rule_enabled(Rule::WrapperChain, &path).then(|| {
                Finding::source(
                    Rule::WrapperChain,
                    path,
                    line_span(function.line),
                    function.cell,
                    format!("`{}` is a one-caller forwarding helper", function.name),
                )
            })
        })
        .collect()
}

fn line_span(line: usize) -> Span {
    Span {
        line,
        column: 1,
        end_line: line,
        end_column: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::FileMetrics;
    use std::path::PathBuf;

    fn file(
        path: &str,
        loc: usize,
        is_test: bool,
        test_fns: usize,
        mock_hits: usize,
    ) -> FileMetrics {
        FileMetrics {
            path: PathBuf::from(path),
            loc,
            is_test,
            test_fns,
            mock_hits,
            ast_findings: Vec::new(),
            func_sigs: Vec::new(),
            classes: Vec::new(),
            callers: HashMap::new(),
            ambiguous_calls: HashSet::new(),
            public_symbols: Some(0),
        }
    }

    fn class(name: &str, qualified_name: &str, bases: &[&str], is_abstract: bool) -> ClassInfo {
        ClassInfo {
            name: name.to_string(),
            qualified_name: qualified_name.to_string(),
            bases: bases.iter().map(|base| base.to_string()).collect(),
            is_abstract,
            is_protocol: false,
            abstract_methods: Vec::new(),
            concrete_methods: Vec::new(),
            line: 1,
            cell: None,
        }
    }

    fn sig(name: &str, body_sig: u64, body_len: usize) -> crate::astrules::FuncSig {
        crate::astrules::FuncSig {
            name: name.to_string(),
            qualified_name: format!("m.{name}"),
            normalized_body: format!("body-{body_sig}"),
            body_len,
            is_forwarder: false,
            line: 1,
            cell: None,
        }
    }

    fn rules(files: Vec<FileMetrics>) -> Vec<Rule> {
        let mut rules: Vec<_> = evaluate(&Scan { files }, &Config::default())
            .into_iter()
            .map(|finding| finding.rule)
            .collect();
        rules.sort_unstable();
        rules
    }

    #[test]
    fn name_tokenization_and_stems() {
        assert_eq!(
            tokenize("_require_explicit_cache_owner_sha256"),
            vec!["require", "explicit", "cache", "owner", "sha256"]
        );
        assert_eq!(
            tokenize("TargetSwapInputPlan"),
            vec!["target", "swap", "input", "plan"]
        );
        assert_eq!(
            name_stem("_require_explicit_cache_owner_sha256"),
            Some("owner sha256".to_string())
        );
        assert_eq!(
            name_stem("_cache_owner_sha256"),
            Some("owner sha256".to_string())
        );
        assert_eq!(name_stem("solve"), None);
    }

    #[test]
    fn aggregate_thresholds() {
        let mut files: Vec<FileMetrics> = (0..14)
            .map(|i| file(&format!("m{i}.py"), 2000, false, 0, 0))
            .collect();
        files.push(file("tests/test_all.py", 2000, true, 20, 0));
        assert_eq!(rules(files), vec![Rule::BloatRepo]);

        assert_eq!(
            rules(vec![file("a.py", 30_000, false, 0, 0)]),
            vec![Rule::BloatRepo, Rule::BloatFile, Rule::TestAbsent]
        );
        assert!(rules(vec![
            file("m.py", 500, false, 0, 0),
            file("tests/test_m.py", 200, true, 10, 0),
        ])
        .is_empty());

        let mut module = file("m.py", 1000, false, 0, 0);
        module.func_sigs = (0..30)
            .map(|i| sig(&format!("fn_{i}"), i as u64, 1))
            .collect();
        module.public_symbols = Some(41);
        assert_eq!(
            rules(vec![module]),
            vec![Rule::BloatDensity, Rule::ModuleApi]
        );

        let mut small = file("m.py", 999, false, 0, 0);
        small.func_sigs = (0..30)
            .map(|i| sig(&format!("fn_{i}"), i as u64, 1))
            .collect();
        assert!(!rules(vec![small]).contains(&Rule::BloatDensity));
    }

    #[test]
    fn abstraction_analysis() {
        let mut solo = file("m.py", 100, false, 0, 0);
        solo.classes = vec![
            class("Base", "m.Base", &[], true),
            class("Only", "m.Only", &["m.Base"], false),
        ];
        assert_eq!(
            abstraction_solo(&Scan { files: vec![solo] }, &Config::default()).len(),
            1
        );

        let mut pair = file("m.py", 100, false, 0, 0);
        pair.classes = vec![
            class("Base", "m.Base", &[], true),
            class("A", "m.A", &["m.Base"], false),
            class("B", "m.B", &["m.Base"], false),
        ];
        assert!(abstraction_solo(&Scan { files: vec![pair] }, &Config::default()).is_empty());

        let mut iface = file("m.py", 100, false, 0, 0);
        iface.classes = vec![class("Base", "m.Base", &[], true)];
        assert!(abstraction_solo(&Scan { files: vec![iface] }, &Config::default()).is_empty());
        let mut first = file("a.py", 100, false, 0, 0);
        first.classes = vec![
            class("Base", "a.Base", &[], true),
            class("Mid", "a.Mid", &["a.Base"], true),
            class("Leaf", "a.Leaf", &["a.Mid"], false),
        ];
        let mut second = file("b.py", 100, false, 0, 0);
        second.classes = vec![class("Base", "b.Base", &[], true)];
        let findings = abstraction_solo(
            &Scan {
                files: vec![first, second],
            },
            &Config::default(),
        );
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|finding| finding.file == "a.py"));
        let mut module = file("a.py", 100, false, 0, 0);
        let mut base = class("Base", "a.Base", &[], true);
        base.abstract_methods = vec!["run".to_string()];
        let mid = class("Mid", "a.Mid", &["a.Base"], false);
        let mut leaf = class("Leaf", "a.Leaf", &["a.Mid"], false);
        leaf.concrete_methods = vec!["run".to_string()];
        module.classes = vec![base, mid, leaf];
        let findings = abstraction_solo(
            &Scan {
                files: vec![module],
            },
            &Config::default(),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`Base`"));
        let mut module = file("analysis.ipynb", 20, false, 0, 0);
        module.classes = vec![
            class("Base", "m.Base", &[], true),
            class("Base", "m.Base", &[], true),
            class("Only", "m.Only", &["m.Base"], false),
        ];
        assert!(abstraction_solo(
            &Scan {
                files: vec![module]
            },
            &Config::default()
        )
        .is_empty());
    }

    #[test]
    fn dup_body_fires_above_clone_limit_with_distinct_names() {
        let cfg = Config::default(); // max_body_clones = 2
        let mut f = file("m.py", 100, false, 0, 0);
        f.func_sigs = vec![sig("load", 42, 6), sig("read", 42, 6), sig("fetch", 42, 6)];
        assert!(dup_body(&Scan { files: vec![f] }, &cfg)
            .iter()
            .any(|fd| fd.rule == Rule::DupBody));

        let mut g = file("m.py", 100, false, 0, 0);
        g.func_sigs = vec![sig("load", 42, 6), sig("read", 42, 6)];
        assert!(dup_body(&Scan { files: vec![g] }, &cfg).is_empty());

        let mut h = file("m.py", 100, false, 0, 0);
        h.func_sigs = vec![sig("a", 42, 1), sig("b", 42, 1), sig("c", 42, 1)];
        assert!(dup_body(&Scan { files: vec![h] }, &cfg).is_empty());
    }

    #[test]
    fn wrapper_chain_requires_exactly_one_caller() {
        let mut module = file("m.py", 100, false, 0, 0);
        module.func_sigs = vec![sig("_forward", 1, 1)];
        module.func_sigs[0].is_forwarder = true;
        module.callers.insert(
            "m._forward".to_string(),
            HashSet::from(["m.run".to_string()]),
        );
        assert!(rules(vec![module]).contains(&Rule::WrapperChain));

        let mut module = file("m.py", 100, false, 0, 0);
        module.func_sigs = vec![sig("_forward", 1, 1)];
        module.func_sigs[0].is_forwarder = true;
        module.callers.insert(
            "m._forward".to_string(),
            HashSet::from(["m.first".to_string(), "m.C.second".to_string()]),
        );
        assert!(!rules(vec![module]).contains(&Rule::WrapperChain));
    }
}
