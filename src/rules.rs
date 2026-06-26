use crate::astrules::ClassInfo;
use crate::config::Config;
use crate::finding::Finding;
use crate::scan::Scan;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Apply every rule. A rule fires or it does not; there is no warn tier.
pub fn evaluate(scan: &Scan, cfg: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();

    let total_loc: usize = scan.files.iter().map(|f| f.loc).sum();
    if total_loc > cfg.repo_max_loc {
        findings.push(Finding {
            rule: "bloat-repo",
            file: ".".to_string(),
            line: None,
            message: format!("repo is {total_loc} lines (limit {})", cfg.repo_max_loc),
        });
    }

    for f in &scan.files {
        if f.loc > cfg.file_max_loc {
            findings.push(Finding {
                rule: "bloat-file",
                file: f.path.display().to_string(),
                line: None,
                message: format!("{} lines (limit {})", f.loc, cfg.file_max_loc),
            });
        }
    }

    let prod_loc: usize = scan
        .files
        .iter()
        .filter(|f| !f.is_test)
        .map(|f| f.loc)
        .sum();

    let mut names: HashSet<&str> = HashSet::new();
    for f in scan.files.iter().filter(|f| !f.is_test) {
        for sig in &f.func_sigs {
            if !sig.name.starts_with("test_") {
                names.insert(sig.name.as_str());
            }
        }
    }

    if prod_loc > 0 {
        let density = 1000.0 * names.len() as f64 / prod_loc as f64;
        if density > cfg.max_funcs_per_kloc {
            findings.push(Finding {
                rule: "bloat-density",
                file: ".".to_string(),
                line: None,
                message: format!(
                    "{density:.1} top-level functions per 1k production lines (limit {:.0})",
                    cfg.max_funcs_per_kloc
                ),
            });
        }
    }

    let mut stems: HashMap<String, Vec<u64>> = HashMap::new();
    for file in scan.files.iter().filter(|f| !f.is_test) {
        for sig in &file.func_sigs {
            if sig.name.starts_with("test_") {
                continue;
            }
            if let Some(stem) = name_stem(&sig.name) {
                stems.entry(stem).or_default().push(sig.body_sig);
            }
        }
    }
    let mut families: Vec<(&String, &Vec<u64>)> = stems
        .iter()
        .filter(|(_, sigs)| sigs.len() > cfg.max_name_family)
        .collect();
    families.sort_by(|a, b| a.0.cmp(b.0));
    for (stem, sigs) in families {
        let mut by_body: HashMap<u64, usize> = HashMap::new();
        for body_sig in sigs {
            *by_body.entry(*body_sig).or_insert(0) += 1;
        }
        let clones = by_body.values().copied().max().unwrap_or(0);
        findings.push(Finding {
            rule: "dup-family",
            file: ".".to_string(),
            line: None,
            message: format!(
                "{} functions share the name stem \"{stem}\" ({clones} with identical bodies, limit {})",
                sigs.len(),
                cfg.max_name_family
            ),
        });
    }

    findings.extend(abstraction_solo(scan));
    findings.extend(dup_body(scan, cfg));

    let test_fns: usize = scan
        .files
        .iter()
        .filter(|f| f.is_test)
        .map(|f| f.test_fns)
        .sum();
    let mock_hits: usize = scan
        .files
        .iter()
        .filter(|f| f.is_test)
        .map(|f| f.mock_hits)
        .sum();
    if test_fns > 0 {
        let ratio = mock_hits as f64 / test_fns as f64;
        if ratio > cfg.max_mocks_per_test {
            findings.push(Finding {
                rule: "test-mock",
                file: ".".to_string(),
                line: None,
                message: format!(
                    "{ratio:.2} mock/patch calls per test ({mock_hits} mocks / {test_fns} tests, limit {:.2})",
                    cfg.max_mocks_per_test
                ),
            });
        }
    }

    let test_loc: usize = scan.files.iter().filter(|f| f.is_test).map(|f| f.loc).sum();
    if prod_loc > cfg.test_absent_min_prod_loc {
        let ratio = test_loc as f64 / prod_loc as f64;
        if ratio < cfg.min_test_ratio {
            findings.push(Finding {
                rule: "test-absent",
                file: ".".to_string(),
                line: None,
                message: format!(
                    "tests are {:.0}% of production lines (floor {:.0}%)",
                    ratio * 100.0,
                    cfg.min_test_ratio * 100.0
                ),
            });
        }
    }

    for file in &scan.files {
        findings.extend(file.ast_findings.iter().cloned());
    }

    // Deterministic output, regardless of walk order or hashmap iteration order.
    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.rule.cmp(b.rule))
    });
    findings
}

/// The two-word stem of a function name: `_require_cache_owner_sha256` -> "owner sha256".
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

/// Split a function name into lowercase word-tokens on underscores and camelCase boundaries.
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

/// An abstract base (Protocol, ABC, or a class carrying an `@abstractmethod`) whose only
/// concrete implementation in the repo is a single class. Zero in-repo implementations is
/// a public extension point and is left alone; two or more justify the abstraction.
fn abstraction_solo(scan: &Scan) -> Vec<Finding> {
    let classes: Vec<(&Path, &ClassInfo)> = scan
        .files
        .iter()
        .filter(|f| !f.is_test)
        .flat_map(|f| f.classes.iter().map(|c| (f.path.as_path(), c)))
        .collect();

    let mut concrete_impls: HashMap<&str, usize> = HashMap::new();
    for (_, class) in &classes {
        if class.is_abstract {
            continue;
        }
        for base in &class.bases {
            *concrete_impls.entry(base.as_str()).or_insert(0) += 1;
        }
    }

    let mut findings = Vec::new();
    for (path, class) in &classes {
        if !class.is_abstract {
            continue;
        }
        if concrete_impls.get(class.name.as_str()).copied() == Some(1) {
            findings.push(Finding {
                rule: "abstraction-solo",
                file: path.display().to_string(),
                line: Some(class.line),
                message: format!(
                    "abstract base `{}` has a single concrete implementation",
                    class.name
                ),
            });
        }
    }
    findings
}

/// More than `max_body_clones` distinct top-level functions sharing one identical body
/// (same control flow and same calls) is copy-paste. Trivial bodies are excluded by a
/// statement-count floor; methods are excluded entirely, since near-identical bodies
/// across classes are normal.
fn dup_body(scan: &Scan, cfg: &Config) -> Vec<Finding> {
    const MIN_BODY_LEN: usize = 5;

    let mut by_sig: HashMap<u64, Vec<&str>> = HashMap::new();
    for file in scan.files.iter().filter(|f| !f.is_test) {
        for sig in &file.func_sigs {
            if sig.name.starts_with("test_") || sig.body_len < MIN_BODY_LEN {
                continue;
            }
            by_sig.entry(sig.body_sig).or_default().push(&sig.name);
        }
    }

    let mut groups: Vec<Vec<&str>> = by_sig
        .into_values()
        .map(|mut names| {
            names.sort_unstable();
            names.dedup();
            names
        })
        .filter(|names| names.len() > cfg.max_body_clones)
        .collect();
    groups.sort();

    let mut findings = Vec::new();
    for names in groups {
        let shown = names.iter().take(3).copied().collect::<Vec<_>>().join(", ");
        findings.push(Finding {
            rule: "dup-body",
            file: ".".to_string(),
            line: None,
            message: format!(
                "{} functions share one identical body ({shown}), limit {}",
                names.len(),
                cfg.max_body_clones
            ),
        });
    }
    findings
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
        }
    }

    fn class(name: &str, bases: &[&str], is_abstract: bool) -> ClassInfo {
        ClassInfo {
            name: name.to_string(),
            bases: bases.iter().map(|s| s.to_string()).collect(),
            is_abstract,
            is_protocol: false,
            line: 1,
        }
    }

    fn sig(name: &str, body_sig: u64, body_len: usize) -> crate::astrules::FuncSig {
        crate::astrules::FuncSig {
            name: name.to_string(),
            body_sig,
            body_len,
        }
    }

    #[test]
    fn tokenize_underscores_and_camel() {
        assert_eq!(
            tokenize("_require_explicit_cache_owner_sha256"),
            vec!["require", "explicit", "cache", "owner", "sha256"]
        );
        assert_eq!(
            tokenize("TargetSwapInputPlan"),
            vec!["target", "swap", "input", "plan"]
        );
    }

    #[test]
    fn name_stem_uses_last_two_tokens() {
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
    fn repo_size_flags_in_isolation() {
        // 14 prod files of 2000 lines = 28k prod (over the 26k repo limit), each under the
        // 3k file limit, with a test file big enough to clear test-absent. Only REPO trips.
        let mut files: Vec<FileMetrics> = (0..14)
            .map(|i| file(&format!("m{i}.py"), 2000, false, 0, 0))
            .collect();
        files.push(file("tests/test_all.py", 2000, true, 20, 0));

        let findings = evaluate(&Scan { files }, &Config::default());
        let rules: Vec<&str> = findings.iter().map(|f| f.rule).collect();
        assert_eq!(
            rules,
            vec!["bloat-repo"],
            "expected only repo-size, got {rules:?}"
        );
        assert!(findings[0].message.contains("30000"));
    }

    #[test]
    fn huge_untested_single_file_trips_repo_file_and_absent() {
        let scan = Scan {
            files: vec![file("a.py", 30_000, false, 0, 0)],
        };
        let findings = evaluate(&scan, &Config::default());
        let mut rules: Vec<&str> = findings.iter().map(|f| f.rule).collect();
        rules.sort_unstable();
        assert_eq!(rules, vec!["bloat-file", "bloat-repo", "test-absent"]);
    }

    #[test]
    fn small_repo_has_no_findings() {
        let scan = Scan {
            files: vec![
                file("m.py", 500, false, 0, 0),
                file("tests/test_m.py", 200, true, 10, 0),
            ],
        };
        let findings = evaluate(&scan, &Config::default());
        let rules: Vec<&str> = findings.iter().map(|f| f.rule).collect();
        assert!(rules.is_empty(), "unexpected findings: {rules:?}");
    }

    #[test]
    fn density_uses_production_only_and_distinct_names() {
        // 30 distinct prod functions over 1000 prod lines = 30/kLoC, over the 22 limit.
        let mut m = file("m.py", 1000, false, 0, 0);
        m.func_sigs = (0..30)
            .map(|i| sig(&format!("fn_{i}"), i as u64, 1))
            .collect();
        let findings = evaluate(&Scan { files: vec![m] }, &Config::default());
        assert!(findings.iter().any(|f| f.rule == "bloat-density"));
    }

    #[test]
    fn abstraction_solo_fires_on_single_impl_only() {
        // one abstract base, one concrete subclass: premature
        let mut solo = file("m.py", 100, false, 0, 0);
        solo.classes = vec![class("Base", &[], true), class("Only", &["Base"], false)];
        assert!(abstraction_solo(&Scan { files: vec![solo] })
            .iter()
            .any(|f| f.rule == "abstraction-solo"));

        // two concrete subclasses: justified abstraction, no finding
        let mut pair = file("m.py", 100, false, 0, 0);
        pair.classes = vec![
            class("Base", &[], true),
            class("A", &["Base"], false),
            class("B", &["Base"], false),
        ];
        assert!(abstraction_solo(&Scan { files: vec![pair] }).is_empty());

        // zero in-repo implementations: public extension point, no finding
        let mut iface = file("m.py", 100, false, 0, 0);
        iface.classes = vec![class("Base", &[], true)];
        assert!(abstraction_solo(&Scan { files: vec![iface] }).is_empty());
    }

    #[test]
    fn dup_body_fires_above_clone_limit_with_distinct_names() {
        let cfg = Config::default(); // max_body_clones = 2
        let mut f = file("m.py", 100, false, 0, 0);
        // three distinct names, identical non-trivial body signature 42
        f.func_sigs = vec![sig("load", 42, 6), sig("read", 42, 6), sig("fetch", 42, 6)];
        assert!(dup_body(&Scan { files: vec![f] }, &cfg)
            .iter()
            .any(|fd| fd.rule == "dup-body"));

        // two is at the limit, not over it
        let mut g = file("m.py", 100, false, 0, 0);
        g.func_sigs = vec![sig("load", 42, 6), sig("read", 42, 6)];
        assert!(dup_body(&Scan { files: vec![g] }, &cfg).is_empty());

        // trivial bodies (below the statement floor) never count
        let mut h = file("m.py", 100, false, 0, 0);
        h.func_sigs = vec![sig("a", 42, 1), sig("b", 42, 1), sig("c", 42, 1)];
        assert!(dup_body(&Scan { files: vec![h] }, &cfg).is_empty());
    }
}
