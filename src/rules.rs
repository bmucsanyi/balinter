use crate::config::Config;
use crate::finding::Finding;
use crate::scan::Scan;
use std::collections::{HashMap, HashSet};

/// Apply every rule. A rule fires or it does not; there is no warn tier.
pub fn evaluate(scan: &Scan, cfg: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();

    let total_loc: usize = scan.files.iter().map(|f| f.loc).sum();
    if total_loc > cfg.repo_max_loc {
        findings.push(Finding {
            rule: "BLOAT-REPO",
            file: ".".to_string(),
            line: None,
            message: format!("repo is {total_loc} lines (limit {})", cfg.repo_max_loc),
        });
    }

    for f in &scan.files {
        if f.loc > cfg.file_max_loc {
            findings.push(Finding {
                rule: "BLOAT-FILE",
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
        for n in &f.defs {
            if !n.starts_with("test_") {
                names.insert(n.as_str());
            }
        }
    }

    if prod_loc > 0 {
        let density = 1000.0 * names.len() as f64 / prod_loc as f64;
        if density > cfg.max_funcs_per_kloc {
            findings.push(Finding {
                rule: "BLOAT-DENSITY",
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
    if let Some((stem, sigs)) = stems.iter().max_by_key(|(_, sigs)| sigs.len()) {
        let family_size = sigs.len();
        if family_size > cfg.max_name_family {
            let mut by_body: HashMap<u64, usize> = HashMap::new();
            for body_sig in sigs {
                *by_body.entry(*body_sig).or_insert(0) += 1;
            }
            let clones = by_body.values().copied().max().unwrap_or(0);
            findings.push(Finding {
                rule: "DUP-FAMILY",
                file: ".".to_string(),
                line: None,
                message: format!(
                    "{family_size} functions share the name stem \"{stem}\" ({clones} with identical bodies, limit {})",
                    cfg.max_name_family
                ),
            });
        }
    }

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
                rule: "TEST-MOCK",
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
                rule: "TEST-ABSENT",
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
fn tokenize(name: &str) -> Vec<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::FileMetrics;
    use std::path::PathBuf;

    fn file(
        path: &str,
        loc: usize,
        is_test: bool,
        defs: &[&str],
        test_fns: usize,
        mock_hits: usize,
    ) -> FileMetrics {
        FileMetrics {
            path: PathBuf::from(path),
            loc,
            is_test,
            defs: defs.iter().map(|s| s.to_string()).collect(),
            test_fns,
            mock_hits,
            ast_findings: Vec::new(),
            func_sigs: Vec::new(),
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
        // 3k file limit, with a test file big enough to clear TEST-ABSENT. Only REPO trips.
        let mut files: Vec<FileMetrics> = (0..14)
            .map(|i| file(&format!("m{i}.py"), 2000, false, &[], 0, 0))
            .collect();
        files.push(file("tests/test_all.py", 2000, true, &[], 20, 0));

        let findings = evaluate(&Scan { files }, &Config::default());
        let rules: Vec<&str> = findings.iter().map(|f| f.rule).collect();
        assert_eq!(
            rules,
            vec!["BLOAT-REPO"],
            "expected only repo-size, got {rules:?}"
        );
        assert!(findings[0].message.contains("30000"));
    }

    #[test]
    fn huge_untested_single_file_trips_repo_file_and_absent() {
        let scan = Scan {
            files: vec![file("a.py", 30_000, false, &[], 0, 0)],
        };
        let findings = evaluate(&scan, &Config::default());
        let mut rules: Vec<&str> = findings.iter().map(|f| f.rule).collect();
        rules.sort_unstable();
        assert_eq!(rules, vec!["BLOAT-FILE", "BLOAT-REPO", "TEST-ABSENT"]);
    }

    #[test]
    fn small_repo_has_no_findings() {
        let scan = Scan {
            files: vec![
                file("m.py", 500, false, &["run"], 0, 0),
                file("tests/test_m.py", 200, true, &[], 10, 0),
            ],
        };
        let findings = evaluate(&scan, &Config::default());
        let rules: Vec<&str> = findings.iter().map(|f| f.rule).collect();
        assert!(rules.is_empty(), "unexpected findings: {rules:?}");
    }

    #[test]
    fn density_uses_production_only_and_distinct_names() {
        // 30 distinct prod functions over 1000 prod lines = 30/kLoC, over the 22 limit.
        let defs: Vec<String> = (0..30).map(|i| format!("fn_{i}")).collect();
        let def_refs: Vec<&str> = defs.iter().map(|s| s.as_str()).collect();
        let scan = Scan {
            files: vec![file("m.py", 1000, false, &def_refs, 0, 0)],
        };
        let findings = evaluate(&scan, &Config::default());
        assert!(findings.iter().any(|f| f.rule == "BLOAT-DENSITY"));
    }
}
