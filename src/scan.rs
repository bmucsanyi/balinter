use crate::astrules::{self, FuncSig};
use crate::finding::{rule_code, Finding};
use crate::noqa;
use ignore::WalkBuilder;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct FileMetrics {
    pub path: PathBuf,
    pub loc: usize,
    pub is_test: bool,
    pub defs: Vec<String>,
    pub test_fns: usize,
    pub mock_hits: usize,
    pub ast_findings: Vec<Finding>,
    pub func_sigs: Vec<FuncSig>,
}

pub struct Scan {
    pub files: Vec<FileMetrics>,
}

/// Walk `root` (gitignore-aware), then measure and parse every Python file.
pub fn scan(root: &Path) -> Scan {
    let mut paths: Vec<(PathBuf, PathBuf)> = Vec::new();
    for result in WalkBuilder::new(root).build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!("balinter: walk error: {err}");
                continue;
            }
        };

        let is_py_file = entry.file_type().is_some_and(|t| t.is_file())
            && entry.path().extension().and_then(|e| e.to_str()) == Some("py");

        if is_py_file {
            let abs = entry.path().to_path_buf();
            let rel = entry
                .path()
                .strip_prefix(root)
                .unwrap_or(entry.path())
                .to_path_buf();
            paths.push((abs, rel));
        }
    }

    let package_dirs = package_dirs(&paths);

    let mut files = Vec::new();
    for (abs, rel) in &paths {
        match analyze_file(abs, rel, &package_dirs) {
            Ok(metrics) => files.push(metrics),
            Err(err) => eprintln!("balinter: skipped {}: {err}", rel.display()),
        }
    }

    Scan { files }
}

/// The repo's own directory names, so a first-party mock target can be told from an external one.
fn package_dirs(paths: &[(PathBuf, PathBuf)]) -> HashSet<String> {
    let mut dirs = HashSet::new();
    for (_, rel) in paths {
        if is_test_path(rel) {
            continue;
        }

        let mut components = rel.components();
        components.next_back();
        for component in components {
            if let Some(name) = component.as_os_str().to_str() {
                dirs.insert(name.to_string());
            }
        }
    }
    dirs
}

fn analyze_file(
    abs: &Path,
    rel: &Path,
    package_dirs: &HashSet<String>,
) -> std::io::Result<FileMetrics> {
    let bytes = std::fs::read(abs)?;
    let loc = bytes.iter().filter(|&&b| b == b'\n').count();
    let is_test = is_test_path(rel);

    let text = String::from_utf8_lossy(&bytes);
    let mut defs = Vec::new();
    let mut test_fns = 0;
    let mut mock_hits = 0;

    for line in text.lines() {
        if let Some(name) = top_level_def_name(line) {
            defs.push(name);
        }

        let trimmed = line.trim_start();
        if trimmed.starts_with("def test_") || trimmed.starts_with("async def test_") {
            test_fns += 1;
        }

        if line_has_mock(line) {
            mock_hits += 1;
        }
    }

    let result = astrules::check_file(rel, &text, package_dirs);
    let noqa = noqa::directives(&text);
    let ast_findings: Vec<Finding> = result
        .findings
        .into_iter()
        .filter(|f| match f.line {
            Some(line) => noqa
                .get(&line)
                .is_none_or(|directive| !directive.suppresses(f.rule, rule_code(f.rule))),
            None => true,
        })
        .collect();

    Ok(FileMetrics {
        path: rel.to_path_buf(),
        loc,
        is_test,
        defs,
        test_fns,
        mock_hits,
        ast_findings,
        func_sigs: result.func_sigs,
    })
}

/// Name of a function defined at module scope (column 0), or None.
fn top_level_def_name(line: &str) -> Option<String> {
    let rest = line
        .strip_prefix("def ")
        .or_else(|| line.strip_prefix("async def "))?;

    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn is_test_path(rel: &Path) -> bool {
    for component in rel.components() {
        if let Some(s) = component.as_os_str().to_str() {
            if s == "test" || s == "tests" {
                return true;
            }
        }
    }

    let fname = rel.file_name().and_then(|f| f.to_str()).unwrap_or("");

    fname.starts_with("test_")
        || fname.ends_with("_test.py")
        || fname == "test.py"
        || fname == "tests.py"
        || fname == "conftest.py"
}

fn line_has_mock(line: &str) -> bool {
    const PATTERNS: [&str; 9] = [
        "monkeypatch.setattr",
        "monkeypatch.setitem",
        "monkeypatch.delattr",
        "monkeypatch.setenv",
        "mock.patch",
        "MagicMock",
        "create_autospec",
        "unittest.mock",
        ".patch(",
    ];

    PATTERNS.iter().any(|p| line.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_def_detection() {
        assert_eq!(top_level_def_name("def foo(x):"), Some("foo".to_string()));
        assert_eq!(
            top_level_def_name("async def bar() -> int:"),
            Some("bar".to_string())
        );
        assert_eq!(top_level_def_name("    def method(self):"), None);
        assert_eq!(top_level_def_name("define_x = 1"), None);
        assert_eq!(top_level_def_name("class Foo:"), None);
    }

    #[test]
    fn test_path_classification() {
        assert!(is_test_path(Path::new("tests/test_core.py")));
        assert!(is_test_path(Path::new("pkg/test/helpers.py")));
        assert!(is_test_path(Path::new("conftest.py")));
        assert!(is_test_path(Path::new("foo_test.py")));
        assert!(!is_test_path(Path::new("src/model.py")));
        assert!(!is_test_path(Path::new("contest.py")));
    }

    #[test]
    fn mock_detection() {
        assert!(line_has_mock("    monkeypatch.setattr(mod, 'f', g)"));
        assert!(line_has_mock("m = MagicMock()"));
        assert!(!line_has_mock("y = compute(x)"));
    }

    #[test]
    fn package_dirs_from_non_test_files() {
        let paths = vec![
            (
                PathBuf::from("/a/pkg/core/x.py"),
                PathBuf::from("pkg/core/x.py"),
            ),
            (
                PathBuf::from("/a/tests/test_x.py"),
                PathBuf::from("tests/test_x.py"),
            ),
        ];
        let dirs = package_dirs(&paths);
        assert!(dirs.contains("pkg"));
        assert!(dirs.contains("core"));
        assert!(!dirs.contains("tests"));
    }
}
