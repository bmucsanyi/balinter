use crate::astrules::{self, ClassInfo, FuncSig};
use crate::config::Config;
use crate::finding::Finding;
use encoding_rs::{Encoding, UTF_8};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub struct FileMetrics {
    pub path: PathBuf,
    pub loc: usize,
    pub is_test: bool,
    pub test_fns: usize,
    pub mock_hits: usize,
    pub ast_findings: Vec<Finding>,
    pub func_sigs: Vec<FuncSig>,
    pub classes: Vec<ClassInfo>,
    pub callers: HashMap<String, HashSet<String>>,
    pub ambiguous_calls: HashSet<String>,
    pub public_symbols: Option<usize>,
}

pub struct Scan {
    pub files: Vec<FileMetrics>,
}

pub fn scan(root: &Path, requested: &[PathBuf], config: &Config) -> Result<Scan, String> {
    let exclude = build_exclude_set(&config.exclude)?;
    let targets = canonical_targets(requested)?;
    let inventory = inventory(root, &targets, &exclude)?;
    let package_roots = package_roots(&inventory);

    let results: Vec<Result<Vec<FileMetrics>, String>> = inventory
        .par_iter()
        .filter(|entry| entry.selected)
        .map(|entry| analyze_entry(entry, &package_roots, config))
        .collect();

    let mut files = Vec::new();
    let mut failures = Vec::new();
    for result in results {
        match result {
            Ok(mut metrics) => files.append(&mut metrics),
            Err(error) => failures.push(error),
        }
    }
    if !failures.is_empty() {
        failures.sort();
        return Err(failures.join("\n"));
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(Scan { files })
}

struct InventoryEntry {
    absolute: PathBuf,
    relative: PathBuf,
    selected: bool,
}

fn inventory(
    root: &Path,
    targets: &[Target],
    exclude: &GlobSet,
) -> Result<Vec<InventoryEntry>, String> {
    let prune = exclude.clone();
    let prune_root = root.to_path_buf();
    let mut builder = WalkBuilder::new(root);
    for target in targets.iter().filter(|target| target.directory) {
        if target.path != root {
            builder.add(&target.path);
        }
    }
    builder.filter_entry(move |entry| {
        let relative = entry
            .path()
            .strip_prefix(&prune_root)
            .unwrap_or(entry.path());
        relative.as_os_str().is_empty() || !prune.is_match(relative)
    });

    let mut entries = Vec::new();
    let mut failures = Vec::new();
    for result in builder.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                failures.push(format!("walk error: {error}"));
                continue;
            }
        };
        if !entry.file_type().is_some_and(|kind| kind.is_file()) || !is_supported(entry.path()) {
            continue;
        }
        let relative = entry.path().strip_prefix(root).map_err(|error| {
            format!(
                "could not make {} relative to {}: {error}",
                entry.path().display(),
                root.display()
            )
        })?;
        if exclude.is_match(relative) {
            continue;
        }
        entries.push(InventoryEntry {
            absolute: entry.path().to_path_buf(),
            relative: relative.to_path_buf(),
            selected: targets.iter().any(|target| target.contains(entry.path())),
        });
    }
    for target in targets {
        if target.directory {
            continue;
        }
        let absolute = &target.path;
        let relative = absolute.strip_prefix(root).map_err(|error| {
            format!(
                "could not make {} relative to {}: {error}",
                absolute.display(),
                root.display()
            )
        })?;
        if !exclude.is_match(relative) {
            entries.push(InventoryEntry {
                absolute: absolute.clone(),
                relative: relative.to_path_buf(),
                selected: true,
            });
        }
    }
    entries.sort_by(|left, right| left.absolute.cmp(&right.absolute));
    entries.dedup_by(|left, right| left.absolute == right.absolute);
    if failures.is_empty() {
        Ok(entries)
    } else {
        failures.sort();
        Err(failures.join("\n"))
    }
}

struct Target {
    path: PathBuf,
    directory: bool,
}

impl Target {
    fn contains(&self, path: &Path) -> bool {
        if self.directory {
            path.starts_with(&self.path)
        } else {
            path == self.path
        }
    }
}

fn canonical_targets(paths: &[PathBuf]) -> Result<Vec<Target>, String> {
    let mut paths = paths
        .iter()
        .map(|path| {
            std::fs::canonicalize(path)
                .map_err(|error| format!("could not access {}: {error}", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    paths.dedup();
    paths
        .into_iter()
        .map(|path| {
            let directory = path.is_dir();
            if directory || is_supported(&path) {
                Ok(Target { path, directory })
            } else {
                Err(format!("unsupported input file: {}", path.display()))
            }
        })
        .collect()
}

fn analyze_entry(
    entry: &InventoryEntry,
    package_roots: &HashSet<String>,
    config: &Config,
) -> Result<Vec<FileMetrics>, String> {
    if entry.absolute.extension().and_then(|value| value.to_str()) == Some("ipynb") {
        analyze_notebook(entry, package_roots, config)
    } else {
        let bytes = std::fs::read(&entry.absolute)
            .map_err(|error| format!("could not read {}: {error}", entry.relative.display()))?;
        let source = decode_python(&entry.relative, &bytes)?;
        let is_stub_file =
            entry.absolute.extension().and_then(|value| value.to_str()) == Some("pyi");
        analyze_python(
            entry.relative.clone(),
            &source,
            is_stub_file,
            None,
            package_roots,
            config,
        )
        .map(|metrics| vec![metrics])
    }
}

fn analyze_notebook(
    entry: &InventoryEntry,
    package_roots: &HashSet<String>,
    config: &Config,
) -> Result<Vec<FileMetrics>, String> {
    let text = std::fs::read_to_string(&entry.absolute)
        .map_err(|error| format!("could not read {}: {error}", entry.relative.display()))?;
    let notebook: Value = serde_json::from_str(&text)
        .map_err(|error| format!("invalid notebook {}: {error}", entry.relative.display()))?;
    let cells = notebook
        .get("cells")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("notebook {} has no cells array", entry.relative.display()))?;
    let mut combined = FileMetrics {
        path: entry.relative.clone(),
        loc: 0,
        is_test: is_test_path(&entry.relative),
        test_fns: 0,
        mock_hits: 0,
        ast_findings: Vec::new(),
        func_sigs: Vec::new(),
        classes: Vec::new(),
        callers: HashMap::new(),
        ambiguous_calls: HashSet::new(),
        public_symbols: None,
    };
    for (index, cell) in cells.iter().enumerate() {
        if cell.get("cell_type").and_then(Value::as_str) != Some("code") {
            continue;
        }
        let source = notebook_source(cell.get("source")).ok_or_else(|| {
            format!(
                "notebook {} cell {} has an invalid source",
                entry.relative.display(),
                index + 1
            )
        })?;
        if source.trim().is_empty() {
            continue;
        }
        if !is_python_notebook_cell(&source) {
            continue;
        }
        let result = analyze_python(
            entry.relative.clone(),
            &source,
            false,
            Some(index + 1),
            package_roots,
            config,
        )?;
        combined.loc += result.loc;
        combined.test_fns += result.test_fns;
        combined.mock_hits += result.mock_hits;
        combined.ast_findings.extend(result.ast_findings);
        combined.func_sigs.extend(result.func_sigs);
        combined.classes.extend(result.classes);
        for (name, callers) in result.callers {
            combined.callers.entry(name).or_default().extend(callers);
        }
        combined.ambiguous_calls.extend(result.ambiguous_calls);
    }
    Ok(vec![combined])
}

fn notebook_source(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(source) => Some(source.clone()),
        Value::Array(lines) => lines
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .map(|lines| lines.concat()),
        _ => None,
    }
}

fn is_python_notebook_cell(source: &str) -> bool {
    let cell_magic = source
        .lines()
        .find(|line| !line.trim().is_empty())
        .and_then(|line| line.trim_start().strip_prefix("%%"))
        .and_then(|line| line.split_whitespace().next());
    cell_magic.is_none_or(|name| {
        matches!(
            name,
            "capture"
                | "debug"
                | "prun"
                | "pypy"
                | "python"
                | "python2"
                | "python3"
                | "time"
                | "timeit"
        )
    })
}

fn decode_python<'a>(path: &Path, bytes: &'a [u8]) -> Result<Cow<'a, str>, String> {
    let had_bom = bytes.starts_with(&[0xEF, 0xBB, 0xBF]);
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let label = declared_encoding(bytes).unwrap_or_else(|| "utf-8".to_string());
    let normalized = label.replace('_', "-");
    if had_bom && !matches!(normalized.as_str(), "utf-8" | "utf8" | "utf-8-sig") {
        return Err(format!(
            "{} has a UTF-8 BOM but declares {label}",
            path.display()
        ));
    }
    let compact = normalized.replace('-', "");
    let latin1 = "8859 cp819 csisolatin1 ibm819 iso8859 iso88591 iso885911987 isoir100 isolatin1 l1 latin latin1".split_whitespace().any(|alias| alias == compact);
    let decoded = if latin1 {
        Cow::Owned(bytes.iter().map(|&byte| char::from(byte)).collect())
    } else {
        let encoding = if matches!(normalized.as_str(), "ascii" | "us-ascii" | "646") {
            if !bytes.is_ascii() {
                return Err(format!("{} contains non-ASCII source text", path.display()));
            }
            UTF_8
        } else if normalized == "utf-8-sig" {
            UTF_8
        } else {
            Encoding::for_label(normalized.as_bytes()).ok_or_else(|| {
                format!("{} declares unsupported encoding {label:?}", path.display())
            })?
        };
        let (decoded, _, malformed) = encoding.decode(bytes);
        if malformed {
            return Err(format!(
                "{} contains malformed {label} text",
                path.display()
            ));
        }
        decoded
    };
    Ok(decoded)
}

fn declared_encoding(bytes: &[u8]) -> Option<String> {
    let mut lines = bytes.split(|&byte| byte == b'\n');
    let first = String::from_utf8_lossy(lines.next()?);
    if let Some(encoding) = encoding_from_comment(&first) {
        return Some(encoding);
    }
    if !first.trim().is_empty() && !first.trim_start().starts_with('#') {
        return None;
    }
    encoding_from_comment(&String::from_utf8_lossy(lines.next()?))
}

fn encoding_from_comment(line: &str) -> Option<String> {
    if !line.trim_start().starts_with('#') {
        return None;
    }
    let lower = line.to_ascii_lowercase();
    let coding = lower.find("coding")?;
    let tail = lower.get(coding + "coding".len()..)?;
    let tail = tail
        .strip_prefix(':')
        .or_else(|| tail.strip_prefix('='))?
        .trim_start();
    let end = tail
        .find(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
        })
        .unwrap_or(tail.len());
    (end > 0).then(|| tail[..end].to_string())
}

fn analyze_python(
    path: PathBuf,
    source: &str,
    is_stub_file: bool,
    cell: Option<usize>,
    package_roots: &HashSet<String>,
    config: &Config,
) -> Result<FileMetrics, String> {
    let loc = physical_lines(source.as_bytes());
    let is_test = is_test_path(&path);
    let mut result = astrules::check_file(
        &path,
        source,
        &astrules::FileOptions {
            package_roots,
            is_stub_file,
            is_test_file: is_test,
            cell,
            config,
        },
    )?;
    result
        .findings
        .retain(|finding| config.rule_enabled(finding.rule, &finding.file));
    Ok(FileMetrics {
        path,
        loc,
        is_test,
        test_fns: result.test_fns,
        mock_hits: result.mock_calls,
        ast_findings: result.findings,
        func_sigs: result.func_sigs,
        classes: result.classes,
        callers: result.callers,
        ambiguous_calls: result.ambiguous_calls,
        public_symbols: result.public_symbols,
    })
}

fn physical_lines(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        0
    } else {
        bytes.iter().filter(|&&byte| byte == b'\n').count()
            + usize::from(bytes.last() != Some(&b'\n'))
    }
}

fn build_exclude_set(patterns: &[String]) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let has_meta = pattern.contains(['*', '?', '[', ']']);
        let globs = if has_meta {
            vec![pattern.clone()]
        } else if pattern.contains('/') {
            vec![pattern.clone(), format!("{pattern}/**")]
        } else {
            vec![format!("**/{pattern}"), format!("**/{pattern}/**")]
        };
        for value in globs {
            builder.add(
                Glob::new(&value)
                    .map_err(|error| format!("invalid exclude pattern {value:?}: {error}"))?,
            );
        }
    }
    builder
        .build()
        .map_err(|error| format!("could not build exclude set: {error}"))
}

fn package_roots(entries: &[InventoryEntry]) -> HashSet<String> {
    let mut roots = HashSet::new();
    for entry in entries {
        if is_test_path(&entry.relative)
            || entry.relative.extension().and_then(|value| value.to_str()) == Some("ipynb")
        {
            continue;
        }
        let parts: Vec<&str> = entry
            .relative
            .components()
            .filter_map(|component| component.as_os_str().to_str())
            .collect();
        let index = ["src", "python", "lib"]
            .into_iter()
            .find_map(|name| parts.iter().position(|part| *part == name).map(|i| i + 1))
            .unwrap_or(0);
        if let Some(root) = parts.get(index) {
            let root = if index + 1 == parts.len() {
                Path::new(root)
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or(root)
            } else {
                root
            };
            roots.insert(root.to_string());
        }
    }
    roots
}

fn is_supported(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("py" | "pyi" | "ipynb")
    )
}

fn is_test_path(relative: &Path) -> bool {
    if relative
        .components()
        .any(|component| matches!(component.as_os_str().to_str(), Some("test" | "tests")))
    {
        return true;
    }
    let name = relative
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    name.starts_with("test_")
        || name.ends_with("_test.py")
        || name.ends_with("_test.pyi")
        || name.ends_with("_test.ipynb")
        || matches!(name, "test.py" | "tests.py" | "conftest.py")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_helpers() {
        assert_eq!(physical_lines(b""), 0);
        assert_eq!(physical_lines(b"x"), 1);
        assert_eq!(physical_lines(b"x\n"), 1);
        assert_eq!(physical_lines(b"x\ny"), 2);
        assert!(is_test_path(Path::new("tests/test_core.py")));
        assert!(is_test_path(Path::new("pkg/foo_test.pyi")));
        assert!(is_test_path(Path::new("pkg/foo_test.ipynb")));
        assert!(is_test_path(Path::new("conftest.py")));
        assert!(!is_test_path(Path::new("src/model.py")));
        let matcher = build_exclude_set(&["tests/fixtures".to_string()]).unwrap();
        assert!(matcher.is_match("tests/fixtures/a.py"));
        assert!(!matcher.is_match("tests/test_a.py"));

        let plain = build_exclude_set(&["docs".to_string()]).unwrap();
        assert!(plain.is_match("docs/example.py"));
        assert!(plain.is_match("package/docs/example.py"));
        let entries = vec![InventoryEntry {
            absolute: PathBuf::from("/repo/packages/core/src/pkg/a.py"),
            relative: PathBuf::from("packages/core/src/pkg/a.py"),
            selected: true,
        }];
        assert_eq!(package_roots(&entries), HashSet::from(["pkg".to_string()]));
        assert!(!is_python_notebook_cell("%%bash\necho hi\n"));
        assert!(is_python_notebook_cell("%%time\nx = !ls\nvalue?\n"));
        for label in ["latin-1", "latin1", "iso8859-1", "cp819"] {
            let mut bytes = format!("# coding: {label}\n# ").into_bytes();
            bytes.extend([0x80, b'\n']);
            let decoded = decode_python(Path::new("latin.py"), &bytes).unwrap();
            assert!(decoded.contains('\u{80}'), "{label}");
        }
    }
}
