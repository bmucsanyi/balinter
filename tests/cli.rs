use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "balinter-test-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn write(&self, relative: &str, contents: &str) -> PathBuf {
        self.write_bytes(relative, contents.as_bytes())
    }

    fn write_bytes(&self, relative: &str, contents: &[u8]) -> PathBuf {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_balinter"))
            .args(arguments)
            .current_dir(&self.root)
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON: {error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn selected(rule: &str) -> String {
    format!("select = [\"{rule}\"]\n")
}

#[test]
fn parse_errors_fail_the_run() {
    let fixture = Fixture::new();
    fixture.write("a.py", "def broken(:\n");
    let output = fixture.run(&["check", ".", "--output-format", "json"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("parse error in a.py"));
}

#[test]
fn direct_and_overlapping_inputs_are_project_relative_and_deduplicated() {
    let fixture = Fixture::new();
    fixture.write("balinter.toml", &selected("BAL013"));
    let file = fixture.write("sub/a.py", "def f():\n    pass\n");
    let file_arg = file.to_str().unwrap();
    let root_arg = fixture.root.to_str().unwrap();
    let sub_arg = fixture.root.join("sub");

    let direct = fixture.run(&["check", file_arg, "--output-format", "json"]);
    assert_eq!(direct.status.code(), Some(1));
    let values = json(&direct).as_array().unwrap().clone();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["file"], "sub/a.py");

    let overlap = fixture.run(&[
        "check",
        root_arg,
        sub_arg.to_str().unwrap(),
        file_arg,
        file_arg,
        "--output-format",
        "json",
    ]);
    assert_eq!(json(&overlap).as_array().unwrap().len(), 1);
}

#[test]
fn explicit_hidden_and_ignored_files_are_analyzed() {
    let fixture = Fixture::new();
    fixture.write("balinter.toml", &selected("BAL013"));
    fixture.write(".git/HEAD", "ref: refs/heads/main\n");
    fixture.write(".gitignore", "ignored.py\nignored/\n");
    let ignored = fixture.write("ignored.py", "def ignored():\n    pass\n");
    let hidden = fixture.write(".hidden/a.py", "def hidden():\n    pass\n");
    let directory = fixture.write("ignored/a.py", "def ignored():\n    pass\n");

    for path in [ignored, hidden] {
        let output = fixture.run(&["check", path.to_str().unwrap(), "--output-format", "json"]);
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(json(&output).as_array().unwrap().len(), 1);
    }
    let directory = directory.parent().unwrap().to_str().unwrap();
    let output = fixture.run(&["check", ".", directory, "--output-format", "json"]);
    assert_eq!(json(&output).as_array().unwrap().len(), 1);
}

#[test]
fn slashed_excludes_remove_directory_descendants() {
    let fixture = Fixture::new();
    fixture.write(
        "balinter.toml",
        "select = [\"BAL013\"]\nexclude = [\"tests/fixtures\"]\n",
    );
    fixture.write("tests/fixtures/a.py", "def f():\n    pass\n");
    let output = fixture.run(&["check", ".", "--output-format", "json"]);
    assert!(output.status.success());
    assert_eq!(json(&output), Value::Array(Vec::new()));
}

#[test]
fn pyi_and_notebook_code_are_analyzed() {
    let fixture = Fixture::new();
    fixture.write("balinter.toml", &selected("BAL012"));
    fixture.write("types.pyi", "seamless: int\n");
    fixture.write("analysis.ipynb", r#"{"cells":[{"cell_type":"code","source":["seamless = 1\n"]}],"metadata":{},"nbformat":4,"nbformat_minor":5}"#);
    let output = fixture.run(&["check", ".", "--output-format", "json"]);
    let values = json(&output).as_array().unwrap().clone();
    assert_eq!(values.len(), 2);
    assert!(values.iter().any(|value| value["file"] == "types.pyi"));
    assert!(values
        .iter()
        .any(|value| value["file"] == "analysis.ipynb" && value["cell"] == 1));
}

#[test]
fn pep_263_encoded_python_is_analyzed() {
    let fixture = Fixture::new();
    fixture.write("balinter.toml", &selected("BAL013"));
    fixture.write_bytes(
        "latin.py",
        b"# coding: latin-1\n# caf\xe9\ndef placeholder():\n    pass\n",
    );
    let output = fixture.run(&["check", ".", "--output-format", "json"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(json(&output)[0]["code"], "BAL013");
}

#[test]
fn notebook_external_outputs_use_logical_cell_locations() {
    let fixture = Fixture::new();
    fixture.write("balinter.toml", &selected("BAL012"));
    fixture.write("analysis.ipynb", r#"{"cells":[{"cell_type":"code","source":["x = 1\n","seamless = x\n"]}],"metadata":{},"nbformat":4,"nbformat_minor":5}"#);

    let sarif = fixture.run(&["check", ".", "--output-format", "sarif"]);
    let value = json(&sarif);
    let location = &value["runs"][0]["results"][0]["locations"][0];
    assert!(location["physicalLocation"].get("region").is_none());
    assert_eq!(location["logicalLocations"][0]["name"], "cell 1");

    let github = fixture.run(&["check", ".", "--output-format", "github"]);
    let output = String::from_utf8(github.stdout).unwrap();
    assert!(output.contains("file=analysis.ipynb"));
    assert!(output.contains("cell 1, line 2"));
    assert!(!output.contains(",line="));
}

#[test]
fn notebook_repository_findings_preserve_their_cell() {
    let fixture = Fixture::new();
    fixture.write("balinter.toml", &selected("BAL014"));
    fixture.write(
            "analysis.ipynb",
            r#"{"cells":[{"cell_type":"code","source":["from abc import ABC, abstractmethod\n","class Base(ABC):\n","    @abstractmethod\n","    def run(self): ...\n"]},{"cell_type":"code","source":["class Only(Base):\n","    def run(self): return 1\n"]}],"metadata":{},"nbformat":4,"nbformat_minor":5}"#,
        );
    let output = fixture.run(&["check", ".", "--output-format", "json"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(json(&output)[0]["cell"], 1);
}

#[test]
fn strings_cannot_suppress_and_comments_cannot_create_mock_calls() {
    let fixture = Fixture::new();
    fixture.write("balinter.toml", "select = [\"BAL005\", \"BAL012\"]\n");
    fixture.write("a.py", "seamless = \"# noqa \"\n");
    fixture.write(
        "test_a.py",
        "def test_value():\n    # MagicMock is documentation, not a call.\n    assert 1 == 1\n",
    );
    let output = fixture.run(&["check", ".", "--output-format", "json"]);
    let values = json(&output).as_array().unwrap().clone();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["code"], "BAL012");
}

#[test]
fn malformed_and_invalid_configuration_fails() {
    let malformed = Fixture::new();
    malformed.write("pyproject.toml", "[tool.balinter\n");
    malformed.write("a.py", "x = 1\n");
    assert_eq!(malformed.run(&["check", "."]).status.code(), Some(2));

    let invalid = Fixture::new();
    invalid.write("balinter.toml", "banned_words = [\"\"]\n");
    invalid.write("a.py", "x = 1\n");
    assert_eq!(invalid.run(&["check", "."]).status.code(), Some(2));
}

#[test]
fn sarif_output_is_machine_usable() {
    let fixture = Fixture::new();
    fixture.write("balinter.toml", &selected("BAL013"));
    fixture.write("a.py", "def f():\n    pass\n");

    let sarif = fixture.run(&["check", ".", "--output-format", "sarif"]);
    let sarif = json(&sarif);
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["columnKind"], "unicodeCodePoints");
}

#[test]
fn explain_and_show_settings_are_machine_usable() {
    let fixture = Fixture::new();
    fixture.write("balinter.toml", &selected("BAL013"));
    let explain = fixture.run(&["explain", "stub"]);
    assert!(String::from_utf8_lossy(&explain.stdout).starts_with("BAL013 stub\n"));
    let settings = fixture.run(&["show-settings", "."]);
    assert_eq!(json(&settings)["enabled"], serde_json::json!(["BAL013"]));
}

#[test]
fn statistics_rejects_annotation_formats() {
    let fixture = Fixture::new();
    fixture.write("a.py", "x = 1\n");
    for format in ["sarif", "github"] {
        let output = fixture.run(&["check", ".", "--statistics", "--output-format", format]);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains("--statistics supports only text and JSON output"));
    }
}
