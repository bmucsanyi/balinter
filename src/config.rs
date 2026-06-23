use serde::Deserialize;
use std::path::Path;

pub struct Config {
    pub repo_max_loc: usize,
    pub file_max_loc: usize,
    pub max_funcs_per_kloc: f64,
    pub max_name_family: usize,
    pub max_mocks_per_test: f64,
    pub min_test_ratio: f64,
    pub test_absent_min_prod_loc: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            repo_max_loc: 26_000,
            file_max_loc: 3_000,
            max_funcs_per_kloc: 22.0,
            max_name_family: 10,
            max_mocks_per_test: 0.7,
            min_test_ratio: 0.05,
            test_absent_min_prod_loc: 2_000,
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Overrides {
    repo_max_loc: Option<usize>,
    file_max_loc: Option<usize>,
    max_funcs_per_kloc: Option<f64>,
    max_name_family: Option<usize>,
    max_mocks_per_test: Option<f64>,
    min_test_ratio: Option<f64>,
    test_absent_min_prod_loc: Option<usize>,
}

impl Config {
    /// Load defaults, then apply pyproject.toml `[tool.balinter]`, then balinter.toml.
    /// balinter.toml wins, mirroring how ruff prefers ruff.toml over pyproject.toml.
    pub fn load(root: &Path) -> Config {
        let mut cfg = Config::default();

        if let Ok(text) = std::fs::read_to_string(root.join("pyproject.toml")) {
            if let Ok(table) = toml::from_str::<toml::Table>(&text) {
                if let Some(section) = table.get("tool").and_then(|t| t.get("balinter")) {
                    let overrides: Overrides = section.clone().try_into().unwrap_or_else(|e| {
                        fatal(&format!("invalid [tool.balinter] in pyproject.toml: {e}"))
                    });
                    cfg.apply(overrides);
                }
            }
        }

        if let Ok(text) = std::fs::read_to_string(root.join("balinter.toml")) {
            let overrides: Overrides = toml::from_str(&text)
                .unwrap_or_else(|e| fatal(&format!("invalid balinter.toml: {e}")));
            cfg.apply(overrides);
        }

        cfg
    }

    fn apply(&mut self, o: Overrides) {
        if let Some(v) = o.repo_max_loc {
            self.repo_max_loc = v;
        }
        if let Some(v) = o.file_max_loc {
            self.file_max_loc = v;
        }
        if let Some(v) = o.max_funcs_per_kloc {
            self.max_funcs_per_kloc = v;
        }
        if let Some(v) = o.max_name_family {
            self.max_name_family = v;
        }
        if let Some(v) = o.max_mocks_per_test {
            self.max_mocks_per_test = v;
        }
        if let Some(v) = o.min_test_ratio {
            self.min_test_ratio = v;
        }
        if let Some(v) = o.test_absent_min_prod_loc {
            self.test_absent_min_prod_loc = v;
        }
    }
}

fn fatal(msg: &str) -> ! {
    eprintln!("balinter: {msg}");
    std::process::exit(2);
}
