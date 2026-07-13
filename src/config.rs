use crate::finding::{Rule, ALL_RULES};
use globset::{Glob, GlobMatcher};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub repo_max_loc: usize,
    pub file_max_loc: usize,
    pub max_funcs_per_kloc: f64,
    pub max_name_family: usize,
    pub max_mocks_per_test: f64,
    pub min_test_ratio: f64,
    pub test_absent_min_prod_loc: usize,
    pub max_body_clones: usize,
    pub max_function_statements: usize,
    pub max_branch_depth: usize,
    pub max_class_methods: usize,
    pub max_public_symbols_per_module: usize,
    pub banned_words: Vec<String>,
    pub exclude: Vec<String>,
    select: Option<Vec<String>>,
    ignore: Option<Vec<String>>,
    #[serde(rename = "per_file_ignores")]
    raw_ignores: BTreeMap<String, Vec<String>>,
    #[serde(skip)]
    enabled: HashSet<Rule>,
    #[serde(skip)]
    per_file_ignores: Vec<PerFileIgnore>,
}

struct PerFileIgnore {
    pattern: String,
    matcher: GlobMatcher,
    rules: HashSet<Rule>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            repo_max_loc: 26_000,
            file_max_loc: 3_000,
            max_funcs_per_kloc: 22.0,
            max_name_family: 10,
            max_mocks_per_test: 0.7,
            min_test_ratio: 0.05,
            test_absent_min_prod_loc: 2_000,
            max_body_clones: 2,
            max_function_statements: 80,
            max_branch_depth: 6,
            max_class_methods: 30,
            max_public_symbols_per_module: 40,
            banned_words: default_banned_words(),
            exclude: Vec::new(),
            select: None,
            ignore: None,
            raw_ignores: BTreeMap::new(),
            enabled: ALL_RULES.into_iter().collect(),
            per_file_ignores: Vec::new(),
        }
    }
}

fn default_banned_words() -> Vec<String> {
    "seamless|blazingly|effortless|cutting-edge|world-class|battle-tested|production-grade|production-ready|out-of-the-box|turnkey|supercharge|it's worth noting|feel free|as we can see"
        .split('|')
        .map(str::to_string)
        .collect()
}

impl Config {
    pub fn discover(start: &Path) -> Result<(PathBuf, Self), String> {
        let mut dir = if start.is_dir() {
            Some(start)
        } else {
            start.parent()
        };

        while let Some(candidate) = dir {
            if let Some(config) = Self::load(candidate)? {
                return Ok((candidate.to_path_buf(), config));
            }
            dir = candidate.parent();
        }

        let root = if start.is_dir() {
            start.to_path_buf()
        } else {
            start.parent().unwrap_or(start).to_path_buf()
        };
        Ok((root, Self::default()))
    }

    fn load(root: &Path) -> Result<Option<Self>, String> {
        let mut values = toml::Table::new();
        let mut configured = false;
        let pyproject = root.join("pyproject.toml");
        if pyproject.exists() {
            let text = read_required(&pyproject)?;
            let table: toml::Table = toml::from_str(&text)
                .map_err(|error| format!("invalid {}: {error}", pyproject.display()))?;
            if let Some(section) = table
                .get("tool")
                .and_then(|tool| tool.get("balinter"))
                .and_then(toml::Value::as_table)
            {
                configured = true;
                parse_config(section.clone())?;
                values.extend(section.clone());
            }
        }
        let standalone = root.join("balinter.toml");
        if standalone.exists() {
            configured = true;
            let text = read_required(&standalone)?;
            let standalone: toml::Table = toml::from_str(&text)
                .map_err(|error| format!("invalid {}: {error}", standalone.display()))?;
            parse_config(standalone.clone())?;
            if standalone.contains_key("select") {
                values.remove("ignore");
            }
            values.extend(standalone);
        }
        if !configured {
            return Ok(None);
        }
        Ok(Some(parse_config(values)?))
    }

    pub fn rule_enabled(&self, rule: Rule, path: &str) -> bool {
        self.enabled.contains(&rule)
            && !self
                .per_file_ignores
                .iter()
                .any(|entry| entry.matcher.is_match(path) && entry.rules.contains(&rule))
    }

    pub fn settings_json(&self, root: &Path) -> Value {
        let mut enabled: Vec<&str> = self.enabled.iter().map(|rule| rule.code()).collect();
        enabled.sort_unstable();
        let per_file: Vec<Value> = self
            .per_file_ignores
            .iter()
            .map(|entry| {
                let mut rules: Vec<_> = entry.rules.iter().map(|rule| rule.code()).collect();
                rules.sort_unstable();
                json!({"pattern": entry.pattern, "rules": rules})
            })
            .collect();
        json!({
            "root": root,
            "repo_max_loc": self.repo_max_loc,
            "file_max_loc": self.file_max_loc,
            "max_funcs_per_kloc": self.max_funcs_per_kloc,
            "max_name_family": self.max_name_family,
            "max_mocks_per_test": self.max_mocks_per_test,
            "min_test_ratio": self.min_test_ratio,
            "test_absent_min_prod_loc": self.test_absent_min_prod_loc,
            "max_body_clones": self.max_body_clones,
            "max_function_statements": self.max_function_statements,
            "max_branch_depth": self.max_branch_depth,
            "max_class_methods": self.max_class_methods,
            "max_public_symbols_per_module": self.max_public_symbols_per_module,
            "banned_words": self.banned_words,
            "exclude": self.exclude,
            "enabled": enabled,
            "per_file_ignores": per_file,
        })
    }

    fn finish(&mut self) -> Result<(), String> {
        self.banned_words = self
            .banned_words
            .drain(..)
            .map(|word| word.trim().to_ascii_lowercase())
            .collect();
        self.banned_words.sort();
        self.banned_words.dedup();
        if let Some(selectors) = self.select.take() {
            self.enabled = parse_rules(&selectors, "select")?.into_iter().collect();
        }
        if let Some(selectors) = self.ignore.take() {
            for rule in parse_rules(&selectors, "ignore")? {
                self.enabled.remove(&rule);
            }
        }
        for (pattern, selectors) in std::mem::take(&mut self.raw_ignores) {
            let rules = parse_rules(&selectors, "per_file_ignores")?;
            let matcher = Glob::new(&pattern)
                .map_err(|error| format!("invalid per-file ignore pattern {pattern:?}: {error}"))?
                .compile_matcher();
            self.per_file_ignores.push(PerFileIgnore {
                pattern,
                matcher,
                rules: rules.into_iter().collect(),
            });
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("max_funcs_per_kloc", self.max_funcs_per_kloc),
            ("max_mocks_per_test", self.max_mocks_per_test),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(format!("{name} must be finite and non-negative"));
            }
        }
        if !self.min_test_ratio.is_finite() || !(0.0..=1.0).contains(&self.min_test_ratio) {
            return Err("min_test_ratio must be finite and between 0 and 1".to_string());
        }
        if self.max_name_family == 0 || self.max_body_clones == 0 {
            return Err("max_name_family and max_body_clones must be at least 1".to_string());
        }
        if self.max_function_statements == 0
            || self.max_branch_depth == 0
            || self.max_class_methods == 0
            || self.max_public_symbols_per_module == 0
        {
            return Err("code-shape limits must be at least 1".to_string());
        }
        if self.banned_words.iter().any(|word| word.is_empty()) {
            return Err("banned_words cannot contain an empty term".to_string());
        }
        Ok(())
    }
}

fn parse_rules(values: &[String], field: &str) -> Result<Vec<Rule>, String> {
    values
        .iter()
        .map(|value| Rule::parse(value).ok_or_else(|| format!("unknown rule {value:?} in {field}")))
        .collect()
}

fn parse_config(values: toml::Table) -> Result<Config, String> {
    let mut config: Config = toml::Value::Table(values)
        .try_into()
        .map_err(|error| format!("invalid balinter configuration: {error}"))?;
    config.finish()?;
    config.validate()?;
    Ok(config)
}

fn read_required(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_config(source: &str) -> Result<Config, String> {
        let mut config: Config = toml::from_str(source).map_err(|error| error.to_string())?;
        config.finish()?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn parsing_selection_and_validation() {
        let config = parse_config("select = [\"BAL013\", \"banned-word\"]\n[per_file_ignores]\n\"tests/**\" = [\"BAL013\"]\n").unwrap();
        assert!(config.rule_enabled(Rule::Stub, "src/a.py"));
        assert!(!config.rule_enabled(Rule::Stub, "tests/a.py"));
        assert!(config.rule_enabled(Rule::BannedWord, "tests/a.py"));
        assert!(!config.rule_enabled(Rule::TestWeak, "tests/a.py"));
        let config = parse_config("[per_file_ignores]\n\"tests/**\" = [\"BAL012\"]\n").unwrap();
        assert!(config.rule_enabled(Rule::Stub, "tests/a.py"));
        assert!(!config.rule_enabled(Rule::BannedWord, "tests/a.py"));
        let mut config = Config {
            min_test_ratio: 1.1,
            ..Config::default()
        };
        assert!(config.validate().is_err());
        config.min_test_ratio = 0.1;
        config.banned_words = vec![String::new()];
        assert!(config.validate().is_err());
        assert!(parse_config("select = [\"BAL999\"]").is_err());
    }
}
