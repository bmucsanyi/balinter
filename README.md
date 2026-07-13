# balinter

[![PyPI](https://img.shields.io/pypi/v/balinter.svg)](https://pypi.org/project/balinter/)
[![CI](https://github.com/bmucsanyi/balinter/actions/workflows/ci.yml/badge.svg)](https://github.com/bmucsanyi/balinter/actions/workflows/ci.yml)

Balint's opinionated linter for sprawling research codebases. Ruff checks syntax and ty checks types; `balinter` checks repository growth, over-decomposition, duplicate helpers, placeholder scaffolding, weak tests, fallback paths, silent defaults, oversized units, broad module APIs, and low-information prose.

## Install

```console
pip install balinter
```

Platform wheels contain a Rust binary; releases also provide a source distribution.

## Use

```console
balinter check                         # current project
balinter check src/ tests/             # shared repository index
balinter check module.py               # explicit file
balinter check --statistics            # per-rule counts
balinter check --output-format json    # JSON spans
balinter check --output-format sarif   # SARIF 2.1.0
balinter check --output-format github  # workflow commands
balinter explain BAL015
balinter show-settings
```

Exit codes are 0 for no findings, 1 for findings, and 2 for invalid runs. Explicit paths bypass VCS and hidden-file filters; configured excludes still apply. Python encoding declarations, `.pyi` files, and Python notebook cells are supported. Non-Python cell magics are skipped.

## Rules

| Code | Name | Check |
|---|---|---|
| BAL001 | bloat-repo | repository physical-line limit |
| BAL002 | bloat-file | file physical-line limit |
| BAL003 | bloat-density | top-level functions per 1k production lines |
| BAL004 | dup-family | functions sharing a two-token name suffix |
| BAL005 | test-mock | resolved mock calls per test |
| BAL006 | test-absent | test-to-production line ratio |
| BAL007 | guard-fallback | exception handlers substituting alternate results |
| BAL008 | guard-silent-default | local `None` defaults and NaN replacement |
| BAL009 | test-mock-sut | first-party patches matching the test subject |
| BAL010 | test-weak | missing value observations or metadata-only assertions |
| BAL011 | comment-noise | changelog comments and divider blocks |
| BAL012 | banned-word | configured vocabulary and emoji |
| BAL013 | stub | concrete placeholder bodies |
| BAL014 | abstraction-solo | qualified abstract bases with one implementation |
| BAL015 | dup-body | equal normalized token bodies |
| BAL016 | doc-bloat | long unstructured docstrings on short functions |
| BAL017 | god-function | function statement count or branch depth |
| BAL018 | god-class | class method count |
| BAL019 | wrapper-chain | one-caller private forwarding helpers |
| BAL020 | module-api | statically exported symbols per module |

`balinter explain` lists all rule metadata.

## Configure

Settings come from `[tool.balinter]` in `pyproject.toml`, overridden by `balinter.toml`. Unknown keys, selectors, ranges, unreadable files, and malformed TOML are errors.

```toml
select = ["BAL007", "stub"]          # replacement selection
ignore = ["BAL011"]
repo_max_loc = 40000
file_max_loc = 2000
max_function_statements = 70
max_branch_depth = 5
max_class_methods = 24
max_public_symbols_per_module = 32
banned_words = ["seamless", "delve"] # [] is valid
exclude = ["docs", "tests/fixtures", "**/_generated.py"]
[per_file_ignores]
"tests/**" = ["BAL013"]
```

Plain excluded names match at any depth; slashed paths include descendants; globs use project-relative paths.

## Suppress

```python
x = fallback()  # noqa: BAL007
```

## Pre-commit

```yaml
- repo: https://github.com/bmucsanyi/balinter
  rev: v0.1.0
  hooks: [{id: balinter}]
```

## Development

```console
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all
```
