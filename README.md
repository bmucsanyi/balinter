# balinter

[![PyPI](https://img.shields.io/pypi/v/balinter.svg)](https://pypi.org/project/balinter/)
[![Python](https://img.shields.io/pypi/pyversions/balinter.svg)](https://pypi.org/project/balinter/)
[![CI](https://github.com/bmucsanyi/balinter/actions/workflows/ci.yml/badge.svg)](https://github.com/bmucsanyi/balinter/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/bmucsanyi/balinter/badge.svg?branch=main)](https://coveralls.io/github/bmucsanyi/balinter?branch=main)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Balint's opinionated linter for sprawling research codebases.

ruff checks whether a line is well-formed and ty checks whether it is well-typed.
`balinter` checks whether the code should exist at all - sprawl, god-files,
over-decomposition, near-duplicate helpers, placeholder scaffolding, tests that fake
what they test, fallbacks and silent defaults, and slop vocabulary. It runs one layer
above ruff, on ruff's own parser.

## Install

```
pip install balinter
```

`balinter` is a Rust binary shipped as a prebuilt wheel, built with `maturin`, like Ruff.

## Use

```
balinter check                        # lint the current directory
balinter check src/ tests/            # one or more files or directories
balinter check --statistics           # per-rule counts instead of findings
balinter check --output-format json   # machine-readable output for CI
```

It exits non-zero when anything fires, so it gates CI out of the box.

## Rules

Size and shape (aggregate counts, thresholds tunable):

| Code | Name | What it does |
|---|---|---|
| BAL001 | bloat-repo | the whole repo over 26k lines |
| BAL002 | bloat-file | a single file over 3k lines |
| BAL003 | bloat-density | over 22 top-level functions per 1k production lines |
| BAL004 | dup-family | over 10 functions sharing a two-word name stem |
| BAL005 | test-mock | over 0.7 mock/patch calls per test |
| BAL006 | test-absent | test lines under 5% of production lines |
| BAL015 | dup-body | more than two functions sharing one identical body |

Bans (parser-based, fire on any instance):

| Code | Name | What it does |
|---|---|---|
| BAL007 | guard-fallback | a `try` whose `except` substitutes for the failed path |
| BAL008 | guard-silent-default | `if x is None: x = ...` defaulting a local; silent NaN fill (parameters exempt) |
| BAL009 | test-mock-sut | a test that mocks its own first-party subject |
| BAL010 | test-weak | a test whose only checks are type/shape/None (value-checking assertion calls count) |
| BAL011 | comment-noise | changelog comments and decorative dividers (skipped in doc trees) |
| BAL012 | banned-word | slop vocabulary or emoji in comments, docstrings, or identifiers |
| BAL013 | stub | a placeholder body (`pass`/`...`/bare `NotImplementedError`) in a concrete function |
| BAL014 | abstraction-solo | an abstract base with a single concrete implementation in the repo |
| BAL016 | doc-bloat | a docstring longer than the code, on a short function, with no Parameters/Returns section |

`stub` exempts `@overload`, `@abstractmethod`, and `Protocol` members; if you mean
"abstract", use one of those. `guard-fallback`-style catch-and-ignore is left to ruff
(BLE001, S110, S112, E722) - balinter never duplicates a ruff rule and assumes ruff runs
underneath.

## Configure

Every threshold is an overridable default. balinter reads `[tool.balinter]` from
`pyproject.toml` and a top-level `balinter.toml`; `balinter.toml` wins where both set a
key, as ruff prefers `ruff.toml`. Rules cannot be disabled - only their numbers tuned.

```toml
# balinter.toml
repo_max_loc = 40000
file_max_loc = 2000

# the banned-word list; this replaces the default outright (set [] to disable the words)
banned_words = ["seamless", "delve", "robust"]

# paths removed from every rule, ruff-style: a bare name matches that directory
# anywhere, a slash or glob is a literal glob
exclude = ["docs", "tests/fixtures", "**/_generated.py"]
```

## Suppress

Standard `noqa`, on the line that flagged, by code or by rule name:

```python
x = fallback()  # noqa
x = fallback()  # noqa: BAL007
x = fallback()  # noqa: guard-fallback
```

## Pre-commit

```yaml
# .pre-commit-config.yaml
- repo: https://github.com/bmucsanyi/balinter
  rev: v0.1.0
  hooks:
    - id: balinter
```

The hook runs `balinter check` over the whole repo (the rules are repo-level), not per
changed file.

## How it works

balinter is built on ruff's own Python parser. Size and density are line scans over a
gitignore-aware, parallel file walk (minus the configured excludes); every other rule runs
on the AST. Findings are sorted by file and line, so output is deterministic.
