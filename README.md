# balinter

Balint's opinionated linter for sprawling research codebases.

ruff checks whether a line is well-formed and ty checks whether it is well-typed.
`balinter` checks whether the code should exist at all - sprawl, god-files,
over-decomposition, near-duplicate helpers, tests that fake what they test, and
quiet fallbacks. It runs one layer above ruff, on ruff's own parser, and lints a
320k-line repo in about 0.12s.

## Install

```
pip install balinter
```

`balinter` is a Rust binary shipped as a prebuilt wheel, built with `maturin`,
just like Ruff. You can also install from source:

```
cargo install --git https://github.com/USER/balinter
```

## Use

```
balinter check                 # lint the current directory
balinter check path/to/repo
balinter check --format json   # machine-readable output for CI
```

It exits non-zero when anything fires, so it gates CI out of the box.

## Rules

Size and shape (thresholds, tunable):

| code | rule | flags |
|---|---|---|
| BAL001 | BLOAT-REPO | the whole repo over 26k lines |
| BAL002 | BLOAT-FILE | a single file over 3k lines |
| BAL003 | BLOAT-DENSITY | over 22 top-level functions per 1k production lines |
| BAL004 | DUP-FAMILY | over 10 functions sharing a two-word name stem |
| BAL005 | TEST-MOCK | over 0.7 mock/patch calls per test |
| BAL006 | TEST-ABSENT | test lines under 5% of production lines |

Bans (parser-based, fire on any instance):

| code | rule | flags |
|---|---|---|
| BAL007 | GUARD-FALLBACK | a `try` that quietly falls back to an alternative |
| BAL008 | GUARD-SILENT-DEFAULT | masking a missing value; silent NaN fill |
| BAL009 | TEST-MOCK-SUT | a test that mocks its own subject |
| BAL010 | TEST-WEAK | a test asserting only type/shape/length/None |
| BAL011 | COMMENT-NOISE | changelog comments and decorative dividers |

Catching and ignoring an error is left to ruff (BLE001, S110, S112, E722) -
balinter never duplicates a ruff rule and assumes ruff runs underneath.

## Configure

Every threshold is an overridable default. balinter reads `[tool.balinter]` from
`pyproject.toml` and from a top-level `balinter.toml`; `balinter.toml` wins where
both set a key, as ruff prefers `ruff.toml`. Rules cannot be disabled - only their
numbers tuned.

```toml
# balinter.toml
repo_max_loc = 40000
file_max_loc = 2000
```

## Suppress

Standard `noqa`, on the line that flagged, by code or by rule name:

```python
x = fallback()  # noqa
x = fallback()  # noqa: BAL007
x = fallback()  # noqa: GUARD-FALLBACK
```

## How it works

balinter is built on ruff's own Python parser. The size metrics are line
scans over a parallel, gitignore-aware file walk. Only the bans parse the AST.
