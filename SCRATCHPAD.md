# main @ 1bb54e2

## TODO

- [x] Preserve BAL001-BAL020, including BAL019.
- [x] Remove named profiles, baselines, changed-line diff mode, duplicated release checks, and the 200-column formatter settings.
- [x] Preserve Ruff-parity output, settings, rule-explanation, and selection interfaces.
- [x] Remove only the added calibration code and wiring; restore all 16 pre-existing `positive_examples` repositories at default-branch HEAD.
- [x] Run formatting, Clippy, unit tests, CLI tests, release build, self-scan, and diff checks.

## Open questions for the user

- Whether the deleted repository copies contained uncommitted or untracked files; fresh clones cannot recover those contents.

## Uncertain / ideas to explore

- BAL019 stays conservative under static source analysis: decorators, escapes, shadowed bindings, star imports, and unresolved caller paths disable the finding.

## Notes to self

- The acceptance baseline is zero; the current diff against HEAD is +3,712/-1,534, net +2,178 under standard rustfmt.
- Removing calibration code and wiring lowered the tracked physical line count by 176, including scratchpad changes.
- Deleting the pre-existing `positive_examples` directory was an error; all 16 repositories were freshly cloned and checked out on `origin`'s default branch.
- Validation after calibration-code removal: formatting, Clippy with `-D warnings`, 14 unit tests, 13 CLI tests, release build, self-scan, and diff whitespace checks pass.
- The adversarial BAL019 review found no concrete false-positive path under the static source model.
