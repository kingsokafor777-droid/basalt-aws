## What and why

<!-- What changes, and what problem it solves. Link the issue if there is one. -->

## Checklist

- [ ] `make check` passes locally (lint, format, mypy strict, tests with coverage)
- [ ] Tests added or updated for the behaviour change
- [ ] `CHANGELOG.md` updated under `[Unreleased]` if user-visible
- [ ] No new runtime dependency, or it was agreed in an issue first

## Check impact

- [ ] No new AWS API calls
- [ ] New API calls added — all read-only, and added to `cli.REQUIRED_PERMISSIONS` and `terraform/main.tf`
- [ ] New check — tested in both directions (misconfigured produces a finding, hardened produces none)
- [ ] No `rule_id` renamed (renaming orphans downstream history)

## Notes for the reviewer

<!-- Trade-offs considered, alternatives rejected, anything you are unsure about. -->
