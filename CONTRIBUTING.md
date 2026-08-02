# Contributing

## Setup

```bash
git clone https://github.com/kingsokafor777-droid/basalt-aws
cd basalt-aws
make install
make check
```

`make check` runs what CI runs: Ruff, mypy strict, and pytest with coverage gated at 80%.
Tests need no AWS credentials — everything runs against moto in-process.

## Adding a check

1. Add the class to the right module under `src/basalt_aws/checks/`, decorated with
   `@register`.
2. Declare all metadata as class attributes. Build findings with `self.finding()`, never
   by calling `Finding(...)` directly.
3. Every `control_ids` entry must resolve against the `basalt-core` catalog. If the control
   you need is not there, add it to `basalt-core`'s catalog first — CI fails otherwise.
4. Set `scope` correctly. Account-wide APIs are `Scope.GLOBAL`; anything regional is
   `Scope.REGIONAL`. Getting this wrong produces duplicate findings that survive
   deduplication.
5. Skip resources you cannot read using `is_access_denied()`. Do not let one denied
   permission end a scan.
6. If the check calls a new API, add it to `cli.REQUIRED_PERMISSIONS` and to
   `terraform/main.tf`. It must be a read.

**Tests are required in both directions.** A misconfigured resource must produce a
finding, and a correctly configured one must produce none. The second is the one that
catches a check which flags everything.

## House rules

- **Read-only, always.** A pull request adding a mutating permission will be declined. See
  ADR 0003.
- **No hand-written boto3 mocks.** Use moto. A mock written by the same person who wrote
  the check asserts only that they were self-consistent. See ADR 0002.
- **Severity is impact; exposure and exploitability are reachability.** Do not inflate
  severity to raise a risk score — set `exposure` and `exploitability` honestly and let
  the model rank it.
- **Descriptions explain consequence, not configuration.** "The bucket ACL grants READ to
  AllUsers" is what. "…exposing every object to anonymous callers" is why anyone cares.
- **Remediation must be actionable.** A `cli_command` or `iac_patch` someone can run, not
  "review your configuration".

## Changing a rule_id

Breaking. `Finding.fingerprint` derives from it, so a rename orphans that check's entire
history in every downstream warehouse. Open an issue first, and expect to justify it.

## Commits

Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`). Update `CHANGELOG.md`
under `[Unreleased]` for anything user-visible.
