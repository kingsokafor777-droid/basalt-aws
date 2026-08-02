# ADR 0003: Read-only by construction

- **Status:** Accepted
- **Date:** 2026-08-02

## Context

A security scanner is asked for credentials into the most sensitive account an
organisation owns. "It only reads" is a claim that has to be verifiable, not asserted.

Remediation is genuinely useful, and it is tempting to let the scanner apply fixes it has
already identified. That temptation is the problem: a scanner with write access is a
single compromised dependency away from being an attack tool with production credentials.

## Decision

This package never mutates AWS state. Remediation is emitted as data —
`Remediation.cli_command` and `Remediation.iac_patch` on the finding — for a human or for
`basalt-agent` to apply through a reviewed pull request.

Every API the scanner calls is enumerated in `cli.REQUIRED_PERMISSIONS`, surfaced by
`basalt-aws permissions`, and emitted as a least-privilege policy document with
`--json`. A test asserts that no entry in that list begins with a mutating verb.

`terraform/` provisions the read-only role, so the deployment artifact and the documented
permission set come from the same place.

## Consequences

**Positive.** The claim is checkable in CI, not just in the README. The blast radius of a
compromise of this package is limited to disclosure of posture data — which is still
sensitive, and `SECURITY.md` says so.

**Negative.** Users must apply remediations themselves. The permission list is maintained
by hand and can drift from what the code calls.

**Mitigation.** The drift is bounded: the list is a single module-level constant next to
the CLI that displays it, and adding a check without updating it will surface as an
AccessDenied on the first real run.
