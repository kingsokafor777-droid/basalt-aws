# ADR 0001: Checks as classes with declarative metadata

- **Status:** Accepted
- **Date:** 2026-08-02

## Context

A posture scanner is mostly a catalogue. The interesting operations are not "run a scan"
but "which rules exist", "which controls does rule X satisfy", "run only the S3 rules",
and "does every rule cite a control that actually exists". A design where each check is a
function that constructs findings inline can answer none of those without executing it.

## Decision

Each check is a class subclassing `Check`, declaring `rule_id`, `title`, `description`,
`severity`, `exposure`, `exploitability`, `control_ids`, `service` and `scope` as class
attributes, and implementing one generator.

Findings are built through `Check.finding()` rather than by calling `Finding(...)`
directly, so rule id, controls and tags cannot drift from the declared metadata.

`register` rejects duplicate or missing rule ids at import time, not at scan time.

## Consequences

**Positive.** `basalt-aws checks` lists the catalogue without AWS credentials. CI asserts
every declared control id resolves against the `basalt-core` catalog, so a typo fails the
build rather than reaching a compliance report. Filtering by service or rule is a list
comprehension over metadata.

**Negative.** More ceremony per check than a bare function. A check whose severity varies
by observation must override it per finding, which splits the truth between the class
attribute and the call site — `iam.password-policy-weak` does exactly this.

**Mitigation.** `finding()` accepts a `severity` override explicitly, so the variance is
visible at the call site rather than hidden.
