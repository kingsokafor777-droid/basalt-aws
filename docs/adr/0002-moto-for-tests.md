# ADR 0002: Test against moto, not hand-written mocks

- **Status:** Accepted
- **Date:** 2026-08-02

## Context

Checks are almost entirely AWS API interaction. Testing them requires either a real
account, hand-written mocks, or an API simulator.

A real account makes tests slow, costly, non-deterministic and unrunnable in a fork's CI.

Hand-written mocks have a worse problem: they are written by the same person who wrote the
check, from the same reading of the API. When that reading is wrong, the mock and the check
are wrong together and the test passes. A mock asserts that the code does what its author
expected, which is not the same as asserting it works.

## Decision

Tests run against `moto`, which implements the boto3 API surface in-process. Checks
exercise real request construction, real pagination, and real error codes.

Fixtures set dummy credentials with `monkeypatch` and unset `AWS_PROFILE`,
`AWS_SHARED_CREDENTIALS_FILE` and `AWS_CONFIG_FILE`, so a developer with an active profile
cannot accidentally scan a real account by running the suite.

Tests assert on both directions: a misconfigured resource produces a finding, and a
correctly configured one produces none. `secure_bucket()` builds a fully hardened bucket
that every S3 check must pass.

## Consequences

**Positive.** Tests run offline in about ten seconds, in any fork, with no credentials. A
check that mishandles an error code fails here rather than in production. The negative
tests catch the more embarrassing failure mode: a check that reports every resource.

**Negative.** moto's fidelity is good but not complete, and its coverage of newer APIs lags
AWS. A check can pass against moto and fail against AWS.

**Mitigation.** A `live` pytest marker is reserved for tests requiring real credentials; it
is deselected by default and is where genuine API drift should be caught before a release.
