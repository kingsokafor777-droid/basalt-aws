# ADR 0004: Check scope, and errors that do not discard findings

- **Status:** Accepted
- **Date:** 2026-08-02

## Context

IAM and the S3 bucket listing are account-wide. CloudTrail and KMS are per-region. Running
a global check once per region would emit near-duplicate findings differing only in the
region field — and because `Finding.fingerprint` includes the resource URN, and the URN
includes the region, those duplicates would survive deduplication and inflate every count
downstream.

Separately, a posture scan of a real account will hit permission denials, unsupported
regions and throttling. Aborting on the first one wastes the work already done.

## Decision

Every check declares `scope`. `Scope.GLOBAL` checks run once with `region=None`;
`Scope.REGIONAL` checks run once per requested region.

Individual checks skip resources they cannot read: `is_access_denied()` classifies
authorisation failures, which are expected for a read-only auditor role, and the check
continues to the next resource.

Failures that are not authorisation problems are collected across the whole scan and
raised once at the end, after every finding has already been yielded. The base
`Scanner.run()` in `basalt-core` captures that into `ScanResult.metadata.errors`.

## Consequences

**Positive.** Counts are correct across multi-region scans. A denied permission degrades
coverage rather than failing the run. Errors are visible in the scan document rather than
lost to a stack trace.

**Negative.** A partial scan and a clean scan both exit successfully, so an unattended run
that silently lost coverage looks like a pass.

**Mitigation.** The CLI prints every collected error to stderr, and `metadata.errors` is
carried into every emitted format. A consumer treating an empty result as "secure" without
checking `errors` is making a mistake the data does not hide.
