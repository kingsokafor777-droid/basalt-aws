# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Changing a `rule_id` is breaking: it orphans that check's history in any downstream
warehouse, because `Finding.fingerprint` is derived from it.

## [Unreleased]

## [0.1.0] - 2026-08-02

Initial release. 17 checks across four services.

### Added

- **IAM** (6 checks): root MFA, root access key, per-user console MFA, stale access keys,
  customer-managed policies granting `Action:* Resource:*`, and account password policy.
- **S3** (6 checks): public ACL, unconditioned public bucket policy, Block Public Access
  coverage, default encryption, versioning, and TLS enforcement.
- **CloudTrail** (4 checks): trail existence, multi-region coverage, log file validation,
  and KMS encryption of delivered logs.
- **KMS** (1 check): automatic rotation of customer-managed symmetric keys. AWS-managed,
  asymmetric and imported-material keys are correctly excluded.
- `Check` base class with declarative metadata and a registry that rejects duplicate rule
  ids at import time.
- `AwsContext` with per-`(service, region)` client caching, adaptive retries, and
  `is_access_denied()` so a read-only role degrades coverage instead of failing the scan.
- `basalt-aws` CLI: `scan`, `checks`, `permissions`, with `--fail-on` for CI gating.
- Terraform module provisioning a least-privilege scanner role gated by an external id.
- Registered under the `basalt.scanners` entry point for discovery by any Basalt tool.

### Notes

- Requires `basalt-core>=0.1.1`. The ecosystem contract tests in this repository found a
  URN escaping defect in `basalt-core` 0.1.0 where unsafe characters were replaced rather
  than encoded, allowing two distinct resources to collapse onto one URN.

[Unreleased]: https://github.com/kingsokafor777-droid/basalt-aws/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kingsokafor777-droid/basalt-aws/releases/tag/v0.1.0
