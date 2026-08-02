# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

Report privately through
[GitHub private vulnerability reporting](https://github.com/kingsokafor777-droid/basalt-aws/security/advisories/new),
not a public issue. Include the affected version, reproduction steps, and what an attacker
gains. Expect acknowledgement within 72 hours and an assessment within 7 days.

## This scanner is read-only

`basalt-aws` never mutates AWS state. Every API it calls is enumerated in
`cli.REQUIRED_PERMISSIONS`, emitted as a policy document by `basalt-aws permissions --json`,
provisioned by `terraform/main.tf`, and asserted mutation-free by a test that rejects any
permission beginning with a mutating verb. See ADR 0003.

Remediation is emitted as data — `cli_command` and `iac_patch` on each finding — for a
human or for `basalt-agent` to apply through a reviewed pull request. This package will not
gain write permissions.

## Scan output is sensitive

The scanner is read-only; its **output is not harmless**. A scan result is a ranked map of
where an account is weakest, including account ids, bucket ARNs, IAM user names and
resource tags.

- Do not commit scan output to a public repository. The `.gitignore` excludes
  `results.sarif` and `findings.json` for this reason.
- Treat scan artifacts in CI as secrets. Do not attach them to public workflow runs.
- SARIF uploaded to GitHub Code Scanning inherits the repository's visibility.

## Credential handling

Credentials come from the standard boto3 chain, or from an explicit session passed via
`ScanContext.credentials`. This package stores nothing, writes no config file, and logs no
credential material. `ScanContext.credentials` is excluded from serialization by
`basalt-core`, so credentials cannot leak into an emitted scan document.

Prefer an assumed role with an external id over long-lived access keys — `terraform/`
provisions exactly that.

## Out of scope

- Correctness of compliance mappings. Control catalogs are seed subsets flagged
  non-authoritative; see ADR 0005 in `basalt-core`.
- Vulnerabilities in boto3, botocore or moto. Report those upstream.
- A check producing a false negative is a bug, not a vulnerability — open an issue.
