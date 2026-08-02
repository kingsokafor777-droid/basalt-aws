# Basalt AWS

[![CI](https://github.com/kingsokafor777-droid/basalt-aws/actions/workflows/ci.yml/badge.svg)](https://github.com/kingsokafor777-droid/basalt-aws/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/basalt-aws.svg)](https://pypi.org/project/basalt-aws/)
[![Python](https://img.shields.io/pypi/pyversions/basalt-aws.svg)](https://pypi.org/project/basalt-aws/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Read-only AWS posture scanner. 17 checks across IAM, S3, CloudTrail and KMS.**

Output is [`basalt-core`](https://github.com/kingsokafor777-droid/basalt-core) findings, so it
converts to SARIF for GitHub Code Scanning, to OCSF for a SIEM or Security Lake, and to
NDJSON for a warehouse — without an adapter in between.

The scanner never writes. Every API it calls is enumerated, surfaced by
`basalt-aws permissions`, and asserted read-only by a test.

---

## Install

```bash
pip install basalt-aws
```

Python 3.10+. Pulls in `basalt-core` and `boto3`.

## Try it without an AWS account

```bash
pip install "basalt-aws[dev]"
python examples/scan_local.py
```

Builds a simulated account with realistic misconfigurations and scans it offline:

```
10 findings, ranked by risk:

   90  critical s3.bucket-public-acl                 acme-prod-exports
   77  critical iam.root-mfa-missing                 root
   60  high     iam.user-mfa-missing                 contractor
   60  high     s3.block-public-access-disabled      acme-prod-exports
   44  critical cloudtrail.no-trail-configured       cloudtrail-config-ca-central-1
   38  medium   iam.password-policy-weak             account-password-policy
   ...
```

Note the ordering: `cloudtrail.no-trail-configured` is CRITICAL severity but scores 44,
below a HIGH at 60. Risk is `severity × exposure × exploitability`, and a missing trail is
internal and hard to exploit directly. Severity says how bad it would be; risk says what to
fix on Monday.

## Scan a real account

```bash
basalt-aws scan --regions ca-central-1 us-east-1
basalt-aws scan --service s3 --format sarif -o results.sarif
basalt-aws scan --fail-on critical            # exit 1 for CI gating
basalt-aws checks                             # the catalogue, no credentials needed
basalt-aws permissions --json                 # least-privilege policy document
```

Credentials come from the standard boto3 chain. Nothing is read from a config file this
package owns.

## The checks

| Service | Rule | Severity | Scope |
|---|---|---|---|
| iam | `iam.root-mfa-missing` | critical | global |
| iam | `iam.root-access-key-present` | critical | global |
| iam | `iam.user-mfa-missing` | high | global |
| iam | `iam.admin-policy-attached` | high | global |
| iam | `iam.access-key-stale` | medium | global |
| iam | `iam.password-policy-weak` | medium | global |
| s3 | `s3.bucket-public-acl` | critical | global |
| s3 | `s3.bucket-public-policy` | critical | global |
| s3 | `s3.block-public-access-disabled` | high | global |
| s3 | `s3.bucket-encryption-disabled` | medium | global |
| s3 | `s3.bucket-versioning-disabled` | medium | global |
| s3 | `s3.bucket-tls-not-enforced` | medium | global |
| cloudtrail | `cloudtrail.no-trail-configured` | critical | regional |
| cloudtrail | `cloudtrail.trail-not-multi-region` | high | regional |
| cloudtrail | `cloudtrail.log-validation-disabled` | medium | regional |
| cloudtrail | `cloudtrail.logs-not-kms-encrypted` | medium | regional |
| kms | `kms.key-rotation-disabled` | medium | regional |

Every check maps to controls in NIST SP 800-53 Rev 5 and the CIS AWS Foundations
Benchmark. A test asserts every declared control id resolves against the `basalt-core`
catalog, so a typo fails CI rather than reaching a compliance report.

Global checks run once per account; regional checks run once per requested region. That
distinction matters — see [ADR 0004](docs/adr/0004-scope-and-error-isolation.md).

## Permissions

```bash
basalt-aws permissions --json > scanner-policy.json
```

The AWS managed policy `arn:aws:iam::aws:policy/SecurityAudit` covers everything.
`terraform/` provisions a dedicated role with only the twenty calls the scanner makes,
gated by an external id:

```bash
cd terraform
terraform apply -var='trusted_principal_arns=["arn:aws:iam::111122223333:role/ci"]' \
                -var='external_id=<random>'
```

## Use as a library

```python
from basalt_aws import AwsScanner
from basalt_core import ScanContext, get_emitter

result = AwsScanner().run(ScanContext(regions=["ca-central-1"]))

for finding in sorted(result.findings, key=lambda f: -f.risk.value):
    print(finding.risk.value, finding.rule_id, finding.resource.urn)

open("results.sarif", "w").write(get_emitter("sarif").emit_json(result))
```

The scanner also registers under the `basalt.scanners` entry point, so `basalt scanners`
lists it once installed and any Basalt tool can discover it without importing this package.

## In CI

```yaml
- run: pip install basalt-aws
- run: basalt-aws scan --format sarif -o results.sarif --fail-on critical
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

## Writing a check

```python
from typing import Iterable
from basalt_core import Evidence, Finding, Remediation, Severity
from basalt_aws import Check, Scope, register


@register
class BucketLoggingDisabled(Check):
    rule_id = "s3.bucket-logging-disabled"
    title = "S3 bucket has no server access logging"
    description = "Object-level access is not recorded, so exfiltration leaves no trace."
    severity = Severity.LOW
    control_ids = ("nist-800-53-r5:AU-2",)
    service = "s3"
    scope = Scope.GLOBAL

    def run(self, ctx, region=None) -> Iterable[Finding]:
        for bucket in ctx.client("s3").list_buckets()["Buckets"]:
            ...
```

Metadata is declared on the class so the catalogue is introspectable without running a
scan, and findings are built through `self.finding()` so they cannot drift from it. See
[ADR 0001](docs/adr/0001-check-registry-and-declarative-metadata.md).

## Design decisions

| # | Decision |
|---|---|
| [0001](docs/adr/0001-check-registry-and-declarative-metadata.md) | Checks as classes with declarative metadata |
| [0002](docs/adr/0002-moto-for-tests.md) | Test against moto, not hand-written mocks |
| [0003](docs/adr/0003-read-only-by-construction.md) | Read-only by construction |
| [0004](docs/adr/0004-scope-and-error-isolation.md) | Check scope, and errors that do not discard findings |

## Scope

**In scope:** read-only posture checks for IAM, S3, CloudTrail and KMS.

**Deliberately out of scope:** remediation (emitted as data for `basalt-agent` to apply
through a reviewed PR), scheduling, storage, and notification. EC2, VPC, RDS and
GuardDuty are not covered yet — the four services here were chosen because they carry the
highest-severity misconfigurations in most accounts.

**Known limitation:** the CIS control mappings inherited from `basalt-core` are seed
subsets flagged non-authoritative. Pin the official benchmark revision before using this
output for an audit.

## Development

```bash
git clone https://github.com/kingsokafor777-droid/basalt-aws
cd basalt-aws
make install
make check
```

Tests run offline against moto in about ten seconds, with no credentials and no AWS
account. Fixtures actively unset `AWS_PROFILE` so a developer's ambient session cannot be
reached by accident.

## Security

This scanner is read-only, but its **output is sensitive** — it is a map of where your
weaknesses are. Do not commit scan results to a public repository. See
[SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
