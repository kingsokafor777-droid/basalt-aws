"""Scan a simulated AWS account and print the findings.

Runs entirely offline against moto, so it needs no credentials and touches no real
account. This is the fastest way to see what basalt-aws output looks like.

    python examples/scan_local.py
"""

from __future__ import annotations

import json
import os

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "ca-central-1")

import boto3
from basalt_core import ScanContext, get_emitter
from moto import mock_aws

from basalt_aws import AwsScanner

REGION = "ca-central-1"


def seed() -> None:
    """Create an account with realistic, deliberate misconfigurations."""
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(
        Bucket="acme-prod-exports",
        CreateBucketConfiguration={"LocationConstraint": REGION},
    )
    s3.put_bucket_acl(Bucket="acme-prod-exports", ACL="public-read")

    iam = boto3.client("iam", region_name=REGION)
    iam.create_user(UserName="contractor")
    iam.create_login_profile(UserName="contractor", Password="Hunter2-Hunter2")
    iam.update_account_password_policy(MinimumPasswordLength=8)

    kms = boto3.client("kms", region_name=REGION)
    kms.create_key(Description="prod-data-key")


def main() -> None:
    with mock_aws():
        seed()
        result = AwsScanner().run(ScanContext(regions=[REGION]))

        print(f"\n{len(result.findings)} findings, ranked by risk:\n")
        for finding in sorted(result.findings, key=lambda f: -f.risk.value):
            print(
                f"  {finding.risk.value:>3}  {finding.severity.value:<8} "
                f"{finding.rule_id:<36} {finding.resource.name}"
            )

        print(f"\n  severity counts: {result.severity_counts()}")
        print(f"  max risk: {result.max_risk()}")

        sarif = json.loads(get_emitter("sarif").emit_json(result))
        print(f"  sarif: {len(sarif['runs'][0]['results'])} results ready for code scanning\n")


if __name__ == "__main__":
    main()
