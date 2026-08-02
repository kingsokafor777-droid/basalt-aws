"""Test fixtures.

Every test runs against `moto`, which implements the real boto3 API surface in-process.
That means the checks exercise genuine request signing, pagination and error codes rather
than hand-written mocks, so a check that passes here fails for real reasons, not because
a mock was written to agree with it.

No test touches a real AWS account. The dummy credentials below are set explicitly so
that an ambient profile on a developer machine can never be reached by accident.
"""

from __future__ import annotations

import json
import os

import boto3
import pytest
from basalt_core import ScanContext
from moto import mock_aws

from basalt_aws.client import AwsContext

REGION = "ca-central-1"
ACCOUNT_ID = "123456789012"


@pytest.fixture(autouse=True)
def _dummy_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guarantee no test can reach a real account, whatever the developer's env holds."""
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SECURITY_TOKEN": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": REGION,
    }.items():
        monkeypatch.setenv(key, value)
    for key in ("AWS_PROFILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE"):
        monkeypatch.delenv(key, raising=False)
    os.environ.setdefault("MOTO_ACCOUNT_ID", ACCOUNT_ID)


@pytest.fixture
def aws():
    """Activate moto for the duration of a test."""
    with mock_aws():
        yield


@pytest.fixture
def ctx(aws) -> AwsContext:
    """An AwsContext bound to the mocked account."""
    return AwsContext.build(ScanContext(regions=[REGION]))


@pytest.fixture
def iam(aws):
    return boto3.client("iam", region_name=REGION)


@pytest.fixture
def s3(aws):
    return boto3.client("s3", region_name=REGION)


@pytest.fixture
def cloudtrail(aws):
    return boto3.client("cloudtrail", region_name=REGION)


@pytest.fixture
def kms(aws):
    return boto3.client("kms", region_name=REGION)


@pytest.fixture
def bucket(s3) -> str:
    """A bucket with no hardening applied. The baseline every S3 test starts from."""
    name = "basalt-test-bucket"
    s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": REGION})
    return name


def secure_bucket(s3, name: str = "basalt-secure-bucket") -> str:
    """A bucket configured to pass every S3 check. Used to assert the absence of findings."""
    s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": REGION})
    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket=name,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_policy(
        Bucket=name,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DenyInsecureTransport",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": [f"arn:aws:s3:::{name}", f"arn:aws:s3:::{name}/*"],
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    }
                ],
            }
        ),
    )
    return name


def run_check(check_cls, ctx: AwsContext, region: str | None = None) -> list:
    """Run one check and collect its findings."""
    return list(check_cls().run(ctx, region))


def rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}
