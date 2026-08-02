from __future__ import annotations

from basalt_core import Severity
from tests.conftest import REGION, run_check

from basalt_aws.checks.cloudtrail import (
    NoTrailConfigured,
    TrailNotEncrypted,
    TrailNotMultiRegion,
    TrailValidationDisabled,
)
from basalt_aws.checks.kms import KeyRotationDisabled


def _trail_bucket(s3, name="basalt-trail-logs"):
    s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": REGION})
    import json

    s3.put_bucket_policy(
        Bucket=name,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AWSCloudTrailAclCheck",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{name}",
                    },
                    {
                        "Sid": "AWSCloudTrailWrite",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{name}/*",
                    },
                ],
            }
        ),
    )
    return name


class TestNoTrailConfigured:
    def test_account_without_a_trail_is_critical(self, ctx):
        findings = run_check(NoTrailConfigured, ctx, REGION)
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    def test_account_with_a_trail_passes(self, ctx, s3, cloudtrail):
        cloudtrail.create_trail(Name="primary", S3BucketName=_trail_bucket(s3))
        assert run_check(NoTrailConfigured, ctx, REGION) == []


class TestTrailNotMultiRegion:
    def test_single_region_trail_is_flagged(self, ctx, s3, cloudtrail):
        cloudtrail.create_trail(
            Name="single", S3BucketName=_trail_bucket(s3), IsMultiRegionTrail=False
        )
        findings = run_check(TrailNotMultiRegion, ctx, REGION)
        assert len(findings) == 1
        assert findings[0].severity is Severity.HIGH

    def test_multi_region_trail_passes(self, ctx, s3, cloudtrail):
        cloudtrail.create_trail(
            Name="everywhere", S3BucketName=_trail_bucket(s3), IsMultiRegionTrail=True
        )
        assert run_check(TrailNotMultiRegion, ctx, REGION) == []


class TestTrailValidation:
    def test_disabled_validation_is_flagged(self, ctx, s3, cloudtrail):
        cloudtrail.create_trail(Name="unvalidated", S3BucketName=_trail_bucket(s3))
        findings = run_check(TrailValidationDisabled, ctx, REGION)
        assert len(findings) == 1
        assert findings[0].evidence[0].expected is True

    def test_enabled_validation_passes(self, ctx, s3, cloudtrail):
        cloudtrail.create_trail(
            Name="validated", S3BucketName=_trail_bucket(s3), EnableLogFileValidation=True
        )
        assert run_check(TrailValidationDisabled, ctx, REGION) == []


class TestTrailEncryption:
    def test_unencrypted_trail_is_flagged(self, ctx, s3, cloudtrail):
        cloudtrail.create_trail(Name="plain", S3BucketName=_trail_bucket(s3))
        assert len(run_check(TrailNotEncrypted, ctx, REGION)) == 1

    def test_kms_encrypted_trail_passes(self, ctx, s3, cloudtrail, kms):
        key = kms.create_key(Description="trail")["KeyMetadata"]["KeyId"]
        cloudtrail.create_trail(Name="encrypted", S3BucketName=_trail_bucket(s3), KmsKeyId=key)
        assert run_check(TrailNotEncrypted, ctx, REGION) == []


class TestKmsRotation:
    def test_key_without_rotation_is_flagged(self, ctx, kms):
        kms.create_key(Description="unrotated")
        findings = run_check(KeyRotationDisabled, ctx, REGION)
        assert len(findings) == 1
        assert findings[0].severity is Severity.MEDIUM

    def test_rotating_key_passes(self, ctx, kms):
        key = kms.create_key(Description="rotated")["KeyMetadata"]["KeyId"]
        kms.enable_key_rotation(KeyId=key)
        assert run_check(KeyRotationDisabled, ctx, REGION) == []

    def test_disabled_key_is_ignored(self, ctx, kms):
        key = kms.create_key(Description="retired")["KeyMetadata"]["KeyId"]
        kms.disable_key(KeyId=key)
        assert run_check(KeyRotationDisabled, ctx, REGION) == []

    def test_asymmetric_key_is_ignored(self, ctx, kms):
        kms.create_key(
            Description="signing",
            KeySpec="RSA_2048",
            KeyUsage="SIGN_VERIFY",
        )
        assert run_check(KeyRotationDisabled, ctx, REGION) == []

    def test_finding_records_the_region(self, ctx, kms):
        kms.create_key(Description="unrotated")
        assert run_check(KeyRotationDisabled, ctx, REGION)[0].resource.region == REGION
