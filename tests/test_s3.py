from __future__ import annotations

import json

from basalt_core import Severity

from basalt_aws.checks.s3 import (
    BlockPublicAccessDisabled,
    BucketEncryptionDisabled,
    BucketPublicAcl,
    BucketPublicPolicy,
    BucketTlsNotEnforced,
    BucketVersioningDisabled,
    _denies_insecure_transport,
    _policy_is_public,
)
from tests.conftest import REGION, run_check, secure_bucket

PUBLIC_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::b/*",
        }
    ],
}


class TestPublicAcl:
    def test_private_bucket_passes(self, ctx, bucket):
        assert run_check(BucketPublicAcl, ctx) == []

    def test_public_read_acl_is_critical(self, ctx, s3, bucket):
        s3.put_bucket_acl(Bucket=bucket, ACL="public-read")
        findings = run_check(BucketPublicAcl, ctx)
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
        assert findings[0].risk.value == 90

    def test_finding_records_the_bucket_region(self, ctx, s3, bucket):
        s3.put_bucket_acl(Bucket=bucket, ACL="public-read")
        assert run_check(BucketPublicAcl, ctx)[0].resource.region == REGION

    def test_remediation_includes_an_iac_patch(self, ctx, s3, bucket):
        s3.put_bucket_acl(Bucket=bucket, ACL="public-read")
        patch = run_check(BucketPublicAcl, ctx)[0].remediation.iac_patch
        assert "aws_s3_bucket_public_access_block" in patch
        assert bucket in patch


class TestPublicPolicyDetection:
    def test_wildcard_principal_is_public(self):
        assert _policy_is_public(PUBLIC_POLICY) is True

    def test_conditioned_wildcard_is_not_public(self):
        doc = json.loads(json.dumps(PUBLIC_POLICY))
        doc["Statement"][0]["Condition"] = {"StringEquals": {"aws:PrincipalOrgID": "o-x"}}
        assert _policy_is_public(doc) is False

    def test_aws_wildcard_form_is_public(self):
        assert (
            _policy_is_public(
                {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:*"}]}
            )
            is True
        )

    def test_scoped_principal_is_not_public(self):
        assert (
            _policy_is_public(
                {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:root"}}]}
            )
            is False
        )

    def test_bucket_without_policy_is_ignored(self, ctx, bucket):
        assert run_check(BucketPublicPolicy, ctx) == []

    def test_public_policy_is_flagged(self, ctx, s3, bucket):
        s3.put_bucket_policy(
            Bucket=bucket,
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": f"arn:aws:s3:::{bucket}/*",
                        }
                    ],
                }
            ),
        )
        findings = run_check(BucketPublicPolicy, ctx)
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL


class TestBlockPublicAccess:
    def test_unconfigured_bucket_reports_all_four(self, ctx, bucket):
        findings = run_check(BlockPublicAccessDisabled, ctx)
        assert len(findings) == 1
        assert len(findings[0].evidence[0].observed) == 4

    def test_fully_enabled_passes(self, ctx, s3):
        secure_bucket(s3)
        assert run_check(BlockPublicAccessDisabled, ctx) == []

    def test_partial_configuration_reports_the_gap(self, ctx, s3, bucket):
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        findings = run_check(BlockPublicAccessDisabled, ctx)
        assert findings[0].evidence[0].observed == ["BlockPublicPolicy", "RestrictPublicBuckets"]


class TestEncryption:
    def test_unencrypted_bucket_is_flagged(self, ctx, bucket):
        assert len(run_check(BucketEncryptionDisabled, ctx)) == 1

    def test_encrypted_bucket_passes(self, ctx, s3):
        secure_bucket(s3)
        assert run_check(BucketEncryptionDisabled, ctx) == []


class TestVersioning:
    def test_unversioned_bucket_is_flagged(self, ctx, bucket):
        findings = run_check(BucketVersioningDisabled, ctx)
        assert len(findings) == 1
        assert findings[0].evidence[0].observed == "not configured"

    def test_versioned_bucket_passes(self, ctx, s3):
        secure_bucket(s3)
        assert run_check(BucketVersioningDisabled, ctx) == []

    def test_suspended_versioning_is_flagged(self, ctx, s3, bucket):
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Suspended"})
        assert run_check(BucketVersioningDisabled, ctx)[0].evidence[0].observed == "Suspended"


class TestTlsEnforcement:
    def test_detects_deny_on_secure_transport(self):
        assert (
            _denies_insecure_transport(
                {
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                        }
                    ]
                }
            )
            is True
        )

    def test_allow_statement_does_not_count(self):
        assert (
            _denies_insecure_transport(
                {
                    "Statement": [
                        {"Effect": "Allow", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
                    ]
                }
            )
            is False
        )

    def test_bool_if_exists_is_accepted(self):
        assert (
            _denies_insecure_transport(
                {
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Condition": {"BoolIfExists": {"aws:SecureTransport": "false"}},
                        }
                    ]
                }
            )
            is True
        )

    def test_bucket_without_policy_is_flagged(self, ctx, bucket):
        assert len(run_check(BucketTlsNotEnforced, ctx)) == 1

    def test_hardened_bucket_passes(self, ctx, s3):
        secure_bucket(s3)
        assert run_check(BucketTlsNotEnforced, ctx) == []


class TestFullyHardenedBucket:
    def test_produces_no_s3_findings_at_all(self, ctx, s3):
        secure_bucket(s3)
        checks = [
            BucketPublicAcl,
            BucketPublicPolicy,
            BlockPublicAccessDisabled,
            BucketEncryptionDisabled,
            BucketVersioningDisabled,
            BucketTlsNotEnforced,
        ]
        assert [f for c in checks for f in run_check(c, ctx)] == []
