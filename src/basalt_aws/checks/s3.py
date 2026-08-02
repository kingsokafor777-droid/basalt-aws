"""S3 checks: public exposure, encryption, versioning, transport security and logging.

The bucket listing is global, but every per-bucket call must be made against the bucket's
own region or S3 returns a redirect. :meth:`_bucket_region` resolves that once per bucket.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from basalt_core import (
    Evidence,
    Exploitability,
    Exposure,
    Finding,
    Remediation,
    ResourceRef,
    Severity,
)
from botocore.exceptions import BotoCoreError, ClientError

from ..client import AwsContext, is_access_denied
from ..registry import Check, Scope, register

__all__ = [
    "BucketPublicAcl",
    "BucketPublicPolicy",
    "BlockPublicAccessDisabled",
    "BucketEncryptionDisabled",
    "BucketVersioningDisabled",
    "BucketTlsNotEnforced",
]

_PUBLIC_ACL_URIS = frozenset(
    {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
)


class _S3Check(Check):
    """Shared plumbing for per-bucket checks."""

    service = "s3"
    scope = Scope.GLOBAL

    def _buckets(self, ctx: AwsContext) -> list[dict[str, Any]]:
        try:
            return list(ctx.client("s3").list_buckets().get("Buckets", []))
        except (BotoCoreError, ClientError) as exc:
            if is_access_denied(exc):
                return []
            raise

    def _bucket_region(self, ctx: AwsContext, bucket: str) -> str:
        """Resolve a bucket's region. ``None`` from the API means us-east-1."""
        try:
            location = ctx.client("s3").get_bucket_location(Bucket=bucket)
            return location.get("LocationConstraint") or "us-east-1"
        except (BotoCoreError, ClientError):
            return "us-east-1"

    def _ref(self, ctx: AwsContext, bucket: str) -> ResourceRef:
        return self.resource(
            ctx,
            "AWS::S3::Bucket",
            f"arn:{ctx.partition}:s3:::{bucket}",
            name=bucket,
            region=self._bucket_region(ctx, bucket),
        )


@register
class BucketPublicAcl(_S3Check):
    rule_id = "s3.bucket-public-acl"
    title = "S3 bucket ACL grants access to everyone"
    description = (
        "The bucket ACL grants a permission to AllUsers or AuthenticatedUsers, exposing "
        "objects to anonymous or any-AWS-principal callers respectively."
    )
    severity = Severity.CRITICAL
    exposure = Exposure.PUBLIC
    exploitability = Exploitability.TRIVIAL
    control_ids = ("cis-aws:storage.bucket-public-access", "nist-800-53-r5:AC-3")
    tags = ("storage", "data-exposure")

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        s3 = ctx.client("s3")
        for bucket in self._buckets(ctx):
            name = bucket["Name"]
            try:
                acl = s3.get_bucket_acl(Bucket=name)
            except (BotoCoreError, ClientError) as exc:
                if is_access_denied(exc):
                    continue
                raise
            public = [
                f"{g['Grantee'].get('URI', '').rsplit('/', 1)[-1]}:{g['Permission']}"
                for g in acl.get("Grants", [])
                if g.get("Grantee", {}).get("URI") in _PUBLIC_ACL_URIS
            ]
            if not public:
                continue
            yield self.finding(
                resource=self._ref(ctx, name),
                description=f"Bucket {name} grants {', '.join(public)} through its ACL.",
                evidence=[
                    Evidence(
                        description="Public ACL grants",
                        observed=public,
                        expected="no grants to AllUsers or AuthenticatedUsers",
                        source="s3:GetBucketAcl",
                    )
                ],
                remediation=Remediation(
                    summary=(
                        "Remove the public grants and enable Block Public Access on the bucket."
                    ),
                    cli_command=f"aws s3api put-bucket-acl --bucket {name} --acl private",
                    iac_patch=(
                        'resource "aws_s3_bucket_public_access_block" "this" {\n'
                        f'  bucket                  = "{name}"\n'
                        "  block_public_acls       = true\n"
                        "  ignore_public_acls      = true\n"
                        "  block_public_policy     = true\n"
                        "  restrict_public_buckets = true\n"
                        "}"
                    ),
                ),
            )


def _policy_is_public(document: dict[str, Any]) -> bool:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        wildcard = principal == "*" or (
            isinstance(principal, dict) and principal.get("AWS") in ("*", ["*"])
        )
        # A condition -- org id, VPC endpoint, source IP -- is what makes a wildcard
        # principal defensible. An unconditioned wildcard is the actual defect.
        if wildcard and "Condition" not in statement:
            return True
    return False


@register
class BucketPublicPolicy(_S3Check):
    rule_id = "s3.bucket-public-policy"
    title = "S3 bucket policy allows unconditional public access"
    description = (
        "The bucket policy contains an Allow statement with a wildcard principal and no "
        "condition, so any caller on the internet can perform the listed actions."
    )
    severity = Severity.CRITICAL
    exposure = Exposure.PUBLIC
    exploitability = Exploitability.TRIVIAL
    control_ids = ("cis-aws:storage.bucket-public-access", "nist-800-53-r5:AC-3")
    tags = ("storage", "data-exposure")

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        s3 = ctx.client("s3")
        for bucket in self._buckets(ctx):
            name = bucket["Name"]
            try:
                raw = s3.get_bucket_policy(Bucket=name)["Policy"]
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in {"NoSuchBucketPolicy", "NoSuchBucket"} or is_access_denied(exc):
                    continue
                raise
            except BotoCoreError:
                continue
            document = json.loads(raw) if isinstance(raw, str) else raw
            if not _policy_is_public(document):
                continue
            yield self.finding(
                resource=self._ref(ctx, name),
                description=(
                    f"Bucket {name} has a policy statement allowing "
                    f"Principal '*' without a condition."
                ),
                evidence=[
                    Evidence(
                        description="Wildcard principal in bucket policy",
                        observed='Principal: "*"',
                        expected="a scoped principal, or a condition restricting access",
                        source="s3:GetBucketPolicy",
                    )
                ],
                remediation=Remediation(
                    summary=(
                        "Scope the principal, or add a condition such as aws:SourceVpce or "
                        "aws:PrincipalOrgID. Use CloudFront with OAC for public content."
                    ),
                ),
            )


@register
class BlockPublicAccessDisabled(_S3Check):
    rule_id = "s3.block-public-access-disabled"
    title = "S3 Block Public Access is not fully enabled on the bucket"
    description = (
        "Block Public Access is the backstop that prevents a future ACL or policy change "
        "from exposing the bucket. Without all four settings it can be made public by a "
        "single API call."
    )
    severity = Severity.HIGH
    exposure = Exposure.PUBLIC
    exploitability = Exploitability.MODERATE
    control_ids = ("cis-aws:storage.bucket-public-access", "nist-800-53-r5:CM-6")
    tags = ("storage", "defense-in-depth")

    _SETTINGS = (
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    )

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        s3 = ctx.client("s3")
        for bucket in self._buckets(ctx):
            name = bucket["Name"]
            try:
                config = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code == "NoSuchPublicAccessBlockConfiguration":
                    config = {}
                elif is_access_denied(exc):
                    continue
                else:
                    raise
            except BotoCoreError:
                continue
            disabled = [s for s in self._SETTINGS if not config.get(s, False)]
            if not disabled:
                continue
            yield self.finding(
                resource=self._ref(ctx, name),
                description=(
                    f"Bucket {name} has {len(disabled)} of 4 Block Public Access settings "
                    f"disabled: {', '.join(disabled)}."
                ),
                evidence=[
                    Evidence(
                        description="Disabled Block Public Access settings",
                        observed=disabled,
                        expected="all four enabled",
                        source="s3:GetPublicAccessBlock",
                    )
                ],
                remediation=Remediation(
                    summary=(
                        "Enable all four Block Public Access settings "
                        "on the bucket and the account."
                    ),
                    cli_command=(
                        f"aws s3api put-public-access-block --bucket {name} "
                        "--public-access-block-configuration BlockPublicAcls=true,"
                        "IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                    ),
                ),
            )


@register
class BucketEncryptionDisabled(_S3Check):
    rule_id = "s3.bucket-encryption-disabled"
    title = "S3 bucket has no default encryption configuration"
    description = (
        "Objects written without an explicit encryption header are stored unencrypted, "
        "leaving protection dependent on every writer behaving correctly."
    )
    severity = Severity.MEDIUM
    exposure = Exposure.INTERNAL
    exploitability = Exploitability.DIFFICULT
    control_ids = ("cis-aws:storage.bucket-encryption", "nist-800-53-r5:SC-28")
    tags = ("storage", "encryption")

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        s3 = ctx.client("s3")
        for bucket in self._buckets(ctx):
            name = bucket["Name"]
            try:
                s3.get_bucket_encryption(Bucket=name)
                continue
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code != "ServerSideEncryptionConfigurationNotFoundError":
                    if is_access_denied(exc):
                        continue
                    raise
            except BotoCoreError:
                continue
            yield self.finding(
                resource=self._ref(ctx, name),
                description=f"Bucket {name} has no default server-side encryption configured.",
                evidence=[
                    Evidence(
                        description="Default encryption configuration",
                        observed=None,
                        expected="SSE-S3 or SSE-KMS",
                        source="s3:GetBucketEncryption",
                    )
                ],
                remediation=Remediation(
                    summary=(
                        "Enable default encryption, preferring SSE-KMS with a customer-managed key."
                    ),
                    cli_command=(
                        f"aws s3api put-bucket-encryption --bucket {name} "
                        '--server-side-encryption-configuration \'{"Rules":[{"ApplyServerSide'
                        'EncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}\''
                    ),
                ),
            )


@register
class BucketVersioningDisabled(_S3Check):
    rule_id = "s3.bucket-versioning-disabled"
    title = "S3 bucket versioning is not enabled"
    description = (
        "Without versioning, an overwrite or delete is unrecoverable. This is the control "
        "that makes ransomware and accidental deletion survivable."
    )
    severity = Severity.MEDIUM
    exposure = Exposure.INTERNAL
    exploitability = Exploitability.DIFFICULT
    control_ids = ("nist-800-53-r5:CP-9",)
    tags = ("storage", "resilience")

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        s3 = ctx.client("s3")
        for bucket in self._buckets(ctx):
            name = bucket["Name"]
            try:
                status = s3.get_bucket_versioning(Bucket=name).get("Status")
            except (BotoCoreError, ClientError) as exc:
                if is_access_denied(exc):
                    continue
                raise
            if status == "Enabled":
                continue
            yield self.finding(
                resource=self._ref(ctx, name),
                description=f"Bucket {name} has versioning {status or 'not configured'}.",
                evidence=[
                    Evidence(
                        description="Versioning status",
                        observed=status or "not configured",
                        expected="Enabled",
                        source="s3:GetBucketVersioning",
                    )
                ],
                remediation=Remediation(
                    summary=(
                        "Enable versioning, and add a lifecycle rule to expire noncurrent versions."
                    ),
                    cli_command=(
                        f"aws s3api put-bucket-versioning --bucket {name} "
                        "--versioning-configuration Status=Enabled"
                    ),
                ),
            )


def _denies_insecure_transport(document: dict[str, Any]) -> bool:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if statement.get("Effect") != "Deny":
            continue
        condition = statement.get("Condition", {})
        for operator in ("Bool", "BoolIfExists"):
            value = condition.get(operator, {}).get("aws:SecureTransport")
            if value in (False, "false", "False", ["false"]):
                return True
    return False


@register
class BucketTlsNotEnforced(_S3Check):
    rule_id = "s3.bucket-tls-not-enforced"
    title = "S3 bucket policy does not deny plaintext requests"
    description = (
        "Without a Deny on aws:SecureTransport false, the bucket accepts unencrypted HTTP "
        "requests, exposing object contents and credentials to network observers."
    )
    severity = Severity.MEDIUM
    exposure = Exposure.EXTERNAL
    exploitability = Exploitability.DIFFICULT
    control_ids = ("cis-aws:storage.bucket-tls-only", "nist-800-53-r5:SC-8")
    tags = ("storage", "transport")

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        s3 = ctx.client("s3")
        for bucket in self._buckets(ctx):
            name = bucket["Name"]
            document: dict[str, Any] = {}
            try:
                raw = s3.get_bucket_policy(Bucket=name)["Policy"]
                document = json.loads(raw) if isinstance(raw, str) else raw
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if is_access_denied(exc):
                    continue
                if code not in {"NoSuchBucketPolicy", "NoSuchBucket"}:
                    raise
            except BotoCoreError:
                continue
            if _denies_insecure_transport(document):
                continue
            yield self.finding(
                resource=self._ref(ctx, name),
                description=f"Bucket {name} has no policy statement denying non-TLS requests.",
                evidence=[
                    Evidence(
                        description="Deny on aws:SecureTransport",
                        observed="absent",
                        expected="Deny when aws:SecureTransport is false",
                        source="s3:GetBucketPolicy",
                    )
                ],
                remediation=Remediation(
                    summary="Add a Deny statement for requests where aws:SecureTransport is false.",
                    iac_patch=(
                        "{\n"
                        '  "Effect": "Deny",\n'
                        '  "Principal": "*",\n'
                        '  "Action": "s3:*",\n'
                        f'  "Resource": ["arn:aws:s3:::{name}", "arn:aws:s3:::{name}/*"],\n'
                        '  "Condition": {"Bool": {"aws:SecureTransport": "false"}}\n'
                        "}"
                    ),
                ),
            )
