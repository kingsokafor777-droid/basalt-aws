"""CloudTrail checks: trail existence, coverage, integrity and log encryption.

Without CloudTrail there is no record of who did what, so a compromise cannot be scoped
after the fact. These checks are regional, but a multi-region trail is discoverable from
any region, which is why :class:`NoTrailConfigured` looks account-wide before reporting.
"""

from __future__ import annotations

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
    "NoTrailConfigured",
    "TrailNotMultiRegion",
    "TrailValidationDisabled",
    "TrailNotEncrypted",
]


def _trails(ctx: AwsContext, region: str | None) -> list[dict[str, Any]]:
    try:
        response = ctx.client("cloudtrail", region).describe_trails(includeShadowTrails=False)
    except (BotoCoreError, ClientError) as exc:
        if is_access_denied(exc):
            return []
        raise
    return list(response.get("trailList", []))


class _TrailCheck(Check):
    service = "cloudtrail"
    scope = Scope.REGIONAL

    def _ref(self, ctx: AwsContext, trail: dict[str, Any], region: str | None) -> ResourceRef:
        return self.resource(
            ctx,
            "AWS::CloudTrail::Trail",
            trail.get("TrailARN") or ctx.arn("cloudtrail", f"trail/{trail['Name']}", region or ""),
            name=trail.get("Name"),
            region=trail.get("HomeRegion") or region,
        )


@register
class NoTrailConfigured(_TrailCheck):
    rule_id = "cloudtrail.no-trail-configured"
    title = "No CloudTrail trail is configured in the region"
    description = (
        "Management events are not being recorded. Without a trail there is no "
        "authoritative record of API activity, so an intrusion cannot be reconstructed "
        "and no detection built on CloudTrail can fire."
    )
    severity = Severity.CRITICAL
    exposure = Exposure.INTERNAL
    exploitability = Exploitability.DIFFICULT
    control_ids = ("cis-aws:logging.cloudtrail-multi-region", "nist-800-53-r5:AU-12")
    tags = ("logging", "detection")

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        if _trails(ctx, region):
            return
        yield self.finding(
            # The subject is the region's logging configuration, not a trail -- there is
            # no trail to point at. Inventing a wildcard ARN would create a resource that
            # does not exist and cannot be looked up.
            resource=self.resource(
                ctx,
                "AWS::CloudTrail::Configuration",
                f"{ctx.account_id}/{region or 'default'}/cloudtrail",
                name=f"cloudtrail-config-{region or 'default'}",
                region=region,
            ),
            description=f"No CloudTrail trail is configured in {region or 'the target region'}.",
            evidence=[
                Evidence(
                    description="Trails visible in region",
                    observed=0,
                    expected="at least one multi-region trail",
                    source="cloudtrail:DescribeTrails",
                )
            ],
            remediation=Remediation(
                summary=(
                    "Create one organisation-wide multi-region trail delivering to a "
                    "dedicated, access-restricted log archive account."
                ),
                references=[
                    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/"
                    "cloudtrail-create-and-update-a-trail.html"
                ],
            ),
        )


@register
class TrailNotMultiRegion(_TrailCheck):
    rule_id = "cloudtrail.trail-not-multi-region"
    title = "CloudTrail trail is not multi-region"
    description = (
        "A single-region trail leaves every other region unlogged. Attackers routinely "
        "operate in unused regions precisely because they are unmonitored."
    )
    severity = Severity.HIGH
    exposure = Exposure.INTERNAL
    exploitability = Exploitability.DIFFICULT
    control_ids = ("cis-aws:logging.cloudtrail-multi-region", "nist-800-53-r5:AU-2")
    tags = ("logging", "coverage")

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        for trail in _trails(ctx, region):
            if trail.get("IsMultiRegionTrail"):
                continue
            yield self.finding(
                resource=self._ref(ctx, trail, region),
                description=(f"Trail {trail.get('Name')} records events in only one region."),
                evidence=[
                    Evidence(
                        description="IsMultiRegionTrail",
                        observed=False,
                        expected=True,
                        source="cloudtrail:DescribeTrails",
                    )
                ],
                remediation=Remediation(
                    summary=(
                        "Convert the trail to multi-region so that "
                        "activity in every region is captured."
                    ),
                    cli_command=(
                        "aws cloudtrail update-trail "
                        f"--name {trail.get('Name')} --is-multi-region-trail"
                    ),
                ),
            )


@register
class TrailValidationDisabled(_TrailCheck):
    rule_id = "cloudtrail.log-validation-disabled"
    title = "CloudTrail log file validation is disabled"
    description = (
        "Without validation there is no cryptographic evidence that delivered log files "
        "are unmodified, so tampered or deleted logs cannot be distinguished from "
        "legitimate ones during an investigation."
    )
    severity = Severity.MEDIUM
    exposure = Exposure.INTERNAL
    exploitability = Exploitability.DIFFICULT
    control_ids = ("cis-aws:logging.cloudtrail-validation", "nist-800-53-r5:AU-9")
    tags = ("logging", "integrity")

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        for trail in _trails(ctx, region):
            if trail.get("LogFileValidationEnabled"):
                continue
            yield self.finding(
                resource=self._ref(ctx, trail, region),
                description=(f"Trail {trail.get('Name')} does not produce digest files."),
                evidence=[
                    Evidence(
                        description="LogFileValidationEnabled",
                        observed=False,
                        expected=True,
                        source="cloudtrail:DescribeTrails",
                    )
                ],
                remediation=Remediation(
                    summary=(
                        "Enable log file validation so delivered "
                        "logs can be verified against digests."
                    ),
                    cli_command=(
                        "aws cloudtrail update-trail "
                        f"--name {trail.get('Name')} --enable-log-file-validation"
                    ),
                ),
            )


@register
class TrailNotEncrypted(_TrailCheck):
    rule_id = "cloudtrail.logs-not-kms-encrypted"
    title = "CloudTrail logs are not encrypted with a KMS key"
    description = (
        "Logs fall back to SSE-S3, so access is governed only by bucket policy. A KMS "
        "customer-managed key adds a second, independently auditable authorisation step "
        "before audit history can be read."
    )
    severity = Severity.MEDIUM
    exposure = Exposure.INTERNAL
    exploitability = Exploitability.DIFFICULT
    control_ids = ("cis-aws:logging.cloudtrail-encryption", "nist-800-53-r5:SC-28")
    tags = ("logging", "encryption")

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        for trail in _trails(ctx, region):
            if trail.get("KmsKeyId"):
                continue
            yield self.finding(
                resource=self._ref(ctx, trail, region),
                description=(
                    f"Trail {trail.get('Name')} has no KMS key configured for log encryption."
                ),
                evidence=[
                    Evidence(
                        description="KmsKeyId",
                        observed=None,
                        expected="a customer-managed KMS key ARN",
                        source="cloudtrail:DescribeTrails",
                    )
                ],
                remediation=Remediation(
                    summary=(
                        "Encrypt the trail with a customer-managed KMS key whose policy grants "
                        "decrypt only to investigators."
                    ),
                    cli_command=(
                        "aws cloudtrail update-trail "
                        f"--name {trail.get('Name')} --kms-key-id <key-arn>"
                    ),
                ),
            )
