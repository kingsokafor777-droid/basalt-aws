"""KMS checks: rotation of customer-managed keys.

AWS-managed keys rotate on their own schedule and are not actionable, so they are
excluded. Only keys whose manager is CUSTOMER are evaluated.
"""

from __future__ import annotations

from collections.abc import Iterable

from basalt_core import Evidence, Exploitability, Exposure, Finding, Remediation, Severity
from botocore.exceptions import BotoCoreError, ClientError

from ..client import AwsContext, is_access_denied
from ..registry import Check, Scope, register

__all__ = ["KeyRotationDisabled"]


@register
class KeyRotationDisabled(Check):
    rule_id = "kms.key-rotation-disabled"
    title = "Customer-managed KMS key does not have automatic rotation enabled"
    description = (
        "Annual rotation bounds the volume of ciphertext protected by any single key "
        "version, limiting the blast radius if key material is ever compromised."
    )
    severity = Severity.MEDIUM
    exposure = Exposure.INTERNAL
    exploitability = Exploitability.DIFFICULT
    control_ids = ("cis-aws:logging.kms-key-rotation", "nist-800-53-r5:SC-12")
    service = "kms"
    scope = Scope.REGIONAL
    tags = ("encryption", "key-management")

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        kms = ctx.client("kms", region)
        try:
            pages = ctx.paginate("kms", "list_keys", region)
        except (BotoCoreError, ClientError) as exc:
            if is_access_denied(exc):
                return
            raise

        for page in pages:
            for entry in page.get("Keys", []):
                key_id = entry["KeyId"]
                try:
                    metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                except (BotoCoreError, ClientError) as exc:
                    if is_access_denied(exc):
                        continue
                    raise

                if metadata.get("KeyManager") != "CUSTOMER":
                    continue
                if metadata.get("KeyState") != "Enabled":
                    continue
                # Rotation applies only to symmetric keys with AWS-generated material.
                if metadata.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                    continue
                if metadata.get("Origin", "AWS_KMS") != "AWS_KMS":
                    continue

                try:
                    enabled = kms.get_key_rotation_status(KeyId=key_id).get(
                        "KeyRotationEnabled", False
                    )
                except (BotoCoreError, ClientError) as exc:
                    if is_access_denied(exc):
                        continue
                    raise
                if enabled:
                    continue

                yield self.finding(
                    resource=self.resource(
                        ctx,
                        "AWS::KMS::Key",
                        metadata.get("Arn", key_id),
                        name=metadata.get("Description") or key_id,
                        region=region,
                    ),
                    description=f"Customer-managed key {key_id} does not rotate automatically.",
                    evidence=[
                        Evidence(
                            description="KeyRotationEnabled",
                            observed=False,
                            expected=True,
                            source="kms:GetKeyRotationStatus",
                        )
                    ],
                    remediation=Remediation(
                        summary="Enable automatic annual rotation for the key.",
                        cli_command=f"aws kms enable-key-rotation --key-id {key_id}",
                    ),
                )
