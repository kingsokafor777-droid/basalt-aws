"""IAM checks: root account hygiene, MFA coverage, key age and privilege breadth.

IAM is global, so every check here is :attr:`Scope.GLOBAL` and runs once per account
regardless of how many regions were requested.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any

from basalt_core import Evidence, Exploitability, Exposure, Finding, Remediation, Severity
from botocore.exceptions import BotoCoreError, ClientError

from ..client import AwsContext, is_access_denied
from ..registry import Check, Scope, register

__all__ = [
    "RootMfaMissing",
    "RootAccessKeyPresent",
    "UserMfaMissing",
    "AccessKeyStale",
    "AdminPolicyAttached",
    "PasswordPolicyWeak",
]

DEFAULT_MAX_KEY_AGE_DAYS = 90
DEFAULT_MIN_PASSWORD_LENGTH = 14


def _root_arn(ctx: AwsContext) -> str:
    return f"arn:{ctx.partition}:iam::{ctx.account_id}:root"


def _account_summary(ctx: AwsContext) -> dict[str, int]:
    return dict(ctx.client("iam").get_account_summary()["SummaryMap"])


@register
class RootMfaMissing(Check):
    rule_id = "iam.root-mfa-missing"
    title = "MFA is not enabled for the root user"
    description = (
        "The account root user can authenticate with a password alone. The root user "
        "cannot be restricted by IAM policy, so a single credential compromise grants "
        "unrestricted control of the account."
    )
    severity = Severity.CRITICAL
    exposure = Exposure.PUBLIC
    exploitability = Exploitability.MODERATE
    control_ids = ("cis-aws:iam.root-mfa", "nist-800-53-r5:IA-2")
    service = "iam"
    scope = Scope.GLOBAL
    tags = ("identity", "root")

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        summary = _account_summary(ctx)
        if summary.get("AccountMFAEnabled", 0) == 1:
            return
        yield self.finding(
            resource=self.resource(ctx, "AWS::IAM::User", _root_arn(ctx), name="root"),
            evidence=[
                Evidence(
                    description="Account summary MFA flag",
                    observed=summary.get("AccountMFAEnabled", 0),
                    expected=1,
                    source="iam:GetAccountSummary",
                )
            ],
            remediation=Remediation(
                summary="Register a hardware MFA device for the root user and store it securely.",
                console_steps=[
                    "Sign in as the root user",
                    "Open My Security Credentials",
                    "Assign an MFA device, preferring hardware over virtual",
                ],
                references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"],
            ),
        )


@register
class RootAccessKeyPresent(Check):
    rule_id = "iam.root-access-key-present"
    title = "The root user has an active access key"
    description = (
        "Root access keys grant unrestricted programmatic control of the account, cannot "
        "be scoped by policy, and are frequently leaked through committed source or CI "
        "configuration. There is no legitimate steady-state use for one."
    )
    severity = Severity.CRITICAL
    exposure = Exposure.PUBLIC
    exploitability = Exploitability.TRIVIAL
    control_ids = ("cis-aws:iam.root-access-key", "nist-800-53-r5:AC-6")
    service = "iam"
    scope = Scope.GLOBAL
    tags = ("identity", "root", "credentials")

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        summary = _account_summary(ctx)
        present = summary.get("AccountAccessKeysPresent", 0)
        if present == 0:
            return
        yield self.finding(
            resource=self.resource(ctx, "AWS::IAM::User", _root_arn(ctx), name="root"),
            evidence=[
                Evidence(
                    description="Account summary root access key count",
                    observed=present,
                    expected=0,
                    source="iam:GetAccountSummary",
                )
            ],
            remediation=Remediation(
                summary=(
                    "Delete the root access key and use an IAM "
                    "role or user for programmatic access."
                ),
                console_steps=[
                    "Sign in as the root user",
                    "Open My Security Credentials",
                    "Delete every listed root access key",
                ],
            ),
        )


@register
class UserMfaMissing(Check):
    rule_id = "iam.user-mfa-missing"
    title = "IAM user with console access has no MFA device"
    description = (
        "The user can sign in to the console with a password alone, so a phished or "
        "reused password is sufficient to authenticate as them."
    )
    severity = Severity.HIGH
    exposure = Exposure.PUBLIC
    exploitability = Exploitability.MODERATE
    control_ids = ("cis-aws:iam.user-mfa", "nist-800-53-r5:IA-2")
    service = "iam"
    scope = Scope.GLOBAL
    tags = ("identity",)

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        iam = ctx.client("iam")
        for page in ctx.paginate("iam", "list_users"):
            for user in page.get("Users", []):
                name = user["UserName"]
                try:
                    iam.get_login_profile(UserName=name)
                except ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                        continue  # programmatic-only user; console MFA does not apply
                    if is_access_denied(exc):
                        continue
                    raise
                devices = iam.list_mfa_devices(UserName=name).get("MFADevices", [])
                if devices:
                    continue
                yield self.finding(
                    resource=self.resource(ctx, "AWS::IAM::User", user["Arn"], name=name),
                    description=(
                        f"IAM user {name} has console access but no MFA device registered."
                    ),
                    evidence=[
                        Evidence(
                            description="Registered MFA devices",
                            observed=0,
                            expected="at least 1",
                            source="iam:ListMFADevices",
                        )
                    ],
                    remediation=Remediation(
                        summary=(
                            f"Register an MFA device for {name}, or remove console "
                            "access if unused."
                        ),
                        cli_command=f"aws iam delete-login-profile --user-name {name}",
                    ),
                )


@register
class AccessKeyStale(Check):
    rule_id = "iam.access-key-stale"
    title = "IAM access key has not been rotated"
    description = (
        "Long-lived access keys widen the window in which a leaked credential remains "
        "valid. Rotation bounds the value of a key an attacker obtains."
    )
    severity = Severity.MEDIUM
    exposure = Exposure.EXTERNAL
    exploitability = Exploitability.MODERATE
    control_ids = ("cis-aws:iam.key-rotation", "nist-800-53-r5:IA-5")
    service = "iam"
    scope = Scope.GLOBAL
    tags = ("identity", "credentials")

    def _max_age(self, ctx: AwsContext) -> int:
        return int(ctx.options.get("max_access_key_age_days", DEFAULT_MAX_KEY_AGE_DAYS))

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        iam = ctx.client("iam")
        max_age = self._max_age(ctx)
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age)
        for page in ctx.paginate("iam", "list_users"):
            for user in page.get("Users", []):
                name = user["UserName"]
                try:
                    keys = iam.list_access_keys(UserName=name).get("AccessKeyMetadata", [])
                except (BotoCoreError, ClientError) as exc:
                    if is_access_denied(exc):
                        continue
                    raise
                for key in keys:
                    if key.get("Status") != "Active":
                        continue
                    created = key["CreateDate"]
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    if created > cutoff:
                        continue
                    age_days = (datetime.now(timezone.utc) - created).days
                    key_id = key["AccessKeyId"]
                    yield self.finding(
                        resource=self.resource(
                            ctx,
                            "AWS::IAM::AccessKey",
                            ctx.arn("iam", f"user/{name}/accesskey/{key_id}"),
                            name=key_id,
                        ),
                        description=(
                            f"Access key {key_id} belonging to {name} is {age_days} days old, "
                            f"exceeding the {max_age} day rotation threshold."
                        ),
                        evidence=[
                            Evidence(
                                description="Access key age in days",
                                observed=age_days,
                                expected=f"<= {max_age}",
                                source="iam:ListAccessKeys",
                            )
                        ],
                        remediation=Remediation(
                            summary=(
                                "Create a replacement key, migrate consumers, then deactivate and "
                                "delete the old key."
                            ),
                            cli_command=(
                                f"aws iam update-access-key --user-name {name} "
                                f"--access-key-id {key_id} --status Inactive"
                            ),
                        ),
                    )


def _grants_full_admin(document: dict[str, Any]) -> bool:
    """Whether a policy document allows every action on every resource."""
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        actions = [actions] if isinstance(actions, str) else list(actions)
        resources = [resources] if isinstance(resources, str) else list(resources)
        if "*" in actions and "*" in resources:
            return True
    return False


@register
class AdminPolicyAttached(Check):
    rule_id = "iam.admin-policy-attached"
    title = "Customer-managed policy grants full administrative privileges"
    description = (
        "The policy allows every action on every resource. Any principal it is attached "
        "to holds unrestricted control, which defeats blast-radius containment and makes "
        "least-privilege review impossible."
    )
    severity = Severity.HIGH
    exposure = Exposure.INTERNAL
    exploitability = Exploitability.MODERATE
    control_ids = ("cis-aws:iam.no-full-admin-policy", "nist-800-53-r5:AC-6")
    service = "iam"
    scope = Scope.GLOBAL
    tags = ("identity", "least-privilege")

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        iam = ctx.client("iam")
        for page in ctx.paginate("iam", "list_policies", Scope="Local", OnlyAttached=True):
            for policy in page.get("Policies", []):
                arn = policy["Arn"]
                version_id = policy.get("DefaultVersionId")
                if not version_id:
                    continue
                try:
                    version = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
                except (BotoCoreError, ClientError) as exc:
                    if is_access_denied(exc):
                        continue
                    raise
                document = version["PolicyVersion"]["Document"]
                if isinstance(document, str):
                    import json

                    document = json.loads(document)
                if not _grants_full_admin(document):
                    continue
                yield self.finding(
                    resource=self.resource(
                        ctx, "AWS::IAM::ManagedPolicy", arn, name=policy["PolicyName"]
                    ),
                    description=(
                        f"Policy {policy['PolicyName']} allows Action '*' on Resource '*' and is "
                        f"attached to {policy.get('AttachmentCount', 0)} principal(s)."
                    ),
                    evidence=[
                        Evidence(
                            description="Policy statement breadth",
                            observed="Action:* Resource:*",
                            expected="scoped actions and resources",
                            source="iam:GetPolicyVersion",
                        )
                    ],
                    remediation=Remediation(
                        summary=(
                            "Replace with a policy scoped to the actions and resources the "
                            "principals actually use; IAM Access Analyzer can generate one from "
                            "CloudTrail history."
                        ),
                        references=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                            "access-analyzer-policy-generation.html"
                        ],
                    ),
                )


@register
class PasswordPolicyWeak(Check):
    rule_id = "iam.password-policy-weak"
    title = "Account password policy is weak or absent"
    description = (
        "Without a minimum length and complexity requirement, console passwords can be "
        "short enough to be brute-forced or guessed from a breach corpus."
    )
    severity = Severity.MEDIUM
    exposure = Exposure.PUBLIC
    exploitability = Exploitability.MODERATE
    control_ids = ("cis-aws:iam.password-policy", "nist-800-53-r5:IA-5")
    service = "iam"
    scope = Scope.GLOBAL
    tags = ("identity",)

    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        iam = ctx.client("iam")
        minimum = int(ctx.options.get("min_password_length", DEFAULT_MIN_PASSWORD_LENGTH))
        resource = self.resource(
            ctx,
            "AWS::IAM::AccountPasswordPolicy",
            ctx.arn("iam", "account-password-policy"),
            name="account-password-policy",
        )
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                yield self.finding(
                    resource=resource,
                    description="No account password policy is configured.",
                    severity=Severity.HIGH,
                    evidence=[
                        Evidence(
                            description="Account password policy",
                            observed=None,
                            expected=f"minimum length >= {minimum}",
                            source="iam:GetAccountPasswordPolicy",
                        )
                    ],
                    remediation=Remediation(
                        summary=(
                            "Set an account password policy, or federate console access via SSO."
                        ),
                        cli_command=(
                            f"aws iam update-account-password-policy "
                            f"--minimum-password-length {minimum} --require-symbols "
                            "--require-numbers --require-uppercase-characters "
                            "--require-lowercase-characters"
                        ),
                    ),
                )
                return
            if is_access_denied(exc):
                return
            raise

        length = policy.get("MinimumPasswordLength", 0)
        if length >= minimum:
            return
        yield self.finding(
            resource=resource,
            description=(
                f"The account password policy permits passwords of {length} characters, "
                f"below the {minimum} character threshold."
            ),
            evidence=[
                Evidence(
                    description="Minimum password length",
                    observed=length,
                    expected=f">= {minimum}",
                    source="iam:GetAccountPasswordPolicy",
                )
            ],
            remediation=Remediation(
                summary=f"Raise the minimum password length to at least {minimum} characters.",
                cli_command=(
                    f"aws iam update-account-password-policy --minimum-password-length {minimum}"
                ),
            ),
        )
