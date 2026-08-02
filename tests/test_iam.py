from __future__ import annotations

import json

from basalt_core import Severity
from tests.conftest import run_check

from basalt_aws.checks.iam import (
    AccessKeyStale,
    AdminPolicyAttached,
    PasswordPolicyWeak,
    RootAccessKeyPresent,
    RootMfaMissing,
    UserMfaMissing,
    _grants_full_admin,
)

ADMIN_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}
SCOPED_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}],
}


class TestRootMfaMissing:
    def test_flags_account_without_root_mfa(self, ctx):
        findings = run_check(RootMfaMissing, ctx)
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    def test_finding_targets_the_root_user(self, ctx):
        finding = run_check(RootMfaMissing, ctx)[0]
        assert finding.resource.name == "root"
        assert finding.resource.uid.endswith(":root")

    def test_carries_resolvable_controls(self, ctx):
        from basalt_core import load_catalog

        finding = run_check(RootMfaMissing, ctx)[0]
        assert load_catalog().unknown(finding.control_ids) == []

    def test_evidence_records_the_observation(self, ctx):
        evidence = run_check(RootMfaMissing, ctx)[0].evidence[0]
        assert evidence.source == "iam:GetAccountSummary"
        assert evidence.expected == 1


class TestRootAccessKeyPresent:
    def test_clean_account_produces_nothing(self, ctx):
        assert run_check(RootAccessKeyPresent, ctx) == []


class TestUserMfaMissing:
    def test_console_user_without_mfa_is_flagged(self, ctx, iam):
        iam.create_user(UserName="alice")
        iam.create_login_profile(UserName="alice", Password="Correct-Horse-1")
        findings = run_check(UserMfaMissing, ctx)
        assert len(findings) == 1
        assert "alice" in findings[0].description

    def test_programmatic_only_user_is_ignored(self, ctx, iam):
        iam.create_user(UserName="ci-robot")
        assert run_check(UserMfaMissing, ctx) == []

    def test_user_with_mfa_is_ignored(self, ctx, iam):
        iam.create_user(UserName="bob")
        iam.create_login_profile(UserName="bob", Password="Correct-Horse-1")
        iam.create_virtual_mfa_device(VirtualMFADeviceName="bob-mfa")
        iam.enable_mfa_device(
            UserName="bob",
            SerialNumber="arn:aws:iam::123456789012:mfa/bob-mfa",
            AuthenticationCode1="123456",
            AuthenticationCode2="234567",
        )
        assert run_check(UserMfaMissing, ctx) == []

    def test_flags_each_affected_user_separately(self, ctx, iam):
        for name in ("carol", "dave"):
            iam.create_user(UserName=name)
            iam.create_login_profile(UserName=name, Password="Correct-Horse-1")
        findings = run_check(UserMfaMissing, ctx)
        assert len(findings) == 2
        assert len({f.fingerprint for f in findings}) == 2


class TestAccessKeyStale:
    def test_fresh_key_is_ignored(self, ctx, iam):
        iam.create_user(UserName="eve")
        iam.create_access_key(UserName="eve")
        assert run_check(AccessKeyStale, ctx) == []

    def test_threshold_is_configurable(self, ctx, iam):
        iam.create_user(UserName="frank")
        iam.create_access_key(UserName="frank")
        ctx.options["max_access_key_age_days"] = 0
        findings = run_check(AccessKeyStale, ctx)
        assert len(findings) == 1
        assert "0 day rotation threshold" in findings[0].description

    def test_inactive_key_is_ignored(self, ctx, iam):
        iam.create_user(UserName="grace")
        key = iam.create_access_key(UserName="grace")["AccessKey"]["AccessKeyId"]
        iam.update_access_key(UserName="grace", AccessKeyId=key, Status="Inactive")
        ctx.options["max_access_key_age_days"] = 0
        assert run_check(AccessKeyStale, ctx) == []

    def test_remediation_deactivates_rather_than_deletes(self, ctx, iam):
        iam.create_user(UserName="heidi")
        iam.create_access_key(UserName="heidi")
        ctx.options["max_access_key_age_days"] = 0
        finding = run_check(AccessKeyStale, ctx)[0]
        assert "update-access-key" in finding.remediation.cli_command
        assert "Inactive" in finding.remediation.cli_command


class TestAdminPolicyDetection:
    def test_wildcard_action_and_resource_is_admin(self):
        assert _grants_full_admin(ADMIN_DOC) is True

    def test_scoped_policy_is_not_admin(self):
        assert _grants_full_admin(SCOPED_DOC) is False

    def test_deny_all_is_not_admin(self):
        assert (
            _grants_full_admin({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})
            is False
        )

    def test_single_statement_dict_is_handled(self):
        assert (
            _grants_full_admin({"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
            is True
        )

    def test_wildcard_action_with_scoped_resource_is_not_admin(self):
        assert (
            _grants_full_admin(
                {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b"}]}
            )
            is False
        )

    def test_attached_admin_policy_is_flagged(self, ctx, iam):
        policy = iam.create_policy(PolicyName="too-broad", PolicyDocument=json.dumps(ADMIN_DOC))[
            "Policy"
        ]
        iam.create_user(UserName="ivan")
        iam.attach_user_policy(UserName="ivan", PolicyArn=policy["Arn"])
        findings = run_check(AdminPolicyAttached, ctx)
        assert len(findings) == 1
        assert findings[0].resource.name == "too-broad"

    def test_unattached_policy_is_ignored(self, ctx, iam):
        iam.create_policy(PolicyName="dormant", PolicyDocument=json.dumps(ADMIN_DOC))
        assert run_check(AdminPolicyAttached, ctx) == []


class TestPasswordPolicy:
    def test_absent_policy_is_high(self, ctx):
        findings = run_check(PasswordPolicyWeak, ctx)
        assert len(findings) == 1
        assert findings[0].severity is Severity.HIGH

    def test_short_policy_is_medium(self, ctx, iam):
        iam.update_account_password_policy(MinimumPasswordLength=8)
        findings = run_check(PasswordPolicyWeak, ctx)
        assert len(findings) == 1
        assert findings[0].severity is Severity.MEDIUM
        assert findings[0].evidence[0].observed == 8

    def test_strong_policy_passes(self, ctx, iam):
        iam.update_account_password_policy(MinimumPasswordLength=16)
        assert run_check(PasswordPolicyWeak, ctx) == []

    def test_threshold_is_configurable(self, ctx, iam):
        iam.update_account_password_policy(MinimumPasswordLength=10)
        ctx.options["min_password_length"] = 10
        assert run_check(PasswordPolicyWeak, ctx) == []
