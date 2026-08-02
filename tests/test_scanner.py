"""Scanner, registry and ecosystem-contract tests.

The contract tests are the point of this file: they assert that basalt-aws output is
consumable by every basalt-core facility without an adapter. If these pass, the plugin
architecture from ADR 0004 of basalt-core actually works.
"""

from __future__ import annotations

import json

import pytest
from basalt_core import (
    Provider,
    ScanContext,
    ScanResult,
    Severity,
    get_emitter,
    load_catalog,
)
from basalt_core.plugin import ENTRY_POINT_GROUP, discover_scanners
from tests.conftest import REGION, secure_bucket

from basalt_aws import CHECKS, AwsScanner, Scope, get_check
from basalt_aws.registry import Check, checks_for_service, register


class TestRegistry:
    def test_checks_are_registered(self):
        assert len(CHECKS) >= 17

    def test_rule_ids_are_unique(self):
        ids = [c.rule_id for c in CHECKS]
        assert len(ids) == len(set(ids))

    def test_every_check_declares_metadata(self):
        for cls in CHECKS:
            assert cls.rule_id and cls.title and cls.description
            assert cls.service and cls.control_ids

    def test_every_control_id_resolves(self):
        """The contract with basalt-core: no check may cite a control that does not exist."""
        catalog = load_catalog()
        unresolved = {
            cls.rule_id: catalog.unknown(cls.control_ids)
            for cls in CHECKS
            if catalog.unknown(cls.control_ids)
        }
        assert unresolved == {}

    def test_lookup_by_rule_id(self):
        assert get_check("iam.root-mfa-missing").severity is Severity.CRITICAL

    def test_unknown_rule_id_raises(self):
        with pytest.raises(KeyError):
            get_check("iam.does-not-exist")

    def test_service_filter(self):
        assert all(c.service == "s3" for c in checks_for_service("s3"))

    def test_duplicate_registration_is_rejected(self):
        with pytest.raises(ValueError, match="duplicate rule_id"):

            @register
            class Dupe(Check):
                rule_id = "iam.root-mfa-missing"
                service = "iam"

                def run(self, ctx, region=None):
                    yield from ()

    def test_missing_rule_id_is_rejected(self):
        with pytest.raises(ValueError, match="must declare a rule_id"):

            @register
            class NoId(Check):
                service = "iam"

                def run(self, ctx, region=None):
                    yield from ()

    def test_global_checks_outnumber_regional(self):
        assert sum(1 for c in CHECKS if c.scope is Scope.GLOBAL) > 0
        assert sum(1 for c in CHECKS if c.scope is Scope.REGIONAL) > 0


class TestScannerRun:
    def test_produces_a_scan_result(self, aws):
        result = AwsScanner().run(ScanContext(regions=[REGION]))
        assert isinstance(result, ScanResult)
        assert result.metadata.provider is Provider.AWS
        assert result.metadata.scanner == "basalt-aws"

    def test_empty_account_still_finds_baseline_gaps(self, aws):
        """A brand-new account is not secure: no MFA, no password policy, no trail."""
        result = AwsScanner().run(ScanContext(regions=[REGION]))
        found = {f.rule_id for f in result.findings}
        assert "iam.root-mfa-missing" in found
        assert "iam.password-policy-weak" in found
        assert "cloudtrail.no-trail-configured" in found

    def test_findings_are_stamped_with_scanner_identity(self, aws):
        result = AwsScanner().run(ScanContext(regions=[REGION]))
        assert all(f.scanner == "basalt-aws" for f in result.findings)
        assert all(f.scanner_version == AwsScanner.version for f in result.findings)

    def test_rule_filter_restricts_the_run(self, aws):
        context = ScanContext(regions=[REGION], rule_filter=["iam.root-mfa-missing"])
        result = AwsScanner().run(context)
        assert {f.rule_id for f in result.findings} == {"iam.root-mfa-missing"}

    def test_global_checks_do_not_duplicate_across_regions(self, aws):
        context = ScanContext(regions=["ca-central-1", "us-east-1", "eu-west-1"])
        result = AwsScanner().run(context)
        root = [f for f in result.findings if f.rule_id == "iam.root-mfa-missing"]
        assert len(root) == 1, "a global check emitted once per region"

    def test_regional_checks_run_per_region(self, aws):
        context = ScanContext(regions=["ca-central-1", "us-east-1"])
        result = AwsScanner().run(context)
        trails = [f for f in result.findings if f.rule_id == "cloudtrail.no-trail-configured"]
        assert len(trails) == 2

    def test_fingerprints_are_unique_within_a_scan(self, aws, s3):
        secure_bucket(s3)
        result = AwsScanner().run(ScanContext(regions=[REGION]))
        prints = [f.fingerprint for f in result.findings]
        assert len(prints) == len(set(prints))

    def test_scan_is_reproducible(self, aws):
        context = ScanContext(regions=[REGION])
        first = {f.fingerprint for f in AwsScanner().run(context).findings}
        second = {f.fingerprint for f in AwsScanner().run(context).findings}
        assert first == second

    def test_a_broken_check_does_not_lose_other_findings(self, aws):
        class Exploding(Check):
            rule_id = "test.explodes"
            title = "t"
            description = "d"
            service = "iam"
            control_ids = ("nist-800-53-r5:AC-6",)

            def run(self, ctx, region=None):
                raise RuntimeError("boom")
                yield  # pragma: no cover

        checks = [get_check("iam.root-mfa-missing"), Exploding]
        result = AwsScanner(checks).run(ScanContext(regions=[REGION]))
        assert any(f.rule_id == "iam.root-mfa-missing" for f in result.findings)
        assert any("test.explodes" in e for e in result.metadata.errors)

    def test_check_count_is_exposed(self):
        assert AwsScanner().check_count == len(CHECKS)


class TestEcosystemContract:
    """basalt-aws output must be consumable by basalt-core with no adapter."""

    @pytest.fixture
    def result(self, aws, s3, iam):
        s3.create_bucket(Bucket="leaky", CreateBucketConfiguration={"LocationConstraint": REGION})
        s3.put_bucket_acl(Bucket="leaky", ACL="public-read")
        iam.create_user(UserName="nomfa")
        iam.create_login_profile(UserName="nomfa", Password="Correct-Horse-1")
        return AwsScanner().run(ScanContext(regions=[REGION]))

    def test_round_trips_through_the_native_format(self, result):
        payload = get_emitter("basalt").emit_json(result)
        restored = ScanResult.model_validate(json.loads(payload))
        assert len(restored.findings) == len(result.findings)

    def test_converts_to_sarif(self, result):
        doc = get_emitter("sarif").emit(result)
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"][0]["results"]) == len(result.findings)

    def test_converts_to_ocsf(self, result):
        events = get_emitter("ocsf").emit(result)
        assert all(e["class_uid"] == 2003 for e in events)
        assert len(events) == len(result.findings)

    def test_converts_to_jsonl_for_the_warehouse(self, result):
        lines = get_emitter("jsonl").emit_json(result).splitlines()
        rows = [json.loads(line) for line in lines if line.strip()]
        assert len(rows) == len(result.findings)
        assert all(0 <= r["risk_score"] <= 100 for r in rows)

    def test_every_emitted_control_id_resolves(self, result):
        catalog = load_catalog()
        for finding in result.findings:
            assert catalog.unknown(finding.control_ids) == []

    def test_risk_scores_order_public_exposure_first(self, result):
        public = next(f for f in result.findings if f.rule_id == "s3.bucket-public-acl")
        versioning = next(
            (f for f in result.findings if f.rule_id == "s3.bucket-versioning-disabled"), None
        )
        if versioning:
            assert public.risk.value > versioning.risk.value

    def test_urns_are_parseable(self, result):
        from basalt_core import ResourceRef

        for finding in result.findings:
            parsed = ResourceRef.parse_urn(finding.resource.urn)
            assert parsed.uid == finding.resource.uid


class TestEntryPoint:
    def test_registered_under_the_basalt_group(self):
        assert ENTRY_POINT_GROUP == "basalt.scanners"
        assert discover_scanners().get("aws") is AwsScanner
