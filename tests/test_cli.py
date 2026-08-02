from __future__ import annotations

import json

import pytest
from tests.conftest import REGION

from basalt_aws.cli import REQUIRED_PERMISSIONS, main


class TestScanCommand:
    def test_emits_a_valid_document(self, aws, capsys):
        assert main(["scan", "--regions", REGION]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["schema_version"] == "1.0.0"
        assert payload["findings"]

    @pytest.mark.parametrize("fmt", ["sarif", "ocsf", "basalt"])
    def test_every_format_is_valid_json(self, aws, capsys, fmt):
        main(["scan", "--regions", REGION, "--format", fmt])
        json.loads(capsys.readouterr().out)

    def test_jsonl_is_one_object_per_line(self, aws, capsys):
        main(["scan", "--regions", REGION, "--format", "jsonl"])
        lines = [x for x in capsys.readouterr().out.splitlines() if x.strip()]
        assert lines and all(json.loads(x) for x in lines)

    def test_writes_to_a_file(self, aws, tmp_path):
        out = tmp_path / "scan.sarif"
        assert main(["scan", "--regions", REGION, "--format", "sarif", "-o", str(out)]) == 0
        assert json.loads(out.read_text())["version"] == "2.1.0"

    def test_service_filter(self, aws, capsys):
        main(["scan", "--regions", REGION, "--service", "iam"])
        payload = json.loads(capsys.readouterr().out)
        assert all(f["rule_id"].startswith("iam.") for f in payload["findings"])

    def test_rule_filter(self, aws, capsys):
        main(["scan", "--regions", REGION, "--rule", "iam.root-mfa-missing"])
        payload = json.loads(capsys.readouterr().out)
        assert {f["rule_id"] for f in payload["findings"]} == {"iam.root-mfa-missing"}

    def test_fail_on_critical_exits_one(self, aws):
        assert main(["scan", "--regions", REGION, "--fail-on", "critical"]) == 1

    def test_fail_on_is_not_triggered_when_nothing_qualifies(self, aws):
        code = main(
            [
                "scan",
                "--regions",
                REGION,
                "--rule",
                "s3.bucket-versioning-disabled",
                "--fail-on",
                "critical",
            ]
        )
        assert code == 0

    def test_summary_goes_to_stderr(self, aws, capsys):
        main(["scan", "--regions", REGION])
        assert "findings across" in capsys.readouterr().err

    def test_compact_output_is_one_line(self, aws, capsys):
        main(["scan", "--regions", REGION, "--compact"])
        assert len(capsys.readouterr().out.strip().splitlines()) == 1


class TestChecksCommand:
    def test_lists_every_service(self, capsys):
        assert main(["checks"]) == 0
        out = capsys.readouterr().out
        for service in ("iam", "s3", "cloudtrail", "kms"):
            assert service in out

    def test_reports_no_unknown_controls(self, capsys):
        main(["checks"])
        assert "unknown controls" not in capsys.readouterr().out

    def test_verbose_shows_control_ids(self, capsys):
        main(["checks", "-v"])
        assert "controls:" in capsys.readouterr().out


class TestPermissionsCommand:
    def test_lists_permissions(self, capsys):
        assert main(["permissions"]) == 0
        assert "SecurityAudit" in capsys.readouterr().out

    def test_emits_a_policy_document(self, capsys):
        main(["permissions", "--json"])
        policy = json.loads(capsys.readouterr().out)
        assert policy["Statement"][0]["Effect"] == "Allow"
        assert "sts:GetCallerIdentity" in policy["Statement"][0]["Action"]

    def test_every_permission_is_read_only(self):
        """A posture scanner must never require a mutating permission."""
        mutating = ("Create", "Delete", "Put", "Update", "Attach", "Detach", "Modify", "Write")
        offenders = [
            p for p in REQUIRED_PERMISSIONS if any(p.split(":")[1].startswith(m) for m in mutating)
        ]
        assert offenders == []


class TestParser:
    def test_no_command_exits(self):
        with pytest.raises(SystemExit):
            main([])

    def test_unknown_service_rejected(self):
        with pytest.raises(SystemExit):
            main(["scan", "--service", "dynamodb"])
