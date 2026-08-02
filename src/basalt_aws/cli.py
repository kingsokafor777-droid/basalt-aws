"""``basalt-aws`` command line interface.

Three commands: run a scan, list the checks, and show which IAM permissions a scan needs.
The last one exists because the first question anyone asks of a posture scanner is what
it is allowed to do.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from basalt_core import ScanContext, available_formats, get_emitter, load_catalog

from . import __version__
from .client import AwsAccessError
from .registry import CHECKS, Check
from .scanner import AwsScanner

# Every API this scanner calls. Kept here so `permissions` cannot drift from reality
# without someone editing this list deliberately.
REQUIRED_PERMISSIONS = [
    "iam:GetAccountSummary",
    "iam:GetAccountPasswordPolicy",
    "iam:ListUsers",
    "iam:GetLoginProfile",
    "iam:ListMFADevices",
    "iam:ListAccessKeys",
    "iam:ListPolicies",
    "iam:GetPolicyVersion",
    "s3:ListAllMyBuckets",
    "s3:GetBucketLocation",
    "s3:GetBucketAcl",
    "s3:GetBucketPolicy",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetEncryptionConfiguration",
    "s3:GetBucketVersioning",
    "cloudtrail:DescribeTrails",
    "kms:ListKeys",
    "kms:DescribeKey",
    "kms:GetKeyRotationStatus",
    "sts:GetCallerIdentity",
]


def _cmd_scan(args: argparse.Namespace) -> int:
    context = ScanContext(
        account=args.account,
        regions=args.regions or [],
        rule_filter=args.rule or [],
        options={
            k: v
            for k, v in (
                ("max_access_key_age_days", args.max_key_age),
                ("min_password_length", args.min_password_length),
            )
            if v is not None
        },
    )
    checks = [c for c in CHECKS if not args.service or c.service in args.service]
    if not checks:
        print(f"no checks match service filter {args.service}", file=sys.stderr)
        return 2

    try:
        result = AwsScanner(checks).run(context)
    except AwsAccessError as exc:
        print(f"could not authenticate to AWS: {exc}", file=sys.stderr)
        return 2

    if args.dedupe:
        result = result.deduplicate()

    emitter = get_emitter(args.format)
    output = emitter.emit_json(result, indent=None if args.compact else 2)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
        print(f"wrote {args.output} ({emitter.format})", file=sys.stderr)
    else:
        print(output)

    counts = result.severity_counts()
    summary = "  ".join(f"{k}={v}" for k, v in counts.items())
    print(
        f"{len(result.findings)} findings across {len(checks)} checks  [{summary}]  "
        f"max risk {result.max_risk()}",
        file=sys.stderr,
    )
    for error in result.metadata.errors:
        print(f"error: {error}", file=sys.stderr)

    if args.fail_on:
        from basalt_core import Severity

        threshold = Severity.from_any(args.fail_on).rank
        if any(f.severity.rank >= threshold for f in result.findings):
            return 1
    return 0


def _cmd_checks(args: argparse.Namespace) -> int:
    catalog = load_catalog()
    by_service: dict[str, list[type[Check]]] = {}
    for cls in CHECKS:
        by_service.setdefault(cls.service, []).append(cls)

    for service in sorted(by_service):
        print(f"\n{service}")
        for cls in sorted(by_service[service], key=lambda c: c.rule_id):
            unresolved = catalog.unknown(cls.control_ids)
            flag = "  [unknown controls: " + ", ".join(unresolved) + "]" if unresolved else ""
            print(
                f"  {cls.rule_id:<38} {cls.severity.value:<8} "
                f"{cls.scope.value:<9} {cls.title}{flag}"
            )
            if args.verbose:
                print(f"      controls: {', '.join(cls.control_ids)}")
    print(f"\n{len(CHECKS)} checks across {len(by_service)} services")
    return 0


def _cmd_permissions(args: argparse.Namespace) -> int:
    if args.json:
        import json

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "BasaltAwsReadOnly",
                    "Effect": "Allow",
                    "Action": sorted(REQUIRED_PERMISSIONS),
                    "Resource": "*",
                }
            ],
        }
        print(json.dumps(policy, indent=2))
        return 0
    print("basalt-aws is read-only. It calls:\n")
    for permission in sorted(REQUIRED_PERMISSIONS):
        print(f"  {permission}")
    print(
        "\nThe AWS managed policy arn:aws:iam::aws:policy/SecurityAudit covers all of these."
        "\nUse --json to emit a least-privilege policy document instead."
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="basalt-aws", description="Read-only AWS posture scanner."
    )
    parser.add_argument("--version", action="version", version=f"basalt-aws {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Run posture checks against an AWS account")
    p_scan.add_argument("--account", help="Override the account id recorded in output")
    p_scan.add_argument("--regions", nargs="+", help="Regions for regional checks")
    p_scan.add_argument("--service", nargs="+", choices=["iam", "s3", "cloudtrail", "kms"])
    p_scan.add_argument("--rule", nargs="+", help="Run only these rule ids")
    p_scan.add_argument("--format", default="basalt", choices=available_formats())
    p_scan.add_argument("-o", "--output", help="Write to a file instead of stdout")
    p_scan.add_argument("--dedupe", action="store_true")
    p_scan.add_argument("--compact", action="store_true")
    p_scan.add_argument("--max-key-age", type=int, help="Access key rotation threshold in days")
    p_scan.add_argument("--min-password-length", type=int)
    p_scan.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        help="Exit 1 if any finding is at or above this severity",
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_checks = sub.add_parser("checks", help="List every registered check")
    p_checks.add_argument("-v", "--verbose", action="store_true")
    p_checks.set_defaults(func=_cmd_checks)

    p_perms = sub.add_parser("permissions", help="Show the IAM permissions a scan requires")
    p_perms.add_argument("--json", action="store_true", help="Emit a least-privilege policy")
    p_perms.set_defaults(func=_cmd_permissions)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
