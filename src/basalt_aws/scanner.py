"""The AWS scanner: the entry point Basalt discovers and runs.

Orchestration only. It resolves an :class:`~basalt_aws.client.AwsContext`, decides which
checks run where, and converts per-check failures into recorded errors rather than a
failed scan. All AWS knowledge lives in the check modules.
"""

from __future__ import annotations

from collections.abc import Iterable

from basalt_core import Finding, Provider, ScanContext, Scanner

from . import checks as _checks  # noqa: F401 - import registers every check
from .client import AwsAccessError, AwsContext
from .registry import CHECKS, Check, Scope

__all__ = ["AwsScanner", "__version__"]

__version__ = "0.1.0"


class AwsScanner(Scanner):
    """Read-only posture scanner for IAM, S3, CloudTrail and KMS.

    Requires no write permissions. ``arn:aws:iam::aws:policy/SecurityAudit`` covers every
    API this scanner calls.
    """

    name = "basalt-aws"
    version = __version__
    provider = Provider.AWS
    description = "AWS posture checks for IAM, S3, CloudTrail and KMS"

    def __init__(self, checks: list[type[Check]] | None = None) -> None:
        self._checks = list(checks if checks is not None else CHECKS)

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        """Run every selected check and yield findings.

        A check that raises is skipped and its failure is re-raised only if it would
        otherwise be silent — the base :meth:`Scanner.run` records the message in scan
        metadata, so one broken check never discards findings already collected.
        """
        try:
            ctx = AwsContext.build(context)
        except AwsAccessError:
            raise

        selected = [c for c in self._checks if context.selects(c.rule_id)]
        errors: list[str] = []

        for cls in selected:
            check = cls()
            targets: list[str | None] = [None] if check.scope is Scope.GLOBAL else list(ctx.regions)
            for region in targets:
                try:
                    yield from check.run(ctx, region)
                except Exception as exc:
                    where = f" in {region}" if region else ""
                    errors.append(f"{cls.rule_id}{where}: {type(exc).__name__}: {exc}")

        if errors:
            # Raised at the end so that findings from healthy checks are already yielded.
            # Scanner.run() captures this into ScanResult.metadata.errors.
            raise RuntimeError("; ".join(errors))

    @property
    def check_count(self) -> int:
        return len(self._checks)
