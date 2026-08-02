"""The check contract and registry.

A check is one question asked of one AWS service. It declares its metadata as class
attributes — rule id, severity, control mappings, scope — and implements a single
generator that yields findings.

Metadata lives on the class rather than inside the finding constructor so that the
catalogue is introspectable without running a scan. ``basalt-aws checks`` lists every
check, and CI asserts every declared control id resolves against the Basalt catalog.
"""

from __future__ import annotations

import abc
from collections.abc import Iterable, Iterator
from enum import Enum
from typing import TYPE_CHECKING

from basalt_core import (
    Evidence,
    Exploitability,
    Exposure,
    Finding,
    Provider,
    Remediation,
    ResourceRef,
    Severity,
)

if TYPE_CHECKING:  # pragma: no cover
    from .client import AwsContext

__all__ = ["Scope", "Check", "CHECKS", "register", "get_check", "checks_for_service"]


class Scope(str, Enum):
    """Whether a check runs once per account or once per region.

    IAM and the S3 bucket listing are account-wide; CloudTrail and KMS are regional.
    Running a global check per region would emit duplicate findings that differ only by
    the region field, which would then survive fingerprint deduplication.
    """

    GLOBAL = "global"
    REGIONAL = "regional"


class Check(abc.ABC):
    """One posture question.

    Subclasses set the metadata attributes and implement :meth:`run`. They should skip
    resources they cannot read rather than raise; the scanner records access failures in
    scan metadata.
    """

    #: Stable, lowercase, dot-separated. Changing this orphans history downstream.
    rule_id: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    exposure: Exposure = Exposure.INTERNAL
    exploitability: Exploitability = Exploitability.MODERATE
    #: Namespaced control ids; every one must resolve against the Basalt catalog.
    control_ids: tuple[str, ...] = ()
    #: boto3 service name, used for grouping and for the CLI listing.
    service: str = ""
    scope: Scope = Scope.GLOBAL
    tags: tuple[str, ...] = ()

    @abc.abstractmethod
    def run(self, ctx: AwsContext, region: str | None = None) -> Iterable[Finding]:
        """Yield a finding for each resource that fails this check."""

    def finding(
        self,
        resource: ResourceRef,
        *,
        evidence: list[Evidence] | None = None,
        remediation: Remediation | None = None,
        title: str | None = None,
        description: str | None = None,
        severity: Severity | None = None,
        exposure: Exposure | None = None,
    ) -> Finding:
        """Build a finding pre-populated from this check's metadata.

        Checks call this rather than constructing ``Finding`` directly, so that rule id,
        controls and tags cannot drift from the declared metadata.
        """
        return Finding(
            rule_id=self.rule_id,
            title=title or self.title,
            description=description or self.description,
            severity=severity or self.severity,
            exposure=exposure or self.exposure,
            exploitability=self.exploitability,
            resource=resource,
            scanner="basalt-aws",
            control_ids=list(self.control_ids),
            evidence=evidence or [],
            remediation=remediation,
            tags=list(self.tags),
        )

    def resource(
        self,
        ctx: AwsContext,
        resource_type: str,
        uid: str,
        name: str | None = None,
        region: str | None = None,
        tags: dict[str, str] | None = None,
    ) -> ResourceRef:
        """Build a resource reference bound to the scanned account."""
        return ResourceRef(
            provider=Provider.AWS,
            resource_type=resource_type,
            uid=uid,
            name=name,
            account=ctx.account_id,
            region=region,
            tags=tags or {},
        )


CHECKS: list[type[Check]] = []


def register(cls: type[Check]) -> type[Check]:
    """Class decorator adding a check to the registry.

    Rejects duplicate and malformed rule ids at import time rather than at scan time.
    """
    if not cls.rule_id:
        raise ValueError(f"{cls.__name__} must declare a rule_id")
    if not cls.service:
        raise ValueError(f"{cls.__name__} must declare a service")
    existing = {c.rule_id for c in CHECKS}
    if cls.rule_id in existing:
        raise ValueError(f"duplicate rule_id {cls.rule_id!r}")
    CHECKS.append(cls)
    return cls


def get_check(rule_id: str) -> type[Check]:
    """Look up one check by rule id."""
    for cls in CHECKS:
        if cls.rule_id == rule_id:
            return cls
    raise KeyError(f"no check with rule_id {rule_id!r}")


def checks_for_service(service: str) -> Iterator[type[Check]]:
    """Every registered check for one boto3 service."""
    for cls in CHECKS:
        if cls.service == service:
            yield cls
