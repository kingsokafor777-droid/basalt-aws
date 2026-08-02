"""Basalt AWS - read-only posture scanner for IAM, S3, CloudTrail and KMS.

Emits :class:`basalt_core.Finding` objects, so output converts to SARIF or OCSF and
loads into the Basalt warehouse without an adapter.

    from basalt_aws import AwsScanner
    from basalt_core import ScanContext, get_emitter

    result = AwsScanner().run(ScanContext(regions=["ca-central-1"]))
    print(get_emitter("sarif").emit_json(result))
"""

from .client import AwsAccessError, AwsContext
from .registry import CHECKS, Check, Scope, checks_for_service, get_check, register
from .scanner import AwsScanner, __version__

__all__ = [
    "AwsScanner",
    "AwsContext",
    "AwsAccessError",
    "Check",
    "Scope",
    "CHECKS",
    "register",
    "get_check",
    "checks_for_service",
    "__version__",
]
