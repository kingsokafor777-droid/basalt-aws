"""AWS session and client construction.

All AWS access in this package goes through :class:`AwsContext`. Nothing else creates a
boto3 client. That keeps credential handling in one auditable place, makes every check
testable by handing it a context, and gives one place to set the retry policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

if TYPE_CHECKING:  # pragma: no cover
    from basalt_core import ScanContext

__all__ = [
    "AwsContext",
    "AwsAccessError",
    "DEFAULT_BOTO_CONFIG",
    "is_access_denied",
]

# Adaptive retries because posture scanning is read-heavy and will hit IAM and S3 rate
# limits on a large account. Failing a whole scan on a throttle is not acceptable.
DEFAULT_BOTO_CONFIG = Config(
    retries={"max_attempts": 8, "mode": "adaptive"},
    user_agent_extra="basalt-aws",
    connect_timeout=10,
    read_timeout=30,
)

# Error codes that mean "this principal cannot see this", as opposed to "this is broken".
# A posture scanner runs with read-only credentials and will legitimately hit these.
_ACCESS_DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "AuthorizationError",
        "InvalidClientTokenId",
        "SignatureDoesNotMatch",
    }
)


class AwsAccessError(RuntimeError):
    """Raised when the scanner cannot establish who it is authenticated as."""


def is_access_denied(exc: BaseException) -> bool:
    """Whether an exception is an authorisation failure rather than a real fault.

    Checks skip resources they cannot read instead of failing the scan, because a
    read-only auditor role will always be denied somewhere.
    """
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        return code in _ACCESS_DENIED_CODES
    return False


@dataclass
class AwsContext:
    """Everything a check needs to talk to AWS.

    Clients are cached per ``(service, region)`` so a scan of twenty checks against five
    regions does not construct a hundred clients.
    """

    session: boto3.session.Session
    account_id: str
    regions: list[str]
    partition: str = "aws"
    options: dict[str, Any] = field(default_factory=dict)
    _clients: dict[tuple[str, str | None], Any] = field(default_factory=dict, repr=False)

    @classmethod
    def build(cls, scan_context: ScanContext) -> AwsContext:
        """Construct a context from a Basalt :class:`~basalt_core.ScanContext`.

        Credentials come from ``scan_context.credentials`` when supplied (a dict of
        boto3 session kwargs, or a ready-made ``Session``), otherwise from the ambient
        boto3 credential chain.
        """
        credentials = scan_context.credentials
        if isinstance(credentials, boto3.session.Session):
            session = credentials
        elif isinstance(credentials, dict):
            session = boto3.session.Session(**credentials)
        else:
            session = boto3.session.Session()

        sts = session.client("sts", config=DEFAULT_BOTO_CONFIG)
        try:
            identity = sts.get_caller_identity()
        except (BotoCoreError, ClientError) as exc:
            raise AwsAccessError(
                "could not resolve caller identity; check credentials and region"
            ) from exc

        account_id = scan_context.account or identity["Account"]
        arn = identity.get("Arn", "")
        partition = arn.split(":")[1] if arn.count(":") >= 2 else "aws"

        regions = list(scan_context.regions)
        if not regions:
            configured = session.region_name
            regions = [configured] if configured else ["us-east-1"]

        return cls(
            session=session,
            account_id=account_id,
            regions=regions,
            partition=partition,
            options=dict(scan_context.options),
        )

    def client(self, service: str, region: str | None = None) -> Any:
        """Return a cached client for a service, optionally pinned to a region.

        Returns ``Any`` deliberately. boto3-stubs types ``session.client`` as a Literal
        overload per service; this factory is dynamic by design, so a precise return type
        is not expressible here. Call sites that need typed access should annotate locally.
        """
        key = (service, region)
        if key not in self._clients:
            self._clients[key] = self.session.client(  # type: ignore[call-overload]
                service, region_name=region, config=DEFAULT_BOTO_CONFIG
            )
        return self._clients[key]

    def paginate(
        self, service: str, operation: str, region: str | None = None, **kwargs: Any
    ) -> list[dict[str, Any]]:
        """Collect every page of a paginated operation.

        Falls back to a single call for operations boto3 does not expose a paginator for.
        """
        client = self.client(service, region)
        if client.can_paginate(operation):
            paginator = client.get_paginator(operation)
            return list(paginator.paginate(**kwargs))
        return [getattr(client, operation)(**kwargs)]

    def arn(self, service: str, resource: str, region: str = "", account: str | None = None) -> str:
        """Build an ARN for a resource, for services whose APIs do not return one."""
        return f"arn:{self.partition}:{service}:{region}:{account or self.account_id}:{resource}"
