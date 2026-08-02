"""Check implementations, grouped by AWS service.

Importing this package registers every check. The scanner imports it once at module
load, which is what populates :data:`basalt_aws.registry.CHECKS`.
"""

from . import cloudtrail, iam, kms, s3

__all__ = ["cloudtrail", "iam", "kms", "s3"]
