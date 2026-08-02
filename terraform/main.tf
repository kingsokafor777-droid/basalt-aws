# Read-only role for basalt-aws.
#
# Grants exactly the API calls the scanner makes -- the same list surfaced by
# `basalt-aws permissions --json`. See ADR 0003: the scanner is read-only by
# construction, and this is the artifact that makes that checkable rather than asserted.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "role_name" {
  description = "Name of the IAM role the scanner assumes."
  type        = string
  default     = "basalt-aws-scanner"
}

variable "trusted_principal_arns" {
  description = "Principals permitted to assume the scanner role. Never leave this open."
  type        = list(string)
}

variable "external_id" {
  description = "External id required on AssumeRole, guarding against the confused deputy problem."
  type        = string
  sensitive   = true
}

data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = var.trusted_principal_arns
    }

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

# Every action here is a read. A test in this repository asserts that no permission in
# the scanner's declared list begins with a mutating verb.
data "aws_iam_policy_document" "scanner" {
  statement {
    sid    = "BasaltAwsReadOnly"
    effect = "Allow"
    actions = [
      "cloudtrail:DescribeTrails",
      "iam:GetAccountPasswordPolicy",
      "iam:GetAccountSummary",
      "iam:GetLoginProfile",
      "iam:GetPolicyVersion",
      "iam:ListAccessKeys",
      "iam:ListMFADevices",
      "iam:ListPolicies",
      "iam:ListUsers",
      "kms:DescribeKey",
      "kms:GetKeyRotationStatus",
      "kms:ListKeys",
      "s3:GetBucketAcl",
      "s3:GetBucketLocation",
      "s3:GetBucketPolicy",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketVersioning",
      "s3:GetEncryptionConfiguration",
      "s3:ListAllMyBuckets",
      "sts:GetCallerIdentity",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "scanner" {
  name                 = var.role_name
  description          = "Read-only posture scanning role for basalt-aws"
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  max_session_duration = 3600

  tags = {
    ManagedBy = "terraform"
    Purpose   = "security-posture-scanning"
  }
}

resource "aws_iam_role_policy" "scanner" {
  name   = "${var.role_name}-readonly"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.scanner.json
}

output "role_arn" {
  description = "Pass this to the scanner via an assumed-role session."
  value       = aws_iam_role.scanner.arn
}
