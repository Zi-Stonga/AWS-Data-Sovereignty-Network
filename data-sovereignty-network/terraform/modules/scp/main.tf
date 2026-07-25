terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  required_version = ">= 1.6.0"
}

variable "target_ou_id" {
  description = "The Organizations OU ID to attach this SCP to."
  type        = string
}

variable "zone" {
  description = "Sovereign zone this SCP enforces."
  type        = string
  validation {
    condition     = contains(["eu", "apac", "us"], var.zone)
    error_message = "zone must be one of: eu, apac, us."
  }
}

variable "allowed_regions" {
  description = "AWS regions permitted for data resource creation in this zone."
  type        = list(string)
}

variable "eu_pii_bucket_patterns" {
  description = "S3 bucket ARN patterns containing EU PII. Used in US zone SCP only."
  type        = list(string)
  default     = []
}

locals {
  zone_scp_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyNonZoneRegionDataResources"
        Effect = "Deny"
        Action = [
          "s3:PutObject", "s3:CopyObject",
          "rds:CreateDBInstance", "rds:CreateDBCluster",
          "ec2:RunInstances", "ec2:CreateVolume",
          "dynamodb:CreateTable", "lambda:CreateFunction", "eks:CreateCluster",
        ]
        Resource  = "*"
        Condition = { StringNotLike = { "aws:RequestedRegion" = var.allowed_regions } }
      },
      {
        Sid      = "DenyKMSKeyCreationOutsideZone"
        Effect   = "Deny"
        Action   = ["kms:CreateKey", "kms:ReplicateKey"]
        Resource  = "*"
        Condition = { StringNotLike = { "aws:RequestedRegion" = var.allowed_regions } }
      },
      {
        Sid      = "DenyDisableCloudTrail"
        Effect   = "Deny"
        Action   = [
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging",
          "cloudtrail:UpdateTrail",
        ]
        Resource = "*"
      },
      {
        Sid      = "DenyLeaveOrganization"
        Effect   = "Deny"
        Action   = ["organizations:LeaveOrganization"]
        Resource = "*"
      },
    ]
  })
}

resource "aws_organizations_policy" "zone_scp" {
  name        = "data-sovereignty-${var.zone}"
  description = "Data sovereignty SCP for the ${upper(var.zone)} zone."
  content     = local.zone_scp_policy
  type        = "SERVICE_CONTROL_POLICY"
  tags        = { SovereignZone = var.zone, ManagedBy = "terraform" }
}

resource "aws_organizations_policy_attachment" "zone_scp" {
  policy_id = aws_organizations_policy.zone_scp.id
  target_id = var.target_ou_id
}

output "scp_id" {
  description = "The ID of the created SCP."
  value       = aws_organizations_policy.zone_scp.id
}

output "scp_arn" {
  description = "The ARN of the created SCP."
  value       = aws_organizations_policy.zone_scp.arn
}
