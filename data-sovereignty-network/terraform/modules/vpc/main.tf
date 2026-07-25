terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  required_version = ">= 1.6.0"
}

variable "vpc_name" {
  description = "Name tag for the VPC and all associated resources."
  type        = string
}

variable "cidr_block" {
  description = "IPv4 CIDR block for the VPC. Must not overlap with CIDRs in other sovereign zones."
  type        = string
  validation {
    condition     = can(cidrhost(var.cidr_block, 0))
    error_message = "cidr_block must be a valid IPv4 CIDR."
  }
}

variable "zone" {
  description = "Sovereign zone identifier."
  type        = string
  validation {
    condition     = contains(["eu", "apac", "us"], var.zone)
    error_message = "zone must be one of: eu, apac, us."
  }
}

variable "availability_zones" {
  description = "List of AZs to deploy subnets into. Minimum 2 for HA."
  type        = list(string)
  validation {
    condition     = length(var.availability_zones) >= 2
    error_message = "At least 2 availability zones are required for HA."
  }
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets, one per AZ."
  type        = list(string)
}

variable "enable_flow_logs" {
  description = "Whether to enable VPC Flow Logs. Required for DORA and GDPR evidence."
  type        = bool
  default     = true
}

variable "flow_log_group_name" {
  description = "CloudWatch Log Group name for VPC Flow Logs."
  type        = string
}

variable "flow_log_role_arn" {
  description = "IAM role ARN for VPC Flow Log delivery to CloudWatch."
  type        = string
}

variable "environment" {
  description = "Deployment environment tag."
  type        = string
  default     = "production"
}

locals {
  common_tags = {
    SovereignZone = var.zone
    Environment   = var.environment
    ManagedBy     = "terraform"
    Module        = "vpc"
  }
}

resource "aws_vpc" "sovereign" {
  cidr_block           = var.cidr_block
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = merge(local.common_tags, { Name = var.vpc_name })
}

resource "aws_subnet" "private" {
  count                   = length(var.availability_zones)
  vpc_id                  = aws_vpc.sovereign.id
  cidr_block              = var.private_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false
  tags = merge(local.common_tags, {
    Name = "${var.vpc_name}-private-${var.availability_zones[count.index]}"
    Tier = "private"
  })
}

resource "aws_default_security_group" "deny_all" {
  vpc_id = aws_vpc.sovereign.id
  tags   = merge(local.common_tags, { Name = "${var.vpc_name}-default-deny-all" })
}

resource "aws_flow_log" "vpc" {
  count           = var.enable_flow_logs ? 1 : 0
  iam_role_arn    = var.flow_log_role_arn
  log_destination = var.flow_log_group_name
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.sovereign.id
  tags            = merge(local.common_tags, { Name = "${var.vpc_name}-flow-logs" })
}

output "vpc_id" {
  description = "The ID of the sovereign VPC."
  value       = aws_vpc.sovereign.id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets."
  value       = aws_subnet.private[*].id
}

output "vpc_cidr" {
  description = "The CIDR block of the VPC."
  value       = aws_vpc.sovereign.cidr_block
}
