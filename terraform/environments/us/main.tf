terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  backend "s3" {
    bucket         = "tfstate-data-sovereignty-us"
    key            = "environments/us/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "tfstate-locks"
  }
}

provider "aws" {
  region = "us-east-1"
  alias  = "us_east_1"
  default_tags {
    tags = {
      SovereignZone = "us"
      Environment   = var.environment
      ManagedBy     = "terraform"
    }
  }
}

provider "aws" {
  region = "us-east-2"
  alias  = "us_east_2"
  default_tags {
    tags = {
      SovereignZone = "us"
      Environment   = var.environment
      ManagedBy     = "terraform"
    }
  }
}

variable "environment"         { type = string, default = "production" }
variable "us_ou_id"            { type = string }
variable "flow_log_role_arn"   { type = string }
variable "alert_sns_topic_arn" { type = string }

module "us_banking_vpc" {
  source               = "../../modules/vpc"
  providers            = { aws = aws.us_east_1 }
  vpc_name             = "us-banking-vpc"
  cidr_block           = "10.70.0.0/16"
  zone                 = "us"
  availability_zones   = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnet_cidrs = ["10.70.1.0/24", "10.70.2.0/24", "10.70.3.0/24"]
  enable_flow_logs     = true
  flow_log_group_name  = "/vpc/us-banking/flowlogs"
  flow_log_role_arn    = var.flow_log_role_arn
  environment          = var.environment
}

module "us_scp" {
  source          = "../../modules/scp"
  target_ou_id    = var.us_ou_id
  zone            = "us"
  allowed_regions = ["us-east-1", "us-east-2"]
}

resource "aws_cloudwatch_metric_alarm" "us_scp_violation" {
  provider            = aws.us_east_1
  alarm_name          = "us-scp-violation"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "SCPDenialCount"
  namespace           = "DataSovereignty/US"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Fires on any SCP denial in the US zone. Investigate immediately."
  alarm_actions       = [var.alert_sns_topic_arn]
  treat_missing_data  = "notBreaching"
  tags                = { SovereignZone = "us", Severity = "critical" }
}

resource "aws_cloudwatch_metric_alarm" "us_eu_pii_access_attempt" {
  provider            = aws.us_east_1
  alarm_name          = "us-eu-pii-bucket-access-denied"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "EUPIIBucketAccessDeniedCount"
  namespace           = "DataSovereignty/US"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "A US principal attempted to access an EU PII bucket and was denied. Investigate immediately."
  alarm_actions       = [var.alert_sns_topic_arn]
  treat_missing_data  = "notBreaching"
  tags                = { SovereignZone = "us", Severity = "critical", Regulation = "GDPR" }
}

resource "aws_config_config_rule" "us_s3_no_public_access" {
  provider = aws.us_east_1
  name     = "us-s3-no-public-access"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  }
  tags = { SovereignZone = "us", Regulation = "NYDFS-500" }
}

resource "aws_config_config_rule" "us_vpc_flow_logs_enabled" {
  provider = aws.us_east_1
  name     = "us-vpc-flow-logs-enabled"
  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }
  tags = { SovereignZone = "us", Regulation = "NYDFS-500" }
}

resource "aws_config_config_rule" "us_encrypted_volumes" {
  provider = aws.us_east_1
  name     = "us-encrypted-volumes"
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
  tags = { SovereignZone = "us", Regulation = "NYDFS-500" }
}

resource "aws_config_config_rule" "us_mfa_enabled" {
  provider = aws.us_east_1
  name     = "us-mfa-enabled-iam-console"
  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }
  tags = { SovereignZone = "us", Regulation = "NYDFS-500" }
}

resource "aws_config_config_rule" "us_rds_storage_encrypted" {
  provider = aws.us_east_1
  name     = "us-rds-storage-encrypted"
  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }
  tags = { SovereignZone = "us", Regulation = "NYDFS-500" }
}

resource "aws_config_config_rule" "us_cloudtrail_enabled" {
  provider = aws.us_east_1
  name     = "us-cloudtrail-enabled"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }
  tags = { SovereignZone = "us", Regulation = "NYDFS-500" }
}

output "us_banking_vpc_id"   { value = module.us_banking_vpc.vpc_id }
output "us_banking_vpc_cidr" { value = module.us_banking_vpc.vpc_cidr }
output "us_scp_id"           { value = module.us_scp.scp_id }
output "us_scp_arn"          { value = module.us_scp.scp_arn }
