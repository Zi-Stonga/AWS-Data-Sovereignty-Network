terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  backend "s3" {
    bucket         = "tfstate-data-sovereignty-eu"
    key            = "environments/eu/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    dynamodb_table = "tfstate-locks"
  }
}

provider "aws" {
  region = "eu-west-1"
  alias  = "eu_west_1"
  default_tags {
    tags = {
      SovereignZone = "eu"
      Environment   = var.environment
      ManagedBy     = "terraform"
    }
  }
}

provider "aws" {
  region = "eu-central-1"
  alias  = "eu_central_1"
  default_tags {
    tags = {
      SovereignZone = "eu"
      Environment   = var.environment
      ManagedBy     = "terraform"
    }
  }
}

variable "environment"         { type = string, default = "production" }
variable "eu_ou_id"            { type = string }
variable "flow_log_role_arn"   { type = string }
variable "alert_sns_topic_arn" { type = string }

module "eu_gdpr_vpc" {
  source               = "../../modules/vpc"
  providers            = { aws = aws.eu_west_1 }
  vpc_name             = "eu-gdpr-vpc"
  cidr_block           = "10.50.0.0/16"
  zone                 = "eu"
  availability_zones   = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
  private_subnet_cidrs = ["10.50.1.0/24", "10.50.2.0/24", "10.50.3.0/24"]
  enable_flow_logs     = true
  flow_log_group_name  = "/vpc/eu-gdpr/flowlogs"
  flow_log_role_arn    = var.flow_log_role_arn
  environment          = var.environment
}

module "eu_mifid_vpc" {
  source               = "../../modules/vpc"
  providers            = { aws = aws.eu_central_1 }
  vpc_name             = "eu-mifid-vpc"
  cidr_block           = "10.51.0.0/16"
  zone                 = "eu"
  availability_zones   = ["eu-central-1a", "eu-central-1b", "eu-central-1c"]
  private_subnet_cidrs = ["10.51.1.0/24", "10.51.2.0/24", "10.51.3.0/24"]
  enable_flow_logs     = true
  flow_log_group_name  = "/vpc/eu-mifid/flowlogs"
  flow_log_role_arn    = var.flow_log_role_arn
  environment          = var.environment
}

module "eu_scp" {
  source          = "../../modules/scp"
  target_ou_id    = var.eu_ou_id
  zone            = "eu"
  allowed_regions = ["eu-west-1", "eu-central-1"]
}

resource "aws_cloudwatch_metric_alarm" "eu_scp_violation" {
  provider            = aws.eu_west_1
  alarm_name          = "eu-scp-violation"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "SCPDenialCount"
  namespace           = "DataSovereignty/EU"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Fires on any SCP denial in the EU zone. Investigate immediately."
  alarm_actions       = [var.alert_sns_topic_arn]
  treat_missing_data  = "notBreaching"
  tags                = { SovereignZone = "eu", Severity = "critical" }
}

resource "aws_config_config_rule" "eu_s3_no_public_access" {
  provider = aws.eu_west_1
  name     = "eu-s3-no-public-access"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  }
  tags = { SovereignZone = "eu", Regulation = "GDPR" }
}

resource "aws_config_config_rule" "eu_vpc_flow_logs_enabled" {
  provider = aws.eu_west_1
  name     = "eu-vpc-flow-logs-enabled"
  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }
  tags = { SovereignZone = "eu", Regulation = "GDPR" }
}

resource "aws_config_config_rule" "eu_encrypted_volumes" {
  provider = aws.eu_west_1
  name     = "eu-encrypted-volumes"
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
  tags = { SovereignZone = "eu", Regulation = "GDPR" }
}

resource "aws_config_config_rule" "eu_mfa_enabled" {
  provider = aws.eu_west_1
  name     = "eu-mfa-enabled-iam-console"
  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }
  tags = { SovereignZone = "eu", Regulation = "DORA" }
}

output "eu_gdpr_vpc_id"  { value = module.eu_gdpr_vpc.vpc_id }
output "eu_mifid_vpc_id" { value = module.eu_mifid_vpc.vpc_id }
output "eu_scp_id"       { value = module.eu_scp.scp_id }
output "eu_scp_arn"      { value = module.eu_scp.scp_arn }
