terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  backend "s3" {
    bucket         = "tfstate-data-sovereignty-apac"
    key            = "environments/apac/terraform.tfstate"
    region         = "ap-southeast-1"
    encrypt        = true
    dynamodb_table = "tfstate-locks"
  }
}

provider "aws" {
  region = "ap-southeast-1"
  alias  = "ap_southeast_1"
  default_tags {
    tags = {
      SovereignZone = "apac"
      Environment   = var.environment
      ManagedBy     = "terraform"
    }
  }
}

variable "environment"         { type = string, default = "production" }
variable "apac_ou_id"          { type = string }
variable "flow_log_role_arn"   { type = string }
variable "alert_sns_topic_arn" { type = string }

module "apac_mas_vpc" {
  source               = "../../modules/vpc"
  providers            = { aws = aws.ap_southeast_1 }
  vpc_name             = "apac-mas-vpc"
  cidr_block           = "10.60.0.0/16"
  zone                 = "apac"
  availability_zones   = ["ap-southeast-1a", "ap-southeast-1b", "ap-southeast-1c"]
  private_subnet_cidrs = ["10.60.1.0/24", "10.60.2.0/24", "10.60.3.0/24"]
  enable_flow_logs     = true
  flow_log_group_name  = "/vpc/apac-mas/flowlogs"
  flow_log_role_arn    = var.flow_log_role_arn
  environment          = var.environment
}

module "apac_scp" {
  source          = "../../modules/scp"
  target_ou_id    = var.apac_ou_id
  zone            = "apac"
  allowed_regions = ["ap-southeast-1"]
}

resource "aws_cloudwatch_metric_alarm" "apac_scp_violation" {
  provider            = aws.ap_southeast_1
  alarm_name          = "apac-scp-violation"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "SCPDenialCount"
  namespace           = "DataSovereignty/APAC"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Fires on any SCP denial in the APAC zone. Investigate immediately."
  alarm_actions       = [var.alert_sns_topic_arn]
  treat_missing_data  = "notBreaching"
  tags                = { SovereignZone = "apac", Severity = "critical" }
}

resource "aws_config_config_rule" "apac_s3_no_public_access" {
  provider = aws.ap_southeast_1
  name     = "apac-s3-no-public-access"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  }
  tags = { SovereignZone = "apac", Regulation = "MAS-TRM-2021" }
}

resource "aws_config_config_rule" "apac_vpc_flow_logs_enabled" {
  provider = aws.ap_southeast_1
  name     = "apac-vpc-flow-logs-enabled"
  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }
  tags = { SovereignZone = "apac", Regulation = "MAS-TRM-2021" }
}

resource "aws_config_config_rule" "apac_encrypted_volumes" {
  provider = aws.ap_southeast_1
  name     = "apac-encrypted-volumes"
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
  tags = { SovereignZone = "apac", Regulation = "MAS-TRM-2021" }
}

resource "aws_config_config_rule" "apac_cloudtrail_enabled" {
  provider = aws.ap_southeast_1
  name     = "apac-cloudtrail-enabled"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }
  tags = { SovereignZone = "apac", Regulation = "MAS-TRM-2021" }
}

output "apac_mas_vpc_id" { value = module.apac_mas_vpc.vpc_id }
output "apac_mas_vpc_cidr" { value = module.apac_mas_vpc.vpc_cidr }
output "apac_scp_id"     { value = module.apac_scp.scp_id }
output "apac_scp_arn"    { value = module.apac_scp.scp_arn }
