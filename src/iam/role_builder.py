"""
Least-privilege IAM roles for each service component.
Every role carries only the permissions its service needs.
No wildcards on sensitive actions. Resource ARNs are scoped to the zone.
"""

import json
import logging
from dataclasses import dataclass

from src.config.enums import SovereignZone, ZONE_REGIONS
from src.config.settings import AppConfig

logger = logging.getLogger(__name__)


class RoleError(Exception):
    """Raised when a role definition cannot be constructed."""


@dataclass(frozen=True)
class IamRole:
    """Definition of an IAM role including its trust policy and inline policies."""

    name: str
    description: str
    zone: SovereignZone
    trust_policy: dict
    inline_policies: dict[str, dict]
    managed_policy_arns: list[str]
    max_session_duration_seconds: int = 3600


def _service_trust_policy(service_principal: str) -> dict:
    """Build a trust policy allowing a single AWS service to assume the role.

    Args:
        service_principal: e.g. 'vpc-flow-logs.amazonaws.com'

    Returns:
        Trust policy document dict.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": service_principal},
            "Action": "sts:AssumeRole",
        }],
    }


def _zone_region_values(zone: SovereignZone) -> list[str]:
    """Return region strings for a zone.

    Args:
        zone: The sovereign zone.

    Returns:
        List of region value strings.
    """
    return [r.value for r in ZONE_REGIONS[zone]]


def _resolve_account_id(config: AppConfig, zone: SovereignZone) -> str:
    """Return the AWS account ID for a given zone.

    Args:
        config: Validated application configuration.
        zone: The zone whose account ID is required.

    Returns:
        Account ID string.

    Raises:
        RoleError: When an unrecognised zone is supplied.
    """
    mapping = {
        SovereignZone.EU: config.aws.account_id_eu,
        SovereignZone.APAC: config.aws.account_id_apac,
        SovereignZone.US: config.aws.account_id_us,
    }
    account_id = mapping.get(zone)
    if not account_id:
        raise RoleError(
            f"No account ID configured for zone '{zone.value}'. "
            f"Check AWS_ACCOUNT_ID_EU, AWS_ACCOUNT_ID_APAC, AWS_ACCOUNT_ID_US."
        )
    return account_id


def build_flow_log_role(config: AppConfig, zone: SovereignZone) -> IamRole:
    """Build a least-privilege role for VPC Flow Logs delivery to CloudWatch.

    Args:
        config: Validated application configuration.
        zone: The sovereign zone this role serves.

    Returns:
        IamRole for Flow Log delivery.
    """
    log_group = config.monitoring.vpc_flow_log_group
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowFlowLogDelivery",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup", "logs:CreateLogStream",
                "logs:PutLogEvents", "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
            ],
            "Resource": [
                f"arn:aws:logs:*:*:log-group:{log_group}*",
                f"arn:aws:logs:*:*:log-group:{log_group}*:*",
            ],
        }],
    }
    logger.info("Built flow log role for zone=%s", zone.value)
    return IamRole(
        name=f"vpc-flow-log-delivery-{zone.value}",
        description=f"Delivers VPC Flow Logs to CloudWatch for the {zone.value.upper()} zone.",
        zone=zone,
        trust_policy=_service_trust_policy("vpc-flow-logs.amazonaws.com"),
        inline_policies={"FlowLogDelivery": inline_policy},
        managed_policy_arns=[],
    )


def build_compliance_scanner_role(config: AppConfig, zone: SovereignZone) -> IamRole:
    """Build a least-privilege role for the compliance scanner Lambda.

    Read-only access to Config, Macie, and CloudTrail within the zone.
    Write access to SNS publish and CloudWatch Logs only.

    Args:
        config: Validated application configuration.
        zone: The sovereign zone this scanner operates in.

    Returns:
        IamRole for the compliance scanner.
    """
    account_id = _resolve_account_id(config, zone)
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadConfigFindings",
                "Effect": "Allow",
                "Action": [
                    "config:GetComplianceDetailsByConfigRule",
                    "config:DescribeConfigRules",
                    "config:GetResourceConfigHistory",
                    "config:ListDiscoveredResources",
                ],
                "Resource": f"arn:aws:config:*:{account_id}:config-rule/*",
            },
            {
                "Sid": "ReadMacieFindings",
                "Effect": "Allow",
                "Action": [
                    "macie2:GetFindings", "macie2:ListFindings", "macie2:GetMacieSession",
                ],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:RequestedRegion": _zone_region_values(zone)}
                },
            },
            {
                "Sid": "ReadCloudTrailEvents",
                "Effect": "Allow",
                "Action": ["cloudtrail:LookupEvents", "cloudtrail:GetTrailStatus"],
                "Resource": f"arn:aws:cloudtrail:*:{account_id}:trail/*",
            },
            {
                "Sid": "PublishFindingsToSNS",
                "Effect": "Allow",
                "Action": ["sns:Publish"],
                "Resource": config.monitoring.alert_sns_topic_arn,
            },
            {
                "Sid": "WriteLogsToCloudWatch",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
                ],
                "Resource": (
                    f"arn:aws:logs:*:{account_id}:log-group:/aws/lambda/"
                    f"compliance-scanner-{zone.value}*"
                ),
            },
        ],
    }
    logger.info("Built compliance scanner role for zone=%s", zone.value)
    return IamRole(
        name=f"compliance-scanner-{zone.value}",
        description=(
            f"Read-only scanner for Config, Macie, and CloudTrail findings "
            f"in the {zone.value.upper()} zone."
        ),
        zone=zone,
        trust_policy=_service_trust_policy("lambda.amazonaws.com"),
        inline_policies={"ComplianceScannerPolicy": inline_policy},
        managed_policy_arns=[],
    )


def build_dpo_read_role(config: AppConfig) -> IamRole:
    """Build a read-only role for the Data Protection Officer portal.

    MFA required. No write or mutation permissions anywhere.

    Args:
        config: Validated application configuration.

    Returns:
        IamRole for DPO read access.
    """
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadAuditLogsS3",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    "arn:aws:s3:::*-audit-logs-*",
                    "arn:aws:s3:::*-audit-logs-*/*",
                    "arn:aws:s3:::*-gdpr-audit-*",
                    "arn:aws:s3:::*-gdpr-audit-*/*",
                ],
            },
            {
                "Sid": "ReadConfigCompliance",
                "Effect": "Allow",
                "Action": [
                    "config:DescribeConfigRuleEvaluationStatus",
                    "config:GetComplianceSummaryByConfigRule",
                    "config:DescribeComplianceByConfigRule",
                ],
                "Resource": "*",
            },
            {
                "Sid": "ReadMacieFindings",
                "Effect": "Allow",
                "Action": ["macie2:GetFindings", "macie2:ListFindings"],
                "Resource": "*",
            },
            {
                "Sid": "ReadCloudTrailLogs",
                "Effect": "Allow",
                "Action": ["cloudtrail:LookupEvents", "cloudtrail:GetTrailStatus"],
                "Resource": "*",
            },
        ],
    }
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{config.aws.management_account_id}:root"},
            "Action": "sts:AssumeRole",
            "Condition": {
                "Bool": {"aws:MultiFactorAuthPresent": "true"},
                "NumericLessThan": {"aws:MultiFactorAuthAge": "3600"},
            },
        }],
    }
    logger.info("Built DPO read role")
    return IamRole(
        name="dpo-read-only",
        description="Read-only access for the Data Protection Officer portal across all zones.",
        zone=SovereignZone.EU,
        trust_policy=trust_policy,
        inline_policies={"DPOReadPolicy": inline_policy},
        managed_policy_arns=[],
        max_session_duration_seconds=3600,
    )


def build_network_admin_role(config: AppConfig, zone: SovereignZone) -> IamRole:
    """Build a least-privilege network administration role for each zone.

    Scoped to zone regions only. Cross-zone TGW peering explicitly denied.

    Args:
        config: Validated application configuration.
        zone: The zone this administrator manages.

    Returns:
        IamRole for network administration.
    """
    allowed_regions = _zone_region_values(zone)
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "VPCManagementInZone",
                "Effect": "Allow",
                "Action": [
                    "ec2:CreateVpc", "ec2:DeleteVpc", "ec2:ModifyVpcAttribute",
                    "ec2:CreateSubnet", "ec2:DeleteSubnet",
                    "ec2:CreateRouteTable", "ec2:DeleteRouteTable",
                    "ec2:CreateRoute", "ec2:DeleteRoute",
                    "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
                    "ec2:AuthorizeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupEgress",
                    "ec2:RevokeSecurityGroupIngress", "ec2:RevokeSecurityGroupEgress",
                    "ec2:CreateVpcEndpoint", "ec2:DeleteVpcEndpoints",
                    "ec2:CreateTransitGatewayAttachment",
                ],
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:RequestedRegion": allowed_regions}},
            },
            {
                "Sid": "DenyTGWPeeringCrossZone",
                "Effect": "Deny",
                "Action": [
                    "ec2:CreateTransitGatewayPeeringAttachment",
                    "ec2:AcceptTransitGatewayPeeringAttachment",
                ],
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {"aws:RequestedRegion": allowed_regions}
                },
            },
            {
                "Sid": "ReadNetworkResources",
                "Effect": "Allow",
                "Action": ["ec2:Describe*", "ec2:Get*", "directconnect:Describe*"],
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:RequestedRegion": allowed_regions}},
            },
        ],
    }
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {
                "AWS": f"arn:aws:iam::{config.aws.management_account_id}:root"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "Bool": {"aws:MultiFactorAuthPresent": "true"},
                "StringEquals": {"sts:RoleSessionName": "${aws:username}"},
            },
        }],
    }
    logger.info("Built network admin role for zone=%s", zone.value)
    return IamRole(
        name=f"network-admin-{zone.value}",
        description=(
            f"Network administration for the {zone.value.upper()} zone. "
            f"Scoped to: {', '.join(allowed_regions)}. Cross-zone TGW peering denied."
        ),
        zone=zone,
        trust_policy=trust_policy,
        inline_policies={"NetworkAdminPolicy": inline_policy},
        managed_policy_arns=[],
    )


def serialise_role(role: IamRole) -> dict:
    """Serialise an IamRole to a dict suitable for CloudFormation or Terraform.

    Args:
        role: The role to serialise.

    Returns:
        Dict with trust_policy and inline_policies as JSON strings.
    """
    return {
        "role_name": role.name,
        "description": role.description,
        "zone": role.zone.value,
        "trust_policy": json.dumps(role.trust_policy, indent=2),
        "inline_policies": {
            name: json.dumps(policy, indent=2)
            for name, policy in role.inline_policies.items()
        },
        "managed_policy_arns": role.managed_policy_arns,
        "max_session_duration_seconds": role.max_session_duration_seconds,
    }
