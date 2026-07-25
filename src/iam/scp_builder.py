"""
IAM policy generation for each sovereign zone.
All statements use explicit actions. Wildcard actions are prohibited.
Conditions restrict by region using StringNotLike. SCPs contain only Deny statements.
"""

import json
import logging
from dataclasses import dataclass

from src.config.enums import AwsRegion, SovereignZone, ZONE_REGIONS
from src.config.settings import AppConfig

logger = logging.getLogger(__name__)


class IamPolicyError(Exception):
    """Raised when a policy cannot be constructed due to invalid inputs."""


@dataclass(frozen=True)
class PolicyStatement:
    """Single IAM statement. sid must be unique within a policy document."""

    sid: str
    effect: str
    actions: list[str]
    resources: list[str]
    conditions: dict


@dataclass(frozen=True)
class PolicyDocument:
    """Complete IAM or SCP policy document ready for serialisation."""

    version: str
    statements: list[PolicyStatement]
    zone: SovereignZone
    description: str


def _build_region_deny_condition(allowed_regions: list[AwsRegion]) -> dict:
    """Return a StringNotLike condition restricting requests to allowed_regions.

    Args:
        allowed_regions: Regions that are permitted for this zone.

    Returns:
        IAM condition dict using StringNotLike on aws:RequestedRegion.
    """
    return {
        "StringNotLike": {
            "aws:RequestedRegion": [r.value for r in allowed_regions]
        }
    }


def build_eu_scp(config: AppConfig) -> PolicyDocument:
    """Construct the EU data sovereignty SCP applied to the EU OU.

    Args:
        config: Validated application configuration.

    Returns:
        PolicyDocument for the EU SCP.

    Raises:
        IamPolicyError: When EU region list is empty.
    """
    eu_regions = ZONE_REGIONS[SovereignZone.EU]
    if not eu_regions:
        raise IamPolicyError("EU zone has no configured regions. Cannot build SCP.")

    statements = [
        PolicyStatement(
            sid="DenyNonEURegionDataResources",
            effect="Deny",
            actions=[
                "s3:PutObject", "s3:CopyObject",
                "rds:CreateDBInstance", "rds:CreateDBCluster",
                "rds:RestoreDBInstanceFromDBSnapshot",
                "ec2:RunInstances", "ec2:CreateVolume",
                "dynamodb:CreateTable", "dynamodb:RestoreTableFromBackup",
                "lambda:CreateFunction", "eks:CreateCluster", "ecs:CreateCluster",
            ],
            resources=["*"],
            conditions=_build_region_deny_condition(eu_regions),
        ),
        PolicyStatement(
            sid="DenyS3ReplicationOutsideEU",
            effect="Deny",
            actions=["s3:PutBucketReplication"],
            resources=["*"],
            conditions={"ArnNotLike": {"s3:ReplicationDestination": "arn:aws:s3:::*-eu-*"}},
        ),
        PolicyStatement(
            sid="DenyKMSKeyCreationOutsideEU",
            effect="Deny",
            actions=["kms:CreateKey", "kms:ReplicateKey", "kms:ScheduleKeyDeletion"],
            resources=["*"],
            conditions=_build_region_deny_condition(eu_regions),
        ),
        PolicyStatement(
            sid="DenyS3PublicAccess",
            effect="Deny",
            actions=[
                "s3:DeleteBucketPolicy", "s3:PutBucketAcl",
                "s3:PutBucketPolicy", "s3:PutObjectAcl",
            ],
            resources=["*"],
            conditions={
                "StringEquals": {
                    "s3:x-amz-acl": [
                        "public-read", "public-read-write", "authenticated-read",
                    ]
                }
            },
        ),
        PolicyStatement(
            sid="DenyDisableCloudTrail",
            effect="Deny",
            actions=[
                "cloudtrail:DeleteTrail",
                "cloudtrail:StopLogging",
                "cloudtrail:UpdateTrail",
            ],
            resources=["*"],
            conditions={},
        ),
        PolicyStatement(
            sid="DenyLeaveOrganization",
            effect="Deny",
            actions=["organizations:LeaveOrganization"],
            resources=["*"],
            conditions={},
        ),
    ]

    logger.info("Built EU SCP with %d statements", len(statements))
    return PolicyDocument(
        version="2012-10-17",
        statements=statements,
        zone=SovereignZone.EU,
        description=(
            "EU sovereign zone SCP. Enforces GDPR Article 44 and MiFID II Article 16 "
            "data residency at the infrastructure layer. Applied to the EU OU."
        ),
    )


def build_apac_scp(config: AppConfig) -> PolicyDocument:
    """Construct the APAC data sovereignty SCP applied to the APAC OU.

    Args:
        config: Validated application configuration.

    Returns:
        PolicyDocument for the APAC SCP.
    """
    apac_regions = ZONE_REGIONS[SovereignZone.APAC]
    statements = [
        PolicyStatement(
            sid="DenyNonAPACRegionDataResources",
            effect="Deny",
            actions=[
                "s3:PutObject", "s3:CopyObject",
                "rds:CreateDBInstance", "rds:CreateDBCluster",
                "ec2:RunInstances", "ec2:CreateVolume",
                "dynamodb:CreateTable",
            ],
            resources=["*"],
            conditions=_build_region_deny_condition(apac_regions),
        ),
        PolicyStatement(
            sid="DenyTGWPeeringToNonAPAC",
            effect="Deny",
            actions=[
                "ec2:CreateTransitGatewayPeeringAttachment",
                "ec2:AcceptTransitGatewayPeeringAttachment",
            ],
            resources=["*"],
            conditions={
                "StringNotLike": {"ec2:Region": [r.value for r in apac_regions]}
            },
        ),
        PolicyStatement(
            sid="DenyKMSKeyCreationOutsideAPAC",
            effect="Deny",
            actions=["kms:CreateKey", "kms:ReplicateKey"],
            resources=["*"],
            conditions=_build_region_deny_condition(apac_regions),
        ),
        PolicyStatement(
            sid="DenyDisableCloudTrail",
            effect="Deny",
            actions=[
                "cloudtrail:DeleteTrail",
                "cloudtrail:StopLogging",
                "cloudtrail:UpdateTrail",
            ],
            resources=["*"],
            conditions={},
        ),
        PolicyStatement(
            sid="DenyLeaveOrganization",
            effect="Deny",
            actions=["organizations:LeaveOrganization"],
            resources=["*"],
            conditions={},
        ),
    ]

    logger.info("Built APAC SCP with %d statements", len(statements))
    return PolicyDocument(
        version="2012-10-17",
        statements=statements,
        zone=SovereignZone.APAC,
        description=(
            "APAC sovereign zone SCP. Enforces MAS TRM 2021 data residency "
            "in ap-southeast-1. Blocks TGW peering to non-APAC regions."
        ),
    )


def build_us_scp(config: AppConfig) -> PolicyDocument:
    """Construct the US zone SCP applied to the US OU.

    Args:
        config: Validated application configuration.

    Returns:
        PolicyDocument for the US SCP.
    """
    us_regions = ZONE_REGIONS[SovereignZone.US]
    statements = [
        PolicyStatement(
            sid="DenyEUPIIBucketsFromUS",
            effect="Deny",
            actions=["s3:GetObject", "s3:PutObject", "s3:CopyObject", "s3:ListBucket"],
            resources=[
                "arn:aws:s3:::*-eu-pii-*", "arn:aws:s3:::*-eu-pii-*/*",
                "arn:aws:s3:::*-eu-gdpr-*", "arn:aws:s3:::*-eu-gdpr-*/*",
                "arn:aws:s3:::*-eu-mifid-*", "arn:aws:s3:::*-eu-mifid-*/*",
            ],
            conditions={
                "StringLike": {
                    "aws:RequestedRegion": [r.value for r in us_regions]
                }
            },
        ),
        PolicyStatement(
            sid="DenyNonUSRegionDataResources",
            effect="Deny",
            actions=["rds:CreateDBInstance", "ec2:RunInstances", "dynamodb:CreateTable"],
            resources=["*"],
            conditions=_build_region_deny_condition(us_regions),
        ),
        PolicyStatement(
            sid="DenyDisableCloudTrail",
            effect="Deny",
            actions=[
                "cloudtrail:DeleteTrail",
                "cloudtrail:StopLogging",
                "cloudtrail:UpdateTrail",
            ],
            resources=["*"],
            conditions={},
        ),
        PolicyStatement(
            sid="DenyLeaveOrganization",
            effect="Deny",
            actions=["organizations:LeaveOrganization"],
            resources=["*"],
            conditions={},
        ),
    ]

    logger.info("Built US SCP with %d statements", len(statements))
    return PolicyDocument(
        version="2012-10-17",
        statements=statements,
        zone=SovereignZone.US,
        description=(
            "US zone SCP. Blocks access to EU PII/GDPR/MiFID S3 buckets from US regions. "
            "Enforces GLBA and NYDFS Part 500 data residency."
        ),
    )


def serialise_policy(document: PolicyDocument) -> str:
    """Serialise a PolicyDocument to a JSON string suitable for AWS APIs.

    Args:
        document: The policy document to serialise.

    Returns:
        JSON string of the policy. Empty Condition blocks are omitted.
    """
    raw: dict = {
        "Version": document.version,
        "Statement": [
            {
                "Sid": stmt.sid,
                "Effect": stmt.effect,
                "Action": stmt.actions,
                "Resource": stmt.resources,
                **({"Condition": stmt.conditions} if stmt.conditions else {}),
            }
            for stmt in document.statements
        ],
    }
    return json.dumps(raw, indent=2)
