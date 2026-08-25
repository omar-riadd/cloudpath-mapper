"""EC2 resource collector with multi-region fan-out.

Fetches EC2 instances and security groups from *every* region enabled
for the authenticated account, producing a JSON snapshot
(``data/raw_ec2.json``) for later graph construction.

The critical capture target is each instance's ``IamInstanceProfile``:
this is the bridge edge the graph builder uses to connect an EC2
instance (potentially internet-exposed via security groups) to the IAM
role it can assume at runtime. Security groups are collected with full
ingress rules so the engine can later detect ``0.0.0.0/0`` exposure.

Attackers frequently deploy resources into forgotten or opt-in regions
assuming nobody looks there, so coverage is deliberately global: every
region returned by ``describe_regions`` is scanned, and a per-region
failure (e.g., ``AuthFailure``/``UnauthorizedOperation`` on opted-out
or restricted regions) degrades to a warning and skips to the next
region without aborting the overall collection.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from cloud_path_mapper.auth.session import build_session, verify_session
from cloud_path_mapper.config import DEFAULT_PROFILE, DEFAULT_REGION, RAW_EC2_PATH

logger = logging.getLogger(__name__)

OPEN_CIDR = "0.0.0.0/0"
OPEN_CIDR_V6 = "::/0"


def list_enabled_regions(session: boto3.Session) -> list[str]:
    """Fetch all regions enabled for the authenticated account.

    Args:
        session: An authenticated :class:`boto3.Session`.

    Returns:
        Sorted list of region names (e.g., ``["ap-south-1", ...]``).
        Falls back to a minimal default when the API call fails so a
        regional STS/S3 hiccup cannot zero out the entire scan.
    """
    try:
        response = session.client("ec2", region_name="us-east-1").describe_regions()
        return sorted(r["RegionName"] for r in response["Regions"])
    except ClientError as exc:
        logger.warning("Could not enumerate regions, falling back to session default: %s", exc)
        fallback = [session.region_name or "us-east-1"]
        return sorted(set(fallback))


class RegionCollector:
    """Collects EC2 resources from exactly one region.

    Attributes:
        session: The authenticated boto3 session to collect with.
        region: The region this collector targets.
        client: The regional EC2 client.
    """

    def __init__(self, session: boto3.Session, region_name: str, account_id: str) -> None:
        """Initialize the collector.

        Args:
            session: An authenticated :class:`boto3.Session`.
            region_name: The EC2 region to scan.
            account_id: Account ID resolved once by the caller, reused
                across all regional collectors for ARN construction.
        """
        self.session = session
        self.region = region_name
        self.account_id = account_id
        self.client = session.client("ec2", region_name=region_name)

    def collect(self) -> dict[str, list[dict]]:
        """Collect instances and security groups for this region.

        A region-level failure (auth revocation, opted-out region,
        throttling exhaustion) propagates as ``ClientError`` so the
        orchestrating fan-out can skip just this region.

        Returns:
            Dict with ``instances`` and ``security_groups`` lists; every
            record carries its ``region`` for cross-region uniqueness.
        """
        return {
            "instances": self.collect_instances(),
            "security_groups": self.collect_security_groups(),
        }

    def collect_instances(self) -> list[dict]:
        """List all EC2 instances in this region with their IAM profiles.

        Pagination is handled via ``describe_instances`` paginator; the
        response nests reservations -> instances, which are flattened
        here into a single instance list.

        Returns:
            A list of instance records including ``iam_instance_profile``
            (the future graph bridge to an IAM role), public/private IPs,
            attached security group IDs, and the owning ``region``.
        """
        account_id = self.account_id
        instances: list[dict] = []
        pages = self.client.get_paginator("describe_instances").paginate()
        for reservation in pages.search("Reservations"):
            for instance in reservation.get("Instances", []):
                record: dict = {
                    "type": "instance",
                    "instance_id": instance["InstanceId"],
                    "arn": (
                        f"arn:aws:ec2:{self.region}:{account_id}:"
                        f"instance/{instance['InstanceId']}"
                    ),
                    "region": self.region,
                    "state": instance.get("State", {}).get("Name"),
                    "instance_type": instance.get("InstanceType"),
                    "public_ip": instance.get("PublicIpAddress"),
                    "private_ip": instance.get("PrivateIpAddress"),
                    "key_name": instance.get("KeyName"),
                    "security_group_ids": [
                        sg["GroupId"] for sg in instance.get("SecurityGroups", [])
                    ],
                    "iam_instance_profile": self._extract_instance_profile(instance),
                }
                record["has_public_ip"] = record["public_ip"] is not None
                instances.append(record)
                logger.debug("Collected instance %s", record["instance_id"])
        return instances

    def collect_security_groups(self) -> list[dict]:
        """List all security groups in this region with ingress detail.

        Each ingress rule's ``IpRanges`` are preserved verbatim and
        augmented with a derived ``is_open_world`` flag so the analysis
        layer can find ``0.0.0.0/0`` exposure without re-parsing CIDRs.

        Returns:
            A list of security group records tagged with ``region``.
        """
        groups: list[dict] = []
        for page in self.client.get_paginator("describe_security_groups").paginate():
            for sg in page["SecurityGroups"]:
                record: dict = {
                    "type": "security_group",
                    "group_id": sg["GroupId"],
                    "arn": f"arn:aws:ec2:{self.region}:{self.account_id}:security-group/{sg['GroupId']}",
                    "region": self.region,
                    "group_name": sg.get("GroupName"),
                    "description": sg.get("Description"),
                    "vpc_id": sg.get("VpcId"),
                    "ingress_rules": [
                        self._normalize_ingress_rule(rule) for rule in sg.get("IpPermissions", [])
                    ],
                    "egress_rules": [
                        self._normalize_ingress_rule(rule) for rule in sg.get("IpPermissionsEgress", [])
                    ],
                }
                record["has_open_ingress"] = any(
                    r["is_open_world"] for r in record["ingress_rules"]
                )
                groups.append(record)
                logger.debug("Collected security group %s", record["group_id"])
        return groups

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_instance_profile(instance: dict) -> dict | None:
        """Normalize an instance profile association to ARN + name.

        Args:
            instance: Raw instance dict from ``describe_instances``.

        Returns:
            ``{"arn": ..., "name": ..., "id": ...}`` or None when the
            instance has no profile attached. Note that the API only
            exposes the *instance profile* ARN here; role resolution
            from profile -> roles happens against the IAM snapshot
            during graph building.
        """
        profile = instance.get("IamInstanceProfile")
        if not profile:
            return None
        return {
            "arn": profile.get("Arn"),
            "name": profile.get("Name"),
            "id": profile.get("Id"),
        }

    @staticmethod
    def _normalize_ingress_rule(rule: dict) -> dict:
        """Normalize an IpPermission, flagging open-world CIDRs.

        Args:
            rule: Raw ``IpPermission`` dict.

        Returns:
            The rule with ``is_open_world`` set on the record and on
            each individual range entry.
        """
        normalized = dict(rule)

        for range_key in ("IpRanges", "Ipv6Ranges"):
            ranges = normalized.get(range_key, [])
            for cidr_entry in ranges:
                cidr = cidr_entry.get("CidrIp") or cidr_entry.get("CidrIpv6")
                cidr_entry["is_open_world"] = cidr in (OPEN_CIDR, OPEN_CIDR_V6)
            if ranges:
                normalized.setdefault("is_open_world", any(r["is_open_world"] for r in ranges))

        normalized.setdefault("is_open_world", False)
        return normalized


def run(profile_name: str | None = DEFAULT_PROFILE, region_name: str | None = DEFAULT_REGION) -> dict:
    """Execute a multi-region EC2 collection and persist it to disk.

    Enumerates every region enabled for the account (unless an explicit
    ``region_name`` override narrows the scan) and fans out a
    :class:`RegionCollector` per region. Regions that fail — e.g.,
    ``AuthFailure`` or ``UnauthorizedOperation`` on opted-out or
    SCP-restricted regions — are recorded and skipped; remaining
    regions continue normally.

    Args:
        profile_name: AWS CLI profile to authenticate with.
        region_name: Optional single-region override instead of global
            fan-out.

    Returns:
        The saved EC2 snapshot. Top-level ``instances`` and
        ``security_groups`` are flattened across all successful regions;
        failed regions are listed under ``failed_regions``.
    """
    session = build_session(profile_name=profile_name, region_name=region_name)
    account_id = verify_session(session)["account"]

    if region_name:
        regions = [region_name]
    else:
        regions = list_enabled_regions(session)
    logger.info("Scanning %d region(s): %s", len(regions), ", ".join(regions))

    snapshot: dict = {
        "account_id": account_id,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "regions_scanned": [],
        "failed_regions": [],
        "instances": [],
        "security_groups": [],
    }

    for region in regions:
        try:
            collector = RegionCollector(session, region_name=region, account_id=account_id)
            result = collector.collect()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", str(exc))
            logger.warning("Skipping region %s (%s): %s", region, code, message)
            snapshot["failed_regions"].append({"region": region, "error_code": code})
            continue

        snapshot["regions_scanned"].append(region)
        snapshot["instances"].extend(result["instances"])
        snapshot["security_groups"].extend(result["security_groups"])
        logger.info(
            "Region %s: %d instance(s), %d security group(s)",
            region,
            len(result["instances"]),
            len(result["security_groups"]),
        )

    logger.info(
        "Collection finished: %d instance(s), %d security group(s) across %d/%d region(s)"
        " (%d skipped)",
        len(snapshot["instances"]),
        len(snapshot["security_groups"]),
        len(snapshot["regions_scanned"]),
        len(regions),
        len(snapshot["failed_regions"]),
    )

    RAW_EC2_PATH.parent.mkdir(parents=True, exist_ok=True)
    RAW_EC2_PATH.write_text(json.dumps(snapshot, indent=2, default=str))
    logger.info("Snapshot written to %s", RAW_EC2_PATH)
    return snapshot
