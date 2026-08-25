"""S3 resource collector.

Fetches every S3 bucket in the account together with its bucket
policy, ACL, and public access block configuration, producing a JSON
snapshot (``data/raw_s3.json``) for later graph construction.

S3 is a per-bucket API surface: several calls commonly fail with
``AccessDenied`` on hardened buckets or ``NoSuch*`` when optional
configurations simply do not exist. Every per-bucket call therefore
degrades to a warning and records an explicit ``{"error": ...}`` so
the analysis layer can distinguish "locked down" from "unscannable".
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from cloud_path_mapper.auth.session import build_session, verify_session
from cloud_path_mapper.config import DEFAULT_PROFILE, DEFAULT_REGION, RAW_S3_PATH

logger = logging.getLogger(__name__)

# Error codes that mean "configuration absent", not "problem".
_EXPECTED_ABSENT_CODES = {
    "NoSuchBucketPolicy",
    "NoSuchPublicAccessBlockConfiguration",
    "NoSuchAcl",
}


class S3Collector:
    """Collects an S3 posture snapshot for a single AWS account.

    Attributes:
        session: The authenticated boto3 session to collect with.
        snapshot: The in-progress collection result.
    """

    def __init__(self, session: boto3.Session) -> None:
        """Initialize the collector.

        Args:
            session: An authenticated :class:`boto3.Session`.
        """
        self.session = session
        self.account_id = verify_session(session)["account"]
        self.snapshot: dict = {
            "account_id": self.account_id,
            "collected_at": None,
            "buckets": [],
        }

    def collect_all(self) -> dict:
        """Run every collector and return the assembled snapshot.

        Returns:
            The complete S3 snapshot as a JSON-serializable dict.
        """
        self.snapshot["collected_at"] = datetime.now(timezone.utc).isoformat()
        self.snapshot["buckets"] = self.collect_buckets()
        logger.info("Collected %d buckets", len(self.snapshot["buckets"]))
        return self.snapshot

    def collect_buckets(self) -> list[dict]:
        """List all buckets and enrich each with policy/ACL/PAB data.

        Bucket region is resolved via ``get_bucket_location`` (which
        returns ``None`` for us-east-1) so the analysis layer can build
        fully qualified ARNs later.

        Returns:
            A list of bucket records.
        """
        buckets: list[dict] = []
        for bucket in self.session.client("s3").list_buckets().get("Buckets", []):
            name = bucket["Name"]
            record: dict = {
                "type": "bucket",
                "name": name,
                "arn": f"arn:aws:s3:::{name}",
                "created": bucket["CreationDate"].isoformat(),
                "region": self._get_bucket_region(name),
                "policy": self._get_bucket_policy(name),
                "acl": self._get_bucket_acl(name),
                "public_access_block": self._get_public_access_block(name),
            }
            record["is_publicly_exposed"] = self._assess_public_exposure(record)
            buckets.append(record)
            logger.debug("Collected bucket %s (%s)", name, record["region"])
        return buckets

    # ------------------------------------------------------------------
    # Per-bucket API calls (each degrades gracefully)
    # ------------------------------------------------------------------

    def _get_bucket_region(self, bucket_name: str) -> str:
        """Resolve the region hosting a bucket.

        Args:
            bucket_name: The bucket to locate.

        Returns:
            Region name; ``us-east-1`` when the API returns None.
        """
        try:
            location = self.session.client("s3").get_bucket_location(Bucket=bucket_name)
            return location.get("LocationConstraint") or "us-east-1"
        except ClientError as exc:
            logger.warning("Could not get location for bucket %s: %s", bucket_name, exc)
            return "unknown"

    def _get_bucket_policy(self, bucket_name: str) -> dict:
        """Fetch the bucket policy document, if one exists.

        Args:
            bucket_name: The bucket to inspect.

        Returns:
            Either ``{"status": "ok", "document": {...}}``,
            ``{"status": "absent"}``, or ``{"status": "error", "error": ...}``.
        """
        try:
            response = self.session.client("s3").get_bucket_policy(Bucket=bucket_name)
            return {"status": "ok", "document": json.loads(response["Policy"])}
        except ClientError as exc:
            return self._classify_error(bucket_name, "policy", exc)
        except json.JSONDecodeError as exc:
            logger.warning("Bucket %s has malformed policy JSON: %s", bucket_name, exc)
            return {"status": "error", "error": f"malformed policy JSON: {exc}"}

    def _get_bucket_acl(self, bucket_name: str) -> dict:
        """Fetch the bucket ACL grants.

        Args:
            bucket_name: The bucket to inspect.

        Returns:
            Either ``{"status": "ok", "grants": [...]}``,
            ``{"status": "absent"}``, or ``{"status": "error", "error": ...}``.
        """
        try:
            response = self.session.client("s3").get_bucket_acl(Bucket=bucket_name)
            return {"status": "ok", "grants": response["Grants"], "owner": response.get("Owner", {})}
        except ClientError as exc:
            return self._classify_error(bucket_name, "ACL", exc)

    def _get_public_access_block(self, bucket_name: str) -> dict:
        """Fetch the bucket-level Public Access Block configuration.

        Args:
            bucket_name: The bucket to inspect.

        Returns:
            Either ``{"status": "ok", "configuration": {...}}``,
            ``{"status": "absent"}`` (treated as all-blocks-off by the
            rule engine), or ``{"status": "error", "error": ...}``.
        """
        try:
            response = self.session.client("s3").get_public_access_block(Bucket=bucket_name)
            return {"status": "ok", "configuration": response["PublicAccessBlockConfiguration"]}
        except ClientError as exc:
            return self._classify_error(bucket_name, "public access block", exc)

    def _classify_error(self, bucket_name: str, what: str, exc: ClientError) -> dict:
        """Convert a ClientError into a structured status record.

        Args:
            bucket_name: Bucket the failed call targeted.
            what: Human label of what was being fetched.
            exc: The raised error.

        Returns:
            ``{"status": "absent"}`` when the configuration simply does
            not exist, otherwise ``{"status": "error", ...}`` with the
            AWS error code preserved for the analysis layer.
        """
        code = exc.response["Error"]["Code"]
        if code in _EXPECTED_ABSENT_CODES or code == "NoSuchConfiguration":
            logger.debug("Bucket %s has no %s configuration", bucket_name, what)
            return {"status": "absent"}
        if code in ("AccessDenied",):
            logger.warning("AccessDenied reading %s of bucket %s", what, bucket_name)
        else:
            logger.warning("Failed reading %s of bucket %s: %s", what, bucket_name, code)
        return {"status": "error", "error_code": code}

    @staticmethod
    def _assess_public_exposure(record: dict) -> bool:
        """Cheap heuristic flag: could this bucket serve public reads?

        This is NOT the authoritative misconfig decision (the Week 2+
        rule engine owns that); it is a convenience flag computed from
        raw signals: ACL grants to the AllUsers/AuthenticatedUsers
        groups combined with a permissive policy statement.

        Args:
            record: A collected bucket record.

        Returns:
            True if any signal indicates public readability/exposure.
        """
        public_principals = ("AllUsers", "http://acs.amazonaws.com/groups/global/AllUsers")

        acl = record["acl"]
        if acl["status"] == "ok":
            for grant in acl["grants"]:
                uri = grant.get("Grantee", {}).get("URI", "")
                if any(p in uri for p in public_principals):
                    return True

        policy = record["policy"]
        if policy["status"] == "ok":
            for statement in policy["document"].get("Statement", []):
                principal = statement.get("Principal")
                effect_allow = statement.get("Effect") == "Allow"
                wildcard_principal = (
                    principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*")
                )
                if effect_allow and wildcard_principal:
                    return True

        pab = record["public_access_block"]
        if pab["status"] == "absent":
            return False

        return False


def run(profile_name: str | None = DEFAULT_PROFILE, region_name: str | None = DEFAULT_REGION) -> dict:
    """Execute a full S3 collection and persist it to disk.

    Args:
        profile_name: AWS CLI profile to authenticate with.
        region_name: Optional region override.

    Returns:
        The saved S3 snapshot.
    """
    session = build_session(profile_name=profile_name, region_name=region_name)
    collector = S3Collector(session)
    collector.collect_all()

    RAW_S3_PATH.parent.mkdir(parents=True, exist_ok=True)
    RAW_S3_PATH.write_text(json.dumps(collector.snapshot, indent=2, default=str))
    logger.info("Snapshot written to %s", RAW_S3_PATH)
    return collector.snapshot
