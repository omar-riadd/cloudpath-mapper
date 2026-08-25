"""IAM resource collector.

Fetches IAM Users, Roles, Groups, their attached managed policies and
inline policies from an AWS account, producing a single JSON snapshot
(``data/raw_iam.json``) that later analysis stages consume as a local
fixture instead of hitting the AWS API again.

Every list operation uses boto3 paginators so accounts with large
numbers of identities are handled correctly.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from cloud_path_mapper.auth.session import build_session, verify_session
from cloud_path_mapper.config import DEFAULT_PROFILE, DEFAULT_REGION, RAW_IAM_PATH

logger = logging.getLogger(__name__)

# Policies below this ARN prefix are AWS-managed; flag them so the graph
# builder can distinguish customer-managed over-permission (interesting)
# from AWS defaults (noise).
AWS_MANAGED_PREFIX = "arn:aws:iam::aws:policy/"


class IAMCollector:
    """Collects a full IAM snapshot for a single AWS account.

    Attributes:
        session: The authenticated boto3 session to collect with.
        snapshot: The in-progress collection result, keyed by entity type.
    """

    def __init__(self, session: boto3.Session) -> None:
        """Initialize the collector.

        Args:
            session: An authenticated :class:`boto3.Session`.
        """
        self.session = session
        self.client = session.client("iam")
        self.account_id = verify_session(session)["account"]
        self.snapshot: dict[str, Any] = {
            "account_id": self.account_id,
            "collected_at": None,
            "users": [],
            "roles": [],
            "groups": [],
            "instance_profiles": [],
            "policies": {},
        }

    def collect_all(self) -> dict[str, Any]:
        """Run every collector and return the assembled snapshot.

        Returns:
            The complete IAM snapshot as a JSON-serializable dict.
        """
        from datetime import datetime, timezone

        self.snapshot["collected_at"] = datetime.now(timezone.utc).isoformat()
        self.snapshot["users"] = self.collect_users()
        self.snapshot["groups"] = self.collect_groups()
        self.snapshot["roles"] = self.collect_roles()
        self.snapshot["instance_profiles"] = self.collect_instance_profiles()
        logger.info(
            "Collected %d users, %d groups, %d roles, %d instance profiles",
            len(self.snapshot["users"]),
            len(self.snapshot["groups"]),
            len(self.snapshot["roles"]),
            len(self.snapshot["instance_profiles"]),
        )
        return self.snapshot

    def collect_users(self) -> list[dict[str, Any]]:
        """Collect all IAM users with group memberships and policies.

        Returns:
            A list of user records including ``groups``,
            ``attached_policy_arns``, and ``inline_policies``.
        """
        users: list[dict[str, Any]] = []
        for page in self.client.get_paginator("list_users").paginate():
            for user in page["Users"]:
                name = user["UserName"]
                record: dict[str, Any] = {
                    "type": "user",
                    "name": name,
                    "arn": user["Arn"],
                    "path": user.get("Path", "/"),
                    "created": user["CreateDate"].isoformat(),
                    "groups": self._list_user_groups(name),
                    "attached_policy_arns": self._list_attached_policy_arns(self._user_policies(name)),
                    "inline_policies": self._get_inline_policies(self._user_policies(name)),
                }
                users.append(record)
                logger.debug("Collected user %s", name)
        return users

    def collect_roles(self) -> list[dict[str, Any]]:
        """Collect all IAM roles with trust policies and policies.

        Trust policies are captured explicitly because they drive
        privilege-escalation edges (e.g., sts:AssumeRole chains).

        Returns:
            A list of role records including ``trust_policy``,
            ``attached_policy_arns``, and ``inline_policies``.
        """
        roles: list[dict[str, Any]] = []
        for page in self.client.get_paginator("list_roles").paginate():
            for role in page["Roles"]:
                name = role["RoleName"]
                roles.append(
                    {
                        "type": "role",
                        "name": name,
                        "arn": role["Arn"],
                        "path": role.get("Path", "/"),
                        "created": role["CreateDate"].isoformat(),
                        "trust_policy": role.get("AssumeRolePolicyDocument", {}),
                        "attached_policy_arns": self._list_attached_policy_arns(self._role_policies(name)),
                        "inline_policies": self._get_inline_policies(self._role_policies(name)),
                    }
                )
                logger.debug("Collected role %s", name)
        return roles

    def collect_groups(self) -> list[dict[str, Any]]:
        """Collect all IAM groups with their attached/inline policies.

        Returns:
            A list of group records. Group membership itself lives on
            each user record under ``groups``.
        """
        groups: list[dict[str, Any]] = []
        for page in self.client.get_paginator("list_groups").paginate():
            for group in page["Groups"]:
                name = group["GroupName"]
                groups.append(
                    {
                        "type": "group",
                        "name": name,
                        "arn": group["Arn"],
                        "path": group.get("Path", "/"),
                        "created": group["CreateDate"].isoformat(),
                        "attached_policy_arns": self._list_attached_policy_arns(self._group_policies(name)),
                        "inline_policies": self._get_inline_policies(self._group_policies(name)),
                    }
                )
                logger.debug("Collected group %s", name)
        return groups

    def collect_instance_profiles(self) -> list[dict[str, Any]]:
        """Collect instance profiles and the roles they embed.

        This mapping is what allows the graph builder to draw the
        ``EC2 -> Role`` bridge edge from an EC2 instance's
        ``iam_instance_profile`` ARN to the role it grants at runtime.

        Returns:
            A list of ``{"arn", "name", "role_arns": [...]}`` records.
        """
        profiles: list[dict[str, Any]] = []
        for page in self.client.get_paginator("list_instance_profiles").paginate():
            for profile in page["InstanceProfiles"]:
                profiles.append(
                    {
                        "arn": profile["Arn"],
                        "name": profile["InstanceProfileName"],
                        "path": profile.get("Path", "/"),
                        "created": profile["CreateDate"].isoformat(),
                        "role_arns": [role["Arn"] for role in profile.get("Roles", [])],
                    }
                )
                logger.debug("Collected instance profile %s", profile["Arn"])
        return profiles

    # ------------------------------------------------------------------
    # Policy document resolution
    # ------------------------------------------------------------------

    def resolve_policy_documents(self) -> dict[str, Any]:
        """Resolve every referenced policy ARN to its full document.

        Managed policy versions are fetched via paginated
        ``list_policy_versions`` and the non-default version documents
        are retrieved with ``get_policy_version``. Results populate
        ``self.snapshot['policies']`` keyed by ARN.

        Returns:
            Mapping of policy ARN -> metadata plus parsed policy document.
        """
        all_arns: set[str] = set()
        for entity in (*self.snapshot["users"], *self.snapshot["groups"], *self.snapshot["roles"]):
            all_arns.update(entity["attached_policy_arns"])

        for arn in sorted(all_arns):
            try:
                policy_meta = self.client.get_policy(PolicyArn=arn)["Policy"]
                default_version = policy_meta["DefaultVersionId"]
                version = self.client.get_policy_version(
                    PolicyArn=arn,
                    VersionId=default_version,
                )["PolicyVersion"]

                self.snapshot["policies"][arn] = {
                    "name": policy_meta["PolicyName"],
                    "is_aws_managed": arn.startswith(AWS_MANAGED_PREFIX),
                    "version": default_version,
                    "attachment_count": policy_meta["AttachmentCount"],
                    "document": version["Document"],
                }
                logger.debug("Resolved policy %s", arn)
            except ClientError as exc:
                # A single unreadable policy must not abort the scan;
                # record the failure so analysis can flag it as unknown.
                logger.warning("Could not resolve policy %s: %s", arn, exc)
                self.snapshot["policies"][arn] = {"error": str(exc)}
        return self.snapshot["policies"]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _user_policies(self, user_name: str) -> Any:
        """Return the IAM policies sub-client interface for a user."""
        return _UserPolicyOps(self.client, user_name)

    def _role_policies(self, role_name: str) -> Any:
        """Return the IAM policies sub-client interface for a role."""
        return _RolePolicyOps(self.client, role_name)

    def _group_policies(self, group_name: str) -> Any:
        """Return the IAM policies sub-client interface for a group."""
        return _GroupPolicyOps(self.client, group_name)

    def _list_user_groups(self, user_name: str) -> list[dict[str, str]]:
        """List group names and ARNs a user belongs to.

        Args:
            user_name: The IAM user to inspect.

        Returns:
            List of ``{"group_name": ..., "group_arn": ...}`` dicts.
        """
        try:
            return [
                {"group_name": g["GroupName"], "group_arn": g["Arn"]}
                for page in self.client.get_paginator("list_groups_for_user").paginate(UserName=user_name)
                for g in page["Groups"]
            ]
        except ClientError as exc:
            logger.warning("Could not list groups for user %s: %s", user_name, exc)
            return []

    @staticmethod
    def _list_attached_policy_arns(ops: Any) -> list[str]:
        """Extract managed policy ARNs from a paginated listing call.

        Args:
            ops: Policy operations adapter exposing
                ``list_attached()`` returning paginator pages.

        Returns:
            Sorted list of attached policy ARNs.
        """
        try:
            return sorted(
                p["PolicyArn"] for page in ops.list_attached() for p in page["AttachedPolicies"]
            )
        except ClientError as exc:
            logger.warning("Could not list attached policies: %s", exc)
            return []

    @staticmethod
    def _get_inline_policies(ops: Any) -> dict[str, dict[str, Any]]:
        """Fetch every inline policy document on an entity.

        Args:
            ops: Policy operations adapter exposing ``list_inline()``
                and ``get_inline(name)``.

        Returns:
            Mapping of inline policy name -> parsed policy document.
        """
        inline: dict[str, dict[str, Any]] = {}
        try:
            names = [p["PolicyName"] for page in ops.list_inline() for p in page["PolicyNames"]]
            for name in names:
                response = ops.get_inline(name)
                doc = response["PolicyDocument"]
                inline[name] = _normalize_document(doc)
        except ClientError as exc:
            logger.warning("Could not fetch inline policies: %s", exc)
        return inline


class _UserPolicyOps:
    """Adapter exposing uniform policy calls for IAM users."""

    def __init__(self, client: Any, user_name: str) -> None:
        self._client = client
        self._name = user_name

    def list_attached(self) -> Any:
        return self._client.get_paginator("list_attached_user_policies").paginate(UserName=self._name)

    def list_inline(self) -> Any:
        return self._client.get_paginator("list_user_policies").paginate(UserName=self._name)

    def get_inline(self, policy_name: str) -> dict[str, Any]:
        return self._client.get_user_policy(UserName=self._name, PolicyName=policy_name)


class _RolePolicyOps:
    """Adapter exposing uniform policy calls for IAM roles."""

    def __init__(self, client: Any, role_name: str) -> None:
        self._client = client
        self._name = role_name

    def list_attached(self) -> Any:
        return self._client.get_paginator("list_attached_role_policies").paginate(RoleName=self._name)

    def list_inline(self) -> Any:
        return self._client.get_paginator("list_role_policies").paginate(RoleName=self._name)

    def get_inline(self, policy_name: str) -> dict[str, Any]:
        return self._client.get_role_policy(RoleName=self._name, PolicyName=policy_name)


class _GroupPolicyOps:
    """Adapter exposing uniform policy calls for IAM groups."""

    def __init__(self, client: Any, group_name: str) -> None:
        self._client = client
        self._name = group_name

    def list_attached(self) -> Any:
        return self._client.get_paginator("list_attached_group_policies").paginate(GroupName=self._name)

    def list_inline(self) -> Any:
        return self._client.get_paginator("list_group_policies").paginate(GroupName=self._name)

    def get_inline(self, policy_name: str) -> dict[str, Any]:
        return self._client.get_group_policy(GroupName=self._name, PolicyName=policy_name)


def _normalize_document(document: Any) -> dict[str, Any]:
    """Normalize a policy document to a plain JSON-safe dict.

    boto3 returns policy documents URL-encoded in some code paths;
    this helper guarantees we always store decoded dicts.

    Args:
        document: Raw policy document (dict or URL-encoded string).

    Returns:
        Parsed, JSON-serializable policy document.
    """
    if isinstance(document, str):
        import urllib.parse

        return json.loads(urllib.parse.unquote_plus(document))
    return document


def run(profile_name: str | None = DEFAULT_PROFILE, region_name: str | None = DEFAULT_REGION) -> dict[str, Any]:
    """Execute a full IAM collection and persist it to disk.

    Args:
        profile_name: AWS CLI profile to authenticate with.
        region_name: Optional region override.

    Returns:
        The saved IAM snapshot.
    """
    session = build_session(profile_name=profile_name, region_name=region_name)
    collector = IAMCollector(session)
    collector.collect_all()
    collector.resolve_policy_documents()

    RAW_IAM_PATH.parent.mkdir(parents=True, exist_ok=True)
    RAW_IAM_PATH.write_text(json.dumps(collector.snapshot, indent=2, default=str))
    logger.info("Snapshot written to %s", RAW_IAM_PATH)
    return collector.snapshot
