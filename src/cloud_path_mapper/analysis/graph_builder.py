"""Attack graph construction from raw collector snapshots.

Loads the JSON snapshots produced by the collectors (``raw_iam.json``,
``raw_s3.json``, ``raw_ec2.json``) and assembles a NetworkX ``DiGraph``
modeling how identities, compute, and data assets relate to each other
and where an attacker could pivot between them.

Node model
    - IAM users / roles: keyed by their full ARN.
    - EC2 instances: keyed by their full ARN (region-qualified).
    - S3 buckets: keyed by ``arn:aws:s3:::<bucket>``.

Edge model (directed, in the direction of privilege flow)
    - ``(Principal -> Role)`` with ``relation="CanAssumeRole"`` derived
      from each role's trust policy.
    - ``(EC2 instance -> Role)`` with ``relation="HasInstanceProfile"``
      resolved through the IAM snapshot's instance-profile mapping.
    - ``(Identity -> Bucket)`` with ``relation="CanRead"`` derived from
      attached managed policies, inline policies, and (for users) the
      policies of groups they belong to.

The resulting graph is exported with ``networkx.node_link_data`` so the
Week 4 attack-path engine and pyvis renderer can consume it without
recomputing.
"""

from __future__ import annotations

import fnmatch
import json
import logging
from collections import Counter
from typing import Any

import networkx as nx

from cloud_path_mapper.config import (
    GRAPH_PATH,
    INFORMATIONAL_FINDINGS_PATH,
    RAW_EC2_PATH,
    RAW_IAM_PATH,
    RAW_S3_PATH,
)

logger = logging.getLogger(__name__)

# Actions that imply read access to any S3 object when allowed on a
# wildcard resource. "*" is included because admin-style s3:*/* grants
# are the most common real-world escalation primitive.
S3_READ_ACTIONS = {"s3:GetObject", "s3:*", "*"}

# Actions that grant the ability to call sts:AssumeRole. Case is
# normalized to lowercase at match time (IAM actions are case-insensitive).
ASSUME_ROLE_ACTIONS = {"sts:assumerole", "sts:*", "*"}

# Attached managed policy name that implies full admin (case-insensitive).
ADMIN_POLICY_NAME = "administratoraccess"

# IAM write actions enabling persistence or further escalation even
# without full admin. Stored lowercase; matched case-insensitively.
IAM_WRITE_ACTIONS = {
    "iam:createuser",
    "iam:createpolicy",
    "iam:attachuserpolicy",
    "iam:attachrolepolicy",
    "iam:putuserpolicy",
    "iam:putrolepolicy",
    "iam:updateassumerolepolicy",
    "iam:createaccesskey",
    "iam:createloginprofile",
}

# Service-level wildcard actions on Resource "*" for sensitive data
# services. Stored lowercase.
SENSITIVE_SERVICE_WILDCARDS = {"s3:*", "secretsmanager:*", "kms:*", "dynamodb:*", "rds:*"}

# Resource wildcards meaning "every bucket in every account".
S3_GLOBAL_RESOURCES = {"*", "arn:aws:s3:::*"}


def load_snapshots(
    iam_path: Any = RAW_IAM_PATH,
    s3_path: Any = RAW_S3_PATH,
    ec2_path: Any = RAW_EC2_PATH,
) -> tuple[dict, dict, dict]:
    """Load the three raw collector snapshots from disk.

    Args:
        iam_path: Path to ``raw_iam.json``.
        s3_path: Path to ``raw_s3.json``.
        ec2_path: Path to ``raw_ec2.json``.

    Returns:
        Tuple of ``(iam, s3, ec2)`` parsed snapshot dicts.

    Raises:
        FileNotFoundError: If any snapshot is missing, with a message
            pointing at the collector command that produces it.
    """
    snapshots = []
    for path, command in ((iam_path, "collect-iam"), (s3_path, "collect-s3"), (ec2_path, "collect-ec2")):
        try:
            snapshots.append(json.loads(path.read_text()))
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"{path} not found. Run `cloud-path-mapper {command}` first.") from exc
    return snapshots[0], snapshots[1], snapshots[2]


# ----------------------------------------------------------------------
# Policy document parsing helpers (raw AWS structures, per MVP decision)
# ----------------------------------------------------------------------

def _as_list(value: Any) -> list:
    """Normalize an AWS policy field that may be scalar or list.

    Args:
        value: A policy field such as ``Statement``, ``Action``, or
            ``Resource`` which AWS allows as either a single value or a
            list.

    Returns:
        Always a list; scalars become single-element lists.
    """
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _all_statements(document: dict) -> list[dict]:
    """Extract every statement from a policy document, any Effect.

    Args:
        document: Parsed IAM policy document.

    Returns:
        All statement dicts regardless of Effect (Allow/Deny).
    """
    return [stmt for stmt in _as_list(document.get("Statement")) if isinstance(stmt, dict)]


def _iter_statements(document: dict) -> list[dict]:
    """Extract Allow statements from a policy document.

    Args:
        document: Parsed IAM policy document.

    Returns:
        All statements whose Effect is ``Allow``.
    """
    return [stmt for stmt in _all_statements(document) if stmt.get("Effect") == "Allow"]


def _action_matches(actions: Any, wanted: set[str]) -> bool:
    """Check whether a statement's Action list intersects `wanted`.

    Matching is case-insensitive per IAM semantics.

    Args:
        actions: Statement Action field (scalar or list).
        wanted: Set of action strings to match (may include ``*``).

    Returns:
        True if any listed action matches.
    """
    wanted_lower = {w.lower() for w in wanted}
    return any(action.lower() in wanted_lower for action in _as_list(actions))


def _resource_matches_arn(pattern: str, target_arn: str) -> bool:
    """Check whether an IAM resource pattern covers a target ARN.

    Uses glob semantics (``*`` and ``?``), which covers the common IAM
    resource wildcard forms such as exact ARNs, ``role/path/*`` suffix
    wildcards, and full ``*``.

    Args:
        pattern: Resource value from a policy statement.
        target_arn: The concrete role ARN being tested.

    Returns:
        True if the pattern matches the target ARN.
    """
    if not isinstance(pattern, str):
        return False
    return pattern == target_arn or fnmatch.fnmatchcase(target_arn, pattern)


def _role_targets(stmt: dict, role_arns: set[str]) -> set[str]:
    """Extract role ARNs matched by a statement's Resources.

    Args:
        stmt: Policy statement dict.
        role_arns: Candidate role ARNs from the account scan.

    Returns:
        Set of role ARNs whose ARN matches at least one Resource.
    """
    return {
        role_arn
        for role_arn in role_arns
        if any(_resource_matches_arn(res, role_arn) for res in _as_list(stmt.get("Resource")))
    }


def _has_wildcard_resource(stmt: dict) -> bool:
    """Check whether a statement's Resources include a bare wildcard.

    Args:
        stmt: Policy statement dict.

    Returns:
        True if any Resource entry is exactly ``*``.
    """
    return "*" in {res.strip() for res in _as_list(stmt.get("Resource"))}


def _denies_cover(denies: list[dict], actions_lower: set[str]) -> bool:
    """Conservative Deny check for a set of candidate actions.

    A Deny statement suppresses flagging when its Action list includes
    one of the candidate actions or a covering wildcard. Condition and
    NotAction semantics are not evaluated (documented limitation).

    Args:
        denies: Deny statements harvested for the identity.
        actions_lower: Lowercased action strings to test.

    Returns:
        True if any Deny statement covers all/any of the actions.
    """
    for stmt in denies:
        for action in _as_list(stmt.get("Action")):
            lowered = str(action).lower()
            if lowered == "*" or lowered in actions_lower:
                return True
    return False


def _bucket_names_from_resources(resources: Any) -> set[str]:
    """Extract concrete bucket names from statement Resources.

    Args:
        resources: Statement Resource field (scalar or list).

    Returns:
        Set of bucket names referenced by bucket ARNs. Wildcard
        resources are excluded here (callers handle them separately).
    """
    names: set[str] = set()
    for resource in _as_list(resources):
        if resource.startswith("arn:aws:s3:::"):
            name = resource.removeprefix("arn:aws:s3:::").split("/")[0]
            if name and name != "*":
                names.add(name)
    return names


class AttackGraphBuilder:
    """Builds the misconfiguration attack DiGraph from raw snapshots.

    Attributes:
        graph: The NetworkX directed graph under construction.
        iam: Raw IAM snapshot.
        s3: Raw S3 snapshot.
        ec2: Raw EC2 snapshot.
        informational_findings: Half-configured relationships (e.g.,
            ``TrustedButNoGrant``) that are not exploitable edges but
            are surfaced for reviewer attention.
    """

    def __init__(self, iam_snapshot: dict, s3_snapshot: dict, ec2_snapshot: dict) -> None:
        """Initialize the builder with loaded snapshots.

        Args:
            iam_snapshot: Snapshot from the IAM collector.
            s3_snapshot: Snapshot from the S3 collector.
            ec2_snapshot: Snapshot from the EC2 collector.
        """
        self.graph = nx.DiGraph()
        self.informational_findings: list[dict] = []
        self.iam = iam_snapshot
        self.s3 = s3_snapshot
        self.ec2 = ec2_snapshot

    def build(self) -> nx.DiGraph:
        """Run all node and edge generators and return the graph.

        Returns:
            The fully populated :class:`networkx.DiGraph`.
        """
        self._add_identity_nodes()
        self._add_bucket_nodes()
        self._add_ec2_nodes()
        self._add_trust_edges()
        self._add_instance_profile_edges()
        self._add_s3_permission_edges()
        self._tag_high_value_targets()

        logger.info(
            "Graph built: %d nodes, %d edges", self.graph.number_of_nodes(), self.graph.number_of_edges()
        )
        return self.graph

    # ------------------------------------------------------------------
    # Nodes
    # ------------------------------------------------------------------

    def _add_identity_nodes(self) -> None:
        """Add IAM users and roles as nodes keyed by ARN."""
        for user in self.iam.get("users", []):
            self.graph.add_node(
                user["arn"],
                node_type="user",
                name=user["name"],
                arn=user["arn"],
                region=None,
            )
        for role in self.iam.get("roles", []):
            trust_doc = role.get("trust_policy") or {}
            wildcard_trust = any(
                stmt.get("Principal") == "*" or _as_list(_principal_aws(stmt)) == ["*"]
                for stmt in _iter_statements(trust_doc)
            )
            self.graph.add_node(
                role["arn"],
                node_type="role",
                name=role["name"],
                arn=role["arn"],
                region=None,
                trust_wildcard=wildcard_trust,
                instance_profile=any(
                    role["arn"] in p.get("role_arns", []) for p in self.iam.get("instance_profiles", [])
                ),
            )

    def _add_bucket_nodes(self) -> None:
        """Add S3 buckets as nodes keyed by their canonical ARN."""
        for bucket in self.s3.get("buckets", []):
            publicly_exposed = bucket.get("is_publicly_exposed", False)
            pab = bucket.get("public_access_block", {})
            pab_status = pab.get("status")
            self.graph.add_node(
                bucket["arn"],
                node_type="s3_bucket",
                name=bucket["name"],
                arn=bucket["arn"],
                region=bucket.get("region"),
                publicly_exposed=publicly_exposed,
                pab_configured=pab_status == "ok",
                pab_scannable=pab_status != "error",
            )

    def _add_ec2_nodes(self) -> None:
        """Add EC2 instances as nodes keyed by their regional ARN."""
        for instance in self.ec2.get("instances", []):
            self.graph.add_node(
                instance["arn"],
                node_type="ec2_instance",
                name=instance["instance_id"],
                arn=instance["arn"],
                region=instance["region"],
                public_ip=instance.get("public_ip"),
                has_public_ip=instance.get("has_public_ip", False),
            )

    # ------------------------------------------------------------------
    # Edges
    # ------------------------------------------------------------------

    def _add_trust_edges(self) -> None:
        """Draw ``CanAssumeRole`` edges using unified two-sided resolution.

        Assuming a role in AWS requires BOTH a trust-side grant (the
        role's policy permits the identity) AND a permission-side grant
        (the identity's policies permit ``sts:AssumeRole`` on the role).
        This method evaluates every candidate pair against both sides:

        **Trust-side** (from :meth:`_summarize_role_trusts`):
            - ``named`` — the trust policy names the identity's ARN
              specifically,
            - ``root`` — the trust policy trusts the same-account root
              (``arn:aws:iam::<account>:root``) without a blocking
              Condition,
            - ``none`` — otherwise (no exploitable relationship).

        **Permission-side** (from :meth:`_assume_role_grants`):
            Allow statements on ``sts:AssumeRole`` (including wildcards)
            across attached managed, inline, and inherited group
            policies, with Resource matched by glob against role ARNs
            and explicit Denys winning per AWS evaluation order.

        An edge is created only when both sides check out. A trust-side
        ``named`` result with NO matching permission grant is recorded
        as an informational finding of type ``TrustedButNoGrant``
        (half-configured relationship) instead of an edge, so reviewers
        see it without it counting as an exploitable attack step.
        """
        self._add_assume_role_edges()

    def _add_instance_profile_edges(self) -> None:
        """Draw ``HasInstanceProfile`` edges from EC2 instances to roles.

        Resolves each instance's ``iam_instance_profile`` ARN against
        the ``instance_profiles`` mapping collected by the IAM
        collector, connecting the instance to every role embedded in
        that profile.
        """
        profile_to_roles: dict[str, list[str]] = {}
        for profile in self.iam.get("instance_profiles", []):
            profile_to_roles[profile["arn"]] = profile.get("role_arns", [])

        for instance in self.ec2.get("instances", []):
            profile = instance.get("iam_instance_profile")
            if not profile:
                continue
            profile_arn = profile.get("arn")
            role_arns = profile_to_roles.get(profile_arn)
            if role_arns is None:
                logger.warning(
                    "Instance profile %s (on %s) not present in IAM snapshot; "
                    "re-run collect-iam to refresh.",
                    profile_arn,
                    instance["arn"],
                )
                continue
            for role_arn in role_arns:
                if self.graph.has_node(role_arn):
                    self.graph.add_edge(
                        instance["arn"],
                        role_arn,
                        relation="HasInstanceProfile",
                        instance_profile_arn=profile_arn,
                    )
                else:
                    logger.warning("Profile %s references unknown role %s", profile_arn, role_arn)

    def _add_assume_role_edges(self) -> None:
        """Create all ``CanAssumeRole`` edges via one two-sided check.

        Candidate pairs are collected from the trust side (named
        principals, plus permission-side candidates for root-trusted
        roles), then each candidate is confirmed against the
        permission-side grants before an edge is emitted. Pairs that
        pass the trust side but lack a permission grant are recorded in
        :attr:`informational_findings` as ``TrustedButNoGrant``.
        """
        trusts = self._summarize_role_trusts()
        grants = self._assume_role_grants()

        # Trust-side candidates. Named principals take precedence over
        # the coarser root-trust signal when both apply to a pair.
        candidates: dict[tuple[str, str], str] = {}
        for role_arn, info in trusts.items():
            for principal in info["explicit"]:
                if self.graph.has_node(principal):
                    candidates.setdefault((principal, role_arn), "named-principal")

        for identity_arn, (allowed, _denied) in grants.items():
            if not self.graph.has_node(identity_arn):
                continue
            for role_arn in allowed:
                info = trusts.get(role_arn)
                if info and info["root_trusted"]:
                    candidates.setdefault((identity_arn, role_arn), "root-trust")

        # Two-sided confirmation.
        for (identity_arn, role_arn), basis in sorted(candidates.items()):
            allowed_targets = grants.get(identity_arn, (set(), set()))[0]
            if role_arn not in allowed_targets:
                self.informational_findings.append(
                    {
                        "type": "TrustedButNoGrant",
                        "identity": identity_arn,
                        "role": role_arn,
                        "detail": (
                            "Trust policy names this identity, but no sts:AssumeRole "
                            "permission grant on this role was found in its policies."
                        ),
                    }
                )
                logger.info(
                    "TrustedButNoGrant: %s is named in %s's trust policy but holds no "
                    "sts:AssumeRole grant; recorded as informational only.",
                    identity_arn,
                    role_arn,
                )
                continue

            self.graph.add_edge(
                identity_arn,
                role_arn,
                relation="CanAssumeRole",
                basis=basis,
            )
            logger.debug("Assume-role edge: %s -> %s (%s)", identity_arn, role_arn, basis)

            if basis == "root-trust" and trusts[role_arn]["condition_present"]:
                logger.warning(
                    "Edge %s -> %s created from an unconditional statement, but the "
                    "trust policy also contains Condition-blocked statement(s); "
                    "conditions were NOT evaluated.",
                    identity_arn,
                    role_arn,
                )

        if self.informational_findings:
            logger.info(
                "Recorded %d TrustedButNoGrant informational finding(s)",
                len(self.informational_findings),
            )

    def _summarize_role_trusts(self) -> dict[str, dict]:
        """Classify each role's trust policy for resolution.

        Statements carrying a Condition are conservatively treated as
        unresolvable (see module limitation notes): a root-trust
        statement with a Condition neither grants nor is counted as
        blocking — the role simply cannot be resolved via root trust,
        and any matching permission-side grant logs a warning.

        Returns:
            Mapping of role ARN to ``{"explicit": set[str], "root_trusted":
            bool, "condition_present": bool}``.
        """
        account_id = self.iam.get("account_id")
        root_principal = f"arn:aws:iam::{account_id}:root"
        bare_account = account_id or ""

        summary: dict[str, dict] = {}
        for role in self.iam.get("roles", []):
            explicit: set[str] = set()
            root_trusted = False
            condition_present = False

            for stmt in _iter_statements(role.get("trust_policy") or {}):
                if stmt.get("Condition"):
                    # Cannot evaluate condition semantics (sts:ExternalId,
                    # aws:SourceIdentity, ...); treat as resolvable only
                    # via other unconditional statements.
                    condition_present = True
                    continue
                for principal in _principal_aws(stmt):
                    if principal == "*":
                        continue
                    if principal == root_principal or principal == bare_account:
                        root_trusted = True
                    else:
                        explicit.add(principal)

            summary[role["arn"]] = {
                "explicit": explicit,
                "root_trusted": root_trusted,
                "condition_present": condition_present,
            }
        return summary

    def _harvest_effective_statements(self) -> dict[str, tuple[list[dict], list[dict]]]:
        """Harvest Allow/Deny statements reachable by each identity.

        Single shared pass over attached managed, inline, and
        group-inherited policies; consumers (assume-role grant
        resolution, high-value target tagging) evaluate their own
        action/resource patterns against these statements.

        Returns:
            Mapping of identity ARN -> ``(allow_stmts, deny_stmts)``.
        """
        group_index = self._build_group_index()
        harvested: dict[str, tuple[list[dict], list[dict]]] = {}
        for identity in (*self.iam.get("users", []), *self.iam.get("roles", [])):
            allows: list[dict] = []
            denies: list[dict] = []
            for document in self._documents_for_identity(identity, group_index):
                for stmt in _all_statements(document):
                    if stmt.get("Effect") == "Allow":
                        allows.append(stmt)
                    elif stmt.get("Effect") == "Deny":
                        denies.append(stmt)
            harvested[identity["arn"]] = (allows, denies)
        return harvested

    def _assume_role_grants(self) -> dict[str, tuple[set[str], set[str]]]:
        """Resolve sts:AssumeRole permissions per identity.

        Parses every policy document reachable by each identity
        (attached managed, inline, and inherited group policies) for
        statements whose Action includes ``sts:AssumeRole`` (or a
        wildcard covering it) and whose Resource matches a scanned
        role's ARN. Resource patterns are matched with glob semantics
        (``*``/``?``), so ``arn:aws:iam::<acct>:role/pivot/*`` style
        grants resolve correctly.

        Explicit Deny statements on the same action/resource pair
        suppress the grant rather than being silently ignored.

        Note (known limitation): SCPs, permission boundaries, and
        session policies are out of scope for snapshot-based analysis.

        Returns:
            Mapping of identity ARN -> ``(allowed_targets, denied_targets)``
            where both are sets of role ARNs.
        """
        role_arns = {r["arn"] for r in self.iam.get("roles", [])}

        grants: dict[str, tuple[set[str], set[str]]] = {}
        for identity_arn, (allows, denies) in self._harvest_effective_statements().items():
            allowed: set[str] = set()
            denied: set[str] = set()

            for stmt in allows:
                if not _action_matches(stmt.get("Action"), ASSUME_ROLE_ACTIONS):
                    continue
                allowed.update(_role_targets(stmt, role_arns))
            for stmt in denies:
                if not _action_matches(stmt.get("Action"), ASSUME_ROLE_ACTIONS):
                    continue
                denied.update(_role_targets(stmt, role_arns))

            suppressed = allowed & denied
            if suppressed:
                logger.warning(
                    "%s holds both Allow and Deny for sts:AssumeRole on %d role(s); "
                    "Deny wins per AWS evaluation order.",
                    identity_arn,
                    len(suppressed),
                )
            grants[identity_arn] = (allowed - denied, denied)
        return grants

    def _build_group_index(self) -> dict[str, list[dict]]:
        """Index group records by name.

        Returns:
            Mapping of group name -> list of group snapshot records.
        """
        index: dict[str, list[dict]] = {}
        for group in self.iam.get("groups", []):
            index.setdefault(group["name"], []).append(group)
        return index

    def _documents_for_identity(
        self,
        identity: dict,
        group_index: dict[str, list[dict]] | None = None,
    ) -> list[dict]:
        """Collect all policy documents applying to one identity.

        Includes directly attached managed policies (resolved
        documents), inline policies embedded in the identity record,
        and — for users — attached + inline policies of their groups.

        Args:
            identity: A user or role record from the IAM snapshot.
            group_index: Optional prebuilt group index (built on demand
                when omitted).

        Returns:
            List of parsed policy documents to evaluate.
        """
        if group_index is None:
            group_index = self._build_group_index()

        docs: list[dict] = []
        policy_docs = self.iam.get("policies", {})

        def harvest(entity: dict) -> None:
            for arn in entity.get("attached_policy_arns", []):
                meta = policy_docs.get(arn, {})
                if "document" in meta:
                    docs.append(meta["document"])
            docs.extend(p for p in entity.get("inline_policies", {}).values() if isinstance(p, dict))

        harvest(identity)

        if identity.get("type") == "user":
            for membership in identity.get("groups", []):
                for group in group_index.get(membership["group_name"], []):
                    harvest(group)
        return docs

    def _add_s3_permission_edges(self) -> None:
        """Draw ``CanRead`` edges from identities to S3 buckets.

        Evaluates every policy document reachable by each user/role:

        - directly attached managed policies (resolved documents),
        - inline policies embedded in the identity record,
        - for users, attached + inline policies of their groups.

        Statements allowing an S3-read action produce edges to all
        buckets (wildcard resource) or only the referenced buckets
        (specific ARN). Duplicate edges collapse naturally because
        NetworkX DiGraphs key edges by endpoint pair.
        """
        bucket_names = {b["name"] for b in self.s3.get("buckets", [])}
        group_index = self._build_group_index()

        edge_count_before = self.graph.number_of_edges()
        for identity in (*self.iam.get("users", []), *self.iam.get("roles", [])):
            source_arn = identity["arn"]
            if not self.graph.has_node(source_arn):
                continue
            for document in self._documents_for_identity(identity, group_index):
                for stmt in _iter_statements(document):
                    if not _action_matches(stmt.get("Action"), S3_READ_ACTIONS):
                        continue
                    resources = stmt.get("Resource")
                    if any(r in S3_GLOBAL_RESOURCES for r in _as_list(resources)):
                        for bucket in self.s3.get("buckets", []):
                            self.graph.add_edge(source_arn, bucket["arn"], relation="CanRead")
                    for bucket_name in _bucket_names_from_resources(resources):
                        if bucket_name in bucket_names:
                            self.graph.add_edge(
                                source_arn,
                                f"arn:aws:s3:::{bucket_name}",
                                relation="CanRead",
                            )
                        else:
                            logger.debug(
                                "%s can read bucket '%s' but it was not found in the account scan",
                                identity["name"],
                                bucket_name,
                            )
        added = self.graph.number_of_edges() - edge_count_before
        logger.info("Added %d CanRead edges", added)

    def _tag_high_value_targets(self) -> None:
        """Flag identities as high-value targets with explicit reasons.

        Policy-content signals (Deny-aware, reusing the shared
        statement harvest):

        1. AdministratorAccess — attached managed policy of that name,
           or any Allow of ``Action: *`` on ``Resource: *``.
        2. IAM-write actions (persistence/escalation primitives) such
           as ``iam:CreateAccessKey`` or ``iam:UpdateAssumeRolePolicy``.
        3. Service-level wildcards (``s3:*`` etc.) on ``Resource: *``
           for sensitive services.

        The legacy name-based heuristic is kept as an additional cheap
        signal (role names containing "admin") but no longer drives
        detection alone. Each flagged node gets a ``target_reason``
        attribute describing WHY, for display in reports.
        """
        harvested = self._harvest_effective_statements()
        policy_meta = self.iam.get("policies", {})
        flagged = 0

        for identity in (*self.iam.get("users", []), *self.iam.get("roles", [])):
            arn = identity["arn"]
            if not self.graph.has_node(arn):
                continue
            allows, denies = harvested.get(arn, ([], []))
            reasons: list[str] = []

            # --- AdministratorAccess ---
            attached_admin = any(
                str(policy_meta.get(policy_arn, {}).get("name", "")).lower() == ADMIN_POLICY_NAME
                for policy_arn in identity.get("attached_policy_arns", [])
            )
            wildcard_admin = any(
                _action_matches(stmt.get("Action"), {"*"}) and _has_wildcard_resource(stmt)
                for stmt in allows
            )
            if (attached_admin or wildcard_admin) and not _denies_cover(denies, {"*"}):
                reasons.append("AdministratorAccess")

            # --- IAM write actions (persistence / escalation primitives) ---
            for stmt in allows:
                for action in _as_list(stmt.get("Action")):
                    lowered = str(action).lower()
                    if lowered in IAM_WRITE_ACTIONS and not _denies_cover(denies, {lowered}):
                        reasons.append(str(action))

            # --- Sensitive service wildcards on Resource "*" ---
            for stmt in allows:
                if not _has_wildcard_resource(stmt):
                    continue
                for action in _as_list(stmt.get("Action")):
                    lowered = str(action).lower()
                    if lowered in SENSITIVE_SERVICE_WILDCARDS and not _denies_cover(denies, {lowered}):
                        reasons.append(f"{action} on *")

            # --- Legacy name-based heuristic (demoted to a hint) ---
            # Kept as a cheap signal per MVP history, but it no longer
            # drives target selection: a role merely named "*admin*"
            # gets an ``admin_name_hint`` attribute instead of
            # ``target_reason``, so path-finding ignores it.
            node_attrs = self.graph.nodes[arn]
            if (
                "target_reason" not in node_attrs
                and "admin" in str(node_attrs.get("name", "")).lower()
            ):
                node_attrs["admin_name_hint"] = True

            # Dedupe, preserving order.
            seen: set[str] = set()
            unique_reasons = [r for r in reasons if not (r in seen or seen.add(r))]
            if unique_reasons:
                node_attrs["target_reason"] = "; ".join(unique_reasons)
                flagged += 1

        logger.info("Tagged %d high-value target(s)", flagged)


def _principal_aws(statement: dict) -> list[str]:
    """Extract AWS principal identifiers from a trust statement.

    Args:
        statement: Trust policy statement dict.

    Returns:
        List of principal strings (ARNs, account roots, or ``*``).
    """
    principal = statement.get("Principal")
    if principal == "*":
        return ["*"]
    if isinstance(principal, dict):
        return [p for p in _as_list(principal.get("AWS"))]
    return []


def graph_statistics(graph: nx.DiGraph) -> dict[str, Counter]:
    """Summarize node types and edge relations.

    Args:
        graph: The built attack graph.

    Returns:
        Dict with ``nodes_by_type`` and ``edges_by_relation`` counters.
    """
    nodes_by_type = Counter(attrs.get("node_type", "unknown") for _, attrs in graph.nodes(data=True))
    edges_by_relation = Counter(data.get("relation", "unknown") for _, _, data in graph.edges(data=True))
    return {"nodes_by_type": nodes_by_type, "edges_by_relation": edges_by_relation}


def export_graph(graph: nx.DiGraph, output_path: Any = GRAPH_PATH) -> Any:
    """Serialize the graph to a node-link JSON file.

    Args:
        graph: The built attack graph.
        output_path: Destination path for ``graph.json``.

    Returns:
        The path written to.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = nx.node_link_data(graph)
    output_path.write_text(json.dumps(payload, indent=2, default=str))
    logger.info("Graph exported to %s", output_path)
    return output_path


def export_informational_findings(
    findings: list[dict],
    output_path: Any = INFORMATIONAL_FINDINGS_PATH,
) -> Any:
    """Persist informational (non-exploitable) findings to disk.

    Args:
        findings: Records from
            :attr:`AttackGraphBuilder.informational_findings`.
        output_path: Destination JSON path.

    Returns:
        The path written to.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"finding_count": len(findings), "findings": findings}
    output_path.write_text(json.dumps(payload, indent=2))
    logger.info("Informational findings written to %s", output_path)
    return output_path


def load_informational_findings(path: Any = INFORMATIONAL_FINDINGS_PATH) -> list[dict]:
    """Load previously exported informational findings, if any.

    Args:
        path: Path to ``informational_findings.json``.

    Returns:
        List of finding records; empty list when the file does not
        exist or cannot be parsed.
    """
    try:
        return json.loads(path.read_text()).get("findings", [])
    except FileNotFoundError:
        return []
    except json.JSONDecodeError as exc:
        logger.warning("Could not parse %s: %s", path, exc)
        return []


def run(iam_path: Any = RAW_IAM_PATH, s3_path: Any = RAW_S3_PATH, ec2_path: Any = RAW_EC2_PATH) -> nx.DiGraph:
    """Load snapshots, build the graph, export it, and log statistics.

    Args:
        iam_path: Override path to ``raw_iam.json``.
        s3_path: Override path to ``raw_s3.json``.
        ec2_path: Override path to ``raw_ec2.json``.

    Returns:
        The built :class:`networkx.DiGraph`.
    """
    iam, s3, ec2 = load_snapshots(iam_path=iam_path, s3_path=s3_path, ec2_path=ec2_path)
    builder = AttackGraphBuilder(iam, s3, ec2)
    graph = builder.build()

    stats = graph_statistics(graph)
    logger.info(
        "Nodes: %s | Edges: %s",
        dict(stats["nodes_by_type"]),
        dict(stats["edges_by_relation"]),
    )
    export_graph(graph)
    export_informational_findings(builder.informational_findings)
    return graph
