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

import json
import logging
from collections import Counter
from typing import Any

import networkx as nx

from cloud_path_mapper.config import GRAPH_PATH, RAW_EC2_PATH, RAW_IAM_PATH, RAW_S3_PATH

logger = logging.getLogger(__name__)

# Actions that imply read access to any S3 object when allowed on a
# wildcard resource. "*" is included because admin-style s3:*/* grants
# are the most common real-world escalation primitive.
S3_READ_ACTIONS = {"s3:GetObject", "s3:*", "*"}

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


def _iter_statements(document: dict) -> list[dict]:
    """Extract Allow statements from a policy document.

    Args:
        document: Parsed IAM policy document.

    Returns:
        All statements whose Effect is ``Allow``.
    """
    return [
        stmt for stmt in _as_list(document.get("Statement")) if isinstance(stmt, dict) and stmt.get("Effect") == "Allow"
    ]


def _action_matches(actions: Any, wanted: set[str]) -> bool:
    """Check whether a statement's Action list intersects `wanted`.

    Args:
        actions: Statement Action field (scalar or list).
        wanted: Set of action strings to match (may include ``*``).

    Returns:
        True if any listed action matches.
    """
    return any(action in wanted for action in _as_list(actions))


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
    """

    def __init__(self, iam_snapshot: dict, s3_snapshot: dict, ec2_snapshot: dict) -> None:
        """Initialize the builder with loaded snapshots.

        Args:
            iam_snapshot: Snapshot from the IAM collector.
            s3_snapshot: Snapshot from the S3 collector.
            ec2_snapshot: Snapshot from the EC2 collector.
        """
        self.graph = nx.DiGraph()
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
        """Draw ``CanAssumeRole`` edges from role trust policies.

        For each role, parse ``assume_role_policy_document`` Allow
        statements and connect every principal ARN that matches a user
        or role already in the graph: edge direction is principal ->
        assumable role. Wildcard principals (``"*"``) are not expanded
        into N edges; instead the target role carries the boolean node
        attribute ``trust_wildcard`` for the rule engine to flag, since
        expanding it would add no routing information to path-finding.
        """
        known_principals = {
            n for n, attrs in self.graph.nodes(data=True)
            if attrs.get("node_type") in ("user", "role")
        }

        for role in self.iam.get("roles", []):
            for stmt in _iter_statements(role.get("trust_policy") or {}):
                principals = _principal_aws(stmt)
                for principal in principals:
                    if principal == "*":
                        continue
                    if principal in known_principals:
                        self.graph.add_edge(
                            principal,
                            role["arn"],
                            relation="CanAssumeRole",
                            source_statement_effect="Allow",
                        )
                        logger.debug("Trust edge: %s -> %s", principal, role["name"])

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
        policy_docs = self.iam.get("policies", {})

        def documents_for_identity(identity: dict, group_map: dict[str, list[dict]]) -> list[dict]:
            """Collect all policy documents applying to one identity.

            Args:
                identity: A user or role record from the IAM snapshot.
                group_map: Group name -> list of group records (users).

            Returns:
                List of parsed policy documents to evaluate.
            """
            docs: list[dict] = []

            def harvest(entity: dict) -> None:
                for arn in entity.get("attached_policy_arns", []):
                    meta = policy_docs.get(arn, {})
                    if "document" in meta:
                        docs.append(meta["document"])
                docs.extend(p for p in entity.get("inline_policies", {}).values() if isinstance(p, dict))

            harvest(identity)

            if identity.get("type") == "user":
                for membership in identity.get("groups", []):
                    for group in group_map.get(membership["group_name"], []):
                        harvest(group)
            return docs

        group_index: dict[str, list[dict]] = {}
        for group in self.iam.get("groups", []):
            group_index.setdefault(group["name"], []).append(group)

        edge_count_before = self.graph.number_of_edges()
        for identity in (*self.iam.get("users", []), *self.iam.get("roles", [])):
            source_arn = identity["arn"]
            if not self.graph.has_node(source_arn):
                continue
            for document in documents_for_identity(identity, group_index):
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
    graph = AttackGraphBuilder(iam, s3, ec2).build()

    stats = graph_statistics(graph)
    logger.info(
        "Nodes: %s | Edges: %s",
        dict(stats["nodes_by_type"]),
        dict(stats["edges_by_relation"]),
    )
    export_graph(graph)
    return graph
