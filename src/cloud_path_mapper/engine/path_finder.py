"""Attack path discovery over the constructed misconfiguration graph.

Loads the node-link graph exported by the analysis layer
(``data/graph.json``) and enumerates simple paths from attacker-reachable
entry points to high-value targets.

MVP definitions:
    Entry points: any IAM user or EC2 instance node (things an attacker
        commonly reaches first: leaked keys, SSRF on a public instance).
    High-value targets: any S3 bucket node, or any role whose name
        contains "admin" (case-insensitive).

Path enumeration uses :func:`networkx.all_simple_paths` with a hop
cutoff (default 5) to bound runtime in dense accounts, and caps total
reported paths as a further safety valve. Paths are also persisted to
``data/attack_paths.json`` so Week 5+ (SQLite history, diffing between
scans) can consume them without recomputation.
"""

from __future__ import annotations

import json
import logging
from itertools import product
from typing import Any

import networkx as nx

from cloud_path_mapper.config import ATTACK_PATHS_PATH, GRAPH_PATH

logger = logging.getLogger(__name__)

# Maximum hops per path; prevents pathological runtimes on dense graphs.
PATH_CUTOFF = 5

# Safety valve on total enumerated paths.
MAX_PATHS = 500

ENTRY_NODE_TYPES = {"user", "ec2_instance"}
ADMIN_NAME_MARKER = "admin"


def load_graph(path: Any = GRAPH_PATH) -> nx.DiGraph:
    """Reload the attack graph from its node-link JSON export.

    Args:
        path: Path to ``graph.json``.

    Returns:
        The reconstructed :class:`networkx.DiGraph`.

    Raises:
        FileNotFoundError: If no graph has been exported yet.
    """
    try:
        payload = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"{path} not found. Run `cloud-path-mapper analyze` first.") from exc
    return nx.node_link_graph(payload)


def find_entry_points(graph: nx.DiGraph) -> list[str]:
    """Select attacker entry-point nodes.

    Args:
        graph: The attack graph.

    Returns:
        Sorted list of ARNs whose ``node_type`` is a user or EC2
        instance.
    """
    return sorted(
        node for node, attrs in graph.nodes(data=True)
        if attrs.get("node_type") in ENTRY_NODE_TYPES
    )


def find_high_value_targets(graph: nx.DiGraph) -> list[str]:
    """Select high-value target nodes.

    Args:
        graph: The attack graph.

    Returns:
        Sorted list of ARNs for S3 bucket nodes plus roles whose name
        contains "admin" (case-insensitive).
    """
    targets = [
        node for node, attrs in graph.nodes(data=True)
        if attrs.get("node_type") == "s3_bucket"
    ]
    targets.extend(
        node for node, attrs in graph.nodes(data=True)
        if attrs.get("node_type") == "role"
        and ADMIN_NAME_MARKER in str(attrs.get("name", "")).lower()
    )
    return sorted(set(targets))


def find_attack_paths(
    graph: nx.DiGraph,
    cutoff: int = PATH_CUTOFF,
    max_paths: int = MAX_PATHS,
) -> list[dict[str, Any]]:
    """Enumerate simple paths from every entry point to every target.

    Args:
        graph: The attack graph.
        cutoff: Maximum number of edges per path.
        max_paths: Hard cap on returned paths; when exceeded the scan
            logs a warning and returns early (paths are still valid,
            just not exhaustive).

    Returns:
        List of path records::

            {
                "entry": <arn>,
                "target": <arn>,
                "hops": <int edge count>,
                "nodes": [<arn>, ...],
                "relations": [<relation label>, ...],
                "names": [<display name>, ...],
            }
    """
    entries = find_entry_points(graph)
    targets = find_high_value_targets(graph)

    if not entries:
        logger.warning("No entry points found (no users or EC2 instances in graph).")
        return []
    if not targets:
        logger.warning("No high-value targets found (no buckets or '*admin*' roles in graph).")
        return []

    paths: list[dict[str, Any]] = []
    truncated = False

    # all_simple_paths takes a single source/target; iterate pairs but
    # bail out of each generator as soon as the global cap is hit.
    for entry, target in product(entries, targets):
        if entry == target:
            continue
        try:
            for raw_path in nx.all_simple_paths(graph, source=entry, target=target, cutoff=cutoff):
                relations = [
                    graph[raw_path[i]][raw_path[i + 1]].get("relation", "?")
                    for i in range(len(raw_path) - 1)
                ]
                paths.append(
                    {
                        "entry": entry,
                        "target": target,
                        "hops": len(raw_path) - 1,
                        "nodes": list(raw_path),
                        "relations": relations,
                        "names": [graph.nodes[n].get("name", n) for n in raw_path],
                    }
                )
                if len(paths) >= max_paths:
                    truncated = True
                    break
        except nx.NodeNotFound:
            continue
        if truncated:
            break

    paths.sort(key=lambda p: p["hops"])
    if truncated:
        logger.warning("Path enumeration hit the %d-path cap; output is not exhaustive.", max_paths)
    logger.info("Discovered %d attack path(s) (cutoff=%d)", len(paths), cutoff)
    return paths


def format_path(path: dict[str, Any]) -> str:
    """Render one path record as a readable arrow chain.

    Args:
        path: A record from :func:`find_attack_paths`.

    Returns:
        Example: ``alice --CanAssumeRole--> ec2-ssm-role --CanRead--> customer-pii``
    """
    parts = [path["names"][0]]
    for i, relation in enumerate(path["relations"]):
        parts.append(f"--{relation}-->")
        parts.append(path["names"][i + 1])
    return " ".join(parts)


def save_paths(paths: list[dict[str, Any]], output_path: Any = ATTACK_PATHS_PATH) -> Any:
    """Persist discovered paths for history/diffing.

    Args:
        paths: Records from :func:`find_attack_paths`.
        output_path: Destination JSON path.

    Returns:
        The path written to.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"path_count": len(paths), "cutoff": PATH_CUTOFF, "paths": paths}, indent=2))
    logger.info("Paths written to %s", output_path)
    return output_path


def run(graph_path: Any = GRAPH_PATH, save: bool = True) -> list[dict[str, Any]]:
    """Load the graph, discover attack paths, and optionally persist them.

    Args:
        graph_path: Path to the exported ``graph.json``.
        save: Whether to write ``attack_paths.json``.

    Returns:
        Discovered path records, shortest first.
    """
    graph = load_graph(graph_path)
    paths = find_attack_paths(graph)
    if save:
        save_paths(paths)
    return paths
