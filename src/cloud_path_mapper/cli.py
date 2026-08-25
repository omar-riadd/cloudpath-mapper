"""Command-line entry point for the attack path mapper.

Week 2 scope: ``collect-iam``, ``collect-s3``, ``collect-ec2`` and
``collect-all`` are live. Analysis, attack-path, and reporting commands
land in later weeks.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from botocore.exceptions import BotoCoreError, ClientError

import networkx as nx

from cloud_path_mapper.auth.session import AWSSessionError
from cloud_path_mapper.config import DEFAULT_PROFILE, DEFAULT_REGION
from cloud_path_mapper.analysis import graph_builder
from cloud_path_mapper.collectors import ec2_collector, iam_collector, s3_collector
from cloud_path_mapper.engine import path_finder
from cloud_path_mapper.output import visualizer

logger = logging.getLogger(__name__)

# Maps CLI command names to collector run functions (used by collect-all
# and by the single-service dispatch below).
_COLLECTORS = {
    "iam": iam_collector.run,
    "s3": s3_collector.run,
    "ec2": ec2_collector.run,
}


def _print_analysis_summary(graph: nx.DiGraph) -> None:
    """Print node/edge statistics for a built graph.

    Args:
        graph: The constructed attack graph.
    """
    stats = graph_builder.graph_statistics(graph)
    width = max((len(k) for k in (*stats["nodes_by_type"], *stats["edges_by_relation"])), default=10)

    print("\n=== Attack Graph Summary ===")
    print(f"{'node type':<{width}}  {'count':>6}")
    print("-" * (width + 9))
    for node_type, count in sorted(stats["nodes_by_type"].items()):
        print(f"{node_type:<{width}}  {count:>6}")
    print(f"{'TOTAL':<{width}}  {graph.number_of_nodes():>6}")

    print(f"\n{'relation':<{width}}  {'count':>6}")
    print("-" * (width + 9))
    for relation, count in sorted(stats["edges_by_relation"].items()):
        print(f"{relation:<{width}}  {count:>6}")
    print(f"{'TOTAL':<{width}}  {graph.number_of_edges():>6}\n")


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser.

    Returns:
        Configured :class:`argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog="cloud-path-mapper",
        description="Map AWS misconfigurations into chained attack path graphs.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    def _add_common_args(sub: argparse.ArgumentParser) -> None:
        """Attach shared auth arguments to a subcommand.

        Args:
            sub: The subparser to extend.
        """
        sub.add_argument("--profile", default=DEFAULT_PROFILE, help="AWS CLI profile name (from `aws configure`).")
        sub.add_argument("--region", default=DEFAULT_REGION, help="AWS region override.")

    iam_sub = subparsers.add_parser(
        "collect-iam",
        help="Collect IAM users/roles/groups/policies into data/raw_iam.json.",
    )
    _add_common_args(iam_sub)

    s3_sub = subparsers.add_parser(
        "collect-s3",
        help="Collect S3 bucket policies/ACLs/public access blocks into data/raw_s3.json.",
    )
    _add_common_args(s3_sub)

    ec2_sub = subparsers.add_parser(
        "collect-ec2",
        help="Collect EC2 instances and security groups into data/raw_ec2.json.",
    )
    _add_common_args(ec2_sub)

    all_sub = subparsers.add_parser(
        "collect-all",
        help="Run every collector sequentially; one failure does not abort the rest.",
    )
    _add_common_args(all_sub)
    all_sub.add_argument(
        "--only",
        nargs="*",
        choices=sorted(_COLLECTORS),
        default=None,
        help="Restrict collect-all to these collectors (default: all).",
    )

    subparsers.add_parser(
        "analyze",
        help="Build the attack graph from data/raw_*.json and export data/graph.json.",
    )

    report = subparsers.add_parser(
        "report",
        help="Find attack paths in data/graph.json, print them, and render attack_paths.html.",
    )
    report.add_argument(
        "--cutoff",
        type=int,
        default=path_finder.PATH_CUTOFF,
        help=f"Maximum hops per path (default: {path_finder.PATH_CUTOFF}).",
    )

    return parser


def _execute(name: str, profile_name: str | None, region_name: str | None) -> int:
    """Run a single collector and report the result.

    Args:
        name: Collector key from :data:`_COLLECTORS`.
        profile_name: AWS CLI profile to authenticate with.
        region_name: Optional region override.

    Returns:
        Process exit code (0 on success, 2 on auth/collector failure).
    """
    try:
        snapshot = _COLLECTORS[name](profile_name=profile_name, region_name=region_name)
    except AWSSessionError as exc:
        logging.error("%s", exc)
        return 2
    except (ClientError, BotoCoreError) as exc:
        logging.error("Collector '%s' failed: %s", name, exc)
        return 3

    entity_counts = ", ".join(f"{k}={len(v)}" for k, v in snapshot.items() if isinstance(v, list))
    print(f"[{name}] OK ({entity_counts})")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the CLI.

    Args:
        argv: Argument list override (used in tests).

    Returns:
        Process exit code.
    """
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.command == "collect-iam":
        return _execute("iam", args.profile, args.region)

    if args.command == "collect-s3":
        return _execute("s3", args.profile, args.region)

    if args.command == "collect-ec2":
        return _execute("ec2", args.profile, args.region)

    if args.command == "collect-all":
        targets = args.only or list(_COLLECTORS)
        results = {name: _execute(name, args.profile, args.region) for name in targets}
        failed = [name for name, code in results.items() if code != 0]
        if failed:
            logger.error("collect-all finished with failures: %s", ", ".join(failed))
            return max(results.values())
        logger.info("collect-all completed successfully.")
        return 0

    if args.command == "analyze":
        try:
            graph = graph_builder.run()
        except FileNotFoundError as exc:
            logging.error("%s", exc)
            return 4
        _print_analysis_summary(graph)
        print("Graph exported to data/graph.json")
        return 0

    if args.command == "report":
        try:
            graph = path_finder.load_graph()
        except FileNotFoundError as exc:
            logging.error("%s", exc)
            return 4

        paths = path_finder.find_attack_paths(graph, cutoff=args.cutoff)

        targets = [
            (node, attrs) for node, attrs in graph.nodes(data=True)
            if attrs.get("target_reason")
        ]
        if targets:
            print(f"\n=== High-Value Targets ({len(targets)}) ===")
            for node, attrs in sorted(targets, key=lambda t: t[1].get("name", "")):
                print(f"  {attrs.get('name')} [{attrs.get('node_type')}] — {attrs['target_reason']}")

        print(f"\n=== Attack Paths ({len(paths)} found, max {args.cutoff} hops) ===")
        if not paths:
            print("No attack paths discovered from entry points to high-value targets.")
        for rank, path in enumerate(paths, start=1):
            print(f"{rank:>3}. [{path['hops']} hops] {path_finder.format_path(path)}")

        findings = graph_builder.load_informational_findings()
        if findings:
            print(f"\n=== Half-Configured Trust Relationships ({len(findings)}) ===")
            print("Named in a trust policy but no sts:AssumeRole grant found;")
            print("not exploitable paths, but cleanup candidates:\n")
            for rank, finding in enumerate(findings, start=1):
                print(
                    f"{rank:>3}. {finding.get('identity', '?')}\n"
                    f"     -> {finding.get('role', '?')}"
                )

        path_finder.save_paths(paths)
        highlighted = {node for path in paths for node in path["nodes"]}
        visualizer.build_visualization(graph, highlighted_nodes=highlighted, informational_findings=findings)
        print(f"\nInteractive visualization: {visualizer.HTML_REPORT_PATH}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
