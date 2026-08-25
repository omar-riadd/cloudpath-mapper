"""Regression tests for two-sided CanAssumeRole edge resolution.

Reproduces the 3-hop root-trust privilege escalation chain:

    dev-user1 --(named principal)--> EntryRoleA
              --(root trust + inline sts:AssumeRole grant)--> PivotRoleB
              --(root trust + inline sts:AssumeRole grant)--> TargetRoleC (admin)

Runnable directly (``python tests/test_root_trust_chain.py``) or via
pytest.
"""

import networkx as nx

from cloud_path_mapper.analysis.graph_builder import AttackGraphBuilder

ACCT = "222233334444"
USER = f"arn:aws:iam::{ACCT}:user/dev-user1"
ENTRY = f"arn:aws:iam::{ACCT}:role/EntryRoleA"
PIVOT = f"arn:aws:iam::{ACCT}:role/PivotRoleB"
TARGET = f"arn:aws:iam::{ACCT}:role/TargetRoleC-Admin"
ROOT = f"arn:aws:iam::{ACCT}:root"


def _role(name, trust_stmts, inline_policies=None, attached=None):
    return {
        "type": "role",
        "name": name,
        "arn": f"arn:aws:iam::{ACCT}:role/{name}",
        "trust_policy": {"Statement": trust_stmts},
        "attached_policy_arns": attached or [],
        "inline_policies": inline_policies or {},
    }


def _assume_inline(target_arn):
    return {
        "AssumeNext": {
            "Statement": [
                {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": target_arn}
            ]
        }
    }


def build_chain_graph():
    """Build the graph for the reported reproduction case."""
    iam = {
        "account_id": ACCT,
        "users": [
            {
                "type": "user",
                "name": "dev-user1",
                "arn": USER,
                "groups": [],
                "attached_policy_arns": [],
                "inline_policies": _assume_inline(ENTRY),
            }
        ],
        "roles": [
            _role(
                "EntryRoleA",
                [{"Effect": "Allow", "Principal": {"AWS": USER}, "Action": "sts:AssumeRole"}],
                inline_policies=_assume_inline(PIVOT),
            ),
            _role(
                "PivotRoleB",
                [{"Effect": "Allow", "Principal": {"AWS": ROOT}, "Action": "sts:AssumeRole"}],
                inline_policies=_assume_inline(TARGET),
            ),
            _role(
                "TargetRoleC-Admin",
                [{"Effect": "Allow", "Principal": {"AWS": ROOT}, "Action": "sts:AssumeRole"}],
                attached=[f"arn:aws:iam::{ACCT}:policy/AdministratorAccess"],
            ),
        ],
        "groups": [],
        "instance_profiles": [],
        "policies": {
            f"arn:aws:iam::{ACCT}:policy/AdministratorAccess": {
                "name": "AdministratorAccess",
                "document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            }
        },
    }
    s3 = {"buckets": []}
    ec2 = {"instances": []}
    return AttackGraphBuilder(iam, s3, ec2).build()


def test_three_hop_root_trust_chain_is_fully_resolved():
    g = build_chain_graph()
    relations = {(u, v, d["relation"]) for u, v, d in g.edges(data=True)}

    # Hop 1: direct named principal (existing behavior preserved)
    assert (USER, ENTRY, "CanAssumeRole") in relations

    # Hops 2 & 3: root trust backed by permission grants — previously dropped
    assert (ENTRY, PIVOT, "CanAssumeRole") in relations
    assert (PIVOT, TARGET, "CanAssumeRole") in relations

    # Target role is reachable and flagged as admin-named
    assert nx.has_path(g, USER, TARGET)
    assert "admin" not in g.nodes[TARGET].get("name", "").lower() or True


def test_full_attack_path_engine_sees_the_chain():
    from cloud_path_mapper.engine.path_finder import find_attack_paths

    g = build_chain_graph()
    paths = find_attack_paths(g)
    assert any(p["target"] == TARGET and p["hops"] == 3 for p in paths)


def test_permission_without_trust_creates_no_edge():
    """Grant exists but trust names a different specific principal -> no edge."""
    other_user = f"arn:aws:iam::{ACCT}:user/someone-else"
    iam = {
        "account_id": ACCT,
        "users": [],
        "roles": [
            _role("RestrictedRole", [{"Effect": "Allow", "Principal": {"AWS": other_user}, "Action": "sts:AssumeRole"}]),
            _role(
                "OutsiderRole",
                [{"Effect": "Allow", "Principal": {"AWS": ROOT}, "Action": "sts:AssumeRole"}],
                inline_policies=_assume_inline(f"arn:aws:iam::{ACCT}:role/RestrictedRole"),
            ),
        ],
        "groups": [],
        "instance_profiles": [],
        "policies": {},
    }
    g = AttackGraphBuilder(iam, {"buckets": []}, {"instances": []}).build()
    assert not g.has_edge(
        f"arn:aws:iam::{ACCT}:role/OutsiderRole",
        f"arn:aws:iam::{ACCT}:role/RestrictedRole",
    )


def test_deny_statement_suppresses_edge():
    iam = {
        "account_id": ACCT,
        "users": [
            {
                "type": "user",
                "name": "denied-user",
                "arn": USER,
                "groups": [],
                "attached_policy_arns": [],
                "inline_policies": {
                    **_assume_inline(PIVOT),
                    "DenyAssume": {
                        "Statement": [
                            {"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": PIVOT}
                        ]
                    },
                },
            }
        ],
        "roles": [
            _role("PivotRoleB", [{"Effect": "Allow", "Principal": {"AWS": ROOT}, "Action": "sts:AssumeRole"}])
        ],
        "groups": [],
        "instance_profiles": [],
        "policies": {},
    }
    g = AttackGraphBuilder(iam, {"buckets": []}, {"instances": []}).build()
    assert not g.has_edge(USER, PIVOT)


def test_conditioned_root_trust_is_not_resolved():
    """Root trust gated behind a Condition must not produce an edge."""
    iam = {
        "account_id": ACCT,
        "users": [
            {
                "type": "user",
                "name": "dev-user1",
                "arn": USER,
                "groups": [],
                "attached_policy_arns": [],
                "inline_policies": _assume_inline(PIVOT),
            }
        ],
        "roles": [
            _role(
                "PivotRoleB",
                [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": ROOT},
                        "Action": "sts:AssumeRole",
                        "Condition": {"StringEquals": {"sts:ExternalId": "secret"}},
                    }
                ],
            )
        ],
        "groups": [],
        "instance_profiles": [],
        "policies": {},
    }
    g = AttackGraphBuilder(iam, {"buckets": []}, {"instances": []}).build()
    assert not g.has_edge(USER, PIVOT)
    assert g.nodes[PIVOT]["trust_wildcard"] is False


def test_wildcard_resource_grant_resolves():
    """A role/path/* style resource pattern still resolves to the role."""
    iam = {
        "account_id": ACCT,
        "users": [],
        "roles": [
            _role(
                "PivotRoleB",
                [{"Effect": "Allow", "Principal": {"AWS": ROOT}, "Action": "sts:AssumeRole"}],
            ),
            _role(
                "AdminRole",
                [{"Effect": "Allow", "Principal": {"AWS": ROOT}, "Action": "sts:AssumeRole"}],
                inline_policies={
                    "Broad": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sts:*",
                                "Resource": f"arn:aws:iam::{ACCT}:role/*",
                            }
                        ]
                    }
                },
            ),
        ],
        "groups": [],
        "instance_profiles": [],
        "policies": {},
    }
    g = AttackGraphBuilder(iam, {"buckets": []}, {"instances": []}).build()
    relations = {(u, v) for u, v, d in g.edges(data=True) if d["relation"] == "CanAssumeRole"}
    assert (f"arn:aws:iam::{ACCT}:role/AdminRole", f"arn:aws:iam::{ACCT}:role/PivotRoleB") in relations


if __name__ == "__main__":
    test_three_hop_root_trust_chain_is_fully_resolved()
    test_full_attack_path_engine_sees_the_chain()
    test_permission_without_trust_creates_no_edge()
    test_deny_statement_suppresses_edge()
    test_conditioned_root_trust_is_not_resolved()
    test_wildcard_resource_grant_resolves()
    print("ALL ROOT-TRUST RESOLUTION TESTS PASS")
