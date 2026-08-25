"""Prefix-collapse behavior of the attack path finder.

Strict prefixes of longer paths to the same chain are collapsed;
same-prefix paths reaching genuinely different targets are kept.
"""

import networkx as nx

from cloud_path_mapper.engine.path_finder import find_attack_paths

ACCT = "444455556666"


def _node(g, arn, node_type, name, target=False):
    g.add_node(
        arn,
        node_type=node_type,
        name=name,
        arn=arn,
        region=None,
        **({"target_reason": "AdministratorAccess"} if target else {}),
    )


def _edge(g, u, v, relation="CanAssumeRole"):
    g.add_edge(u, v, relation=relation)


def _identity_graph():
    g = nx.DiGraph()
    _node(g, f"arn:aws:iam::{ACCT}:user/attacker", "user", "attacker")
    return g


def _role(g, name, target):
    _node(g, f"arn:aws:iam::{ACCT}:role/{name}", "role", name, target=target)


def _bucket(g, name):
    _node(g, f"arn:aws:s3:::{name}", "s3_bucket", name)


def test_strict_prefix_collapsed_to_longest_path():
    """A->B->Target and A->B->Target->Bucket collapse to the longest."""
    A = f"arn:aws:iam::{ACCT}:user/attacker"
    B = f"arn:aws:iam::{ACCT}:role/mid-role"
    C = f"arn:aws:iam::{ACCT}:role/TargetRoleC"
    D = "arn:aws:s3:::crown-jewels"

    g = _identity_graph()
    _role(g, "mid-role", target=True)
    _role(g, "TargetRoleC", target=True)
    _bucket(g, "crown-jewels")
    _edge(g, A, B)
    _edge(g, B, C)
    _edge(g, C, D, relation="CanRead")

    paths = find_attack_paths(g)

    # Without collapsing there would be 3 (A->B, A->B->C, A->B->C->D).
    assert len(paths) == 1
    assert paths[0]["target"] == D
    assert paths[0]["names"] == ["attacker", "mid-role", "TargetRoleC", "crown-jewels"]


def test_same_prefix_different_targets_both_kept():
    """A->P->X and A->P->Y are distinct findings; neither collapses."""
    A = f"arn:aws:iam::{ACCT}:user/attacker"
    P = f"arn:aws:iam::{ACCT}:role/pivot"
    X = f"arn:aws:iam::{ACCT}:role/target-x"
    Y = f"arn:aws:iam::{ACCT}:role/target-y"

    g = _identity_graph()
    _role(g, "pivot", target=False)
    _role(g, "target-x", target=True)
    _role(g, "target-y", target=True)
    _edge(g, A, P)
    _edge(g, P, X)
    _edge(g, P, Y)

    paths = find_attack_paths(g)

    targets = {p["target"] for p in paths}
    assert targets == {X, Y}
    assert all(p["hops"] == 2 for p in paths)


def test_unrelated_single_path_unaffected():
    """One path with no prefix relationship anywhere is untouched."""
    A = f"arn:aws:iam::{ACCT}:user/attacker"
    T = f"arn:aws:iam::{ACCT}:role/lone-target"

    g = _identity_graph()
    _role(g, "lone-target", target=True)
    _edge(g, A, T)

    paths = find_attack_paths(g)
    assert len(paths) == 1 and paths[0]["target"] == T


if __name__ == "__main__":
    test_strict_prefix_collapsed_to_longest_path()
    test_same_prefix_different_targets_both_kept()
    test_unrelated_single_path_unaffected()
    print("ALL PREFIX-COLLAPSE TESTS PASS")
