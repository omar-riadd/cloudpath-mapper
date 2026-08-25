"""Entry-point filtering for attack path enumeration.

Identities that are already high-value targets (``target_reason``
present) are excluded as path ORIGINS: an already-privileged identity
exercising its own access is normal operation, not escalation. Such
nodes remain valid as intermediate hops and destinations.
"""

import networkx as nx

from cloud_path_mapper.engine.path_finder import find_attack_paths

ACCT = "555566667777"


def _node(g, arn, node_type, name, target=False):
    g.add_node(
        arn,
        node_type=node_type,
        name=name,
        arn=arn,
        region=None,
        **({"target_reason": "AdministratorAccess"} if target else {}),
    )


def _role_arn(name):
    return f"arn:aws:iam::{ACCT}:role/{name}"


def _user_arn(name):
    return f"arn:aws:iam::{ACCT}:user/{name}"


def test_privileged_origin_not_reported():
    """An already-privileged identity 'escalating' is a non-finding."""
    g = nx.DiGraph()
    _node(g, _user_arn("super-admin"), "user", "super-admin", target=True)
    _node(g, _role_arn("other-target"), "role", "other-target", target=True)
    g.add_edge(_user_arn("super-admin"), _role_arn("other-target"), relation="CanAssumeRole")

    paths = find_attack_paths(g)
    assert paths == []


def test_privileged_intermediate_hop_still_reported():
    """Normal -> privileged -> further target remains a full finding."""
    g = nx.DiGraph()
    _node(g, _user_arn("low-priv-user"), "user", "low-priv-user")
    _node(g, _role_arn("pivot-admin"), "role", "pivot-admin", target=True)
    _node(g, _role_arn("crown-jewel-role"), "role", "crown-jewel-role", target=True)
    _node(g, "arn:aws:s3:::secrets", "s3_bucket", "secrets")
    g.add_edge(_user_arn("low-priv-user"), _role_arn("pivot-admin"), relation="CanAssumeRole")
    g.add_edge(_role_arn("pivot-admin"), _role_arn("crown-jewel-role"), relation="CanAssumeRole")
    g.add_edge(_role_arn("crown-jewel-role"), "arn:aws:s3:::secrets", relation="CanRead")

    paths = find_attack_paths(g)

    # Prefix collapsing keeps only the longest chain through the
    # privileged intermediate; it must still originate at low-priv-user.
    assert len(paths) == 1
    assert paths[0]["entry"] == _user_arn("low-priv-user")
    assert paths[0]["target"] == "arn:aws:s3:::secrets"
    assert paths[0]["names"] == ["low-priv-user", "pivot-admin", "crown-jewel-role", "secrets"]


def test_plain_normal_path_unaffected():
    """A normal identity reaching one target with no privileged hops."""
    g = nx.DiGraph()
    _node(g, _user_arn("plain-user"), "user", "plain-user")
    _node(g, _role_arn("plain-target"), "role", "plain-target", target=True)
    g.add_edge(_user_arn("plain-user"), _role_arn("plain-target"), relation="CanAssumeRole")

    paths = find_attack_paths(g)
    assert len(paths) == 1
    assert paths[0]["entry"] == _user_arn("plain-user")
    assert paths[0]["target"] == _role_arn("plain-target")


if __name__ == "__main__":
    test_privileged_origin_not_reported()
    test_privileged_intermediate_hop_still_reported()
    test_plain_normal_path_unaffected()
    print("ALL ENTRY-POINT FILTER TESTS PASS")
