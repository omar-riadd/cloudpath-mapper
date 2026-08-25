"""Policy-content-based high-value target detection tests.

Proves that target detection is driven by effective policy content
(AdministratorAccess, IAM-write actions, sensitive service wildcards)
rather than role names, and that each flagged node carries the reason.
"""

from cloud_path_mapper.analysis.graph_builder import AttackGraphBuilder

ACCT = "333344445555"


def _role(name, inline_policies=None, attached_policy_arns=None):
    return {
        "type": "role",
        "name": name,
        "arn": f"arn:aws:iam::{ACCT}:role/{name}",
        "trust_policy": {
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:root"},
                 "Action": "sts:AssumeRole"}
            ]
        },
        "attached_policy_arns": attached_policy_arns or [],
        "inline_policies": inline_policies or {},
    }


def _build(iam):
    return AttackGraphBuilder(iam, {"buckets": []}, {"instances": []})


def test_administratoraccess_detected_on_unassuming_name():
    """svc-billing-helper with AdministratorAccess must be a target."""
    admin_arn = f"arn:aws:iam::{ACCT}:policy/AdministratorAccess"
    iam = {
        "account_id": ACCT,
        "users": [],
        "roles": [
            _role(
                "svc-billing-helper",
                attached_policy_arns=[admin_arn],
            )
        ],
        "groups": [],
        "instance_profiles": [],
        "policies": {
            admin_arn: {
                "name": "AdministratorAccess",
                "document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            }
        },
    }
    builder = _build(iam)
    g = builder.build()
    node = g.nodes[f"arn:aws:iam::{ACCT}:role/svc-billing-helper"]
    assert "target_reason" in node
    assert "AdministratorAccess" in node["target_reason"]


def test_wildcard_action_resource_detected_as_admin():
    """Inline Action:* on Resource:* counts even without a named policy."""
    iam = {
        "account_id": ACCT,
        "users": [],
        "roles": [
            _role(
                "mystery-role",
                inline_policies={
                    "Everything": {
                        "Statement": [
                            {"Effect": "Allow", "Action": "*", "Resource": "*"}
                        ]
                    }
                },
            )
        ],
        "groups": [],
        "instance_profiles": [],
        "policies": {},
    }
    g = _build(iam).build()
    node = g.nodes[f"arn:aws:iam::{ACCT}:role/mystery-role"]
    assert "AdministratorAccess" in node.get("target_reason", "")


def test_admin_named_role_without_privileges_not_flagged_by_content():
    """AdminBackupRole with only s3:GetObject on one bucket is NOT a target.

    Proves the name heuristic alone no longer drives detection.
    """
    iam = {
        "account_id": ACCT,
        "users": [],
        "roles": [
            _role(
                "AdminBackupRole",
                inline_policies={
                    "BackupRead": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": f"arn:aws:s3:::backup-bucket-{ACCT}/*",
                            }
                        ]
                    }
                },
            )
        ],
        "groups": [],
        "instance_profiles": [],
        "policies": {},
    }
    builder = _build(iam)
    g = builder.build()
    node = g.nodes[f"arn:aws:iam::{ACCT}:role/AdminBackupRole"]
    assert "target_reason" not in node

    # And the path finder agrees: no identity targets exist.
    from cloud_path_mapper.engine.path_finder import find_high_value_targets
    assert find_high_value_targets(g) == []


def test_iam_create_access_key_detected_with_reason():
    """A role granting only iam:CreateAccessKey is a target, with reason."""
    iam = {
        "account_id": ACCT,
        "users": [],
        "roles": [
            _role(
                "key-rotator",
                inline_policies={
                    "RotateKeys": {
                        "Statement": [
                            {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"}
                        ]
                    }
                },
            )
        ],
        "groups": [],
        "instance_profiles": [],
        "policies": {},
    }
    g = _build(iam).build()
    node = g.nodes[f"arn:aws:iam::{ACCT}:role/key-rotator"]
    assert node.get("target_reason") == "iam:CreateAccessKey"


def test_sensitive_service_wildcard_detected():
    """s3:* on Resource:* flags the identity as a data-exfil target."""
    iam = {
        "account_id": ACCT,
        "users": [],
        "roles": [
            _role(
                "s3-power-user",
                inline_policies={
                    "S3All": {
                        "Statement": [
                            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
                        ]
                    }
                },
            )
        ],
        "groups": [],
        "instance_profiles": [],
        "policies": {},
    }
    g = _build(iam).build()
    node = g.nodes[f"arn:aws:iam::{ACCT}:role/s3-power-user"]
    assert any("s3:*" in r for r in node.get("target_reason", "").split("; "))


def test_deny_suppresses_target_flag():
    """An explicit Deny on the escalation action prevents flagging."""
    iam = {
        "account_id": ACCT,
        "users": [],
        "roles": [
            _role(
                "restricted-key-rotator",
                inline_policies={
                    "RotateKeys": {
                        "Statement": [
                            {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"}
                        ]
                    },
                    "Guardrail": {
                        "Statement": [
                            {"Effect": "Deny", "Action": "iam:CreateAccessKey", "Resource": "*"}
                        ]
                    },
                },
            )
        ],
        "groups": [],
        "instance_profiles": [],
        "policies": {},
    }
    g = _build(iam).build()
    assert "target_reason" not in g.nodes[f"arn:aws:iam::{ACCT}:role/restricted-key-rotator"]


def test_name_heuristic_demoted_to_hint():
    """The legacy admin-name signal survives as a hint, not a target."""
    iam = {
        "account_id": ACCT,
        "users": [],
        "roles": [_role("some-admin-role")],
        "groups": [],
        "instance_profiles": [],
        "policies": {},
    }
    builder = _build(iam)
    g = builder.build()
    node = g.nodes[f"arn:aws:iam::{ACCT}:role/some-admin-role"]
    assert node.get("admin_name_hint") is True
    assert "target_reason" not in node

    from cloud_path_mapper.engine.path_finder import find_high_value_targets
    assert find_high_value_targets(g) == []


if __name__ == "__main__":
    test_administratoraccess_detected_on_unassuming_name()
    test_wildcard_action_resource_detected_as_admin()
    test_admin_named_role_without_privileges_not_flagged_by_content()
    test_iam_create_access_key_detected_with_reason()
    test_sensitive_service_wildcard_detected()
    test_deny_suppresses_target_flag()
    test_name_heuristic_demoted_to_hint()
    print("ALL HIGH-VALUE TARGET DETECTION TESTS PASS")
