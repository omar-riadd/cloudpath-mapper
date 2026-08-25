# CloudPath Mapper

Most AWS security tools stop at checklists: *"this bucket is public," "this policy is over-permissive."* Findings like these ignore the question that actually matters during an incident — **what could an attacker do with them?**

CloudPath Mapper answers that question. It collects IAM, S3, and EC2 posture from an AWS account, models the results as a **directed privilege graph** (BloodHound-style), and enumerates concrete attack paths that chain individual misconfigurations into full compromise scenarios:

```
Public EC2 instance → instance profile → SSM role → assume-role chain → admin role
                                                     └→ CanRead → customer PII bucket
```

Instead of a flat findings list, you get the handful of paths that actually reach something valuable — with noise from already-privileged identities filtered out.

## Key Features

- **Attack graph, not a checklist** — identities, compute, and data become nodes; trust relationships, instance profiles, and effective S3 permissions become directed edges.
- **Dual-signal trust resolution** — `CanAssumeRole` edges require BOTH a trust-policy match (named principal or same-account root) AND a corresponding `sts:AssumeRole` permission grant on the calling identity. Signals are evaluated independently and combined, closing false negatives (root-trusted roles being invisible) and false positives (named-but-ungranted trust looking like a working path) that a single-sided check would miss.
- **Half-configured trust detection** — when a trust policy names an identity that holds no matching permission grant, it's recorded as a `TrustedButNoGrant` informational finding (not a graph edge) — a real cleanup candidate for reviewers, distinct from an exploitable path.
- **Policy-content-based high-value target detection** — targets are identified by what a role's *effective permissions actually grant* (`AdministratorAccess`, IAM-write actions like `iam:CreateAccessKey`, or wildcard access to sensitive services), not by name-matching. An admin-privileged role with an unassuming name is still caught. Each target is tagged with the specific reason it was flagged.
- **Entry-point noise filtering** — identities that are themselves high-value targets are excluded as path *origins*, since "an already-privileged identity uses its own access" isn't an escalation finding. They remain valid as intermediate hops or destinations, so a normal user pivoting into a privileged identity is still reported in full.
- **Prefix-path collapsing** — when multiple discovered paths share a common route and one is a strict prefix of another, only the longest (most complete) path is reported, eliminating redundant partial-route noise without dropping genuinely distinct paths to different targets.
- **Multi-region fan-out** — EC2 scanning automatically covers every region enabled for the account, so resources hidden in forgotten or opt-in regions don't go unnoticed.
- **Graceful degradation** — `AccessDenied` on a hardened bucket or an opted-out region is recorded and skipped, never fatal. Partial visibility beats no visibility.
- **Offline analysis pipeline** — collectors write raw JSON snapshots once; graph construction, path finding, and visualization run entirely offline against those files. Snapshots double as deterministic test fixtures.
- **Effective permission resolution** — managed policies are resolved to full documents, inline policies are parsed, users inherit group policies, and explicit `Deny` statements correctly suppress otherwise-matching `Allow` grants.
- **Interactive visualization** — pyvis HTML report with color-coded node types, labeled attack-step edges, hover details (full ARNs, region, exposure status, high-value-target reasons), and a dedicated panel surfacing half-configured trust findings.
- **Robust UI failsafes** — the generated report's JavaScript is post-processed to stay fully functional even on clean accounts with zero vulnerabilities, and all identity strings (ARNs, usernames) are HTML-escaped before injection to prevent stored-XSS from attacker-controlled resource names.

## How It Works

```
┌──────────────┐   ┌───────────────┐   ┌──────────────────┐   ┌─────────────┐   ┌───────────────┐
│ boto3        │   │ JSON          │   │ NetworkX         │   │ Path Finder │   │ pyvis         │
│ Collectors   │──▶│ Snapshots     │──▶│ Graph Builder    │──▶│ (filtered,  │──▶│ Interactive   │
│ (IAM/S3/EC2) │   │ (raw_*.json)  │   │ + target tagging │   │  collapsed) │   │ HTML report   │
└──────────────┘   └───────────────┘   └──────────────────┘   └─────────────┘   └───────────────┘
```

1. **Collectors** (`src/cloud_path_mapper/collectors/`) pull IAM users/roles/groups/policies/instance profiles, every S3 bucket's policy/ACL/Public Access Block, and all EC2 instances + security groups across regions into raw JSON snapshots under `data/`.
2. **Graph Builder** (`analysis/graph_builder.py`) loads the snapshots, harvests effective (Deny-aware) policy statements per identity once, and shares that resolution across three consumers:
   - **`CanAssumeRole`** edges — created only when a trust-side signal (named principal or same-account root) AND a permission-side `sts:AssumeRole` grant both hold. Named-but-ungranted pairs are recorded as `TrustedButNoGrant` informational findings instead of edges.
   - **`HasInstanceProfile`** — EC2 instance → embedded IAM role (the compute-to-identity bridge).
   - **`CanRead`** — identity → S3 bucket, derived from resolved policy documents (including wildcard-resource grants).
   - **High-value target tagging** — any node whose effective permissions include `AdministratorAccess`, an IAM-write action, or a sensitive-service wildcard is tagged with a `target_reason`.
3. **Path Finder** (`engine/path_finder.py`) enumerates simple paths from eligible entry points (users/instances that are *not themselves* tagged targets) to tagged high-value targets and S3 buckets, then collapses any path that is a strict prefix of a longer path to the same destination chain.
4. **Visualizer** (`output/visualizer.py`) renders the graph through a single `_post_process_html` pipeline — legend injection, TomSelect repair, zero-edge UI guards, and the half-configured-trust findings panel — producing one self-contained interactive HTML file.

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/omar-riadd/cloudpath-mapper.git
cd cloudpath-mapper

python3 -m venv .venv
source .venv/bin/activate

pip install -e .
```

## AWS Setup

The tool uses the standard AWS credential provider chain only — it never accepts access keys as arguments or environment input.

Configure a profile with read-only permissions:

```bash
aws configure --profile audit-readonly
```

A profile with `ReadOnlyAccess` (or a scoped-down equivalent covering `sts:GetCallerIdentity`, IAM reads, S3 bucket-policy reads, and `ec2:Describe*`) is sufficient. Nothing is ever written to your account.

## Usage

```bash
# 1. Collect everything (IAM + S3 + multi-region EC2)
cloud-path-mapper collect-all --profile audit-readonly

# ...or service by service
cloud-path-mapper collect-iam --profile audit-readonly
cloud-path-mapper collect-s3  --profile audit-readonly
cloud-path-mapper collect-ec2 --profile audit-readonly [--region us-east-1]

# 2. Build the attack graph, tag high-value targets, and record trust findings
cloud-path-mapper analyze

# 3. Discover attack paths and generate the visual report
cloud-path-mapper report [--cutoff 5]
```

| File | Contents |
|---|---|
| `raw_iam.json`, `raw_s3.json`, `raw_ec2.json` | Raw collector snapshots (reusable as test fixtures) |
| `graph.json` | Node-link export of the attack graph, including `target_reason` tags |
| `informational_findings.json` | `TrustedButNoGrant` findings — named-but-ungrantable trust relationships |
| `attack_paths.json` | Discovered, filtered, and collapsed attack paths |
| `attack_paths.html` | Self-contained interactive attack graph with the trust-findings panel |

### Try it without an AWS account

The pipeline runs fully offline against snapshot files, making it easy to demo with [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) or hand-crafted fixtures: drop JSON snapshots matching the collector output format into `data/`, then run `analyze` and `report`. Even a completely clean account works — the report renders an empty-but-functional UI rather than freezing.

## Validation

This tool was validated iteratively against a live AWS sandbox account, not just unit fixtures — each fix below was confirmed by re-running the actual collect/analyze/report pipeline against real AWS API responses, not accepted on the strength of a passing test suite alone.

1. **CloudGoat `cloud_breach_s3` scenario** — the tool reconstructed CloudGoat's intended attack chain (public EC2 instance → instance profile → role → S3 read on a cardholder-data bucket) with zero manual annotation, confirming the instance-profile-to-role bridge and policy resolution logic model real AWS permission structure correctly.
2. **Synthetic 4-hop privilege escalation chain** — a hand-built chain (`dev-user1 → EntryRoleA → PivotRoleB → TargetRoleC`, ending at an `AdministratorAccess`-attached role) using account-root trust policies initially exposed a false negative: `CanAssumeRole` resolution only handled trust policies naming a specific principal, silently missing the far more common root-trust pattern. Fixed with a two-sided grant+trust resolution model; the corrected chain was confirmed end-to-end against the live account.
3. **Named-principal false positive** — after fixing (2), a related gap surfaced: trust policies naming a specific identity created an edge even when that identity held no matching `sts:AssumeRole` permission grant, which doesn't correspond to a working AWS escalation. Unified into one dual-signal check (both named-principal and root-trust require a confirmed grant); independence between the two signals was proven with a live test showing one un-granted named pair correctly produces no edge while a separate, unnamed, root-trust-qualifying identity does.
4. **Orphaned trust relationships (`TrustedButNoGrant`)** — created a disposable IAM user named in a role's trust policy with deliberately no permission grant, confirmed the finding was correctly recorded in `informational_findings.json`, surfaced in the CLI report, and rendered in the HTML panel — then confirmed the finding correctly cleared to zero after the test resources were deleted.
5. **Name-based target detection false negative** — the original high-value-target heuristic matched role *names* (e.g. "Target", "Admin"), meaning an admin-privileged role with an unassuming name would be invisible to the path finder despite the graph correctly containing edges reaching it. Replaced with policy-content-based detection (`AdministratorAccess`, IAM-write actions, sensitive-service wildcards); confirmed live that a previously name-matched role was now caught by content alone.
6. **Entry-point and path noise** — an already-privileged identity (e.g. an account's Terraform deployer with `AdministratorAccess`) "escalating" to another privileged role isn't a real finding. Filtering already-privileged identities out of valid path *origins* (while keeping them as valid intermediate hops/destinations) reduced the live report from 9 paths to 2 genuine findings, while confirmed regression testing showed the one real multi-hop escalation story remained fully intact.

## Known Limitations

- **Cross-account trust** — only same-account root trust is resolved; cross-account role assumption requires visibility into external-account identities this tool doesn't have.
- **Trust policy Conditions** — statements gated by `Condition` blocks (`sts:ExternalId`, `aws:SourceIdentity`, `aws:PrincipalTag/*`, etc.) are never evaluated and are conservatively skipped, which can produce false negatives (a real conditioned path not shown) but never false positives.
- **Permission boundaries, SCPs, and session policies** — invisible in snapshot-based collection; effective permissions may be narrower in practice than what's modeled.
- **`NotPrincipal` / `NotAction`** — rare policy constructs, unsupported by the current matchers.
- **Resource-condition functions** — constructs like `iam:ResourceTag` in `AssumeRole` resource matching aren't modeled.
- **`target_reason` is currently free-text** — a structured enum + detail representation would compose better if risk scoring is added later.

## Roadmap

- Structured (enum-based) `target_reason` for future risk scoring
- Additional collectors (Lambda, Secrets Manager, ECR)
- SQLite scan history and cross-scan diffing
- Cross-account trust chain resolution

## Disclaimer

This tool performs read-only reconnaissance of your own AWS accounts. Only run it against accounts you are authorized to assess.

## Author

**Omar Mohamed**

Repository: [github.com/omar-riadd/cloudpath-mapper](https://github.com/omar-riadd/cloudpath-mapper)
