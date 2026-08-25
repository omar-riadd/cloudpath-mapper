# Cloud Attack Path Mapper

Most AWS security tools stop at checklists: *"this bucket is public," "this policy is over-permissive."* Findings like these ignore the question that actually matters during an incident — **what could an attacker do with them?**

Cloud Attack Path Mapper answers that question. It collects IAM, S3, and EC2 posture from an AWS account, models the results as a **directed privilege graph** (BloodHound-style), and enumerates concrete attack paths that chain individual misconfigurations into full compromise scenarios:

```
Public EC2 instance → instance profile → SSM role → assume-role chain → admin role
                                                     └→ CanRead → customer PII bucket
```

Instead of 400 disconnected findings, you get the handful of paths that end at your data.

## Key Features

- **Attack graph, not a checklist** — identities, compute, and data become nodes; trust relationships, instance profiles, and effective S3 permissions become directed edges.
- **Multi-region fan-out** — EC2 scanning automatically covers every region enabled for the account, so resources hidden in forgotten or opt-in regions don't go unnoticed.
- **Graceful degradation** — `AccessDenied` on a hardened bucket or an opted-out region is recorded and skipped, never fatal. Partial visibility beats no visibility.
- **Offline analysis pipeline** — collectors write raw JSON snapshots once; graph construction, path finding, and visualization run entirely offline against those files. Snapshots double as deterministic test fixtures.
- **Effective permission resolution** — managed policies are resolved to full documents, inline policies are parsed, and users inherit group policies, so edges reflect what identities can *actually* do.
- **Interactive visualization** — pyvis HTML report with color-coded node types, labeled attack-step edges, hover details (full ARNs, region, exposure status), and highlighted nodes on discovered paths.

## How It Works

```
┌──────────────┐   ┌───────────────┐   ┌──────────────────┐   ┌─────────────┐   ┌───────────────┐
│ boto3        │   │ JSON          │   │ NetworkX         │   │ Path Finder │   │ pyvis         │
│ Collectors   │──▶│ Snapshots     │──▶│ Graph Builder    │──▶│ (bounded    │──▶│ Interactive   │
│ (IAM/S3/EC2) │   │ (raw_*.json)  │   │ (DiGraph + edges)│   │  path enum) │   │ HTML report   │
└──────────────┘   └───────────────┘   └──────────────────┘   └─────────────┘   └───────────────┘
```

1. **Collectors** (`src/cloud_path_mapper/collectors/`) pull IAM users/roles/groups/policies/instance profiles, every S3 bucket's policy/ACL/Public Access Block, and all EC2 instances + security groups across regions into raw JSON snapshots under `data/`.
2. **Graph Builder** (`analysis/graph_builder.py`) loads the snapshots and constructs a `DiGraph`. Edges encode attack pivots:
   - `CanAssumeRole` — from parsed role trust policies
   - `HasInstanceProfile` — EC2 instance → embedded IAM role (the compute-to-identity bridge)
   - `CanRead` — identity → S3 bucket, derived from resolved policy documents (including wildcard-resource grants)
3. **Path Finder** (`engine/path_finder.py`) enumerates simple paths from entry points (users, EC2 instances) to high-value targets (S3 buckets, `*admin*` roles) with a configurable hop cutoff.
4. **Visualizer** (`output/visualizer.py`) renders the graph to an interactive HTML report with discovered paths highlighted.

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/<your-username>/cloud-attack-path-mapper.git
cd cloud-attack-path-mapper

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

A profile with `ReadOnlyAccess` (or a scoped-down equivalent covering `sts:GetCallerIdentity`, `iam:*` reads, `s3:` bucket-policy reads, and `ec2:Describe*`) is sufficient. See [`iam-collector` required actions](#usage) — nothing is written to your account.

## Usage

```bash
# 1. Collect everything (IAM + S3 + multi-region EC2)
cloud-path-mapper collect-all --profile audit-readonly

# ...or service by service
cloud-path-mapper collect-iam --profile audit-readonly
cloud-path-mapper collect-s3  --profile audit-readonly
cloud-path-mapper collect-ec2 --profile audit-readonly [--region us-east-1]

# 2. Build the attack graph from the snapshots
cloud-path-mapper analyze

# 3. Discover attack paths and generate the visual report
cloud-path-mapper report [--cutoff 5]
```

Outputs, all under `data/`:

| File | Contents |
|---|---|
| `raw_iam.json`, `raw_s3.json`, `raw_ec2.json` | Raw collector snapshots (reusable as test fixtures) |
| `graph.json` | Node-link export of the attack graph |
| `attack_paths.json` | Discovered paths (entry, target, hops, node chain) |
| `attack_paths.html` | Interactive pyvis visualization |

Open `data/attack_paths.html` in any browser to explore the graph.

### Try it without an AWS account

The pipeline runs fully offline against snapshot files, making it easy to demo with [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) or hand-crafted fixtures: drop JSON snapshots matching the collector output format into `data/`, then run `analyze` and `report`.

## Demo

![Attack Graph](data/attack_paths.png)

## Roadmap

- SQLite scan history and cross-scan diffing (`attack_paths.json` is already structured for this)
- Privilege escalation rules beyond trust chains (e.g., `iam:PassRole`, `lambda:CreateEventSourceMapping`)
- Additional collectors (Lambda, Secrets Manager, ECR)
- Risk scoring of paths based on target sensitivity and edge exploitability

## Disclaimer

This tool performs read-only reconnaissance of your own AWS accounts. Only run it against accounts you are authorized to assess.
