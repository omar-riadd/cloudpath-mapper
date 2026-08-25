"""Central configuration and filesystem paths for the tool."""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data"
RAW_IAM_PATH = DATA_DIR / "raw_iam.json"
RAW_S3_PATH = DATA_DIR / "raw_s3.json"
RAW_EC2_PATH = DATA_DIR / "raw_ec2.json"
GRAPH_PATH = DATA_DIR / "graph.json"
ATTACK_PATHS_PATH = DATA_DIR / "attack_paths.json"
INFORMATIONAL_FINDINGS_PATH = DATA_DIR / "informational_findings.json"
HTML_REPORT_PATH = DATA_DIR / "attack_paths.html"

DEFAULT_PROFILE: str | None = None
DEFAULT_REGION: str | None = None
