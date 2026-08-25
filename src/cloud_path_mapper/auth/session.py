"""Secure AWS session management.

This module is the single entry point for creating boto3 sessions.
Credentials are NEVER accepted as function arguments or environment
variables set by this tool; we rely exclusively on the standard AWS
credential provider chain (aws configure profiles, SSO, instance
profiles, etc.) so secrets never touch this codebase.
"""

from __future__ import annotations

import logging
from typing import Optional

import boto3
from botocore.exceptions import ClientError, ProfileNotFound

logger = logging.getLogger(__name__)


class AWSSessionError(RuntimeError):
    """Raised when a usable AWS session cannot be established."""


def build_session(
    profile_name: Optional[str] = None,
    region_name: Optional[str] = None,
) -> boto3.Session:
    """Create a boto3 session using the standard credential chain.

    Args:
        profile_name: Name of an AWS CLI profile (as configured via
            ``aws configure``). If None, the default profile or any
            ambient credentials (SSO, instance role) are used.
        region_name: AWS region to target. If None, falls back to the
            region configured in the active profile.

    Returns:
        A ready-to-use :class:`boto3.Session`.

    Raises:
        AWSSessionError: If the profile does not exist or credentials
            cannot be resolved.
    """
    try:
        session = boto3.Session(
            profile_name=profile_name,
            region_name=region_name,
        )
    except ProfileNotFound as exc:
        raise AWSSessionError(f"AWS profile '{profile_name}' not found. Check `aws configure list-profiles`.") from exc

    if not session.get_credentials():
        raise AWSSessionError(
            "No AWS credentials found. Configure a profile via `aws configure` "
            "or use SSO/instance roles. This tool does not accept raw keys."
        )

    return session


def verify_session(session: boto3.Session) -> dict[str, str]:
    """Validate the session with STS and return identity details.

    Args:
        session: The session to verify.

    Returns:
        A mapping containing ``account``, ``arn``, and ``user_id``
        describing the identity the session resolves to.

    Raises:
        AWSSessionError: If STS rejects the credentials.
    """
    try:
        identity = session.client("sts").get_caller_identity()
    except ClientError as exc:
        raise AWSSessionError(f"STS rejected credentials: {exc.response['Error']['Message']}") from exc

    logger.info("Authenticated as %s (account %s)", identity["Arn"], identity["Account"])
    return {
        "account": identity["Account"],
        "arn": identity["Arn"],
        "user_id": identity["UserId"],
    }
