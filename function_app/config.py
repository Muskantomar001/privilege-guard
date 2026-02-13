"""
PrivilegeGuard — Configuration & Constants
-------------------------------------------
Centralises environment variable loading, role-definition look-ups,
and validation helpers so every module shares one source of truth.
"""

from __future__ import annotations

import os
from typing import Final

# ──────────────────────────────────────────────
# Azure built-in role definition GUIDs
# Reference: https://learn.microsoft.com/azure/role-based-access-control/built-in-roles
# ──────────────────────────────────────────────
ROLE_DEFINITIONS: Final[dict[str, str]] = {
    "Key Vault Secrets User": "4633458b-17de-408a-b874-0445c86b69e6",
    "Key Vault Secrets Officer": "b86a8fe4-44ce-4948-aee5-eccb2c155cd7",
    "Key Vault Reader": "21090545-7ca7-4776-b22c-e363652d74d2",
    "Key Vault Crypto User": "12338af0-0e69-4776-bea7-57ae8d297424",
    "Storage Blob Data Reader": "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1",
    "Storage Blob Data Contributor": "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
    "Reader": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
    "Contributor": "b24988ac-6180-42a0-ab88-20f7382dd24c",
    "Monitoring Reader": "43d0d8ad-25c7-4714-9337-8ba259a9fe05",
    "Log Analytics Reader": "73c42c96-874c-492b-b04d-ab87d138a893",
}

# Maximum access duration (minutes) — safety guardrail
MAX_DURATION_MINUTES: Final[int] = int(os.getenv("MAX_DURATION_MINUTES", "480"))  # 8 hours

# Minimum access duration
MIN_DURATION_MINUTES: Final[int] = 1


def get_required_env(key: str) -> str:
    """Return an environment variable or raise with a clear message."""
    value = os.getenv(key)
    if not value:
        raise EnvironmentError(f"Required environment variable '{key}' is not set.")
    return value


def get_optional_env(key: str, default: str = "") -> str:
    """Return an environment variable with a fallback."""
    return os.getenv(key, default)


# ──────────────────────────────────────────────
# Validation helpers
# ──────────────────────────────────────────────

def validate_scope(scope: str) -> bool:
    """Verify scope looks like an Azure resource ID."""
    return scope.startswith("/subscriptions/") and len(scope.split("/")) >= 3


def validate_role(role_name: str) -> bool:
    """Check role name is in the allow-list."""
    return role_name in ROLE_DEFINITIONS


def validate_duration(minutes: int) -> bool:
    """Ensure duration is within bounds."""
    return MIN_DURATION_MINUTES <= minutes <= MAX_DURATION_MINUTES


def validate_nhi_request(body: dict) -> tuple[bool, str]:
    """Validate an NHI access request body. Returns (ok, error_message)."""
    required_fields = ["sp_object_id", "scope", "role", "duration_minutes"]
    for field in required_fields:
        if field not in body:
            return False, f"Missing required field: {field}"

    if not validate_scope(body["scope"]):
        return False, "Invalid scope format. Must be a full Azure resource ID."

    if not validate_role(body["role"]):
        allowed = ", ".join(sorted(ROLE_DEFINITIONS.keys()))
        return False, f"Role '{body['role']}' not in allow-list. Allowed: {allowed}"

    if not isinstance(body["duration_minutes"], (int, float)):
        return False, "duration_minutes must be a number."

    if not validate_duration(int(body["duration_minutes"])):
        return False, (
            f"duration_minutes must be between {MIN_DURATION_MINUTES} "
            f"and {MAX_DURATION_MINUTES}."
        )

    return True, ""


def validate_admin_request(body: dict) -> tuple[bool, str]:
    """Validate an admin access request body. Returns (ok, error_message)."""
    required_fields = ["user_id", "group_id", "duration_minutes", "justification"]
    for field in required_fields:
        if field not in body:
            return False, f"Missing required field: {field}"

    if not isinstance(body["duration_minutes"], (int, float)):
        return False, "duration_minutes must be a number."

    if not validate_duration(int(body["duration_minutes"])):
        return False, (
            f"duration_minutes must be between {MIN_DURATION_MINUTES} "
            f"and {MAX_DURATION_MINUTES}."
        )

    justification = body.get("justification", "").strip()
    if len(justification) < 10:
        return False, "Justification must be at least 10 characters."

    return True, ""
