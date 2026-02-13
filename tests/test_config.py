"""
PrivilegeGuard — Unit tests for the config / validation module.
"""

import sys
import os

# Ensure function_app is on the import path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "function_app"))

from config import (
    ROLE_DEFINITIONS,
    validate_admin_request,
    validate_duration,
    validate_nhi_request,
    validate_role,
    validate_scope,
)


# ─── validate_scope ──────────────────────────────

def test_valid_scope():
    scope = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/mykv"
    assert validate_scope(scope) is True


def test_invalid_scope_no_prefix():
    assert validate_scope("resourceGroups/rg") is False


def test_invalid_scope_empty():
    assert validate_scope("") is False


# ─── validate_role ───────────────────────────────

def test_valid_roles():
    for role in ROLE_DEFINITIONS:
        assert validate_role(role) is True


def test_invalid_role():
    assert validate_role("Super Admin") is False


# ─── validate_duration ───────────────────────────

def test_valid_duration():
    assert validate_duration(1) is True
    assert validate_duration(30) is True
    assert validate_duration(480) is True


def test_invalid_duration_too_low():
    assert validate_duration(0) is False
    assert validate_duration(-1) is False


def test_invalid_duration_too_high():
    assert validate_duration(481) is False  # default MAX is 480


# ─── validate_nhi_request ────────────────────────

def test_nhi_request_valid():
    body = {
        "sp_object_id": "00000000-0000-0000-0000-000000000000",
        "scope": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv",
        "role": "Key Vault Secrets User",
        "duration_minutes": 10,
    }
    ok, msg = validate_nhi_request(body)
    assert ok is True
    assert msg == ""


def test_nhi_request_missing_field():
    body = {
        "sp_object_id": "xyz",
        "scope": "/subscriptions/abc/resourceGroups/rg",
    }
    ok, msg = validate_nhi_request(body)
    assert ok is False
    assert "Missing required field" in msg


def test_nhi_request_bad_role():
    body = {
        "sp_object_id": "xyz",
        "scope": "/subscriptions/abc/resourceGroups/rg",
        "role": "Not A Real Role",
        "duration_minutes": 10,
    }
    ok, msg = validate_nhi_request(body)
    assert ok is False
    assert "allow-list" in msg


def test_nhi_request_bad_scope():
    body = {
        "sp_object_id": "xyz",
        "scope": "not-a-scope",
        "role": "Reader",
        "duration_minutes": 10,
    }
    ok, msg = validate_nhi_request(body)
    assert ok is False
    assert "scope" in msg.lower()


# ─── validate_admin_request ──────────────────────

def test_admin_request_valid():
    body = {
        "user_id": "abc",
        "group_id": "def",
        "duration_minutes": 15,
        "justification": "Deploying compliance policy INC0012345",
    }
    ok, msg = validate_admin_request(body)
    assert ok is True


def test_admin_request_short_justification():
    body = {
        "user_id": "abc",
        "group_id": "def",
        "duration_minutes": 15,
        "justification": "short",
    }
    ok, msg = validate_admin_request(body)
    assert ok is False
    assert "justification" in msg.lower()


def test_admin_request_missing_field():
    body = {"user_id": "abc"}
    ok, msg = validate_admin_request(body)
    assert ok is False


if __name__ == "__main__":
    # Simple runner for quick validation
    import inspect
    tests = [
        obj
        for name, obj in inspect.getmembers(sys.modules[__name__])
        if inspect.isfunction(obj) and name.startswith("test_")
    ]
    passed = 0
    failed = 0
    for test_fn in tests:
        try:
            test_fn()
            passed += 1
            print(f"  ✓ {test_fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  ✗ {test_fn.__name__}: {e}")

    print(f"\n{passed} passed, {failed} failed")
