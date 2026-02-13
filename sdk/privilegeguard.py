"""
PrivilegeGuard Python SDK
-------------------------
Drop this single file into any Python project to integrate with PrivilegeGuard.

Usage:
    from privilegeguard import request_access

    # Before your job needs Key Vault access:
    await request_access("Key Vault Secrets User", KEYVAULT_SCOPE, duration_minutes=10)

    # Now do your work — access auto-revokes after 10 minutes.
    secret = kv_client.get_secret("my-secret")

Environment variables (set once):
    PRIVGUARD_URL  — Gateway URL (e.g., https://privguard-xyz.azurewebsites.net)
    PRIVGUARD_KEY  — Function key for authentication

That's it. No other config needed.
"""

import os
import httpx

_URL = os.environ.get("PRIVGUARD_URL", "")
_KEY = os.environ.get("PRIVGUARD_KEY", "")


async def request_access(
    role: str,
    scope: str,
    duration_minutes: int = 10,
    sp_object_id: str | None = None,
    workflow_id: str = "sdk-request",
) -> dict:
    """
    Request temporary access from PrivilegeGuard.

    Args:
        role: Azure role name (e.g., "Key Vault Secrets User")
        scope: Full Azure resource ID
        duration_minutes: How long you need access (default 10)
        sp_object_id: Your service principal's Object ID.
                      Auto-detected from managed identity if not provided.
        workflow_id: Optional label for audit trail

    Returns:
        Grant response dict with status, expires_at, etc.
    """
    if not _URL or not _KEY:
        raise RuntimeError(
            "Set PRIVGUARD_URL and PRIVGUARD_KEY environment variables."
        )

    if not sp_object_id:
        sp_object_id = await _get_my_identity()

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{_URL}/api/nhi-access",
            headers={
                "Content-Type": "application/json",
                "x-functions-key": _KEY,
            },
            json={
                "sp_object_id": sp_object_id,
                "scope": scope,
                "role": role,
                "duration_minutes": duration_minutes,
                "workflow_id": workflow_id,
            },
        )
        resp.raise_for_status()
        return resp.json()


async def _get_my_identity() -> str:
    """Auto-detect this app's managed identity Object ID via Azure IMDS."""
    async with httpx.AsyncClient(timeout=5) as client:
        resp = await client.get(
            "http://169.254.169.254/metadata/identity/oauth2/token",
            params={
                "api-version": "2019-08-01",
                "resource": "https://management.azure.com/",
            },
            headers={"Metadata": "true"},
        )
        resp.raise_for_status()
        import jwt  # PyJWT — already in most Azure SDKs
        token = resp.json()["access_token"]
        claims = jwt.decode(token, options={"verify_signature": False})
        return claims["oid"]
