"""
PrivilegeGuard — Admin (Human) Access Module
----------------------------------------------
Handles granting and revoking temporary Entra ID group membership
for human administrators. Groups are pre-assigned directory roles
but start empty — no one has the role until the gateway adds them.

Pattern:
  1. Entra security groups like "SG-Intune-Admins-ZSP" hold directory roles.
  2. Groups are empty by default → no one has the role.
  3. Admin calls /api/admin-access with justification.
  4. Gateway adds user to group temporarily via Microsoft Graph.
  5. Durable Functions timer removes them.

Requires Graph API permissions on the Function App managed identity:
  • GroupMember.ReadWrite.All
  • Directory.Read.All
  • RoleManagement.ReadWrite.Directory  (for role-assignable groups)
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from azure.identity.aio import DefaultAzureCredential

import httpx

logger = logging.getLogger("privilege-guard.admin")

GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"


async def grant_admin_access(
    user_id: str,
    group_id: str,
    duration_minutes: int,
    justification: str,
) -> dict:
    """
    Add a user to an Entra ID security group temporarily.

    The group is expected to have a directory role assignment, so adding
    the user effectively activates the role for the specified duration.

    Args:
        user_id: Entra Object ID of the human admin.
        group_id: Object ID of the target security group.
        duration_minutes: How long the membership should last.
        justification: Reason for the access request (audit trail).

    Returns:
        Dict with membership metadata.
    """
    credential = DefaultAzureCredential()
    try:
        token = await credential.get_token("https://graph.microsoft.com/.default")
        headers = {
            "Authorization": f"Bearer {token.token}",
            "Content-Type": "application/json",
        }

        # Add user as member of the group
        add_member_url = f"{GRAPH_API_BASE}/groups/{group_id}/members/$ref"
        body = {
            "@odata.id": f"{GRAPH_API_BASE}/directoryObjects/{user_id}"
        }

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(add_member_url, headers=headers, json=body)

            if response.status_code == 204:
                # Successfully added
                pass
            elif response.status_code == 400 and "already exist" in response.text.lower():
                logger.warning(
                    "User %s is already a member of group %s", user_id, group_id
                )
                return {
                    "status": "already_member",
                    "user_id": user_id,
                    "group_id": group_id,
                    "message": "User is already a member of this group.",
                }
            else:
                response.raise_for_status()

        expires_at = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)

        logger.info(
            "Admin access granted — user=%s  group=%s  expires=%s  justification=%s",
            user_id,
            group_id,
            expires_at.isoformat(),
            justification[:50],
        )

        return {
            "status": "granted",
            "user_id": user_id,
            "group_id": group_id,
            "expires_at": expires_at.isoformat(),
            "duration_minutes": duration_minutes,
            "justification": justification,
        }
    finally:
        await credential.close()


async def revoke_admin_access(user_id: str, group_id: str) -> dict:
    """
    Remove a user from an Entra ID security group.

    Args:
        user_id: Entra Object ID of the admin to remove.
        group_id: Object ID of the security group.

    Returns:
        Dict with revocation status.
    """
    credential = DefaultAzureCredential()
    try:
        token = await credential.get_token("https://graph.microsoft.com/.default")
        headers = {
            "Authorization": f"Bearer {token.token}",
        }

        remove_url = f"{GRAPH_API_BASE}/groups/{group_id}/members/{user_id}/$ref"

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.delete(remove_url, headers=headers)

            if response.status_code == 204:
                logger.info(
                    "Admin access revoked — user=%s  group=%s", user_id, group_id
                )
                return {"status": "revoked", "user_id": user_id, "group_id": group_id}
            elif response.status_code == 404:
                logger.warning(
                    "User %s already removed from group %s", user_id, group_id
                )
                return {
                    "status": "already_revoked",
                    "user_id": user_id,
                    "group_id": group_id,
                }
            else:
                response.raise_for_status()
                # Unreachable, but satisfies type checker
                return {"status": "error"}
    finally:
        await credential.close()
