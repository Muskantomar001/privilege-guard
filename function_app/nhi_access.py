"""
PrivilegeGuard — NHI (Non-Human Identity) Access Module
--------------------------------------------------------
Handles granting and revoking time-bounded Azure RBAC role assignments
for service principals, AI agents, and automation workflows.

Design principles:
  • The Function App managed identity is the ONLY identity that can
    create / delete role assignments — service principals cannot
    escalate themselves.
  • Every grant is paired with an automatic Durable Functions revocation.
  • All operations are audit-logged to ZSPAudit_CL via the audit module.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from azure.identity.aio import DefaultAzureCredential
from azure.mgmt.authorization.aio import AuthorizationManagementClient
from azure.mgmt.authorization.models import RoleAssignmentCreateParameters

from config import ROLE_DEFINITIONS

logger = logging.getLogger("privilege-guard.nhi")


async def grant_nhi_access(
    sp_object_id: str,
    scope: str,
    role_name: str,
    duration_minutes: int,
    workflow_id: str,
) -> dict:
    """
    Create a scoped, time-bounded Azure RBAC role assignment.

    Args:
        sp_object_id: Object ID of the target service principal.
        scope: Full Azure resource ID (e.g. /subscriptions/.../vaults/mykv).
        role_name: Friendly role name from the allow-list.
        duration_minutes: How long the assignment should live.
        workflow_id: Caller-supplied correlation ID for auditing.

    Returns:
        Dict with assignment metadata (status, IDs, expiry, etc.).

    Raises:
        ValueError: If the role name is not in the allow-list.
        azure.core.exceptions.HttpResponseError: On Azure SDK errors.
    """
    role_guid = ROLE_DEFINITIONS.get(role_name)
    if not role_guid:
        raise ValueError(f"Role '{role_name}' is not in the allow-list.")

    subscription_id = _extract_subscription_id(scope)
    assignment_name = str(uuid.uuid4())
    full_role_definition_id = (
        f"/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Authorization/roleDefinitions/{role_guid}"
    )

    credential = DefaultAzureCredential()
    try:
        async with AuthorizationManagementClient(
            credential, subscription_id
        ) as auth_client:
            assignment = await auth_client.role_assignments.create(
                scope=scope,
                role_assignment_name=assignment_name,
                parameters=RoleAssignmentCreateParameters(
                    role_definition_id=full_role_definition_id,
                    principal_id=sp_object_id,
                    principal_type="ServicePrincipal",
                ),
            )

        expires_at = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)

        logger.info(
            "NHI access granted — SP=%s  role=%s  scope=%s  expires=%s  workflow=%s",
            sp_object_id,
            role_name,
            scope,
            expires_at.isoformat(),
            workflow_id,
        )

        return {
            "status": "granted",
            "assignment_id": assignment.id,
            "assignment_name": assignment_name,
            "sp_object_id": sp_object_id,
            "scope": scope,
            "role": role_name,
            "expires_at": expires_at.isoformat(),
            "duration_minutes": duration_minutes,
            "workflow_id": workflow_id,
        }
    finally:
        await credential.close()


async def revoke_nhi_access(assignment_id: str) -> dict:
    """
    Delete an Azure RBAC role assignment by its full resource ID.

    Args:
        assignment_id: The full Azure resource ID of the role assignment
                       (returned in grant_nhi_access result).

    Returns:
        Dict with revocation status.
    """
    # assignment_id format:
    # /subscriptions/<sub>/providers/Microsoft.Authorization/roleAssignments/<name>
    # OR it may be scoped:
    # /subscriptions/<sub>/resourceGroups/<rg>/providers/.../roleAssignments/<name>
    subscription_id = assignment_id.split("/")[2]

    credential = DefaultAzureCredential()
    try:
        async with AuthorizationManagementClient(
            credential, subscription_id
        ) as auth_client:
            # The scope is everything before /providers/Microsoft.Authorization
            parts = assignment_id.split("/providers/Microsoft.Authorization/roleAssignments/")
            scope = parts[0]
            role_assignment_name = parts[1]

            await auth_client.role_assignments.delete(
                scope=scope,
                role_assignment_name=role_assignment_name,
            )

        logger.info("NHI access revoked — assignment_id=%s", assignment_id)

        return {"status": "revoked", "assignment_id": assignment_id}
    except Exception as exc:
        # If the assignment is already gone (e.g., manual cleanup), log & continue
        if "RoleAssignmentNotFound" in str(exc) or "404" in str(exc):
            logger.warning(
                "Role assignment already removed — assignment_id=%s", assignment_id
            )
            return {"status": "already_revoked", "assignment_id": assignment_id}
        raise
    finally:
        await credential.close()


def _extract_subscription_id(scope: str) -> str:
    """Extract subscription GUID from a full Azure resource scope string."""
    parts = scope.split("/")
    try:
        idx = parts.index("subscriptions")
        return parts[idx + 1]
    except (ValueError, IndexError):
        raise ValueError(f"Cannot extract subscription ID from scope: {scope}")
