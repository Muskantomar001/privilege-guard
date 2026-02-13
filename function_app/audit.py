"""
PrivilegeGuard — Audit Logging Module
---------------------------------------
Sends structured audit events to Azure Monitor Logs (ZSPAudit_CL table)
via the Azure Monitor Ingestion API using a Data Collection Endpoint (DCE)
and Data Collection Rule (DCR).

Every grant and revocation produces a log entry containing:
  • EventType (AccessGrant / AccessRevoke)
  • IdentityType (nhi / admin)
  • PrincipalId, Target, TargetType, Role
  • DurationMinutes, WorkflowId, ExpiresAt
  • Result (Success / Failure)
  • Justification (admin-only)

These logs power KQL queries for anomaly detection, compliance
reporting, and incident investigation.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from azure.identity.aio import DefaultAzureCredential
from azure.monitor.ingestion.aio import LogsIngestionClient

logger = logging.getLogger("privilege-guard.audit")


async def log_access_event(
    event_type: str,
    identity_type: str,
    principal_id: str,
    target: str,
    target_type: str,
    role: str | None = None,
    duration_minutes: int | None = None,
    workflow_id: str | None = None,
    expires_at: str | None = None,
    result: str = "Success",
    justification: str | None = None,
) -> None:
    """
    Send a structured audit event to the ZSPAudit_CL Log Analytics table.

    Uses the Azure Monitor Ingestion API (DCE + DCR) to deliver events.
    Failures are logged but never propagated — audit should not block
    the access grant/revoke path.

    Args:
        event_type: "AccessGrant" or "AccessRevoke".
        identity_type: "nhi" or "admin".
        principal_id: Object ID of the service principal or user.
        target: Full resource ID or group ID.
        target_type: "AzureResource" or "EntraGroup".
        role: Role name granted / revoked (NHI path).
        duration_minutes: Requested duration (grant only).
        workflow_id: Caller-supplied correlation ID.
        expires_at: ISO-format expiry timestamp (grant only).
        result: "Success" or "Failure".
        justification: Reason for access (admin path).
    """
    dce_endpoint = os.getenv("DCE_ENDPOINT")
    dcr_rule_id = os.getenv("DCR_RULE_ID")
    dcr_stream_name = os.getenv("DCR_STREAM_NAME", "Custom-ZSPAudit_CL")

    if not dce_endpoint or not dcr_rule_id:
        logger.warning(
            "Audit logging skipped — DCE_ENDPOINT or DCR_RULE_ID not configured."
        )
        return

    log_entry = {
        "TimeGenerated": datetime.now(timezone.utc).isoformat(),
        "EventType": event_type,
        "IdentityType": identity_type,
        "PrincipalId": principal_id,
        "Target": target,
        "TargetType": target_type,
        "Role": role or "",
        "DurationMinutes": duration_minutes or 0,
        "WorkflowId": workflow_id or "",
        "ExpiresAt": expires_at or "",
        "Result": result,
        "Justification": justification or "",
    }

    credential = DefaultAzureCredential()
    try:
        async with LogsIngestionClient(
            endpoint=dce_endpoint, credential=credential
        ) as client:
            await client.upload(
                rule_id=dcr_rule_id,
                stream_name=dcr_stream_name,
                logs=[log_entry],
            )
        logger.info(
            "Audit event sent — type=%s  identity=%s  principal=%s  result=%s",
            event_type,
            identity_type,
            principal_id,
            result,
        )
    except Exception:
        # Audit failures must NEVER block the access grant/revoke path
        logger.exception("Failed to send audit event — continuing without audit log.")
    finally:
        await credential.close()
