"""
PrivilegeGuard — Azure Function App Entry Point
=================================================
Zero Standing Privilege (ZSP) Gateway for Azure.

Endpoints:
  POST /api/nhi-access    → Time-bounded RBAC role assignment for service principals
  POST /api/admin-access  → Temporary Entra group membership for human admins
  GET  /api/health        → Health check / status endpoint
  GET  /api/status/{id}   → Check revocation orchestrator status

Internals:
  Timer trigger            → Scheduled backup SP access grants
  Orchestration trigger    → Durable Functions revocation timer
  Activity triggers        → Revoke role assignment / group membership

Architecture:
  The Function App managed identity is the SOLE identity with permission to
  create/delete role assignments and manage group memberships. No service
  principal can escalate itself — all access flows through this gateway.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timedelta, timezone

import azure.durable_functions as df
import azure.functions as func

from admin_access import grant_admin_access, revoke_admin_access
from audit import log_access_event
from config import (
    get_required_env,
    validate_admin_request,
    validate_nhi_request,
)
from nhi_access import grant_nhi_access, revoke_nhi_access

# ──────────────────────────────────────────────
# App initialisation
# ──────────────────────────────────────────────
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)
logger = logging.getLogger("privilege-guard")


# ═══════════════════════════════════════════════
# HTTP TRIGGERS
# ═══════════════════════════════════════════════


@app.route(route="nhi-access", methods=["POST"])
@app.durable_client_input(client_name="client")
async def nhi_access_handler(req: func.HttpRequest, client) -> func.HttpResponse:
    """
    Grant time-bounded Azure RBAC role assignment to a service principal.

    Request body:
    {
        "sp_object_id": "<object-id>",
        "scope": "/subscriptions/.../providers/Microsoft.KeyVault/vaults/<name>",
        "role": "Key Vault Secrets User",
        "duration_minutes": 10,
        "workflow_id": "nightly-backup"
    }
    """
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body."}),
            status_code=400,
            mimetype="application/json",
        )

    # Validate request
    ok, error_msg = validate_nhi_request(body)
    if not ok:
        return func.HttpResponse(
            json.dumps({"error": error_msg}),
            status_code=400,
            mimetype="application/json",
        )

    try:
        # Grant the role assignment
        result = await grant_nhi_access(
            sp_object_id=body["sp_object_id"],
            scope=body["scope"],
            role_name=body["role"],
            duration_minutes=int(body["duration_minutes"]),
            workflow_id=body.get("workflow_id", "api-request"),
        )

        # Audit log the grant
        await log_access_event(
            event_type="AccessGrant",
            identity_type="nhi",
            principal_id=body["sp_object_id"],
            target=body["scope"],
            target_type="AzureResource",
            role=body["role"],
            duration_minutes=int(body["duration_minutes"]),
            workflow_id=body.get("workflow_id", "api-request"),
            expires_at=result["expires_at"],
            result="Success",
        )

        # Schedule automatic revocation via Durable Functions
        expiry_time = datetime.now(timezone.utc) + timedelta(
            minutes=int(body["duration_minutes"])
        )
        instance_id = await client.start_new(
            "revocation_orchestrator",
            client_input={
                "revocation_type": "role_assignment",
                "assignment_id": result["assignment_id"],
                "sp_object_id": body["sp_object_id"],
                "scope": body["scope"],
                "role": body["role"],
                "expiry_time": expiry_time.isoformat(),
                "workflow_id": body.get("workflow_id", "api-request"),
            },
        )

        result["orchestrator_instance_id"] = instance_id

        return func.HttpResponse(
            json.dumps(result, default=str),
            status_code=200,
            mimetype="application/json",
        )

    except Exception as exc:
        logger.exception("NHI access grant failed")

        # Audit log the failure
        await log_access_event(
            event_type="AccessGrant",
            identity_type="nhi",
            principal_id=body.get("sp_object_id", "unknown"),
            target=body.get("scope", "unknown"),
            target_type="AzureResource",
            role=body.get("role"),
            result="Failure",
        )

        return func.HttpResponse(
            json.dumps({"error": "Access grant failed. Check gateway logs."}),
            status_code=500,
            mimetype="application/json",
        )


@app.route(route="admin-access", methods=["POST"])
@app.durable_client_input(client_name="client")
async def admin_access_handler(req: func.HttpRequest, client) -> func.HttpResponse:
    """
    Grant temporary Entra ID group membership to a human admin.

    Request body:
    {
        "user_id": "<entra-object-id>",
        "group_id": "<security-group-object-id>",
        "duration_minutes": 15,
        "justification": "Deploying compliance policy - INC0012345"
    }
    """
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body."}),
            status_code=400,
            mimetype="application/json",
        )

    ok, error_msg = validate_admin_request(body)
    if not ok:
        return func.HttpResponse(
            json.dumps({"error": error_msg}),
            status_code=400,
            mimetype="application/json",
        )

    try:
        result = await grant_admin_access(
            user_id=body["user_id"],
            group_id=body["group_id"],
            duration_minutes=int(body["duration_minutes"]),
            justification=body["justification"],
        )

        # Audit log the grant
        await log_access_event(
            event_type="AccessGrant",
            identity_type="admin",
            principal_id=body["user_id"],
            target=body["group_id"],
            target_type="EntraGroup",
            duration_minutes=int(body["duration_minutes"]),
            expires_at=result.get("expires_at"),
            result="Success",
            justification=body["justification"],
        )

        # Schedule revocation (unless user was already a member)
        if result["status"] == "granted":
            expiry_time = datetime.now(timezone.utc) + timedelta(
                minutes=int(body["duration_minutes"])
            )
            instance_id = await client.start_new(
                "revocation_orchestrator",
                client_input={
                    "revocation_type": "group_membership",
                    "user_id": body["user_id"],
                    "group_id": body["group_id"],
                    "expiry_time": expiry_time.isoformat(),
                    "justification": body["justification"],
                },
            )
            result["orchestrator_instance_id"] = instance_id

        return func.HttpResponse(
            json.dumps(result, default=str),
            status_code=200,
            mimetype="application/json",
        )

    except Exception as exc:
        logger.exception("Admin access grant failed")

        await log_access_event(
            event_type="AccessGrant",
            identity_type="admin",
            principal_id=body.get("user_id", "unknown"),
            target=body.get("group_id", "unknown"),
            target_type="EntraGroup",
            result="Failure",
            justification=body.get("justification"),
        )

        return func.HttpResponse(
            json.dumps({"error": "Access grant failed. Check gateway logs."}),
            status_code=500,
            mimetype="application/json",
        )


@app.route(route="health", methods=["GET"])
async def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """Health check endpoint — returns gateway status and configuration summary."""
    return func.HttpResponse(
        json.dumps({
            "status": "healthy",
            "service": "PrivilegeGuard ZSP Gateway",
            "version": "1.0.0",
            "features": {
                "nhi_access": True,
                "admin_access": True,
                "audit_logging": bool(os.getenv("DCE_ENDPOINT")),
                "scheduled_backup": bool(os.getenv("BACKUP_JOB_SCHEDULE")),
            },
        }),
        mimetype="application/json",
    )


@app.route(route="status/{instance_id}", methods=["GET"])
@app.durable_client_input(client_name="client")
async def orchestrator_status(req: func.HttpRequest, client) -> func.HttpResponse:
    """Check the status of a revocation orchestrator instance."""
    instance_id = req.route_params.get("instance_id")
    if not instance_id:
        return func.HttpResponse(
            json.dumps({"error": "instance_id is required."}),
            status_code=400,
            mimetype="application/json",
        )

    status = await client.get_status(instance_id)
    if not status:
        return func.HttpResponse(
            json.dumps({"error": "Orchestrator instance not found."}),
            status_code=404,
            mimetype="application/json",
        )

    return func.HttpResponse(
        json.dumps({
            "instance_id": status.instance_id,
            "runtime_status": status.runtime_status.value if status.runtime_status else "Unknown",
            "created_time": str(status.created_time) if status.created_time else None,
            "last_updated_time": str(status.last_updated_time) if status.last_updated_time else None,
            "output": status.output,
        }),
        mimetype="application/json",
    )


# ═══════════════════════════════════════════════
# TIMER TRIGGER — Scheduled Backup Access
# ═══════════════════════════════════════════════


@app.timer_trigger(
    schedule="%BACKUP_JOB_SCHEDULE%",
    arg_name="timer",
    run_on_startup=False,
)
@app.durable_client_input(client_name="client")
async def backup_job_access_grant(timer: func.TimerRequest, client):
    """
    Grant backup SP access before the nightly job runs.

    Grants Key Vault + Storage access for the configured duration,
    then schedules automatic revocation for both.
    """
    try:
        backup_sp_id = get_required_env("BACKUP_SP_OBJECT_ID")
        kv_resource_id = get_required_env("KEYVAULT_RESOURCE_ID")
        storage_resource_id = get_required_env("STORAGE_RESOURCE_ID")
        duration = int(os.environ.get("BACKUP_JOB_DURATION_MINUTES", "35"))

        # Grant Key Vault access
        kv_result = await grant_nhi_access(
            sp_object_id=backup_sp_id,
            scope=kv_resource_id,
            role_name="Key Vault Secrets User",
            duration_minutes=duration,
            workflow_id="nightly-backup",
        )

        await log_access_event(
            event_type="AccessGrant",
            identity_type="nhi",
            principal_id=backup_sp_id,
            target=kv_resource_id,
            target_type="AzureResource",
            role="Key Vault Secrets User",
            duration_minutes=duration,
            workflow_id="nightly-backup",
            expires_at=kv_result["expires_at"],
            result="Success",
        )

        # Grant Storage access
        stor_result = await grant_nhi_access(
            sp_object_id=backup_sp_id,
            scope=storage_resource_id,
            role_name="Storage Blob Data Contributor",
            duration_minutes=duration,
            workflow_id="nightly-backup",
        )

        await log_access_event(
            event_type="AccessGrant",
            identity_type="nhi",
            principal_id=backup_sp_id,
            target=storage_resource_id,
            target_type="AzureResource",
            role="Storage Blob Data Contributor",
            duration_minutes=duration,
            workflow_id="nightly-backup",
            expires_at=stor_result["expires_at"],
            result="Success",
        )

        # Schedule revocations
        expiry_time = datetime.now(timezone.utc) + timedelta(minutes=duration)

        for result, scope, role in [
            (kv_result, kv_resource_id, "Key Vault Secrets User"),
            (stor_result, storage_resource_id, "Storage Blob Data Contributor"),
        ]:
            await client.start_new(
                "revocation_orchestrator",
                client_input={
                    "revocation_type": "role_assignment",
                    "assignment_id": result["assignment_id"],
                    "sp_object_id": backup_sp_id,
                    "scope": scope,
                    "role": role,
                    "expiry_time": expiry_time.isoformat(),
                    "workflow_id": "nightly-backup",
                },
            )

        logger.info(
            "Backup job access granted — KV + Storage for %d minutes", duration
        )

    except Exception:
        logger.exception("Backup job access grant failed")


# ═══════════════════════════════════════════════
# DURABLE FUNCTIONS — Revocation Orchestrator
# ═══════════════════════════════════════════════


@app.orchestration_trigger(context_name="context")
def revocation_orchestrator(context: df.DurableOrchestrationContext):
    """
    Wait until expiry time, then revoke the access grant.

    Uses an absolute expiry_time (not relative delay) so the timer
    is deterministic even if the orchestrator replays — a core
    Durable Functions requirement.

    Durable Functions timers survive Function App restarts and
    scale-to-zero — more reliable than in-memory timers.

    Note: Python Durable Functions timers have a max duration of 6 days.
    """
    input_data = context.get_input()

    # Wait until the absolute expiry time
    expiry_time = datetime.fromisoformat(input_data["expiry_time"]).replace(
        tzinfo=timezone.utc
    )
    yield context.create_timer(expiry_time)

    # Dispatch to the correct revocation activity
    if input_data["revocation_type"] == "group_membership":
        yield context.call_activity(
            "revoke_group_membership_activity", input_data
        )
    elif input_data["revocation_type"] == "role_assignment":
        yield context.call_activity(
            "revoke_role_assignment_activity", input_data
        )

    return {
        "status": "revoked",
        "revocation_type": input_data["revocation_type"],
        "completed_at": context.current_utc_datetime.isoformat(),
    }


# ═══════════════════════════════════════════════
# DURABLE FUNCTIONS — Revocation Activities
# ═══════════════════════════════════════════════
# Activity functions run in a sync thread pool — they use
# asyncio.new_event_loop() to call the async SDK methods.
# input_name="activityPayload" with type str is required because
# the .NET host serialises input as a JSON string.


@app.activity_trigger(input_name="activityPayload")
def revoke_role_assignment_activity(activityPayload: str):
    """Revoke an Azure RBAC role assignment and log the event."""
    input_data = (
        json.loads(activityPayload)
        if isinstance(activityPayload, str)
        else activityPayload
    )

    loop = asyncio.new_event_loop()
    try:
        # Revoke the role assignment
        loop.run_until_complete(
            revoke_nhi_access(assignment_id=input_data["assignment_id"])
        )

        # Audit log the revocation
        loop.run_until_complete(
            log_access_event(
                event_type="AccessRevoke",
                identity_type="nhi",
                principal_id=input_data["sp_object_id"],
                target=input_data["scope"],
                target_type="AzureResource",
                role=input_data.get("role"),
                result="Success",
                workflow_id=input_data.get("workflow_id"),
            )
        )
    except Exception:
        logger.exception("Role assignment revocation failed")
        loop.run_until_complete(
            log_access_event(
                event_type="AccessRevoke",
                identity_type="nhi",
                principal_id=input_data.get("sp_object_id", "unknown"),
                target=input_data.get("scope", "unknown"),
                target_type="AzureResource",
                role=input_data.get("role"),
                result="Failure",
                workflow_id=input_data.get("workflow_id"),
            )
        )
    finally:
        loop.close()

    return {"status": "revoked"}


@app.activity_trigger(input_name="activityPayload")
def revoke_group_membership_activity(activityPayload: str):
    """Revoke Entra group membership and log the event."""
    input_data = (
        json.loads(activityPayload)
        if isinstance(activityPayload, str)
        else activityPayload
    )

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(
            revoke_admin_access(
                user_id=input_data["user_id"],
                group_id=input_data["group_id"],
            )
        )

        loop.run_until_complete(
            log_access_event(
                event_type="AccessRevoke",
                identity_type="admin",
                principal_id=input_data["user_id"],
                target=input_data["group_id"],
                target_type="EntraGroup",
                result="Success",
                justification=input_data.get("justification"),
            )
        )
    except Exception:
        logger.exception("Group membership revocation failed")
        loop.run_until_complete(
            log_access_event(
                event_type="AccessRevoke",
                identity_type="admin",
                principal_id=input_data.get("user_id", "unknown"),
                target=input_data.get("group_id", "unknown"),
                target_type="EntraGroup",
                result="Failure",
                justification=input_data.get("justification"),
            )
        )
    finally:
        loop.close()

    return {"status": "revoked"}
