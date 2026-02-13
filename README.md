# PrivilegeGuard

**Zero Standing Privilege Gateway for Azure**

Eliminates 24/7 standing access for AI agents, automation, and service principals. Access is granted just-in-time, scoped to specific resources, and automatically revoked.

---

## Quick Start

### Prerequisites

- Azure subscription with **Owner** access
- Azure CLI logged in (`az login`)
- Azure Functions Core Tools v4 (`func --version`)
- Python 3.11+

### Step 1: Deploy (one command)

```powershell
git clone <your-repo-url>
cd privilege-guard
powershell -ExecutionPolicy Bypass -File scripts/Setup-Gateway.ps1
```

This single command:
- Creates all Azure infrastructure (Function App, Key Vault, Storage, Log Analytics, audit pipeline)
- Grants the gateway **subscription-level** User Access Administrator (can manage roles on any resource group)
- Grants Microsoft Graph API permissions (for admin group management)
- Deploys the gateway code
- Outputs your **Gateway URL** and **Function Key**

### Step 2: Integrate (2 env vars + 1 line of code)

Add these environment variables to your app (Azure Portal > Your App > Configuration):

```
PRIVGUARD_URL = <Gateway URL from Step 1>
PRIVGUARD_KEY = <Function Key from Step 1>
```

Drop [`sdk/privilegeguard.py`](sdk/privilegeguard.py) into your project, then add one line before any code that needs Azure access:

```python
from privilegeguard import request_access

# One line. That's the entire integration.
# Change the role based on what your job needs:
await request_access("Key Vault Secrets User", KEYVAULT_RESOURCE_ID, duration_minutes=10)

# Your existing code works unchanged - access auto-revokes after 10 minutes
secret = kv_client.get_secret("openai-api-key")
```

**Use the role that matches your job:**

| Your job needs to... | Role |
|---|---|
| Read secrets from Key Vault | `Key Vault Secrets User` |
| Read + write secrets | `Key Vault Secrets Officer` |
| Read blobs from Storage | `Storage Blob Data Reader` |
| Write blobs to Storage | `Storage Blob Data Contributor` |
| Read any Azure resource metadata | `Reader` |
| Deploy/modify Azure resources | `Contributor` |
| Read Key Vault keys (encryption) | `Key Vault Crypto User` |
| View monitoring data | `Monitoring Reader` |

If your job needs multiple resources, make multiple calls:

```python
from privilegeguard import request_access

# AI agent that reads a secret and writes results to storage
await request_access("Key Vault Secrets User", KEYVAULT_SCOPE, duration_minutes=10)
await request_access("Storage Blob Data Contributor", STORAGE_SCOPE, duration_minutes=10)

# Both roles are now active - auto-revoke after 10 minutes
secret = kv_client.get_secret("openai-api-key")
blob_client.upload_blob(result_data)
```

> The allow-list of roles is defined in [`function_app/config.py`](function_app/config.py) (`ROLE_DEFINITIONS`). To support additional roles, add the role name and its Azure GUID there.

### Step 3: Remove standing privileges from your service principal

```bash
# Strip the 24/7 access - PrivilegeGuard handles it on-demand now
az role assignment delete \
  --assignee <your-sp-object-id> \
  --role "Key Vault Secrets User" \
  --scope <your-keyvault-resource-id>
```

**Done.** Your agent now has zero standing access. It requests what it needs, uses it, and the gateway auto-revokes.

---

## How It Works

```
Your Agent                    PrivilegeGuard Gateway              Azure RBAC
    |                                |                                |
    |-- POST /api/nhi-access ------->|                                |
    |   (role, scope, duration)      |-- Create role assignment ----->|
    |                                |-- Schedule revocation timer    |
    |<-- { status: "granted" } ------|                                |
    |                                |                                |
    |-- (does its work) -------------|--------- (has access) -------->|
    |                                |                                |
    |   (duration expires)           |                                |
    |                                |-- Delete role assignment ----->|
    |                                |-- Log to ZSPAudit_CL          |
    |                                |                                |
    |-- (zero access again) ---------|--------- (403 Forbidden) ---->|
```

## API

### `POST /api/nhi-access`

Grant temporary role to a service principal.

```json
{
  "sp_object_id": "your-sp-object-id",
  "scope": "/subscriptions/.../providers/Microsoft.KeyVault/vaults/my-kv",
  "role": "Key Vault Secrets User",
  "duration_minutes": 10,
  "workflow_id": "my-agent-job"
}
```

**Allowed roles:** Key Vault Secrets User, Key Vault Secrets Officer, Key Vault Reader, Key Vault Crypto User, Storage Blob Data Reader, Storage Blob Data Contributor, Reader, Contributor, Monitoring Reader, Log Analytics Reader.

### `POST /api/admin-access`

Grant temporary Entra group membership to a human admin.

```json
{
  "user_id": "user-object-id",
  "group_id": "security-group-id",
  "duration_minutes": 15,
  "justification": "Deploying compliance policy - INC0012345"
}
```

### `GET /api/health`

Gateway health check.

### `GET /api/status/{instance_id}`

Check revocation timer status.

## SDK

The Python SDK ([`sdk/privilegeguard.py`](sdk/privilegeguard.py)) is a single file, zero extra dependencies. Drop it into any project.

```python
from privilegeguard import request_access

# Get Key Vault access for 10 minutes
await request_access("Key Vault Secrets User", KV_SCOPE)

# Get Storage access for 30 minutes with custom workflow ID
await request_access("Storage Blob Data Contributor", STORAGE_SCOPE, 
                     duration_minutes=30, workflow_id="nightly-backup")
```

Or skip the SDK entirely and use one HTTP call:

```python
httpx.post(f"{GATEWAY}/api/nhi-access", 
    headers={"x-functions-key": KEY, "Content-Type": "application/json"},
    json={"sp_object_id": SP_ID, "scope": SCOPE, "role": ROLE, 
          "duration_minutes": 10, "workflow_id": "my-job"})
```

## Audit Trail

Every grant and revocation is logged to `ZSPAudit_CL` in Log Analytics.

```kql
// All NHI grants in the last 24 hours
ZSPAudit_CL
| where TimeGenerated > ago(24h)
| where EventType == "AccessGrant"
| project TimeGenerated, PrincipalId, Target, Role, DurationMinutes, WorkflowId
| order by TimeGenerated desc
```

## Project Structure

```
privilege-guard/
  function_app/          # Azure Function App (Python)
    function_app.py      # All triggers, orchestrators, endpoints
    nhi_access.py        # RBAC grant/revoke logic
    admin_access.py      # Entra group membership logic
    audit.py             # Log Analytics audit logging
    config.py            # Config, validation, role allow-list
    host.json            # Function host config
    requirements.txt     # Python dependencies
  sdk/                   # Drop-in SDK for end users
    privilegeguard.py    # Single-file Python SDK
  infra/                 # Infrastructure as Code
    main.bicep           # Complete Bicep template
  scripts/               # Deployment automation
    Setup-Gateway.ps1    # One-command setup
    Remove-Gateway.ps1   # Teardown
  dashboard/             # Visual testing UI
    index.html           # Static HTML dashboard
  tests/
    test_config.py       # Unit tests
```

## Cleanup

```powershell
powershell -ExecutionPolicy Bypass -File scripts/Remove-Gateway.ps1 -Force
```

## Security Design

- **Gateway pattern** — one identity controls all role assignments, no self-escalation
- **Subscription-level authority** — gateway manages roles across all resource groups
- **Time-bounded** — every grant has an automatic Durable Functions revocation timer
- **Audit trail** — every grant/revoke logged with workflow correlation IDs
- **Role allow-list** — only pre-approved roles can be granted
- **Duration limits** — 1-480 minutes, configurable max

---

Built by [Muskan Tomar](https://github.com/muskantomar)
