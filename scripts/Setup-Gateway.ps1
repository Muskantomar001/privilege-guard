<#
.SYNOPSIS
    PrivilegeGuard - One-command gateway setup.

.DESCRIPTION
    Deploys the complete PrivilegeGuard ZSP Gateway:
      Step 1 - Create Resource Group
      Step 2 - Deploy infrastructure via Bicep
      Step 3 - Grant subscription-level User Access Administrator
      Step 4 - Grant Microsoft Graph API permissions
      Step 5 - Create demo backup service principal (zero permissions)
      Step 6 - Configure Function App settings
      Step 7 - Deploy Function App code
      Step 8 - Smoke test

.PARAMETER ProjectName
    Short prefix for all resource names (2-12 chars). Default: "privguard"

.PARAMETER Location
    Azure region. Default: "centralindia"

.EXAMPLE
    ./Setup-Gateway.ps1
    ./Setup-Gateway.ps1 -ProjectName "privguard" -Location "centralindia"
#>

[CmdletBinding()]
param(
    [ValidateLength(2, 12)]
    [string]$ProjectName = "privguard",
    [string]$Location = "centralindia",
    [string]$SubscriptionId = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Step { param([string]$Num, [string]$Msg); Write-Host ""; Write-Host "[$Num] $Msg" -ForegroundColor Cyan }
function Write-OK { param([string]$Msg); Write-Host "    OK: $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg); Write-Host "    !! $Msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "================================================" -ForegroundColor Magenta
Write-Host "  PrivilegeGuard - ZSP Gateway Setup" -ForegroundColor Magenta
Write-Host "================================================" -ForegroundColor Magenta

# --- Pre-flight ---
if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw "Azure CLI not installed. https://aka.ms/installazurecli" }
$account = az account show 2>&1 | ConvertFrom-Json
if (-not $account) { throw "Run 'az login' first." }
if ($SubscriptionId) { az account set --subscription $SubscriptionId; $account = az account show | ConvertFrom-Json }
$subId = $account.id
Write-OK "Logged in - Subscription: $subId"

$rgName = "$ProjectName-zsp-rg"

# -------------------------------------------------
# STEP 1 - Resource Group
# -------------------------------------------------
Write-Step "1/8" "Creating Resource Group: $rgName"
az group create --name $rgName --location $Location --output none
Write-OK "Resource Group ready"

# -------------------------------------------------
# STEP 2 - Deploy Bicep (infra)
# -------------------------------------------------
Write-Step "2/8" "Deploying infrastructure (Bicep)"
$bicepPath = Join-Path (Join-Path $PSScriptRoot "..") "infra"
$bicepPath = Join-Path $bicepPath "main.bicep"

$deployment = az deployment group create `
    --resource-group $rgName `
    --template-file $bicepPath `
    --parameters projectName=$ProjectName `
    --query "properties.outputs" `
    --output json | ConvertFrom-Json

$functionAppName = $deployment.functionAppName.value
$principalId     = $deployment.functionAppPrincipalId.value
$kvName          = $deployment.keyVaultName.value
$kvId            = $deployment.keyVaultResourceId.value
$storageId       = $deployment.storageResourceId.value

Write-OK "Function App:  $functionAppName"
Write-OK "Key Vault:     $kvName"

# -------------------------------------------------
# STEP 3 - Subscription-level RBAC
# -------------------------------------------------
Write-Step "3/8" "Granting User Access Administrator at SUBSCRIPTION level"
az role assignment create `
    --assignee $principalId `
    --role "User Access Administrator" `
    --scope "/subscriptions/$subId" `
    --output none 2>$null
Write-OK "Gateway can now manage role assignments on ANY resource group"

# -------------------------------------------------
# STEP 4 - Graph API permissions
# -------------------------------------------------
Write-Step "4/8" "Granting Microsoft Graph API permissions"
$graphAppId = "00000003-0000-0000-c000-000000000000"
$graphSp = az ad sp show --id $graphAppId --query "id" -o tsv

$permissions = @("GroupMember.ReadWrite.All", "Directory.Read.All", "RoleManagement.ReadWrite.Directory")
foreach ($perm in $permissions) {
    $roleId = az ad sp show --id $graphAppId --query "appRoles[?value=='$perm'].id" -o tsv
    if ($roleId) {
        $body = @{ principalId = $principalId; resourceId = $graphSp; appRoleId = $roleId } | ConvertTo-Json
        $tmp = [System.IO.Path]::GetTempFileName()
        $body | Out-File $tmp -Encoding utf8
        az rest --method POST `
            --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphSp/appRoleAssignments" `
            --headers "Content-Type=application/json" `
            --body "@$tmp" --output none 2>$null
        Remove-Item $tmp -ErrorAction SilentlyContinue
        Write-OK $perm
    } else {
        Write-Warn "Skipped $perm (role not found)"
    }
}

# -------------------------------------------------
# STEP 5 - Demo backup service principal
# -------------------------------------------------
Write-Step "5/8" "Creating demo backup SP (zero permissions)"
$spName = "$ProjectName-backup-sp"
$existingSp = az ad sp list --display-name $spName --query "[0].appId" -o tsv 2>$null
if ($existingSp) {
    $backupSpOid = az ad sp show --id $existingSp --query "id" -o tsv
    Write-Warn "SP already exists: $spName"
} else {
    $sp = az ad sp create-for-rbac --name $spName --skip-assignment --output json 2>$null | ConvertFrom-Json
    $backupSpOid = az ad sp show --id $sp.appId --query "id" -o tsv
    Write-OK "Created: $spName (zero roles)"
}

# -------------------------------------------------
# STEP 6 - Function App settings
# -------------------------------------------------
Write-Step "6/8" "Configuring Function App"
az functionapp config appsettings set `
    --name $functionAppName --resource-group $rgName `
    --settings "BACKUP_SP_OBJECT_ID=$backupSpOid" `
    --output none 2>$null
Write-OK "Settings configured"

# -------------------------------------------------
# STEP 7 - Deploy code
# -------------------------------------------------
Write-Step "7/8" "Deploying Function App code"
$codePath = Join-Path (Join-Path $PSScriptRoot "..") "function_app"
Push-Location $codePath
try { func azure functionapp publish $functionAppName --python } finally { Pop-Location }
Write-OK "Code deployed"

# -------------------------------------------------
# STEP 8 - Smoke test
# -------------------------------------------------
Write-Step "8/8" "Running smoke test"
Start-Sleep -Seconds 20
$functionKey = az functionapp keys list --name $functionAppName --resource-group $rgName --query "functionKeys.default" -o tsv 2>$null
$functionUrl = "https://$($deployment.functionAppHostname.value)"

try {
    $health = Invoke-RestMethod -Uri "$functionUrl/api/health" -Headers @{"x-functions-key" = $functionKey} -Method GET
    if ($health.status -eq "healthy") { Write-OK "Health check passed!" }
    else { Write-Warn "Unexpected health response" }
} catch {
    Write-Warn "Health check failed (app may need 1-2 min to start). Try: curl $functionUrl/api/health"
}

# -------------------------------------------------
# DONE
# -------------------------------------------------
Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "  PrivilegeGuard is LIVE" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Gateway URL:  $functionUrl" -ForegroundColor White
Write-Host "  Function Key: $functionKey" -ForegroundColor White
Write-Host "  Demo SP:      $backupSpOid" -ForegroundColor White
Write-Host ""
Write-Host "  NEXT: See README.md for integration steps." -ForegroundColor Yellow
Write-Host ""

# Save output
$outFile = Join-Path (Join-Path $PSScriptRoot "..") ".deployment-output.json"
@{
    gatewayUrl = $functionUrl
    functionKey = $functionKey
    backupSpObjectId = $backupSpOid
    keyVaultResourceId = $kvId
    storageResourceId = $storageId
    resourceGroup = $rgName
    subscriptionId = $subId
    principalId = $principalId
} | ConvertTo-Json | Out-File $outFile -Encoding utf8
Write-OK "Saved to .deployment-output.json"
