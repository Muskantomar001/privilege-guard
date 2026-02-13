<#
.SYNOPSIS
    PrivilegeGuard — Cleanup script to tear down all ZSP Gateway resources.

.DESCRIPTION
    Removes all Azure resources deployed by Deploy-Lab.ps1:
      1. Deletes the Azure Resource Group (and all contained resources)
      2. Deletes Entra ID security groups
      3. Deletes the backup service principal
      4. Removes deployment output file

.PARAMETER ProjectName
    Must match the ProjectName used during deployment. Default: "privguard"

.PARAMETER Force
    Skip confirmation prompt.

.EXAMPLE
    ./Cleanup-Lab.ps1 -ProjectName "privguard" -Force
#>

[CmdletBinding()]
param(
    [string]$ProjectName = "privguard",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "`n═══════════════════════════════════════════════" -ForegroundColor Red
Write-Host "  PrivilegeGuard — ZSP Gateway Cleanup" -ForegroundColor Red
Write-Host "═══════════════════════════════════════════════`n" -ForegroundColor Red

if (-not $Force) {
    $confirm = Read-Host "This will DELETE all PrivilegeGuard resources for project '$ProjectName'. Continue? (yes/no)"
    if ($confirm -ne "yes") {
        Write-Host "Cleanup cancelled." -ForegroundColor Yellow
        exit 0
    }
}

$rgName = "$ProjectName-zsp-rg"

# ──────────────────────────────────────────────
# Step 1: Delete Resource Group
# ──────────────────────────────────────────────

Write-Host "`n▶ Deleting Resource Group: $rgName..." -ForegroundColor Cyan
$rgExists = az group exists --name $rgName -o tsv
if ($rgExists -eq "true") {
    az group delete --name $rgName --yes --no-wait
    Write-Host "  ✓ Resource Group deletion initiated (runs in background)" -ForegroundColor Green
} else {
    Write-Host "  ℹ Resource Group not found: $rgName" -ForegroundColor Yellow
}

# ──────────────────────────────────────────────
# Step 2: Delete Entra ID objects
# ──────────────────────────────────────────────

Write-Host "`n▶ Deleting Entra ID security groups..." -ForegroundColor Cyan
$groupNames = @("SG-GlobalAdmin-ZSP", "SG-IntuneAdmin-ZSP", "SG-SecurityReader-ZSP")

foreach ($groupName in $groupNames) {
    $groupId = az ad group list --display-name $groupName --query "[0].id" -o tsv 2>$null
    if ($groupId) {
        az ad group delete --group $groupId --output none 2>$null
        Write-Host "  ✓ Deleted group: $groupName" -ForegroundColor Green
    } else {
        Write-Host "  ℹ Group not found: $groupName" -ForegroundColor Yellow
    }
}

# ──────────────────────────────────────────────
# Step 3: Delete backup service principal
# ──────────────────────────────────────────────

Write-Host "`n▶ Deleting backup service principal..." -ForegroundColor Cyan
$spName = "$ProjectName-backup-sp"
$spId = az ad sp list --display-name $spName --query "[0].id" -o tsv 2>$null
if ($spId) {
    az ad sp delete --id $spId --output none
    Write-Host "  ✓ Deleted SP: $spName" -ForegroundColor Green
} else {
    Write-Host "  ℹ SP not found: $spName" -ForegroundColor Yellow
}

# Remove the app registration too
$appId = az ad app list --display-name $spName --query "[0].id" -o tsv 2>$null
if ($appId) {
    az ad app delete --id $appId --output none
    Write-Host "  ✓ Deleted app registration: $spName" -ForegroundColor Green
}

# ──────────────────────────────────────────────
# Step 4: Clean up local files
# ──────────────────────────────────────────────

$outputFile = Join-Path $PSScriptRoot ".." ".deployment-output.json"
if (Test-Path $outputFile) {
    Remove-Item $outputFile -Force
    Write-Host "`n  ✓ Removed .deployment-output.json" -ForegroundColor Green
}

Write-Host "`n═══════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  ✓ Cleanup complete!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Green
Write-Host "`nNote: Resource Group deletion runs asynchronously." -ForegroundColor Yellow
Write-Host "Check Azure portal to confirm all resources are removed.`n" -ForegroundColor Yellow
