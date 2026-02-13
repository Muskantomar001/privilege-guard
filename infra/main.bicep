// ──────────────────────────────────────────────────────────────
// PrivilegeGuard — Main Bicep Template
// ──────────────────────────────────────────────────────────────
// Deploys the complete ZSP Gateway infrastructure:
//   • Log Analytics Workspace + Application Insights
//   • Data Collection Endpoint (DCE) + Data Collection Rule (DCR)
//   • Storage Account (for Function App + demo target)
//   • Key Vault (demo target resource)
//   • Function App (Flex Consumption, Python 3.11) with System Managed Identity
//   • App Service Plan (Consumption Y1)
// ──────────────────────────────────────────────────────────────

targetScope = 'resourceGroup'

// ─── Parameters ──────────────────────────────────────────────

@description('Project name prefix used for all resource names.')
@minLength(2)
@maxLength(12)
param projectName string = 'privguard'

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Unique suffix to prevent naming collisions (default: first 6 chars of resource group ID).')
param uniqueSuffix string = substring(uniqueString(resourceGroup().id), 0, 6)

@description('Python runtime version for the Function App.')
param pythonVersion string = '3.11'

@description('Object ID of the backup service principal (set post-deployment via script).')
param backupSpObjectId string = ''

@description('Cron schedule for backup job timer trigger.')
param backupJobSchedule string = '0 55 1 * * *'

@description('Duration in minutes for backup job access window.')
param backupJobDurationMinutes int = 35

// ─── Variables ───────────────────────────────────────────────

var resourcePrefix = '${projectName}-${uniqueSuffix}'
var logAnalyticsName = '${resourcePrefix}-law'
var appInsightsName = '${resourcePrefix}-ai'
var dceName = '${resourcePrefix}-dce'
var dcrName = '${resourcePrefix}-dcr'
var storageName = replace('${projectName}${uniqueSuffix}sa', '-', '')
var keyVaultName = '${resourcePrefix}-kv'
var functionAppName = '${resourcePrefix}-gw'
var appServicePlanName = '${resourcePrefix}-asp'
var customTableName = 'ZSPAudit_CL'

// ─── Log Analytics Workspace ─────────────────────────────────

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 90
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

// Custom table for ZSP audit events
resource customTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: logAnalytics
  name: customTableName
  properties: {
    schema: {
      name: customTableName
      columns: [
        { name: 'TimeGenerated', type: 'datetime', description: 'Event timestamp' }
        { name: 'EventType', type: 'string', description: 'AccessGrant or AccessRevoke' }
        { name: 'IdentityType', type: 'string', description: 'nhi or admin' }
        { name: 'PrincipalId', type: 'string', description: 'Object ID of service principal or user' }
        { name: 'Target', type: 'string', description: 'Resource ID or group ID' }
        { name: 'TargetType', type: 'string', description: 'AzureResource or EntraGroup' }
        { name: 'Role', type: 'string', description: 'Role name' }
        { name: 'DurationMinutes', type: 'int', description: 'Requested access duration' }
        { name: 'WorkflowId', type: 'string', description: 'Caller-supplied correlation ID' }
        { name: 'ExpiresAt', type: 'string', description: 'ISO format expiry time' }
        { name: 'Result', type: 'string', description: 'Success or Failure' }
        { name: 'Justification', type: 'string', description: 'Admin justification text' }
      ]
    }
    retentionInDays: 90
  }
}

// ─── Application Insights ────────────────────────────────────

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// ─── Data Collection Endpoint ────────────────────────────────

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2022-06-01' = {
  name: dceName
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

// ─── Data Collection Rule ────────────────────────────────────

resource dcr 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: dcrName
  location: location
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      'Custom-ZSPAudit_CL': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'EventType', type: 'string' }
          { name: 'IdentityType', type: 'string' }
          { name: 'PrincipalId', type: 'string' }
          { name: 'Target', type: 'string' }
          { name: 'TargetType', type: 'string' }
          { name: 'Role', type: 'string' }
          { name: 'DurationMinutes', type: 'int' }
          { name: 'WorkflowId', type: 'string' }
          { name: 'ExpiresAt', type: 'string' }
          { name: 'Result', type: 'string' }
          { name: 'Justification', type: 'string' }
        ]
      }
    }
    dataSources: {}
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: logAnalytics.id
          name: 'logAnalyticsDest'
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Custom-ZSPAudit_CL']
        destinations: ['logAnalyticsDest']
        transformKql: 'source'
        outputStream: 'Custom-ZSPAudit_CL'
      }
    ]
  }
  dependsOn: [customTable]
}

// ─── Storage Account ─────────────────────────────────────────
// Used for: Function App state (Durable Functions) + demo target resource

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    networkAcls: {
      defaultAction: 'Allow'
    }
  }
}

// ─── Key Vault ───────────────────────────────────────────────
// Demo target resource — the backup SP will request JIT access here

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    // enablePurgeProtection is omitted for lab flexibility
    networkAcls: {
      defaultAction: 'Allow'
    }
  }
}

// Add a demo secret to Key Vault
resource demoSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'demo-backup-credential'
  properties: {
    value: 'this-is-a-demo-secret-for-zsp-lab'
  }
}

// ─── App Service Plan (Consumption) ──────────────────────────

resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: appServicePlanName
  location: location
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  kind: 'functionapp'
  properties: {
    reserved: true // Required for Linux
  }
}

// ─── Function App ────────────────────────────────────────────

resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      pythonVersion: pythonVersion
      linuxFxVersion: 'Python|${pythonVersion}'
      appSettings: [
        { name: 'AzureWebJobsStorage', value: 'DefaultEndpointsProtocol=https;AccountName=${storage.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storage.listKeys().keys[0].value}' }
        { name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING', value: 'DefaultEndpointsProtocol=https;AccountName=${storage.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storage.listKeys().keys[0].value}' }
        { name: 'WEBSITE_CONTENTSHARE', value: toLower(functionAppName) }
        { name: 'FUNCTIONS_EXTENSION_VERSION', value: '~4' }
        { name: 'FUNCTIONS_WORKER_RUNTIME', value: 'python' }
        { name: 'APPINSIGHTS_INSTRUMENTATIONKEY', value: appInsights.properties.InstrumentationKey }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsights.properties.ConnectionString }
        { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'true' }
        // ZSP Gateway configuration
        { name: 'DCE_ENDPOINT', value: dce.properties.logsIngestion.endpoint }
        { name: 'DCR_RULE_ID', value: dcr.properties.immutableId }
        { name: 'DCR_STREAM_NAME', value: 'Custom-ZSPAudit_CL' }
        { name: 'KEYVAULT_RESOURCE_ID', value: keyVault.id }
        { name: 'STORAGE_RESOURCE_ID', value: storage.id }
        { name: 'BACKUP_SP_OBJECT_ID', value: backupSpObjectId }
        { name: 'BACKUP_JOB_SCHEDULE', value: backupJobSchedule }
        { name: 'BACKUP_JOB_DURATION_MINUTES', value: string(backupJobDurationMinutes) }
        { name: 'MAX_DURATION_MINUTES', value: '480' }
      ]
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
    }
  }
}

// ─── RBAC: User Access Administrator is granted at SUBSCRIPTION level ───
// Done by Deploy-Lab.ps1 after Bicep deploys (can't scope to subscription in RG-scoped Bicep)

// ─── RBAC: Function App → Monitoring Metrics Publisher on DCR ─

var monitoringMetricsPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'

resource functionAppDcrPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, functionApp.id, monitoringMetricsPublisherRoleId)
  scope: dcr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherRoleId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ─── Outputs ─────────────────────────────────────────────────

output functionAppName string = functionApp.name
output functionAppHostname string = functionApp.properties.defaultHostName
output functionAppPrincipalId string = functionApp.identity.principalId
output keyVaultName string = keyVault.name
output keyVaultResourceId string = keyVault.id
output storageAccountName string = storage.name
output storageResourceId string = storage.id
output logAnalyticsWorkspaceId string = logAnalytics.id
output logAnalyticsWorkspaceName string = logAnalytics.name
output dceEndpoint string = dce.properties.logsIngestion.endpoint
output dcrImmutableId string = dcr.properties.immutableId
output resourceGroupName string = resourceGroup().name
output appInsightsName string = appInsights.name
output appInsightsConnectionString string = appInsights.properties.ConnectionString
