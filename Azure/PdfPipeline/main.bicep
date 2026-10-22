targetScope = 'resourceGroup'

@description('Azure region. Verify availability of Defender for Storage malware scanning and all selected services here.')
param location string
@description('Globally unique storage account name, 3-24 lowercase alphanumeric characters.')
@minLength(3)
@maxLength(24)
param storageAccountName string
@description('Globally unique Azure Container Registry name.')
param acrName string
@description('Container image tag for the separately built PDF worker. Use an immutable digest in production.')
param workerImage string = 'pdfpipelineworker:dev'
@description('Container image tag for the separately built upload API. Use an immutable digest in production.')
param apiImage string = 'pdfpipelineuploadapi:dev'
@description('Entra tenant ID used to validate API access tokens.')
param entraTenantId string
@description('Expected JWT audience for the upload API.')
param apiAudience string
@secure()
@description('Random high-entropy internal credential shared only between the .NET worker and PDFium sandbox; keep it out of source control and deployment logs.')
param pdfSandboxToken string
@description('Object ID of the Microsoft Defender for Storage service principal in this subscription. Discover/confirm this value for the target Azure cloud before deployment.')
param defenderServicePrincipalObjectId string
@description('Enable an internal-only Container Apps environment. Requires a valid infrastructure subnet ID and supported workload profile.')
param internalEnvironment bool = false
@description('Infrastructure subnet ID for internal environment; omit for a public ingress environment.')
param infrastructureSubnetId string = ''
@description('Prefix for resource names.')
param namePrefix string = 'secrev-pdf'

var suffix = uniqueString(subscription().id, resourceGroup().id, storageAccountName)
var scanTopicName = '${namePrefix}-scan-${suffix}'
var uploadApiName = '${namePrefix}-api-${suffix}'
var workerName = '${namePrefix}-worker-${suffix}'

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: acrName
  location: location
  sku: { name: 'Basic' }
  properties: {
    adminUserEnabled: false
    // Defender scan-result delivery requires a publicly reachable Event Grid endpoint.
    publicNetworkAccess: 'Enabled'
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  sku: { name: 'Standard_ZRS' }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: internalEnvironment ? 'Disabled' : 'Enabled'
    // Prototype default only. Production should use private endpoints for Blob/Queue,
    // VNet integration and explicit private DNS before switching the default to Deny.
    networkAcls: { bypass: 'AzureServices', defaultAction: 'Allow', ipRules: [], virtualNetworkRules: [] }
    encryption: {
      keySource: 'Microsoft.Storage'
      requireInfrastructureEncryption: true
      services: {
        blob: { enabled: true, keyType: 'Account' }
        file: { enabled: true, keyType: 'Account' }
      }
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    deleteRetentionPolicy: { enabled: true, days: 30 }
    containerDeleteRetentionPolicy: { enabled: true, days: 30 }
    isVersioningEnabled: true
  }
}

resource quarantine 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  name: '${storage.name}/default/quarantine'
  properties: { publicAccess: 'None' }
}

resource processed 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  name: '${storage.name}/default/processed'
  properties: { publicAccess: 'None' }
}

resource deadletter 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  name: '${storage.name}/default/event-deadletter'
  properties: { publicAccess: 'None' }
}

resource defenderSettings 'Microsoft.Security/defenderForStorageSettings@2022-12-01-preview' = {
  name: 'current'
  scope: storage
  properties: {
    isEnabled: true
    overrideSubscriptionLevelSettings: true
    malwareScanning: {
      onUpload: { isEnabled: true, capGBPerMonth: 10000 }
      scanResultsEventGridTopicResourceId: scanTopic.id
    }
    sensitiveDataDiscovery: { isEnabled: false }
  }
}

resource scanTopic 'Microsoft.EventGrid/topics@2022-06-15' = {
  name: scanTopicName
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    inputSchema: 'EventGridSchema'
    publicNetworkAccess: internalEnvironment ? 'Disabled' : 'Enabled'
    disableLocalAuth: false
  }
}

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${namePrefix}-logs-${suffix}'
  location: location
  properties: { retentionInDays: 90, sku: { name: 'PerGB2018' }, features: { enableLogAccessUsingOnlyResourcePermissions: true } }
}

resource apiIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-api-id-${suffix}'
  location: location
}

resource workerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-worker-id-${suffix}'
  location: location
}

resource sandboxIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-sandbox-image-id-${suffix}'
  location: location
}

resource documentIntelligence 'Microsoft.CognitiveServices/accounts@2023-05-01' = {
  name: '${namePrefix}-docintel-${suffix}'
  location: location
  kind: 'FormRecognizer'
  sku: { name: 'S0' }
  properties: {
    customSubDomainName: '${namePrefix}-docintel-${suffix}'
    publicNetworkAccess: 'Enabled'
    disableLocalAuth: true
  }
}

resource documentIntelligencePrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-09-01' = if (internalEnvironment && !empty(infrastructureSubnetId)) {
  name: '${namePrefix}-docintel-pe-${suffix}'
  location: location
  properties: {
    subnet: { id: infrastructureSubnetId }
    privateLinkServiceConnections: [{
      name: '${namePrefix}-docintel-link-${suffix}'
      properties: {
        privateLinkServiceId: documentIntelligence.id
        groupIds: ['account']
      }
    }]
  }
}

resource search 'Microsoft.Search/searchServices@2023-11-01' = {
  name: '${namePrefix}-search-${suffix}'
  location: location
  sku: { name: 'basic' }
  identity: { type: 'SystemAssigned' }
  properties: {
    hostingMode: 'default'
    partitionCount: 1
    replicaCount: 1
    publicNetworkAccess: 'enabled'
    disableLocalAuth: true
    authOptions: { aadOrApiKey: { aadAuthFailureMode: 'http403' } }
  }
}

resource cosmos 'Microsoft.DocumentDB/databaseAccounts@2024-05-15' = {
  name: '${namePrefix}-cosmos-${suffix}'
  location: location
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    locations: [{ locationName: location, failoverPriority: 0, isZoneRedundant: false }]
    consistencyPolicy: { defaultConsistencyLevel: 'Session' }
    disableLocalAuth: true
    publicNetworkAccess: 'Enabled'
    minimalTlsVersion: 'Tls12'
    capabilities: [{ name: 'EnableServerless' }]
    backupPolicy: { type: 'Periodic', periodicModeProperties: { backupIntervalInMinutes: 240, backupRetentionIntervalInHours: 24 } }
  }
}

resource cosmosDb 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2024-05-15' = {
  parent: cosmos
  name: 'secrev'
  properties: { resource: { id: 'secrev' }, options: {} }
}

resource cosmosContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2024-05-15' = {
  parent: cosmosDb
  name: 'documents'
  properties: {
    resource: {
      id: 'documents'
      partitionKey: { paths: ['/PartitionKey'], kind: 'Hash' }
      indexingPolicy: { indexingMode: 'consistent', automatic: true }
    }
    options: {}
  }
}

resource environment 'Microsoft.App/managedEnvironments@2025-01-01' = {
  name: '${namePrefix}-env-${suffix}'
  location: location
  properties: union({
    appLogsConfiguration: { destination: 'log-analytics', logAnalyticsConfiguration: { customerId: logs.properties.customerId, sharedKey: logs.listKeys().primarySharedKey } }
    publicNetworkAccess: 'Enabled'
    peerTrafficConfiguration: { encryption: { enabled: true } }
  }, internalEnvironment ? { vnetConfiguration: { internal: true, infrastructureSubnetId: infrastructureSubnetId } } : {})
}

resource sbNamespace 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = {
  name: '${namePrefix}-sb-${suffix}'
  location: location
  sku: { name: 'Standard', tier: 'Standard' }
  properties: { minimumTlsVersion: '1.2', publicNetworkAccess: 'Enabled', disableLocalAuth: true }
}

resource scanQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: sbNamespace
  name: 'pdf-scan-results'
  properties: {
    lockDuration: 'PT15M'
    maxDeliveryCount: 5
    deadLetteringOnMessageExpiration: true
    defaultMessageTimeToLive: 'P7D'
    requiresDuplicateDetection: true
    duplicateDetectionHistoryTimeWindow: 'PT10M'
  }
}

resource defenderEventGridRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(scanTopic.id, defenderServicePrincipalObjectId, 'eventgrid-data-sender')
  scope: scanTopic
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'd5a91429-5739-47e2-a06b-3470a27159e7')
    principalId: defenderServicePrincipalObjectId
    principalType: 'ServicePrincipal'
  }
}

resource scanResultToQueue 'Microsoft.EventGrid/eventSubscriptions@2022-06-15' = {
  name: '${namePrefix}-scan-to-queue-${suffix}'
  scope: scanTopic
  properties: {
    deliveryWithResourceIdentity: {
      identity: { type: 'SystemAssigned' }
      destination: {
        endpointType: 'ServiceBusQueue'
        properties: { resourceId: scanQueue.id }
      }
    }
    eventDeliverySchema: 'EventGridSchema'
    filter: { includedEventTypes: ['Microsoft.Security.MalwareScanningResult'] }
      deadLetterWithResourceIdentity: {
        identity: { type: 'SystemAssigned' }
        deadLetterDestination: { endpointType: 'StorageBlob', properties: { resourceId: storage.id, blobContainerName: 'event-deadletter' } }
      }
    retryPolicy: { maxDeliveryAttempts: 30, eventTimeToLiveInMinutes: 1440 }
  }
}

resource eventGridDeadletterRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(deadletter.id, scanTopic.id, 'blob-data-contributor')
  scope: deadletter
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: scanTopic.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource eventGridBusSenderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(scanQueue.id, scanTopic.id, 'servicebus-data-sender')
  scope: scanQueue
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39')
    principalId: scanTopic.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource apiAcrPullRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, apiIdentity.id, 'acr-pull')
  scope: registry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
    principalId: apiIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource sandboxAcrPullRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, sandboxIdentity.id, 'acr-pull')
  scope: registry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
    principalId: sandboxIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource workerAcrPullRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, workerIdentity.id, 'acr-pull')
  scope: registry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
    principalId: workerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource api 'Microsoft.App/containerApps@2025-01-01' = {
  name: uploadApiName
  location: location
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${apiIdentity.id}': {} } }
  properties: {
    managedEnvironmentId: environment.id
    configuration: {
      ingress: {
        external: !internalEnvironment
        targetPort: 8080
        transport: 'http'
        allowInsecure: false
      }
      registries: [{ server: registry.properties.loginServer, identity: apiIdentity.id }]
      maxInactiveRevisions: 3
    }
    template: {
      containers: [{
        name: 'upload-api'
        image: '${registry.properties.loginServer}/${apiImage}'
        resources: { cpu: json('0.5'), memory: '1Gi' }
        env: [
          { name: 'Pipeline__StorageAccountUrl', value: 'https://${storage.name}.blob.${az.environment().suffixes.storage}/' }
          { name: 'Pipeline__QuarantineContainer', value: 'quarantine' }
          { name: 'Authentication__TenantId', value: entraTenantId }
          { name: 'Authentication__Audience', value: apiAudience }
        ]
      }]
      scale: { minReplicas: 0, maxReplicas: 5 }
    }
  }
  dependsOn: [apiAcrPullRole, apiStorageRole, apiCosmosRole]
}

// PDFium is isolated in a separate, credential-free container app with internal-only ingress.
// This uses a pull-only identity; it is a process boundary, not VM-grade sandboxing or egress denial.
resource pdfSandbox 'Microsoft.App/containerApps@2025-01-01' = {
  name: '${namePrefix}-sandbox-${suffix}'
  location: location
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${sandboxIdentity.id}': {} } }
  properties: {
    managedEnvironmentId: environment.id
    configuration: {
      secrets: [{ name: 'pdf-sandbox-token', value: pdfSandboxToken }]
      registries: [{ server: registry.properties.loginServer, identity: sandboxIdentity.id }]
      ingress: {
        external: false
        targetPort: 8080
        transport: 'http'
        allowInsecure: false
      }
    }
    template: {
      containers: [{
        name: 'pdfium-sandbox'
        image: '${registry.properties.loginServer}/pdfsandbox:dev'
        resources: { cpu: json('1.0'), memory: '2Gi' }
        env: [
          { name: 'ASPNETCORE_HTTP_PORTS', value: '8080' }
          { name: 'PDF_SANDBOX_TOKEN', secretRef: 'pdf-sandbox-token' }
        ]
      }]
      scale: { minReplicas: 1, maxReplicas: 2 }
    }
  }
  dependsOn: [sandboxAcrPullRole]
}

resource worker 'Microsoft.App/containerApps@2025-01-01' = {
  name: workerName
  location: location
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${workerIdentity.id}': {} } }
  properties: {
    managedEnvironmentId: environment.id
    configuration: {
      secrets: [{ name: 'pdf-sandbox-token', value: pdfSandboxToken }]
      registries: [{ server: registry.properties.loginServer, identity: workerIdentity.id }]
      activeRevisionsMode: 'single'
    }
    template: {
      containers: [{
        name: 'pdf-worker'
        image: '${registry.properties.loginServer}/${workerImage}'
        resources: { cpu: json('1.0'), memory: '2Gi' }
        env: [
          { name: 'Pipeline__StorageAccountUrl', value: 'https://${storage.name}.blob.${az.environment().suffixes.storage}/' }
          { name: 'Pipeline__QuarantineContainer', value: 'quarantine' }
          { name: 'Pipeline__ProcessedContainer', value: 'processed' }
          { name: 'Pipeline__ServiceBusNamespace', value: '${sbNamespace.name}.servicebus.windows.net' }
          { name: 'Pipeline__ServiceBusQueue', value: scanQueue.name }
          { name: 'Pipeline__DocumentIntelligenceEndpoint', value: documentIntelligence.properties.endpoint }
          { name: 'Pipeline__SearchEndpoint', value: 'https://${search.name}.search.windows.net' }
          { name: 'Pipeline__CosmosEndpoint', value: cosmos.properties.documentEndpoint }
          { name: 'Pipeline__CosmosDatabase', value: 'secrev' }
          { name: 'Pipeline__CosmosContainer', value: 'documents' }
          { name: 'Pipeline__MaxPdfBytes', value: '26214400' }
          { name: 'Pipeline__MaxPages', value: '100' }
          { name: 'Pipeline__MaxExtractedTextCharacters', value: '500000' }
          { name: 'Pipeline__MaxPreviewWidth', value: '1600' }
          { name: 'Pipeline__MaxPreviewHeight', value: '2400' }
          { name: 'Pipeline__PdfSandboxEndpoint', value: 'http://${pdfSandbox.properties.configuration.ingress.fqdn}' }
          { name: 'Pipeline__PdfSandboxToken', secretRef: 'pdf-sandbox-token' }
        ]
        volumeMounts: [{ volumeName: 'scratch', mountPath: '/work' }]
      }]
      volumes: [{ name: 'scratch', storageType: 'EmptyDir' }]
      scale: {
        minReplicas: 1
        maxReplicas: 5
        rules: [{
          name: 'servicebus-pdf-scan-results'
          custom: {
            type: 'azure-servicebus'
            metadata: {
              queueName: scanQueue.name
              messageCount: '1'
              namespace: sbNamespace.name
            }
            identity: workerIdentity.id
          }
        }]
      }
    }
  }
  dependsOn: [processed, quarantine, scanResultToQueue, workerDocumentIntelligenceRole, workerSearchRole, workerCosmosRole, workerProcessedWriterRole, workerQuarantineReaderRole, workerSbRole, workerAcrPullRole]
}

resource apiStorageRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(quarantine.id, apiIdentity.id, 'blob-data-contributor')
  scope: quarantine
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: apiIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource apiCosmosRole 'Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments@2024-05-15' = {
  parent: cosmos
  name: guid(cosmos.id, apiIdentity.id, 'cosmos-data-contributor')
  properties: {
    principalId: apiIdentity.properties.principalId
    roleDefinitionId: '${cosmos.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002'
    scope: '${cosmos.id}/dbs/secrev/colls/documents'
  }
}

resource workerQuarantineReaderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(quarantine.id, workerIdentity.id, 'blob-data-reader')
  scope: quarantine
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1')
    principalId: workerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource workerProcessedWriterRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(processed.id, workerIdentity.id, 'blob-data-contributor')
  scope: processed
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: workerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource workerSbRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(scanQueue.id, workerIdentity.id, 'servicebus-data-receiver')
  scope: scanQueue
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0')
    principalId: workerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource workerDocumentIntelligenceRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(documentIntelligence.id, workerIdentity.id, 'cognitive-services-data-reader')
  scope: documentIntelligence
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'a97b65f3-24c7-4388-baec-2e87135dc908')
    principalId: workerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource workerSearchRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(search.id, workerIdentity.id, 'search-index-data-contributor')
  scope: search
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '8ebe5a00-799e-43f5-93ac-243d3dce84a7')
    principalId: workerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource workerCosmosRole 'Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments@2024-05-15' = {
  parent: cosmos
  name: guid(cosmos.id, workerIdentity.id, 'cosmos-data-contributor')
  properties: {
    principalId: workerIdentity.properties.principalId
    roleDefinitionId: '${cosmos.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002'
    scope: '${cosmos.id}/dbs/secrev/colls/documents'
  }
}

output uploadApiFqdn string = api.properties.configuration.ingress.fqdn
output storageAccountResourceId string = storage.id
output serviceBusNamespace string = sbNamespace.properties.serviceBusEndpoint
output containerRegistry string = registry.properties.loginServer
