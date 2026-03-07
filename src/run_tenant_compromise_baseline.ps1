<#
.SYNOPSIS
Runs a reusable, read-only tenant-wide compromise baseline and exports evidence.

.DESCRIPTION
Supports device-code or interactive authentication and can be launched with no
parameters (it will prompt for missing tenant details). Evidence is saved to a
timestamped output folder by default.
#>

param(
    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$TenantDomain,

    [Parameter()]
    [int]$DaysBack = 14,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$OutputRoot,

    [Parameter()]
    [ValidateSet("Device", "Interactive")]
    [string]$AuthMode = "Device",

    [Parameter()]
    [switch]$SkipPrompt
)

$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $projectRoot "output/incidents"
}
if (-not $OutputPath) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputPath = Join-Path $OutputRoot "compromise-baseline-$stamp"
}

. (Join-Path $PSScriptRoot "lib/common.ps1")
. (Join-Path $PSScriptRoot "lib/collectors.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantMailboxForwarding.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantInboxRules.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantTransportRules.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantConnectors.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantRiskySignins.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantAppChanges.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantAuditCoverage.ps1")

function Prompt-RequiredValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter()]
        [string]$DefaultValue
    )

    $prompt = if ($DefaultValue) { "$Label [$DefaultValue]" } else { $Label }
    $input = Read-Host $prompt
    if ([string]::IsNullOrWhiteSpace($input)) {
        $input = $DefaultValue
    }
    if ([string]::IsNullOrWhiteSpace($input)) {
        throw "$Label is required."
    }
    return $input.Trim()
}

function Get-DefaultTenantId {
    param([string]$RootPath)
    $summaryFile = Join-Path $RootPath "output/app-registration/investigation-app-registration.json"
    if (-not (Test-Path $summaryFile)) { return $null }
    try {
        $summary = Get-Content $summaryFile -Raw | ConvertFrom-Json -ErrorAction Stop
        return $summary.TenantId
    } catch {
        return $null
    }
}

function Get-DefaultTenantDomain {
    param([string]$RootPath)
    $incidentRoot = Join-Path $RootPath "output/incidents"
    if (-not (Test-Path $incidentRoot)) { return $null }
    $latest = Get-ChildItem -Path $incidentRoot -Filter "tenant-compromise-baseline-summary.json" -Recurse -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $latest) { return $null }
    try {
        $summary = Get-Content $latest.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
        return $summary.TenantDomain
    } catch {
        return $null
    }
}

$defaultTenantId = Get-DefaultTenantId -RootPath $projectRoot
$defaultTenantDomain = Get-DefaultTenantDomain -RootPath $projectRoot

if (-not $TenantId) {
    if ($SkipPrompt) {
        throw "TenantId was not provided and prompting is disabled."
    }
    $TenantId = Prompt-RequiredValue -Label "Tenant ID" -DefaultValue $defaultTenantId
}

if (-not $TenantDomain) {
    if ($SkipPrompt) {
        throw "TenantDomain was not provided and prompting is disabled."
    }
    $TenantDomain = Prompt-RequiredValue -Label "Tenant domain (e.g. contoso.onmicrosoft.com)" -DefaultValue $defaultTenantDomain
}

Import-Module ExchangeOnlineManagement -ErrorAction Stop
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Applications -ErrorAction Stop
Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
Resolve-InvestigationPath -Path (Join-Path $OutputPath "raw") | Out-Null
Resolve-InvestigationPath -Path (Join-Path $OutputPath "normalized") | Out-Null

$sinceUtc = (Get-Date).ToUniversalTime().AddDays(-$DaysBack)
$sinceIso = $sinceUtc.ToString("o")

$graphScopes = @("AuditLog.Read.All", "Application.Read.All", "Directory.Read.All")

Write-Host "Output path: $OutputPath" -ForegroundColor Gray
Write-Host "Connecting Exchange Online ($AuthMode auth)..." -ForegroundColor Cyan
if ($AuthMode -eq "Device") {
    Connect-ExchangeOnline -Organization $TenantDomain -Device -ShowBanner:$false | Out-Null
} else {
    Connect-ExchangeOnline -Organization $TenantDomain -ShowBanner:$false | Out-Null
}

Write-Host "Connecting Microsoft Graph ($AuthMode auth)..." -ForegroundColor Cyan
if ($AuthMode -eq "Device") {
    Connect-MgGraph -TenantId $TenantId -Scopes $graphScopes -UseDeviceAuthentication -NoWelcome | Out-Null
} else {
    Connect-MgGraph -TenantId $TenantId -Scopes $graphScopes -NoWelcome | Out-Null
}

$mgContext = Get-MgContext
$exoContext = Get-ConnectionInformation | Select-Object -First 1

if ($mgContext.TenantId -ne $TenantId) {
    throw "Connected Graph tenant mismatch. Expected '$TenantId' but got '$($mgContext.TenantId)'."
}

try {
    $acceptedDomain = Get-AcceptedDomain -Identity $TenantDomain -ErrorAction Stop
    if (-not $acceptedDomain) {
        throw "Accepted domain '$TenantDomain' not found after Exchange authentication."
    }
} catch {
    throw "Connected Exchange tenant mismatch or domain not available. Expected accepted domain '$TenantDomain'. $($_.Exception.Message)"
}

Write-InvestigationJsonFile -Path (Join-Path $OutputPath "run-context.json") -Data @{
    TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    TenantId = $TenantId
    TenantDomain = $TenantDomain
    AuthMode = $AuthMode
    GraphAccount = $mgContext.Account
    GraphScopes = $mgContext.Scopes
    ExchangeUserPrincipal = $exoContext.UserPrincipalName
}

$collectorResults = @()

Write-Host "Collecting mailbox forwarding settings..." -ForegroundColor Cyan
$collectorResults += Invoke-TenantMailboxForwardingCollector -OutputPath $OutputPath

Write-Host "Collecting inbox rules..." -ForegroundColor Cyan
$collectorResults += Invoke-TenantInboxRulesCollector -OutputPath $OutputPath

Write-Host "Collecting transport rules..." -ForegroundColor Cyan
$collectorResults += Invoke-TenantTransportRulesCollector -OutputPath $OutputPath

Write-Host "Collecting connectors..." -ForegroundColor Cyan
$collectorResults += Invoke-TenantConnectorsCollector -OutputPath $OutputPath

Write-Host "Collecting risky sign-ins..." -ForegroundColor Cyan
$collectorResults += Invoke-TenantRiskySigninsCollector -OutputPath $OutputPath -SinceIso $sinceIso

Write-Host "Collecting recently created app registrations and service principals..." -ForegroundColor Cyan
$collectorResults += Invoke-TenantAppChangesCollector -OutputPath $OutputPath -SinceIso $sinceIso

Write-Host "Collecting audit coverage..." -ForegroundColor Cyan
$collectorResults += Invoke-TenantAuditCoverageCollector -OutputPath $OutputPath

$collectorIndex = @{}
foreach ($result in $collectorResults) {
    $collectorIndex[$result.Module] = $result
}

$collectionStatus = @(
    $collectorResults |
        Select-Object Module, Status, RawPath, NormalizedPath, Metrics, Error, Warnings
)
Write-InvestigationJsonFile -Path (Join-Path $OutputPath "collection-status.json") -Data @{
    TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    Results = $collectionStatus
} | Out-Null

$failedCollectors = @($collectorResults | Where-Object { $_.Status -eq "failed" })
$collectorErrors = @(
    $failedCollectors |
        ForEach-Object { "$($_.Module): $($_.Error)" }
)
$partialWarnings = @(
    $collectorResults |
        Where-Object { $_.Status -eq "partial" -and @($_.Warnings).Count -gt 0 } |
        ForEach-Object { $_.Warnings }
)

$mailboxForwardingMetrics = if ($collectorIndex.ContainsKey("mailboxForwarding")) { $collectorIndex["mailboxForwarding"].Metrics } else { [pscustomobject]@{} }
$inboxRulesMetrics = if ($collectorIndex.ContainsKey("inboxRules")) { $collectorIndex["inboxRules"].Metrics } else { [pscustomobject]@{} }
$transportRuleMetrics = if ($collectorIndex.ContainsKey("transportRules")) { $collectorIndex["transportRules"].Metrics } else { [pscustomobject]@{} }
$connectorMetrics = if ($collectorIndex.ContainsKey("connectors")) { $collectorIndex["connectors"].Metrics } else { [pscustomobject]@{} }
$riskySigninMetrics = if ($collectorIndex.ContainsKey("riskySignins")) { $collectorIndex["riskySignins"].Metrics } else { [pscustomobject]@{} }
$appChangesMetrics = if ($collectorIndex.ContainsKey("appChanges")) { $collectorIndex["appChanges"].Metrics } else { [pscustomobject]@{} }
$auditCoverageMetrics = if ($collectorIndex.ContainsKey("auditCoverage")) { $collectorIndex["auditCoverage"].Metrics } else { [pscustomobject]@{} }

$summary = [ordered]@{
    TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    TenantId = $TenantId
    TenantDomain = $TenantDomain
    AuthMode = $AuthMode
    DaysBack = $DaysBack
    SinceUtc = $sinceIso
    OutputPath = $OutputPath
    TotalMailboxes = $mailboxForwardingMetrics.TotalMailboxes
    ForwardingHitCount = $mailboxForwardingMetrics.ForwardingHitCount
    InboxRuleCount = $inboxRulesMetrics.RuleCount
    TransportRuleCount = $transportRuleMetrics.TotalRules
    InboundConnectorCount = $connectorMetrics.InboundConnectorCount
    OutboundConnectorCount = $connectorMetrics.OutboundConnectorCount
    RiskySigninCount = $riskySigninMetrics.TotalRows
    RecentAppCount = $appChangesMetrics.ApplicationCount
    RecentServicePrincipalCount = $appChangesMetrics.ServicePrincipalCount
    UnifiedAuditLogIngestionEnabled = $auditCoverageMetrics.UnifiedAuditLogIngestionEnabled
    AdminAuditLogEnabled = $auditCoverageMetrics.AdminAuditLogEnabled
    UnifiedAuditLogVerificationStatus = $auditCoverageMetrics.UnifiedAuditLogVerificationStatus
    ErrorCount = @($collectorErrors).Count
    Errors = $collectorErrors
    WarningCount = @($partialWarnings).Count
    Warnings = $partialWarnings
    CollectionStatusFile = Join-Path $OutputPath "collection-status.json"
    Collectors = $collectionStatus
}

$summaryFile = Join-Path $OutputPath "tenant-compromise-baseline-summary.json"
Write-InvestigationJsonFile -Path $summaryFile -Data $summary | Out-Null

Write-Host ""
Write-Host "Baseline summary saved: $summaryFile" -ForegroundColor Green
$summary | ConvertTo-Json -Depth 8
