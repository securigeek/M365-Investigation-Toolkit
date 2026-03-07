param(
    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$TenantDomain,

    [Parameter()]
    [string]$CaseName,

    [Parameter()]
    [int]$DaysBack = 14,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$OutputRoot,

    [Parameter()]
    [string]$ProfilePath,

    [Parameter()]
    [string]$ProfileRoot,

    [Parameter()]
    [string]$Sender,

    [Parameter()]
    [string]$Domain,

    [Parameter()]
    [string]$UserPrincipalName,

    [Parameter()]
    [string]$SubjectContains,

    [Parameter()]
    [switch]$SkipPrompt
)

Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $projectRoot "output/incidents"
}

. (Join-Path $PSScriptRoot "lib/common.ps1")
. (Join-Path $PSScriptRoot "lib/profiles.ps1")
. (Join-Path $PSScriptRoot "lib/prereqs.ps1")
. (Join-Path $PSScriptRoot "lib/auth.ps1")
. (Join-Path $PSScriptRoot "lib/api-capabilities.ps1")
. (Join-Path $PSScriptRoot "lib/collectors.ps1")
. (Join-Path $PSScriptRoot "lib/detections.ps1")
. (Join-Path $PSScriptRoot "lib/reporting.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantMailboxForwarding.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantInboxRules.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantTransportRules.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantConnectors.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantRiskySignins.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantAppChanges.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantAuditCoverage.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantRoleAssignments.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantConsentGrants.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantAcceptedDomains.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantMailboxAuditPosture.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantMessageTracePivot.ps1")
. (Join-Path $PSScriptRoot "collectors/Get-TenantQuarantinePivot.ps1")

foreach ($optionalCollectorPath in @(
    (Join-Path $PSScriptRoot "collectors/Get-TenantDirectoryAuditLog.ps1"),
    (Join-Path $PSScriptRoot "collectors/Get-TenantInteractiveSignins.ps1"),
    (Join-Path $PSScriptRoot "collectors/Get-TenantNonInteractiveSignins.ps1"),
    (Join-Path $PSScriptRoot "collectors/Get-TenantServicePrincipalSignins.ps1"),
    (Join-Path $PSScriptRoot "collectors/Get-TenantUnifiedAuditLog.ps1")
)) {
    if (Test-Path $optionalCollectorPath) {
        . $optionalCollectorPath
    }
}

function ConvertTo-InvestigationSlug {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $slug = $Value.ToLowerInvariant() -replace "[^a-z0-9]+", "-"
    $slug = $slug.Trim("-")
    if ([string]::IsNullOrWhiteSpace($slug)) {
        return "investigation"
    }

    return $slug
}

function Get-InvestigationDefaultCaseName {
    return "compromise-check-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}

function Get-InvestigationPromptDefinitions {
    return [pscustomobject]@{
        CaseName = "Case name (used in the report title and output folder)"
        DaysBack = "Lookback days (how far back to search for compromise signals; default 14)"
        Sender = "Sender (optional; email address to pivot message trace and quarantine checks, e.g. bad@domain.com)"
        Domain = "Domain (optional; domain to pivot message trace and quarantine checks, e.g. contoso.com)"
        UserPrincipalName = "Recipient UPN (optional; user mailbox to focus on, e.g. alice@contoso.com)"
        SubjectContains = "Subject contains (optional; text fragment to match suspicious mail subjects)"
        TenantId = "Tenant ID (optional; use for strict tenant validation before collection)"
        TenantDomain = "Tenant domain (optional; use for Exchange domain validation, e.g. contoso.onmicrosoft.com)"
    }
}

function Test-InvestigationLegacyProfileMode {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$BoundParameters
    )

    foreach ($name in @("ProfilePath", "ProfileRoot")) {
        if ($BoundParameters.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace([string]$BoundParameters[$name])) {
            return $true
        }
    }

    return $false
}

function Get-AvailableInvestigationProfiles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath
    )

    $tenantRoot = Join-Path $RootPath "tenants"
    if (-not (Test-Path $tenantRoot)) {
        return @()
    }

    return @(
        Get-ChildItem -Path $tenantRoot -Filter "*.json" -File |
            ForEach-Object { Read-InvestigationJsonFile -Path $_.FullName }
    )
}

function Prompt-InvestigationRunValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter()]
        [string]$DefaultValue,

        [Parameter()]
        [switch]$AllowEmpty,

        [Parameter()]
        [switch]$SkipPrompt
    )

    if (-not $SkipPrompt) {
        $promptLabel = $Label
        if (-not [string]::IsNullOrWhiteSpace($DefaultValue)) {
            $promptLabel = "$Label [$DefaultValue]"
        }

        $value = Read-Host $promptLabel
        if ([string]::IsNullOrWhiteSpace($value)) {
            if (-not [string]::IsNullOrWhiteSpace($DefaultValue)) {
                return $DefaultValue.Trim()
            }
            if ($AllowEmpty) {
                return $null
            }
            throw "$Label is required."
        }

        return $value.Trim()
    }

    if (-not [string]::IsNullOrWhiteSpace($DefaultValue)) {
        return $DefaultValue.Trim()
    }
    if ($AllowEmpty) {
        return $null
    }

    throw "$Label is required."
}

function Prompt-InvestigationLookbackDays {
    param(
        [Parameter()]
        [int]$DefaultValue = 14,

        [Parameter()]
        [switch]$SkipPrompt
    )

    $prompts = Get-InvestigationPromptDefinitions
    $resolved = Prompt-InvestigationRunValue -Label $prompts.DaysBack -DefaultValue $DefaultValue.ToString() -SkipPrompt:$SkipPrompt
    $parsed = 0
    if (-not [int]::TryParse($resolved, [ref]$parsed) -or $parsed -lt 1) {
        throw "Lookback days must be a positive integer."
    }

    return $parsed
}

function Confirm-InvestigationAction {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt,

        [Parameter()]
        [bool]$DefaultYes = $true,

        [Parameter()]
        [switch]$SkipPrompt
    )

    if ($SkipPrompt) {
        return $DefaultYes
    }

    $suffix = if ($DefaultYes) { "[Y/n]" } else { "[y/N]" }
    $response = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($response)) {
        return $DefaultYes
    }

    return $response.Trim().ToLowerInvariant() -in @("y", "yes")
}

function Test-InvestigationPivotsPresent {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Pivots
    )

    foreach ($key in $Pivots.Keys) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Pivots[$key])) {
            return $true
        }
    }

    return $false
}

function Ensure-InvestigationPrerequisites {
    param(
        [Parameter()]
        [switch]$SkipPrompt
    )

    $status = Get-InvestigationPrerequisiteStatus
    if ($status.Ready) {
        return $status
    }

    $moduleChanges = @($status.MissingModules) + @($status.OutdatedModules)
    $needsModuleInstall = $moduleChanges.Count -gt 0
    if ($needsModuleInstall) {
        $moduleSummary = @(
            $moduleChanges |
                ForEach-Object {
                    if ($_.PSObject.Properties.Name -contains "InstalledVersion") {
                        "$($_.Name) >= $($_.MinimumVersion) (installed $($_.InstalledVersion))"
                    } else {
                        "$($_.Name) >= $($_.MinimumVersion)"
                    }
                }
        ) -join ", "

        if (-not (Confirm-InvestigationAction -Prompt "Install or update required modules in current-user scope: $moduleSummary?" -DefaultYes $true -SkipPrompt:$SkipPrompt)) {
            throw "Required modules are missing or outdated. Install them and rerun."
        }

        $installTargets = @(
            $status.MissingModules |
                ForEach-Object { [pscustomobject]@{ Name = $_.Name; MinimumVersion = $_.MinimumVersion } }
        )
        $installTargets += @(
            $status.OutdatedModules |
                ForEach-Object { [pscustomobject]@{ Name = $_.Name; MinimumVersion = $_.MinimumVersion } }
        )
        Install-InvestigationModules -Modules $installTargets
        $status = Get-InvestigationPrerequisiteStatus
    }

    if ([version]$status.CurrentPwshVersion -lt [version]$status.MinimumPwshVersion) {
        throw "PowerShell $($status.MinimumPwshVersion) or later is required. Current version: $($status.CurrentPwshVersion)."
    }
    if (-not $status.Browser.Supported) {
        throw "A browser launch command was not detected on this system. Windows and macOS self-service auth require browser launch support."
    }
    if (-not $status.Ready) {
        $remainingModules = @($status.MissingModules.Name) + @($status.OutdatedModules.Name)
        throw "Prerequisites are still not ready. Remaining module issues: $($remainingModules -join ', ')."
    }

    return $status
}

function Resolve-InvestigationExecutionPlan {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$ApiCatalog,

        [Parameter(Mandatory = $true)]
        [hashtable]$Pivots,

        [Parameter()]
        [psobject]$Profile
    )

    $pivotPresent = Test-InvestigationPivotsPresent -Pivots $Pivots
    $registryEntries = if ($ApiCatalog.PSObject.Properties.Name -contains "Registry" -and $ApiCatalog.Registry) {
        @($ApiCatalog.Registry)
    } else {
        @(Get-InvestigationCollectorRegistry)
    }
    $registryByName = @{}
    foreach ($entry in $registryEntries) {
        $registryByName[$entry.Name] = $entry
    }

    $selectedModules = @()
    $skippedModules = @()

    foreach ($module in @($ApiCatalog.Modules)) {
        $registryEntry = $registryByName[$module.Name]
        $skipReason = $null

        if ($registryEntry -and $registryEntry.RequiresPivots -and (-not $pivotPresent)) {
            $skipReason = "no-pivot-input"
        }

        if (-not $skipReason -and $Profile -and $Profile.PSObject.Properties.Name -contains "Modules" -and $Profile.Modules) {
            if ($Profile.Modules.PSObject.Properties.Name -contains $module.Name) {
                $moduleConfig = $Profile.Modules.$($module.Name)
                if ($moduleConfig -and $moduleConfig.Enabled -eq $false) {
                    $skipReason = "module-disabled-in-profile"
                }
            }
        }

        if (-not $skipReason -and $module.Status -eq "unavailable") {
            $skipReason = "unavailable-command-or-api"
        }

        $planEntry = [pscustomobject]@{
            Name = $module.Name
            Surface = if ($module.PSObject.Properties.Name -contains "Surface") { $module.Surface } else { if ($registryEntry) { $registryEntry.Surface } else { $null } }
            Status = $module.Status
            Profile = if ($module.PSObject.Properties.Name -contains "Profile") { $module.Profile } else { if ($registryEntry) { $registryEntry.PreferredProfile } else { $null } }
            Command = if ($module.PSObject.Properties.Name -contains "Command") { $module.Command } else { if ($registryEntry) { $registryEntry.PreferredCommand } else { $null } }
            RequiredScopes = if ($module.PSObject.Properties.Name -contains "RequiredScopes") { $module.RequiredScopes } else { if ($registryEntry) { $registryEntry.RequiredScopes } else { @() } }
            RoleAssumptions = if ($registryEntry) { $registryEntry.RoleAssumptions } else { @() }
            RequiresPivots = if ($registryEntry) { [bool]$registryEntry.RequiresPivots } else { $false }
            SkipReason = $skipReason
        }

        if ($skipReason) {
            $skippedModules += $planEntry
        } else {
            $selectedModules += $planEntry
        }
    }

    return [pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
        ModuleNames = @($selectedModules.Name)
        Modules = $selectedModules
        SkippedModules = $skippedModules
    }
}

function New-InvestigationManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [string]$TenantDomain,

        [Parameter(Mandatory = $true)]
        [string]$CaseName,

        [Parameter()]
        [int]$DaysBack = 14,

        [Parameter()]
        [hashtable]$Pivots,

        [Parameter()]
        [string]$AuthMode,

        [Parameter()]
        [string]$Operator,

        [Parameter()]
        [string]$CustomerName
    )

    return [pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
        CaseName = $CaseName
        CaseSlug = ConvertTo-InvestigationSlug -Value $CaseName
        TenantId = $TenantId
        TenantDomain = $TenantDomain
        CustomerName = $CustomerName
        Operator = $Operator
        AuthMode = $AuthMode
        DaysBack = $DaysBack
        Pivots = if ($Pivots) { [pscustomobject]$Pivots } else { [pscustomobject]@{} }
    }
}

function New-InvestigationSkippedResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [psobject]$Module
    )

    return Publish-CollectorArtifacts `
        -OutputPath $OutputPath `
        -ModuleName $Module.Name `
        -Status "skipped" `
        -NormalizedData ([pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            Reason = $Module.SkipReason
        }) `
        -Warnings @($Module.SkipReason)
}

function Resolve-InvestigationRuntimeSkip {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults
    )

    if ($ModuleName -ne "unifiedAuditLog") {
        return [pscustomobject]@{
            ShouldSkip = $false
            Reason = $null
        }
    }

    $auditCoverage = @($CollectorResults | Where-Object { $_.Module -eq "auditCoverage" } | Select-Object -First 1)[0]
    if (-not $auditCoverage -or -not $auditCoverage.Data -or $auditCoverage.Data.PSObject.Properties.Name -notcontains "UnifiedAuditLogStatus") {
        return [pscustomobject]@{
            ShouldSkip = $false
            Reason = $null
        }
    }

    switch ([string]$auditCoverage.Data.UnifiedAuditLogStatus) {
        "verified-off" {
            return [pscustomobject]@{
                ShouldSkip = $true
                Reason = "ual-verified-off"
            }
        }
        "ambiguous" {
            return [pscustomobject]@{
                ShouldSkip = $true
                Reason = "ual-status-ambiguous"
            }
        }
        default {
            return [pscustomobject]@{
                ShouldSkip = $false
                Reason = $null
            }
        }
    }
}

function Invoke-InvestigationPlannedCollector {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Module,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$SinceIso,

        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter(Mandatory = $true)]
        [hashtable]$Pivots
    )

    switch ($Module.Name) {
        "mailboxForwarding" { return Invoke-TenantMailboxForwardingCollector -OutputPath $OutputPath }
        "inboxRules" { return Invoke-TenantInboxRulesCollector -OutputPath $OutputPath }
        "transportRules" { return Invoke-TenantTransportRulesCollector -OutputPath $OutputPath }
        "connectors" { return Invoke-TenantConnectorsCollector -OutputPath $OutputPath }
        "riskySignins" { return Invoke-TenantRiskySigninsCollector -OutputPath $OutputPath -SinceIso $SinceIso -CommandName $Module.Command }
        "appChanges" { return Invoke-TenantAppChangesCollector -OutputPath $OutputPath -SinceIso $SinceIso }
        "auditCoverage" { return Invoke-TenantAuditCoverageCollector -OutputPath $OutputPath }
        "directoryAuditLog" { return Invoke-TenantDirectoryAuditLogCollector -OutputPath $OutputPath -SinceIso $SinceIso -CommandName $Module.Command }
        "interactiveSignins" { return Invoke-TenantInteractiveSigninsCollector -OutputPath $OutputPath -SinceIso $SinceIso -CommandName $Module.Command }
        "nonInteractiveSignins" { return Invoke-TenantNonInteractiveSigninsCollector -OutputPath $OutputPath -SinceIso $SinceIso -CommandName $Module.Command }
        "servicePrincipalSignins" { return Invoke-TenantServicePrincipalSigninsCollector -OutputPath $OutputPath -SinceIso $SinceIso -CommandName $Module.Command }
        "unifiedAuditLog" { return Invoke-TenantUnifiedAuditLogCollector -OutputPath $OutputPath -StartDate $StartDate -EndDate $EndDate }
        "roleAssignments" { return Invoke-TenantRoleAssignmentsCollector -OutputPath $OutputPath -SinceIso $SinceIso -CommandName $Module.Command }
        "consentGrants" { return Invoke-TenantConsentGrantsCollector -OutputPath $OutputPath -CommandName $Module.Command }
        "acceptedDomains" { return Invoke-TenantAcceptedDomainsCollector -OutputPath $OutputPath }
        "mailboxAuditPosture" { return Invoke-TenantMailboxAuditPostureCollector -OutputPath $OutputPath }
        "messageTracePivot" { return Invoke-TenantMessageTracePivotCollector -OutputPath $OutputPath -StartDate $StartDate -EndDate $EndDate -Pivots $Pivots -CommandName $Module.Command }
        "quarantinePivot" { return Invoke-TenantQuarantinePivotCollector -OutputPath $OutputPath -StartDate $StartDate -EndDate $EndDate -Pivots $Pivots }
        default { throw "Unknown investigation module '$($Module.Name)'." }
    }
}

function New-InvestigationPreflightCapabilities {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Prerequisites,

        [Parameter(Mandatory = $true)]
        [psobject]$ExecutionPlan,

        [Parameter(Mandatory = $true)]
        [psobject]$Connection,

        [Parameter(Mandatory = $true)]
        [string]$AuthMode
    )

    return [pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
        AuthMode = $AuthMode
        TenantId = $Connection.TenantId
        TenantDomain = $Connection.TenantDomain
        Operator = $Connection.Graph.Account
        Browser = $Prerequisites.Browser
        CurrentPwshVersion = $Prerequisites.CurrentPwshVersion
        MinimumPwshVersion = $Prerequisites.MinimumPwshVersion
        GrantedScopes = @($Connection.Graph.Scopes)
        SelectedModules = @($ExecutionPlan.ModuleNames)
        SkippedModules = @(
            $ExecutionPlan.SkippedModules |
                Select-Object Name, SkipReason, Status, Command
        )
    }
}

function Invoke-InvestigationCollectionRun {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Connection,

        [Parameter(Mandatory = $true)]
        [string]$AuthMode,

        [Parameter(Mandatory = $true)]
        [string]$CaseName,

        [Parameter(Mandatory = $true)]
        [int]$DaysBack,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [psobject]$Prerequisites,

        [Parameter(Mandatory = $true)]
        [hashtable]$Pivots,

        [Parameter()]
        [psobject]$Profile
    )

    $startDate = (Get-Date).ToUniversalTime().AddDays(-$DaysBack)
    $endDate = (Get-Date).ToUniversalTime()
    $sinceIso = $startDate.ToString("o")
    $apiCatalog = Get-InvestigationApiCatalog
    $executionPlan = Resolve-InvestigationExecutionPlan -ApiCatalog $apiCatalog -Pivots $Pivots -Profile $Profile
    $preflight = New-InvestigationPreflightCapabilities `
        -Prerequisites $Prerequisites `
        -ExecutionPlan $executionPlan `
        -Connection $Connection `
        -AuthMode $AuthMode

    Write-InvestigationJsonFile -Path (Join-Path $OutputPath "api-catalog.json") -Data $apiCatalog | Out-Null
    Write-InvestigationJsonFile -Path (Join-Path $OutputPath "preflight-capabilities.json") -Data $preflight | Out-Null

    $manifest = New-InvestigationManifest `
        -TenantId $Connection.TenantId `
        -TenantDomain $Connection.TenantDomain `
        -CaseName $CaseName `
        -DaysBack $DaysBack `
        -Pivots $Pivots `
        -AuthMode $AuthMode `
        -Operator $Connection.Graph.Account `
        -CustomerName $(if ($Profile -and $Profile.PSObject.Properties.Name -contains "CustomerName") { $Profile.CustomerName } else { $null })

    $collectorResults = @()
    foreach ($module in @($executionPlan.Modules)) {
        $runtimeSkip = Resolve-InvestigationRuntimeSkip -ModuleName $module.Name -CollectorResults $collectorResults
        if ($runtimeSkip.ShouldSkip) {
            $collectorResults += New-InvestigationSkippedResult `
                -OutputPath $OutputPath `
                -Module ([pscustomobject]@{
                    Name = $module.Name
                    SkipReason = $runtimeSkip.Reason
                })
            continue
        }

        $collectorResults += Invoke-InvestigationPlannedCollector `
            -Module $module `
            -OutputPath $OutputPath `
            -SinceIso $sinceIso `
            -StartDate $startDate `
            -EndDate $endDate `
            -Pivots $Pivots
    }
    foreach ($module in @($executionPlan.SkippedModules)) {
        $collectorResults += New-InvestigationSkippedResult -OutputPath $OutputPath -Module $module
    }

    $detectionResults = @(Invoke-InvestigationDetectors -Manifest $manifest -CollectorResults $collectorResults -OutputPath $OutputPath)
    $reportBundle = Write-InvestigationReportBundle -OutputPath $OutputPath -Manifest $manifest -CollectorResults $collectorResults -Detections $detectionResults

    return [pscustomobject]@{
        OutputPath = $OutputPath
        Manifest = $manifest
        ApiCatalog = $apiCatalog
        Preflight = $preflight
        ExecutionPlan = $executionPlan
        CollectorResults = $collectorResults
        DetectionResults = $detectionResults
        Report = $reportBundle
    }
}

function Invoke-LegacyProfileCollection {
    param(
        [Parameter()]
        [string]$TenantId,

        [Parameter()]
        [string]$TenantDomain,

        [Parameter()]
        [string]$ProfilePath,

        [Parameter()]
        [string]$ProfileRoot,

        [Parameter(Mandatory = $true)]
        [psobject]$Prerequisites,

        [Parameter(Mandatory = $true)]
        [string]$CaseName,

        [Parameter(Mandatory = $true)]
        [int]$DaysBack,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$Pivots
    )

    if (-not $ProfileRoot) {
        $ProfileRoot = Join-Path $projectRoot "profiles"
    }

    $availableProfiles = @(Get-AvailableInvestigationProfiles -RootPath $ProfileRoot)
    if (-not $TenantId -and -not $ProfilePath -and $availableProfiles.Count -gt 0) {
        Write-Host "Available tenant profiles:" -ForegroundColor Gray
        $availableProfiles | ForEach-Object {
            Write-Host "  $($_.TenantId)  $($_.TenantDomain)  $($_.CustomerName)" -ForegroundColor Gray
        }
    }

    if (-not $TenantId -and -not $ProfilePath) {
        $TenantId = Prompt-InvestigationRunValue -Label "Tenant ID" -SkipPrompt:$SkipPrompt
    }

    $profile = Resolve-InvestigationTenantProfile -ProfilePath $ProfilePath -ProfileRoot $ProfileRoot -TenantId $TenantId
    if (-not $profile) {
        throw "Tenant profile not found for '$TenantId'. Run tenant onboarding first or provide -ProfilePath."
    }

    if (-not $TenantId) {
        $TenantId = $profile.TenantId
    }
    if (-not $TenantDomain -and $profile.PSObject.Properties.Name -contains "TenantDomain") {
        $TenantDomain = $profile.TenantDomain
    }

    $connection = & (Join-Path $projectRoot "Connect-Tenant.ps1") `
        -TenantId $TenantId `
        -TenantDomain $TenantDomain `
        -ProfilePath $ProfilePath `
        -ProfileRoot $ProfileRoot
    if (-not $connection.Connected) {
        throw "Connection failed. $($connection.Error)"
    }

    return Invoke-InvestigationCollectionRun `
        -Connection $connection `
        -AuthMode "LegacyProfile" `
        -CaseName $CaseName `
        -DaysBack $DaysBack `
        -OutputPath $OutputPath `
        -Prerequisites $Prerequisites `
        -Pivots $Pivots `
        -Profile $profile
}

function Invoke-SelfServiceCollection {
    param(
        [Parameter()]
        [string]$TenantId,

        [Parameter()]
        [string]$TenantDomain,

        [Parameter(Mandatory = $true)]
        [psobject]$Prerequisites,

        [Parameter(Mandatory = $true)]
        [string]$CaseName,

        [Parameter(Mandatory = $true)]
        [int]$DaysBack,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$Pivots
    )

    Write-Host "Opening delegated browser sign-in for Microsoft 365 read-only collection..." -ForegroundColor Cyan
    $connection = Connect-InvestigationTenantDelegated -TenantId $TenantId -TenantDomain $TenantDomain

    return Invoke-InvestigationCollectionRun `
        -Connection $connection `
        -AuthMode "DelegatedSelfService" `
        -CaseName $CaseName `
        -DaysBack $DaysBack `
        -OutputPath $OutputPath `
        -Prerequisites $Prerequisites `
        -Pivots $Pivots
}

function Invoke-InvestigationCollector {
    param(
        [string]$TenantId,
        [string]$TenantDomain,
        [string]$CaseName,
        [int]$DaysBack,
        [string]$OutputPath,
        [string]$OutputRoot,
        [string]$ProfilePath,
        [string]$ProfileRoot,
        [string]$Sender,
        [string]$Domain,
        [string]$UserPrincipalName,
        [string]$SubjectContains,
        [switch]$SkipPrompt
    )

    $prerequisites = Ensure-InvestigationPrerequisites -SkipPrompt:$SkipPrompt
    if (-not $OutputRoot) {
        $OutputRoot = Join-Path $projectRoot "output/incidents"
    }
    $prompts = Get-InvestigationPromptDefinitions

    $resolvedCaseName = Prompt-InvestigationRunValue `
        -Label $prompts.CaseName `
        -DefaultValue $(if ($CaseName) { $CaseName } else { Get-InvestigationDefaultCaseName }) `
        -SkipPrompt:$SkipPrompt
    $resolvedDaysBack = if ($PSBoundParameters.ContainsKey("DaysBack")) {
        $DaysBack
    } else {
        Prompt-InvestigationLookbackDays -DefaultValue 14 -SkipPrompt:$SkipPrompt
    }

    $pivots = @{
        Sender = $Sender
        Domain = $Domain
        UserPrincipalName = $UserPrincipalName
        SubjectContains = $SubjectContains
    }
    if (-not $SkipPrompt) {
        foreach ($pivotName in @("Sender", "Domain", "UserPrincipalName", "SubjectContains")) {
            if (-not $pivots[$pivotName]) {
                $promptLabel = switch ($pivotName) {
                    "Sender" { $prompts.Sender }
                    "Domain" { $prompts.Domain }
                    "UserPrincipalName" { $prompts.UserPrincipalName }
                    "SubjectContains" { $prompts.SubjectContains }
                }
                $pivots[$pivotName] = Prompt-InvestigationRunValue -Label $promptLabel -AllowEmpty -SkipPrompt:$false
            }
        }
    }

    if (-not (Test-InvestigationPivotsPresent -Pivots $pivots)) {
        Write-Host "No sender, domain, recipient UPN, or subject pivot was supplied. Message trace and quarantine pivot modules will be skipped by design." -ForegroundColor DarkYellow
    }

    if (-not $OutputPath) {
        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $caseSlug = ConvertTo-InvestigationSlug -Value $resolvedCaseName
        $OutputPath = Join-Path $OutputRoot "$caseSlug-$stamp"
    }
    Resolve-InvestigationPath -Path $OutputPath | Out-Null

    $useLegacyProfileMode = Test-InvestigationLegacyProfileMode -BoundParameters $PSBoundParameters

    try {
        if ($useLegacyProfileMode) {
            return Invoke-LegacyProfileCollection `
                -TenantId $TenantId `
                -TenantDomain $TenantDomain `
                -ProfilePath $ProfilePath `
                -ProfileRoot $ProfileRoot `
                -Prerequisites $prerequisites `
                -CaseName $resolvedCaseName `
                -DaysBack $resolvedDaysBack `
                -OutputPath $OutputPath `
                -Pivots $pivots
        }

        return Invoke-SelfServiceCollection `
            -TenantId $TenantId `
            -TenantDomain $TenantDomain `
            -Prerequisites $prerequisites `
            -CaseName $resolvedCaseName `
            -DaysBack $resolvedDaysBack `
            -OutputPath $OutputPath `
            -Pivots $pivots
    } finally {
        Clear-InvestigationConnections
    }
}

if ($MyInvocation.InvocationName -ne ".") {
    $invokeParams = @{}
    foreach ($name in @("TenantId", "TenantDomain", "CaseName", "OutputPath", "OutputRoot", "ProfilePath", "ProfileRoot", "Sender", "Domain", "UserPrincipalName", "SubjectContains")) {
        if ($PSBoundParameters.ContainsKey($name)) {
            $invokeParams[$name] = $PSBoundParameters[$name]
        }
    }
    if ($PSBoundParameters.ContainsKey("DaysBack")) {
        $invokeParams.DaysBack = $DaysBack
    }
    if ($PSBoundParameters.ContainsKey("SkipPrompt")) {
        $invokeParams.SkipPrompt = $SkipPrompt
    }

    $result = Invoke-InvestigationCollector @invokeParams

    $terminalSummary = New-InvestigationTerminalSummary `
        -Manifest $result.Manifest `
        -CollectorResults $result.CollectorResults `
        -OutputPath $result.OutputPath

    Write-Host ""
    Write-Host $terminalSummary -ForegroundColor Green

    return $result
}
