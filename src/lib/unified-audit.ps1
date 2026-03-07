Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "forensic-normalization.ps1")

function Get-InvestigationDefaultUnifiedAuditOperations {
    return @(
        "UserLoggedIn",
        "MailItemsAccessed",
        "UpdateInboxRules",
        "New-InboxRule",
        "Set-InboxRule",
        "SearchQueryInitiated",
        "SearchExportDownloaded",
        "ComplianceSearch"
    )
}

function Get-InvestigationObjectPropertyValue {
    param(
        [Parameter()]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string[]]$PropertyNames,

        [Parameter()]
        [object]$DefaultValue = $null
    )

    if ($null -eq $Object) {
        return $DefaultValue
    }

    foreach ($propertyName in @($PropertyNames)) {
        if ($Object.PSObject.Properties.Name -contains $propertyName) {
            return $Object.$propertyName
        }
    }

    return $DefaultValue
}

function ConvertTo-InvestigationUnifiedAuditLegacyStatus {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("verifiedOn", "verifiedOff", "ambiguous")]
        [string]$Status
    )

    switch ($Status) {
        "verifiedOn" { return "verified-on" }
        "verifiedOff" { return "verified-off" }
        default { return "ambiguous" }
    }
}

function Test-InvestigationExchangeAdminAuditCommand {
    param(
        [Parameter()]
        [object]$Command
    )

    if ($null -eq $Command) {
        return $false
    }

    foreach ($candidate in @(
        (Get-InvestigationObjectPropertyValue -Object $Command -PropertyNames @("Source")),
        (Get-InvestigationObjectPropertyValue -Object $Command -PropertyNames @("ModuleName"))
    )) {
        if ([string]::IsNullOrWhiteSpace([string]$candidate)) {
            continue
        }

        $resolved = [string]$candidate
        if ($resolved -eq "ExchangeOnlineManagement" -or $resolved -like "tmpEXO_*") {
            return $true
        }
    }

    return $false
}

function Get-InvestigationExchangeAdminAuditCommandContext {
    param(
        [Parameter()]
        [string]$CommandName = "Get-AdminAuditLogConfig"
    )

    $commands = @()
    try {
        $commands = @(Get-Command $CommandName -All -ErrorAction SilentlyContinue)
    } catch {
        $commands = @()
    }

    $matchedCommand = $commands |
        Where-Object { Test-InvestigationExchangeAdminAuditCommand -Command $_ } |
        Select-Object -First 1

    $connections = @()
    try {
        $connections = @(Get-ConnectionInformation)
    } catch {
        $connections = @()
    }

    return [pscustomobject]@{
        Verified = ($null -ne $matchedCommand -and @($connections).Count -gt 0)
        Command = $matchedCommand
        Candidates = @(
            $commands |
                Select-Object Name, Source, ModuleName
        )
        ConnectionCount = @($connections).Count
    }
}

function Test-InvestigationUnifiedAuditDisabledError {
    param(
        [Parameter()]
        [string]$Message
    )

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return $false
    }

    return $Message -match "unified audit log ingestion is disabled|audit(ing)? logging is disabled|recording user and admin activity"
}

function Invoke-InvestigationUnifiedAuditProbe {
    param(
        [Parameter()]
        [string]$CommandName = "Search-UnifiedAuditLog",

        [Parameter()]
        [int]$HoursBack = 24,

        [Parameter()]
        [int]$ResultSize = 5
    )

    $endDate = (Get-Date).ToUniversalTime()
    $startDate = $endDate.AddHours(-1 * $HoursBack)

    $records = @(
        & $CommandName `
            -StartDate $startDate `
            -EndDate $endDate `
            -ResultSize $ResultSize
    )

    return [pscustomobject]@{
        StartDate = $startDate
        EndDate = $endDate
        ResultSize = $ResultSize
        Records = $records
    }
}

function Resolve-InvestigationUnifiedAuditAssessment {
    param(
        [Parameter()]
        [psobject]$Config,

        [Parameter()]
        [psobject]$Probe,

        [Parameter()]
        [psobject]$CommandContext
    )

    $gaps = @()
    $warnings = @()
    $probeRan = [bool](Get-InvestigationObjectPropertyValue -Object $Probe -PropertyNames @("Ran") -DefaultValue $false)
    $probeSucceeded = [bool](Get-InvestigationObjectPropertyValue -Object $Probe -PropertyNames @("Succeeded") -DefaultValue $false)
    $probeCount = [int](Get-InvestigationObjectPropertyValue -Object $Probe -PropertyNames @("ResultCount") -DefaultValue 0)
    $probeError = [string](Get-InvestigationObjectPropertyValue -Object $Probe -PropertyNames @("Error") -DefaultValue $null)
    $exchangeContextVerified = [bool](Get-InvestigationObjectPropertyValue -Object $CommandContext -PropertyNames @("Verified") -DefaultValue $false)

    $adminAuditEnabled = if ($Config -and $Config.PSObject.Properties.Name -contains "AdminAuditLogEnabled") {
        [bool]$Config.AdminAuditLogEnabled
    } else {
        $null
    }
    $ualEnabled = if ($Config -and $Config.PSObject.Properties.Name -contains "UnifiedAuditLogIngestionEnabled") {
        [bool]$Config.UnifiedAuditLogIngestionEnabled
    } else {
        $null
    }

    if ($adminAuditEnabled -eq $false) {
        $gaps += "Admin audit logging is disabled."
    }

    $verificationStatus = "ambiguous"
    $verificationReason = "command-source-unverified"
    $collectorStatus = "success"

    if (-not $exchangeContextVerified) {
        $gaps += "Unified audit log status is ambiguous and must be verified from an Exchange Online session."
        $warnings += "Get-AdminAuditLogConfig could not be verified from Exchange Online context."
        $collectorStatus = "partial"
    } elseif (Test-InvestigationUnifiedAuditDisabledError -Message $probeError) {
        $gaps += "Unified audit log ingestion is disabled."
        $verificationStatus = "verifiedOff"
        $verificationReason = "probe-disabled-error"
    } elseif ($probeError) {
        $gaps += "Unified audit log status is ambiguous and must be verified from an Exchange Online session."
        $warnings += "Unified audit log probe could not verify status: $probeError"
        $verificationReason = "probe-failed"
        $collectorStatus = "partial"
    } elseif ($probeSucceeded -and $probeCount -gt 0) {
        if ($ualEnabled -eq $false) {
            $warnings += "Unified audit log config returned disabled, but a live Search-UnifiedAuditLog probe returned data. Verify the command source in Exchange Online PowerShell."
            $verificationReason = "probe-returned-records-config-conflict"
            $collectorStatus = "partial"
        } else {
            $verificationReason = "probe-returned-records"
        }
        $verificationStatus = "verifiedOn"
    } elseif ($ualEnabled -eq $true) {
        $verificationStatus = "verifiedOn"
        $verificationReason = "config-enabled-no-recent-events"
    } else {
        $gaps += "Unified audit log status is ambiguous and must be verified from an Exchange Online session."
        $collectorStatus = "partial"

        if ($ualEnabled -eq $false) {
            $verificationReason = "config-disabled-no-confirming-probe"
        } else {
            $verificationReason = "probe-no-results"
        }
    }

    $gaps = @($gaps | Sort-Object -Unique)
    $warnings = @($warnings | Sort-Object -Unique)

    $probeStatus = if (-not $probeRan) {
        "not-run"
    } elseif (Test-InvestigationUnifiedAuditDisabledError -Message $probeError) {
        "disabled"
    } elseif ($probeSucceeded -and $probeCount -gt 0) {
        "records-returned"
    } elseif ($probeSucceeded) {
        "no-results"
    } else {
        "failed"
    }

    return [pscustomobject]@{
        UnifiedAuditLogStatus = ConvertTo-InvestigationUnifiedAuditLegacyStatus -Status $verificationStatus
        UnifiedAuditLogVerification = [pscustomobject]@{
            Status = $verificationStatus
            Reason = $verificationReason
        }
        CoverageGaps = $gaps
        Warnings = $warnings
        ProbeStatus = $probeStatus
        ProbeError = $probeError
        ProbeResultCount = $probeCount
        ProbeRan = $probeRan
        ProbeSucceeded = $probeSucceeded
        CollectorStatus = $collectorStatus
    }
}

function ConvertFrom-InvestigationUnifiedAuditData {
    param(
        [Parameter()]
        [object]$AuditData
    )

    if ($null -eq $AuditData) {
        return [pscustomobject]@{}
    }

    if ($AuditData -is [string]) {
        if ([string]::IsNullOrWhiteSpace($AuditData)) {
            return [pscustomobject]@{}
        }

        return $AuditData | ConvertFrom-Json -Depth 20
    }

    return $AuditData
}

function ConvertTo-InvestigationUnifiedAuditPropertyMap {
    param(
        [Parameter()]
        [object[]]$Properties
    )

    return ConvertTo-ForensicPropertyMap -Properties $Properties
}

function Invoke-InvestigationUnifiedAuditSearch {
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter()]
        [string[]]$Operations = (Get-InvestigationDefaultUnifiedAuditOperations),

        [Parameter()]
        [int]$ResultSize = 5000,

        [Parameter()]
        [string]$CommandName = "Search-UnifiedAuditLog"
    )

    $sessionId = "investigation-$([guid]::NewGuid().ToString("N"))"
    $pageNumber = 0
    $records = @()

    do {
        $pageNumber++
        $page = @(
            & $CommandName `
                -StartDate $StartDate `
                -EndDate $EndDate `
                -Operations $Operations `
                -SessionId $sessionId `
                -SessionCommand "ReturnLargeSet" `
                -ResultSize $ResultSize
        )
        $records += $page
    } while ($page.Count -ge $ResultSize -and $pageNumber -lt 100)

    return @($records)
}
