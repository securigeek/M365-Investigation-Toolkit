Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")

function Test-MessageTracePivotMatch {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Row,

        [Parameter(Mandatory = $true)]
        [hashtable]$Pivots
    )

    if ($Pivots.Sender -and ([string]$Row.SenderAddress) -ne $Pivots.Sender) {
        return $false
    }

    if ($Pivots.UserPrincipalName -and ([string]$Row.RecipientAddress) -ne $Pivots.UserPrincipalName) {
        return $false
    }

    if ($Pivots.Domain) {
        $senderDomainMatch = ([string]$Row.SenderAddress) -match "@$([regex]::Escape($Pivots.Domain))$"
        $recipientDomainMatch = ([string]$Row.RecipientAddress) -match "@$([regex]::Escape($Pivots.Domain))$"
        if (-not ($senderDomainMatch -or $recipientDomainMatch)) {
            return $false
        }
    }

    if ($Pivots.SubjectContains -and ([string]$Row.Subject) -notmatch [regex]::Escape($Pivots.SubjectContains)) {
        return $false
    }

    return $true
}

function Get-InvestigationMessageTraceWindows {
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter()]
        [int]$MaxWindowDays = 10
    )

    if ($EndDate -le $StartDate) {
        return @(
            [pscustomobject]@{
                StartDate = $StartDate
                EndDate = $EndDate
            }
        )
    }

    $windows = @()
    $cursor = $StartDate
    while ($cursor -lt $EndDate) {
        $windowEnd = $cursor.AddDays($MaxWindowDays)
        if ($windowEnd -gt $EndDate) {
            $windowEnd = $EndDate
        }

        $windows += [pscustomobject]@{
            StartDate = $cursor
            EndDate = $windowEnd
        }

        $cursor = $windowEnd
    }

    return $windows
}

function Resolve-MessageTracePivotErrorMessage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Message -match "Get-MessageTrace" -and $Message -match "September 1(st)?[,]? 2025") {
        $today = Get-Date -Format "MMMM d, yyyy"
        return "As of $today, Exchange reports Get-MessageTrace is deprecated as of September 1, 2025. Use Get-MessageTraceV2 instead. See https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/new-message-trace"
    }

    return $Message
}

function Invoke-TenantMessageTracePivotCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter(Mandatory = $true)]
        [hashtable]$Pivots,

        [Parameter()]
        [string]$CommandName = "Get-MessageTraceV2"
    )

    $moduleName = "messageTracePivot"

    try {
        $rows = @()
        foreach ($window in @(Get-InvestigationMessageTraceWindows -StartDate $StartDate -EndDate $EndDate)) {
            $traceParams = @{
                StartDate = $window.StartDate
                EndDate = $window.EndDate
                ResultSize = 5000
            }
            if ($Pivots.Sender) {
                $traceParams.SenderAddress = $Pivots.Sender
            }
            if ($Pivots.UserPrincipalName) {
                $traceParams.RecipientAddress = $Pivots.UserPrincipalName
            }

            $rows += @(
                & $CommandName @traceParams |
                    Select-Object MessageTraceId, Received, SenderAddress, RecipientAddress, Subject, Status, MessageId, FromIP, ToIP, Size
            )
        }

        $dedupedRows = @()
        $seenKeys = @{}
        foreach ($row in @($rows)) {
            $key = "$($row.MessageTraceId)|$($row.RecipientAddress)|$($row.Received)|$($row.MessageId)"
            if (-not $seenKeys.ContainsKey($key)) {
                $seenKeys[$key] = $true
                $dedupedRows += $row
            }
        }
        $matchedRows = @(
            $dedupedRows |
                Where-Object { Test-MessageTracePivotMatch -Row $_ -Pivots $Pivots }
        )

        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            StartDate = $StartDate.ToUniversalTime().ToString("o")
            EndDate = $EndDate.ToUniversalTime().ToString("o")
            Trace = $dedupedRows
        }
        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            StartDate = $rawData.StartDate
            EndDate = $rawData.EndDate
            Pivots = [pscustomobject]$Pivots
            TotalRows = @($dedupedRows).Count
            MatchedRows = $matchedRows
        }

        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{
                TotalRows = @($dedupedRows).Count
                MatchedRowCount = @($matchedRows).Count
            }
    } catch {
        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -Status "failed" `
            -NormalizedData ([pscustomobject]@{
                TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
                Pivots = [pscustomobject]$Pivots
                MatchedRows = @()
            }) `
            -Metrics @{ TotalRows = 0; MatchedRowCount = 0 } `
            -ErrorMessage (Resolve-MessageTracePivotErrorMessage -Message $_.Exception.Message)
    }
}
