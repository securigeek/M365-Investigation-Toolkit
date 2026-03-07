Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")

function Test-QuarantinePivotMatch {
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
        if (-not $senderDomainMatch) {
            return $false
        }
    }

    if ($Pivots.SubjectContains -and ([string]$Row.Subject) -notmatch [regex]::Escape($Pivots.SubjectContains)) {
        return $false
    }

    return $true
}

function Invoke-TenantQuarantinePivotCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter(Mandatory = $true)]
        [hashtable]$Pivots
    )

    $moduleName = "quarantinePivot"

    try {
        $rows = @(
            Get-QuarantineMessage -StartReceivedDate $StartDate -EndReceivedDate $EndDate |
                Select-Object Identity, ReceivedTime, Type, ReleaseStatus, SenderAddress, RecipientAddress, Subject, Expires
        )
        $matchedRows = @(
            $rows |
                Where-Object { Test-QuarantinePivotMatch -Row $_ -Pivots $Pivots }
        )

        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            StartDate = $StartDate.ToUniversalTime().ToString("o")
            EndDate = $EndDate.ToUniversalTime().ToString("o")
            Messages = $rows
        }
        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            StartDate = $rawData.StartDate
            EndDate = $rawData.EndDate
            Pivots = [pscustomobject]$Pivots
            TotalRows = @($rows).Count
            MatchedRows = $matchedRows
        }

        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{
                TotalRows = @($rows).Count
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
            -ErrorMessage $_.Exception.Message
    }
}
