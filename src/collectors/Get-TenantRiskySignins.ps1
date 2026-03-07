Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")

function Invoke-TenantRiskySigninsCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

    [Parameter(Mandatory = $true)]
        [string]$SinceIso,

        [Parameter()]
        [string]$CommandName = "Get-MgAuditLogSignIn"
    )

    $moduleName = "riskySignins"

    try {
        $signIns = @(& $CommandName -Filter "createdDateTime ge $SinceIso and riskLevelDuringSignIn ne 'none'" -All)
        $rows = @(
            $signIns |
                Select-Object CreatedDateTime, UserPrincipalName, IPAddress, AppDisplayName, RiskLevelDuringSignIn, RiskState, ConditionalAccessStatus, ClientAppUsed
        )
        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            SinceUtc = $SinceIso
            SignIns = $signIns
        }
        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            SinceUtc = $SinceIso
            TotalRows = @($rows).Count
            Rows = $rows
        }

        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{ TotalRows = @($rows).Count }
    } catch {
        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -Status "failed" `
            -NormalizedData ([pscustomobject]@{ TimestampUtc = (Get-Date).ToUniversalTime().ToString("o"); SinceUtc = $SinceIso; Rows = @() }) `
            -Metrics @{ TotalRows = 0 } `
            -ErrorMessage $_.Exception.Message
    }
}
