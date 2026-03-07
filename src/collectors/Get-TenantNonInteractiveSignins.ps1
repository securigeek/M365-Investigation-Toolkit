Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "Get-TenantInteractiveSignins.ps1")

function Invoke-TenantNonInteractiveSigninsCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$SinceIso,

        [Parameter()]
        [string]$CommandName = "Get-MgAuditLogSignIn"
    )

    $moduleName = "nonInteractiveSignins"
    $filter = Get-InvestigationSignInBaseFilter -SinceIso $SinceIso

    try {
        $records = @(& $CommandName -Filter $filter -All)
        $rows = ConvertTo-InvestigationSignInRows -Records @($records | Where-Object { Test-InvestigationNonInteractiveSignInRecord -Record $_ })
        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            SinceUtc = $SinceIso
            Filter = $filter
            Records = $records
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
            -NormalizedData ([pscustomobject]@{ TimestampUtc = (Get-Date).ToUniversalTime().ToString("o"); SinceUtc = $SinceIso; Rows = @(); TotalRows = 0 }) `
            -Metrics @{ TotalRows = 0 } `
            -ErrorMessage $_.Exception.Message
    }
}
