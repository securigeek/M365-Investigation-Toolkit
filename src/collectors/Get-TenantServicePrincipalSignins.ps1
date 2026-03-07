Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")

function Invoke-TenantServicePrincipalSigninsCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$SinceIso,

        [Parameter()]
        [string]$CommandName = "Get-MgBetaAuditLogServicePrincipalSignIn"
    )

    $moduleName = "servicePrincipalSignins"

    try {
        $records = @(& $CommandName -Filter "createdDateTime ge $SinceIso" -All)
        $rows = @(
            $records |
                ForEach-Object {
                    [pscustomobject]@{
                        CreatedDateTime = $_.CreatedDateTime
                        AppDisplayName = $_.AppDisplayName
                        AppId = $_.AppId
                        ServicePrincipalId = $_.ServicePrincipalId
                        ResourceDisplayName = $_.ResourceDisplayName
                        ClientApp = $_.ClientAppUsed
                        IPAddress = $_.IPAddress
                        ResultType = if ($_.Status) { $_.Status.ErrorCode } else { $null }
                        FailureReason = if ($_.Status) { $_.Status.FailureReason } else { $null }
                    }
                }
        )
        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            SinceUtc = $SinceIso
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
