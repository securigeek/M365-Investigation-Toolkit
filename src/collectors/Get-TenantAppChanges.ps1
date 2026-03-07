Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")

function Invoke-TenantAppChangesCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$SinceIso
    )

    $moduleName = "appChanges"

    try {
        $applications = @(
            Get-MgApplication -Filter "createdDateTime ge $SinceIso" -ConsistencyLevel eventual -All |
                Select-Object DisplayName, AppId, Id, CreatedDateTime, SignInAudience
        )
        $servicePrincipals = @(
            Get-MgServicePrincipal -Filter "createdDateTime ge $SinceIso" -ConsistencyLevel eventual -All |
                Select-Object DisplayName, AppId, Id, CreatedDateTime, ServicePrincipalType
        )

        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            SinceUtc = $SinceIso
            Applications = $applications
            ServicePrincipals = $servicePrincipals
        }
        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            SinceUtc = $SinceIso
            ApplicationCount = @($applications).Count
            ServicePrincipalCount = @($servicePrincipals).Count
            Applications = $applications
            ServicePrincipals = $servicePrincipals
        }

        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{
                ApplicationCount = @($applications).Count
                ServicePrincipalCount = @($servicePrincipals).Count
            }
    } catch {
        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -Status "failed" `
            -NormalizedData ([pscustomobject]@{ TimestampUtc = (Get-Date).ToUniversalTime().ToString("o"); SinceUtc = $SinceIso; Applications = @(); ServicePrincipals = @() }) `
            -Metrics @{ ApplicationCount = 0; ServicePrincipalCount = 0 } `
            -ErrorMessage $_.Exception.Message
    }
}
