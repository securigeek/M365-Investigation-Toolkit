Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")

function Invoke-TenantAcceptedDomainsCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $moduleName = "acceptedDomains"

    try {
        $domains = @(
            Get-MgDomain -All |
                Select-Object Id, IsDefault, IsInitial, IsVerified, AuthenticationType, SupportedServices, AvailabilityStatus
        )
        $anomalies = @(
            $domains |
                Where-Object { (-not $_.IsVerified) -or $_.AvailabilityStatus }
        )

        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            Domains = $domains
        }
        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            TotalDomains = @($domains).Count
            Domains = $domains
            Anomalies = $anomalies
        }

        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{
                TotalDomains = @($domains).Count
                AnomalyCount = @($anomalies).Count
            }
    } catch {
        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -Status "failed" `
            -NormalizedData ([pscustomobject]@{ TimestampUtc = (Get-Date).ToUniversalTime().ToString("o"); Domains = @(); Anomalies = @() }) `
            -Metrics @{ TotalDomains = 0; AnomalyCount = 0 } `
            -ErrorMessage $_.Exception.Message
    }
}
