Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")

function Invoke-TenantConnectorsCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $moduleName = "connectors"

    try {
        $inbound = @(Get-InboundConnector | Select-Object Name, Enabled, ConnectorType, SenderDomains, RestrictDomainsToIPAddresses, RequireTls, TlsSenderCertificateName)
        $outbound = @(Get-OutboundConnector | Select-Object Name, Enabled, ConnectorType, RecipientDomains, RouteAllMessagesViaOnPremises, UseMXRecord, TlsSettings)
        $anomalies = @()
        $anomalies += @(
            $inbound |
                Where-Object { $_.Enabled -and ((-not $_.RequireTls) -or (-not $_.RestrictDomainsToIPAddresses)) } |
                Select-Object @{ Name = "Direction"; Expression = { "Inbound" } }, Name, Enabled, ConnectorType, SenderDomains, RestrictDomainsToIPAddresses, RequireTls
        )
        $anomalies += @(
            $outbound |
                Where-Object { $_.Enabled -and $_.RouteAllMessagesViaOnPremises -and (-not $_.UseMXRecord) } |
                Select-Object @{ Name = "Direction"; Expression = { "Outbound" } }, Name, Enabled, ConnectorType, RecipientDomains, RouteAllMessagesViaOnPremises, UseMXRecord, TlsSettings
        )
        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            Inbound = $inbound
            Outbound = $outbound
        }
        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            Inbound = $inbound
            Outbound = $outbound
            Anomalies = $anomalies
        }

        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{
                InboundConnectorCount = @($inbound).Count
                OutboundConnectorCount = @($outbound).Count
                AnomalyCount = @($anomalies).Count
            }
    } catch {
        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -Status "failed" `
            -NormalizedData ([pscustomobject]@{ TimestampUtc = (Get-Date).ToUniversalTime().ToString("o"); Inbound = @(); Outbound = @(); Anomalies = @() }) `
            -Metrics @{ InboundConnectorCount = 0; OutboundConnectorCount = 0; AnomalyCount = 0 } `
            -ErrorMessage $_.Exception.Message
    }
}
