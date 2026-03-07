Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")

function Invoke-TenantTransportRulesCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $moduleName = "transportRules"

    try {
        $rules = @(Get-TransportRule | Select-Object Name, State, Mode, Priority, DeleteMessage, RedirectMessageTo, BlindCopyTo, AddToRecipients, SetHeaderName, SetHeaderValue)
        $suspiciousRules = @(
            $rules |
                Where-Object {
                    $_.State -eq "Enabled" -and (
                        $_.DeleteMessage -or
                        $_.RedirectMessageTo -or
                        $_.BlindCopyTo -or
                        $_.AddToRecipients
                    )
                }
        )
        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            Rules = $rules
        }
        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            TotalRules = @($rules).Count
            Rules = $rules
            SuspiciousRules = $suspiciousRules
        }

        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{
                TotalRules = @($rules).Count
                SuspiciousRuleCount = @($suspiciousRules).Count
            }
    } catch {
        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -Status "failed" `
            -NormalizedData ([pscustomobject]@{ TimestampUtc = (Get-Date).ToUniversalTime().ToString("o"); Rules = @(); SuspiciousRules = @() }) `
            -Metrics @{ TotalRules = 0; SuspiciousRuleCount = 0 } `
            -ErrorMessage $_.Exception.Message
    }
}
