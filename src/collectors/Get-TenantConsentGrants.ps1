Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")

function Invoke-TenantConsentGrantsCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter()]
        [string]$CommandName = "Get-MgOauth2PermissionGrant"
    )

    $moduleName = "consentGrants"
    $highRiskScopes = @(
        "Mail.ReadWrite",
        "Mail.Send",
        "Files.ReadWrite.All",
        "Directory.AccessAsUser.All",
        "offline_access"
    )

    try {
        $grants = @(
            & $CommandName -All |
                Select-Object ClientId, ConsentType, PrincipalId, ResourceId, Scope, StartTime, ExpiryTime
        )
        $highRiskGrants = @(
            $grants |
                Where-Object {
                    $scopeValue = [string]$_.Scope
                    $highRiskScopes | Where-Object { $scopeValue -match [regex]::Escape($_) }
                }
        )

        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            Grants = $grants
        }
        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            GrantCount = @($grants).Count
            Grants = $grants
            HighRiskScopes = $highRiskScopes
            HighRiskGrants = $highRiskGrants
        }

        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{
                GrantCount = @($grants).Count
                HighRiskGrantCount = @($highRiskGrants).Count
            }
    } catch {
        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -Status "failed" `
            -NormalizedData ([pscustomobject]@{
                TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
                Grants = @()
                HighRiskScopes = $highRiskScopes
                HighRiskGrants = @()
            }) `
            -Metrics @{ GrantCount = 0; HighRiskGrantCount = 0 } `
            -ErrorMessage $_.Exception.Message
    }
}
